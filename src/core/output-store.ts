import { randomBytes as cryptoRandomBytes } from "node:crypto";
import type { Dirent } from "node:fs";
import {
  lstat,
  mkdir,
  open as openFile,
  readdir,
  readFile,
  rename,
  rm,
} from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { parse, resolve } from "node:path";

import {
  GATEWAY_ERROR_CODES,
  GatewayError,
} from "../shared/errors.js";
import {
  MAX_INLINE_PREVIEW_BYTES,
  MAX_OUTPUT_READ_BYTES,
  type OutputChunk,
  type OutputStreamSummary,
} from "../shared/protocol.js";
import { completeUtf8PrefixLength } from "../shared/utf8.js";

export type OutputStream = "stdout" | "stderr";

export interface OutputStoreOptions {
  readonly directory: string;
  readonly inlineBytesPerStream: number;
  readonly maxStoredBytes: number;
  readonly maxTotalRetainedBytes: number;
  readonly maxRetainedEntries: number;
  readonly ttlMs: number;
  readonly maxReadBytes?: number;
  readonly now?: () => number;
  readonly randomBytes?: (size: number) => Uint8Array;
}

export interface StoredOutputSummary {
  readonly stdout: OutputStreamSummary;
  readonly stderr: OutputStreamSummary;
  readonly outputRef?: string;
  readonly outputExpiresAt?: string;
}

export interface OutputSink {
  append(stream: OutputStream, chunk: Uint8Array): Promise<void>;
  finalize(): Promise<StoredOutputSummary>;
  /** Immediately quarantines the sink. Call abort() to clean it up. */
  cancel(): void;
  /** Cleans up once already-started append operations settle. */
  abort(): Promise<void>;
}

export class OutputLimitExceededError extends Error {
  public readonly code = "OUTPUT_LIMIT_EXCEEDED" as const;
  public readonly limitKind: "bytes" | "entries";
  public readonly maxBytes: number;
  public readonly currentBytes: number;
  public readonly attemptedBytes: number;

  public constructor(
    maxBytes: number,
    currentBytes: number,
    attemptedBytes: number,
    limitKind: "bytes" | "entries" = "bytes",
  ) {
    super(
      limitKind === "bytes"
        ? "Stored output exceeded the configured byte limit"
        : "Stored output exceeded the configured retained entry limit",
    );
    this.name = "OutputLimitExceededError";
    this.limitKind = limitKind;
    this.maxBytes = maxBytes;
    this.currentBytes = currentBytes;
    this.attemptedBytes = attemptedBytes;
  }
}

export class OutputNotFoundError extends GatewayError {
  public constructor() {
    super(
      GATEWAY_ERROR_CODES.outputNotFound,
      "Output reference was not found",
    );
    this.name = "OutputNotFoundError";
  }
}

export class OutputExpiredError extends GatewayError {
  public constructor() {
    super(GATEWAY_ERROR_CODES.outputExpired, "Output reference has expired");
    this.name = "OutputExpiredError";
  }
}

export class OutputStoreIoError extends GatewayError {
  public constructor(options: ErrorOptions = {}) {
    super(
      GATEWAY_ERROR_CODES.internalError,
      "Output storage operation failed",
      options,
    );
    this.name = "OutputStoreIoError";
  }
}

export class OutputSinkClosedError extends Error {
  public constructor() {
    super("Output sink is closed");
    this.name = "OutputSinkClosedError";
  }
}

interface OutputMetadata {
  readonly version: 1;
  readonly expiresAtMs: number;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
}

interface StreamState {
  readonly inlineChunks: Buffer[];
  inlineBytes: number;
  totalBytes: number;
  handle: FileHandle | undefined;
}

interface RetainedEntry {
  readonly reference: string;
  readonly directory: string;
  readonly metadata: OutputMetadata;
  readonly bytes: number;
}

interface CleanupResult {
  readonly removed: number;
  readonly retained: readonly RetainedEntry[];
}

interface ByteReservation {
  readonly grantedBytes: number;
  readonly currentBytes: number;
  readonly maxBytes: number;
  readonly entryLimit?: {
    readonly currentEntries: number;
    readonly maxEntries: number;
  };
}

const OUTPUT_REFERENCE_BYTES = 32;
const OUTPUT_REFERENCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const METADATA_FILE = "metadata.json";
const RETAINED_ENTRY_FILE_NAMES = new Set([
  METADATA_FILE,
  "stdout.bin",
  "stderr.bin",
]);
const METADATA_MAX_BYTES = 4_096;
const MAX_REFERENCE_ATTEMPTS = 8;

function isNodeError(error: unknown, code: string): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === code
  );
}

function assertSafeInteger(
  value: number,
  name: string,
  minimum: number,
): void {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new RangeError(`${name} must be a safe integer >= ${minimum}`);
  }
}

function parseMetadata(value: unknown): OutputMetadata | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return undefined;
  }

  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const expectedKeys = [
    "expiresAtMs",
    "stderrBytes",
    "stdoutBytes",
    "version",
  ];
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index])
  ) {
    return undefined;
  }

  const stdoutBytes = record.stdoutBytes as number;
  const stderrBytes = record.stderrBytes as number;
  if (
    record.version !== 1 ||
    !Number.isSafeInteger(record.expiresAtMs) ||
    (record.expiresAtMs as number) < 0 ||
    !Number.isSafeInteger(stdoutBytes) ||
    stdoutBytes < 0 ||
    !Number.isSafeInteger(stderrBytes) ||
    stderrBytes < 0 ||
    !Number.isSafeInteger(stdoutBytes + stderrBytes)
  ) {
    return undefined;
  }

  return {
    version: 1,
    expiresAtMs: record.expiresAtMs as number,
    stdoutBytes,
    stderrBytes,
  };
}

function metadataBytes(metadata: OutputMetadata): number {
  return metadata.stdoutBytes + metadata.stderrBytes;
}

class RetainedByteQuota {
  readonly #maxBytes: number;
  readonly #maxEntries: number;
  readonly #bytesByReference = new Map<string, number>();
  #totalBytes = 0;

  public constructor(maxBytes: number, maxEntries: number) {
    this.#maxBytes = maxBytes;
    this.#maxEntries = maxEntries;
  }

  public get maxBytes(): number {
    return this.#maxBytes;
  }

  public get maxEntries(): number {
    return this.#maxEntries;
  }

  public references(): readonly string[] {
    return [...this.#bytesByReference.keys()];
  }

  public has(reference: string): boolean {
    return this.#bytesByReference.has(reference);
  }

  public reserve(reference: string, requestedBytes: number): ByteReservation {
    const currentBytes = this.#totalBytes;
    if (
      requestedBytes > 0 &&
      !this.#bytesByReference.has(reference) &&
      this.#bytesByReference.size >= this.#maxEntries
    ) {
      return {
        grantedBytes: 0,
        currentBytes,
        maxBytes: this.#maxBytes,
        entryLimit: {
          currentEntries: this.#bytesByReference.size,
          maxEntries: this.#maxEntries,
        },
      };
    }
    const grantedBytes = Math.min(
      requestedBytes,
      this.#maxBytes - currentBytes,
    );
    if (grantedBytes > 0) {
      this.#totalBytes += grantedBytes;
      this.#bytesByReference.set(
        reference,
        (this.#bytesByReference.get(reference) ?? 0) + grantedBytes,
      );
    }
    return { grantedBytes, currentBytes, maxBytes: this.#maxBytes };
  }

  public trackExisting(reference: string, bytes: number): void {
    if (this.#bytesByReference.has(reference)) {
      throw new Error("Retained output reference was registered more than once");
    }
    if (bytes > this.#maxBytes - this.#totalBytes) {
      throw new Error("Retained output exceeds the configured total byte limit");
    }
    if (this.#bytesByReference.size >= this.#maxEntries) {
      throw new Error("Retained output exceeds the configured entry limit");
    }
    this.#bytesByReference.set(reference, bytes);
    this.#totalBytes += bytes;
  }

  public release(reference: string): void {
    const retainedBytes = this.#bytesByReference.get(reference);
    if (retainedBytes === undefined) {
      return;
    }

    this.#totalBytes -= retainedBytes;
    this.#bytesByReference.delete(reference);
  }
}

export class OutputStore {
  readonly #directory: string;
  readonly #inlineBytesPerStream: number;
  readonly #maxStoredBytes: number;
  readonly #ttlMs: number;
  readonly #maxReadBytes: number;
  readonly #now: () => number;
  readonly #randomBytes: (size: number) => Uint8Array;
  readonly #quota: RetainedByteQuota;
  readonly #activeReferences = new Set<string>();
  #initialization: Promise<void> | undefined;

  public constructor(options: OutputStoreOptions) {
    if (options.directory.trim().length === 0) {
      throw new RangeError("directory must not be empty");
    }
    const directory = resolve(options.directory);
    if (directory === parse(directory).root) {
      throw new RangeError("directory must not be a filesystem root");
    }

    assertSafeInteger(
      options.inlineBytesPerStream,
      "inlineBytesPerStream",
      0,
    );
    assertSafeInteger(options.maxStoredBytes, "maxStoredBytes", 1);
    assertSafeInteger(
      options.maxTotalRetainedBytes,
      "maxTotalRetainedBytes",
      1,
    );
    assertSafeInteger(
      options.maxRetainedEntries,
      "maxRetainedEntries",
      1,
    );
    assertSafeInteger(options.ttlMs, "ttlMs", 1);
    const maxReadBytes = options.maxReadBytes ?? MAX_OUTPUT_READ_BYTES;
    assertSafeInteger(maxReadBytes, "maxReadBytes", 1);

    this.#directory = directory;
    // Older managed revisions may still contain the historical 64 KiB value.
    // Keep those configurations loadable while enforcing the current preview
    // ceiling before anything can enter an RPC response.
    this.#inlineBytesPerStream = Math.min(
      options.inlineBytesPerStream,
      MAX_INLINE_PREVIEW_BYTES,
    );
    this.#maxStoredBytes = options.maxStoredBytes;
    this.#ttlMs = options.ttlMs;
    this.#maxReadBytes = maxReadBytes;
    this.#now = options.now ?? Date.now;
    this.#randomBytes = options.randomBytes ?? cryptoRandomBytes;
    this.#quota = new RetainedByteQuota(
      options.maxTotalRetainedBytes,
      options.maxRetainedEntries,
    );
  }

  public static async open(options: OutputStoreOptions): Promise<OutputStore> {
    const store = new OutputStore(options);
    await store.#ensureInitialized();
    return store;
  }

  public async create(requestId: string | number): Promise<OutputSink> {
    if (
      (typeof requestId !== "string" && typeof requestId !== "number") ||
      (typeof requestId === "string" && requestId.length === 0) ||
      (typeof requestId === "number" && !Number.isSafeInteger(requestId))
    ) {
      throw new TypeError("requestId must be a non-empty string or safe integer");
    }

    await this.#ensureInitialized();
    const reservation = await this.#reserveReference();
    const sink = new FileOutputSink(
      reservation.reference,
      reservation.directory,
      this.#inlineBytesPerStream,
      this.#maxStoredBytes,
      this.#ttlMs,
      this.#now,
      this.#randomBytes,
      this.#quota,
    );
    return new TrackedOutputSink(sink, () => {
      this.#activeReferences.delete(reservation.reference);
    });
  }

  public async read(
    reference: string,
    stream: OutputStream,
    offset: number,
    limit: number,
  ): Promise<OutputChunk> {
    await this.#ensureInitialized();
    if (!OUTPUT_REFERENCE_PATTERN.test(reference)) {
      throw new OutputNotFoundError();
    }
    if (stream !== "stdout" && stream !== "stderr") {
      throw new RangeError("stream must be stdout or stderr");
    }
    assertSafeInteger(offset, "offset", 0);
    assertSafeInteger(limit, "limit", 1);
    if (limit > this.#maxReadBytes) {
      throw new RangeError("limit exceeds maxReadBytes");
    }

    const entryDirectory = this.#entryDirectory(reference);
    let metadata: OutputMetadata;
    try {
      metadata = await this.#readMetadata(entryDirectory);
    } catch (error) {
      if (error instanceof OutputNotFoundError) {
        await this.#throwReadNotFound(reference, entryDirectory);
      }
      throw error;
    }
    if (metadata.expiresAtMs <= this.#now()) {
      try {
        await rm(entryDirectory, { recursive: true, force: true });
        this.#quota.release(reference);
      } catch (error) {
        throw new OutputStoreIoError({ cause: error });
      }
      throw new OutputExpiredError();
    }

    const totalBytes =
      stream === "stdout" ? metadata.stdoutBytes : metadata.stderrBytes;
    if (offset > totalBytes) {
      throw new RangeError("offset exceeds the stream length");
    }

    const requestedBytes = Math.min(limit, totalBytes - offset);
    if (requestedBytes === 0) {
      return {
        dataBase64: "",
        nextOffset: null,
        eof: true,
        totalBytes,
      };
    }

    let handle: FileHandle | undefined;
    try {
      handle = await openFile(
        `${entryDirectory}/${stream === "stdout" ? "stdout.bin" : "stderr.bin"}`,
        "r",
      );
      const buffer = Buffer.allocUnsafe(requestedBytes);
      const { bytesRead } = await handle.read(buffer, 0, requestedBytes, offset);
      if (bytesRead !== requestedBytes) {
        throw new Error("Stored output is incomplete");
      }
      const followingOffset = offset + bytesRead;
      const eof = followingOffset === totalBytes;
      return {
        dataBase64: buffer.toString("base64"),
        nextOffset: eof ? null : followingOffset,
        eof,
        totalBytes,
      };
    } catch (error) {
      if (isNodeError(error, "ENOENT")) {
        await this.#throwReadNotFound(reference, entryDirectory);
      }
      throw new OutputStoreIoError({ cause: error });
    } finally {
      if (handle !== undefined) {
        await handle.close().catch(() => undefined);
      }
    }
  }

  public async cleanupExpired(): Promise<number> {
    await this.#ensureInitialized();
    return (await this.#cleanupEntries()).removed;
  }

  async #ensureInitialized(): Promise<void> {
    this.#initialization ??= this.#initialize();
    return this.#initialization;
  }

  async #initialize(): Promise<void> {
    try {
      await mkdir(this.#directory, { recursive: true, mode: 0o700 });
      const cleanup = await this.#cleanupEntries();
      await this.#adoptRetainedEntries(cleanup.retained);
    } catch (error) {
      throw new OutputStoreIoError({ cause: error });
    }
  }

  async #cleanupEntries(): Promise<CleanupResult> {
    const trackedBeforeScan = this.#quota.references();
    let entries;
    try {
      entries = await readdir(this.#directory, { withFileTypes: true });
    } catch (error) {
      throw new OutputStoreIoError({ cause: error });
    }

    const now = this.#now();
    const seenReferences = new Set<string>();
    const retained: RetainedEntry[] = [];
    let removed = 0;
    for (const entry of entries) {
      if (!OUTPUT_REFERENCE_PATTERN.test(entry.name)) {
        try {
          await rm(this.#entryDirectory(entry.name), {
            recursive: true,
            force: true,
          });
          removed += 1;
        } catch (error) {
          throw new OutputStoreIoError({ cause: error });
        }
        continue;
      }
      seenReferences.add(entry.name);
      if (this.#activeReferences.has(entry.name)) {
        continue;
      }
      const entryDirectory = this.#entryDirectory(entry.name);
      let shouldRemove = !entry.isDirectory() || entry.isSymbolicLink();
      let metadata: OutputMetadata | undefined;
      if (!shouldRemove) {
        try {
          metadata = await this.#readMetadataFile(entryDirectory);
          shouldRemove =
            metadata === undefined ||
            metadata.expiresAtMs <= now ||
            !(await this.#isCanonicalRetainedEntry(entryDirectory, metadata));
        } catch (error) {
          throw error instanceof OutputStoreIoError
            ? error
            : new OutputStoreIoError({ cause: error });
        }
      }

      if (shouldRemove) {
        try {
          await rm(entryDirectory, { recursive: true, force: true });
          this.#quota.release(entry.name);
          removed += 1;
        } catch (error) {
          throw new OutputStoreIoError({ cause: error });
        }
      } else if (metadata !== undefined) {
        retained.push({
          reference: entry.name,
          directory: entryDirectory,
          metadata,
          bytes: metadataBytes(metadata),
        });
      }
    }

    for (const reference of trackedBeforeScan) {
      if (
        !seenReferences.has(reference) &&
        !this.#activeReferences.has(reference)
      ) {
        this.#quota.release(reference);
      }
    }
    return { removed, retained };
  }

  async #adoptRetainedEntries(
    entries: readonly RetainedEntry[],
  ): Promise<void> {
    const ordered = [...entries].sort((left, right) => {
      if (left.metadata.expiresAtMs !== right.metadata.expiresAtMs) {
        return left.metadata.expiresAtMs < right.metadata.expiresAtMs ? -1 : 1;
      }
      return left.reference < right.reference
        ? -1
        : left.reference === right.reference
          ? 0
          : 1;
    });
    let totalBytes = ordered.reduce(
      (total, entry) => total + BigInt(entry.bytes),
      0n,
    );
    let retainedEntries = ordered.length;
    const maxBytes = BigInt(this.#quota.maxBytes);
    const maxEntries = this.#quota.maxEntries;
    const evicted = new Set<string>();

    for (const entry of ordered) {
      if (totalBytes <= maxBytes && retainedEntries <= maxEntries) {
        break;
      }
      try {
        await rm(entry.directory, { recursive: true, force: true });
      } catch (error) {
        throw new OutputStoreIoError({ cause: error });
      }
      evicted.add(entry.reference);
      totalBytes -= BigInt(entry.bytes);
      retainedEntries -= 1;
    }

    for (const entry of entries) {
      if (!evicted.has(entry.reference)) {
        this.#quota.trackExisting(entry.reference, entry.bytes);
      }
    }
  }

  async #reserveReference(): Promise<{
    readonly reference: string;
    readonly directory: string;
  }> {
    for (let attempt = 0; attempt < MAX_REFERENCE_ATTEMPTS; attempt += 1) {
      const random = Buffer.from(this.#randomBytes(OUTPUT_REFERENCE_BYTES));
      if (random.byteLength !== OUTPUT_REFERENCE_BYTES) {
        throw new OutputStoreIoError({
          cause: new Error("Random source returned an invalid length"),
        });
      }
      const reference = random.toString("base64url");
      const directory = this.#entryDirectory(reference);
      if (
        this.#activeReferences.has(reference) ||
        this.#quota.has(reference)
      ) {
        continue;
      }
      // Register before mkdir makes the directory visible to concurrent TTL
      // cleanup. Failed reservations remove the marker before retrying.
      this.#activeReferences.add(reference);
      try {
        await mkdir(directory, { recursive: false, mode: 0o700 });
        return { reference, directory };
      } catch (error) {
        this.#activeReferences.delete(reference);
        if (isNodeError(error, "EEXIST")) {
          continue;
        }
        throw new OutputStoreIoError({ cause: error });
      }
    }

    throw new OutputStoreIoError({
      cause: new Error("Unable to allocate an output reference"),
    });
  }

  async #readMetadata(entryDirectory: string): Promise<OutputMetadata> {
    let metadata: OutputMetadata | undefined;
    try {
      metadata = await this.#readMetadataFile(entryDirectory);
    } catch (error) {
      if (isNodeError(error, "ENOENT")) {
        throw new OutputNotFoundError();
      }
      throw new OutputStoreIoError({ cause: error });
    }
    if (metadata === undefined) {
      throw new OutputNotFoundError();
    }
    return metadata;
  }

  async #throwReadNotFound(
    reference: string,
    entryDirectory: string,
  ): Promise<never> {
    try {
      await lstat(entryDirectory);
    } catch (error) {
      if (isNodeError(error, "ENOENT")) {
        if (!this.#activeReferences.has(reference)) {
          this.#quota.release(reference);
        }
        throw new OutputNotFoundError();
      }
      throw new OutputStoreIoError({ cause: error });
    }

    throw new OutputNotFoundError();
  }

  async #readMetadataFile(
    entryDirectory: string,
  ): Promise<OutputMetadata | undefined> {
    const metadataPath = `${entryDirectory}/${METADATA_FILE}`;
    let metadataStat;
    try {
      metadataStat = await lstat(metadataPath);
    } catch (error) {
      if (isNodeError(error, "ENOENT")) {
        return undefined;
      }
      throw error;
    }
    if (!metadataStat.isFile() || metadataStat.size > METADATA_MAX_BYTES) {
      return undefined;
    }
    let serialized: string;
    try {
      serialized = await readFile(metadataPath, "utf8");
    } catch (error) {
      if (isNodeError(error, "ENOENT")) {
        return undefined;
      }
      throw error;
    }
    try {
      return parseMetadata(JSON.parse(serialized) as unknown);
    } catch {
      return undefined;
    }
  }

  async #isCanonicalRetainedEntry(
    entryDirectory: string,
    metadata: OutputMetadata,
  ): Promise<boolean> {
    let entries;
    try {
      entries = await readdir(entryDirectory, { withFileTypes: true });
    } catch (error) {
      if (isNodeError(error, "ENOENT")) {
        return false;
      }
      throw error;
    }

    if (
      entries.some((entry) => !RETAINED_ENTRY_FILE_NAMES.has(entry.name)) ||
      !entries.some(
        (entry) =>
          entry.name === METADATA_FILE &&
          entry.isFile() &&
          !entry.isSymbolicLink(),
      )
    ) {
      return false;
    }

    return (
      (await this.#isCanonicalPayloadFile(
        entryDirectory,
        entries,
        "stdout.bin",
        metadata.stdoutBytes,
      )) &&
      (await this.#isCanonicalPayloadFile(
        entryDirectory,
        entries,
        "stderr.bin",
        metadata.stderrBytes,
      ))
    );
  }

  async #isCanonicalPayloadFile(
    entryDirectory: string,
    entries: readonly Dirent<string>[],
    fileName: "stdout.bin" | "stderr.bin",
    expectedBytes: number,
  ): Promise<boolean> {
    const entry = entries.find((candidate) => candidate.name === fileName);
    if (entry === undefined) {
      return expectedBytes === 0;
    }
    if (!entry.isFile() || entry.isSymbolicLink()) {
      return false;
    }

    try {
      const payloadStat = await lstat(`${entryDirectory}/${fileName}`);
      return payloadStat.isFile() && payloadStat.size === expectedBytes;
    } catch (error) {
      if (isNodeError(error, "ENOENT")) {
        return false;
      }
      throw error;
    }
  }

  #entryDirectory(reference: string): string {
    return `${this.#directory}/${reference}`;
  }
}

class TrackedOutputSink implements OutputSink {
  readonly #sink: OutputSink;
  readonly #release: () => void;
  #released = false;

  public constructor(sink: OutputSink, release: () => void) {
    this.#sink = sink;
    this.#release = release;
  }

  public append(stream: OutputStream, chunk: Uint8Array): Promise<void> {
    return this.#sink.append(stream, chunk);
  }

  public async finalize(): Promise<StoredOutputSummary> {
    try {
      return await this.#sink.finalize();
    } finally {
      this.#releaseOnce();
    }
  }

  public cancel(): void {
    this.#sink.cancel();
  }

  public async abort(): Promise<void> {
    try {
      await this.#sink.abort();
    } finally {
      this.#releaseOnce();
    }
  }

  #releaseOnce(): void {
    if (!this.#released) {
      this.#released = true;
      this.#release();
    }
  }
}

class FileOutputSink implements OutputSink {
  readonly #reference: string;
  readonly #directory: string;
  readonly #inlineBytesPerStream: number;
  readonly #maxStoredBytes: number;
  readonly #ttlMs: number;
  readonly #now: () => number;
  readonly #randomBytes: (size: number) => Uint8Array;
  readonly #quota: RetainedByteQuota;
  readonly #streams: Record<OutputStream, StreamState> = {
    stdout: {
      inlineChunks: [],
      inlineBytes: 0,
      totalBytes: 0,
      handle: undefined,
    },
    stderr: {
      inlineChunks: [],
      inlineBytes: 0,
      totalBytes: 0,
      handle: undefined,
    },
  };
  #tail: Promise<void> = Promise.resolve();
  #accepting = true;
  #limitError: OutputLimitExceededError | undefined;
  #fatalError: OutputStoreIoError | undefined;
  #finalizePromise: Promise<StoredOutputSummary> | undefined;
  #abortPromise: Promise<void> | undefined;
  #cancelled = false;
  #published = false;

  public constructor(
    reference: string,
    directory: string,
    inlineBytesPerStream: number,
    maxStoredBytes: number,
    ttlMs: number,
    now: () => number,
    randomBytes: (size: number) => Uint8Array,
    quota: RetainedByteQuota,
  ) {
    this.#reference = reference;
    this.#directory = directory;
    this.#inlineBytesPerStream = inlineBytesPerStream;
    this.#maxStoredBytes = maxStoredBytes;
    this.#ttlMs = ttlMs;
    this.#now = now;
    this.#randomBytes = randomBytes;
    this.#quota = quota;
  }

  public append(stream: OutputStream, chunk: Uint8Array): Promise<void> {
    if (!this.#accepting) {
      return Promise.reject(new OutputSinkClosedError());
    }
    if (stream !== "stdout" && stream !== "stderr") {
      return Promise.reject(new TypeError("stream must be stdout or stderr"));
    }
    if (!(chunk instanceof Uint8Array)) {
      return Promise.reject(new TypeError("chunk must be a Uint8Array"));
    }

    const copiedChunk = Buffer.from(chunk);
    const operation = this.#tail.then(() => this.#appendNow(stream, copiedChunk));
    this.#tail = operation.catch(() => undefined);
    return operation;
  }

  public finalize(): Promise<StoredOutputSummary> {
    if (this.#finalizePromise !== undefined) {
      return this.#finalizePromise;
    }
    if (this.#abortPromise !== undefined) {
      return Promise.reject(new OutputSinkClosedError());
    }
    if (this.#cancelled) {
      return Promise.reject(new OutputSinkClosedError());
    }

    this.#accepting = false;
    this.#finalizePromise = this.#tail
      .then(() => this.#finalizeNow())
      .catch(async (error: unknown) => {
        await this.#closeHandles(false).catch(() => undefined);
        const removed = await rm(this.#directory, {
          recursive: true,
          force: true,
        }).then(
          () => true,
          () => false,
        );
        if (removed) {
          this.#quota.release(this.#reference);
        }
        throw error;
      });
    this.#tail = this.#finalizePromise.then(
      () => undefined,
      () => undefined,
    );
    return this.#finalizePromise;
  }

  public cancel(): void {
    if (
      this.#published ||
      this.#finalizePromise !== undefined ||
      this.#abortPromise !== undefined
    ) {
      return;
    }
    this.#accepting = false;
    this.#cancelled = true;
  }

  public abort(): Promise<void> {
    if (this.#published || this.#finalizePromise !== undefined) {
      return this.#finalizePromise?.then(() => undefined) ?? Promise.resolve();
    }
    if (this.#abortPromise !== undefined) {
      return this.#abortPromise;
    }

    this.cancel();
    this.#abortPromise = this.#tail.then(async () => {
      let firstError: unknown;
      let removed = false;
      try {
        await this.#closeHandles(false);
      } catch (error) {
        firstError = error;
      }
      try {
        await rm(this.#directory, { recursive: true, force: true });
        removed = true;
      } catch (error) {
        firstError ??= error;
      }
      if (removed) {
        this.#quota.release(this.#reference);
      }
      if (firstError !== undefined) {
        throw firstError instanceof OutputStoreIoError
          ? firstError
          : new OutputStoreIoError({ cause: firstError });
      }
    });
    this.#tail = this.#abortPromise.catch(() => undefined);
    return this.#abortPromise;
  }

  async #appendNow(stream: OutputStream, chunk: Buffer): Promise<void> {
    if (this.#cancelled) {
      throw new OutputSinkClosedError();
    }
    if (this.#fatalError !== undefined) {
      throw this.#fatalError;
    }
    if (this.#limitError !== undefined) {
      throw this.#limitError;
    }
    if (chunk.byteLength === 0) {
      return;
    }

    const totalBytesBeforeAppend =
      this.#streams.stdout.totalBytes + this.#streams.stderr.totalBytes;
    const perExecutionRemaining =
      this.#maxStoredBytes - totalBytesBeforeAppend;
    const requestedBytes = Math.min(
      perExecutionRemaining,
      chunk.byteLength,
    );
    const reservation = this.#quota.reserve(this.#reference, requestedBytes);
    const storedChunk = chunk.subarray(0, reservation.grantedBytes);
    const state = this.#streams[stream];
    if (storedChunk.byteLength > 0) {
      try {
        state.handle ??= await openFile(
          `${this.#directory}/${stream === "stdout" ? "stdout.bin" : "stderr.bin"}`,
          "wx",
          0o600,
        );
        if (this.#cancelled) {
          throw new OutputSinkClosedError();
        }
        await writeEntireBuffer(state.handle, storedChunk);
        if (this.#cancelled) {
          throw new OutputSinkClosedError();
        }
      } catch (error) {
        if (this.#cancelled) {
          throw new OutputSinkClosedError();
        }
        this.#fatalError = new OutputStoreIoError({ cause: error });
        throw this.#fatalError;
      }

      const inlineRemaining =
        this.#inlineBytesPerStream - state.inlineBytes;
      if (inlineRemaining > 0) {
        const inlineChunk = storedChunk.subarray(
          0,
          Math.min(inlineRemaining, storedChunk.byteLength),
        );
        state.inlineChunks.push(Buffer.from(inlineChunk));
        state.inlineBytes += inlineChunk.byteLength;
      }
      state.totalBytes += storedChunk.byteLength;
    }

    if (storedChunk.byteLength !== chunk.byteLength) {
      this.#limitError =
        reservation.entryLimit !== undefined
          ? new OutputLimitExceededError(
              reservation.entryLimit.maxEntries,
              reservation.entryLimit.currentEntries,
              1,
              "entries",
            )
          : reservation.grantedBytes < requestedBytes
          ? new OutputLimitExceededError(
              reservation.maxBytes,
              reservation.currentBytes,
              chunk.byteLength,
            )
          : new OutputLimitExceededError(
              this.#maxStoredBytes,
              totalBytesBeforeAppend,
              chunk.byteLength,
            );
      throw this.#limitError;
    }
  }

  async #finalizeNow(): Promise<StoredOutputSummary> {
    if (this.#fatalError !== undefined) {
      await this.#closeHandles(false);
      await rm(this.#directory, { recursive: true, force: true }).catch(
        () => undefined,
      );
      throw this.#fatalError;
    }

    await this.#closeHandles(true);
    const stdout = summarizeStream(
      this.#streams.stdout,
      this.#inlineBytesPerStream,
    );
    const stderr = summarizeStream(
      this.#streams.stderr,
      this.#inlineBytesPerStream,
    );
    if (!stdout.inlineTruncated && !stderr.inlineTruncated) {
      try {
        await rm(this.#directory, { recursive: true, force: true });
        this.#quota.release(this.#reference);
      } catch (error) {
        throw new OutputStoreIoError({ cause: error });
      }
      return { stdout, stderr };
    }

    const expiresAtMs = Math.trunc(this.#now() + this.#ttlMs);
    const metadata: OutputMetadata = {
      version: 1,
      expiresAtMs,
      stdoutBytes: this.#streams.stdout.totalBytes,
      stderrBytes: this.#streams.stderr.totalBytes,
    };
    const temporaryName = `.metadata-${Buffer.from(
      this.#randomBytes(12),
    ).toString("hex")}.tmp`;
    const temporaryPath = `${this.#directory}/${temporaryName}`;
    let metadataHandle: FileHandle | undefined;
    try {
      metadataHandle = await openFile(temporaryPath, "wx", 0o600);
      await writeEntireBuffer(
        metadataHandle,
        Buffer.from(`${JSON.stringify(metadata)}\n`, "utf8"),
      );
      await metadataHandle.sync();
      await metadataHandle.close();
      metadataHandle = undefined;
      await rename(temporaryPath, `${this.#directory}/${METADATA_FILE}`);
    } catch (error) {
      if (metadataHandle !== undefined) {
        await metadataHandle.close().catch(() => undefined);
      }
      await rm(this.#directory, { recursive: true, force: true }).catch(
        () => undefined,
      );
      throw new OutputStoreIoError({ cause: error });
    }

    this.#published = true;
    return {
      stdout,
      stderr,
      outputRef: this.#reference,
      outputExpiresAt: new Date(expiresAtMs).toISOString(),
    };
  }

  async #closeHandles(sync: boolean): Promise<void> {
    let firstError: unknown;
    for (const state of Object.values(this.#streams)) {
      const handle = state.handle;
      state.handle = undefined;
      if (handle === undefined) {
        continue;
      }
      try {
        if (sync) {
          await handle.sync();
        }
        await handle.close();
      } catch (error) {
        firstError ??= error;
        await handle.close().catch(() => undefined);
      }
    }
    if (firstError !== undefined) {
      throw new OutputStoreIoError({ cause: firstError });
    }
  }
}

function summarizeStream(
  state: StreamState,
  inlineBytesPerStream: number,
): OutputStreamSummary {
  const inline = Buffer.concat(state.inlineChunks, state.inlineBytes);
  const truncated = state.totalBytes > inlineBytesPerStream;
  const textBytes = truncated
    ? inline.subarray(0, completeUtf8PrefixLength(inline))
    : inline;
  return {
    text: textBytes.toString("utf8"),
    bytes: state.totalBytes,
    inlineTruncated: truncated,
  };
}

async function writeEntireBuffer(
  handle: FileHandle,
  buffer: Buffer,
): Promise<void> {
  let offset = 0;
  while (offset < buffer.byteLength) {
    const { bytesWritten } = await handle.write(
      buffer,
      offset,
      buffer.byteLength - offset,
      null,
    );
    if (bytesWritten <= 0) {
      throw new Error("Output storage write made no progress");
    }
    offset += bytesWritten;
  }
}
