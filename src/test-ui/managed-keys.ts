import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { constants as fsConstants, type BigIntStats } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rmdir,
  unlink,
} from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import { z } from "zod";

import {
  hardenPrivatePath,
  hardenPrivatePaths,
} from "../daemon/runtime-state.js";

const execFileAsync = promisify(execFile);
const KEY_MANIFEST_VERSION = 1;
const KEY_METADATA_VERSION = 1;
const MAX_PRIVATE_KEY_BYTES = 1_048_576;
const KEY_DIRECTORY_PATTERN = /^k-[a-f0-9]{32}$/u;
const STAGING_DIRECTORY_PATTERN = /^\.staging-(k-[a-f0-9]{32})$/u;
const DELETING_DIRECTORY_PATTERN = /^\.deleting-(k-[a-f0-9]{32})$/u;
const MANIFEST_TEMPORARY_PATTERN = /^manifest\.json\.tmp-[0-9]+-[a-f0-9]{32}$/u;
const PUBLIC_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9@._+-]* [A-Za-z0-9+/]+={0,3}$/u;
const CONTROL_OR_BIDI_PATTERN =
  /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;

export const managedSshKeyIdSchema = z
  .string()
  .regex(KEY_DIRECTORY_PATTERN);

export const managedSshKeyRevisionSchema = z
  .string()
  .regex(/^kr-[a-z0-9]+-[a-f0-9]{32}$/u);

export const managedSshKeyLabelSchema = z
  .string()
  .min(1)
  .max(128)
  .refine((value) => value === value.trim(), "must not have surrounding whitespace")
  .refine((value) => !CONTROL_OR_BIDI_PATTERN.test(value), "must not contain control or bidirectional formatting characters");

export const MANAGED_SSH_KEY_ORIGINS = [
  "generated",
  "imported",
  "migrated",
] as const;

export const MANAGED_SSH_KEY_GENERATION_ALGORITHMS = [
  "ed25519",
  "rsa-3072",
] as const;

export const managedSshKeyGenerationAlgorithmSchema = z.enum(
  MANAGED_SSH_KEY_GENERATION_ALGORITHMS,
);

const managedSshKeyOriginSchema = z.enum(MANAGED_SSH_KEY_ORIGINS);

const managedSshKeyRecordSchema = z.strictObject({
  keyId: managedSshKeyIdSchema,
  label: managedSshKeyLabelSchema,
  algorithm: z.string().min(1).max(128),
  fingerprint: z.string().regex(/^SHA256:[A-Za-z0-9+/]+$/u),
  publicKey: z.string().min(1).max(16_384).regex(PUBLIC_KEY_PATTERN),
  createdAt: z.iso.datetime(),
  origin: managedSshKeyOriginSchema,
});

const managedSshKeyMetadataSchema = z.strictObject({
  version: z.literal(KEY_METADATA_VERSION),
  record: managedSshKeyRecordSchema,
});

const managedSshKeyManifestSchema = z.strictObject({
  version: z.literal(KEY_MANIFEST_VERSION),
  keyRevision: managedSshKeyRevisionSchema,
  keys: z.array(managedSshKeyRecordSchema).max(1_024),
});

export type ManagedSshKeyOrigin = (typeof MANAGED_SSH_KEY_ORIGINS)[number];
export type ManagedSshKeyGenerationAlgorithm = z.infer<
  typeof managedSshKeyGenerationAlgorithmSchema
>;
export type ManagedSshKeyRecord = z.infer<typeof managedSshKeyRecordSchema>;

export interface ManagedSshKeyVaultSnapshot {
  readonly keyRevision: string;
  readonly keys: readonly ManagedSshKeyRecord[];
}

export class ManagedSshKeyVaultError extends Error {
  public readonly status: number;
  public readonly code: string;

  public constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ManagedSshKeyVaultError";
    this.status = status;
    this.code = code;
  }
}

interface KeyPaths {
  readonly keyId: string;
  readonly root: string;
  readonly privateKey: string;
  readonly publicKey: string;
  readonly metadata: string;
}

interface DerivedPublicKey {
  readonly algorithm: string;
  readonly fingerprint: string;
  readonly publicKey: string;
}

export class ManagedSshKeyVault {
  readonly #root: string;
  readonly #manifestPath: string;
  readonly #sshKeygenExecutable: string;
  #keyRevision = createKeyRevision();
  #records = new Map<string, ManagedSshKeyRecord>();
  #initialized = false;

  public constructor(root: string, sshKeygenExecutable: string) {
    this.#root = path.resolve(root);
    this.#manifestPath = path.join(this.#root, "manifest.json");
    this.#sshKeygenExecutable = sshKeygenExecutable;
  }

  public async initialize(): Promise<void> {
    await ensurePrivateDirectory(this.#root);
    const manifest = await this.#readManifestIfPresent();
    await this.#cleanupInterruptedMutations(
      new Set((manifest?.keys ?? []).map((record) => record.keyId)),
    );

    const directories = await this.#readPublishedRecords();
    const records = manifest === undefined
      ? directories
      : mergeManifestWithPublishedRecords(manifest.keys, directories);
    assertUniqueRecords(records);

    const manifestChanged =
      manifest === undefined || !sameRecords(manifest.keys, records);
    this.#records = new Map(records.map((record) => [record.keyId, record]));
    this.#keyRevision = manifestChanged
      ? createKeyRevision()
      : manifest.keyRevision;
    if (manifestChanged) {
      await this.#commitManifest(this.#keyRevision, records);
    }
    this.#initialized = true;
  }

  public snapshot(): ManagedSshKeyVaultSnapshot {
    this.#assertInitialized();
    return {
      keyRevision: this.#keyRevision,
      keys: sortedRecords(this.#records.values()),
    };
  }

  public privateKeyPath(keyId: string): string {
    this.#assertInitialized();
    const parsed = managedSshKeyIdSchema.parse(keyId);
    if (!this.#records.has(parsed)) {
      throw keyError(404, "KEY_NOT_FOUND", "The selected SSH key was not found");
    }
    return createKeyPaths(this.#root, parsed).privateKey;
  }

  public async generate(
    label: string,
    expectedKeyRevision: string,
    algorithm: ManagedSshKeyGenerationAlgorithm = "ed25519",
  ): Promise<ManagedSshKeyVaultSnapshot> {
    this.#assertExpectedRevision(expectedKeyRevision);
    const parsedLabel = managedSshKeyLabelSchema.parse(label);
    const parsedAlgorithm = managedSshKeyGenerationAlgorithmSchema.parse(algorithm);
    this.#assertUniqueLabel(parsedLabel);
    return this.#publishNewKey(parsedLabel, "generated", async (destination) => {
      try {
        const algorithmArguments = parsedAlgorithm === "rsa-3072"
          ? ["-t", "rsa", "-b", "3072"]
          : ["-t", "ed25519"];
        await execFileNoInput(
          this.#sshKeygenExecutable,
          [
            "-q",
            ...algorithmArguments,
            "-N",
            "",
            "-C",
            "agent-ssh-gateway",
            "-f",
            destination,
          ],
          15_000,
        );
        await unlink(`${destination}.pub`).catch(() => undefined);
        await hardenPrivatePath(destination, false);
      } catch (error) {
        throw keyError(
          400,
          "KEY_GENERATION_FAILED",
          "The SSH key could not be generated",
          error,
        );
      }
    });
  }

  public async importFromPath(
    label: string,
    sourcePath: string,
    expectedKeyRevision: string,
  ): Promise<ManagedSshKeyVaultSnapshot> {
    this.#assertExpectedRevision(expectedKeyRevision);
    const parsedLabel = managedSshKeyLabelSchema.parse(label);
    this.#assertUniqueLabel(parsedLabel);
    return this.#publishNewKey(parsedLabel, "imported", (destination) =>
      importPrivateFile(sourcePath, destination),
    );
  }

  public async importMigrated(
    label: string,
    sourcePath: string,
  ): Promise<ManagedSshKeyRecord> {
    this.#assertInitialized();
    const parsedLabel = uniqueMigrationLabel(
      managedSshKeyLabelSchema.parse(label),
      this.#records.values(),
    );
    const sourcePublicKey = await derivePublicKey(
      this.#sshKeygenExecutable,
      sourcePath,
    );
    const existing = [...this.#records.values()].find(
      (record) => record.fingerprint === sourcePublicKey.fingerprint,
    );
    if (existing !== undefined) {
      return existing;
    }
    await this.#publishNewKey(parsedLabel, "migrated", (destination) =>
      importPrivateFile(sourcePath, destination),
    );
    const migrated = [...this.#records.values()].find(
      (record) => record.fingerprint === sourcePublicKey.fingerprint,
    );
    if (migrated === undefined) {
      throw keyError(500, "KEY_STORAGE_INVALID", "The migrated SSH key was not published");
    }
    return migrated;
  }

  public async renameKey(
    keyId: string,
    label: string,
    expectedKeyRevision: string,
  ): Promise<ManagedSshKeyVaultSnapshot> {
    this.#assertExpectedRevision(expectedKeyRevision);
    const parsedKeyId = managedSshKeyIdSchema.parse(keyId);
    const current = this.#requireRecord(parsedKeyId);
    const parsedLabel = managedSshKeyLabelSchema.parse(label);
    this.#assertUniqueLabel(parsedLabel, parsedKeyId);
    if (current.label === parsedLabel) {
      return this.snapshot();
    }

    const records = new Map(this.#records);
    records.set(parsedKeyId, { ...current, label: parsedLabel });
    await this.#replaceRecords(records);
    return this.snapshot();
  }

  public async removeKey(
    keyId: string,
    expectedKeyRevision: string,
  ): Promise<ManagedSshKeyVaultSnapshot> {
    this.#assertExpectedRevision(expectedKeyRevision);
    const parsedKeyId = managedSshKeyIdSchema.parse(keyId);
    this.#requireRecord(parsedKeyId);
    const published = createKeyPaths(this.#root, parsedKeyId);
    await validateKeyDirectory(published, this.#sshKeygenExecutable);
    const deletingRoot = path.join(this.#root, `.deleting-${parsedKeyId}`);
    await rename(published.root, deletingRoot);

    const records = new Map(this.#records);
    records.delete(parsedKeyId);
    try {
      await this.#replaceRecords(records);
    } catch (error) {
      await rename(deletingRoot, published.root).catch(() => undefined);
      throw error;
    }
    await removeKeyDirectory(deletingRoot).catch(() => undefined);
    return this.snapshot();
  }

  async #publishNewKey(
    label: string,
    origin: ManagedSshKeyOrigin,
    createPrivateKey: (destination: string) => Promise<void>,
  ): Promise<ManagedSshKeyVaultSnapshot> {
    const keyId = `k-${randomBytes(16).toString("hex")}`;
    const published = createKeyPaths(this.#root, keyId);
    const staging = createKeyPaths(this.#root, `.staging-${keyId}`);
    await mkdir(staging.root, { mode: 0o700 });
    let publishedDirectory = false;
    try {
      await hardenPrivatePath(staging.root, true);
      await createPrivateKey(staging.privateKey);
      const derived = await derivePublicKey(
        this.#sshKeygenExecutable,
        staging.privateKey,
      );
      const duplicate = [...this.#records.values()].find(
        (record) => record.fingerprint === derived.fingerprint,
      );
      if (duplicate !== undefined) {
        throw keyError(
          409,
          "KEY_ALREADY_EXISTS",
          "The same SSH key already exists in the key library",
        );
      }
      const record = managedSshKeyRecordSchema.parse({
        keyId,
        label,
        ...derived,
        createdAt: new Date().toISOString(),
        origin,
      });
      await Promise.all([
        writeExclusivePrivateFile(staging.publicKey, `${record.publicKey}\n`),
        writeExclusivePrivateFile(
          staging.metadata,
          `${JSON.stringify({ version: KEY_METADATA_VERSION, record }, null, 2)}\n`,
        ),
      ]);
      await validateKeyDirectory(staging, this.#sshKeygenExecutable, keyId);
      await rename(staging.root, published.root);
      publishedDirectory = true;
      await hardenPrivatePath(published.root, true);
      await validateKeyDirectory(published, this.#sshKeygenExecutable);

      const records = new Map(this.#records);
      records.set(keyId, record);
      await this.#replaceRecords(records);
      return this.snapshot();
    } catch (error) {
      if (!publishedDirectory) {
        await removeKeyDirectory(staging.root).catch(() => undefined);
      } else if (!this.#records.has(keyId)) {
        await removeKeyDirectory(published.root).catch(() => undefined);
      }
      if (error instanceof ManagedSshKeyVaultError || error instanceof z.ZodError) {
        throw error;
      }
      throw keyError(400, "KEY_INVALID", "The SSH key could not be stored", error);
    }
  }

  async #replaceRecords(records: Map<string, ManagedSshKeyRecord>): Promise<void> {
    const nextRevision = createKeyRevision();
    const sorted = sortedRecords(records.values());
    assertUniqueRecords(sorted);
    await this.#commitManifest(nextRevision, sorted);
    this.#records = records;
    this.#keyRevision = nextRevision;
  }

  async #commitManifest(
    keyRevision: string,
    records: readonly ManagedSshKeyRecord[],
  ): Promise<void> {
    const manifest = managedSshKeyManifestSchema.parse({
      version: KEY_MANIFEST_VERSION,
      keyRevision,
      keys: records,
    });
    await atomicWritePrivateFile(
      this.#manifestPath,
      `${JSON.stringify(manifest, null, 2)}\n`,
    );
  }

  async #readManifestIfPresent(): Promise<
    z.infer<typeof managedSshKeyManifestSchema> | undefined
  > {
    try {
      await assertRegularFile(this.#manifestPath, "SSH key manifest");
      await hardenPrivatePath(this.#manifestPath, false);
      return managedSshKeyManifestSchema.parse(
        JSON.parse(await readFile(this.#manifestPath, "utf8")) as unknown,
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return undefined;
      }
      if (error instanceof ManagedSshKeyVaultError && error.code === "FILE_NOT_FOUND") {
        return undefined;
      }
      throw keyError(
        500,
        "KEY_STORAGE_INVALID",
        "The SSH key manifest could not be read",
        error,
      );
    }
  }

  async #readPublishedRecords(): Promise<ManagedSshKeyRecord[]> {
    const entries = await readdir(this.#root, { withFileTypes: true });
    const records: ManagedSshKeyRecord[] = [];
    for (const entry of entries) {
      if (entry.name === "manifest.json") {
        continue;
      }
      if (!KEY_DIRECTORY_PATTERN.test(entry.name)) {
        throw keyError(
          500,
          "KEY_STORAGE_INVALID",
          "The SSH key library contains an unexpected entry",
        );
      }
      if (!entry.isDirectory() || entry.isSymbolicLink()) {
        throw keyError(
          500,
          "KEY_STORAGE_INVALID",
          "An SSH key entry is not a directly referenced directory",
        );
      }
      records.push(
        await validateKeyDirectory(
          createKeyPaths(this.#root, entry.name),
          this.#sshKeygenExecutable,
        ),
      );
    }
    return records;
  }

  async #cleanupInterruptedMutations(
    manifestKeyIds: ReadonlySet<string>,
  ): Promise<void> {
    const entries = await readdir(this.#root, { withFileTypes: true });
    for (const entry of entries) {
      if (STAGING_DIRECTORY_PATTERN.test(entry.name)) {
        if (!entry.isDirectory() || entry.isSymbolicLink()) {
          throw keyError(
            500,
            "KEY_STORAGE_INVALID",
            "An interrupted SSH key mutation has an unsafe type",
          );
        }
        await removeKeyDirectory(path.join(this.#root, entry.name));
        continue;
      }
      const deleting = entry.name.match(DELETING_DIRECTORY_PATTERN);
      if (deleting !== null) {
        if (!entry.isDirectory() || entry.isSymbolicLink()) {
          throw keyError(
            500,
            "KEY_STORAGE_INVALID",
            "An interrupted SSH key deletion has an unsafe type",
          );
        }
        const keyId = deleting[1]!;
        const deletingPath = path.join(this.#root, entry.name);
        if (manifestKeyIds.has(keyId)) {
          const publishedPath = path.join(this.#root, keyId);
          try {
            await lstat(publishedPath);
            throw keyError(
              500,
              "KEY_STORAGE_INVALID",
              "An interrupted SSH key deletion conflicts with published material",
            );
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
          }
          await rename(deletingPath, publishedPath);
          await hardenPrivatePath(publishedPath, true);
        } else {
          await removeKeyDirectory(deletingPath);
        }
        continue;
      }
      if (MANIFEST_TEMPORARY_PATTERN.test(entry.name)) {
        if (!entry.isFile() || entry.isSymbolicLink()) {
          throw keyError(
            500,
            "KEY_STORAGE_INVALID",
            "An interrupted SSH key manifest has an unsafe type",
          );
        }
        await removeSingleLinkFile(path.join(this.#root, entry.name));
      }
    }
  }

  #assertExpectedRevision(expectedKeyRevision: string): void {
    this.#assertInitialized();
    const parsed = managedSshKeyRevisionSchema.parse(expectedKeyRevision);
    if (parsed !== this.#keyRevision) {
      throw keyError(
        409,
        "KEY_REVISION_CONFLICT",
        "The SSH key library changed after it was read",
      );
    }
  }

  #assertUniqueLabel(label: string, ignoredKeyId?: string): void {
    const comparable = comparableLabel(label);
    const duplicate = [...this.#records.values()].some(
      (record) =>
        record.keyId !== ignoredKeyId && comparableLabel(record.label) === comparable,
    );
    if (duplicate) {
      throw keyError(
        409,
        "KEY_NAME_EXISTS",
        "An SSH key already uses the same label",
      );
    }
  }

  #requireRecord(keyId: string): ManagedSshKeyRecord {
    const record = this.#records.get(keyId);
    if (record === undefined) {
      throw keyError(404, "KEY_NOT_FOUND", "The selected SSH key was not found");
    }
    return record;
  }

  #assertInitialized(): void {
    if (!this.#initialized) {
      throw keyError(
        503,
        "KEY_STORAGE_UNAVAILABLE",
        "The SSH key library is unavailable",
      );
    }
  }
}

function createKeyPaths(root: string, keyId: string): KeyPaths {
  const directory = path.join(root, keyId);
  return {
    keyId,
    root: directory,
    privateKey: path.join(directory, "private.key"),
    publicKey: path.join(directory, "public.key"),
    metadata: path.join(directory, "metadata.json"),
  };
}

async function validateKeyDirectory(
  paths: KeyPaths,
  sshKeygenExecutable: string,
  expectedKeyId = paths.keyId,
): Promise<ManagedSshKeyRecord> {
  await assertDirectDirectory(paths.root, "SSH key entry");
  const entries = await readdir(paths.root, { withFileTypes: true });
  const expected = new Set(["private.key", "public.key", "metadata.json"]);
  if (
    entries.length !== expected.size ||
    entries.some(
      (entry) =>
        !expected.has(entry.name) ||
        !entry.isFile() ||
        entry.isSymbolicLink(),
    )
  ) {
    throw keyError(
      500,
      "KEY_STORAGE_INVALID",
      "An SSH key entry contains unexpected files",
    );
  }
  await Promise.all([
    assertRegularFileSize(paths.privateKey, "SSH private key", MAX_PRIVATE_KEY_BYTES),
    assertRegularFileSize(paths.publicKey, "SSH public key", 16_384),
    assertRegularFileSize(paths.metadata, "SSH key metadata", 32_768),
  ]);
  await hardenPrivatePaths([
    { path: paths.root, directory: true },
    { path: paths.privateKey, directory: false },
    { path: paths.publicKey, directory: false },
    { path: paths.metadata, directory: false },
  ]);
  const metadata = managedSshKeyMetadataSchema.parse(
    JSON.parse(await readFile(paths.metadata, "utf8")) as unknown,
  );
  if (metadata.record.keyId !== expectedKeyId) {
    throw keyError(
      500,
      "KEY_STORAGE_INVALID",
      "SSH key metadata does not match its key identifier",
    );
  }
  const derived = await derivePublicKey(sshKeygenExecutable, paths.privateKey);
  const storedPublic = (await readFile(paths.publicKey, "utf8")).trim();
  if (
    storedPublic !== metadata.record.publicKey ||
    derived.publicKey !== metadata.record.publicKey ||
    derived.algorithm !== metadata.record.algorithm ||
    derived.fingerprint !== metadata.record.fingerprint
  ) {
    throw keyError(
      500,
      "KEY_STORAGE_INVALID",
      "SSH key material does not match its metadata",
    );
  }
  return metadata.record;
}

async function derivePublicKey(
  sshKeygenExecutable: string,
  privateKeyPath: string,
): Promise<DerivedPublicKey> {
  await assertRegularFile(privateKeyPath, "SSH private key");
  try {
    const { stdout } = await execFileNoInput(
      sshKeygenExecutable,
      ["-y", "-P", "", "-f", privateKeyPath],
      10_000,
    );
    const fields = stdout.trim().split(/\s+/u);
    const algorithm = fields[0];
    const encoded = fields[1];
    if (
      algorithm === undefined ||
      encoded === undefined ||
      fields.length < 2 ||
      !PUBLIC_KEY_PATTERN.test(`${algorithm} ${encoded}`)
    ) {
      throw new Error("ssh-keygen returned an invalid public key");
    }
    const keyBytes = Buffer.from(encoded, "base64");
    if (keyBytes.length === 0) {
      throw new Error("ssh-keygen returned empty public key material");
    }
    return {
      algorithm,
      publicKey: `${algorithm} ${encoded}`,
      fingerprint: `SHA256:${createHash("sha256")
        .update(keyBytes)
        .digest("base64")
        .replace(/=+$/u, "")}`,
    };
  } catch (error) {
    if (error instanceof ManagedSshKeyVaultError) {
      throw error;
    }
    throw keyError(
      400,
      "KEY_INVALID",
      "The SSH private key is invalid or requires a passphrase",
      error,
    );
  }
}

async function importPrivateFile(
  sourcePath: string,
  destinationPath: string,
): Promise<void> {
  const inspected = await lstat(sourcePath, { bigint: true }).catch(
    (error: unknown) => {
      throw keyError(404, "FILE_NOT_FOUND", "The SSH private key was not found", error);
    },
  );
  assertImportableFile(inspected);
  const noFollowFlag = process.platform === "win32" ? 0 : fsConstants.O_NOFOLLOW;
  const source = await open(sourcePath, fsConstants.O_RDONLY | noFollowFlag);
  let destinationCreated = false;
  try {
    const initial = await source.stat({ bigint: true });
    assertImportableFile(initial);
    assertSameImportSource(inspected, initial);
    const body = await source.readFile();
    const verified = await source.stat({ bigint: true });
    assertSameImportSource(initial, verified);
    if (BigInt(body.length) !== initial.size) {
      throw keyError(409, "FILE_CHANGED", "The SSH private key changed while it was imported");
    }
    await writeExclusivePrivateFile(destinationPath, body);
    destinationCreated = true;
    assertSameImportSource(initial, await lstat(sourcePath, { bigint: true }));
  } finally {
    await source.close();
    if (!destinationCreated) {
      await unlink(destinationPath).catch(() => undefined);
    }
  }
}

function assertImportableFile(entry: BigIntStats): void {
  if (
    !entry.isFile() ||
    entry.isSymbolicLink() ||
    entry.nlink !== 1n ||
    entry.size < 1n ||
    entry.size > BigInt(MAX_PRIVATE_KEY_BYTES)
  ) {
    throw keyError(
      400,
      "FILE_UNSAFE",
      "The SSH private key has an unsupported type or size",
    );
  }
}

function assertSameImportSource(expected: BigIntStats, actual: BigIntStats): void {
  if (
    expected.dev !== actual.dev ||
    expected.ino !== actual.ino ||
    expected.nlink !== actual.nlink ||
    expected.size !== actual.size ||
    expected.mtimeNs !== actual.mtimeNs ||
    expected.ctimeNs !== actual.ctimeNs
  ) {
    throw keyError(409, "FILE_CHANGED", "The SSH private key changed while it was imported");
  }
}

async function execFileNoInput(
  executable: string,
  arguments_: readonly string[],
  timeoutMs: number,
): Promise<{ stdout: string; stderr: string }> {
  try {
    const result = await execFileAsync(executable, [...arguments_], {
      encoding: "utf8",
      timeout: timeoutMs,
      windowsHide: true,
      maxBuffer: 1_048_576,
      env: {
        ...process.env,
        SSH_ASKPASS_REQUIRE: "never",
      },
    });
    return { stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    throw error;
  }
}

async function ensurePrivateDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await hardenPrivatePath(directory, true);
}

async function assertDirectDirectory(directory: string, label: string): Promise<void> {
  let entry;
  try {
    entry = await lstat(directory);
  } catch (error) {
    throw keyError(500, "FILE_NOT_FOUND", `${label} was not found`, error);
  }
  if (!entry.isDirectory() || entry.isSymbolicLink()) {
    throw keyError(500, "FILE_UNSAFE", `${label} must be a directly referenced directory`);
  }
}

async function assertRegularFile(filePath: string, label: string): Promise<void> {
  let entry;
  try {
    entry = await lstat(filePath);
  } catch (error) {
    throw keyError(500, "FILE_NOT_FOUND", `${label} was not found`, error);
  }
  if (!entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1) {
    throw keyError(400, "FILE_UNSAFE", `${label} must be a single-link regular file`);
  }
}

async function assertRegularFileSize(
  filePath: string,
  label: string,
  maxBytes: number,
): Promise<void> {
  const entry = await lstat(filePath, { bigint: true }).catch((error: unknown) => {
    throw keyError(500, "FILE_NOT_FOUND", `${label} was not found`, error);
  });
  if (
    !entry.isFile() ||
    entry.isSymbolicLink() ||
    entry.nlink !== 1n ||
    entry.size < 1n ||
    entry.size > BigInt(maxBytes)
  ) {
    throw keyError(400, "FILE_UNSAFE", `${label} has an unsupported type or size`);
  }
}

async function writeExclusivePrivateFile(
  filePath: string,
  source: string | Buffer,
): Promise<void> {
  const handle = await open(
    filePath,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
    0o600,
  );
  try {
    await handle.writeFile(source, typeof source === "string" ? "utf8" : undefined);
    await handle.sync();
  } catch (error) {
    await handle.close().catch(() => undefined);
    await unlink(filePath).catch(() => undefined);
    throw error;
  }
  await handle.close();
  await hardenPrivatePath(filePath, false).catch(async (error: unknown) => {
    await unlink(filePath).catch(() => undefined);
    throw error;
  });
}

async function atomicWritePrivateFile(filePath: string, source: string): Promise<void> {
  const temporaryPath = `${filePath}.tmp-${process.pid}-${randomBytes(16).toString("hex")}`;
  await writeExclusivePrivateFile(temporaryPath, source);
  try {
    await rename(temporaryPath, filePath);
  } catch (error) {
    await unlink(temporaryPath).catch(() => undefined);
    throw error;
  }
}

async function removeKeyDirectory(directory: string): Promise<void> {
  const entry = await lstat(directory);
  if (!entry.isDirectory() || entry.isSymbolicLink()) {
    throw keyError(500, "FILE_UNSAFE", "Refusing to remove an unsafe SSH key directory");
  }
  const children = await readdir(directory, { withFileTypes: true });
  for (const child of children) {
    if (
      child.name !== "private.key" &&
      child.name !== "private.key.pub" &&
      child.name !== "public.key" &&
      child.name !== "metadata.json" &&
      child.name !== "agent_ssh_ed25519.pub"
    ) {
      throw keyError(500, "FILE_UNSAFE", "Refusing to remove an unexpected SSH key file");
    }
    await removeSingleLinkFile(path.join(directory, child.name));
  }
  await rmdir(directory);
}

async function removeSingleLinkFile(filePath: string): Promise<void> {
  const entry = await lstat(filePath);
  if (!entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1) {
    throw keyError(500, "FILE_UNSAFE", "Refusing to remove an unsafe SSH key file");
  }
  await unlink(filePath);
}

function mergeManifestWithPublishedRecords(
  manifestRecords: readonly ManagedSshKeyRecord[],
  publishedRecords: readonly ManagedSshKeyRecord[],
): ManagedSshKeyRecord[] {
  const published = new Map(publishedRecords.map((record) => [record.keyId, record]));
  const merged: ManagedSshKeyRecord[] = [];
  for (const manifestRecord of manifestRecords) {
    const material = published.get(manifestRecord.keyId);
    if (material === undefined) {
      throw keyError(
        500,
        "KEY_STORAGE_INVALID",
        "The SSH key manifest references missing key material",
      );
    }
    if (
      material.algorithm !== manifestRecord.algorithm ||
      material.fingerprint !== manifestRecord.fingerprint ||
      material.publicKey !== manifestRecord.publicKey ||
      material.createdAt !== manifestRecord.createdAt ||
      material.origin !== manifestRecord.origin
    ) {
      throw keyError(
        500,
        "KEY_STORAGE_INVALID",
        "The SSH key manifest does not match stored key material",
      );
    }
    merged.push({ ...material, label: manifestRecord.label });
    published.delete(manifestRecord.keyId);
  }
  for (const orphan of published.values()) {
    merged.push({
      ...orphan,
      label: uniqueMigrationLabel(orphan.label, merged),
    });
  }
  return sortedRecords(merged);
}

function assertUniqueRecords(records: readonly ManagedSshKeyRecord[]): void {
  const ids = new Set<string>();
  const labels = new Set<string>();
  const fingerprints = new Set<string>();
  for (const record of records) {
    if (
      ids.has(record.keyId) ||
      labels.has(comparableLabel(record.label)) ||
      fingerprints.has(record.fingerprint)
    ) {
      throw keyError(
        500,
        "KEY_STORAGE_INVALID",
        "The SSH key library contains duplicate records",
      );
    }
    ids.add(record.keyId);
    labels.add(comparableLabel(record.label));
    fingerprints.add(record.fingerprint);
  }
}

function uniqueMigrationLabel(
  requested: string,
  existing: Iterable<ManagedSshKeyRecord>,
): string {
  const labels = new Set([...existing].map((record) => comparableLabel(record.label)));
  if (!labels.has(comparableLabel(requested))) {
    return requested;
  }
  for (let suffix = 2; suffix <= 9_999; suffix += 1) {
    const addition = ` (${suffix})`;
    const candidate = `${requested.slice(0, 128 - addition.length)}${addition}`;
    if (!labels.has(comparableLabel(candidate))) {
      return candidate;
    }
  }
  throw keyError(409, "KEY_NAME_EXISTS", "A unique SSH key label could not be assigned");
}

function comparableLabel(label: string): string {
  return label.normalize("NFKC").toLocaleLowerCase("en-US");
}

function sortedRecords(records: Iterable<ManagedSshKeyRecord>): ManagedSshKeyRecord[] {
  return [...records].sort((left, right) =>
    left.label.localeCompare(right.label) || left.keyId.localeCompare(right.keyId),
  );
}

function sameRecords(
  left: readonly ManagedSshKeyRecord[],
  right: readonly ManagedSshKeyRecord[],
): boolean {
  return JSON.stringify(sortedRecords(left)) === JSON.stringify(sortedRecords(right));
}

function createKeyRevision(): string {
  return `kr-${Date.now().toString(36)}-${randomBytes(16).toString("hex")}`;
}

function keyError(
  status: number,
  code: string,
  message: string,
  cause?: unknown,
): ManagedSshKeyVaultError {
  const error = new ManagedSshKeyVaultError(status, code, message);
  if (cause !== undefined) {
    Object.defineProperty(error, "cause", { value: cause, enumerable: false });
  }
  return error;
}
