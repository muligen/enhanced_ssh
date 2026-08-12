import type { AuditEvent, AuditWriter } from "../../src/infra/audit-writer.js";
import type {
  SshExecutor,
  SshOutcome,
  SshRunInput,
} from "../../src/infra/openssh-executor.js";
import {
  OutputLimitExceededError,
  type OutputSink,
  type OutputStore,
  type StoredOutputSummary,
} from "../../src/core/output-store.js";
import { ExecService } from "../../src/core/exec-service.js";
import { TargetRegistry } from "../../src/core/target-registry.js";
import type { OutputChunk, RpcId } from "../../src/shared/protocol.js";

export interface Deferred<Value> {
  readonly promise: Promise<Value>;
  resolve(value: Value): void;
  reject(error: unknown): void;
}

export function deferred<Value>(): Deferred<Value> {
  let resolvePromise!: (value: Value) => void;
  let rejectPromise!: (error: unknown) => void;
  const promise = new Promise<Value>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  return {
    promise,
    resolve: resolvePromise,
    reject: rejectPromise,
  };
}

export function sshOutcome(
  overrides: Partial<SshOutcome> = {},
): SshOutcome {
  return {
    exitCode: 0,
    signal: null,
    stdout: "",
    stderr: "",
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false,
    aborted: false,
    durationMs: 1,
    terminationMode: null,
    ...overrides,
  };
}

export class FakeSshExecutor {
  public readonly calls: SshRunInput[] = [];
  readonly #handler: (input: SshRunInput) => Promise<SshOutcome>;

  public constructor(
    handler: (input: SshRunInput) => Promise<SshOutcome>,
  ) {
    this.#handler = handler;
  }

  public async run(input: SshRunInput): Promise<SshOutcome> {
    this.calls.push(input);
    return this.#handler(input);
  }
}

export class FakeAuditWriter {
  public readonly events: AuditEvent[] = [];
  readonly #beforeWrite:
    | ((event: AuditEvent) => Promise<void> | void)
    | undefined;

  public constructor(
    beforeWrite?: (event: AuditEvent) => Promise<void> | void,
  ) {
    this.#beforeWrite = beforeWrite;
  }

  public async write(event: AuditEvent): Promise<void> {
    await this.#beforeWrite?.(event);
    this.events.push(event);
  }
}

type OutputStream = "stdout" | "stderr";

class MemoryOutputSink implements OutputSink {
  public readonly reference: string;
  readonly #inlineBytesPerStream: number;
  readonly #maxStoredBytes: number;
  readonly #chunks: Record<OutputStream, Buffer[]> = {
    stdout: [],
    stderr: [],
  };
  #closed = false;

  public constructor(
    reference: string,
    inlineBytesPerStream: number,
    maxStoredBytes: number,
  ) {
    this.reference = reference;
    this.#inlineBytesPerStream = inlineBytesPerStream;
    this.#maxStoredBytes = maxStoredBytes;
  }

  public async append(
    stream: OutputStream,
    chunk: Uint8Array,
  ): Promise<void> {
    if (this.#closed) {
      throw new Error("Memory output sink is closed");
    }
    const copied = Buffer.from(chunk);
    const currentBytes = this.#totalBytes();
    const remainingBytes = Math.max(0, this.#maxStoredBytes - currentBytes);
    const stored = copied.subarray(0, Math.min(remainingBytes, copied.length));
    if (stored.length > 0) {
      this.#chunks[stream].push(Buffer.from(stored));
    }
    if (stored.length !== copied.length) {
      throw new OutputLimitExceededError(
        this.#maxStoredBytes,
        currentBytes,
        copied.length,
      );
    }
  }

  public async finalize(): Promise<StoredOutputSummary> {
    this.#closed = true;
    const stdout = this.#summary("stdout");
    const stderr = this.#summary("stderr");
    if (!stdout.inlineTruncated && !stderr.inlineTruncated) {
      return { stdout, stderr };
    }
    return {
      stdout,
      stderr,
      outputRef: this.reference,
      outputExpiresAt: "2099-01-01T00:00:00.000Z",
    };
  }

  public cancel(): void {
    this.#closed = true;
  }

  public async abort(): Promise<void> {
    this.cancel();
    this.#chunks.stdout.length = 0;
    this.#chunks.stderr.length = 0;
  }

  public read(stream: OutputStream, offset: number, limit: number): OutputChunk {
    const contents = Buffer.concat(this.#chunks[stream]);
    const data = contents.subarray(offset, Math.min(contents.length, offset + limit));
    const followingOffset = offset + data.length;
    const eof = followingOffset >= contents.length;
    return {
      dataBase64: data.toString("base64"),
      nextOffset: eof ? null : followingOffset,
      eof,
      totalBytes: contents.length,
    };
  }

  #summary(stream: OutputStream): StoredOutputSummary[OutputStream] {
    const contents = Buffer.concat(this.#chunks[stream]);
    return {
      text: contents.subarray(0, this.#inlineBytesPerStream).toString("utf8"),
      bytes: contents.length,
      inlineTruncated: contents.length > this.#inlineBytesPerStream,
    };
  }

  #totalBytes(): number {
    return (
      Buffer.concat(this.#chunks.stdout).length +
      Buffer.concat(this.#chunks.stderr).length
    );
  }
}

export interface MemoryOutputStoreOptions {
  readonly inlineBytesPerStream?: number;
  readonly maxStoredBytes?: number;
}

export class MemoryOutputStore {
  public readonly sinks: MemoryOutputSink[] = [];
  readonly #inlineBytesPerStream: number;
  readonly #maxStoredBytes: number;

  public constructor(options: MemoryOutputStoreOptions = {}) {
    this.#inlineBytesPerStream = options.inlineBytesPerStream ?? 1_024;
    this.#maxStoredBytes = options.maxStoredBytes ?? 1_048_576;
  }

  public async create(requestId: RpcId): Promise<OutputSink> {
    void requestId;
    const reference = Buffer.alloc(32, this.sinks.length + 1).toString(
      "base64url",
    );
    const sink = new MemoryOutputSink(
      reference,
      this.#inlineBytesPerStream,
      this.#maxStoredBytes,
    );
    this.sinks.push(sink);
    return sink;
  }

  public async read(
    reference: string,
    stream: OutputStream,
    offset: number,
    limit: number,
  ): Promise<OutputChunk> {
    const sink = this.sinks.find((candidate) => candidate.reference === reference);
    if (sink === undefined) {
      throw new Error("Output reference was not found");
    }
    return sink.read(stream, offset, limit);
  }
}

export function testRegistry(maxTimeoutMs = 5_000): TargetRegistry {
  return new TargetRegistry({
    alpha: {
      description: "Test target",
      sshAlias: "internal-alpha",
      platform: "linux",
      enabled: true,
      policy: {
        mode: "allow-list",
        allowedCommands: [
          "echo ok",
          "sleep",
          "long-command",
          "emit-output",
          "first",
          "second",
        ],
        maxTimeoutMs,
      },
    },
  });
}

export interface TestExecServiceOptions {
  readonly executor: FakeSshExecutor;
  readonly outputStore?: MemoryOutputStore;
  readonly audit?: FakeAuditWriter;
  readonly registry?: TargetRegistry;
  readonly maxConcurrentExecutions?: number;
}

export function testExecService(options: TestExecServiceOptions): ExecService {
  return new ExecService({
    registry: options.registry ?? testRegistry(),
    executor: options.executor as unknown as SshExecutor,
    outputStore: (options.outputStore ??
      new MemoryOutputStore()) as unknown as OutputStore,
    audit: (options.audit ?? new FakeAuditWriter()) as unknown as AuditWriter,
    maxConcurrentExecutions: options.maxConcurrentExecutions ?? 4,
  });
}
