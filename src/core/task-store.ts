import { createHash, randomBytes } from "node:crypto";

import { GATEWAY_ERROR_CODES, GatewayError } from "../shared/errors.js";
import {
  type ExecutionTermination,
  type TaskKind,
  type TaskStartResult,
  type TaskState,
  type TaskStatusResult,
  type TaskTailResult,
} from "../shared/protocol.js";
import { completeUtf8PrefixLength } from "../shared/utf8.js";

export type TaskOutputStream = "stdout" | "stderr";

export interface TaskWorkerContext {
  readonly runId: string;
  readonly signal: AbortSignal;
  append(stream: TaskOutputStream, chunk: Uint8Array | string): void;
}

export interface TaskCompletion {
  readonly termination?: ExecutionTermination;
  readonly exitCode?: number | null;
  readonly result?: Readonly<Record<string, unknown>>;
}

export interface StartTaskOptions {
  readonly kind: TaskKind;
  readonly target: string;
  readonly timeoutMs?: number;
  readonly worker: (context: TaskWorkerContext) => Promise<TaskCompletion>;
}

export interface TaskStoreOptions {
  readonly ttlMs: number;
  readonly maxRetainedTasks: number;
  readonly maxConcurrentTasks: number;
  readonly maxLogBytesPerStream?: number;
  readonly now?: () => number;
  readonly createRunId?: () => string;
}

interface InternalTask {
  readonly runId: string;
  readonly target: string;
  readonly kind: TaskKind;
  readonly startedAtMs: number;
  readonly controller: AbortController;
  readonly stdout: RollingByteLog;
  readonly stderr: RollingByteLog;
  state: TaskState;
  updatedAtMs: number;
  finishedAtMs?: number;
  expiresAtMs?: number;
  termination?: ExecutionTermination;
  exitCode?: number | null;
  result?: Readonly<Record<string, unknown>>;
  error?: Readonly<{ gatewayCode: string; message: string }>;
  requestedStop?: "cancelled" | "timed_out";
  completion?: Promise<void>;
}

interface TaskCursor {
  readonly v: 2;
  readonly o: number;
  readonly e: number;
  readonly b: string;
}

const DEFAULT_MAX_LOG_BYTES = 1_048_576;
const RUN_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/u;

export class TaskStore {
  readonly #ttlMs: number;
  readonly #maxRetainedTasks: number;
  readonly #maxConcurrentTasks: number;
  readonly #maxLogBytesPerStream: number;
  readonly #now: () => number;
  readonly #createRunId: () => string;
  readonly #tasks = new Map<string, InternalTask>();
  #closing = false;

  public get activeCount(): number {
    return [...this.#tasks.values()].filter(
      (task) => task.state === "running",
    ).length;
  }

  public constructor(options: TaskStoreOptions) {
    requirePositiveInteger(options.ttlMs, "ttlMs");
    requirePositiveInteger(options.maxRetainedTasks, "maxRetainedTasks");
    requirePositiveInteger(options.maxConcurrentTasks, "maxConcurrentTasks");
    requirePositiveInteger(
      options.maxLogBytesPerStream ?? DEFAULT_MAX_LOG_BYTES,
      "maxLogBytesPerStream",
    );
    this.#ttlMs = options.ttlMs;
    this.#maxRetainedTasks = options.maxRetainedTasks;
    this.#maxConcurrentTasks = options.maxConcurrentTasks;
    this.#maxLogBytesPerStream =
      options.maxLogBytesPerStream ?? DEFAULT_MAX_LOG_BYTES;
    this.#now = options.now ?? Date.now;
    this.#createRunId =
      options.createRunId ?? (() => randomBytes(32).toString("base64url"));
  }

  public start(options: StartTaskOptions): TaskStartResult {
    if (this.#closing) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.executionLimitReached,
        "Gateway is stopping",
      );
    }
    if (options.timeoutMs !== undefined) {
      requirePositiveInteger(options.timeoutMs, "timeoutMs");
    }
    this.#cleanup();
    const activeCount = this.activeCount;
    if (activeCount >= this.#maxConcurrentTasks) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.executionLimitReached,
        "Task concurrency limit reached",
        { details: { maximum: this.#maxConcurrentTasks } },
      );
    }
    this.#makeRetentionRoom();

    const runId = this.#uniqueRunId();
    const startedAtMs = this.#now();
    const task: InternalTask = {
      runId,
      target: options.target,
      kind: options.kind,
      startedAtMs,
      updatedAtMs: startedAtMs,
      state: "running",
      controller: new AbortController(),
      stdout: new RollingByteLog(this.#maxLogBytesPerStream),
      stderr: new RollingByteLog(this.#maxLogBytesPerStream),
    };
    this.#tasks.set(runId, task);

    let timeout: NodeJS.Timeout | undefined;
    if (options.timeoutMs !== undefined) {
      timeout = setTimeout(() => {
        if (task.state !== "running" || task.requestedStop !== undefined) return;
        task.requestedStop = "timed_out";
        task.controller.abort();
      }, options.timeoutMs);
      timeout.unref();
    }

    const context: TaskWorkerContext = Object.freeze({
      runId,
      signal: task.controller.signal,
      append: (stream: TaskOutputStream, chunk: Uint8Array | string): void => {
        if (task.state !== "running") return;
        const bytes =
          typeof chunk === "string" ? Buffer.from(chunk, "utf8") : Buffer.from(chunk);
        task[stream].append(bytes);
        task.updatedAtMs = this.#now();
      },
    });

    const completion = Promise.resolve()
      .then(() => options.worker(context))
      .then(
        (value) => this.#complete(task, value),
        (error: unknown) => this.#fail(task, error),
      )
      .finally(() => {
        if (timeout !== undefined) clearTimeout(timeout);
      });
    task.completion = completion;

    return Object.freeze({
      runId,
      target: options.target,
      kind: options.kind,
      state: "running",
      startedAt: new Date(startedAtMs).toISOString(),
    });
  }

  public status(runId: string): TaskStatusResult {
    const task = this.#require(runId);
    const now = this.#now();
    return {
      runId: task.runId,
      target: task.target,
      kind: task.kind,
      state: task.state,
      startedAt: new Date(task.startedAtMs).toISOString(),
      updatedAt: new Date(task.updatedAtMs).toISOString(),
      ...(task.finishedAtMs === undefined
        ? {}
        : { finishedAt: new Date(task.finishedAtMs).toISOString() }),
      ...(task.expiresAtMs === undefined
        ? {}
        : { expiresAt: new Date(task.expiresAtMs).toISOString() }),
      durationMs: Math.max(
        0,
        Math.round((task.finishedAtMs ?? now) - task.startedAtMs),
      ),
      stdoutBytes: task.stdout.totalBytes,
      stderrBytes: task.stderr.totalBytes,
      ...(task.termination === undefined
        ? {}
        : { termination: task.termination }),
      ...(task.exitCode === undefined ? {} : { exitCode: task.exitCode }),
      ...(task.result === undefined ? {} : { result: { ...task.result } }),
      ...(task.error === undefined ? {} : { error: task.error }),
    };
  }

  public tail(runId: string, cursor: string | undefined, limit: number): TaskTailResult {
    requirePositiveInteger(limit, "limit");
    const task = this.#require(runId);
    const offsets =
      cursor === undefined ? { o: 0, e: 0 } : decodeCursor(cursor, runId);
    const terminal = task.state !== "running";
    const stdout = task.stdout.read(offsets.o, limit, terminal);
    const stderr = task.stderr.read(offsets.e, limit, terminal);
    const nextCursor = encodeCursor(
      runId,
      stdout.nextOffset,
      stderr.nextOffset,
    );
    return {
      runId,
      state: task.state,
      stdout: {
        text: stdout.text,
        bytesRead: stdout.bytesRead,
        totalBytes: task.stdout.totalBytes,
        droppedBytes: stdout.droppedBytes,
        hadDecodingErrors: stdout.hadDecodingErrors,
      },
      stderr: {
        text: stderr.text,
        bytesRead: stderr.bytesRead,
        totalBytes: task.stderr.totalBytes,
        droppedBytes: stderr.droppedBytes,
        hadDecodingErrors: stderr.hadDecodingErrors,
      },
      nextCursor,
      eof:
        terminal &&
        stdout.nextOffset >= task.stdout.totalBytes &&
        stderr.nextOffset >= task.stderr.totalBytes,
    };
  }

  public cancel(runId: string): { runId: string; accepted: boolean; state: TaskState } {
    const task = this.#require(runId);
    if (task.state !== "running" || task.requestedStop !== undefined) {
      return { runId, accepted: false, state: task.state };
    }
    task.requestedStop = "cancelled";
    task.controller.abort();
    return { runId, accepted: true, state: task.state };
  }

  public async shutdown(): Promise<void> {
    this.#closing = true;
    const completions: Promise<void>[] = [];
    for (const task of this.#tasks.values()) {
      if (task.state === "running") {
        task.requestedStop ??= "cancelled";
        task.controller.abort();
        if (task.completion !== undefined) completions.push(task.completion);
      }
    }
    await Promise.all(completions);
  }

  #complete(task: InternalTask, completion: TaskCompletion): void {
    if (completion.result !== undefined) {
      task.result = completion.result;
    }
    if (task.requestedStop !== undefined) {
      task.state = task.requestedStop;
      task.termination = task.requestedStop === "timed_out" ? "timeout" : "cancel";
      task.exitCode = null;
    } else {
      if (completion.termination !== undefined) {
        task.termination = completion.termination;
      }
      if (completion.exitCode !== undefined) {
        task.exitCode = completion.exitCode;
      }
      task.state = stateForTermination(completion.termination, completion.exitCode);
    }
    this.#finish(task);
  }

  #fail(task: InternalTask, error: unknown): void {
    if (task.requestedStop !== undefined) {
      task.state = task.requestedStop;
      task.termination = task.requestedStop === "timed_out" ? "timeout" : "cancel";
      task.exitCode = null;
    } else {
      task.state = "failed";
      if (error instanceof GatewayError) {
        task.error = { gatewayCode: error.code, message: error.message };
      } else {
        task.error = {
          gatewayCode: GATEWAY_ERROR_CODES.internalError,
          message: "Task failed inside the SSH Gateway",
        };
      }
    }
    this.#finish(task);
  }

  #finish(task: InternalTask): void {
    const finishedAtMs = this.#now();
    task.finishedAtMs = finishedAtMs;
    task.updatedAtMs = finishedAtMs;
    task.expiresAtMs = finishedAtMs + this.#ttlMs;
  }

  #require(runId: string): InternalTask {
    this.#cleanup();
    if (!RUN_ID_PATTERN.test(runId)) {
      throw taskNotFound();
    }
    const task = this.#tasks.get(runId);
    if (task === undefined) throw taskNotFound();
    return task;
  }

  #cleanup(): void {
    const now = this.#now();
    for (const [runId, task] of this.#tasks) {
      if (task.expiresAtMs !== undefined && task.expiresAtMs <= now) {
        this.#tasks.delete(runId);
      }
    }
  }

  #makeRetentionRoom(): void {
    while (this.#tasks.size >= this.#maxRetainedTasks) {
      const terminal = [...this.#tasks.values()]
        .filter((task) => task.state !== "running")
        .sort((left, right) =>
          (left.finishedAtMs ?? 0) - (right.finishedAtMs ?? 0),
        )[0];
      if (terminal === undefined) {
        throw new GatewayError(
          GATEWAY_ERROR_CODES.executionLimitReached,
          "Task retention limit reached",
          { details: { maximum: this.#maxRetainedTasks } },
        );
      }
      this.#tasks.delete(terminal.runId);
    }
  }

  #uniqueRunId(): string {
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const runId = this.#createRunId();
      if (!RUN_ID_PATTERN.test(runId)) {
        throw new Error("Task run ID source returned an invalid value");
      }
      if (!this.#tasks.has(runId)) return runId;
    }
    throw new Error("Could not allocate a unique task run ID");
  }
}

class RollingByteLog {
  readonly #limit: number;
  #buffer = Buffer.alloc(0);
  #startOffset = 0;
  #totalBytes = 0;

  public constructor(limit: number) {
    this.#limit = limit;
  }

  public get totalBytes(): number {
    return this.#totalBytes;
  }

  public append(chunk: Buffer): void {
    this.#totalBytes += chunk.byteLength;
    this.#buffer = Buffer.concat([this.#buffer, chunk]);
    if (this.#buffer.byteLength > this.#limit) {
      const overflow = this.#buffer.byteLength - this.#limit;
      this.#buffer = this.#buffer.subarray(overflow);
      this.#startOffset += overflow;
    }
  }

  public read(
    requestedOffset: number,
    limit: number,
    terminal: boolean,
  ): {
    readonly text: string;
    readonly bytesRead: number;
    readonly droppedBytes: number;
    readonly nextOffset: number;
    readonly hadDecodingErrors: boolean;
  } {
    if (!Number.isSafeInteger(requestedOffset) || requestedOffset < 0) {
      throw invalidCursor();
    }
    if (requestedOffset > this.#totalBytes) throw invalidCursor();
    const effectiveOffset = Math.max(requestedOffset, this.#startOffset);
    const droppedBytes = effectiveOffset - requestedOffset;
    const relative = effectiveOffset - this.#startOffset;
    let bytes = this.#buffer.subarray(
      relative,
      Math.min(this.#buffer.byteLength, relative + limit),
    );
    const completeBytes = completeUtf8PrefixLength(bytes);
    if (bytes.byteLength > 0 && completeBytes === 0) {
      const partialLength = bytes.byteLength - completeBytes;
      const expectedLength = utf8SequenceLength(bytes[completeBytes]!);
      const missingBytes = Math.max(0, expectedLength - partialLength);
      if (missingBytes > 0) {
        bytes = this.#buffer.subarray(
          relative,
          Math.min(
            this.#buffer.byteLength,
            relative + bytes.byteLength + missingBytes,
          ),
        );
      }
    }
    if (!terminal || effectiveOffset + bytes.byteLength < this.#totalBytes) {
      bytes = bytes.subarray(0, completeUtf8PrefixLength(bytes));
    }
    const hadDecodingErrors = !isValidUtf8(bytes);
    return {
      text: bytes.toString("utf8"),
      bytesRead: bytes.byteLength,
      droppedBytes,
      nextOffset: effectiveOffset + bytes.byteLength,
      hadDecodingErrors,
    };
  }
}

function stateForTermination(
  termination: ExecutionTermination | undefined,
  exitCode: number | null | undefined,
): TaskState {
  if (termination === "timeout") return "timed_out";
  if (termination === "cancel") return "cancelled";
  if (termination === "exit" && exitCode === 0) return "succeeded";
  return termination === undefined ? "succeeded" : "failed";
}

function encodeCursor(
  runId: string,
  stdoutOffset: number,
  stderrOffset: number,
): string {
  const cursor: TaskCursor = {
    v: 2,
    o: stdoutOffset,
    e: stderrOffset,
    b: taskCursorBinding(runId, stdoutOffset, stderrOffset),
  };
  return Buffer.from(JSON.stringify(cursor), "utf8").toString("base64url");
}

function decodeCursor(value: string, runId: string): TaskCursor {
  try {
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as unknown;
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed) ||
      Object.keys(parsed).sort().join(",") !== "b,e,o,v" ||
      (parsed as { v?: unknown }).v !== 2 ||
      !Number.isSafeInteger((parsed as { o?: unknown }).o) ||
      ((parsed as { o: number }).o < 0) ||
      !Number.isSafeInteger((parsed as { e?: unknown }).e) ||
      ((parsed as { e: number }).e < 0) ||
      typeof (parsed as { b?: unknown }).b !== "string"
    ) {
      throw new Error("invalid cursor");
    }
    const cursor = parsed as TaskCursor;
    if (
      cursor.b !== taskCursorBinding(runId, cursor.o, cursor.e)
    ) {
      throw new Error("invalid cursor binding");
    }
    return cursor;
  } catch {
    throw invalidCursor();
  }
}

function taskCursorBinding(
  runId: string,
  stdoutOffset: number,
  stderrOffset: number,
): string {
  return createHash("sha256")
    .update("agent-ssh-task-cursor-v2\0", "utf8")
    .update(runId, "utf8")
    .update("\0", "utf8")
    .update(String(stdoutOffset), "utf8")
    .update("\0", "utf8")
    .update(String(stderrOffset), "utf8")
    .digest("base64url")
    .slice(0, 22);
}

function utf8SequenceLength(lead: number): number {
  if (lead >= 0xc2 && lead <= 0xdf) return 2;
  if (lead >= 0xe0 && lead <= 0xef) return 3;
  if (lead >= 0xf0 && lead <= 0xf4) return 4;
  return 1;
}

function isValidUtf8(bytes: Buffer): boolean {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return true;
  } catch {
    return false;
  }
}

function invalidCursor(): GatewayError {
  return new GatewayError(GATEWAY_ERROR_CODES.invalidParams, "Task cursor is invalid");
}

function taskNotFound(): GatewayError {
  return new GatewayError(
    GATEWAY_ERROR_CODES.executionNotFound,
    "Task was not found or has expired",
  );
}

function requirePositiveInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${name} must be a positive safe integer`);
  }
}
