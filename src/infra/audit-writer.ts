import { randomUUID } from "node:crypto";
import {
  lstat,
  mkdir,
  open as openFile,
} from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import {
  GATEWAY_ERROR_CODES,
  GatewayError,
} from "../shared/errors.js";
import {
  TARGET_ALIAS_PATTERN,
  type ExecutionTermination,
} from "../shared/protocol.js";
import { redact } from "./redact.js";

interface AuditEventContext {
  readonly executionId: string;
  readonly target: string;
}

export interface ExecStartedAuditEvent extends AuditEventContext {
  readonly event: "exec.started";
  readonly executionId: string;
  readonly target: string;
  readonly commandSha256: string;
  readonly commandBytes: number;
}

export interface ExecCompletedAuditEvent extends AuditEventContext {
  readonly event: "exec.completed";
  readonly executionId: string;
  readonly target: string;
  readonly termination: ExecutionTermination;
  readonly exitCode: number | null;
  readonly durationMs: number;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
  readonly truncated: boolean;
}

export interface ExecCancelledAuditEvent extends AuditEventContext {
  readonly event: "exec.cancelled";
  readonly executionId: string;
  readonly target: string;
  readonly reasonCode: string;
}

export interface RegistryLoadedAuditEvent {
  readonly event: "registry.loaded";
  readonly targetCount: number;
  readonly enabledTargetCount: number;
  readonly registrySha256?: string;
}

export interface DaemonHealthAuditEvent {
  readonly event: "daemon.health";
  readonly status: "started" | "ready" | "degraded" | "stopping" | "stopped";
  readonly detailCode?: string;
}

export type ProbeKind = "target-info" | "docker-preflight";
export type ProbeResultCode =
  | "success"
  | "remote-exit"
  | "timeout"
  | "cancel"
  | "output-limit"
  | "spawn-error"
  | "invalid-response";

export interface ProbeCompletedAuditEvent {
  readonly event: "probe.completed";
  readonly target: string;
  readonly probeKind: ProbeKind;
  readonly durationMs: number;
  readonly resultCode: ProbeResultCode;
}

export type TransferDirection = "upload" | "download" | "sync";

interface TransferAuditEventContext {
  readonly runId: string;
  readonly target: string;
  readonly direction: TransferDirection;
}

export interface TransferStartedAuditEvent extends TransferAuditEventContext {
  readonly event: "transfer.started";
  readonly dryRun: boolean;
}

export interface TransferCompletedAuditEvent extends TransferAuditEventContext {
  readonly event: "transfer.completed";
  readonly files: number;
  readonly bytes: number;
}

export interface TransferFailedAuditEvent extends TransferAuditEventContext {
  readonly event: "transfer.failed";
  readonly reasonCode: string;
}

export type AuditEvent =
  | ExecStartedAuditEvent
  | ExecCompletedAuditEvent
  | ExecCancelledAuditEvent
  | RegistryLoadedAuditEvent
  | DaemonHealthAuditEvent
  | ProbeCompletedAuditEvent
  | TransferStartedAuditEvent
  | TransferCompletedAuditEvent
  | TransferFailedAuditEvent;

export interface AuditRecord extends Readonly<Record<string, unknown>> {
  readonly schemaVersion: 1;
  readonly eventId: string;
  readonly timestamp: string;
  readonly event: AuditEvent["event"];
}

export interface AuditWriterOptions {
  readonly filePath: string;
  readonly maxBytes?: number;
  readonly maxConcurrentExecutions?: number;
  readonly maxConcurrentTransfers?: number;
  readonly now?: () => number;
  readonly createEventId?: () => string;
}

export class AuditSchemaError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "AuditSchemaError";
  }
}

export class AuditWriteError extends GatewayError {
  public constructor(options: ErrorOptions = {}) {
    super(
      GATEWAY_ERROR_CODES.auditUnavailable,
      "Audit log is unavailable",
      options,
    );
    this.name = "AuditWriteError";
  }
}

const COMMON_KEYS = ["event"] as const;
const EVENT_KEYS: Readonly<Record<AuditEvent["event"], readonly string[]>> = {
  "exec.started": ["executionId", "target", "commandSha256", "commandBytes"],
  "exec.completed": [
    "executionId",
    "target",
    "termination",
    "exitCode",
    "durationMs",
    "stdoutBytes",
    "stderrBytes",
    "truncated",
  ],
  "exec.cancelled": ["executionId", "target", "reasonCode"],
  "registry.loaded": [
    "targetCount",
    "enabledTargetCount",
    "registrySha256",
  ],
  "daemon.health": ["status", "detailCode"],
  "probe.completed": ["target", "probeKind", "durationMs", "resultCode"],
  "transfer.started": ["runId", "target", "direction", "dryRun"],
  "transfer.completed": ["runId", "target", "direction", "files", "bytes"],
  "transfer.failed": ["runId", "target", "direction", "reasonCode"],
};
const EXECUTION_TERMINATIONS = new Set<ExecutionTermination>([
  "exit",
  "timeout",
  "cancel",
  "output_limit",
  "spawn_error",
]);
const DAEMON_STATUSES = new Set([
  "started",
  "ready",
  "degraded",
  "stopping",
  "stopped",
]);
const PROBE_KINDS = new Set<ProbeKind>([
  "target-info",
  "docker-preflight",
]);
const PROBE_RESULT_CODES = new Set<ProbeResultCode>([
  "success",
  "remote-exit",
  "timeout",
  "cancel",
  "output-limit",
  "spawn-error",
  "invalid-response",
]);
const TRANSFER_DIRECTIONS = new Set<TransferDirection>([
  "upload",
  "download",
  "sync",
]);
const SAFE_CODE_PATTERN = /^[a-z][a-z0-9_.-]{0,63}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const EXECUTION_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TASK_RUN_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const MAX_AUDIT_RECORD_BYTES = 4_096;
const DAEMON_SHUTDOWN_HEADROOM_BYTES = MAX_AUDIT_RECORD_BYTES * 2;

function isNodeError(error: unknown, code: string): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === code
  );
}

function requirePlainRecord(value: unknown): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null)
  ) {
    throw new AuditSchemaError("Audit event must be a plain object");
  }
  return value as Record<string, unknown>;
}

function requireOwnValue(
  record: Record<string, unknown>,
  key: string,
): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (descriptor === undefined || !("value" in descriptor)) {
    throw new AuditSchemaError(`Audit field ${key} is required`);
  }
  return descriptor.value;
}

function optionalOwnValue(
  record: Record<string, unknown>,
  key: string,
): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (descriptor === undefined) {
    return undefined;
  }
  if (!("value" in descriptor)) {
    throw new AuditSchemaError(`Audit field ${key} must not be an accessor`);
  }
  return descriptor.value;
}

function requireString(
  value: unknown,
  key: string,
  maximumLength: number,
): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumLength
  ) {
    throw new AuditSchemaError(
      `Audit field ${key} must be a non-empty bounded string`,
    );
  }
  return value;
}

function requireNonNegativeSafeInteger(
  value: unknown,
  key: string,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new AuditSchemaError(
      `Audit field ${key} must be a non-negative safe integer`,
    );
  }
  return value as number;
}

function requireExecutionId(value: unknown): string {
  const executionId = requireString(value, "executionId", 36);
  if (EXECUTION_ID_PATTERN.test(executionId)) {
    return executionId;
  }
  throw new AuditSchemaError("Audit field executionId is invalid");
}

function requireTaskRunId(value: unknown): string {
  const runId = requireString(value, "runId", 43);
  if (TASK_RUN_ID_PATTERN.test(runId)) {
    return runId;
  }
  throw new AuditSchemaError("Audit field runId is invalid");
}

function copyContext(
  input: Record<string, unknown>,
  output: Record<string, unknown>,
  requireExecutionContext: boolean,
): void {
  const executionId = optionalOwnValue(input, "executionId");
  const target = optionalOwnValue(input, "target");
  if (requireExecutionContext && executionId === undefined) {
    throw new AuditSchemaError("Audit field executionId is required");
  }
  if (requireExecutionContext && target === undefined) {
    throw new AuditSchemaError("Audit field target is required");
  }
  if (executionId !== undefined) {
    output.executionId = requireExecutionId(executionId);
  }
  if (target !== undefined) {
    const publicTarget = requireString(target, "target", 128);
    if (!TARGET_ALIAS_PATTERN.test(publicTarget)) {
      throw new AuditSchemaError("Audit field target is invalid");
    }
    output.target = publicTarget;
  }
}

function normalizeAuditEvent(
  event: AuditEvent,
  now: () => number,
  createEventId: () => string,
): AuditRecord {
  const input = requirePlainRecord(event);
  const eventName = requireString(
    requireOwnValue(input, "event"),
    "event",
    64,
  ) as AuditEvent["event"];
  if (!Object.hasOwn(EVENT_KEYS, eventName)) {
    throw new AuditSchemaError("Audit event type is not allowed");
  }

  const allowedKeys = new Set<string>([
    ...COMMON_KEYS,
    ...EVENT_KEYS[eventName],
  ]);
  for (const key of Object.keys(input)) {
    if (!allowedKeys.has(key)) {
      throw new AuditSchemaError(`Audit field ${key} is not allowed`);
    }
  }

  const eventId = requireString(createEventId(), "eventId", 128);
  const nowMs = now();
  if (!Number.isFinite(nowMs)) {
    throw new AuditSchemaError("Audit timestamp source is invalid");
  }
  const timestamp = new Date(nowMs).toISOString();
  const normalized: Record<string, unknown> = {
    schemaVersion: 1,
    eventId,
    timestamp,
    event: eventName,
  };

  const isExecutionEvent = eventName.startsWith("exec.");
  copyContext(input, normalized, isExecutionEvent);
  if (eventName.startsWith("transfer.")) {
    requireOwnValue(input, "target");
    normalized.runId = requireTaskRunId(requireOwnValue(input, "runId"));
    const direction = requireString(
      requireOwnValue(input, "direction"),
      "direction",
      16,
    ) as TransferDirection;
    if (!TRANSFER_DIRECTIONS.has(direction)) {
      throw new AuditSchemaError("Audit field direction is invalid");
    }
    normalized.direction = direction;
  }

  switch (eventName) {
    case "exec.started": {
      const commandSha256 = requireString(
        requireOwnValue(input, "commandSha256"),
        "commandSha256",
        64,
      );
      if (!SHA256_PATTERN.test(commandSha256)) {
        throw new AuditSchemaError("Audit field commandSha256 is invalid");
      }
      normalized.commandSha256 = commandSha256;
      normalized.commandBytes = requireNonNegativeSafeInteger(
        requireOwnValue(input, "commandBytes"),
        "commandBytes",
      );
      break;
    }
    case "exec.completed": {
      const termination = requireString(
        requireOwnValue(input, "termination"),
        "termination",
        32,
      ) as ExecutionTermination;
      if (!EXECUTION_TERMINATIONS.has(termination)) {
        throw new AuditSchemaError("Audit field termination is invalid");
      }
      const exitCode = requireOwnValue(input, "exitCode");
      if (
        exitCode !== null &&
        (!Number.isInteger(exitCode) ||
          (exitCode as number) < 0 ||
          (exitCode as number) > 4_294_967_295)
      ) {
        throw new AuditSchemaError("Audit field exitCode is invalid");
      }
      const truncated = requireOwnValue(input, "truncated");
      if (typeof truncated !== "boolean") {
        throw new AuditSchemaError("Audit field truncated must be boolean");
      }
      normalized.termination = termination;
      normalized.exitCode = exitCode;
      normalized.durationMs = requireNonNegativeSafeInteger(
        requireOwnValue(input, "durationMs"),
        "durationMs",
      );
      normalized.stdoutBytes = requireNonNegativeSafeInteger(
        requireOwnValue(input, "stdoutBytes"),
        "stdoutBytes",
      );
      normalized.stderrBytes = requireNonNegativeSafeInteger(
        requireOwnValue(input, "stderrBytes"),
        "stderrBytes",
      );
      normalized.truncated = truncated;
      break;
    }
    case "exec.cancelled": {
      const reasonCode = requireString(
        requireOwnValue(input, "reasonCode"),
        "reasonCode",
        64,
      );
      if (!SAFE_CODE_PATTERN.test(reasonCode)) {
        throw new AuditSchemaError("Audit field reasonCode is invalid");
      }
      normalized.reasonCode = reasonCode;
      break;
    }
    case "registry.loaded": {
      normalized.targetCount = requireNonNegativeSafeInteger(
        requireOwnValue(input, "targetCount"),
        "targetCount",
      );
      normalized.enabledTargetCount = requireNonNegativeSafeInteger(
        requireOwnValue(input, "enabledTargetCount"),
        "enabledTargetCount",
      );
      const registrySha256 = optionalOwnValue(input, "registrySha256");
      if (registrySha256 !== undefined) {
        const hash = requireString(registrySha256, "registrySha256", 64);
        if (!SHA256_PATTERN.test(hash)) {
          throw new AuditSchemaError("Audit field registrySha256 is invalid");
        }
        normalized.registrySha256 = hash;
      }
      break;
    }
    case "daemon.health": {
      const status = requireString(
        requireOwnValue(input, "status"),
        "status",
        32,
      );
      if (!DAEMON_STATUSES.has(status)) {
        throw new AuditSchemaError("Audit field status is invalid");
      }
      normalized.status = status;
      const detailCode = optionalOwnValue(input, "detailCode");
      if (detailCode !== undefined) {
        const code = requireString(detailCode, "detailCode", 64);
        if (!SAFE_CODE_PATTERN.test(code)) {
          throw new AuditSchemaError("Audit field detailCode is invalid");
        }
        normalized.detailCode = code;
      }
      break;
    }
    case "probe.completed": {
      requireOwnValue(input, "target");
      const probeKind = requireString(
        requireOwnValue(input, "probeKind"),
        "probeKind",
        32,
      ) as ProbeKind;
      if (!PROBE_KINDS.has(probeKind)) {
        throw new AuditSchemaError("Audit field probeKind is invalid");
      }
      const resultCode = requireString(
        requireOwnValue(input, "resultCode"),
        "resultCode",
        32,
      ) as ProbeResultCode;
      if (!PROBE_RESULT_CODES.has(resultCode)) {
        throw new AuditSchemaError("Audit field resultCode is invalid");
      }
      normalized.probeKind = probeKind;
      normalized.durationMs = requireNonNegativeSafeInteger(
        requireOwnValue(input, "durationMs"),
        "durationMs",
      );
      normalized.resultCode = resultCode;
      break;
    }
    case "transfer.started": {
      const dryRun = requireOwnValue(input, "dryRun");
      if (typeof dryRun !== "boolean") {
        throw new AuditSchemaError("Audit field dryRun must be boolean");
      }
      normalized.dryRun = dryRun;
      break;
    }
    case "transfer.completed": {
      normalized.files = requireNonNegativeSafeInteger(
        requireOwnValue(input, "files"),
        "files",
      );
      normalized.bytes = requireNonNegativeSafeInteger(
        requireOwnValue(input, "bytes"),
        "bytes",
      );
      break;
    }
    case "transfer.failed": {
      const reasonCode = requireString(
        requireOwnValue(input, "reasonCode"),
        "reasonCode",
        64,
      );
      if (!SAFE_CODE_PATTERN.test(reasonCode)) {
        throw new AuditSchemaError("Audit field reasonCode is invalid");
      }
      normalized.reasonCode = reasonCode;
      break;
    }
  }

  return normalized as AuditRecord;
}

export class AuditWriter {
  readonly #filePath: string;
  readonly #now: () => number;
  readonly #createEventId: () => string;
  readonly #maxBytes: number;
  readonly #normalWriteLimitBytes: number;
  #handlePromise: Promise<FileHandle> | undefined;
  #tail: Promise<void> = Promise.resolve();
  #closed = false;

  public constructor(options: AuditWriterOptions) {
    if (options.filePath.trim().length === 0) {
      throw new RangeError("filePath must not be empty");
    }
    this.#filePath = resolve(options.filePath);
    this.#maxBytes = options.maxBytes ?? Number.MAX_SAFE_INTEGER;
    const maxConcurrentExecutions = options.maxConcurrentExecutions ?? 32;
    const maxConcurrentTransfers =
      options.maxConcurrentTransfers ?? maxConcurrentExecutions;
    if (!Number.isSafeInteger(this.#maxBytes) || this.#maxBytes < 1) {
      throw new RangeError("maxBytes must be a positive safe integer");
    }
    if (
      !Number.isSafeInteger(maxConcurrentExecutions) ||
      maxConcurrentExecutions < 1
    ) {
      throw new RangeError(
        "maxConcurrentExecutions must be a positive safe integer",
      );
    }
    if (
      !Number.isSafeInteger(maxConcurrentTransfers) ||
      maxConcurrentTransfers < 1
    ) {
      throw new RangeError(
        "maxConcurrentTransfers must be a positive safe integer",
      );
    }
    const completionHeadroomBytes =
      (maxConcurrentExecutions * 2 + maxConcurrentTransfers) *
      MAX_AUDIT_RECORD_BYTES;
    this.#normalWriteLimitBytes =
      this.#maxBytes -
      completionHeadroomBytes -
      DAEMON_SHUTDOWN_HEADROOM_BYTES;
    if (this.#normalWriteLimitBytes < MAX_AUDIT_RECORD_BYTES) {
      throw new RangeError(
        "maxBytes is too small for the configured execution concurrency",
      );
    }
    this.#now = options.now ?? Date.now;
    this.#createEventId = options.createEventId ?? randomUUID;
  }

  /**
   * Resolves only after the JSONL record has been appended and synchronized.
   * Callers must await exec.started before launching the SSH process.
   */
  public async write(event: AuditEvent): Promise<void> {
    if (this.#closed) {
      throw new AuditWriteError();
    }
    const record = normalizeAuditEvent(event, this.#now, this.#createEventId);
    const serialized = JSON.stringify(redact(record));
    if (serialized === undefined) {
      throw new AuditSchemaError("Audit event could not be serialized");
    }
    const frame = Buffer.from(`${serialized}\n`, "utf8");
    if (frame.byteLength > MAX_AUDIT_RECORD_BYTES) {
      throw new AuditSchemaError("Audit record exceeds the fixed size limit");
    }

    const operation = this.#tail.then(async () => {
      try {
        const handle = await this.#getHandle();
        const fileStats = await handle.stat();
        const writeLimit = isAuditFollowupRecord(record)
          ? this.#maxBytes
          : this.#normalWriteLimitBytes;
        if (
          !Number.isSafeInteger(fileStats.size) ||
          fileStats.size > writeLimit - frame.byteLength
        ) {
          throw new AuditWriteError({
            cause: new Error("Audit log size limit reached"),
          });
        }
        await handle.appendFile(frame);
        await handle.sync();
      } catch (error) {
        if (error instanceof AuditWriteError) {
          throw error;
        }
        throw new AuditWriteError({ cause: error });
      }
    });
    this.#tail = operation.catch(() => undefined);
    return operation;
  }

  public async flush(): Promise<void> {
    if (this.#closed) {
      throw new AuditWriteError();
    }
    const operation = this.#tail.then(async () => {
      if (this.#handlePromise === undefined) {
        return;
      }
      try {
        const handle = await this.#handlePromise;
        await handle.sync();
      } catch (error) {
        throw new AuditWriteError({ cause: error });
      }
    });
    this.#tail = operation.catch(() => undefined);
    return operation;
  }

  public async close(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    const operation = this.#tail.then(async () => {
      if (this.#handlePromise === undefined) {
        return;
      }
      try {
        const handle = await this.#handlePromise;
        await handle.sync();
        await handle.close();
      } catch (error) {
        throw new AuditWriteError({ cause: error });
      }
    });
    this.#tail = operation.catch(() => undefined);
    return operation;
  }

  #getHandle(): Promise<FileHandle> {
    this.#handlePromise ??= this.#openHandle();
    return this.#handlePromise;
  }

  async #openHandle(): Promise<FileHandle> {
    try {
      await mkdir(dirname(this.#filePath), { recursive: true, mode: 0o700 });
      try {
        const existing = await lstat(this.#filePath);
        if (existing.isSymbolicLink() || !existing.isFile()) {
          throw new Error("Audit destination is not a regular file");
        }
      } catch (error) {
        if (!isNodeError(error, "ENOENT")) {
          throw error;
        }
      }

      const handle = await openFile(this.#filePath, "a", 0o600);
      await handle.chmod(0o600);
      return handle;
    } catch (error) {
      throw new AuditWriteError({ cause: error });
    }
  }
}

function isAuditFollowupRecord(record: AuditRecord): boolean {
  return (
    record.event === "exec.cancelled" ||
    record.event === "exec.completed" ||
    record.event === "probe.completed" ||
    record.event === "transfer.completed" ||
    record.event === "transfer.failed" ||
    (record.event === "daemon.health" &&
      (record.status === "stopping" || record.status === "stopped"))
  );
}
