import { performance } from "node:perf_hooks";
import type { Readable } from "node:stream";

import {
  MAX_MANAGED_STDIN_BYTES,
  ProcessTreeAbortError,
  spawnManagedProcess,
  type ManagedProcess,
  type ManagedProcessOptions,
  WINDOWS_SUPERVISOR_FAILURE_EXIT_CODE,
} from "./process-tree.js";
import {
  SshExecutionError,
  type OutputSink,
  type OutputStream,
  type SshOutcome,
} from "./ssh-runner.js";

export interface ManagedCommandOptions {
  readonly executable: string;
  readonly maxCapturedOutputBytes?: number;
  readonly cwd?: string;
  readonly environment?: NodeJS.ProcessEnv;
  readonly windowsSupervisorPath?: string;
  readonly allowUnsafeProcessTermination?: boolean;
}

export interface ManagedCommandInput {
  readonly arguments: readonly string[];
  readonly stdin?: Uint8Array;
  readonly signal?: AbortSignal;
  readonly outputSink?: OutputSink;
  readonly maxCapturedOutputBytes?: number;
}

export interface ManagedCommandDependencies {
  readonly spawnProcess?: (
    options: ManagedProcessOptions,
  ) => Promise<ManagedProcess>;
}

const DEFAULT_CAPTURE_BYTES = 64 * 1024;

export async function executeManagedCommand(
  options: ManagedCommandOptions,
  input: ManagedCommandInput,
  dependencies: ManagedCommandDependencies = {},
): Promise<SshOutcome> {
  validateManagedCommandOptions(options);
  validateManagedCommandInput(input);
  const startedAt = performance.now();
  const captureLimit =
    input.maxCapturedOutputBytes ??
    options.maxCapturedOutputBytes ??
    DEFAULT_CAPTURE_BYTES;
  validateByteLimit(captureLimit, "maxCapturedOutputBytes");

  if (isSignalAborted(input.signal)) {
    return emptyAbortedOutcome(performance.now() - startedAt);
  }

  const managedOptions: ManagedProcessOptions = {
    executable: options.executable,
    arguments: input.arguments,
    ...(input.stdin === undefined ? {} : { stdinPayload: Buffer.from(input.stdin) }),
    ...(input.signal === undefined ? {} : { signal: input.signal }),
    ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
    ...(options.environment === undefined
      ? {}
      : { environment: options.environment }),
    ...(options.windowsSupervisorPath === undefined
      ? {}
      : { windowsSupervisorPath: options.windowsSupervisorPath }),
    ...(options.allowUnsafeProcessTermination === undefined
      ? {}
      : {
          allowUnsafeProcessTermination: options.allowUnsafeProcessTermination,
        }),
  };

  let managed: ManagedProcess;
  try {
    managed = await (dependencies.spawnProcess ?? spawnManagedProcess)(
      managedOptions,
    );
  } catch (error: unknown) {
    if (error instanceof ProcessTreeAbortError) {
      return emptyAbortedOutcome(performance.now() - startedAt);
    }
    throw new SshExecutionError("failed to prepare the managed SSH process", {
      cause: error,
    });
  }

  const { child } = managed;
  let closed = false;
  let abortRequested = false;
  let processError: Error | undefined;
  let outputError: unknown;
  let terminationError: unknown;
  let termination: Promise<void> | undefined;

  const requestTermination = (): Promise<void> => {
    termination ??= managed.terminate().catch((error: unknown) => {
      terminationError = error;
    });
    return termination;
  };
  const onAbort = (): void => {
    if (closed) return;
    abortRequested = true;
    void requestTermination();
  };
  input.signal?.addEventListener("abort", onAbort, { once: true });
  if (isSignalAborted(input.signal)) onAbort();

  const stdoutCapture = new OutputCapture(captureLimit);
  const stderrCapture = new OutputCapture(captureLimit);
  const stdoutPump = pumpOutput(
    child.stdout,
    "stdout",
    stdoutCapture,
    input.outputSink,
  ).catch((error: unknown) => {
    outputError ??= error;
    void requestTermination();
  });
  const stderrPump = pumpOutput(
    child.stderr,
    "stderr",
    stderrCapture,
    input.outputSink,
  ).catch((error: unknown) => {
    outputError ??= error;
    void requestTermination();
  });

  const closeResult = await waitForProcessClose(child, (error) => {
    processError = error;
  });
  closed = true;

  input.signal?.removeEventListener("abort", onAbort);
  await Promise.all([stdoutPump, stderrPump]);
  if (termination !== undefined) await termination;

  if (outputError !== undefined) {
    throw new SshExecutionError("the SSH output sink failed", {
      cause: outputError,
    });
  }
  if (processError !== undefined && !abortRequested) {
    throw new SshExecutionError("failed to spawn or manage the SSH process", {
      cause: processError,
    });
  }
  if (terminationError !== undefined) {
    throw new SshExecutionError("failed to terminate the SSH process tree", {
      cause: terminationError,
    });
  }
  if (
    managed.terminationMode === "windows-job" &&
    closeResult.code !== null &&
    (closeResult.code >>> 0) === WINDOWS_SUPERVISOR_FAILURE_EXIT_CODE
  ) {
    throw new SshExecutionError(
      "the Windows Job Object supervisor failed after startup",
    );
  }

  return {
    exitCode: closeResult.code,
    signal: closeResult.signal,
    stdout: stdoutCapture.toString(),
    stderr: stderrCapture.toString(),
    stdoutBytes: stdoutCapture.totalBytes,
    stderrBytes: stderrCapture.totalBytes,
    stdoutTruncated: stdoutCapture.truncated,
    stderrTruncated: stderrCapture.truncated,
    aborted: abortRequested,
    durationMs: performance.now() - startedAt,
    terminationMode: managed.terminationMode,
  };
}

export class OutputCapture {
  readonly #limit: number;
  readonly #chunks: Buffer[] = [];
  #capturedBytes = 0;
  #totalBytes = 0;

  public constructor(limit: number) {
    validateByteLimit(limit, "output capture limit");
    this.#limit = limit;
  }

  public get totalBytes(): number {
    return this.#totalBytes;
  }

  public get truncated(): boolean {
    return this.#totalBytes > this.#capturedBytes;
  }

  public append(chunk: Uint8Array): void {
    const copied = Buffer.from(chunk);
    this.#totalBytes += copied.length;
    const remaining = this.#limit - this.#capturedBytes;
    if (remaining <= 0) return;
    const captured = copied.subarray(0, Math.min(remaining, copied.length));
    this.#chunks.push(Buffer.from(captured));
    this.#capturedBytes += captured.length;
  }

  public toString(): string {
    return Buffer.concat(this.#chunks, this.#capturedBytes).toString("utf8");
  }
}

export function emptyAbortedOutcome(durationMs: number): SshOutcome {
  return {
    exitCode: null,
    signal: null,
    stdout: "",
    stderr: "",
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false,
    aborted: true,
    durationMs,
    terminationMode: null,
  };
}

async function pumpOutput(
  stream: Readable,
  channel: OutputStream,
  capture: OutputCapture,
  sink: OutputSink | undefined,
): Promise<void> {
  for await (const rawChunk of stream) {
    const chunk = Buffer.isBuffer(rawChunk)
      ? rawChunk
      : Buffer.from(rawChunk as Uint8Array);
    capture.append(chunk);
    await sink?.append(channel, Buffer.from(chunk));
  }
}

function waitForProcessClose(
  child: ManagedProcess["child"],
  onProcessError: (error: Error) => void,
): Promise<{
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
}> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (
      code: number | null,
      signal: NodeJS.Signals | null,
    ): void => {
      if (settled) return;
      settled = true;
      child.off("error", onError);
      child.off("close", onClose);
      resolve({ code, signal });
    };
    const onError = (error: Error): void => onProcessError(error);
    const onClose = (
      code: number | null,
      signal: NodeJS.Signals | null,
    ): void => finish(code, signal);

    child.once("error", onError);
    child.once("close", onClose);
    if (child.exitCode !== null || child.signalCode !== null) {
      queueMicrotask(() => finish(child.exitCode, child.signalCode));
    }
  });
}

function validateManagedCommandOptions(options: ManagedCommandOptions): void {
  if (options.executable.length === 0 || /[\0\r\n]/u.test(options.executable)) {
    throw new TypeError(
      "executable must be non-empty and must not contain control characters",
    );
  }
  if (options.maxCapturedOutputBytes !== undefined) {
    validateByteLimit(options.maxCapturedOutputBytes, "maxCapturedOutputBytes");
  }
}

function isSignalAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
}

function validateManagedCommandInput(input: ManagedCommandInput): void {
  if (
    input.arguments.some(
      (argument) => typeof argument !== "string" || /[\0\r\n]/u.test(argument),
    )
  ) {
    throw new TypeError("process arguments must not contain control characters");
  }
  if (input.stdin !== undefined && input.stdin.byteLength > MAX_MANAGED_STDIN_BYTES) {
    throw new RangeError(
      `stdin must not exceed ${MAX_MANAGED_STDIN_BYTES} bytes`,
    );
  }
  if (input.maxCapturedOutputBytes !== undefined) {
    validateByteLimit(input.maxCapturedOutputBytes, "maxCapturedOutputBytes");
  }
}

function validateByteLimit(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative safe integer`);
  }
}
