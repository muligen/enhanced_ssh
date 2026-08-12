import { isUtf8 } from "node:buffer";
import path from "node:path";
import { performance } from "node:perf_hooks";
import type { Readable } from "node:stream";

import type { OutputSink, OutputStream } from "./openssh-executor.js";
import {
  MAX_MANAGED_STDIN_BYTES,
  spawnManagedProcess,
  type ManagedProcess,
  type ManagedProcessOptions,
  type ProcessTerminationMode,
  WINDOWS_SUPERVISOR_FAILURE_EXIT_CODE,
} from "./process-tree.js";
import { TARGET_ALIAS_PATTERN } from "../shared/protocol.js";

export interface SftpExecutorOptions {
  readonly executable: string;
  readonly sshExecutable: string;
  readonly configFile: string;
  readonly knownHostsFile: string;
  readonly connectTimeoutSeconds?: number;
  readonly maxCapturedOutputBytes?: number;
  readonly cwd?: string;
  readonly environment?: NodeJS.ProcessEnv;
  readonly windowsSupervisorPath?: string;
  readonly allowUnsafeProcessTermination?: boolean;
}

export interface SftpExecutorDependencies {
  readonly spawnProcess?: (
    options: ManagedProcessOptions,
  ) => Promise<ManagedProcess>;
}

export interface SftpRunInput {
  readonly sshAlias: string;
  readonly batch: string | Uint8Array;
  readonly signal?: AbortSignal;
  readonly outputSink?: OutputSink;
  readonly maxCapturedOutputBytes?: number;
}

export interface SftpOutcome {
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
  readonly stdoutTruncated: boolean;
  readonly stderrTruncated: boolean;
  readonly aborted: boolean;
  readonly durationMs: number;
  readonly terminationMode: ProcessTerminationMode | null;
}

export class SftpExecutionError extends Error {
  public override readonly cause: unknown;

  public constructor(message: string, options?: { readonly cause?: unknown }) {
    super(message);
    this.name = "SftpExecutionError";
    this.cause = options?.cause;
  }
}

const DEFAULT_CONNECT_TIMEOUT_SECONDS = 15;
const DEFAULT_CAPTURE_BYTES = 64 * 1024;
const ALLOWED_BATCH_COMMANDS = new Set([
  "bye",
  "chmod",
  "df",
  "exit",
  "get",
  "ls",
  "mkdir",
  "put",
  "pwd",
  "quit",
  "reget",
  "rename",
  "reput",
  "rm",
  "rmdir",
]);

export class SftpExecutor {
  readonly #options: SftpExecutorOptions;
  readonly #spawnProcess: (
    options: ManagedProcessOptions,
  ) => Promise<ManagedProcess>;

  public constructor(
    options: SftpExecutorOptions,
    dependencies: SftpExecutorDependencies = {},
  ) {
    validateExecutorOptions(options);
    this.#options = options;
    this.#spawnProcess = dependencies.spawnProcess ?? spawnManagedProcess;
  }

  public async run(input: SftpRunInput): Promise<SftpOutcome> {
    const batch = validateRunInput(input);
    const startedAt = performance.now();
    const captureLimit =
      input.maxCapturedOutputBytes ??
      this.#options.maxCapturedOutputBytes ??
      DEFAULT_CAPTURE_BYTES;
    validateByteLimit(captureLimit, "maxCapturedOutputBytes");

    if (isSignalAborted(input.signal)) {
      return emptyAbortedOutcome(performance.now() - startedAt);
    }

    const managedOptions: ManagedProcessOptions = {
      executable: this.#options.executable,
      arguments: buildOpenSftpArguments(this.#options, input),
      stdinPayload: batch,
      ...(this.#options.cwd === undefined ? {} : { cwd: this.#options.cwd }),
      ...(this.#options.environment === undefined
        ? {}
        : { environment: this.#options.environment }),
      ...(this.#options.windowsSupervisorPath === undefined
        ? {}
        : { windowsSupervisorPath: this.#options.windowsSupervisorPath }),
      ...(this.#options.allowUnsafeProcessTermination === undefined
        ? {}
        : {
            allowUnsafeProcessTermination:
              this.#options.allowUnsafeProcessTermination,
          }),
    };

    let managed: ManagedProcess;
    try {
      managed = await this.#spawnProcess(managedOptions);
    } catch (error: unknown) {
      throw new SftpExecutionError("failed to prepare the managed SFTP process", {
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
      if (closed) {
        return;
      }
      abortRequested = true;
      void requestTermination();
    };
    input.signal?.addEventListener("abort", onAbort, { once: true });
    if (isSignalAborted(input.signal)) {
      onAbort();
    }

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
    if (termination !== undefined) {
      await termination;
    }

    if (outputError !== undefined) {
      throw new SftpExecutionError("the SFTP output sink failed", {
        cause: outputError,
      });
    }
    if (processError !== undefined && !abortRequested) {
      throw new SftpExecutionError("failed to spawn or manage the SFTP process", {
        cause: processError,
      });
    }
    if (terminationError !== undefined) {
      throw new SftpExecutionError("failed to terminate the SFTP process tree", {
        cause: terminationError,
      });
    }
    if (
      managed.terminationMode === "windows-job" &&
      closeResult.code !== null &&
      (closeResult.code >>> 0) === WINDOWS_SUPERVISOR_FAILURE_EXIT_CODE
    ) {
      throw new SftpExecutionError(
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
}

export function buildOpenSftpArguments(
  options: Pick<
    SftpExecutorOptions,
    | "sshExecutable"
    | "configFile"
    | "knownHostsFile"
    | "connectTimeoutSeconds"
  >,
  input: Pick<SftpRunInput, "sshAlias" | "batch">,
): string[] {
  validateRequiredPaths(options);
  validateRunInput(input);
  const connectTimeout =
    options.connectTimeoutSeconds ?? DEFAULT_CONNECT_TIMEOUT_SECONDS;
  validateConnectTimeout(connectTimeout);

  return [
    "-b",
    "-",
    "-S",
    options.sshExecutable,
    "-F",
    options.configFile,
    "-o",
    "StdinNull=no",
    "-o",
    "BatchMode=yes",
    "-o",
    "NumberOfPasswordPrompts=0",
    "-o",
    "IdentityAgent=none",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "PubkeyAuthentication=yes",
    "-o",
    "PasswordAuthentication=no",
    "-o",
    "KbdInteractiveAuthentication=no",
    "-o",
    "PreferredAuthentications=publickey",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "KnownHostsCommand=none",
    "-o",
    "VerifyHostKeyDNS=no",
    "-o",
    "ConnectionAttempts=1",
    "-o",
    `ConnectTimeout=${connectTimeout}`,
    "-o",
    "ClearAllForwardings=yes",
    "-o",
    "PermitLocalCommand=no",
    "-o",
    "ForwardAgent=no",
    "-o",
    "ForwardX11=no",
    "-o",
    "ForkAfterAuthentication=no",
    "-o",
    "RequestTTY=no",
    "-o",
    "RemoteCommand=none",
    "-o",
    "AddKeysToAgent=no",
    "-o",
    "ControlMaster=no",
    "-o",
    "ControlPersist=no",
    "-o",
    "ControlPath=none",
    "-o",
    "EscapeChar=none",
    "-o",
    "EnableEscapeCommandline=no",
    "-o",
    "UpdateHostKeys=no",
    "-o",
    `UserKnownHostsFile=${quoteSshConfigValue(options.knownHostsFile)}`,
    "-o",
    "GlobalKnownHostsFile=none",
    input.sshAlias,
  ];
}

function validateExecutorOptions(options: SftpExecutorOptions): void {
  validateAbsolutePath(options.executable, "executable");
  validateRequiredPaths(options);
  if (options.connectTimeoutSeconds !== undefined) {
    validateConnectTimeout(options.connectTimeoutSeconds);
  }
  if (options.maxCapturedOutputBytes !== undefined) {
    validateByteLimit(options.maxCapturedOutputBytes, "maxCapturedOutputBytes");
  }
  if (options.cwd !== undefined) {
    validateAbsolutePath(options.cwd, "cwd");
  }
  if (options.windowsSupervisorPath !== undefined) {
    validateAbsolutePath(
      options.windowsSupervisorPath,
      "windowsSupervisorPath",
    );
  }
}

function validateRequiredPaths(
  options: Pick<
    SftpExecutorOptions,
    "sshExecutable" | "configFile" | "knownHostsFile"
  >,
): void {
  validateAbsolutePath(options.sshExecutable, "sshExecutable");
  validateOpenSshPath(options.configFile, "configFile");
  validateOpenSshPath(options.knownHostsFile, "knownHostsFile");
}

function validateRunInput(
  input: Pick<SftpRunInput, "sshAlias" | "batch">,
): Buffer {
  if (!TARGET_ALIAS_PATTERN.test(input.sshAlias)) {
    throw new TypeError(
      "sshAlias must be an approved OpenSSH alias containing only letters, digits, dots, underscores, and hyphens",
    );
  }
  const batch =
    typeof input.batch === "string"
      ? Buffer.from(input.batch, "utf8")
      : Buffer.from(input.batch);
  if (batch.byteLength === 0) {
    throw new TypeError("batch must not be empty");
  }
  if (batch.byteLength > MAX_MANAGED_STDIN_BYTES) {
    throw new RangeError(
      `batch must not exceed ${MAX_MANAGED_STDIN_BYTES} bytes`,
    );
  }
  if (!isUtf8(batch)) {
    throw new TypeError("batch must be valid UTF-8");
  }
  if (batch.includes(0) || batch.includes(13)) {
    throw new TypeError("batch must not contain NUL or carriage return bytes");
  }
  if (batch.at(-1) !== 0x0a) {
    throw new TypeError("batch must end with a line feed");
  }

  let commandCount = 0;
  for (const rawLine of batch.toString("utf8").split("\n")) {
    let line = rawLine.trimStart();
    if (line.length === 0) {
      continue;
    }
    let prefixes = "";
    for (let prefixCount = 0; prefixCount < 2; prefixCount += 1) {
      if (line.startsWith("@") || line.startsWith("-")) {
        prefixes += line[0];
        line = line.slice(1);
      }
    }
    if (
      line.startsWith("@") ||
      line.startsWith("-") ||
      !prefixes.includes("@") ||
      new Set(prefixes).size !== prefixes.length
    ) {
      throw new TypeError("every batch command must use safe unique prefixes");
    }
    const command = /^([A-Za-z]+)(?:\s|$)/u.exec(line)?.[1]?.toLowerCase();
    if (command === undefined || !ALLOWED_BATCH_COMMANDS.has(command)) {
      throw new TypeError("batch contains a command that is not allowed");
    }
    commandCount += 1;
  }
  if (commandCount === 0) {
    throw new TypeError("batch must contain at least one allowed command");
  }
  return batch;
}

function validateAbsolutePath(value: string, name: string): void {
  validatePathText(value, name);
  if (!path.isAbsolute(value) && !path.win32.isAbsolute(value)) {
    throw new TypeError(`${name} must be an absolute path`);
  }
}

function validateOpenSshPath(value: string, name: string): void {
  validateAbsolutePath(value, name);
  if (value.includes("$")) {
    throw new TypeError(`${name} must not contain OpenSSH environment expansions`);
  }
}

function validatePathText(value: string, name: string): void {
  if (value.length === 0 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError(
      `${name} must be non-empty and must not contain control characters`,
    );
  }
}

function validateConnectTimeout(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > 300) {
    throw new RangeError("connectTimeoutSeconds must be an integer from 1 through 300");
  }
}

function validateByteLimit(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative safe integer`);
  }
}

function isSignalAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
}

function quoteSshConfigValue(value: string): string {
  return `"${value
    .replaceAll("\\", "\\\\")
    .replaceAll('"', '\\"')
    .replaceAll("%", "%%")}"`;
}

class OutputCapture {
  readonly #limit: number;
  readonly #chunks: Buffer[] = [];
  #capturedBytes = 0;
  #totalBytes = 0;

  public constructor(limit: number) {
    this.#limit = limit;
  }

  public get totalBytes(): number {
    return this.#totalBytes;
  }

  public get truncated(): boolean {
    return this.#totalBytes > this.#capturedBytes;
  }

  public append(chunk: Buffer): void {
    this.#totalBytes += chunk.length;
    const remaining = this.#limit - this.#capturedBytes;
    if (remaining <= 0) {
      return;
    }
    const captured = chunk.subarray(0, Math.min(remaining, chunk.length));
    this.#chunks.push(Buffer.from(captured));
    this.#capturedBytes += captured.length;
  }

  public toString(): string {
    return Buffer.concat(this.#chunks, this.#capturedBytes).toString("utf8");
  }
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
    if (sink !== undefined) {
      await sink.append(channel, Buffer.from(chunk));
    }
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
      if (settled) {
        return;
      }
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

function emptyAbortedOutcome(durationMs: number): SftpOutcome {
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
