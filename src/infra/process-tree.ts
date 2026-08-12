import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

export type ProcessTerminationMode =
  | "windows-job"
  | "windows-taskkill-unsafe"
  | "posix-process-group";

export interface ManagedProcessOptions {
  readonly executable: string;
  readonly arguments: readonly string[];
  readonly stdinPayload?: Uint8Array;
  /** Keep the managed child's stdin connected to this process for incremental writes. */
  readonly streamStdin?: boolean;
  /**
   * Cancellation for the process preparation phase. The signal is deliberately
   * handled here instead of being passed to child_process.spawn, so that the
   * whole managed tree (including a Windows Job Object) is terminated.
   */
  readonly signal?: AbortSignal;
  readonly cwd?: string;
  readonly environment?: NodeJS.ProcessEnv;
  readonly windowsSupervisorPath?: string;
  readonly allowUnsafeProcessTermination?: boolean;
}

export interface ManagedProcess {
  readonly child: ChildProcessWithoutNullStreams;
  readonly terminationMode: ProcessTerminationMode;
  terminate(): Promise<void>;
}

export class ProcessTreeUnavailableError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "ProcessTreeUnavailableError";
  }
}

export class ProcessTreeTerminationError extends Error {
  public override readonly cause: unknown;

  public constructor(message: string, options?: { readonly cause?: unknown }) {
    super(message);
    this.name = "ProcessTreeTerminationError";
    this.cause = options?.cause;
  }
}

/** Raised when process preparation is interrupted by the caller's signal. */
export class ProcessTreeAbortError extends Error {
  public override readonly cause: unknown;

  public constructor(options?: { readonly cause?: unknown }) {
    super("managed process preparation was aborted");
    this.name = "AbortError";
    this.cause = options?.cause;
  }
}

const TERMINATION_WAIT_MS = 2_000;
const SUPERVISOR_HANDSHAKE_TIMEOUT_MS = 5_000;
const SUPERVISOR_READY_MARKER = Buffer.from(
  "agent-ssh-job-supervisor-ready-v1\n",
  "ascii",
);
export const MAX_MANAGED_STDIN_BYTES = 1024 * 1024;
export const WINDOWS_SUPERVISOR_FAILURE_EXIT_CODE = 0xe0535301;

export async function spawnManagedProcess(
  options: ManagedProcessOptions,
): Promise<ManagedProcess> {
  validateSpawnOptions(options);
  throwIfAborted(options.signal);

  if (process.platform === "win32") {
    const supervisor = resolveWindowsSupervisorPath(options.windowsSupervisorPath);
    if (supervisor !== undefined) {
      const supervisorArguments = [
        ...(options.streamStdin === true
          ? ["--stdin-stream", "--parent-pid", String(process.pid)]
          : options.stdinPayload === undefined
            ? []
            : ["--stdin-payload"]),
        "--",
        options.executable,
        ...options.arguments,
      ];
      const child = spawnWithPipes(
        supervisor,
        supervisorArguments,
        {
          ...options,
          detached: false,
        },
      );
      const managed = createManagedProcess(child, "windows-job", () =>
        signalSupervisor(child),
      );
      try {
        await waitForSupervisorHandshake(child, options.signal);
        if (options.stdinPayload !== undefined) {
          await writeSupervisorPayload(child, options.stdinPayload, options.signal);
        }
        throwIfAborted(options.signal);
      } catch (error: unknown) {
        await managed.terminate();
        throw error;
      }
      return managed;
    }

    if (options.allowUnsafeProcessTermination !== true) {
      throw new ProcessTreeUnavailableError(
        "the Windows Job Object supervisor is unavailable; refusing unsafe root-only process management",
      );
    }

    const child = spawnWithPipes(options.executable, options.arguments, {
      ...options,
      detached: false,
    });
    const managed = createManagedProcess(child, "windows-taskkill-unsafe", () =>
      terminateWithTaskkill(child),
    );
    try {
      await deliverDirectInput(managed, options.stdinPayload, options.signal);
      throwIfAborted(options.signal);
      return managed;
    } catch (error: unknown) {
      await managed.terminate();
      throw error;
    }
  }

  const child = spawnWithPipes(options.executable, options.arguments, {
    ...options,
    detached: true,
  });
  const managed = createManagedProcess(child, "posix-process-group", () =>
    terminatePosixProcessGroup(child),
  );
  try {
    await deliverDirectInput(managed, options.stdinPayload, options.signal);
    throwIfAborted(options.signal);
    return managed;
  } catch (error: unknown) {
    await managed.terminate();
    throw error;
  }
}

export function resolveWindowsSupervisorPath(
  configuredPath?: string,
): string | undefined {
  if (configuredPath !== undefined) {
    const absolutePath = path.resolve(configuredPath);
    return existsSync(absolutePath) ? absolutePath : undefined;
  }

  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
  const repositoryRoots = [
    path.resolve(moduleDirectory, "..", ".."),
    path.resolve(moduleDirectory, "..", "..", ".."),
  ];
  const relativeCandidates = [
    path.join("native", "windows-job-supervisor", "windows-job-supervisor.exe"),
    path.join(
      "native",
      "windows-job-supervisor",
      "bin",
      "Release",
      "net9.0",
      "win-x64",
      "publish",
      "windows-job-supervisor.exe",
    ),
    path.join(
      "native",
      "windows-job-supervisor",
      "bin",
      "Release",
      "net9.0",
      "windows-job-supervisor.exe",
    ),
    path.join(
      "native",
      "windows-job-supervisor",
      "bin",
      "Debug",
      "net9.0",
      "windows-job-supervisor.exe",
    ),
  ];

  for (const root of repositoryRoots) {
    for (const candidate of relativeCandidates) {
      const absolutePath = path.join(root, candidate);
      if (existsSync(absolutePath)) {
        return absolutePath;
      }
    }
  }

  return undefined;
}

interface SpawnWithPipesOptions extends ManagedProcessOptions {
  readonly detached: boolean;
}

function spawnWithPipes(
  executable: string,
  arguments_: readonly string[],
  options: SpawnWithPipesOptions,
): ChildProcessWithoutNullStreams {
  return spawn(executable, [...arguments_], {
    cwd: options.cwd,
    env: options.environment,
    detached: options.detached,
    shell: false,
    windowsHide: true,
    windowsVerbatimArguments: false,
    stdio: ["pipe", "pipe", "pipe"],
  });
}

export function createManagedProcess(
  child: ChildProcessWithoutNullStreams,
  terminationMode: ProcessTerminationMode,
  terminateImplementation: () => Promise<void>,
): ManagedProcess {
  let termination: Promise<void> | undefined;
  return {
    child,
    terminationMode,
    terminate(): Promise<void> {
      if (termination !== undefined) return termination;

      const operation = terminateImplementation();
      termination = operation;
      void operation.catch(() => {
        if (termination === operation) termination = undefined;
      });
      return operation;
    },
  };
}

async function deliverDirectInput(
  managed: ManagedProcess,
  payload: Uint8Array | undefined,
  signal: AbortSignal | undefined,
): Promise<void> {
  if (payload === undefined) {
    return;
  }
  try {
    await endWritable(managed.child.stdin, Buffer.from(payload), signal);
  } catch (error: unknown) {
    await managed.terminate().catch(() => undefined);
    if (error instanceof ProcessTreeAbortError) {
      throw error;
    }
    throw new ProcessTreeUnavailableError(
      `failed to deliver child standard input: ${formatError(error)}`,
    );
  }
}

async function writeSupervisorPayload(
  child: ChildProcessWithoutNullStreams,
  payload: Uint8Array,
  signal: AbortSignal | undefined,
): Promise<void> {
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32LE(payload.byteLength);
  const frame = Buffer.concat([header, Buffer.from(payload)]);
  try {
    await writeWritable(child.stdin, frame, signal);
  } catch (error: unknown) {
    if (error instanceof ProcessTreeAbortError) {
      throw error;
    }
    throw new ProcessTreeUnavailableError(
      `failed to deliver supervised child standard input: ${formatError(error)}`,
    );
  }
}

function writeWritable(
  stream: NodeJS.WritableStream,
  data: Uint8Array,
  signal: AbortSignal | undefined,
): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const onError = (error: Error): void => finish(error);
    const onAbort = (): void =>
      finish(new ProcessTreeAbortError({ cause: signal?.reason }));
    const finish = (error?: Error | null): void => {
      if (settled) return;
      settled = true;
      stream.removeListener("error", onError);
      signal?.removeEventListener("abort", onAbort);
      if (error === undefined || error === null) {
        resolve();
      } else {
        reject(error);
      }
    };
    stream.once("error", onError);
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted === true) {
      onAbort();
      return;
    }
    try {
      stream.write(data, finish);
    } catch (error: unknown) {
      finish(error instanceof Error ? error : new Error(String(error)));
    }
  });
}

function endWritable(
  stream: NodeJS.WritableStream,
  data: Uint8Array,
  signal: AbortSignal | undefined,
): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const onError = (error: Error): void => finish(error);
    const onAbort = (): void =>
      finish(new ProcessTreeAbortError({ cause: signal?.reason }));
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      stream.removeListener("error", onError);
      signal?.removeEventListener("abort", onAbort);
      if (error === undefined) {
        resolve();
      } else {
        reject(error);
      }
    };
    stream.once("error", onError);
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted === true) {
      onAbort();
      return;
    }
    try {
      stream.end(data, () => finish());
    } catch (error: unknown) {
      finish(error instanceof Error ? error : new Error(String(error)));
    }
  });
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function signalSupervisor(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (hasExited(child)) {
    return;
  }

  child.stdin.end();
  if (await waitForClose(child, TERMINATION_WAIT_MS)) {
    return;
  }

  // Abruptly killing the supervisor closes its non-inherited Job handle. Windows
  // then applies KILL_ON_JOB_CLOSE to every process still in the Job.
  await forceKillAndWait(
    child,
    "the Windows Job Object supervisor did not exit after forced termination",
  );
}

function waitForSupervisorHandshake(
  child: ChildProcessWithoutNullStreams,
  signal: AbortSignal | undefined,
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let received = Buffer.alloc(0);
    let settled = false;
    const timer = setTimeout(() => {
      fail("the Windows Job Object supervisor startup handshake timed out");
    }, SUPERVISOR_HANDSHAKE_TIMEOUT_MS);

    const cleanup = (): void => {
      clearTimeout(timer);
      child.stderr.off("data", onData);
      child.off("error", onError);
      child.off("close", onClose);
      signal?.removeEventListener("abort", onAbort);
    };
    const fail = (message: string, cause?: unknown): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      reject(new ProcessTreeUnavailableError(cause === undefined ? message : `${message}: ${String(cause)}`));
    };
    const onError = (error: Error): void => {
      fail("the Windows Job Object supervisor failed to start", error);
    };
    const onClose = (): void => {
      fail("the Windows Job Object supervisor exited before its startup handshake");
    };
    const onAbort = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new ProcessTreeAbortError({ cause: signal?.reason }));
    };
    const onData = (rawChunk: Buffer | Uint8Array): void => {
      const chunk = Buffer.from(rawChunk);
      received = Buffer.concat([received, chunk]);
      const comparableLength = Math.min(
        received.length,
        SUPERVISOR_READY_MARKER.length,
      );
      if (
        !received
          .subarray(0, comparableLength)
          .equals(SUPERVISOR_READY_MARKER.subarray(0, comparableLength))
      ) {
        fail("the Windows Job Object supervisor returned an invalid startup handshake");
        return;
      }
      if (received.length < SUPERVISOR_READY_MARKER.length) {
        return;
      }

      settled = true;
      child.stderr.pause();
      cleanup();
      const remainder = received.subarray(SUPERVISOR_READY_MARKER.length);
      if (remainder.length > 0) {
        child.stderr.unshift(remainder);
      }
      resolve();
    };

    child.stderr.on("data", onData);
    child.once("error", onError);
    child.once("close", onClose);
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted === true) onAbort();
  });
}

async function terminateWithTaskkill(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (hasExited(child) || child.pid === undefined) {
    return;
  }

  const systemRoot = process.env.SystemRoot ?? String.raw`C:\Windows`;
  const taskkill = path.join(systemRoot, "System32", "taskkill.exe");
  const killer = spawn(taskkill, ["/PID", String(child.pid), "/T", "/F"], {
    detached: false,
    shell: false,
    windowsHide: true,
    windowsVerbatimArguments: false,
    stdio: "ignore",
  });

  await new Promise<void>((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      killer.kill("SIGKILL");
      finish();
    }, TERMINATION_WAIT_MS);
    timer.unref();
    const finish = (): void => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve();
      }
    };
    killer.once("error", finish);
    killer.once("close", finish);
  });

  if (!(await waitForClose(child, TERMINATION_WAIT_MS))) {
    await forceKillAndWait(
      child,
      "the unsafe Windows process tree did not exit after forced termination",
    );
  }
}

async function terminatePosixProcessGroup(
  child: ChildProcessWithoutNullStreams,
): Promise<void> {
  if (child.pid === undefined) {
    return;
  }

  try {
    process.kill(-child.pid, "SIGKILL");
  } catch (error: unknown) {
    if (isNoSuchProcessError(error)) {
      return;
    }
    await forceKillAndWait(
      child,
      "the POSIX process group could not be signalled or terminated",
      error,
    );
    throw new ProcessTreeTerminationError(
      "the POSIX process group could not be signalled",
      { cause: error },
    );
  }

  if (!(await waitForPosixProcessGroupExit(child.pid, TERMINATION_WAIT_MS))) {
    throw new ProcessTreeTerminationError(
      "the POSIX process group did not exit after forced termination",
    );
  }
}

async function forceKillAndWait(
  child: ChildProcessWithoutNullStreams,
  failureMessage: string,
  initialError?: unknown,
): Promise<void> {
  let killError = initialError;
  const onError = (error: Error): void => {
    killError ??= error;
  };
  child.once("error", onError);
  try {
    try {
      child.kill("SIGKILL");
    } catch (error: unknown) {
      killError ??= error;
    }
    const closed = await waitForClose(child, TERMINATION_WAIT_MS);
    // child.kill() reports some failures through a next-tick error event.
    // Keep the temporary listener installed until that queue has drained.
    await new Promise<void>((resolve) => setImmediate(resolve));
    if (!closed) {
      throw new ProcessTreeTerminationError(
        failureMessage,
        killError === undefined ? undefined : { cause: killError },
      );
    }
  } finally {
    child.off("error", onError);
  }
}

function waitForPosixProcessGroupExit(
  processGroupId: number,
  timeoutMs: number,
): Promise<boolean> {
  const startedAt = Date.now();
  return new Promise((resolve) => {
    const check = (): void => {
      try {
        process.kill(-processGroupId, 0);
      } catch (error: unknown) {
        if (isNoSuchProcessError(error)) {
          resolve(true);
          return;
        }
      }

      if (Date.now() - startedAt >= timeoutMs) {
        resolve(false);
        return;
      }
      setTimeout(check, 25);
    };
    check();
  });
}

function waitForClose(
  child: ChildProcessWithoutNullStreams,
  timeoutMs: number,
): Promise<boolean> {
  if (hasExited(child)) {
    return Promise.resolve(true);
  }

  return new Promise<boolean>((resolve) => {
    let settled = false;
    const finish = (closed: boolean): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      child.off("close", onClose);
      resolve(closed);
    };
    const onClose = (): void => finish(true);
    const timer = setTimeout(() => finish(false), timeoutMs);
    timer.unref();
    child.once("close", onClose);
  });
}

function hasExited(child: ChildProcessWithoutNullStreams): boolean {
  return child.exitCode !== null || child.signalCode !== null;
}

function isNoSuchProcessError(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === "ESRCH"
  );
}

function validateSpawnOptions(options: ManagedProcessOptions): void {
  if (options.executable.length === 0 || options.executable.includes("\0")) {
    throw new TypeError("executable must be a non-empty path without NUL characters");
  }

  for (const argument of options.arguments) {
    if (argument.includes("\0")) {
      throw new TypeError("process arguments must not contain NUL characters");
    }
  }

  if (
    options.stdinPayload !== undefined &&
    options.stdinPayload.byteLength > MAX_MANAGED_STDIN_BYTES
  ) {
    throw new RangeError(
      `stdinPayload must not exceed ${MAX_MANAGED_STDIN_BYTES} bytes`,
    );
  }
  if (options.streamStdin === true && options.stdinPayload !== undefined) {
    throw new TypeError("streamStdin and stdinPayload are mutually exclusive");
  }
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw new ProcessTreeAbortError({ cause: signal.reason });
  }
}
