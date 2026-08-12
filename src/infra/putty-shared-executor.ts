import { randomBytes as cryptoRandomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { gzipSync } from "node:zlib";

import {
  OutputCapture,
  emptyAbortedOutcome,
  type ManagedCommandDependencies,
  type ManagedCommandOptions,
} from "./managed-command.js";
import {
  MAX_MANAGED_STDIN_BYTES,
  ProcessTreeAbortError,
  spawnManagedProcess,
  type ManagedProcess,
  type ManagedProcessOptions,
  type ProcessTerminationMode,
} from "./process-tree.js";
import {
  SshExecutionError,
  type OutputSink,
  type OutputStream,
  type SshOutcome,
  type SshFailureReason,
  type SshRunner,
  type SshRunInput,
} from "./ssh-runner.js";
import {
  MAX_COMMAND_BYTES,
  TARGET_ALIAS_PATTERN,
  type TargetPlatform,
} from "../shared/protocol.js";
import { formatPuttyLogicalHost } from "../shared/putty-loghost.js";

const BLOCK_DIRECT_HOST_KEY =
  "ssh-ed25519 255 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const BLOCK_DIRECT_PROXY_COMMAND = "cmd /d /c exit 1";
const PROTOCOL_MAGIC = "__ASH2__";
const SESSION_NONCE_BYTES = 16;
const COMMAND_NONCE_BYTES = 16;
const DEFAULT_CAPTURE_BYTES = 64 * 1024;
const DEFAULT_IDLE_TIMEOUT_MS = 60_000;
const DEFAULT_MAX_LIFETIME_MS = 10 * 60_000;
const DEFAULT_BOOTSTRAP_TIMEOUT_MS = 20_000;
const SHELL_READY_RETRY_MS = 750;
const POSIX_BOOTSTRAP_CHUNK_CHARS = 1_024;
const MAX_PROTOCOL_LINE_BYTES = 256 * 1024;
const MAX_PROTOCOL_PREAMBLE_BYTES = 256 * 1024;
const MAX_LOCAL_STDERR_BYTES = 32 * 1024;
const SAFE_HOST_PATTERN =
  /^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,251}[A-Za-z0-9])?$/u;
const SAFE_EXPECTED_HOSTNAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/u;
const HEX_128_PATTERN = /^[a-f0-9]{32}$/u;

export interface PuttySharedExecutorOptions extends ManagedCommandOptions {
  readonly targetAlias: string;
  readonly gatewayHost: string;
  readonly gatewayPort: number;
  readonly gatewayUsername: string;
  readonly sharingHost?: string;
  readonly sharingPort?: number;
  readonly expectedHostname?: string;
  readonly platform: TargetPlatform;
  readonly idleTimeoutMs?: number;
  readonly maxLifetimeMs?: number;
  readonly bootstrapTimeoutMs?: number;
}

export interface PuttySharedExecutorDependencies
  extends ManagedCommandDependencies {
  readonly randomBytes?: (size: number) => Uint8Array;
}

type PendingState = "queued" | "active" | "settled";

interface PendingRun {
  readonly input: SshRunInput;
  readonly queuedAt: number;
  readonly resolve: (outcome: SshOutcome) => void;
  readonly reject: (error: unknown) => void;
  state: PendingState;
  onQueuedAbort: (() => void) | undefined;
}

interface CommandSnapshot {
  readonly stdout: string;
  readonly stderr: string;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
  readonly stdoutTruncated: boolean;
  readonly stderrTruncated: boolean;
}

interface SessionCommandResult extends CommandSnapshot {
  readonly exitCode: number;
  readonly terminationMode: ProcessTerminationMode;
}

export class PuttySharedExecutor implements SshRunner {
  readonly #options: PuttySharedExecutorOptions;
  readonly #dependencies: PuttySharedExecutorDependencies;
  readonly #queue: PendingRun[] = [];
  readonly #ownedSessions = new Set<PuttyPersistentSession>();
  readonly #lifetimeController = new AbortController();
  #session: PuttyPersistentSession | undefined;
  #drainOperation: Promise<void> | undefined;
  #closed = false;
  #closeOperation: Promise<void> | undefined;

  public constructor(
    options: PuttySharedExecutorOptions,
    dependencies: PuttySharedExecutorDependencies = {},
  ) {
    validateOptions(options);
    this.#options = options;
    this.#dependencies = dependencies;
  }

  public run(input: SshRunInput): Promise<SshOutcome> {
    validateInput(this.#options, input);
    if (this.#closed) {
      return Promise.reject(new SshExecutionError("the SSH executor is closed"));
    }
    if (input.signal?.aborted === true) {
      return Promise.resolve(emptyAbortedOutcome(0));
    }

    return new Promise<SshOutcome>((resolve, reject) => {
      const pending: PendingRun = {
        input,
        queuedAt: performance.now(),
        resolve,
        reject,
        state: "queued",
        onQueuedAbort: undefined,
      };
      const onQueuedAbort = (): void => {
        if (pending.state !== "queued") return;
        pending.state = "settled";
        const index = this.#queue.indexOf(pending);
        if (index >= 0) this.#queue.splice(index, 1);
        input.signal?.removeEventListener("abort", onQueuedAbort);
        resolve(emptyAbortedOutcome(performance.now() - pending.queuedAt));
      };
      pending.onQueuedAbort = onQueuedAbort;
      input.signal?.addEventListener("abort", onQueuedAbort, { once: true });
      if (input.signal?.aborted === true) {
        onQueuedAbort();
        return;
      }
      this.#queue.push(pending);
      this.#ensureDrain();
    });
  }

  public close(): Promise<void> {
    if (this.#closeOperation !== undefined) return this.#closeOperation;

    const operation = this.#closeInternal();
    this.#closeOperation = operation;
    void operation.catch(() => {
      if (this.#closeOperation === operation) {
        this.#closeOperation = undefined;
      }
    });
    return operation;
  }

  #ensureDrain(): void {
    if (this.#drainOperation !== undefined) return;
    const operation = this.#drainQueue();
    this.#drainOperation = operation;
    void operation.finally(() => {
      if (this.#drainOperation === operation) {
        this.#drainOperation = undefined;
      }
      if (!this.#closed && this.#queue.length > 0) this.#ensureDrain();
    });
  }

  async #drainQueue(): Promise<void> {
    while (!this.#closed) {
      const pending = this.#queue.shift();
      if (pending === undefined) return;
      if (pending.state !== "queued") continue;

      pending.state = "active";
      if (pending.onQueuedAbort !== undefined) {
        pending.input.signal?.removeEventListener(
          "abort",
          pending.onQueuedAbort,
        );
      }
      pending.onQueuedAbort = undefined;
      if (pending.input.signal?.aborted === true) {
        pending.state = "settled";
        pending.resolve(
          emptyAbortedOutcome(performance.now() - pending.queuedAt),
        );
        continue;
      }

      try {
        pending.resolve(await this.#execute(pending.input, pending.queuedAt));
      } catch (error: unknown) {
        pending.reject(error);
      } finally {
        pending.state = "settled";
      }
    }
  }

  async #execute(input: SshRunInput, startedAt: number): Promise<SshOutcome> {
    const signal =
      input.signal === undefined
        ? this.#lifetimeController.signal
        : AbortSignal.any([input.signal, this.#lifetimeController.signal]);

    await this.#closeRetiredSessions();

    let session = this.#session;
    if (session !== undefined && !session.reusable) {
      await this.#closeOwnedSession(session);
      session = undefined;
    }

    let openingSession: PuttyPersistentSession | undefined;
    let cleanupAttempted = false;
    try {
      if (session === undefined) {
        session = await PuttyPersistentSession.open(
          this.#options,
          this.#dependencies,
          signal,
          (created) => {
            openingSession = created;
            this.#ownedSessions.add(created);
          },
        );
        openingSession = undefined;
        if (this.#closed) {
          cleanupAttempted = true;
          await this.#closeOwnedSession(session);
          return emptyAbortedOutcome(performance.now() - startedAt);
        }
        this.#session = session;
      }

      const result = await session.execute(input, signal);
      if (!session.reusable) {
        cleanupAttempted = true;
        await this.#closeOwnedSession(session);
      }
      return {
        exitCode: result.exitCode,
        signal: null,
        stdout: result.stdout,
        stderr: result.stderr,
        stdoutBytes: result.stdoutBytes,
        stderrBytes: result.stderrBytes,
        stdoutTruncated: result.stdoutTruncated,
        stderrTruncated: result.stderrTruncated,
        aborted: false,
        durationMs: performance.now() - startedAt,
        terminationMode: result.terminationMode,
      };
    } catch (error: unknown) {
      const ownedSession = session ?? openingSession;
      if (
        ownedSession !== undefined &&
        this.#ownedSessions.has(ownedSession) &&
        !cleanupAttempted &&
        !(error instanceof SharedSessionCleanupError)
      ) {
        try {
          await this.#closeOwnedSession(ownedSession);
        } catch (cleanupError: unknown) {
          throw aggregateSessionCleanupError(error, cleanupError);
        }
      }

      if (error instanceof SharedSessionCleanupError) throw error;

      if (error instanceof SharedSessionAbortedError || signal.aborted) {
        const snapshot =
          error instanceof SharedSessionAbortedError
            ? error.snapshot
            : EMPTY_SNAPSHOT;
        return {
          exitCode: null,
          signal: null,
          stdout: snapshot.stdout,
          stderr: snapshot.stderr,
          stdoutBytes: snapshot.stdoutBytes,
          stderrBytes: snapshot.stderrBytes,
          stdoutTruncated: snapshot.stdoutTruncated,
          stderrTruncated: snapshot.stderrTruncated,
          aborted: true,
          durationMs: performance.now() - startedAt,
          terminationMode: session?.terminationMode ?? null,
        };
      }

      if (error instanceof SharedSessionHostMismatchError) {
        return this.#failureOutcome(
          input,
          "accessclient-host-mismatch",
          "AccessClient is connected to a different target. Close the current shared session and open the configured target.\n",
          startedAt,
          error.snapshot,
          error.terminationMode ?? session?.terminationMode ?? null,
        );
      }
      if (error instanceof SharedSessionUnavailableError) {
        return this.#failureOutcome(
          input,
          error.timedOut
            ? "accessclient-session-timeout"
            : "accessclient-session-unavailable",
          error.timedOut
            ? "AccessClient shared session did not become ready before the connection timeout. Keep the target open in AccessClient and try again.\n"
            : "AccessClient shared session is not available. Open the target in AccessClient and try again.\n",
          startedAt,
          error.snapshot,
          error.terminationMode ?? session?.terminationMode ?? null,
        );
      }
      if (error instanceof SharedSessionCommandError) {
        return this.#failureOutcome(
          input,
          "accessclient-session-ended",
          "AccessClient shared session ended before the command completed. The command was not retried.\n",
          startedAt,
          error.snapshot,
          error.terminationMode ?? session?.terminationMode ?? null,
        );
      }
      throw error;
    }
  }

  async #failureOutcome(
    input: SshRunInput,
    failureReason: SshFailureReason,
    message: string,
    startedAt: number,
    snapshot: CommandSnapshot,
    terminationMode: ProcessTerminationMode | null,
  ): Promise<SshOutcome> {
    await appendDiagnostic(input.outputSink, message);
    const messageBytes = Buffer.byteLength(message);
    return {
      exitCode: 255,
      signal: null,
      stdout: snapshot.stdout,
      stderr: snapshot.stderr + message,
      stdoutBytes: snapshot.stdoutBytes,
      stderrBytes: snapshot.stderrBytes + messageBytes,
      stdoutTruncated: snapshot.stdoutTruncated,
      stderrTruncated: snapshot.stderrTruncated,
      aborted: false,
      durationMs: performance.now() - startedAt,
      terminationMode,
      failureReason,
    };
  }

  async #closeInternal(): Promise<void> {
    this.#closed = true;
    this.#lifetimeController.abort(
      new SshExecutionError("the SSH executor is closed"),
    );
    const closeError = new SshExecutionError("the SSH executor is closed");
    for (const pending of this.#queue.splice(0)) {
      if (pending.state !== "queued") continue;
      pending.state = "settled";
      if (pending.onQueuedAbort !== undefined) {
        pending.input.signal?.removeEventListener(
          "abort",
          pending.onQueuedAbort,
        );
      }
      pending.reject(closeError);
    }

    await this.#drainOperation;
    await this.#closeAllOwnedSessions();
  }

  async #closeRetiredSessions(): Promise<void> {
    const active = this.#session;
    const retired = [...this.#ownedSessions].filter(
      (session) => session !== active,
    );
    await this.#closeSessions(retired);
  }

  async #closeAllOwnedSessions(): Promise<void> {
    await this.#closeSessions([...this.#ownedSessions]);
  }

  async #closeSessions(sessions: readonly PuttyPersistentSession[]): Promise<void> {
    const results = await Promise.allSettled(
      sessions.map(async (session) => this.#closeOwnedSession(session)),
    );
    const failures = results.flatMap((result) =>
      result.status === "rejected" ? [result.reason] : [],
    );
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1) {
      throw new AggregateError(
        failures,
        "multiple persistent AccessClient sessions failed to close",
      );
    }
  }

  async #closeOwnedSession(session: PuttyPersistentSession): Promise<void> {
    if (this.#session === session) this.#session = undefined;
    await session.close();
    this.#ownedSessions.delete(session);
  }
}

export function buildPuttySharedArguments(
  options: Pick<
    PuttySharedExecutorOptions,
    | "gatewayHost"
    | "gatewayPort"
    | "gatewayUsername"
    | "sharingHost"
    | "sharingPort"
  >,
): string[] {
  validateGateway(options);
  const sharingArguments =
    options.sharingHost === undefined
      ? []
      : [
          "-loghost",
          formatPuttyLogicalHost(options.sharingHost, options.sharingPort),
        ];
  return [
    "-batch",
    "-ssh",
    "-P",
    String(options.gatewayPort),
    "-l",
    options.gatewayUsername,
    "-noagent",
    "-a",
    "-x",
    "-no-trivial-auth",
    "-share",
    ...sharingArguments,
    "-proxycmd",
    BLOCK_DIRECT_PROXY_COMMAND,
    "-hostkey",
    BLOCK_DIRECT_HOST_KEY,
    "-t",
    "-no-sanitise-stdout",
    "-no-sanitise-stderr",
    "-no-antispoof",
    options.gatewayHost,
  ];
}

export function buildPuttyShellReadyProbe(
  options: Pick<PuttySharedExecutorOptions, "platform">,
  sessionNonce: string,
): Buffer {
  validateNonce(sessionNonce, "session nonce");
  const marker = shellReadyMarker(sessionNonce);
  return Buffer.from(
    options.platform === "windows"
      ? `echo ${marker}\r\n`
      : `printf '\\n%s\\n' '${marker}'\n`,
    "ascii",
  );
}

function shellReadyMarker(sessionNonce: string): string {
  return `${PROTOCOL_MAGIC}:${sessionNonce}:SHELL_READY`;
}

export function buildPuttyBrokerBootstrap(
  options: Pick<PuttySharedExecutorOptions, "platform">,
  sessionNonce: string,
): Buffer {
  validateNonce(sessionNonce, "session nonce");
  if (options.platform === "windows") {
    const script = buildWindowsBrokerScript(sessionNonce);
    const compressed = gzipSync(Buffer.from(script, "utf8"), { level: 9 });
    const compressedBase64 = compressed.toString("base64");
    const loader =
      "$r=[IO.StreamReader]::new([IO.Compression.GZipStream]::new(" +
      `[IO.MemoryStream]::new([Convert]::FromBase64String('${compressedBase64}')),` +
      "[IO.Compression.CompressionMode]0));iex($r.ReadToEnd())";
    const encoded = Buffer.from(loader, "utf16le").toString("base64");
    const bootstrap = Buffer.from(
      `powershell.exe -NoP -NonI -enc ${encoded}\r\n`,
      "ascii",
    );
    if (bootstrap.byteLength > 8_000) {
      throw new SshExecutionError(
        `the Windows persistent broker bootstrap is ${bootstrap.byteLength} bytes and exceeds the safe cmd.exe limit`,
      );
    }
    return bootstrap;
  }

  const decodeFlag = options.platform === "macos" ? "-D" : "-d";
  const script = buildPosixBrokerScript(sessionNonce, decodeFlag);
  const encoded = Buffer.from(script, "utf8").toString("base64");
  const payloadVariable = `__ash_payload_${sessionNonce}`;
  const scriptVariable = `__ash_script_${sessionNonce}`;
  const chunks: string[] = [];
  for (let offset = 0; offset < encoded.length; offset += POSIX_BOOTSTRAP_CHUNK_CHARS) {
    chunks.push(encoded.slice(offset, offset + POSIX_BOOTSTRAP_CHUNK_CHARS));
  }
  const lines = chunks.map((chunk, index) =>
    index === 0
      ? `${payloadVariable}='${chunk}' || exit 96`
      : `${payloadVariable}="\${${payloadVariable}}"'${chunk}' || exit 96`,
  );
  lines.push(
    `[ "\${#${payloadVariable}}" -eq ${encoded.length} ] || exit 96`,
    `${scriptVariable}=$(printf '%s' "$${payloadVariable}" | base64 ${decodeFlag}) || exit 96`,
    "stty -echo -icanon min 1 time 0 || exit 96",
    `exec bash --noprofile --norc -c "$${scriptVariable}"`,
  );
  return Buffer.from(`${lines.join("\n")}\n`, "ascii");
}

export function buildPuttyCommandFrame(
  sessionNonce: string,
  sequence: number,
  commandNonce: string,
  input: Pick<SshRunInput, "command" | "stdin">,
): Buffer {
  validateNonce(sessionNonce, "session nonce");
  validateNonce(commandNonce, "command nonce");
  if (!Number.isSafeInteger(sequence) || sequence < 1) {
    throw new RangeError("protocol sequence must be a positive safe integer");
  }
  const commandBase64 = Buffer.from(input.command, "utf8").toString("base64");
  const stdinMode = input.stdin === undefined ? "N" : "B";
  const stdinBase64 =
    input.stdin === undefined ? "" : Buffer.from(input.stdin).toString("base64");
  return Buffer.from(
    `${PROTOCOL_MAGIC}:${sessionNonce}:${sequence}:${commandNonce}:RUN:${commandBase64}:${stdinMode}:${stdinBase64}\n`,
    "ascii",
  );
}

class PuttyPersistentSession {
  readonly #options: PuttySharedExecutorOptions;
  readonly #dependencies: PuttySharedExecutorDependencies;
  readonly #sessionNonce: string;
  readonly #parser: PersistentProtocolParser;
  readonly #createdAt = performance.now();
  readonly #stderrCapture = new OutputCapture(MAX_LOCAL_STDERR_BYTES);
  #managed: ManagedProcess | undefined;
  #stdoutPump: Promise<void> | undefined;
  #stderrPump: Promise<void> | undefined;
  #processOperation: Promise<void> | undefined;
  #termination: Promise<void> | undefined;
  #closeOperation: Promise<void> | undefined;
  #stdinErrorListener: ((error: Error) => void) | undefined;
  #idleTimer: NodeJS.Timeout | undefined;
  #lifetimeTimer: NodeJS.Timeout | undefined;
  #sequence = 0;
  #ready = false;
  #reusable = false;
  #retired = false;
  #fatalError: unknown;

  private constructor(
    options: PuttySharedExecutorOptions,
    dependencies: PuttySharedExecutorDependencies,
  ) {
    this.#options = options;
    this.#dependencies = dependencies;
    this.#sessionNonce = randomHex(
      SESSION_NONCE_BYTES,
      dependencies.randomBytes,
    );
    this.#parser = new PersistentProtocolParser(this.#sessionNonce);
  }

  public static async open(
    options: PuttySharedExecutorOptions,
    dependencies: PuttySharedExecutorDependencies,
    signal: AbortSignal,
    onCreated: (session: PuttyPersistentSession) => void,
  ): Promise<PuttyPersistentSession> {
    const session = new PuttyPersistentSession(options, dependencies);
    onCreated(session);
    try {
      await session.#start(signal);
      return session;
    } catch (error: unknown) {
      try {
        await session.close();
      } catch (cleanupError: unknown) {
        throw aggregateSessionCleanupError(error, cleanupError);
      }
      throw error;
    }
  }

  public get terminationMode(): ProcessTerminationMode | null {
    return this.#managed?.terminationMode ?? null;
  }

  public get reusable(): boolean {
    if (
      this.#reusable &&
      performance.now() - this.#createdAt >=
        (this.#options.maxLifetimeMs ?? DEFAULT_MAX_LIFETIME_MS)
    ) {
      this.#retired = true;
      if (!this.#parser.hasActiveCommand) {
        this.#reusable = false;
        void this.close().catch(() => undefined);
      }
    }
    return this.#reusable && !this.#retired;
  }

  public async execute(
    input: SshRunInput,
    signal: AbortSignal,
  ): Promise<SessionCommandResult> {
    if (!this.#ready || !this.#reusable || this.#managed === undefined) {
      throw new SharedSessionCommandError(
        EMPTY_SNAPSHOT,
        this.terminationMode,
      );
    }
    this.#clearIdleTimer();

    const sequence = ++this.#sequence;
    const commandNonce = randomHex(
      COMMAND_NONCE_BYTES,
      this.#dependencies.randomBytes,
    );
    const handle = this.#parser.beginCommand(
      sequence,
      commandNonce,
      input.outputSink,
      input.maxCapturedOutputBytes ??
        this.#options.maxCapturedOutputBytes ??
        DEFAULT_CAPTURE_BYTES,
    );
    let abortWon = false;
    const onAbort = (): void => {
      if (handle.completed) return;
      abortWon = true;
      this.#poison(new SharedSessionAbortSignalError());
    };
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();

    try {
      if (abortWon) throw new SharedSessionAbortSignalError();
      await this.#write(
        buildPuttyCommandFrame(
          this.#sessionNonce,
          sequence,
          commandNonce,
          input,
        ),
        signal,
      );
      const completed = await handle.promise;
      if (abortWon) throw new SharedSessionAbortSignalError();

      if (this.#retired) {
        this.#reusable = false;
        await this.close();
      } else {
        this.#scheduleIdleTimer();
      }
      return {
        ...completed,
        terminationMode: this.#managed.terminationMode,
      };
    } catch (error: unknown) {
      this.#poison(error);
      const termination = this.#terminate();
      await handle.promise.catch(() => undefined);
      try {
        await termination;
      } catch (terminationError: unknown) {
        throw aggregateSessionCleanupError(error, terminationError);
      }
      const snapshot = handle.snapshot();
      if (abortWon || signal.aborted) {
        throw new SharedSessionAbortedError(
          snapshot,
          this.terminationMode,
        );
      }
      if (error instanceof OutputSinkProtocolError) {
        throw new SshExecutionError("the SSH output sink failed", {
          cause: error.cause,
        });
      }
      if (error instanceof SshExecutionError) throw error;
      throw new SharedSessionCommandError(
        snapshot,
        this.terminationMode,
        error,
      );
    } finally {
      signal.removeEventListener("abort", onAbort);
    }
  }

  public close(): Promise<void> {
    if (this.#closeOperation !== undefined) return this.#closeOperation;

    const operation = (async () => {
      this.#reusable = false;
      this.#retired = true;
      this.#clearTimers();
      this.#parser.fail(
        new SharedSessionProtocolError("the persistent session was closed"),
      );
      await this.#terminate();
    })();
    this.#closeOperation = operation;
    void operation.catch(() => {
      if (this.#closeOperation === operation) {
        this.#closeOperation = undefined;
      }
    });
    return operation;
  }

  async #start(signal: AbortSignal): Promise<void> {
    const timeoutController = new AbortController();
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      timeoutController.abort();
    }, this.#options.bootstrapTimeoutMs ?? DEFAULT_BOOTSTRAP_TIMEOUT_MS);
    timeout.unref();
    const startupSignal = AbortSignal.any([
      signal,
      timeoutController.signal,
    ]);

    try {
      const processOptions = managedProcessOptions(this.#options, startupSignal);
      this.#managed = await (
        this.#dependencies.spawnProcess ?? spawnManagedProcess
      )(processOptions);
      this.#attachProcess(this.#managed);
      await this.#waitForShellReady(startupSignal);
      await this.#write(
        buildPuttyBrokerBootstrap(this.#options, this.#sessionNonce),
        startupSignal,
      );
      const observedHostname = await waitWithSignal(
        this.#parser.ready,
        startupSignal,
        () => this.#poison(new SharedSessionAbortSignalError()),
      );
      if (
        this.#options.expectedHostname !== undefined &&
        observedHostname.toLowerCase() !==
          this.#options.expectedHostname.toLowerCase()
      ) {
        const mismatch = new SharedSessionHostMismatchError(
          EMPTY_SNAPSHOT,
          this.terminationMode,
        );
        this.#poison(mismatch);
        throw mismatch;
      }
      this.#ready = true;
      this.#reusable = true;
      this.#scheduleLifetimeTimer();
    } catch (error: unknown) {
      if (signal.aborted) {
        throw new SharedSessionAbortedError(
          EMPTY_SNAPSHOT,
          this.terminationMode,
        );
      }
      if (timedOut) {
        throw new SharedSessionUnavailableError(
          EMPTY_SNAPSHOT,
          this.terminationMode,
          true,
          error,
        );
      }
      if (error instanceof ProcessTreeAbortError) {
        throw new SharedSessionAbortedError(
          EMPTY_SNAPSHOT,
          this.terminationMode,
          error,
        );
      }
      if (
        error instanceof SharedSessionUnavailableError ||
        error instanceof SharedSessionHostMismatchError ||
        error instanceof SshExecutionError
      ) {
        throw error;
      }
      throw new SshExecutionError(
        "failed to prepare the persistent AccessClient session",
        { cause: error },
      );
    } finally {
      clearTimeout(timeout);
    }
  }

  async #waitForShellReady(signal: AbortSignal): Promise<void> {
    const probe = buildPuttyShellReadyProbe(this.#options, this.#sessionNonce);
    while (!this.#parser.shellReadyObserved) {
      await this.#write(probe, signal);
      if (this.#parser.shellReadyObserved) return;
      const ready = await Promise.race([
        this.#parser.shellReady.then(() => true),
        waitForRetryDelay(SHELL_READY_RETRY_MS, signal).then(() => false),
      ]);
      if (ready) return;
    }
  }

  #attachProcess(managed: ManagedProcess): void {
    const { child } = managed;
    this.#stdinErrorListener = (error: Error): void => {
      this.#poison(
        new SharedSessionProtocolError(
          "the persistent session input pipe failed",
          error,
        ),
      );
    };
    child.stdin.on("error", this.#stdinErrorListener);
    this.#stdoutPump = this.#pumpStdout(child);
    this.#stderrPump = this.#pumpStderr(child);
    this.#processOperation = this.#monitorProcess(
      child,
      this.#stdoutPump,
      this.#stderrPump,
    );
  }

  async #pumpStdout(child: ChildProcessWithoutNullStreams): Promise<void> {
    try {
      for await (const rawChunk of child.stdout) {
        const chunk = Buffer.isBuffer(rawChunk)
          ? rawChunk
          : Buffer.from(rawChunk as Uint8Array);
        await this.#parser.append(chunk);
      }
      this.#parser.endOfStream();
    } catch (error: unknown) {
      this.#poison(error);
    }
  }

  async #pumpStderr(child: ChildProcessWithoutNullStreams): Promise<void> {
    try {
      for await (const rawChunk of child.stderr) {
        this.#stderrCapture.append(
          Buffer.isBuffer(rawChunk)
            ? rawChunk
            : Buffer.from(rawChunk as Uint8Array),
        );
      }
    } catch (error: unknown) {
      this.#poison(
        new SharedSessionProtocolError(
          "the persistent session diagnostic pipe failed",
          error,
        ),
      );
    }
  }

  async #monitorProcess(
    child: ChildProcessWithoutNullStreams,
    stdoutPump: Promise<void>,
    stderrPump: Promise<void>,
  ): Promise<void> {
    const closed = await waitForChildClose(child);
    await Promise.all([stdoutPump, stderrPump]);
    this.#ready = false;
    this.#reusable = false;
    this.#clearTimers();
    if (closed.error !== undefined && this.#fatalError === undefined) {
      this.#parser.fail(
        new SharedSessionProtocolError(
          "the persistent session process failed",
          closed.error,
        ),
      );
    } else if (this.#fatalError === undefined) {
      this.#parser.endOfStream();
    }
  }

  async #write(data: Uint8Array, signal: AbortSignal): Promise<void> {
    const child = this.#managed?.child;
    if (child === undefined) {
      throw new SharedSessionProtocolError(
        "the persistent session is not running",
      );
    }
    try {
      await writeWritable(child.stdin, data, signal);
    } catch (error: unknown) {
      if (signal.aborted) throw new SharedSessionAbortSignalError(error);
      const failure = new SharedSessionProtocolError(
        "failed to write the persistent session protocol",
        error,
      );
      this.#poison(failure);
      throw failure;
    }
  }

  #poison(error: unknown): void {
    if (this.#fatalError !== undefined) return;
    this.#fatalError = error;
    this.#ready = false;
    this.#reusable = false;
    this.#clearTimers();
    this.#parser.fail(error);
    void this.#terminate().catch(() => undefined);
  }

  #terminate(): Promise<void> {
    if (this.#termination !== undefined) return this.#termination;

    const operation = this.#terminateInternal();
    this.#termination = operation;
    void operation.catch(() => {
      if (this.#termination === operation) {
        this.#termination = undefined;
      }
    });
    return operation;
  }

  async #terminateInternal(): Promise<void> {
    this.#clearTimers();
    const managed = this.#managed;
    if (managed === undefined) return;
    try {
      await managed.terminate();
    } catch (error: unknown) {
      throw new SshExecutionError(
        "failed to terminate the persistent AccessClient session",
        { cause: error },
      );
    }
    await this.#processOperation;
    if (this.#stdinErrorListener !== undefined) {
      managed.child.stdin.removeListener(
        "error",
        this.#stdinErrorListener,
      );
      this.#stdinErrorListener = undefined;
    }
  }

  #scheduleIdleTimer(): void {
    this.#clearIdleTimer();
    if (!this.#reusable || this.#retired) return;
    this.#idleTimer = setTimeout(() => {
      this.#reusable = false;
      this.#parser.fail(
        new SharedSessionProtocolError(
          "the persistent session reached its idle timeout",
        ),
      );
      void this.#terminate().catch(() => undefined);
    }, this.#options.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS);
    this.#idleTimer.unref();
  }

  #scheduleLifetimeTimer(): void {
    const remaining = Math.max(
      1,
      (this.#options.maxLifetimeMs ?? DEFAULT_MAX_LIFETIME_MS) -
        (performance.now() - this.#createdAt),
    );
    this.#lifetimeTimer = setTimeout(() => {
      this.#retired = true;
      if (this.#parser.hasActiveCommand) return;
      this.#reusable = false;
      this.#parser.fail(
        new SharedSessionProtocolError(
          "the persistent session reached its maximum lifetime",
        ),
      );
      void this.#terminate().catch(() => undefined);
    }, remaining);
    this.#lifetimeTimer.unref();
  }

  #clearIdleTimer(): void {
    if (this.#idleTimer === undefined) return;
    clearTimeout(this.#idleTimer);
    this.#idleTimer = undefined;
  }

  #clearTimers(): void {
    this.#clearIdleTimer();
    if (this.#lifetimeTimer !== undefined) {
      clearTimeout(this.#lifetimeTimer);
      this.#lifetimeTimer = undefined;
    }
  }
}

interface CommandHandle {
  readonly promise: Promise<CommandSnapshot & { readonly exitCode: number }>;
  readonly completed: boolean;
  snapshot(): CommandSnapshot;
}

interface ActiveProtocolCommand {
  readonly sequence: number;
  readonly nonce: string;
  readonly prefix: string;
  readonly sink: OutputSink | undefined;
  readonly captures: Readonly<Record<OutputStream, OutputCapture>>;
  readonly sanitizers: Readonly<Record<OutputStream, TerminalSanitizer>>;
  readonly abortController: AbortController;
  readonly deferred: Deferred<CommandSnapshot & { readonly exitCode: number }>;
  began: boolean;
  completed: boolean;
}

class PersistentProtocolParser {
  readonly #sessionNonce: string;
  readonly #shellReadyDeferred = deferred<void>();
  readonly #readyDeferred = deferred<string>();
  #shellReadyObserved = false;
  #state: "preamble" | "idle" | "fatal" = "preamble";
  #pending = Buffer.alloc(0);
  #preambleBytes = 0;
  #active: ActiveProtocolCommand | undefined;

  public constructor(sessionNonce: string) {
    this.#sessionNonce = sessionNonce;
    // Startup can fail before the owner begins awaiting READY (for example,
    // when spawning Plink itself fails). Keep that rejection observed while
    // preserving the original promise for normal startup error propagation.
    void this.#shellReadyDeferred.promise.catch(() => undefined);
    void this.#readyDeferred.promise.catch(() => undefined);
  }

  public get shellReady(): Promise<void> {
    return this.#shellReadyDeferred.promise;
  }

  public get shellReadyObserved(): boolean {
    return this.#shellReadyObserved;
  }

  public get ready(): Promise<string> {
    return this.#readyDeferred.promise;
  }

  public get hasActiveCommand(): boolean {
    return this.#active !== undefined;
  }

  public beginCommand(
    sequence: number,
    nonce: string,
    sink: OutputSink | undefined,
    captureBytes: number,
  ): CommandHandle {
    if (this.#state !== "idle" || this.#active !== undefined) {
      throw new SharedSessionProtocolError(
        "the persistent session protocol is not idle",
      );
    }
    validateByteLimit(captureBytes, "maxCapturedOutputBytes");
    const active: ActiveProtocolCommand = {
      sequence,
      nonce,
      prefix:
        PROTOCOL_MAGIC +
        ":" +
        this.#sessionNonce +
        ":" +
        String(sequence) +
        ":" +
        nonce,
      sink,
      captures: Object.freeze({
        stdout: new OutputCapture(captureBytes),
        stderr: new OutputCapture(captureBytes),
      }),
      sanitizers: Object.freeze({
        stdout: new TerminalSanitizer(),
        stderr: new TerminalSanitizer(),
      }),
      abortController: new AbortController(),
      deferred: deferred<CommandSnapshot & { readonly exitCode: number }>(),
      began: false,
      completed: false,
    };
    this.#active = active;
    return {
      promise: active.deferred.promise,
      get completed(): boolean {
        return active.completed;
      },
      snapshot: (): CommandSnapshot => snapshotCommand(active),
    };
  }

  public async append(chunk: Uint8Array): Promise<void> {
    if (this.#state === "fatal") return;
    const bytes = Buffer.from(chunk);
    let offset = 0;
    while (offset < bytes.length) {
      const newline = bytes.indexOf(0x0a, offset);
      if (newline < 0) {
        this.#appendPending(bytes.subarray(offset));
        return;
      }
      this.#appendPending(bytes.subarray(offset, newline));
      let line = this.#pending;
      this.#pending = Buffer.alloc(0);
      if (line.at(-1) === 0x0d) line = line.subarray(0, line.length - 1);
      await this.#acceptLine(line);
      offset = newline + 1;
    }
  }

  public endOfStream(): void {
    if (this.#state === "fatal") return;
    if (this.#pending.length > 0) {
      this.#violation("the persistent protocol ended with a partial frame");
    }
    if (this.#state === "preamble") {
      this.fail(
        new SharedSessionUnavailableError(
          EMPTY_SNAPSHOT,
          null,
          false,
        ),
      );
      return;
    }
    this.fail(
      new SharedSessionProtocolError(
        "the persistent protocol stream ended unexpectedly",
      ),
    );
  }

  public fail(error: unknown): void {
    if (this.#state === "fatal") return;
    this.#state = "fatal";
    this.#shellReadyDeferred.reject(error);
    this.#readyDeferred.reject(error);
    const active = this.#active;
    this.#active = undefined;
    if (active !== undefined && !active.completed) {
      active.completed = true;
      active.abortController.abort(error);
      active.deferred.reject(error);
    }
  }

  #appendPending(segment: Uint8Array): void {
    if (segment.byteLength === 0) return;
    if (this.#pending.length + segment.byteLength > MAX_PROTOCOL_LINE_BYTES) {
      this.#violation("the persistent protocol contains an oversized frame");
    }
    this.#pending = Buffer.concat([
      this.#pending,
      Buffer.from(segment),
    ]);
  }

  async #acceptLine(line: Buffer): Promise<void> {
    if (this.#state === "preamble") {
      this.#preambleBytes += line.length + 1;
      if (this.#preambleBytes > MAX_PROTOCOL_PREAMBLE_BYTES) {
        this.#violation("the persistent protocol preamble is too large");
      }
      const readyPrefix =
        PROTOCOL_MAGIC + ":" + this.#sessionNonce + ":READY:";
      const raw = strictAscii(line);
      if (raw === undefined) return;
      if (raw === shellReadyMarker(this.#sessionNonce)) {
        if (!this.#shellReadyObserved) {
          this.#shellReadyObserved = true;
          this.#shellReadyDeferred.resolve();
        }
        return;
      }
      if (!raw.startsWith(readyPrefix)) return;
      const encodedHostname = raw.slice(readyPrefix.length);
      const hostnameBytes = decodeBase64Strict(encodedHostname);
      if (hostnameBytes === undefined) {
        this.#violation("the persistent protocol READY frame is invalid");
      }
      const hostname = decodeUtf8Strict(hostnameBytes);
      if (
        hostname === undefined ||
        !SAFE_EXPECTED_HOSTNAME_PATTERN.test(hostname)
      ) {
        this.#violation("the persistent protocol hostname is invalid");
      }
      this.#state = "idle";
      this.#readyDeferred.resolve(hostname);
      return;
    }

    if (this.#state !== "idle") return;
    const raw = strictAscii(line);
    if (raw === undefined) {
      this.#violation("the persistent protocol frame is not ASCII");
    }
    if (raw === PROTOCOL_MAGIC + ":" + this.#sessionNonce + ":FATAL") {
      this.#violation("the remote persistent broker rejected a frame");
    }
    const active = this.#active;
    if (active === undefined) {
      this.#violation("unexpected output arrived while the session was idle");
    }

    if (raw === active.prefix + ":BEGIN") {
      if (active.began) {
        this.#violation("the persistent protocol repeated BEGIN");
      }
      active.began = true;
      return;
    }

    const outputFrame = parseOutputFrame(active.prefix, raw);
    if (outputFrame !== undefined) {
      if (!active.began) {
        this.#violation("the persistent protocol sent output before BEGIN");
      }
      const decoded = decodeBase64Strict(outputFrame.encoded);
      if (decoded === undefined) {
        this.#violation("the persistent protocol output frame is invalid");
      }
      await this.#emit(active, outputFrame.stream, decoded);
      return;
    }

    const endPrefix = active.prefix + ":END:";
    if (raw.startsWith(endPrefix)) {
      if (!active.began) {
        this.#violation("the persistent protocol sent END before BEGIN");
      }
      const rawExitCode = raw.slice(endPrefix.length);
      if (!/^(?:0|[1-9][0-9]{0,9})$/u.test(rawExitCode)) {
        this.#violation("the persistent protocol exit code is invalid");
      }
      const exitCode = Number(rawExitCode);
      if (!Number.isSafeInteger(exitCode) || exitCode > 0xffff_ffff) {
        this.#violation("the persistent protocol exit code is out of range");
      }
      for (const stream of ["stdout", "stderr"] as const) {
        const tail = active.sanitizers[stream].finish();
        if (tail.byteLength > 0) {
          await this.#emitSanitized(active, stream, tail);
        }
      }
      active.completed = true;
      this.#active = undefined;
      active.deferred.resolve({ ...snapshotCommand(active), exitCode });
      return;
    }

    this.#violation("the persistent protocol received an unexpected frame");
  }

  async #emit(
    active: ActiveProtocolCommand,
    stream: OutputStream,
    decoded: Uint8Array,
  ): Promise<void> {
    const sanitized = active.sanitizers[stream].feed(decoded);
    if (sanitized.byteLength === 0) return;
    await this.#emitSanitized(active, stream, sanitized);
  }

  async #emitSanitized(
    active: ActiveProtocolCommand,
    stream: OutputStream,
    bytes: Uint8Array,
  ): Promise<void> {
    active.captures[stream].append(bytes);
    if (active.sink === undefined) return;
    try {
      const appendOperation = Promise.resolve(
        active.sink.append(stream, Buffer.from(bytes)),
      );
      void appendOperation.catch(() => undefined);
      await waitForSinkOperation(
        appendOperation,
        active.abortController.signal,
      );
    } catch (error: unknown) {
      if (active.abortController.signal.aborted) throw error;
      throw new OutputSinkProtocolError(error);
    }
  }

  #violation(message: string): never {
    const error = new SharedSessionProtocolError(message);
    this.fail(error);
    throw error;
  }
}

class TerminalSanitizer {
  #state:
    | "ground"
    | "escape"
    | "csi"
    | "osc"
    | "osc-escape"
    | "utf8-c2" = "ground";
  #lastWasCarriageReturn = false;

  public feed(chunk: Uint8Array): Buffer {
    const output: number[] = [];
    for (const byte of chunk) {
      switch (this.#state) {
        case "ground":
          if (byte === 0xc2) {
            this.#state = "utf8-c2";
            continue;
          }
          if (byte === 0x1b) {
            this.#state = "escape";
            continue;
          }
          if (byte === 0x0d) {
            output.push(0x0a);
            this.#lastWasCarriageReturn = true;
            continue;
          }
          if (byte === 0x0a && this.#lastWasCarriageReturn) {
            this.#lastWasCarriageReturn = false;
            continue;
          }
          this.#lastWasCarriageReturn = false;
          if (
            (byte < 0x20 && byte !== 0x09 && byte !== 0x0a) ||
            byte === 0x7f
          ) {
            continue;
          }
          output.push(byte);
          continue;
        case "escape":
          if (byte === 0x5b) this.#state = "csi";
          else if (byte === 0x5d) this.#state = "osc";
          else this.#state = "ground";
          continue;
        case "csi":
          if (byte >= 0x40 && byte <= 0x7e) this.#state = "ground";
          continue;
        case "osc":
          if (byte === 0x07) this.#state = "ground";
          else if (byte === 0x1b) this.#state = "osc-escape";
          continue;
        case "osc-escape":
          if (byte === 0x5c) this.#state = "ground";
          else if (byte !== 0x1b) this.#state = "osc";
          continue;
        case "utf8-c2":
          this.#state = "ground";
          if (byte >= 0x80 && byte <= 0x9f) continue;
          if (byte >= 0xa0 && byte <= 0xbf) {
            output.push(0xc2, byte);
            this.#lastWasCarriageReturn = false;
            continue;
          }
          if (byte === 0xc2) {
            this.#state = "utf8-c2";
            continue;
          }
          if (byte === 0x1b) {
            this.#state = "escape";
            continue;
          }
          if (byte === 0x0d) {
            output.push(0x0a);
            this.#lastWasCarriageReturn = true;
            continue;
          }
          if (byte === 0x0a && this.#lastWasCarriageReturn) {
            this.#lastWasCarriageReturn = false;
            continue;
          }
          this.#lastWasCarriageReturn = false;
          if (
            (byte < 0x20 && byte !== 0x09 && byte !== 0x0a) ||
            byte === 0x7f
          ) {
            continue;
          }
          output.push(byte);
          continue;
      }
    }
    return Buffer.from(output);
  }

  public finish(): Buffer {
    this.#state = "ground";
    this.#lastWasCarriageReturn = false;
    return Buffer.alloc(0);
  }
}

function buildPosixBrokerScript(
  sessionNonce: string,
  decodeFlag: "-d" | "-D",
): string {
  return [
    "#!/usr/bin/env bash",
    "set +m",
    "set -o pipefail",
    "__ash_session='" + sessionNonce + "'",
    "__ash_session_prefix='" + PROTOCOL_MAGIC + ":'$__ash_session",
    "__ash_expected=1",
    "__ash_fatal() { printf '%s:FATAL\\n' \"$__ash_session_prefix\"; exit 97; }",
    "__ash_forward() {",
    "  local __ash_frame",
    "  while IFS= read -r __ash_frame || [[ -n \"$__ash_frame\" ]]; do",
    "    printf '%s\\n' \"$__ash_frame\"",
    "  done",
    "}",
    "__ash_emit() {",
    "  local __ash_prefix=\"$1\"",
    "  local __ash_kind=\"$2\"",
    "  local __ash_data",
    "  local __ash_frame",
    "  while IFS= read -r __ash_data || [[ -n \"$__ash_data\" ]]; do",
    "    printf -v __ash_frame '%s:%s:%s' \"$__ash_prefix\" \"$__ash_kind\" \"$__ash_data\"",
    "    printf '%s\\n' \"$__ash_frame\" >&5",
    "  done",
    "}",
    "__ash_host=$(hostname 2>/dev/null) || __ash_fatal",
    "__ash_host_b64=$(printf '%s' \"$__ash_host\" | base64 | tr -d '\\r\\n') || __ash_fatal",
    "printf '\\n%s:READY:%s\\n' \"$__ash_session_prefix\" \"$__ash_host_b64\"",
    "while IFS= read -r __ash_line; do",
    "  __ash_delimiters=${__ash_line//[^:]/}",
    "  (( ${#__ash_delimiters} == 7 )) || __ash_fatal",
    "  IFS=: read -r __ash_magic __ash_session_in __ash_seq __ash_nonce __ash_verb __ash_command_b64 __ash_stdin_mode __ash_stdin_b64 __ash_extra <<< \"$__ash_line\"",
    "  [[ \"$__ash_magic\" == '" + PROTOCOL_MAGIC + "' ]] || __ash_fatal",
    "  [[ \"$__ash_session_in\" == \"$__ash_session\" ]] || __ash_fatal",
    "  [[ \"$__ash_seq\" == \"$__ash_expected\" ]] || __ash_fatal",
    "  [[ \"$__ash_nonce\" =~ ^[a-f0-9]{32}$ ]] || __ash_fatal",
    "  [[ \"$__ash_verb\" == 'RUN' ]] || __ash_fatal",
    "  [[ -z \"$__ash_extra\" ]] || __ash_fatal",
    "  [[ -n \"$__ash_command_b64\" && \"$__ash_command_b64\" =~ ^[A-Za-z0-9+/]*={0,2}$ ]] || __ash_fatal",
    "  (( ${#__ash_command_b64} % 4 == 0 )) || __ash_fatal",
    "  if [[ \"$__ash_stdin_mode\" == 'N' ]]; then",
    "    [[ -z \"$__ash_stdin_b64\" ]] || __ash_fatal",
    "  elif [[ \"$__ash_stdin_mode\" == 'B' ]]; then",
    "    [[ \"$__ash_stdin_b64\" =~ ^[A-Za-z0-9+/]*={0,2}$ ]] || __ash_fatal",
    "    (( ${#__ash_stdin_b64} % 4 == 0 )) || __ash_fatal",
    "  else",
    "    __ash_fatal",
    "  fi",
    "  __ash_command=$(printf '%s' \"$__ash_command_b64\" | base64 " +
      decodeFlag +
      ") || __ash_fatal",
    "  __ash_prefix=\"$__ash_session_prefix:$__ash_seq:$__ash_nonce\"",
    "  printf '%s:BEGIN\\n' \"$__ash_prefix\"",
    "  exec 5> >(__ash_forward) || __ash_fatal",
    "  __ash_mux_pid=$!",
    "  exec 3> >(base64 | __ash_emit \"$__ash_prefix\" OUT) || __ash_fatal",
    "  __ash_out_pid=$!",
    "  exec 4> >(base64 | __ash_emit \"$__ash_prefix\" ERR) || __ash_fatal",
    "  __ash_err_pid=$!",
    "  if [[ \"$__ash_stdin_mode\" == 'N' ]]; then",
    "    bash -c \"$__ash_command\" </dev/null 1>&3 2>&4",
    "    __ash_rc=$?",
    "  else",
    "    printf '%s' \"$__ash_stdin_b64\" | base64 " +
      decodeFlag +
    " | bash -c \"$__ash_command\" 1>&3 2>&4",
    "    __ash_status=(\"${PIPESTATUS[@]}\")",
    "    (( ${#__ash_status[@]} == 3 && __ash_status[0] == 0 && __ash_status[1] == 0 )) || __ash_fatal",
    "    __ash_rc=${__ash_status[2]}",
    "  fi",
    "  exec 3>&- 4>&-",
    "  wait \"$__ash_out_pid\"; __ash_out_rc=$?",
    "  wait \"$__ash_err_pid\"; __ash_err_rc=$?",
    "  exec 5>&-",
    "  wait \"$__ash_mux_pid\"; __ash_mux_rc=$?",
    "  (( __ash_out_rc == 0 && __ash_err_rc == 0 && __ash_mux_rc == 0 )) || __ash_fatal",
    "  [[ \"$__ash_rc\" =~ ^[0-9]+$ ]] || __ash_fatal",
    "  printf '%s:END:%s\\n' \"$__ash_prefix\" \"$__ash_rc\"",
    "  __ash_expected=$((__ash_expected + 1))",
    "done",
  ].join("\n");
}

function buildWindowsBrokerScript(sessionNonce: string): string {
  const commandWrapper = [
    "$ErrorActionPreference='Stop'",
    "$ashUtf8=[System.Text.UTF8Encoding]::new($false,$true)",
    "[Console]::OutputEncoding=$ashUtf8",
    "$OutputEncoding=$ashUtf8",
    "$ashInput=[Console]::OpenStandardInput()",
    "$ashHeader=New-Object IO.MemoryStream",
    "$ashByte=-1",
    "while(($ashByte=$ashInput.ReadByte()) -ge 0 -and $ashByte -ne 10){if($ashByte -gt 127 -or $ashHeader.Length -ge 131072){exit 94};$ashHeader.WriteByte([byte]$ashByte)}",
    "if($ashByte -ne 10){exit 94}",
    "$ashCommandBase64=[Text.Encoding]::ASCII.GetString($ashHeader.ToArray())",
    "$ashCommand=$ashUtf8.GetString([Convert]::FromBase64String($ashCommandBase64))",
    "& $env:ComSpec '/d' '/s' '/c' $ashCommand",
    "$ashCode=if($global:LASTEXITCODE -is [int]){$global:LASTEXITCODE}elseif($?){0}else{1}",
    "exit $ashCode",
  ].join(";");
  const nativeSource =
    "using System; using System.Runtime.InteropServices; " +
    "public static class AshConsoleMode { " +
    "[DllImport(\"kernel32.dll\", SetLastError=true)] " +
    "public static extern IntPtr GetStdHandle(int nStdHandle); " +
    "[DllImport(\"kernel32.dll\", SetLastError=true)] " +
    "public static extern bool GetConsoleMode(IntPtr handle, out uint mode); " +
    "[DllImport(\"kernel32.dll\", SetLastError=true)] " +
    "public static extern bool SetConsoleMode(IntPtr handle, uint mode); " +
    "[DllImport(\"kernel32.dll\")] " +
    "public static extern uint GetFileType(IntPtr handle); }";
  return [
    "$ErrorActionPreference='Stop'",
    "$ashUtf8=[System.Text.UTF8Encoding]::new($false,$true)",
    "[Console]::InputEncoding=$ashUtf8",
    "[Console]::OutputEncoding=$ashUtf8",
    "$OutputEncoding=$ashUtf8",
    "$ashNativeSource='" + nativeSource.replaceAll("'", "''") + "'",
    "Add-Type -TypeDefinition $ashNativeSource -ErrorAction Stop",
    "$ashInputHandle=[AshConsoleMode]::GetStdHandle(-10)",
    "$ashConsoleMode=[uint32]0",
    "if([AshConsoleMode]::GetConsoleMode($ashInputHandle,[ref]$ashConsoleMode)){",
    "  $ashNoEcho=$ashConsoleMode -band (-bnot [uint32]4)",
    "  if(-not [AshConsoleMode]::SetConsoleMode($ashInputHandle,$ashNoEcho)){exit 96}",
    "  $ashVerifiedMode=[uint32]0",
    "  if(-not [AshConsoleMode]::GetConsoleMode($ashInputHandle,[ref]$ashVerifiedMode)){exit 96}",
    "  if(($ashVerifiedMode -band [uint32]4) -ne 0){exit 96}",
    "} elseif([AshConsoleMode]::GetFileType($ashInputHandle) -ne 3){exit 96}",
    "$ashSession='" + sessionNonce + "'",
    "$ashSessionPrefix='" + PROTOCOL_MAGIC + ":'+$ashSession",
    "[uint64]$ashExpected=1",
    "function Write-AshFatal { [Console]::Out.WriteLine($script:ashSessionPrefix+':FATAL'); exit 97 }",
    "function Write-AshBytes([string]$Prefix,[string]$Kind,[byte[]]$Buffer,[int]$Count) {",
    "  if($Count -le 0){return}",
    "  $ashChunk=[byte[]]::new($Count)",
    "  [Buffer]::BlockCopy($Buffer,0,$ashChunk,0,$Count)",
    "  [Console]::Out.WriteLine($Prefix+':'+$Kind+':'+[Convert]::ToBase64String($ashChunk))",
    "}",
    "$ashHost=[System.Net.Dns]::GetHostName()",
    "$ashHostBytes=$ashUtf8.GetBytes($ashHost)",
    "[Console]::Out.WriteLine()",
    "[Console]::Out.WriteLine($ashSessionPrefix+':READY:'+[Convert]::ToBase64String($ashHostBytes))",
    "while($null -ne ($ashLine=[Console]::In.ReadLine())) {",
    "  $ashParts=$ashLine.Split(':')",
    "  if($ashParts.Length -ne 8){Write-AshFatal}",
    "  if($ashParts[0] -cne '" + PROTOCOL_MAGIC + "'){Write-AshFatal}",
    "  if($ashParts[1] -cne $ashSession){Write-AshFatal}",
    "  if($ashParts[2] -cne $ashExpected.ToString([Globalization.CultureInfo]::InvariantCulture)){Write-AshFatal}",
    "  if(-not [regex]::IsMatch($ashParts[3],'^[a-f0-9]{32}$')){Write-AshFatal}",
    "  if($ashParts[4] -cne 'RUN'){Write-AshFatal}",
    "  if([string]::IsNullOrEmpty($ashParts[5]) -or -not [regex]::IsMatch($ashParts[5],'^[A-Za-z0-9+/]*={0,2}$') -or (($ashParts[5].Length % 4) -ne 0)){Write-AshFatal}",
    "  if($ashParts[6] -ceq 'N') {",
    "    if($ashParts[7].Length -ne 0){Write-AshFatal}",
    "  } elseif($ashParts[6] -ceq 'B') {",
    "    if(-not [regex]::IsMatch($ashParts[7],'^[A-Za-z0-9+/]*={0,2}$') -or (($ashParts[7].Length % 4) -ne 0)){Write-AshFatal}",
    "  } else {",
    "    Write-AshFatal",
    "  }",
    "  try {",
    "    if($ashParts[6] -ceq 'B'){[byte[]]$ashInputBytes=[Convert]::FromBase64String($ashParts[7])}else{[byte[]]$ashInputBytes=[byte[]]::new(0)}",
    "  } catch { Write-AshFatal }",
    "  $ashPrefix=$ashSessionPrefix+':'+$ashParts[2]+':'+$ashParts[3]",
    "  [Console]::Out.WriteLine($ashPrefix+':BEGIN')",
    "  $ashStart=[Diagnostics.ProcessStartInfo]::new()",
    "  $ashStart.FileName='powershell.exe'",
    "  $ashStart.Arguments='-NoLogo -NoProfile -NonInteractive -Command \"" +
      commandWrapper.replaceAll("'", "''") +
      "\"'",
    "  $ashStart.UseShellExecute=$false",
    "  $ashStart.CreateNoWindow=$true",
    "  $ashStart.RedirectStandardInput=$true",
    "  $ashStart.RedirectStandardOutput=$true",
    "  $ashStart.RedirectStandardError=$true",
    "  $ashProcess=[Diagnostics.Process]::new()",
    "  $ashProcess.StartInfo=$ashStart",
    "  try{if(-not $ashProcess.Start()){Write-AshFatal}}catch{Write-AshFatal}",
    "  $ashHeaderBytes=[Text.Encoding]::ASCII.GetBytes($ashParts[5]+\"`n\")",
    "  $ashPayload=[byte[]]::new($ashHeaderBytes.Length+$ashInputBytes.Length)",
    "  [Buffer]::BlockCopy($ashHeaderBytes,0,$ashPayload,0,$ashHeaderBytes.Length)",
    "  if($ashInputBytes.Length -gt 0){[Buffer]::BlockCopy($ashInputBytes,0,$ashPayload,$ashHeaderBytes.Length,$ashInputBytes.Length)}",
    "  $ashOutBuffer=[byte[]]::new(32768)",
    "  $ashErrBuffer=[byte[]]::new(32768)",
    "  $ashOutOpen=$true;$ashErrOpen=$true;$ashWriteOpen=$true",
    "  $ashOutTask=$ashProcess.StandardOutput.BaseStream.ReadAsync($ashOutBuffer,0,$ashOutBuffer.Length)",
    "  $ashErrTask=$ashProcess.StandardError.BaseStream.ReadAsync($ashErrBuffer,0,$ashErrBuffer.Length)",
    "  $ashWriteTask=$ashProcess.StandardInput.BaseStream.WriteAsync($ashPayload,0,$ashPayload.Length)",
    "  while($ashOutOpen -or $ashErrOpen -or $ashWriteOpen){",
    "    $ashTasks=@();if($ashOutOpen){$ashTasks+=$ashOutTask};if($ashErrOpen){$ashTasks+=$ashErrTask};if($ashWriteOpen){$ashTasks+=$ashWriteTask}",
    "    [void][Threading.Tasks.Task]::WaitAny([Threading.Tasks.Task[]]$ashTasks)",
    "    if($ashWriteOpen -and $ashWriteTask.IsCompleted){try{[void]$ashWriteTask.GetAwaiter().GetResult()}catch{Write-AshFatal};try{$ashProcess.StandardInput.Close()}catch{Write-AshFatal};$ashWriteOpen=$false}",
    "    if($ashOutOpen -and $ashOutTask.IsCompleted){try{$ashCount=$ashOutTask.GetAwaiter().GetResult()}catch{Write-AshFatal};if($ashCount -eq 0){$ashOutOpen=$false}else{Write-AshBytes $ashPrefix OUT $ashOutBuffer $ashCount;$ashOutTask=$ashProcess.StandardOutput.BaseStream.ReadAsync($ashOutBuffer,0,$ashOutBuffer.Length)}}",
    "    if($ashErrOpen -and $ashErrTask.IsCompleted){try{$ashCount=$ashErrTask.GetAwaiter().GetResult()}catch{Write-AshFatal};if($ashCount -eq 0){$ashErrOpen=$false}else{Write-AshBytes $ashPrefix ERR $ashErrBuffer $ashCount;$ashErrTask=$ashProcess.StandardError.BaseStream.ReadAsync($ashErrBuffer,0,$ashErrBuffer.Length)}}",
    "  }",
    "  $ashProcess.WaitForExit()",
    "  $ashCode=[int64]$ashProcess.ExitCode",
    "  $ashProcess.Dispose()",
    "  if($ashCode -lt 0){$ashCode=[BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$ashCode),0)}",
    "  if($ashCode -gt [uint32]::MaxValue){Write-AshFatal}",
    "  [Console]::Out.WriteLine($ashPrefix+':END:'+$ashCode.ToString([Globalization.CultureInfo]::InvariantCulture))",
    "  $ashExpected++",
    "}",
  ].join("\r\n");
}

function managedProcessOptions(
  options: PuttySharedExecutorOptions,
  signal: AbortSignal,
): ManagedProcessOptions {
  return {
    executable: options.executable,
    arguments: buildPuttySharedArguments(options),
    streamStdin: true,
    signal,
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
          allowUnsafeProcessTermination:
            options.allowUnsafeProcessTermination,
        }),
  };
}

const EMPTY_SNAPSHOT: CommandSnapshot = Object.freeze({
  stdout: "",
  stderr: "",
  stdoutBytes: 0,
  stderrBytes: 0,
  stdoutTruncated: false,
  stderrTruncated: false,
});

class SharedSessionUnavailableError extends Error {
  public readonly snapshot: CommandSnapshot;
  public readonly terminationMode: ProcessTerminationMode | null;
  public readonly timedOut: boolean;
  public override readonly cause: unknown;

  public constructor(
    snapshot: CommandSnapshot,
    terminationMode: ProcessTerminationMode | null,
    timedOut: boolean,
    cause?: unknown,
  ) {
    super("the AccessClient shared session is unavailable");
    this.name = "SharedSessionUnavailableError";
    this.snapshot = snapshot;
    this.terminationMode = terminationMode;
    this.timedOut = timedOut;
    this.cause = cause;
  }
}

class SharedSessionHostMismatchError extends Error {
  public readonly snapshot: CommandSnapshot;
  public readonly terminationMode: ProcessTerminationMode | null;

  public constructor(
    snapshot: CommandSnapshot,
    terminationMode: ProcessTerminationMode | null,
  ) {
    super("the AccessClient shared session hostname did not match");
    this.name = "SharedSessionHostMismatchError";
    this.snapshot = snapshot;
    this.terminationMode = terminationMode;
  }
}

class SharedSessionCommandError extends Error {
  public readonly snapshot: CommandSnapshot;
  public readonly terminationMode: ProcessTerminationMode | null;
  public override readonly cause: unknown;

  public constructor(
    snapshot: CommandSnapshot,
    terminationMode: ProcessTerminationMode | null,
    cause?: unknown,
  ) {
    super("the persistent AccessClient command did not complete");
    this.name = "SharedSessionCommandError";
    this.snapshot = snapshot;
    this.terminationMode = terminationMode;
    this.cause = cause;
  }
}

class SharedSessionAbortedError extends Error {
  public readonly snapshot: CommandSnapshot;
  public readonly terminationMode: ProcessTerminationMode | null;
  public override readonly cause: unknown;

  public constructor(
    snapshot: CommandSnapshot,
    terminationMode: ProcessTerminationMode | null,
    cause?: unknown,
  ) {
    super("the persistent AccessClient command was aborted");
    this.name = "AbortError";
    this.snapshot = snapshot;
    this.terminationMode = terminationMode;
    this.cause = cause;
  }
}

class SharedSessionAbortSignalError extends Error {
  public override readonly cause: unknown;

  public constructor(cause?: unknown) {
    super("the persistent AccessClient operation was aborted");
    this.name = "AbortError";
    this.cause = cause;
  }
}

class SharedSessionProtocolError extends Error {
  public override readonly cause: unknown;

  public constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "SharedSessionProtocolError";
    this.cause = cause;
  }
}

class SharedSessionCleanupError extends SshExecutionError {
  public constructor(primaryError: unknown, cleanupError: unknown) {
    super(
      "the persistent AccessClient session failed and could not be cleaned up",
      {
        cause: new AggregateError(
          [primaryError, cleanupError],
          "persistent AccessClient operation and cleanup both failed",
        ),
      },
    );
    this.name = "SharedSessionCleanupError";
  }
}

class OutputSinkProtocolError extends Error {
  public override readonly cause: unknown;

  public constructor(cause: unknown) {
    super("the persistent AccessClient output sink failed");
    this.name = "OutputSinkProtocolError";
    this.cause = cause;
  }
}

interface Deferred<Value> {
  readonly promise: Promise<Value>;
  resolve(value: Value): void;
  reject(error: unknown): void;
}

function deferred<Value>(): Deferred<Value> {
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

function snapshotCommand(active: ActiveProtocolCommand): CommandSnapshot {
  return {
    stdout: active.captures.stdout.toString(),
    stderr: active.captures.stderr.toString(),
    stdoutBytes: active.captures.stdout.totalBytes,
    stderrBytes: active.captures.stderr.totalBytes,
    stdoutTruncated: active.captures.stdout.truncated,
    stderrTruncated: active.captures.stderr.truncated,
  };
}

function aggregateSessionCleanupError(
  primaryError: unknown,
  cleanupError: unknown,
): SshExecutionError {
  return new SharedSessionCleanupError(primaryError, cleanupError);
}

function parseOutputFrame(
  prefix: string,
  raw: string,
): { readonly stream: OutputStream; readonly encoded: string } | undefined {
  const stdoutPrefix = prefix + ":OUT:";
  if (raw.startsWith(stdoutPrefix)) {
    return { stream: "stdout", encoded: raw.slice(stdoutPrefix.length) };
  }
  const stderrPrefix = prefix + ":ERR:";
  if (raw.startsWith(stderrPrefix)) {
    return { stream: "stderr", encoded: raw.slice(stderrPrefix.length) };
  }
  return undefined;
}

function randomHex(
  size: number,
  source: ((size: number) => Uint8Array) | undefined,
): string {
  const bytes = Buffer.from((source ?? cryptoRandomBytes)(size));
  if (bytes.byteLength !== size) {
    throw new SshExecutionError(
      "the protocol random source returned an invalid byte count",
    );
  }
  return bytes.toString("hex");
}

function validateNonce(value: string, label: string): void {
  if (!HEX_128_PATTERN.test(value)) {
    throw new TypeError(label + " is invalid");
  }
}

function decodeBase64Strict(value: string): Buffer | undefined {
  if (
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]*={0,2}$/u.test(value)
  ) {
    return undefined;
  }
  const decoded = Buffer.from(value, "base64");
  return decoded.toString("base64") === value ? decoded : undefined;
}

function decodeUtf8Strict(value: Uint8Array): string | undefined {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(value);
  } catch {
    return undefined;
  }
}

function strictAscii(line: Uint8Array): string | undefined {
  for (const byte of line) {
    if (byte > 0x7f) return undefined;
  }
  return Buffer.from(line).toString("ascii");
}

function waitWithSignal<Value>(
  promise: Promise<Value>,
  signal: AbortSignal,
  onAbort: () => void,
): Promise<Value> {
  return new Promise<Value>((resolve, reject) => {
    let settled = false;
    const finish = (error: unknown, value?: Value): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", abort);
      if (error === undefined) {
        resolve(value as Value);
      } else {
        reject(error);
      }
    };
    const abort = (): void => {
      onAbort();
      finish(new SharedSessionAbortSignalError(signal.reason));
    };
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) {
      abort();
      return;
    }
    void promise.then(
      (value) => finish(undefined, value),
      (error: unknown) => finish(error),
    );
  });
}

function waitForRetryDelay(
  milliseconds: number,
  signal: AbortSignal,
): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: unknown): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      signal.removeEventListener("abort", onAbort);
      if (error === undefined) resolve();
      else reject(error);
    };
    const onAbort = (): void =>
      finish(new SharedSessionAbortSignalError(signal.reason));
    const timeout = setTimeout(finish, milliseconds);
    timeout.unref();
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
  });
}

function waitForSinkOperation(
  operation: Promise<void>,
  signal: AbortSignal,
): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: unknown): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      if (error === undefined) resolve();
      else reject(error);
    };
    const onAbort = (): void =>
      finish(
        signal.reason ??
          new SharedSessionProtocolError(
            "the persistent output operation was aborted",
          ),
      );
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) {
      onAbort();
      return;
    }
    void operation.then(
      () => finish(),
      (error: unknown) => finish(error),
    );
  });
}

function writeWritable(
  stream: NodeJS.WritableStream,
  data: Uint8Array,
  signal: AbortSignal,
): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const onError = (error: Error): void => finish(error);
    const onAbort = (): void =>
      finish(new SharedSessionAbortSignalError(signal.reason));
    const finish = (error?: unknown): void => {
      if (settled) return;
      settled = true;
      stream.removeListener("error", onError);
      signal.removeEventListener("abort", onAbort);
      if (error === undefined || error === null) resolve();
      else reject(error);
    };
    stream.once("error", onError);
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) {
      onAbort();
      return;
    }
    try {
      stream.write(Buffer.from(data), finish);
    } catch (error: unknown) {
      finish(error);
    }
  });
}

function waitForChildClose(
  child: ChildProcessWithoutNullStreams,
): Promise<{
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly error: Error | undefined;
}> {
  return new Promise((resolve) => {
    let settled = false;
    let processError: Error | undefined;
    const finish = (
      code: number | null,
      signal: NodeJS.Signals | null,
    ): void => {
      if (settled) return;
      settled = true;
      child.removeListener("error", onError);
      child.removeListener("close", onClose);
      resolve({ code, signal, error: processError });
    };
    const onError = (error: Error): void => {
      processError = error;
    };
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

async function appendDiagnostic(
  sink: OutputSink | undefined,
  message: string,
): Promise<void> {
  try {
    await sink?.append("stderr", Buffer.from(message, "utf8"));
  } catch (error: unknown) {
    throw new SshExecutionError("the SSH output sink failed", { cause: error });
  }
}

function validateOptions(options: PuttySharedExecutorOptions): void {
  if (!TARGET_ALIAS_PATTERN.test(options.targetAlias)) {
    throw new TypeError("targetAlias is invalid");
  }
  if (options.executable.length === 0 || /[\0\r\n]/u.test(options.executable)) {
    throw new TypeError("executable is invalid");
  }
  validateGateway(options);
  if (
    options.expectedHostname !== undefined &&
    !SAFE_EXPECTED_HOSTNAME_PATTERN.test(options.expectedHostname)
  ) {
    throw new TypeError("expectedHostname is invalid");
  }
  if (
    !new Set<TargetPlatform>(["windows", "linux", "macos"]).has(
      options.platform,
    )
  ) {
    throw new TypeError("platform is invalid");
  }
  for (const [label, value] of [
    ["idleTimeoutMs", options.idleTimeoutMs],
    ["maxLifetimeMs", options.maxLifetimeMs],
    ["bootstrapTimeoutMs", options.bootstrapTimeoutMs],
  ] as const) {
    if (
      value !== undefined &&
      (!Number.isSafeInteger(value) || value < 1)
    ) {
      throw new RangeError(label + " must be a positive safe integer");
    }
  }
  if (options.maxCapturedOutputBytes !== undefined) {
    validateByteLimit(
      options.maxCapturedOutputBytes,
      "maxCapturedOutputBytes",
    );
  }
}

function validateGateway(
  options: Pick<
    PuttySharedExecutorOptions,
    | "gatewayHost"
    | "gatewayPort"
    | "gatewayUsername"
    | "sharingHost"
    | "sharingPort"
  >,
): void {
  if (!SAFE_HOST_PATTERN.test(options.gatewayHost)) {
    throw new TypeError("gatewayHost is invalid");
  }
  if (
    options.sharingHost !== undefined &&
    !SAFE_HOST_PATTERN.test(options.sharingHost)
  ) {
    throw new TypeError("sharingHost is invalid");
  }
  if (options.sharingHost === undefined && options.sharingPort !== undefined) {
    throw new TypeError("sharingPort requires sharingHost");
  }
  if (
    options.sharingPort !== undefined &&
    (!Number.isSafeInteger(options.sharingPort) ||
      options.sharingPort < 1 ||
      options.sharingPort > 65_535)
  ) {
    throw new RangeError(
      "sharingPort must be an integer from 1 through 65535",
    );
  }
  if (
    !Number.isSafeInteger(options.gatewayPort) ||
    options.gatewayPort < 1 ||
    options.gatewayPort > 65_535
  ) {
    throw new RangeError(
      "gatewayPort must be an integer from 1 through 65535",
    );
  }
  if (
    options.gatewayUsername.length === 0 ||
    options.gatewayUsername.length > 128 ||
    /[\0\r\n]/u.test(options.gatewayUsername)
  ) {
    throw new TypeError("gatewayUsername is invalid");
  }
}

function validateInput(
  options: PuttySharedExecutorOptions,
  input: SshRunInput,
): void {
  if (input.sshAlias !== options.targetAlias) {
    throw new TypeError("sshAlias does not match the PuTTY shared target");
  }
  if (input.command.trim().length === 0 || /[\0\r\n]/u.test(input.command)) {
    throw new TypeError("command is invalid");
  }
  if (Buffer.byteLength(input.command, "utf8") > MAX_COMMAND_BYTES) {
    throw new RangeError(
      "command must not exceed " +
        String(MAX_COMMAND_BYTES) +
        " UTF-8 bytes",
    );
  }
  if (
    input.stdin !== undefined &&
    input.stdin.byteLength > MAX_MANAGED_STDIN_BYTES
  ) {
    throw new RangeError(
      "stdin must not exceed " +
        String(MAX_MANAGED_STDIN_BYTES) +
        " bytes",
    );
  }
  if (input.maxCapturedOutputBytes !== undefined) {
    validateByteLimit(
      input.maxCapturedOutputBytes,
      "maxCapturedOutputBytes",
    );
  }
}

function validateByteLimit(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(name + " must be a non-negative safe integer");
  }
}
