import { WINDOWS_POWERSHELL_REMOTE_COMMAND } from "../core/remote-command.js";
import type { ManagedProcess } from "./process-tree.js";
import {
  SshExecutionError,
  type SshOutcome,
  type SshRunInput,
  type SshRunner,
} from "./ssh-runner.js";

/** An executor that can start a remote command before its input is known. */
export interface PrestartingSshRunner extends SshRunner {
  prestart(sshAlias: string, command: string): Promise<ManagedProcess | undefined>;
  runPrestarted(prestarted: ManagedProcess, input: SshRunInput): Promise<SshOutcome>;
}

export interface StandbyPowerShellExecutorOptions {
  readonly sshAlias: string;
  /** How long an unused standby process waits before it is closed. */
  readonly idleTimeoutMs?: number;
  /** Delay before replacing a standby process that exited on its own. */
  readonly retryAfterFailureMs?: number;
  /** Called after an idle standby closed, e.g. to release the shared connection. */
  readonly onIdle?: () => Promise<void>;
}

const DEFAULT_IDLE_TIMEOUT_MS = 600_000;
const DEFAULT_RETRY_AFTER_FAILURE_MS = 60_000;
const STANDBY_EXIT_GRACE_MS = 5_000;

interface Standby {
  readonly process: ManagedProcess;
  readonly idleTimer: NodeJS.Timeout;
}

/**
 * Keeps one Windows PowerShell process per target started and waiting for its
 * script, so a command skips opening a channel and starting PowerShell (about
 * a second over a slow link).
 *
 * A standby process runs exactly one command, with the same remote command
 * line and input that a cold run uses, so no state carries over between
 * commands. Its replacement starts only after a command finishes, so it sees
 * environment changes that command made, such as PATH after an install.
 */
export class StandbyPowerShellExecutor implements SshRunner {
  readonly #executor: PrestartingSshRunner;
  readonly #options: StandbyPowerShellExecutorOptions;
  #standby: Standby | undefined;
  #starting: Promise<void> | undefined;
  #running = 0;
  #failedAt: number | undefined;
  #closed = false;
  #closeOperation: Promise<void> | undefined;

  public constructor(
    executor: PrestartingSshRunner,
    options: StandbyPowerShellExecutorOptions,
  ) {
    this.#executor = executor;
    this.#options = options;
  }

  public async run(input: SshRunInput): Promise<SshOutcome> {
    if (this.#closed) throw new SshExecutionError("the SSH executor is closed");
    if (
      input.sshAlias !== this.#options.sshAlias ||
      input.command !== WINDOWS_POWERSHELL_REMOTE_COMMAND ||
      input.stdin === undefined ||
      input.signal?.aborted === true
    ) {
      return this.#executor.run(input);
    }

    const standby = this.#take();
    this.#running += 1;
    try {
      if (standby === undefined) return await this.#executor.run(input);
      try {
        return await this.#executor.runPrestarted(standby, input);
      } catch (error: unknown) {
        // E.g. rejected input: a process that never got its script must not linger.
        await stopProcess(standby);
        throw error;
      }
    } finally {
      this.#running -= 1;
      this.#replenish();
    }
  }

  /** Ends the waiting process; commands already running finish normally. */
  public close(): Promise<void> {
    this.#closed = true;
    this.#closeOperation ??= (async () => {
      await this.#starting;
      await this.#retire();
    })();
    return this.#closeOperation;
  }

  #take(): ManagedProcess | undefined {
    const standby = this.#standby;
    if (standby === undefined) return undefined;
    this.#standby = undefined;
    clearTimeout(standby.idleTimer);
    if (hasExited(standby.process) || !standby.process.child.stdin.writable) {
      this.#failedAt = Date.now();
      void stopProcess(standby.process);
      return undefined;
    }
    return standby.process;
  }

  #replenish(): void {
    if (this.#closed || this.#standby !== undefined || this.#starting !== undefined) {
      return;
    }
    const retryAfter =
      this.#options.retryAfterFailureMs ?? DEFAULT_RETRY_AFTER_FAILURE_MS;
    if (this.#failedAt !== undefined && Date.now() - this.#failedAt < retryAfter) {
      return;
    }

    const operation = (async (): Promise<void> => {
      let prestarted: ManagedProcess | undefined;
      try {
        prestarted = await this.#executor.prestart(
          this.#options.sshAlias,
          WINDOWS_POWERSHELL_REMOTE_COMMAND,
        );
      } catch {
        // Commands keep using cold runs; a failure only delays the next attempt.
        this.#failedAt = Date.now();
        return;
      }
      if (prestarted === undefined) return;
      if (this.#closed) {
        await stopProcess(prestarted);
        return;
      }
      this.#adopt(prestarted);
    })();
    this.#starting = operation;
    const clear = (): void => {
      if (this.#starting === operation) this.#starting = undefined;
    };
    void operation.then(clear, clear);
  }

  #adopt(prestarted: ManagedProcess): void {
    if (hasExited(prestarted)) {
      this.#failedAt = Date.now();
      releaseStreams(prestarted);
      return;
    }
    const standby: Standby = {
      process: prestarted,
      idleTimer: setTimeout(
        () => void this.#expire(standby),
        this.#options.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS,
      ),
    };
    standby.idleTimer.unref();
    prestarted.child.once("exit", () => {
      if (this.#standby !== standby) return;
      // It exited before a command reached it, e.g. the connection dropped.
      this.#standby = undefined;
      clearTimeout(standby.idleTimer);
      this.#failedAt = Date.now();
      releaseStreams(prestarted);
    });
    this.#standby = standby;
  }

  async #expire(standby: Standby): Promise<void> {
    if (this.#standby !== standby) return;
    await this.#retire();
    if (
      this.#closed ||
      this.#running !== 0 ||
      this.#standby !== undefined ||
      this.#starting !== undefined
    ) {
      return;
    }
    await this.#options.onIdle?.().catch(() => undefined);
  }

  async #retire(): Promise<void> {
    const standby = this.#standby;
    if (standby === undefined) return;
    this.#standby = undefined;
    clearTimeout(standby.idleTimer);
    await stopProcess(standby.process);
  }
}

/** PowerShell reading a script from standard input exits at its end without running anything. */
async function stopProcess(prestarted: ManagedProcess): Promise<void> {
  const { child } = prestarted;
  // Nothing a waiting process wrote belongs to a command.
  child.stdout.resume();
  child.stderr.resume();
  if (!hasExited(prestarted)) {
    const exited = new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => resolve(false), STANDBY_EXIT_GRACE_MS);
      child.once("exit", () => {
        clearTimeout(timer);
        resolve(true);
      });
    });
    child.stdin.end();
    if (!(await exited)) await prestarted.terminate().catch(() => undefined);
  }
  releaseStreams(prestarted);
}

function releaseStreams(prestarted: ManagedProcess): void {
  prestarted.child.stdin.destroy();
  prestarted.child.stdout.destroy();
  prestarted.child.stderr.destroy();
}

function hasExited(prestarted: ManagedProcess): boolean {
  return prestarted.child.exitCode !== null || prestarted.child.signalCode !== null;
}
