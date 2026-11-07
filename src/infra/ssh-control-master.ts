import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { lstat, mkdir, rm } from "node:fs/promises";
import path from "node:path";

import {
  buildOpenSshControlCommandArguments,
  buildOpenSshControlMasterArguments,
  type SshControlPathProvider,
  type SshExecutorOptions,
} from "./openssh-executor.js";

export interface SshControlMasterPoolOptions
  extends Pick<
    SshExecutorOptions,
    "configFile" | "knownHostsFile" | "connectTimeoutSeconds"
  > {
  readonly executable: string;
  /** Private (0700) directory that will hold this pool's socket directory. */
  readonly runtimeDirectory: string;
  readonly persistSeconds?: number;
  readonly retryAfterFailureMs?: number;
  readonly platform?: NodeJS.Platform;
}

const DEFAULT_PERSIST_SECONDS = 600;
const DEFAULT_RETRY_AFTER_FAILURE_MS = 60_000;
const DEFAULT_CONNECT_TIMEOUT_SECONDS = 15;
const CONTROL_COMMAND_TIMEOUT_MS = 5_000;
// sun_path is 104 bytes on macOS; OpenSSH binds a ".XXXXXXXXXXXXXXXX" temporary
// name first, so keep generous headroom below the platform limit.
const MAX_SOCKET_PATH_BYTES = 104 - 1 - 17;

/**
 * Keeps one daemonized OpenSSH control master per target alias so commands and
 * SFTP sessions skip the TCP, key exchange, and authentication round trips.
 *
 * Each pool owns a fresh socket directory, so a configuration reload never
 * reuses a master authenticated under a previous generation's keys or host
 * keys. Masters run in their own session, so terminating one command's process
 * group cannot tear down sessions that other commands multiplex over it.
 */
export class SshControlMasterPool implements SshControlPathProvider {
  readonly #options: SshControlMasterPoolOptions;
  readonly #directory: string;
  readonly #starting = new Map<string, Promise<string | undefined>>();
  readonly #failedAt = new Map<string, number>();
  readonly #started = new Set<string>();
  #closed = false;
  #closeOperation: Promise<void> | undefined;

  private constructor(options: SshControlMasterPoolOptions, directory: string) {
    this.#options = options;
    this.#directory = directory;
  }

  /**
   * Returns undefined where multiplexing is unavailable (Win32-OpenSSH has no
   * ControlMaster support) or the socket path would not fit in sun_path.
   */
  public static async create(
    options: SshControlMasterPoolOptions,
  ): Promise<SshControlMasterPool | undefined> {
    if ((options.platform ?? process.platform) === "win32") return undefined;
    const directory = path.join(
      options.runtimeDirectory,
      "mux-" + randomBytes(4).toString("hex"),
    );
    if (
      Buffer.byteLength(socketPathFor(directory, "x"), "utf8") >
        MAX_SOCKET_PATH_BYTES ||
      /[%~$\s]/u.test(directory)
    ) {
      return undefined;
    }
    await mkdir(directory, { mode: 0o700 });
    return new SshControlMasterPool(options, directory);
  }

  public get directory(): string {
    return this.#directory;
  }

  public async acquire(
    sshAlias: string,
    signal?: AbortSignal,
  ): Promise<string | undefined> {
    if (this.#closed || signal?.aborted === true) return undefined;
    const pending =
      this.#starting.get(sshAlias) ?? this.#ensureMaster(sshAlias);
    return raceAbort(pending, signal);
  }

  /**
   * Stops masters for removed or idle targets; in-flight sessions finish
   * normally and the next acquire starts a fresh master.
   */
  public async release(sshAliases: readonly string[]): Promise<void> {
    await Promise.all(
      sshAliases.map(async (alias) => {
        this.#failedAt.delete(alias);
        await this.#starting.get(alias)?.catch(() => undefined);
        await this.#stop(alias);
      }),
    );
  }

  public close(): Promise<void> {
    this.#closed = true;
    this.#closeOperation ??= (async () => {
      await Promise.allSettled([...this.#starting.values()]);
      await Promise.allSettled([...this.#started].map(async (alias) => this.#stop(alias)));
      await rm(this.#directory, { recursive: true, force: true });
    })();
    return this.#closeOperation;
  }

  #ensureMaster(sshAlias: string): Promise<string | undefined> {
    const operation = (async (): Promise<string | undefined> => {
      const socketPath = socketPathFor(this.#directory, sshAlias);
      // The master unlinks its socket when it exits, so presence means a
      // usable master or, rarely, a dying one; clients fall back to a direct
      // connection in that case.
      if (await isSocket(socketPath)) return socketPath;

      const failedAt = this.#failedAt.get(sshAlias);
      const retryAfter =
        this.#options.retryAfterFailureMs ?? DEFAULT_RETRY_AFTER_FAILURE_MS;
      if (failedAt !== undefined && Date.now() - failedAt < retryAfter) {
        return undefined;
      }

      const connectTimeoutSeconds =
        this.#options.connectTimeoutSeconds ?? DEFAULT_CONNECT_TIMEOUT_SECONDS;
      const exitCode = await runDetached(
        this.#options.executable,
        buildOpenSshControlMasterArguments(
          this.#options,
          sshAlias,
          socketPath,
          this.#options.persistSeconds ?? DEFAULT_PERSIST_SECONDS,
        ),
        // Authentication may take several round trips after the TCP connect.
        (connectTimeoutSeconds + 15) * 1000,
      );
      if (exitCode === 0 && !this.#closed && (await isSocket(socketPath))) {
        this.#failedAt.delete(sshAlias);
        this.#started.add(sshAlias);
        return socketPath;
      }
      if (exitCode === 0) {
        // Closed while starting: do not leave an orphaned master behind.
        this.#started.add(sshAlias);
        await this.#stop(sshAlias);
        return undefined;
      }
      this.#failedAt.set(sshAlias, Date.now());
      return undefined;
    })();
    this.#starting.set(sshAlias, operation);
    const clear = (): void => {
      if (this.#starting.get(sshAlias) === operation) {
        this.#starting.delete(sshAlias);
      }
    };
    void operation.then(clear, clear);
    return operation;
  }

  async #stop(sshAlias: string): Promise<void> {
    if (!this.#started.delete(sshAlias)) return;
    const socketPath = socketPathFor(this.#directory, sshAlias);
    if (!(await isSocket(socketPath))) return;
    // "stop" refuses new clients and removes the socket while letting active
    // sessions complete; ControlPersist then lets the master exit when idle.
    await runDetached(
      this.#options.executable,
      buildOpenSshControlCommandArguments(sshAlias, socketPath, "stop"),
      CONTROL_COMMAND_TIMEOUT_MS,
    );
    await rm(socketPath, { force: true });
  }
}

function socketPathFor(directory: string, sshAlias: string): string {
  return path.join(
    directory,
    createHash("sha256").update(sshAlias).digest("hex").slice(0, 16),
  );
}

async function isSocket(file: string): Promise<boolean> {
  try {
    return (await lstat(file)).isSocket();
  } catch {
    return false;
  }
}

/**
 * Runs ssh in its own process group with no inherited stdio. The master
 * daemonizes after authentication, so the launched process's exit (not stdio
 * closure) signals that the socket is ready.
 */
function runDetached(
  executable: string,
  arguments_: readonly string[],
  timeoutMs: number,
): Promise<number | null> {
  return new Promise((resolve) => {
    let settled = false;
    const child = spawn(executable, arguments_, {
      detached: true,
      stdio: "ignore",
      windowsHide: true,
    });
    const finish = (code: number | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(code);
    };
    const timer = setTimeout(() => {
      try {
        if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
      finish(null);
    }, timeoutMs);
    child.once("error", () => finish(null));
    child.once("exit", (code) => finish(code));
  });
}

function raceAbort<T>(
  operation: Promise<T>,
  signal: AbortSignal | undefined,
): Promise<T | undefined> {
  if (signal === undefined) return operation;
  return new Promise((resolve, reject) => {
    const onAbort = (): void => resolve(undefined);
    signal.addEventListener("abort", onAbort, { once: true });
    operation.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}
