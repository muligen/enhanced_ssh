import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { link, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import { z } from "zod";

import { formatPuttyLogicalHost } from "../shared/putty-loghost.js";

const PUTTY_DEFAULT_SETTINGS_KEY =
  String.raw`HKCU\Software\SimonTatham\PuTTY\Sessions\Default%20Settings`;
const LOG_HOST_VALUE_NAME = "LogHost";
const DEFAULT_ARM_TIMEOUT_MS = 120_000;
const DEFAULT_POLL_INTERVAL_MS = 100;

const recoveryMarkerSchema = z.strictObject({
  version: z.literal(1),
  alias: z.string().min(1).max(128),
  revision: z.string().min(1).max(128),
  temporaryValue: z.string().min(1).max(260),
  previousValue: z.string().max(4_096).nullable(),
  createdAt: z.string().datetime(),
});

export type AccessClientSessionState =
  | "idle"
  | "armed"
  | "detected"
  | "ready"
  | "timed-out"
  | "cancelled"
  | "error";

export interface AccessClientSessionSnapshot {
  readonly state: AccessClientSessionState;
  readonly alias?: string;
  readonly sharingHost?: string;
  readonly sharingPort?: number;
  readonly startedAt?: string;
  readonly deadlineAt?: string;
  readonly completedAt?: string;
  readonly hostname?: string;
  readonly durationMs?: number;
  readonly message?: string;
}

export interface AccessClientSessionVerification {
  readonly hostname?: string;
  readonly durationMs?: number;
}

export interface AccessClientSessionArmRequest {
  readonly alias: string;
  readonly revision: string;
  readonly sharingHost: string;
  readonly sharingPort: number;
}

export interface AccessClientSessionPreparer {
  initialize(): Promise<void>;
  prepare(request: AccessClientSessionArmRequest): Promise<AccessClientSessionSnapshot>;
  status(): AccessClientSessionSnapshot;
  verify(
    alias: string,
    verification: AccessClientSessionVerification,
  ): Promise<AccessClientSessionSnapshot>;
  reject(alias: string, message: string): Promise<AccessClientSessionSnapshot>;
  cancel(alias: string): Promise<AccessClientSessionSnapshot>;
  close(): Promise<void>;
}

export interface LogHostRegistry {
  read(): Promise<string | undefined>;
  write(value: string): Promise<void>;
  remove(): Promise<void>;
}

export interface PuttyProcessSource {
  listProcessIds(): Promise<ReadonlySet<number>>;
}

export type AccessClientRecoveryMarker = z.infer<typeof recoveryMarkerSchema>;

export interface AccessClientRecoveryStore {
  read(): Promise<AccessClientRecoveryMarker | undefined>;
  write(marker: AccessClientRecoveryMarker): Promise<void>;
  remove(): Promise<void>;
}

export interface AccessClientSessionPreparerOptions {
  readonly registry: LogHostRegistry;
  readonly processes: PuttyProcessSource;
  readonly recoveryStore: AccessClientRecoveryStore;
  readonly armTimeoutMs?: number;
  readonly pollIntervalMs?: number;
  readonly now?: () => number;
}

export class AccessClientSessionError extends Error {
  public readonly status: number;
  public readonly code: string;

  public constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "AccessClientSessionError";
    this.status = status;
    this.code = code;
  }
}

interface ActivePreparation {
  readonly request: AccessClientSessionArmRequest;
  readonly marker: AccessClientRecoveryMarker;
  readonly baselineProcessIds: ReadonlySet<number>;
  readonly seenProcessIds: Set<number>;
  readonly startedAtMs: number;
  readonly deadlineAtMs: number;
  candidateProcessId?: number;
  stopped: boolean;
  wake?: () => void;
  finishPromise?: Promise<AccessClientSessionSnapshot>;
}

export class ManagedAccessClientSessionPreparer
implements AccessClientSessionPreparer {
  readonly #registry: LogHostRegistry;
  readonly #processes: PuttyProcessSource;
  readonly #recoveryStore: AccessClientRecoveryStore;
  readonly #armTimeoutMs: number;
  readonly #pollIntervalMs: number;
  readonly #now: () => number;
  #initializePromise: Promise<void> | undefined;
  #armPromise: Promise<AccessClientSessionSnapshot> | undefined;
  #active: ActivePreparation | undefined;
  #snapshot: AccessClientSessionSnapshot = { state: "idle" };
  #closed = false;
  #closePromise: Promise<void> | undefined;

  public constructor(options: AccessClientSessionPreparerOptions) {
    this.#registry = options.registry;
    this.#processes = options.processes;
    this.#recoveryStore = options.recoveryStore;
    this.#armTimeoutMs = positiveDuration(
      options.armTimeoutMs ?? DEFAULT_ARM_TIMEOUT_MS,
      "armTimeoutMs",
    );
    this.#pollIntervalMs = positiveDuration(
      options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS,
      "pollIntervalMs",
    );
    this.#now = options.now ?? Date.now;
  }

  public initialize(): Promise<void> {
    this.#initializePromise ??= this.#recoverAfterInterruptedRun();
    return this.#initializePromise;
  }

  public async prepare(
    request: AccessClientSessionArmRequest,
  ): Promise<AccessClientSessionSnapshot> {
    await this.initialize();
    if (this.#closed) {
      throw new AccessClientSessionError(
        503,
        "ACCESSCLIENT_PREPARER_CLOSED",
        "AccessClient session preparation is not available",
      );
    }
    if (this.#active !== undefined || this.#armPromise !== undefined) {
      throw new AccessClientSessionError(
        409,
        "ACCESSCLIENT_PREPARATION_BUSY",
        "Another AccessClient target is already being prepared",
      );
    }

    const armPromise = this.#arm(request);
    this.#armPromise = armPromise;
    try {
      return await armPromise;
    } finally {
      if (this.#armPromise === armPromise) this.#armPromise = undefined;
    }
  }

  public status(): AccessClientSessionSnapshot {
    return { ...this.#snapshot };
  }

  public async verify(
    alias: string,
    verification: AccessClientSessionVerification,
  ): Promise<AccessClientSessionSnapshot> {
    await this.initialize();
    const active = this.#requireActiveAlias(alias);
    if (
      active.candidateProcessId === undefined ||
      this.#snapshot.state !== "detected"
    ) {
      throw new AccessClientSessionError(
        409,
        "ACCESSCLIENT_SESSION_NOT_DETECTED",
        "No new PuTTY process is waiting for verification",
      );
    }
    const processIds = await this.#processes.listProcessIds();
    if (!processIds.has(active.candidateProcessId)) {
      this.#resetCandidate(active);
      return this.status();
    }
    return this.#finish(
      active,
      "ready",
      "The new PuTTY session was verified and matched to this target",
      verification,
    );
  }

  public async reject(
    alias: string,
    message: string,
  ): Promise<AccessClientSessionSnapshot> {
    await this.initialize();
    const active = this.#requireActiveAlias(alias);
    return this.#finish(active, "error", message);
  }

  public async cancel(alias: string): Promise<AccessClientSessionSnapshot> {
    await this.initialize();
    if (this.#armPromise !== undefined) await this.#armPromise;
    const active = this.#active;
    if (active === undefined) return this.status();
    this.#requireActiveAlias(alias);
    return this.#finish(
      active,
      "cancelled",
      "AccessClient session preparation was cancelled and PuTTY settings were restored",
    );
  }

  public close(): Promise<void> {
    this.#closePromise ??= this.#closeOnce();
    return this.#closePromise;
  }

  async #closeOnce(): Promise<void> {
    this.#closed = true;
    try {
      await this.initialize();
    } finally {
      if (this.#armPromise !== undefined) {
        await this.#armPromise.catch(() => undefined);
      }
      const active = this.#active;
      if (active !== undefined) {
        await this.#finish(
          active,
          "cancelled",
          "AccessClient session preparation stopped with the management service",
        );
      }
    }
  }

  async #arm(
    request: AccessClientSessionArmRequest,
  ): Promise<AccessClientSessionSnapshot> {
    const temporaryValue = formatPuttyLogicalHost(
      request.sharingHost,
      request.sharingPort,
    );
    let baselineProcessIds: ReadonlySet<number>;
    let previousValue: string | undefined;
    try {
      [baselineProcessIds, previousValue] = await Promise.all([
        this.#processes.listProcessIds(),
        this.#registry.read(),
      ]);
    } catch {
      throw preparationFailed();
    }

    const startedAtMs = this.#now();
    const deadlineAtMs = startedAtMs + this.#armTimeoutMs;
    let marker: AccessClientRecoveryMarker;
    try {
      marker = recoveryMarkerSchema.parse({
        version: 1,
        alias: request.alias,
        revision: request.revision,
        temporaryValue,
        previousValue: previousValue ?? null,
        createdAt: new Date(startedAtMs).toISOString(),
      });
    } catch {
      throw preparationFailed();
    }

    let markerWritten = false;
    try {
      await this.#recoveryStore.write(marker);
      markerWritten = true;
      await this.#registry.write(temporaryValue);
    } catch {
      if (markerWritten) {
        try {
          await this.#restoreMarker(marker);
        } catch {
          this.#closed = true;
          this.#snapshot = {
            state: "error",
            alias: request.alias,
            sharingHost: request.sharingHost,
            sharingPort: request.sharingPort,
            startedAt: new Date(startedAtMs).toISOString(),
            completedAt: new Date(this.#now()).toISOString(),
            message:
              "PuTTY LogHost could not be restored automatically; restart the management service before preparing another target",
          };
          throw new AccessClientSessionError(
            500,
            "ACCESSCLIENT_RECOVERY_FAILED",
            "AccessClient session preparation failed and PuTTY settings could not be restored safely",
          );
        }
      }
      throw preparationFailed();
    }

    const active: ActivePreparation = {
      request,
      marker,
      baselineProcessIds,
      seenProcessIds: new Set(baselineProcessIds),
      startedAtMs,
      deadlineAtMs,
      stopped: false,
    };
    this.#active = active;
    this.#snapshot = {
      state: "armed",
      alias: request.alias,
      sharingHost: request.sharingHost,
      sharingPort: request.sharingPort,
      startedAt: new Date(startedAtMs).toISOString(),
      deadlineAt: new Date(deadlineAtMs).toISOString(),
    };

    if (this.#closed) {
      return this.#finish(
        active,
        "cancelled",
        "AccessClient session preparation stopped with the management service",
      );
    }
    void this.#monitor(active);
    return this.status();
  }

  async #monitor(active: ActivePreparation): Promise<void> {
    try {
      while (!active.stopped) {
        const remainingMs = active.deadlineAtMs - this.#now();
        if (remainingMs <= 0) {
          await this.#finish(
            active,
            "timed-out",
            "No new PuTTY session was verified before the preparation deadline; PuTTY settings were restored",
          );
          return;
        }
        await this.#wait(active, Math.min(this.#pollIntervalMs, remainingMs));
        if (active.stopped) return;

        const processIds = await this.#processes.listProcessIds();
        if (active.stopped || this.#active !== active) return;
        if (
          active.candidateProcessId !== undefined &&
          !processIds.has(active.candidateProcessId)
        ) {
          this.#resetCandidate(active);
          continue;
        }
        if (active.candidateProcessId === undefined) {
          const candidateProcessId = [...processIds].find(
            (processId) => !active.seenProcessIds.has(processId),
          );
          if (candidateProcessId === undefined) continue;
          active.candidateProcessId = candidateProcessId;
          active.seenProcessIds.add(candidateProcessId);
          this.#snapshot = {
            ...this.#snapshot,
            state: "detected",
            message:
              "A new PuTTY process was detected; waiting for the shared session and hostname to be verified",
          };
        }
      }
    } catch {
      await this.#finish(
        active,
        "error",
        "AccessClient session preparation failed; PuTTY settings were restored",
      );
    }
  }

  #finish(
    active: ActivePreparation,
    state: Exclude<AccessClientSessionState, "idle" | "armed" | "detected">,
    message: string,
    verification: AccessClientSessionVerification = {},
  ): Promise<AccessClientSessionSnapshot> {
    if (active.finishPromise !== undefined) return active.finishPromise;
    active.stopped = true;
    active.wake?.();
    const finishPromise = (async (): Promise<AccessClientSessionSnapshot> => {
      try {
        await this.#restoreMarker(active.marker);
        this.#snapshot = {
          state,
          alias: active.request.alias,
          sharingHost: active.request.sharingHost,
          sharingPort: active.request.sharingPort,
          startedAt: new Date(active.startedAtMs).toISOString(),
          completedAt: new Date(this.#now()).toISOString(),
          ...(verification.hostname === undefined
            ? {}
            : { hostname: verification.hostname }),
          ...(verification.durationMs === undefined
            ? {}
            : { durationMs: verification.durationMs }),
          message,
        };
      } catch {
        this.#snapshot = {
          state: "error",
          alias: active.request.alias,
          sharingHost: active.request.sharingHost,
          sharingPort: active.request.sharingPort,
          startedAt: new Date(active.startedAtMs).toISOString(),
          completedAt: new Date(this.#now()).toISOString(),
          message:
            "PuTTY LogHost could not be restored automatically; restart the management service before preparing another target",
        };
      } finally {
        if (this.#active === active) this.#active = undefined;
      }
      return this.status();
    })();
    active.finishPromise = finishPromise;
    return finishPromise;
  }

  #requireActiveAlias(alias: string): ActivePreparation {
    const active = this.#active;
    if (active === undefined) {
      throw new AccessClientSessionError(
        409,
        "ACCESSCLIENT_PREPARATION_NOT_ACTIVE",
        "No AccessClient target is currently being prepared",
      );
    }
    if (active.request.alias !== alias) {
      throw new AccessClientSessionError(
        409,
        "ACCESSCLIENT_PREPARATION_BUSY",
        "Another AccessClient target is already being prepared",
      );
    }
    return active;
  }

  #resetCandidate(active: ActivePreparation): void {
    delete active.candidateProcessId;
    this.#snapshot = {
      state: "armed",
      alias: active.request.alias,
      sharingHost: active.request.sharingHost,
      sharingPort: active.request.sharingPort,
      startedAt: new Date(active.startedAtMs).toISOString(),
      deadlineAt: new Date(active.deadlineAtMs).toISOString(),
      message:
        "The detected PuTTY process exited before verification; waiting for another new PuTTY process",
    };
  }

  #wait(active: ActivePreparation, durationMs: number): Promise<void> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        delete active.wake;
        resolve();
      }, durationMs);
      active.wake = (): void => {
        clearTimeout(timer);
        delete active.wake;
        resolve();
      };
    });
  }

  async #recoverAfterInterruptedRun(): Promise<void> {
    let marker: AccessClientRecoveryMarker | undefined;
    try {
      marker = await this.#recoveryStore.read();
      if (marker !== undefined) await this.#restoreMarker(marker);
    } catch {
      throw new AccessClientSessionError(
        500,
        "ACCESSCLIENT_RECOVERY_FAILED",
        "A previous AccessClient preparation could not be recovered safely",
      );
    }
  }

  async #restoreMarker(marker: AccessClientRecoveryMarker): Promise<void> {
    const currentValue = await this.#registry.read();
    if (currentValue === marker.temporaryValue) {
      if (marker.previousValue === null) await this.#registry.remove();
      else await this.#registry.write(marker.previousValue);
    }
    await this.#recoveryStore.remove();
  }
}

export interface WindowsCommandResult {
  readonly stdout: string;
  readonly stderr: string;
}

export interface WindowsCommandRunner {
  run(executable: string, arguments_: readonly string[]): Promise<WindowsCommandResult>;
}

class WindowsCommandError extends Error {
  public readonly exitCode: number | undefined;

  public constructor(exitCode: number | undefined) {
    super("Windows helper command failed");
    this.name = "WindowsCommandError";
    this.exitCode = exitCode;
  }
}

export class ExecFileWindowsCommandRunner implements WindowsCommandRunner {
  public run(
    executable: string,
    arguments_: readonly string[],
  ): Promise<WindowsCommandResult> {
    return new Promise((resolve, reject) => {
      execFile(
        executable,
        [...arguments_],
        {
          encoding: "utf8",
          maxBuffer: 256 * 1_024,
          timeout: 5_000,
          windowsHide: true,
          shell: false,
        },
        (error, stdout, stderr) => {
          if (error !== null) {
            reject(
              new WindowsCommandError(
                typeof error.code === "number" ? error.code : undefined,
              ),
            );
            return;
          }
          resolve({ stdout, stderr });
        },
      );
    });
  }
}

export class WindowsPuttyLogHostRegistry implements LogHostRegistry {
  readonly #runner: WindowsCommandRunner;
  readonly #regExecutable: string;

  public constructor(runner: WindowsCommandRunner, systemRoot: string) {
    this.#runner = runner;
    this.#regExecutable = path.join(systemRoot, "System32", "reg.exe");
  }

  public async read(): Promise<string | undefined> {
    let result: WindowsCommandResult;
    try {
      result = await this.#runner.run(this.#regExecutable, [
        "QUERY",
        PUTTY_DEFAULT_SETTINGS_KEY,
        "/v",
        LOG_HOST_VALUE_NAME,
      ]);
    } catch (error) {
      if (!(error instanceof WindowsCommandError) || error.exitCode !== 1) {
        throw error;
      }
      // A successful key query distinguishes a missing value from an
      // inaccessible or missing PuTTY Default Settings key.
      await this.#runner.run(this.#regExecutable, [
        "QUERY",
        PUTTY_DEFAULT_SETTINGS_KEY,
      ]);
      return undefined;
    }
    for (const line of result.stdout.split(/\r?\n/u)) {
      const match = /^\s*LogHost\s+REG_SZ(?:\s+(.*))?$/iu.exec(line);
      if (match !== null) return match[1] ?? "";
    }
    throw new Error("PuTTY LogHost registry output was not recognized");
  }

  public async write(value: string): Promise<void> {
    await this.#runner.run(this.#regExecutable, [
      "ADD",
      PUTTY_DEFAULT_SETTINGS_KEY,
      "/v",
      LOG_HOST_VALUE_NAME,
      "/t",
      "REG_SZ",
      "/d",
      value,
      "/f",
    ]);
  }

  public async remove(): Promise<void> {
    try {
      await this.#runner.run(this.#regExecutable, [
        "DELETE",
        PUTTY_DEFAULT_SETTINGS_KEY,
        "/v",
        LOG_HOST_VALUE_NAME,
        "/f",
      ]);
    } catch (error) {
      if (!(error instanceof WindowsCommandError) || error.exitCode !== 1) {
        throw error;
      }
    }
  }
}

export class WindowsPuttyProcessSource implements PuttyProcessSource {
  readonly #runner: WindowsCommandRunner;
  readonly #tasklistExecutable: string;

  public constructor(runner: WindowsCommandRunner, systemRoot: string) {
    this.#runner = runner;
    this.#tasklistExecutable = path.join(systemRoot, "System32", "tasklist.exe");
  }

  public async listProcessIds(): Promise<ReadonlySet<number>> {
    const result = await this.#runner.run(this.#tasklistExecutable, [
      "/FI",
      "IMAGENAME eq putty.exe",
      "/FO",
      "CSV",
      "/NH",
    ]);
    const processIds = new Set<number>();
    for (const line of result.stdout.split(/\r?\n/u)) {
      const match = /^"putty\.exe","([0-9]+)"/iu.exec(line.trim());
      if (match !== null) processIds.add(Number(match[1]));
    }
    return processIds;
  }
}

export class FileAccessClientRecoveryStore implements AccessClientRecoveryStore {
  readonly #markerPath: string;

  public constructor(markerPath: string) {
    this.#markerPath = path.resolve(markerPath);
  }

  public async read(): Promise<AccessClientRecoveryMarker | undefined> {
    let raw: string;
    try {
      raw = await readFile(this.#markerPath, "utf8");
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return undefined;
      throw error;
    }
    return recoveryMarkerSchema.parse(JSON.parse(raw) as unknown);
  }

  public async write(marker: AccessClientRecoveryMarker): Promise<void> {
    const validated = recoveryMarkerSchema.parse(marker);
    await mkdir(path.dirname(this.#markerPath), { recursive: true });
    const temporaryPath = `${this.#markerPath}.${randomBytes(8).toString("hex")}.tmp`;
    try {
      await writeFile(temporaryPath, `${JSON.stringify(validated)}\n`, {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      });
      // Linking the complete temporary file into place is atomic and fails
      // closed when another service instance already owns a recovery marker.
      await link(temporaryPath, this.#markerPath);
    } finally {
      await rm(temporaryPath, { force: true }).catch(() => undefined);
    }
  }

  public remove(): Promise<void> {
    return rm(this.#markerPath, { force: true });
  }
}

export function createWindowsAccessClientSessionPreparer(
  markerPath: string,
): AccessClientSessionPreparer {
  if (process.platform !== "win32") {
    throw new AccessClientSessionError(
      501,
      "ACCESSCLIENT_PREPARATION_UNSUPPORTED",
      "AccessClient session preparation is available only on Windows",
    );
  }
  const runner = new ExecFileWindowsCommandRunner();
  const systemRoot = process.env.SystemRoot ?? String.raw`C:\Windows`;
  return new ManagedAccessClientSessionPreparer({
    registry: new WindowsPuttyLogHostRegistry(runner, systemRoot),
    processes: new WindowsPuttyProcessSource(runner, systemRoot),
    recoveryStore: new FileAccessClientRecoveryStore(markerPath),
  });
}

function positiveDuration(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive integer`);
  }
  return value;
}

function preparationFailed(): AccessClientSessionError {
  return new AccessClientSessionError(
    500,
    "ACCESSCLIENT_PREPARATION_FAILED",
    "AccessClient session preparation failed and no credentials were read",
  );
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
