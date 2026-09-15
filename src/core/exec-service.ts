import { createHash, randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";

import type {
  AuditWriter,
  ProbeKind,
  ProbeResultCode,
} from "../infra/audit-writer.js";
import {
  SshExecutionError,
  type SshOutcome,
  type SshRunner,
} from "../infra/ssh-runner.js";
import {
  OutputLimitExceededError,
  type OutputSink,
  type StoredOutputSummary,
  type OutputStream,
  type OutputStore,
} from "./output-store.js";
import {
  prepareRemoteCommand,
  prepareStructuredRemoteCommand,
  type PreparedRemoteCommand,
} from "./remote-command.js";
import {
  TaskStore,
  type TaskOutputStream,
} from "./task-store.js";
import {
  prepareFixedProbe,
  type PreparedFixedProbe,
} from "./fixed-probe.js";
import {
  FixedProbeParseError,
  parseFixedProbeOutput,
  type DockerPreflightProbeResult,
  type TargetInfoProbeResult,
} from "./probe-parser.js";
import type { MachineIdentityKeyStore } from "./machine-identity.js";
import type { GatewayMetadataUpdate, TargetAuthorization, TargetRegistry } from "./target-registry.js";
import { GATEWAY_ERROR_CODES, GatewayError } from "../shared/errors.js";
import type {
  ExecResult,
  RpcId,
  RpcParamsByMethod,
  RpcResultByMethod,
  TargetCheckResult,
  TargetCheckFailureReason,
  TargetSummary,
  TaskCancelResult,
  TaskStartResult,
  TaskStatusResult,
  TaskTailResult,
  TargetInspectResult,
  DockerPreflightResult,
} from "../shared/protocol.js";
import {
  MAX_TARGET_CHECK_HOSTNAME_LENGTH,
  targetCheckFailureReasonSchema,
} from "../shared/protocol.js";
import { completeUtf8PrefixLength } from "../shared/utf8.js";

const TARGET_CHECK_COMMAND = "hostname";
const SAFE_HOSTNAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const MAX_PRESET_OUTPUT_BYTES = 256 * 1024;

type StopReason = "timeout" | "cancel" | "output_limit";

interface ExecutionCaller {
  readonly sessionId: string;
}

interface ActiveExecution {
  readonly requestId: RpcId;
  readonly executionId: string;
  readonly target: string;
  readonly controller: AbortController;
  acceptingCancellation: boolean;
  reason?: StopReason;
  done?: Promise<void>;
}

export interface ExecServiceOptions {
  readonly registry: TargetRegistry;
  readonly executor: SshRunner;
  readonly outputStore: OutputStore;
  readonly audit: AuditWriter;
  readonly maxConcurrentExecutions: number;
  readonly taskStore?: TaskStore;
  readonly machineIdentity?: MachineIdentityKeyStore;
  readonly hostKeyInspector?: TrustedHostKeyInspector;
}

export interface ExecServiceGeneration {
  readonly registry: TargetRegistry;
  readonly executor: SshRunner;
  readonly hostKeyInspector?: TrustedHostKeyInspector;
}

export interface TrustedHostKeyInspector {
  inspect(sshAlias: string): Promise<readonly string[]>;
}

interface PreparedExecution {
  readonly authorization: TargetAuthorization;
  readonly auditPayload: string;
  readonly remoteCommand: PreparedRemoteCommand;
  readonly executor: SshRunner;
}

interface FixedExecutionResult {
  readonly termination: ExecResult["termination"];
  readonly exitCode: number | null;
  readonly durationMs: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
  readonly stdoutTruncated: boolean;
  readonly stderrTruncated: boolean;
}

interface InternalExecutionResult {
  readonly result: ExecResult;
  readonly failureReason?: TargetCheckFailureReason;
}

export type ExecServiceReloadErrorCode =
  | "ACTIVE_EXECUTIONS"
  | "RELOAD_IN_PROGRESS"
  | "SERVICE_CLOSING";

export class ExecServiceReloadError extends Error {
  public readonly code: ExecServiceReloadErrorCode;

  public constructor(code: ExecServiceReloadErrorCode, message: string) {
    super(message);
    this.name = "ExecServiceReloadError";
    this.code = code;
  }
}

export interface ExecServiceReloadLease {
  /** Replaces the generation while keeping new executions gated. */
  commit(generation: ExecServiceGeneration): void;
  /** Releases the reload gate after every generation consumer has switched. */
  release(): void;
}

export class ExecService {
  #generation: ExecServiceGeneration;
  readonly #outputStore: OutputStore;
  readonly #audit: AuditWriter;
  readonly #maxConcurrentExecutions: number;
  readonly #taskStore: TaskStore;
  readonly #ownsTaskStore: boolean;
  readonly #machineIdentity: MachineIdentityKeyStore | undefined;
  readonly #activeBySession = new Map<string, Map<RpcId, ActiveExecution>>();
  #reloadToken: object | undefined;
  #activeCount = 0;
  #closing = false;

  public constructor(options: ExecServiceOptions) {
    if (
      !Number.isSafeInteger(options.maxConcurrentExecutions) ||
      options.maxConcurrentExecutions < 1
    ) {
      throw new RangeError("maxConcurrentExecutions must be a positive integer");
    }
    this.#generation = createGeneration(
      options.registry,
      options.executor,
      options.hostKeyInspector,
    );
    this.#outputStore = options.outputStore;
    this.#audit = options.audit;
    this.#maxConcurrentExecutions = options.maxConcurrentExecutions;
    this.#machineIdentity = options.machineIdentity;
    this.#ownsTaskStore = options.taskStore === undefined;
    this.#taskStore =
      options.taskStore ??
      new TaskStore({
        ttlMs: 15 * 60_000,
        maxRetainedTasks: 1_024,
        maxConcurrentTasks: options.maxConcurrentExecutions,
      });
  }

  public listTargets(): readonly TargetSummary[] {
    return this.#generation.registry.list();
  }

  public listGroups(): readonly string[] {
    return this.#generation.registry.listGroups();
  }

  public listAllowedOperations(target: string) {
    return this.#generation.registry.listAllowedOperations(target);
  }

  public runOperation(
    caller: ExecutionCaller,
    requestId: RpcId,
    params: RpcParamsByMethod["operation.run"],
  ): Promise<ExecResult> {
    this.#assertExecutionAvailable();
    const generation = this.#generation;
    const authorization = generation.registry.authorizeOperation(params.target, {
      operation: params.operation,
      parameters: params.parameters,
    }, params.timeoutMs);
    const remoteCommand = prepareStructuredRemoteCommand(authorization.target.platform, authorization.operation);
    // The normal execution path preserves audit durability, cancellation,
    // concurrency bounds and retained stdout/stderr. Caller scripts never enter it.
    return this.#startExecution(caller, requestId, authorization.target.alias,
      authorization, JSON.stringify({ operation: params.operation, parameters: params.parameters }),
      remoteCommand, generation.executor, undefined, MAX_PRESET_OUTPUT_BYTES).then((execution) => execution.result);
  }

  public updateMetadata(metadata: GatewayMetadataUpdate): TargetRegistry {
    if (this.#closing) {
      throw new ExecServiceReloadError("SERVICE_CLOSING", "Gateway metadata cannot update while the service is stopping");
    }
    if (this.#reloadToken !== undefined) {
      throw new ExecServiceReloadError("RELOAD_IN_PROGRESS", "Gateway configuration reload is already in progress");
    }
    const current = this.#generation;
    const registry = current.registry.withMetadata(metadata);
    // Active work retains its captured generation; new work reuses the exact same runners.
    this.#generation = createGeneration(registry, current.executor, current.hostKeyInspector);
    return registry;
  }

  /** Revokes an idle subset while preserving all generation resources. */
  public removeTargets(aliases: readonly string[], metadata?: GatewayMetadataUpdate): {
    readonly registry: TargetRegistry;
    readonly sshAliases: readonly string[];
  } {
    const lease = this.beginReload();
    try {
      const current = this.#generation;
      const sshAliases = current.registry.sshAliasesForRemoval(aliases);
      let registry = current.registry.withoutTargets(aliases);
      if (metadata !== undefined) registry = registry.withMetadata(metadata);
      lease.commit({ ...current, registry });
      return { registry, sshAliases };
    } finally {
      lease.release();
    }
  }

  public beginReload(): ExecServiceReloadLease {
    if (this.#closing) {
      throw new ExecServiceReloadError(
        "SERVICE_CLOSING",
        "Gateway configuration cannot reload while the service is stopping",
      );
    }
    if (this.#reloadToken !== undefined) {
      throw new ExecServiceReloadError(
        "RELOAD_IN_PROGRESS",
        "Gateway configuration reload is already in progress",
      );
    }
    if (this.#activeCount !== 0 || this.#taskStore.activeCount !== 0) {
      throw new ExecServiceReloadError(
        "ACTIVE_EXECUTIONS",
        "Gateway configuration cannot reload while executions are active",
      );
    }

    const token = {};
    this.#reloadToken = token;
    let settled = false;
    let committed = false;
    const settle = (): void => {
      if (settled) {
        return;
      }
      settled = true;
      if (this.#reloadToken === token) {
        this.#reloadToken = undefined;
      }
    };

    return Object.freeze({
      commit: (generation: ExecServiceGeneration): void => {
        if (settled || committed || this.#reloadToken !== token) {
          throw new Error("Gateway configuration reload lease is no longer active");
        }
        if (this.#closing) {
          settle();
          throw new ExecServiceReloadError(
            "SERVICE_CLOSING",
            "Gateway configuration cannot reload while the service is stopping",
          );
        }
        if (this.#activeCount !== 0 || this.#taskStore.activeCount !== 0) {
          settle();
          throw new ExecServiceReloadError(
            "ACTIVE_EXECUTIONS",
            "Gateway configuration cannot reload while executions are active",
          );
        }
        this.#generation = createGeneration(
          generation.registry,
          generation.executor,
          generation.hostKeyInspector,
        );
        committed = true;
      },
      release: settle,
    });
  }

  public run(
    caller: ExecutionCaller,
    requestId: RpcId,
    params: RpcParamsByMethod["exec.run"],
  ): Promise<ExecResult> {
    const prepared = this.#prepareRun(params);
    return this.#startExecution(
      caller,
      requestId,
      params.target,
      prepared.authorization,
      prepared.auditPayload,
      prepared.remoteCommand,
      prepared.executor,
    ).then((execution) => execution.result);
  }

  public startTask(
    params: RpcParamsByMethod["task.start"],
  ): TaskStartResult {
    const prepared = this.#prepareRun(params);
    return this.#taskStore.start({
      kind: "exec",
      target: params.target,
      worker: async (context) => {
        const sessionId = `task:${context.runId}`;
        const cancel = (): void => {
          this.cancel(sessionId, context.runId);
        };
        context.signal.addEventListener("abort", cancel, { once: true });
        try {
          const execution = this.#startExecution(
            { sessionId },
            context.runId,
            params.target,
            prepared.authorization,
            prepared.auditPayload,
            prepared.remoteCommand,
            prepared.executor,
            context.append,
          );
          if (context.signal.aborted) cancel();
          const result = (await execution).result;
          return {
            termination: result.termination,
            exitCode: result.exitCode,
            result: {
              durationMs: result.durationMs,
              stdoutBytes: result.stdout.bytes,
              stderrBytes: result.stderr.bytes,
              ...(result.outputRef === undefined
                ? {}
                : {
                    outputRef: result.outputRef,
                    outputExpiresAt: result.outputExpiresAt,
                  }),
            },
          };
        } finally {
          context.signal.removeEventListener("abort", cancel);
        }
      },
    });
  }

  public taskStatus(runId: string): TaskStatusResult {
    return this.#taskStore.status(runId);
  }

  public taskTail(
    runId: string,
    cursor: string | undefined,
    limit: number,
  ): TaskTailResult {
    return this.#taskStore.tail(runId, cursor, limit);
  }

  public cancelTask(runId: string): TaskCancelResult {
    return this.#taskStore.cancel(runId);
  }

  #prepareRun(params: RpcParamsByMethod["exec.run"]): PreparedExecution {
    this.#assertExecutionAvailable();
    const generation = this.#generation;
    if ("command" in params) {
      const authorization = generation.registry.authorize(
        params.target,
        params.command,
        params.timeoutMs,
      );
      return {
        authorization,
        auditPayload: params.command,
        remoteCommand: prepareRemoteCommand(
          authorization.target.platform,
          params.command,
        ),
        executor: generation.executor,
      };
    }

    const authorization = generation.registry.authorizeStructured(
      params.target,
      params.timeoutMs,
    );
    return {
      authorization,
      auditPayload: canonicalStructuredPayload(params),
      remoteCommand: prepareStructuredRemoteCommand(
        authorization.target.platform,
        params,
      ),
      executor: generation.executor,
    };
  }

  #assertExecutionAvailable(): void {
    if (this.#closing) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.executionLimitReached,
        "Gateway is stopping",
      );
    }
    if (this.#reloadToken !== undefined) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.executionLimitReached,
        "Gateway configuration is reloading",
      );
    }
  }

  public check(
    caller: ExecutionCaller,
    requestId: RpcId,
    params: RpcParamsByMethod["target.check"],
  ): Promise<TargetCheckResult> {
    if (this.#closing) {
      return Promise.reject(
        new GatewayError(
          GATEWAY_ERROR_CODES.executionLimitReached,
          "Gateway is stopping",
        ),
      );
    }

    if (this.#reloadToken !== undefined) {
      return Promise.reject(
        new GatewayError(
          GATEWAY_ERROR_CODES.executionLimitReached,
          "Gateway configuration is reloading",
        ),
      );
    }

    const generation = this.#generation;
    const authorization = generation.registry.authorizeCheck(params.target);
    const remoteCommand = prepareRemoteCommand(
      authorization.target.platform,
      TARGET_CHECK_COMMAND,
    );

    return this.#startExecution(
      caller,
      requestId,
      params.target,
      authorization,
      TARGET_CHECK_COMMAND,
      remoteCommand,
      generation.executor,
    ).then((execution) =>
      toTargetCheckResult(
        params.target,
        execution.result,
        execution.failureReason,
      ),
    );
  }

  public async inspect(
    caller: ExecutionCaller,
    requestId: RpcId,
    params: RpcParamsByMethod["target.inspect"],
  ): Promise<TargetInspectResult> {
    this.#assertExecutionAvailable();
    const generation = this.#generation;
    const authorization = generation.registry.authorizeInspect(params.target);
    const probe = prepareFixedProbe(
      authorization.target.platform,
      "target-info",
    );
    const [execution, fingerprints] = await Promise.all([
      this.#runFixedExecution(
        caller,
        requestId,
        params.target,
        authorization,
        "target-info",
        probe,
        generation.executor,
      ),
      generation.hostKeyInspector
        ?.inspect(authorization.target.sshAlias)
        .catch(() => [] as readonly string[]) ?? Promise.resolve([]),
    ]);
    const observedAt = new Date().toISOString();
    if (execution.termination !== "exit" || execution.exitCode !== 0) {
      await this.#writeProbeAudit(
        params.target,
        "target-info",
        execution.durationMs,
        probeExecutionResultCode(execution),
      );
      return {
        target: params.target,
        connected: false,
        observedAt,
        durationMs: execution.durationMs,
        sshHostKeyFingerprints: [...fingerprints],
        warnings: [
          "target-probe-failed",
          ...(fingerprints.length === 0 ? ["host-key-fingerprint-unavailable"] : []),
        ],
      };
    }

    let parsed: TargetInfoProbeResult;
    try {
      parsed = parseProbe("target-info", execution.stdout);
    } catch (error) {
      await this.#writeProbeAudit(
        params.target,
        "target-info",
        execution.durationMs,
        "invalid-response",
      );
      throw error;
    }
    const warnings = [
      ...parsed.warnings,
      ...(parsed.reportedPlatform === authorization.target.platform
        ? []
        : ["platform-mismatch"]),
      ...(fingerprints.length === 0
        ? ["host-key-fingerprint-unavailable"]
        : []),
    ];
    const machineIdentity = this.#machineIdentity;
    const machine =
      machineIdentity === undefined ||
      parsed.nativeMachineId === undefined ||
      parsed.hostname === undefined
        ? undefined
        : {
            machineId: machineIdentity.derive(
              parsed.reportedPlatform,
              parsed.nativeMachineId,
            ),
            hostname: parsed.hostname,
            configuredPlatform: authorization.target.platform,
            reportedPlatform: parsed.reportedPlatform,
            platformMatch:
              parsed.reportedPlatform === authorization.target.platform,
            os: { ...parsed.os },
            ...(parsed.disk === undefined
              ? {}
              : {
                  disk: {
                    totalBytes: parsed.disk.totalBytes,
                    availableBytes: parsed.disk.availableBytes,
                  },
                }),
            docker: {
              installed: parsed.docker.installed,
              daemonReachable: parsed.docker.daemonReachable,
              ...(parsed.docker.clientVersion === undefined
                ? {}
                : { clientVersion: parsed.docker.clientVersion }),
              ...(parsed.docker.serverVersion === undefined
                ? {}
                : { serverVersion: parsed.docker.serverVersion }),
              ...(parsed.docker.compose.version === undefined
                ? {}
                : { composeVersion: parsed.docker.compose.version }),
            },
          };
    const result: TargetInspectResult = {
      target: params.target,
      connected: true,
      observedAt,
      durationMs: execution.durationMs,
      sshHostKeyFingerprints: [...fingerprints],
      ...(machine === undefined ? {} : { machine }),
      warnings: [...new Set(warnings)],
    };
    await this.#writeProbeAudit(
      params.target,
      "target-info",
      execution.durationMs,
      "success",
    );
    return result;
  }

  public async dockerPreflight(
    caller: ExecutionCaller,
    requestId: RpcId,
    params: RpcParamsByMethod["docker.preflight"],
  ): Promise<DockerPreflightResult> {
    this.#assertExecutionAvailable();
    const generation = this.#generation;
    const authorization = generation.registry.authorizeDockerPreflight(
      params.target,
    );
    let probe: PreparedFixedProbe;
    try {
      probe = prepareFixedProbe(
        authorization.target.platform,
        "docker-preflight",
        {
          intent: params.intent,
          ...(params.project === undefined
            ? {}
            : {
                project: {
                  directory: params.project.directory,
                  composeFiles: params.project.composeFiles,
                  ...(params.project.name === undefined
                    ? {}
                    : { name: params.project.name }),
                },
              }),
          ports: params.ports,
          ...(params.requiredFreeBytes === undefined
            ? {}
            : { requiredFreeBytes: params.requiredFreeBytes }),
        },
      );
    } catch (error) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.invalidParams,
        "Docker preflight parameters are invalid for this target",
        { cause: error },
      );
    }
    const execution = await this.#runFixedExecution(
      caller,
      requestId,
      params.target,
      authorization,
      "docker-preflight",
      probe,
      generation.executor,
    );
    if (execution.termination !== "exit" || execution.exitCode !== 0) {
      await this.#writeProbeAudit(
        params.target,
        "docker-preflight",
        execution.durationMs,
        probeExecutionResultCode(execution),
      );
      throw new GatewayError(
        GATEWAY_ERROR_CODES.probeFailed,
        "Docker preflight could not be completed on the target",
      );
    }
    let parsed: DockerPreflightProbeResult;
    try {
      parsed = parseProbe("docker-preflight", execution.stdout);
    } catch (error) {
      await this.#writeProbeAudit(
        params.target,
        "docker-preflight",
        execution.durationMs,
        "invalid-response",
      );
      throw error;
    }
    const items = parsed.containers.items;
    const result: DockerPreflightResult = {
      target: params.target,
      intent: parsed.intent,
      checkedAt: new Date().toISOString(),
      durationMs: execution.durationMs,
      overall: parsed.overall,
      daemon: {
        status: !parsed.daemon.installed
          ? "unavailable"
          : parsed.daemon.daemonReachable
            ? "ok"
            : "blocked",
        installed: parsed.daemon.installed,
        reachable: parsed.daemon.daemonReachable,
        ...(parsed.daemon.clientVersion === undefined
          ? {}
          : { clientVersion: parsed.daemon.clientVersion }),
        ...(parsed.daemon.serverVersion === undefined
          ? {}
          : { serverVersion: parsed.daemon.serverVersion }),
        ...(parsed.daemon.contextName === undefined ||
        parsed.daemon.contextScope === undefined
          ? {}
          : {
              context: {
                name: parsed.daemon.contextName,
                scope: parsed.daemon.contextScope,
              },
            }),
      },
      compose: {
        status: !parsed.compose.installed
          ? "unavailable"
          : parsed.compose.config === "invalid"
            ? "blocked"
            : parsed.compose.config === "unavailable"
              ? "warning"
              : "ok",
        installed: parsed.compose.installed,
        ...(parsed.compose.version === undefined
          ? {}
          : { version: parsed.compose.version }),
        config: parsed.compose.config,
      },
      ports: parsed.ports.map((entry) => ({ ...entry })),
      containers: {
        status:
          parsed.containers.status === "ok"
            ? "ok"
            : parsed.containers.status === "not-requested"
              ? "ok"
              : "unavailable",
        ...(parsed.containers.filter === undefined
          ? {}
          : { filter: parsed.containers.filter }),
        truncated: parsed.containers.truncated,
        total: items.length,
        running: items.filter((item) => item.state === "running").length,
        healthy: items.filter((item) => item.health === "healthy").length,
        unhealthy: items.filter((item) => item.health === "unhealthy").length,
        starting: items.filter((item) => item.health === "starting").length,
        exited: items.filter((item) => item.state === "exited").length,
      },
      ...(parsed.disk.status !== "available" ||
      parsed.disk.totalBytes === undefined ||
      parsed.disk.availableBytes === undefined
        ? {}
        : {
            disk: {
              status:
                parsed.disk.requiredBytes !== undefined &&
                parsed.disk.availableBytes < parsed.disk.requiredBytes
                  ? "blocked"
                  : "ok",
              totalBytes: parsed.disk.totalBytes,
              availableBytes: parsed.disk.availableBytes,
              ...(parsed.disk.requiredBytes === undefined
                ? {}
                : { requiredBytes: parsed.disk.requiredBytes }),
            },
          }),
      warnings: [...parsed.warnings],
    };
    await this.#writeProbeAudit(
      params.target,
      "docker-preflight",
      execution.durationMs,
      "success",
    );
    return result;
  }

  async #writeProbeAudit(
    target: string,
    probeKind: ProbeKind,
    durationMs: number,
    resultCode: ProbeResultCode,
  ): Promise<void> {
    await this.#audit.write({
      event: "probe.completed",
      target,
      probeKind,
      durationMs,
      resultCode,
    });
  }

  async #runFixedExecution(
    caller: ExecutionCaller,
    requestId: RpcId,
    target: string,
    authorization: TargetAuthorization,
    probeKind: "target-info" | "docker-preflight",
    probe: PreparedFixedProbe,
    executor: SshRunner,
  ): Promise<FixedExecutionResult> {
    if (this.#activeCount >= this.#maxConcurrentExecutions) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.executionLimitReached,
        "Execution concurrency limit reached",
        { details: { maximum: this.#maxConcurrentExecutions } },
      );
    }
    let sessionExecutions = this.#activeBySession.get(caller.sessionId);
    if (sessionExecutions === undefined) {
      sessionExecutions = new Map();
      this.#activeBySession.set(caller.sessionId, sessionExecutions);
    }
    if (sessionExecutions.has(requestId)) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.invalidParams,
        "Request ID is already executing in this session",
      );
    }
    const active: ActiveExecution = {
      requestId,
      executionId: randomUUID(),
      target,
      controller: new AbortController(),
      acceptingCancellation: true,
    };
    sessionExecutions.set(requestId, active);
    this.#activeCount += 1;

    const operation = (async (): Promise<FixedExecutionResult> => {
      const auditPayload = `agent-ssh-fixed-probe:${probeKind}:v1`;
      await this.#audit.write({
        event: "exec.started",
        executionId: active.executionId,
        target,
        commandSha256: createHash("sha256")
          .update(auditPayload, "utf8")
          .digest("hex"),
        commandBytes: Buffer.byteLength(auditPayload, "utf8"),
      });
      const startedAt = performance.now();
      const timeout = setTimeout(
        () => this.#requestStop(active, "timeout"),
        authorization.timeoutMs,
      );
      let outcome: SshOutcome;
      let termination: ExecResult["termination"];
      let totalOutputBytes = 0;
      try {
        outcome = await executor.run({
          sshAlias: authorization.target.sshAlias,
          command: probe.command,
          stdin: probe.stdin,
          signal: active.controller.signal,
          maxCapturedOutputBytes: probe.maxOutputBytes,
          outputSink: {
            append: (_stream, chunk): void => {
              const nextBytes = totalOutputBytes + chunk.byteLength;
              if (nextBytes > probe.maxOutputBytes) {
                throw new OutputLimitExceededError(
                  probe.maxOutputBytes,
                  totalOutputBytes,
                  chunk.byteLength,
                );
              }
              totalOutputBytes = nextBytes;
            },
          },
        });
        termination = active.reason ?? (outcome.aborted ? "cancel" : "exit");
      } catch (error) {
        if (findCause(error, OutputLimitExceededError) !== undefined) {
          this.#requestStop(active, "output_limit");
          termination = active.reason ?? "output_limit";
        } else if (error instanceof SshExecutionError) {
          termination = active.reason ?? "spawn_error";
        } else {
          throw error;
        }
        outcome = emptyOutcome(performance.now() - startedAt);
      } finally {
        clearTimeout(timeout);
        active.acceptingCancellation = false;
      }
      const durationMs = Math.max(0, Math.round(outcome.durationMs));
      const exitCode =
        termination === "exit" ? normalizeExitCode(outcome.exitCode) : null;
      await this.#audit.write({
        event: "exec.completed",
        executionId: active.executionId,
        target,
        termination,
        exitCode,
        durationMs,
        stdoutBytes: outcome.stdoutBytes,
        stderrBytes: outcome.stderrBytes,
        truncated:
          termination === "output_limit" ||
          outcome.stdoutTruncated ||
          outcome.stderrTruncated,
      });
      return {
        termination,
        exitCode,
        durationMs,
        stdout: outcome.stdout,
        stderr: outcome.stderr,
        stdoutBytes: outcome.stdoutBytes,
        stderrBytes: outcome.stderrBytes,
        stdoutTruncated: outcome.stdoutTruncated,
        stderrTruncated: outcome.stderrTruncated,
      };
    })().finally(() => this.#removeExecution(caller.sessionId, requestId));
    active.done = operation.then(
      () => undefined,
      () => undefined,
    );
    return operation;
  }

  #startExecution(
    caller: ExecutionCaller,
    requestId: RpcId,
    target: string,
    authorization: TargetAuthorization,
    command: string,
    remoteCommand: PreparedRemoteCommand,
    executor: SshRunner,
    observeOutput?: (stream: TaskOutputStream, chunk: Uint8Array) => void,
    maximumOutputBytes?: number,
  ): Promise<InternalExecutionResult> {
    if (this.#activeCount >= this.#maxConcurrentExecutions) {
      return Promise.reject(
        new GatewayError(
          GATEWAY_ERROR_CODES.executionLimitReached,
          "Execution concurrency limit reached",
          { details: { maximum: this.#maxConcurrentExecutions } },
        ),
      );
    }

    let sessionExecutions = this.#activeBySession.get(caller.sessionId);
    if (sessionExecutions === undefined) {
      sessionExecutions = new Map();
      this.#activeBySession.set(caller.sessionId, sessionExecutions);
    }
    if (sessionExecutions.has(requestId)) {
      return Promise.reject(
        new GatewayError(
          GATEWAY_ERROR_CODES.invalidParams,
          "Request ID is already executing in this session",
        ),
      );
    }

    const active: ActiveExecution = {
      requestId,
      executionId: randomUUID(),
      target,
      controller: new AbortController(),
      acceptingCancellation: true,
    };
    sessionExecutions.set(requestId, active);
    this.#activeCount += 1;

    const result = this.#execute(
      active,
      authorization,
      command,
      remoteCommand,
      executor,
      observeOutput,
      maximumOutputBytes,
    ).finally(() => this.#removeExecution(caller.sessionId, requestId));
    active.done = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  public cancel(sessionId: string, requestId: RpcId): boolean {
    const active = this.#activeBySession.get(sessionId)?.get(requestId);
    if (active === undefined || !active.acceptingCancellation) {
      return false;
    }
    this.#requestStop(active, "cancel");
    return true;
  }

  public disconnect(sessionId: string): void {
    for (const active of this.#activeBySession.get(sessionId)?.values() ?? []) {
      if (active.acceptingCancellation) {
        this.#requestStop(active, "cancel");
      }
    }
  }

  public async readOutput(
    params: RpcParamsByMethod["output.read"],
  ): Promise<Awaited<ReturnType<OutputStore["read"]>>> {
    return this.#outputStore.read(
      params.outputRef,
      params.stream,
      params.offset,
      params.limit,
    );
  }

  public async readOutputText(
    params: RpcParamsByMethod["output.readText"],
  ): Promise<RpcResultByMethod["output.readText"]> {
    const legacyOffset = params.offset;
    const legacyOffsetMode = legacyOffset !== undefined;
    const requestedOffset = legacyOffsetMode
      ? legacyOffset
      : params.cursor === undefined
        ? 0
        : decodeOutputTextCursor(
            params.cursor,
            params.outputRef,
            params.stream,
          );
    const page = await readUtf8OutputPage(
      this.#outputStore,
      params.outputRef,
      params.stream,
      requestedOffset,
      params.limit,
    );
    const continuation = page.eof
      ? null
      : legacyOffsetMode
        ? page.followingOffset
        : encodeOutputTextCursor(
            params.outputRef,
            params.stream,
            page.followingOffset,
          );
    return {
      text: page.bytes.toString("utf8"),
      bytesRead: page.bytes.byteLength,
      ...(legacyOffsetMode
        ? { nextOffset: continuation as number | null }
        : { nextCursor: continuation as string | null }),
      eof: page.eof,
      totalBytes: page.totalBytes,
      hadDecodingErrors: !isValidUtf8(page.bytes),
    };
  }

  public async shutdown(): Promise<void> {
    this.#closing = true;
    this.#reloadToken = undefined;
    if (this.#ownsTaskStore) {
      await this.#taskStore.shutdown();
    }
    const completions: Promise<void>[] = [];
    for (const sessionExecutions of this.#activeBySession.values()) {
      for (const active of sessionExecutions.values()) {
        if (active.acceptingCancellation) {
          this.#requestStop(active, "cancel");
        }
        if (active.done !== undefined) {
          completions.push(active.done);
        }
      }
    }
    await Promise.all(completions);
  }

  async #execute(
    active: ActiveExecution,
    authorization: TargetAuthorization,
    command: string,
    remoteCommand: PreparedRemoteCommand,
    executor: SshRunner,
    observeOutput?: (stream: TaskOutputStream, chunk: Uint8Array) => void,
    maximumOutputBytes?: number,
  ): Promise<InternalExecutionResult> {
    const sink = await this.#outputStore.create(active.executionId);
    let sinkDispositionChosen = false;
    try {
      await this.#audit.write({
        event: "exec.started",
        executionId: active.executionId,
        target: active.target,
        commandSha256: createHash("sha256").update(command, "utf8").digest("hex"),
        commandBytes: Buffer.byteLength(command, "utf8"),
      });

      const startedAt = performance.now();
      const timeout = setTimeout(
        () => this.#requestStop(active, "timeout"),
        authorization.timeoutMs,
      );
      let outcome: SshOutcome;
      let termination: ExecResult["termination"];
      let outputBytes = 0;
      try {
        const outputSink =
          observeOutput === undefined && maximumOutputBytes === undefined
            ? sink
            : {
                append: async (
                  stream: TaskOutputStream,
                  chunk: Uint8Array,
                ): Promise<void> => {
                  outputBytes += chunk.byteLength;
                  if (maximumOutputBytes !== undefined && outputBytes > maximumOutputBytes) {
                    throw new OutputLimitExceededError(maximumOutputBytes, outputBytes - chunk.byteLength, chunk.byteLength);
                  }
                  await sink.append(stream, chunk);
                  observeOutput?.(stream, chunk);
                },
              };
        outcome = await executor.run({
          sshAlias: authorization.target.sshAlias,
          ...remoteCommand,
          signal: active.controller.signal,
          outputSink,
          maxCapturedOutputBytes: 0,
        });
        termination = active.reason ?? (outcome.aborted ? "cancel" : "exit");
      } catch (error) {
        if (findCause(error, OutputLimitExceededError) !== undefined) {
          this.#requestStop(active, "output_limit");
          termination = active.reason ?? "output_limit";
        } else if (error instanceof SshExecutionError) {
          termination = active.reason ?? "spawn_error";
        } else {
          throw error;
        }
        outcome = emptyOutcome(performance.now() - startedAt);
      } finally {
        clearTimeout(timeout);
        active.acceptingCancellation = false;
      }

      const output =
        termination === "exit" || termination === "output_limit"
          ? await sink.finalize()
          : discardOutputSink(sink);
      sinkDispositionChosen = true;
      const durationMs = Math.max(0, Math.round(outcome.durationMs));
      const exitCode = termination === "exit" ? normalizeExitCode(outcome.exitCode) : null;

      if (termination === "timeout" || termination === "cancel" || termination === "output_limit") {
        await this.#audit.write({
          event: "exec.cancelled",
          executionId: active.executionId,
          target: active.target,
          reasonCode: termination,
        });
      }
      await this.#audit.write({
        event: "exec.completed",
        executionId: active.executionId,
        target: active.target,
        termination,
        exitCode,
        durationMs,
        stdoutBytes: output.stdout.bytes,
        stderrBytes: output.stderr.bytes,
        truncated:
          termination === "output_limit" ||
          output.stdout.inlineTruncated ||
          output.stderr.inlineTruncated,
      });

      const failureReason = targetCheckFailureReasonSchema.safeParse(
        outcome.failureReason,
      );

      return {
        result: {
          requestId: active.requestId,
          termination,
          exitCode,
          durationMs,
          stdout: output.stdout,
          stderr: output.stderr,
          ...(output.outputRef === undefined
            ? {}
            : {
                outputRef: output.outputRef,
                outputExpiresAt: output.outputExpiresAt!,
              }),
        },
        ...(termination === "exit" && exitCode === 255 && failureReason.success
          ? { failureReason: failureReason.data }
          : {}),
      };
    } catch (error) {
      if (!sinkDispositionChosen) {
        sinkDispositionChosen = true;
        quarantineOutputSink(sink);
      }
      throw error;
    }
  }

  #requestStop(active: ActiveExecution, reason: StopReason): void {
    if (!active.acceptingCancellation || active.reason !== undefined) {
      return;
    }
    active.reason = reason;
    active.controller.abort();
  }

  #removeExecution(sessionId: string, requestId: RpcId): void {
    const sessionExecutions = this.#activeBySession.get(sessionId);
    if (sessionExecutions?.delete(requestId)) {
      this.#activeCount -= 1;
    }
    if (sessionExecutions?.size === 0) {
      this.#activeBySession.delete(sessionId);
    }
  }
}

function createGeneration(
  registry: TargetRegistry,
  executor: SshRunner,
  hostKeyInspector?: TrustedHostKeyInspector,
): ExecServiceGeneration {
  return Object.freeze({
    registry,
    executor,
    ...(hostKeyInspector === undefined ? {} : { hostKeyInspector }),
  });
}

function emptyOutcome(durationMs: number): SshOutcome {
  return {
    exitCode: null,
    signal: null,
    stdout: "",
    stderr: "",
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false,
    aborted: false,
    durationMs,
    terminationMode: null,
  };
}

function discardOutputSink(sink: OutputSink): StoredOutputSummary {
  quarantineOutputSink(sink);
  return {
    stdout: { text: "", bytes: 0, inlineTruncated: false },
    stderr: { text: "", bytes: 0, inlineTruncated: false },
  };
}

function quarantineOutputSink(sink: OutputSink): void {
  try {
    sink.cancel();
  } catch {
    // A broken sink must not delay or replace the execution result.
  }
  try {
    void sink.abort().catch(() => undefined);
  } catch {
    // abort() implementations are expected to return promises, but fail closed
    // if an implementation throws synchronously.
  }
}

function normalizeExitCode(exitCode: number | null): number | null {
  if (exitCode === null) {
    return null;
  }
  return exitCode < 0 ? exitCode >>> 0 : exitCode;
}

function probeExecutionResultCode(
  result: FixedExecutionResult,
): ProbeResultCode {
  switch (result.termination) {
    case "exit":
      return result.exitCode === 0 ? "success" : "remote-exit";
    case "timeout":
      return "timeout";
    case "cancel":
      return "cancel";
    case "output_limit":
      return "output-limit";
    case "spawn_error":
      return "spawn-error";
  }
}

function findCause<ErrorType extends Error>(
  error: unknown,
  constructor: abstract new (...args: never[]) => ErrorType,
): ErrorType | undefined {
  let current = error;
  for (let depth = 0; depth < 8; depth += 1) {
    if (current instanceof constructor) {
      return current;
    }
    if (!(current instanceof Error) || !("cause" in current)) {
      return undefined;
    }
    current = current.cause;
  }
  return undefined;
}

function toTargetCheckResult(
  target: string,
  result: ExecResult,
  failureReason?: TargetCheckFailureReason,
): TargetCheckResult {
  const connected = result.termination === "exit" && result.exitCode === 0;
  const hostname = connected ? extractSafeHostname(result.stdout.text) : undefined;
  return {
    target,
    connected,
    termination: result.termination,
    exitCode: result.exitCode,
    durationMs: result.durationMs,
    ...(hostname === undefined ? {} : { hostname }),
    ...(!connected && failureReason !== undefined ? { failureReason } : {}),
  };
}

function extractSafeHostname(stdout: string): string | undefined {
  const firstLine = stdout.split(/[\r\n]/u, 1)[0]?.trim();
  if (firstLine === undefined || firstLine.length === 0) {
    return undefined;
  }
  const hostname = firstLine.slice(0, MAX_TARGET_CHECK_HOSTNAME_LENGTH);
  return SAFE_HOSTNAME_PATTERN.test(hostname) ? hostname : undefined;
}

function canonicalStructuredPayload(
  params: Extract<RpcParamsByMethod["exec.run"], { script: string }>,
): string {
  const env = Object.fromEntries(
    Object.entries(params.env ?? {}).sort(([left], [right]) =>
      left < right ? -1 : left > right ? 1 : 0,
    ),
  );
  return JSON.stringify({
    type: "agent-ssh-structured-v1",
    shell: params.shell,
    script: params.script,
    cwd: params.cwd ?? null,
    env,
    encoding: params.encoding,
  });
}

interface Utf8OutputPage {
  readonly bytes: Buffer;
  readonly followingOffset: number;
  readonly eof: boolean;
  readonly totalBytes: number;
}

interface OutputTextCursor {
  readonly v: 1;
  readonly o: number;
  readonly b: string;
}

async function readUtf8OutputPage(
  store: OutputStore,
  outputRef: string,
  stream: OutputStream,
  requestedOffset: number,
  limit: number,
): Promise<Utf8OutputPage> {
  const offset = await alignUtf8ReadOffset(
    store,
    outputRef,
    stream,
    requestedOffset,
  );
  const first = await store.read(outputRef, stream, offset, limit);
  let bytes = Buffer.from(first.dataBase64, "base64");
  let atEof = first.eof;

  if (!atEof) {
    const completeBytes = completeUtf8PrefixLength(bytes);
    if (completeBytes < bytes.byteLength) {
      const partialLength = bytes.byteLength - completeBytes;
      const expectedLength = utf8SequenceLength(bytes[completeBytes]!);
      const missingBytes = Math.max(0, expectedLength - partialLength);
      if (missingBytes > 0) {
        const extra = await store.read(
          outputRef,
          stream,
          offset + bytes.byteLength,
          missingBytes,
        );
        bytes = Buffer.concat([
          bytes,
          Buffer.from(extra.dataBase64, "base64"),
        ]);
        atEof = extra.eof;
      }
    }

    if (!atEof) {
      bytes = bytes.subarray(0, completeUtf8PrefixLength(bytes));
    }
  }

  const followingOffset = offset + bytes.byteLength;
  return {
    bytes,
    followingOffset,
    eof: followingOffset >= first.totalBytes,
    totalBytes: first.totalBytes,
  };
}

async function alignUtf8ReadOffset(
  store: OutputStore,
  outputRef: string,
  stream: OutputStream,
  offset: number,
): Promise<number> {
  if (offset === 0) return 0;

  const probeOffset = Math.max(0, offset - 3);
  const probe = await store.read(outputRef, stream, probeOffset, 7);
  const bytes = Buffer.from(probe.dataBase64, "base64");
  const index = offset - probeOffset;
  if (index >= bytes.byteLength || !isUtf8Continuation(bytes[index]!)) {
    return offset;
  }

  for (let leadIndex = index - 1; leadIndex >= 0; leadIndex -= 1) {
    const expectedLength = utf8SequenceLength(bytes[leadIndex]!);
    if (expectedLength === 1) continue;
    const sequenceEnd = leadIndex + expectedLength;
    if (sequenceEnd <= index || sequenceEnd > bytes.byteLength) continue;
    const sequence = bytes.subarray(leadIndex, sequenceEnd);
    if (isValidUtf8(sequence)) {
      return probeOffset + sequenceEnd;
    }
  }
  return offset;
}

function utf8SequenceLength(lead: number): number {
  if (lead >= 0xc2 && lead <= 0xdf) return 2;
  if (lead >= 0xe0 && lead <= 0xef) return 3;
  if (lead >= 0xf0 && lead <= 0xf4) return 4;
  return 1;
}

function isUtf8Continuation(byte: number): boolean {
  return (byte & 0xc0) === 0x80;
}

function encodeOutputTextCursor(
  outputRef: string,
  stream: OutputStream,
  offset: number,
): string {
  const cursor: OutputTextCursor = {
    v: 1,
    o: offset,
    b: outputTextCursorBinding(outputRef, stream, offset),
  };
  return Buffer.from(JSON.stringify(cursor), "utf8").toString("base64url");
}

function decodeOutputTextCursor(
  value: string,
  outputRef: string,
  stream: OutputStream,
): number {
  try {
    const parsed = JSON.parse(
      Buffer.from(value, "base64url").toString("utf8"),
    ) as unknown;
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed) ||
      Object.keys(parsed).sort().join(",") !== "b,o,v" ||
      (parsed as { v?: unknown }).v !== 1 ||
      !Number.isSafeInteger((parsed as { o?: unknown }).o) ||
      (parsed as { o: number }).o < 0 ||
      typeof (parsed as { b?: unknown }).b !== "string"
    ) {
      throw new Error("invalid cursor");
    }
    const cursor = parsed as OutputTextCursor;
    if (cursor.b !== outputTextCursorBinding(outputRef, stream, cursor.o)) {
      throw new Error("invalid cursor binding");
    }
    return cursor.o;
  } catch {
    throw new GatewayError(
      GATEWAY_ERROR_CODES.invalidParams,
      "Output cursor is invalid",
    );
  }
}

function outputTextCursorBinding(
  outputRef: string,
  stream: OutputStream,
  offset: number,
): string {
  return createHash("sha256")
    .update("agent-ssh-output-text-cursor-v1\0", "utf8")
    .update(outputRef, "utf8")
    .update("\0", "utf8")
    .update(stream, "utf8")
    .update("\0", "utf8")
    .update(String(offset), "utf8")
    .digest("base64url")
    .slice(0, 22);
}

function isValidUtf8(bytes: Uint8Array): boolean {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return true;
  } catch {
    return false;
  }
}

function parseProbe(
  kind: "target-info",
  output: string,
): TargetInfoProbeResult;
function parseProbe(
  kind: "docker-preflight",
  output: string,
): DockerPreflightProbeResult;
function parseProbe(
  kind: "target-info" | "docker-preflight",
  output: string,
) {
  try {
    return kind === "target-info"
      ? parseFixedProbeOutput("target-info", output)
      : parseFixedProbeOutput("docker-preflight", output);
  } catch (error) {
    throw new GatewayError(
      GATEWAY_ERROR_CODES.probeFailed,
      "Target returned an invalid fixed-probe response",
      { ...(error instanceof FixedProbeParseError ? { cause: error } : {}) },
    );
  }
}
