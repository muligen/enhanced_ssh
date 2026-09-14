import { lstat } from "node:fs/promises";
import path from "node:path";

import { loadConfig, type GatewayConfig } from "../config/load-config.js";
import {
  ExecService,
  ExecServiceReloadError,
  type TrustedHostKeyInspector,
} from "../core/exec-service.js";
import { OutputStore } from "../core/output-store.js";
import { TargetRegistry } from "../core/target-registry.js";
import { TaskStore } from "../core/task-store.js";
import { TransferService } from "../core/transfer-service.js";
import {
  openMachineIdentityKey,
  type MachineIdentityKeyStore,
} from "../core/machine-identity.js";
import { AuditWriter } from "../infra/audit-writer.js";
import { HostKeyInspector } from "../infra/host-key-inspector.js";
import { SshExecutor } from "../infra/openssh-executor.js";
import { PuttySharedExecutor } from "../infra/putty-shared-executor.js";
import { TailscaleSshExecutor } from "../infra/tailscale-ssh-executor.js";
import { RoutingSshExecutor } from "../infra/routing-ssh-executor.js";
import { SftpExecutor } from "../infra/sftp-executor.js";
import type { SshRunner } from "../infra/ssh-runner.js";
import { resolveWindowsSupervisorPath } from "../infra/process-tree.js";
import { MAX_INLINE_PREVIEW_BYTES } from "../shared/protocol.js";
import { GATEWAY_VERSION } from "../shared/version.js";
import { ActivationGateDispatcher } from "./activation-gate.js";
import { GatewayDispatcher } from "./dispatcher.js";
import { PipeRpcServer } from "./pipe-server.js";
import { prepareRuntimeStorage } from "./storage-security.js";
import {
  cleanupOrphanedSshWrapperConfigs,
  createSshWrapperConfig,
  type GeneratedSshConfig,
} from "./ssh-wrapper-config.js";
import {
  createRuntimeDescriptor,
  type RuntimeDescriptor,
  type RuntimeLease,
} from "./runtime-state.js";

export interface RunningGatewayDaemon {
  readonly dataDirectory: string;
  activate(): void;
  reload(configPath: string): Promise<void>;
  stop(): Promise<void>;
}

export class GatewayReloadCommittedCleanupError extends Error {
  public readonly code = "RELOAD_COMMITTED_CLEANUP_FAILED";
  public readonly committed = true;
  public override readonly cause: unknown;

  public constructor(cause: unknown) {
    super(
      "Gateway configuration reload committed, but a retired SSH generation could not be cleaned up",
    );
    this.name = "GatewayReloadCommittedCleanupError";
    this.cause = cause;
  }
}

export interface StartGatewayDaemonOptions {
  readonly deferActivation?: boolean;
  readonly cleanupManagedSshWrapperOrphans?: boolean;
}

async function assertRegularFile(filePath: string, label: string): Promise<void> {
  const entry = await lstat(filePath);
  if (!entry.isFile() || entry.isSymbolicLink()) {
    throw new Error(`${label} must be a directly referenced regular file`);
  }
}

async function validateRuntimeDependencies(
  config: GatewayConfig,
): Promise<{ readonly supervisorPath?: string; readonly sftpExecutable: string }> {
  const sftpExecutable =
    config.ssh.sftpExecutable ??
    path.join(
      path.dirname(config.ssh.executable),
      process.platform === "win32" ? "sftp.exe" : "sftp",
    );
  await Promise.all([
    assertRegularFile(config.ssh.executable, "ssh.executable"),
    assertRegularFile(sftpExecutable, "ssh.sftpExecutable"),
    assertRegularFile(config.ssh.configFile, "ssh.configFile"),
    assertRegularFile(config.ssh.knownHostsFile, "ssh.knownHostsFile"),
    ...(config.tailscale === undefined ? [] : [assertRegularFile(config.tailscale.executable, "tailscale.executable")]),
    ...(config.putty === undefined
      ? []
      : [assertRegularFile(config.putty.executable, "putty.executable")]),
  ]);

  // POSIX uses the managed process group implementation; only Windows needs
  // the native Job Object supervisor.
  if (process.platform !== "win32") return { sftpExecutable };

  const supervisor = resolveWindowsSupervisorPath();
  if (supervisor === undefined) {
    throw new Error(
      "Windows Job Object supervisor is unavailable; build the native helper first",
    );
  }
  await assertRegularFile(supervisor, "Windows Job Object supervisor");
  return { supervisorPath: supervisor, sftpExecutable };
}

interface PreparedGeneration {
  readonly registry: TargetRegistry;
  readonly executor: SshRunner;
  readonly sftp: SftpExecutor;
  readonly hostKeyInspector: TrustedHostKeyInspector;
  readonly generatedSshConfig: GeneratedSshConfig;
  dispose(): Promise<void>;
}

async function prepareGeneration(
  config: GatewayConfig,
): Promise<PreparedGeneration> {
  const { supervisorPath, sftpExecutable } =
    await validateRuntimeDependencies(config);
  const generatedSshConfig = await createSshWrapperConfig(
    config.runtime.dataDirectory,
    config.ssh.configFile,
    config.ssh.knownHostsFile,
    config.ssh.connectTimeoutSeconds,
  );
  const ownedRunners = new Set<SshRunner>();
  try {
    const registry = TargetRegistry.fromConfig(config);
    const openSshExecutor = new SshExecutor({
      executable: config.ssh.executable,
      configFile: generatedSshConfig.path,
      knownHostsFile: config.ssh.knownHostsFile,
      connectTimeoutSeconds: config.ssh.connectTimeoutSeconds,
      ...(supervisorPath === undefined ? {} : { windowsSupervisorPath: supervisorPath }),
      allowUnsafeProcessTermination: false,
    });
    ownedRunners.add(openSshExecutor);
    const accessClientAliases = new Set<string>();
    const routes = new Map<string, SshRunner>();
    const tailscaleRoutes = new Map<string, TailscaleSshExecutor>();
    for (const target of Object.values(config.targets)) {
      if (target.connection?.mode === "tailscale-ssh") {
        if (config.tailscale === undefined) throw new Error("Tailscale SSH requires tailscale.executable");
        const route = new TailscaleSshExecutor({
          executable: config.ssh.executable,
          tailscaleExecutable: config.tailscale.executable,
          runtimeDirectory: config.runtime.dataDirectory,
          targetAlias: target.sshAlias,
          host: target.connection.host,
          username: target.connection.username,
          connectTimeoutSeconds: config.ssh.connectTimeoutSeconds,
          ...(supervisorPath === undefined ? {} : { windowsSupervisorPath: supervisorPath }),
          allowUnsafeProcessTermination: false,
        });
        ownedRunners.add(route);
        routes.set(target.sshAlias, route);
        tailscaleRoutes.set(target.sshAlias, route);
        continue;
      }
      if (target.connection?.mode !== "accessclient-share") continue;
      if (config.putty === undefined) {
        throw new Error("AccessClient target requires putty.executable");
      }
      accessClientAliases.add(target.sshAlias);
      const route = new PuttySharedExecutor({
        executable: config.putty.executable,
        targetAlias: target.sshAlias,
        gatewayHost: target.connection.gatewayHost,
        gatewayPort: target.connection.gatewayPort,
        gatewayUsername: target.connection.gatewayUsername,
        ...(target.connection.sharingHost === undefined
          ? {}
          : { sharingHost: target.connection.sharingHost }),
        ...(target.connection.sharingPort === undefined
          ? {}
          : { sharingPort: target.connection.sharingPort }),
        ...(target.connection.expectedHostname === undefined
          ? {}
          : { expectedHostname: target.connection.expectedHostname }),
        platform: target.platform,
        ...(supervisorPath === undefined ? {} : { windowsSupervisorPath: supervisorPath }),
        allowUnsafeProcessTermination: false,
      });
      ownedRunners.add(route);
      routes.set(target.sshAlias, route);
    }
    const executor = new RoutingSshExecutor(openSshExecutor, routes);
    const sftp = new SftpExecutor({
      executable: sftpExecutable,
      sshExecutable: config.ssh.executable,
      configFile: generatedSshConfig.path,
      knownHostsFile: config.ssh.knownHostsFile,
      connectTimeoutSeconds: config.ssh.connectTimeoutSeconds,
      ...(supervisorPath === undefined ? {} : { windowsSupervisorPath: supervisorPath }),
      allowUnsafeProcessTermination: false,
    });
    const hostKeys = new HostKeyInspector({
      sshExecutable: config.ssh.executable,
      configFile: generatedSshConfig.path,
      knownHostsFile: config.ssh.knownHostsFile,
    });
    const hostKeyInspector: TrustedHostKeyInspector = Object.freeze({
      inspect: async (sshAlias: string): Promise<readonly string[]> =>
        tailscaleRoutes.has(sshAlias) ? tailscaleRoutes.get(sshAlias)!.fingerprints :
        accessClientAliases.has(sshAlias)
          ? Object.freeze([])
          :
        Object.freeze(
          [
            ...new Set(
              (await hostKeys.inspect(sshAlias)).map(
                (entry) => entry.fingerprintSha256,
              ),
            ),
          ],
        ),
    });
    let disposed = false;
    let disposeOperation: Promise<void> | undefined;
    return {
      registry,
      executor,
      sftp,
      hostKeyInspector,
      generatedSshConfig,
      dispose(): Promise<void> {
        if (disposed) return Promise.resolve();
        if (disposeOperation === undefined) {
          const operation = disposeGenerationResources(
            new Set([executor]),
            generatedSshConfig,
          ).then(() => {
            disposed = true;
          });
          disposeOperation = operation;
          const clearOperation = (): void => {
            if (disposeOperation === operation) {
              disposeOperation = undefined;
            }
          };
          void operation.then(clearOperation, clearOperation);
        }
        return disposeOperation;
      },
    };
  } catch (error) {
    await disposeGenerationResources(ownedRunners, generatedSshConfig).catch(
      reportMaintenanceError,
    );
    throw error;
  }
}

async function disposeGenerationResources(
  runners: ReadonlySet<SshRunner>,
  generatedSshConfig: GeneratedSshConfig,
): Promise<void> {
  const results = await Promise.allSettled([
    ...[...runners].map(async (runner) => runner.close()),
    generatedSshConfig.remove(),
  ]);
  const failures = results.flatMap((result) =>
    result.status === "rejected" ? [result.reason] : [],
  );
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) {
    throw new AggregateError(
      failures,
      "multiple SSH generation resources failed to close",
    );
  }
}

async function disposeRetiredGenerations(
  generations: Set<PreparedGeneration>,
): Promise<void> {
  const retired = [...generations];
  const results = await Promise.allSettled(
    retired.map(async (generation) => generation.dispose()),
  );
  const failures: unknown[] = [];
  for (const [index, result] of results.entries()) {
    const generation = retired[index]!;
    if (result.status === "fulfilled") {
      generations.delete(generation);
    } else {
      failures.push(result.reason);
    }
  }
  throwCleanupFailures(
    failures,
    "multiple retired SSH generations failed to close",
  );
}

export async function startGatewayDaemon(
  configPath: string,
  options: StartGatewayDaemonOptions = {},
): Promise<RunningGatewayDaemon> {
  const config = await loadConfig(configPath);

  let runtime: RuntimeDescriptor | undefined;
  let runtimeLease: RuntimeLease | undefined;
  let audit: AuditWriter | undefined;
  let service: ExecService | undefined;
  let taskStore: TaskStore | undefined;
  let transferService: TransferService | undefined;
  let machineIdentity: MachineIdentityKeyStore | undefined;
  let server: PipeRpcServer | undefined;
  let activeGeneration: PreparedGeneration | undefined;
  const retiredGenerations = new Set<PreparedGeneration>();
  let activationGate: ActivationGateDispatcher | undefined;
  let activated = options.deferActivation !== true;
  let outputCleanupTimer: NodeJS.Timeout | undefined;
  let reloadOperation: Promise<void> | undefined;
  let stopping: Promise<void> | undefined;

  const stop = (): Promise<void> => {
    stopping ??= (async () => {
      const cleanupFailures: unknown[] = [];
      if (reloadOperation !== undefined) {
        const currentReload = reloadOperation;
        await collectCleanupFailure(cleanupFailures, async () => currentReload);
      }
      if (audit !== undefined) {
        const currentAudit = audit;
        await collectCleanupFailure(cleanupFailures, async () =>
          currentAudit.write({ event: "daemon.health", status: "stopping" }),
        );
      }
      if (outputCleanupTimer !== undefined) {
        clearInterval(outputCleanupTimer);
      }
      if (server !== undefined) {
        const currentServer = server;
        await collectCleanupFailure(cleanupFailures, async () =>
          currentServer.close(),
        );
      }
      if (taskStore !== undefined) {
        const currentTaskStore = taskStore;
        await collectCleanupFailure(cleanupFailures, async () =>
          currentTaskStore.shutdown(),
        );
      }
      if (service !== undefined) {
        const currentService = service;
        await collectCleanupFailure(cleanupFailures, async () =>
          currentService.shutdown(),
        );
      }
      if (activeGeneration !== undefined) {
        const currentGeneration = activeGeneration;
        await collectCleanupFailure(cleanupFailures, async () =>
          currentGeneration.dispose(),
        );
      }
      if (retiredGenerations.size !== 0) {
        await collectCleanupFailure(cleanupFailures, async () =>
          disposeRetiredGenerations(retiredGenerations),
        );
      }
      if (machineIdentity !== undefined) {
        const currentMachineIdentity = machineIdentity;
        await collectCleanupFailure(cleanupFailures, () =>
          currentMachineIdentity.close(),
        );
      }
      if (audit !== undefined) {
        const currentAudit = audit;
        await collectCleanupFailure(cleanupFailures, async () =>
          currentAudit.write({ event: "daemon.health", status: "stopped" }),
        );
        await collectCleanupFailure(cleanupFailures, async () =>
          currentAudit.close(),
        );
      }
      if (runtimeLease !== undefined) {
        const currentRuntimeLease = runtimeLease;
        await collectCleanupFailure(cleanupFailures, async () =>
          currentRuntimeLease.release(),
        );
      }
      throwCleanupFailures(
        cleanupFailures,
        "Gateway daemon shutdown cleanup failed",
      );
    })();
    return stopping;
  };

  try {
    runtimeLease = await createRuntimeDescriptor(config.runtime.dataDirectory);
    runtime = runtimeLease.descriptor;
    if (options.cleanupManagedSshWrapperOrphans === true) {
      await cleanupOrphanedSshWrapperConfigs(config.runtime.dataDirectory);
    }
    const storage = await prepareRuntimeStorage(config.runtime.dataDirectory);
    machineIdentity = await openMachineIdentityKey(
      storage.machineIdentityKeyFile,
    );
    const initialGeneration = await prepareGeneration(config);
    activeGeneration = initialGeneration;
    audit = new AuditWriter({
      filePath: storage.auditFile,
      maxBytes: config.runtime.maxAuditBytes,
      maxConcurrentExecutions: config.runtime.maxConcurrentExecutions,
      maxConcurrentTransfers: config.runtime.maxConcurrentExecutions,
    });
    await audit.write({ event: "daemon.health", status: "started" });

    const registry = initialGeneration.registry;
    const targets = registry.list();
    await audit.write({
      event: "registry.loaded",
      targetCount: targets.length,
      enabledTargetCount: targets.filter((target) => target.enabled).length,
    });

    const outputStore = await OutputStore.open({
      directory: storage.outputsDirectory,
      inlineBytesPerStream: config.runtime.inlineOutputBytes,
      maxStoredBytes: config.runtime.maxStoredOutputBytes,
      maxTotalRetainedBytes: config.runtime.maxTotalRetainedOutputBytes,
      maxRetainedEntries: config.runtime.maxRetainedOutputs,
      ttlMs: config.runtime.outputTtlSeconds * 1_000,
    });
    outputCleanupTimer = setInterval(
      () => void outputStore.cleanupExpired().catch(reportMaintenanceError),
      Math.min(60_000, Math.max(10_000, config.runtime.outputTtlSeconds * 500)),
    );
    outputCleanupTimer.unref();
    taskStore = new TaskStore({
      ttlMs: config.runtime.outputTtlSeconds * 1_000,
      maxRetainedTasks: config.runtime.maxRetainedOutputs,
      maxConcurrentTasks: config.runtime.maxConcurrentExecutions,
    });
    service = new ExecService({
      registry,
      executor: initialGeneration.executor,
      outputStore,
      audit,
      maxConcurrentExecutions: config.runtime.maxConcurrentExecutions,
      taskStore,
      machineIdentity,
      hostKeyInspector: initialGeneration.hostKeyInspector,
    });
    transferService = new TransferService({
      registry,
      ssh: initialGeneration.executor,
      sftp: initialGeneration.sftp,
      taskStore,
      spoolDirectory: storage.transfersDirectory,
      audit,
    });
    const dispatcher = new GatewayDispatcher(service, transferService);
    if (options.deferActivation === true) {
      activationGate = new ActivationGateDispatcher(dispatcher);
    }
    server = new PipeRpcServer({
      runtime,
      dispatcher: activationGate ?? dispatcher,
      serverVersion: GATEWAY_VERSION,
    });
    await server.listen();
    if (activated) {
      await audit.write({ event: "daemon.health", status: "ready" });
    }
  } catch (error) {
    await stop();
    throw error;
  }

  return Object.freeze({
    dataDirectory: config.runtime.dataDirectory,
    activate: (): void => {
      if (activated) {
        return;
      }
      activated = true;
      activationGate?.activate();
      void audit
        ?.write({ event: "daemon.health", status: "ready" })
        .catch(reportMaintenanceError);
    },
    reload: (nextConfigPath: string): Promise<void> => {
      if (stopping !== undefined) {
        return Promise.reject(
          new ExecServiceReloadError(
            "SERVICE_CLOSING",
            "Gateway configuration cannot reload while the service is stopping",
          ),
        );
      }
      if (reloadOperation !== undefined) {
        return Promise.reject(
          new ExecServiceReloadError(
            "RELOAD_IN_PROGRESS",
            "Gateway configuration reload is already in progress",
          ),
        );
      }

      const operation = (async (): Promise<void> => {
        const reloadLease = service!.beginReload();
        let candidate: PreparedGeneration | undefined;
        try {
          const nextConfig = await loadConfig(nextConfigPath);
          assertRuntimeCompatible(config, nextConfig);
          candidate = await prepareGeneration(nextConfig);
          const targets = candidate.registry.list();
          await audit!.write({
            event: "registry.loaded",
            targetCount: targets.length,
            enabledTargetCount: targets.filter((target) => target.enabled).length,
          });
          if (stopping !== undefined) {
            throw new Error("Gateway configuration reload was interrupted by shutdown");
          }

          const previousGeneration = activeGeneration!;
          reloadLease.commit({
            registry: candidate.registry,
            executor: candidate.executor,
            hostKeyInspector: candidate.hostKeyInspector,
          });
          transferService!.replaceGeneration({
            registry: candidate.registry,
            ssh: candidate.executor,
            sftp: candidate.sftp,
          });
          activeGeneration = candidate;
          retiredGenerations.add(previousGeneration);
          candidate = undefined;
          try {
            await disposeRetiredGenerations(retiredGenerations);
          } catch (cleanupError) {
            throw new GatewayReloadCommittedCleanupError(cleanupError);
          }
        } catch (error) {
          if (candidate !== undefined) {
            try {
              await candidate.dispose();
            } catch (cleanupError) {
              throw new AggregateError(
                [error, cleanupError],
                "Gateway configuration reload failed and candidate cleanup was incomplete",
              );
            }
          }
          throw error;
        } finally {
          reloadLease.release();
        }
      })();
      reloadOperation = operation;
      const clearOperation = (): void => {
        if (reloadOperation === operation) {
          reloadOperation = undefined;
        }
      };
      void operation.then(clearOperation, clearOperation);
      return operation;
    },
    stop,
  });
}

function assertRuntimeCompatible(
  initial: GatewayConfig,
  candidate: GatewayConfig,
): void {
  const keys = Object.keys(initial.runtime) as Array<keyof GatewayConfig["runtime"]>;
  for (const key of keys) {
    if (key === "inlineOutputBytes") {
      const initialEffective = Math.min(
        initial.runtime.inlineOutputBytes,
        MAX_INLINE_PREVIEW_BYTES,
      );
      const candidateEffective = Math.min(
        candidate.runtime.inlineOutputBytes,
        MAX_INLINE_PREVIEW_BYTES,
      );
      if (candidateEffective === initialEffective) {
        continue;
      }
    }
    if (candidate.runtime[key] !== initial.runtime[key]) {
      throw new Error(
        `Reloaded configuration must preserve runtime.${String(key)}`,
      );
    }
  }
}

async function collectCleanupFailure(
  failures: unknown[],
  operation: () => void | Promise<void>,
): Promise<void> {
  try {
    await operation();
  } catch (error) {
    failures.push(error);
  }
}

function throwCleanupFailures(failures: unknown[], message: string): void {
  if (failures.length === 1) {
    throw failures[0];
  }
  if (failures.length > 1) {
    throw new AggregateError(failures, message);
  }
}

function reportMaintenanceError(error: unknown): void {
  const name = error instanceof Error ? error.name : "UnknownError";
  process.stderr.write(`agent-ssh-gateway maintenance warning: ${name}\n`);
}
