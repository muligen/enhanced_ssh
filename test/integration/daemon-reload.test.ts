import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { stringify } from "yaml";

import {
  ExecServiceReloadError,
} from "../../src/core/exec-service.js";
import { TargetRegistry } from "../../src/core/target-registry.js";
import {
  GatewayReloadCommittedCleanupError,
  startGatewayDaemon,
  type RunningGatewayDaemon,
} from "../../src/daemon/service.js";
import {
  createRuntimeDescriptor,
  loadRuntimeDescriptor,
} from "../../src/daemon/runtime-state.js";
import { AuditWriter } from "../../src/infra/audit-writer.js";
import type { SshExecutor } from "../../src/infra/openssh-executor.js";
import { GatewayRpcClient } from "../../src/shared/rpc-client.js";
import {
  FakeSshExecutor,
  deferred,
  sshOutcome,
  testExecService,
} from "../helpers/fakes.js";

test("execution service rejects reload while active and swaps one idle generation", async () => {
  const entered = deferred<void>();
  const finish = deferred<ReturnType<typeof sshOutcome>>();
  const firstExecutor = new FakeSshExecutor(async () => {
    entered.resolve();
    return finish.promise;
  });
  const service = testExecService({ executor: firstExecutor });

  const running = service.run(
    { sessionId: "reload-test-session" },
    "active-request",
    { target: "alpha", command: "long-command" },
  );
  await entered.promise;

  assert.throws(
    () => service.beginReload(),
    (error: unknown) =>
      error instanceof ExecServiceReloadError &&
      error.code === "ACTIVE_EXECUTIONS",
  );

  finish.resolve(sshOutcome());
  await running;

  const reload = service.beginReload();
  assert.throws(
    () => service.run(
      { sessionId: "reload-test-session" },
      "blocked-during-reload",
      { target: "alpha", command: "echo ok" },
    ),
    /configuration is reloading/iu,
  );

  const secondExecutor = new FakeSshExecutor(async () => sshOutcome());
  const secondRegistry = new TargetRegistry({
    beta: {
      description: "Reloaded target",
      sshAlias: "internal-beta",
      platform: "linux",
      enabled: true,
      policy: {
        mode: "allow-list",
        allowedCommands: ["hostname"],
        maxTimeoutMs: 5_000,
      },
    },
  });
  reload.commit({
    registry: secondRegistry,
    executor: secondExecutor as unknown as SshExecutor,
  });

  assert.deepEqual(
    service.listTargets().map((target) => target.alias),
    ["beta"],
  );
  assert.throws(
    () => service.run(
      { sessionId: "reload-test-session" },
      "still-blocked-after-commit",
      { target: "beta", command: "hostname" },
    ),
    /configuration is reloading/iu,
  );
  reload.release();
  await service.run(
    { sessionId: "reload-test-session" },
    "after-reload",
    { target: "beta", command: "hostname" },
  );
  assert.equal(firstExecutor.calls.length, 1);
  assert.equal(secondExecutor.calls.length, 1);
  await service.shutdown();
});

test(
  "daemon reload preserves its RPC session and rolls back invalid candidates",
  { skip: process.platform !== "win32", timeout: 120_000 },
  async (t) => {
    const sandbox = await mkdtemp(
      path.join(os.tmpdir(), "agent-ssh-daemon-reload-"),
    );
    const dataDirectory = path.join(sandbox, "runtime");
    const knownHosts = path.join(sandbox, "known_hosts");
    const firstSshConfig = path.join(sandbox, "first_ssh_config");
    const secondSshConfig = path.join(sandbox, "second_ssh_config");
    const firstGatewayConfig = path.join(sandbox, "first_gateway.yaml");
    const secondGatewayConfig = path.join(sandbox, "second_gateway.yaml");
    const incompatibleGatewayConfig = path.join(
      sandbox,
      "incompatible_gateway.yaml",
    );
    const missingDependencyGatewayConfig = path.join(
      sandbox,
      "missing_dependency_gateway.yaml",
    );
    let daemon: RunningGatewayDaemon | undefined;
    let client: GatewayRpcClient | undefined;
    t.after(async () => {
      client?.close();
      await daemon?.stop().catch(() => undefined);
      await rm(sandbox, { recursive: true, force: true });
    });

    await Promise.all([
      mkdir(dataDirectory, { recursive: true }),
      writeFile(knownHosts, "", { encoding: "utf8", mode: 0o600 }),
      writeFile(
        firstSshConfig,
        renderSshConfig("internal-alpha"),
        { encoding: "utf8", mode: 0o600 },
      ),
      writeFile(
        secondSshConfig,
        renderSshConfig("internal-beta"),
        { encoding: "utf8", mode: 0o600 },
      ),
    ]);

    const firstConfig = gatewayConfiguration(
      dataDirectory,
      firstSshConfig,
      knownHosts,
      "alpha",
    );
    const secondConfig = gatewayConfiguration(
      dataDirectory,
      secondSshConfig,
      knownHosts,
      "beta",
      8_192,
    );
    await Promise.all([
      writeFile(firstGatewayConfig, stringify(firstConfig), "utf8"),
      writeFile(secondGatewayConfig, stringify(secondConfig), "utf8"),
      writeFile(
        incompatibleGatewayConfig,
        stringify({
          ...secondConfig,
          runtime: {
            ...secondConfig.runtime,
            maxConcurrentExecutions: 3,
          },
        }),
        "utf8",
      ),
      writeFile(
        missingDependencyGatewayConfig,
        stringify({
          ...secondConfig,
          ssh: {
            ...secondConfig.ssh,
            configFile: path.join(sandbox, "missing_ssh_config"),
          },
        }),
        "utf8",
      ),
    ]);

    const orphanedWrapper =
      `.ssh-wrapper-2147483647-${"f".repeat(32)}.conf`;
    await writeFile(
      path.join(dataDirectory, orphanedWrapper),
      "orphaned wrapper fixture",
      "utf8",
    );

    daemon = await startGatewayDaemon(firstGatewayConfig, {
      cleanupManagedSshWrapperOrphans: true,
    });
    client = await GatewayRpcClient.connect(dataDirectory, {
      name: "daemon-reload-test",
      version: "1.0.0",
    });
    const runtimeBefore = await loadRuntimeDescriptor(dataDirectory);
    const firstWrappers = await wrapperNames(dataDirectory);
    assert.equal(firstWrappers.length, 1);
    assert.equal(firstWrappers.includes(orphanedWrapper), false);
    assert.deepEqual(await targetAliases(client), ["alpha"]);

    await daemon.reload(secondGatewayConfig);

    assert.deepEqual(await loadRuntimeDescriptor(dataDirectory), runtimeBefore);
    assert.deepEqual(await targetAliases(client), ["beta"]);
    const secondWrappers = await wrapperNames(dataDirectory);
    assert.equal(secondWrappers.length, 1);
    assert.notDeepEqual(secondWrappers, firstWrappers);

    await assert.rejects(
      daemon.reload(incompatibleGatewayConfig),
      /preserve runtime\.maxConcurrentExecutions/iu,
    );
    assert.deepEqual(await targetAliases(client), ["beta"]);
    assert.deepEqual(await wrapperNames(dataDirectory), secondWrappers);

    await assert.rejects(
      daemon.reload(missingDependencyGatewayConfig),
      /ENOENT|must be a directly referenced regular file/iu,
    );
    assert.deepEqual(await targetAliases(client), ["beta"]);
    assert.deepEqual(await wrapperNames(dataDirectory), secondWrappers);

    await assert.rejects(daemon.removeTargets(["beta"], { targets: { beta: {} } }), /preserve every target/iu);
    assert.deepEqual(await targetAliases(client), ["beta"]);
    await daemon.removeTargets(["beta"], { targets: {}, groups: [] });
    assert.deepEqual(await targetAliases(client), []);
    assert.deepEqual(await wrapperNames(dataDirectory), secondWrappers);
    assert.deepEqual(await loadRuntimeDescriptor(dataDirectory), runtimeBefore);
    daemon.updateMetadata({ targets: {}, groups: ["Empty"] });

    client.close();
    client = undefined;
    await daemon.stop();
    daemon = undefined;
    assert.deepEqual(await wrapperNames(dataDirectory), []);
  },
);

test(
  "daemon reload keeps the committed generation active when retiring the previous generation fails",
  { skip: process.platform !== "win32", timeout: 120_000 },
  async (t) => {
    const sandbox = await mkdtemp(
      path.join(os.tmpdir(), "agent-ssh-daemon-reload-dispose-"),
    );
    const fixture = await createDaemonFixture(sandbox);
    let daemon: RunningGatewayDaemon | undefined;
    let client: GatewayRpcClient | undefined;
    t.after(async () => {
      client?.close();
      await daemon?.stop().catch(() => undefined);
      await rm(sandbox, { recursive: true, force: true });
    });

    daemon = await startGatewayDaemon(fixture.firstGatewayConfig);
    client = await GatewayRpcClient.connect(fixture.dataDirectory, {
      name: "daemon-reload-dispose-test",
      version: "1.0.0",
    });
    const firstWrappers = await wrapperNames(fixture.dataDirectory);
    assert.equal(firstWrappers.length, 1);
    await replaceWrapperWithDirectory(
      fixture.dataDirectory,
      firstWrappers[0]!,
    );

    await assert.rejects(daemon.reload(fixture.secondGatewayConfig), (error) =>
      error instanceof GatewayReloadCommittedCleanupError &&
      error.code === "RELOAD_COMMITTED_CLEANUP_FAILED" &&
      error.committed &&
      isWrapperDisposalError(error.cause),
    );
    assert.deepEqual(await targetAliases(client), ["beta"]);
    const execution = await client.run({
      target: "beta",
      command: "hostname",
      timeoutMs: 2_000,
    });
    assert.notEqual(
      execution.termination,
      "spawn_error",
      "the committed generation executor must remain open",
    );
    const retainedWrappers = await wrapperNames(fixture.dataDirectory);
    assert.equal(retainedWrappers.length, 2);
    assert.equal(retainedWrappers.includes(firstWrappers[0]!), true);

    await assert.rejects(daemon.stop(), isWrapperDisposalError);
    daemon = undefined;
    await assert.rejects(client.request("system.ping", {}));
  },
);

test(
  "daemon stop aggregates generation cleanup failures and still releases runtime resources",
  { skip: process.platform !== "win32", timeout: 120_000 },
  async (t) => {
    const sandbox = await mkdtemp(
      path.join(os.tmpdir(), "agent-ssh-daemon-stop-dispose-"),
    );
    const fixture = await createDaemonFixture(sandbox);
    const syntheticAuditFailure = new Error("synthetic audit close failure");
    const originalAuditClose = AuditWriter.prototype.close;
    let auditCloseCalls = 0;
    t.mock.method(
      AuditWriter.prototype,
      "close",
      async function (this: AuditWriter): Promise<void> {
        auditCloseCalls += 1;
        await originalAuditClose.call(this);
        throw syntheticAuditFailure;
      },
    );

    let daemon: RunningGatewayDaemon | undefined;
    let client: GatewayRpcClient | undefined;
    t.after(async () => {
      client?.close();
      await daemon?.stop().catch(() => undefined);
      await rm(sandbox, { recursive: true, force: true });
    });

    daemon = await startGatewayDaemon(fixture.firstGatewayConfig);
    client = await GatewayRpcClient.connect(fixture.dataDirectory, {
      name: "daemon-stop-dispose-test",
      version: "1.0.0",
    });
    const wrappers = await wrapperNames(fixture.dataDirectory);
    assert.equal(wrappers.length, 1);
    await replaceWrapperWithDirectory(fixture.dataDirectory, wrappers[0]!);

    let shutdownFailure: unknown;
    await assert.rejects(daemon.stop(), (error: unknown) => {
      shutdownFailure = error;
      return true;
    });
    daemon = undefined;

    assert.ok(shutdownFailure instanceof AggregateError);
    assert.equal(shutdownFailure.errors.length, 2);
    assert.equal(auditCloseCalls, 1);
    assert.match(errorTreeText(shutdownFailure), /EPERM|EISDIR|operation not permitted/iu);
    assert.match(errorTreeText(shutdownFailure), /synthetic audit close failure/iu);
    await assert.rejects(client.request("system.ping", {}));
    client.close();
    client = undefined;
    await assert.rejects(
      loadRuntimeDescriptor(fixture.dataDirectory),
      (error: unknown) => (error as NodeJS.ErrnoException).code === "ENOENT",
    );

    const replacementLease = await createRuntimeDescriptor(
      fixture.dataDirectory,
    );
    await replacementLease.release();
  },
);

function renderSshConfig(alias: string): string {
  return [
    `Host ${alias}`,
    "    HostName 127.0.0.1",
    "    User reload-test",
    "",
  ].join("\n");
}

function gatewayConfiguration(
  dataDirectory: string,
  sshConfig: string,
  knownHosts: string,
  alias: string,
  inlineOutputBytes = 65_536,
) {
  const systemRoot = process.env.SystemRoot ?? String.raw`C:\Windows`;
  return {
    version: 1,
    runtime: {
      dataDirectory,
      inlineOutputBytes,
      maxStoredOutputBytes: 10_485_760,
      maxTotalRetainedOutputBytes: 104_857_600,
      maxAuditBytes: 104_857_600,
      maxRetainedOutputs: 1_024,
      outputTtlSeconds: 900,
      maxConcurrentExecutions: 2,
    },
    ssh: {
      executable: path.join(systemRoot, "System32", "OpenSSH", "ssh.exe"),
      configFile: sshConfig,
      knownHostsFile: knownHosts,
      connectTimeoutSeconds: 15,
    },
    targets: {
      [alias]: {
        description: `${alias} reload target`,
        sshAlias: `internal-${alias}`,
        platform: "linux",
        enabled: true,
        policy: {
          mode: "allow-list",
          allowedCommands: ["hostname"],
          maxTimeoutMs: 30_000,
        },
      },
    },
  };
}

async function targetAliases(client: GatewayRpcClient): Promise<string[]> {
  return (await client.request("target.list", {})).targets.map(
    (target) => target.alias,
  );
}

async function wrapperNames(dataDirectory: string): Promise<string[]> {
  return (await readdir(dataDirectory))
    .filter(
      (entry) =>
        entry.startsWith(".ssh-wrapper-") && entry.endsWith(".conf"),
    )
    .sort();
}

interface DaemonFixture {
  readonly dataDirectory: string;
  readonly firstGatewayConfig: string;
  readonly secondGatewayConfig: string;
}

async function createDaemonFixture(sandbox: string): Promise<DaemonFixture> {
  const dataDirectory = path.join(sandbox, "runtime");
  const knownHosts = path.join(sandbox, "known_hosts");
  const firstSshConfig = path.join(sandbox, "first_ssh_config");
  const secondSshConfig = path.join(sandbox, "second_ssh_config");
  const firstGatewayConfig = path.join(sandbox, "first_gateway.yaml");
  const secondGatewayConfig = path.join(sandbox, "second_gateway.yaml");
  await Promise.all([
    writeFile(knownHosts, "", { encoding: "utf8", mode: 0o600 }),
    writeFile(firstSshConfig, renderSshConfig("internal-alpha"), {
      encoding: "utf8",
      mode: 0o600,
    }),
    writeFile(secondSshConfig, renderSshConfig("internal-beta"), {
      encoding: "utf8",
      mode: 0o600,
    }),
  ]);
  await Promise.all([
    writeFile(
      firstGatewayConfig,
      stringify(
        gatewayConfiguration(
          dataDirectory,
          firstSshConfig,
          knownHosts,
          "alpha",
        ),
      ),
      "utf8",
    ),
    writeFile(
      secondGatewayConfig,
      stringify(
        gatewayConfiguration(
          dataDirectory,
          secondSshConfig,
          knownHosts,
          "beta",
        ),
      ),
      "utf8",
    ),
  ]);
  return { dataDirectory, firstGatewayConfig, secondGatewayConfig };
}

async function replaceWrapperWithDirectory(
  dataDirectory: string,
  wrapperName: string,
): Promise<void> {
  const wrapperPath = path.join(dataDirectory, wrapperName);
  await rm(wrapperPath, { force: true });
  await mkdir(wrapperPath);
}

function isWrapperDisposalError(error: unknown): boolean {
  return /EPERM|EISDIR|operation not permitted/iu.test(errorTreeText(error));
}

function errorTreeText(error: unknown): string {
  if (error instanceof AggregateError) {
    return [error.message, ...error.errors.map(errorTreeText)].join("\n");
  }
  if (error instanceof Error) {
    return `${error.name}: ${error.message}\n${errorTreeText(error.cause)}`;
  }
  return String(error ?? "");
}
