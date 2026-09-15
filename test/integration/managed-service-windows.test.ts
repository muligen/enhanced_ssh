import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  rmdir,
  unlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

import { parseConfigText } from "../../src/config/load-config.js";
import {
  startGatewayDaemon,
  type RunningGatewayDaemon,
} from "../../src/daemon/service.js";
import { GATEWAY_ERROR_CODES } from "../../src/shared/errors.js";
import type { TargetListResult } from "../../src/shared/protocol.js";
import {
  GatewayRpcClient,
  RpcRemoteError,
} from "../../src/shared/rpc-client.js";
import {
  createManagedSshService,
  managedSshFleetProfileSchema,
  ManagedSshError,
  type CurrentManagedSshProfile,
  type ManagedSshProfile,
  type ManagedSshFleetProfile,
  type TestUiConfigurationService,
} from "../../src/test-ui/managed.js";

const execFileAsync = promisify(execFile);
const ICACLS = String.raw`C:\Windows\System32\icacls.exe`;
const POWERSHELL = String.raw`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`;

test(
  "deferred daemon rejects real RPCs until activation",
  { skip: process.platform !== "win32", timeout: 240_000 },
  async (t) => {
    const sandbox = await mkdtemp(
      path.join(os.tmpdir(), "agent-ssh-deferred-integration-"),
    );
    const managedDirectory = path.join(sandbox, "managed");
    const knownHostsSource = path.join(sandbox, "known_hosts");
    let service: TestUiConfigurationService | undefined;
    let daemon: RunningGatewayDaemon | undefined;
    let client: GatewayRpcClient | undefined;
    t.after(async () => {
      client?.close();
      await daemon?.stop().catch(() => undefined);
      await service?.close().catch(() => undefined);
      await rm(sandbox, { recursive: true, force: true });
    });

    service = await createManagedSshService(managedDirectory);
    const generated = await service.generateKey();
    assert.notEqual(generated.generatedKey, undefined);
    const generatedKey = generated.generatedKey!;
    const hostKey = generatedKey.publicKey.trim().split(/\s+/u).slice(0, 2);
    assert.equal(hostKey.length, 2);
    await writeFile(
      knownHostsSource,
      `127.0.0.1 ${hostKey.join(" ")}\n`,
      { encoding: "utf8", mode: 0o600 },
    );

    await service.apply({
      target: {
        host: "127.0.0.1",
        port: 22,
        username: "agent_test",
        identityFile: generatedKey.privateKeyPath,
      },
      knownHostsFile: knownHostsSource,
      platform: "windows",
      policyMode: "allow-list",
      allowedCommands: ["hostname"],
    });
    const revision = await activeRevision(managedDirectory);
    const gatewayConfig = path.join(
      managedDirectory,
      "revisions",
      revision,
      "gateway.yaml",
    );
    await service.close();
    service = undefined;

    const orphanOwnerPid = await exitedChildProcessId();
    const orphanedWrapper =
      `.ssh-wrapper-${orphanOwnerPid}-${"f".repeat(32)}.conf`;
    await writeFile(
      path.join(managedDirectory, "runtime", orphanedWrapper),
      "orphaned wrapper fixture",
      "utf8",
    );
    service = await createManagedSshService(managedDirectory);
    assert.equal((await service.status()).state, "ready");
    assert.equal(
      (await sshWrapperNames(path.join(managedDirectory, "runtime"))).includes(
        orphanedWrapper,
      ),
      false,
    );
    await service.close();
    service = undefined;

    daemon = await startGatewayDaemon(gatewayConfig, {
      deferActivation: true,
    });
    client = await GatewayRpcClient.connect(
      path.join(managedDirectory, "runtime"),
      { name: "deferred-integration-test", version: "1.0.0" },
    );

    await assertDaemonNotActive(client.request("system.ping", {}));
    await assertDaemonNotActive(client.request("target.list", {}));
    await assertDaemonNotActive(
      client.request("exec.run", {
        target: "managed-ssh",
        command: "hostname",
        timeoutMs: 2_000,
      }),
    );

    daemon.activate();
    assert.equal((await client.request("system.ping", {})).ok, true);
    assert.equal(
      (await client.request("target.list", {})).targets[0]?.alias,
      "managed-ssh",
    );
    const execution = await client.run({
      target: "managed-ssh",
      command: "hostname",
      timeoutMs: 2_000,
    });
    assert.match(String(execution.requestId), /.+/u);
  },
);

test(
  "managed setup rejects a missing or unready Windows drive",
  { skip: process.platform !== "win32", timeout: 30_000 },
  async (t) => {
    const drive = await findUnavailableDriveLetter();
    if (drive === undefined) {
      t.skip("all Windows drive letters are present and ready");
      return;
    }

    await assert.rejects(
      createManagedSshService(`${drive}:\\managed`),
      (error: unknown) =>
        error instanceof ManagedSshError && error.code === "MANAGED_PATH_UNSAFE",
    );
  },
);

test(
  "current single profile migrates to fleet from revision-managed credentials",
  { skip: process.platform !== "win32", timeout: 240_000 },
  async (t) => {
    const sandbox = await mkdtemp(
      path.join(os.tmpdir(), "agent-ssh-managed-current-migration-"),
    );
    const managedDirectory = path.join(sandbox, "managed");
    const knownHostsSource = path.join(sandbox, "known_hosts");
    let service: TestUiConfigurationService | undefined;
    t.after(async () => {
      await service?.close().catch(() => undefined);
      await rm(sandbox, { recursive: true, force: true });
    });

    service = await createManagedSshService(managedDirectory);
    const generated = await service.generateKey();
    const generatedKey = generated.generatedKey!;
    const hostKey = generatedKey.publicKey.trim().split(/\s+/u).slice(0, 2);
    await writeFile(
      knownHostsSource,
      `127.0.0.1 ${hostKey.join(" ")}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
    const currentProfile: CurrentManagedSshProfile = {
      target: {
        host: "127.0.0.1",
        port: 22,
        username: "agent_test",
        identityFile: generatedKey.privateKeyPath,
      },
      knownHostsFile: knownHostsSource,
      platform: "windows",
      policyMode: "full-access",
      allowedCommands: [],
    };
    await service.apply(currentProfile);
    const revision = await activeRevision(managedDirectory);
    const generatedGatewaySource = await readFile(
      path.join(
        managedDirectory,
        "revisions",
        revision,
        "gateway.yaml",
      ),
      "utf8",
    );
    assert.doesNotMatch(generatedGatewaySource, /^    transfer:/mu);
    await service.close();
    service = undefined;

    const revisionDirectory = path.join(
      managedDirectory,
      "revisions",
      revision,
    );
    await convertFleetRevisionToSingle(
      revisionDirectory,
      currentProfile,
      false,
    );
    await Promise.all([
      unlink(generatedKey.privateKeyPath),
      unlink(`${generatedKey.privateKeyPath}.pub`),
      unlink(knownHostsSource),
    ]);

    service = await createManagedSshService(managedDirectory);
    const status = await service.fleetStatus();
    assert.equal(status.state, "ready");
    assert.notEqual(status.revision, revision, JSON.stringify(status));
    assert.equal(await rollbackRevision(managedDirectory), revision);
    const migrated = managedSshFleetProfileSchema.parse(status.profile);
    const expectedFleet: ManagedSshFleetProfile = migrated;
    const target = expectedFleet.targets["managed-ssh"]!;
    assert.equal(target.platform, "windows");
    assert.equal(target.policyMode, "full-access");
    assert.deepEqual(target.allowedCommands, []);
    assert.ok(target.target.keyId);
    assert.match(target.target.keyId, /^k-[a-f0-9]{32}$/u);
    assert.equal(
      target.knownHostsFile,
      path.join(
        managedDirectory,
        "revisions",
        status.revision!,
        "credentials",
        "managed-ssh",
        "known_hosts",
      ),
    );
    const gateway = await service.gatewayFactory();
    try {
      assert.deepEqual(await listTargetsWithoutIds(gateway), {
        targets: [
          {
            alias: "managed-ssh",
            connectionMode: "openssh",
            description: "agent_test@127.0.0.1:22",
            enabled: true,
            platform: "windows",
            policyMode: "full-access",
            transferMode: "bidirectional",
            transferScope: "all",
            transferRoots: [],
            maxTimeoutMs: 30_000,
          },
        ],
      });
    } finally {
      gateway.close();
    }
    const migratedRevision = status.revision!;
    const migratedKeyId = target.target.keyId;
    await service.close();
    service = await createManagedSshService(managedDirectory);
    const reopened = await service.fleetStatus();
    assert.equal(reopened.revision, migratedRevision);
    assert.equal(
      reopened.profile?.targets["managed-ssh"]?.target.keyId,
      migratedKeyId,
    );
  },
);

test(
  "stored fleet v2 migrates keys once without losing target identity or policy",
  { skip: process.platform !== "win32", timeout: 240_000 },
  async (t) => {
    const sandbox = await mkdtemp(
      path.join(os.tmpdir(), "agent-ssh-managed-fleet-v2-migration-"),
    );
    const managedDirectory = path.join(sandbox, "managed");
    const knownHostsSource = path.join(sandbox, "known_hosts");
    let service: TestUiConfigurationService | undefined;
    t.after(async () => {
      await service?.close().catch(() => undefined);
      await rm(sandbox, { recursive: true, force: true });
    });

    service = await createManagedSshService(managedDirectory);
    const generatedKey = (await service.generateKey()).generatedKey!;
    const publicFields = generatedKey.publicKey.trim().split(/\s+/u).slice(0, 2);
    await writeFile(
      knownHostsSource,
      `127.0.0.1 ${publicFields.join(" ")}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
    const keyId = await importGeneratedKey(
      service,
      generatedKey.privateKeyPath,
      "legacy shared key",
    );
    const endpoint = {
      host: "127.0.0.1",
      port: 22,
      username: "agent_test",
      keyId,
    };
    const original = await service.applyFleet({
      version: 3,
      targets: {
        xiaoxu_deploy: {
          targetId: "t-dc1d6cb226567e5ea355527c1526e104",
          previousAliases: ["managed-ssh"],
          description: "Xiaoxu deploy",
          enabled: true,
          target: endpoint,
          knownHostsFile: knownHostsSource,
          platform: "windows",
          policyMode: "full-access",
          allowedCommands: [],
          maxTimeoutMs: 3_600_000,
        },
        shared_key_host: {
          description: "Shared key host",
          enabled: false,
          target: endpoint,
          knownHostsFile: knownHostsSource,
          platform: "linux",
          policyMode: "allow-list",
          allowedCommands: ["hostname"],
          maxTimeoutMs: 30_000,
        },
      },
    });
    const legacyRevision = original.revision!;
    await service.close();
    service = undefined;
    await convertFleetRevisionToV2(managedDirectory, legacyRevision);
    await rm(path.join(managedDirectory, "keys"), {
      recursive: true,
      force: true,
    });

    const keyDirectory = path.join(managedDirectory, "keys");
    await mkdir(keyDirectory);
    await writeFile(path.join(keyDirectory, "manifest.json"), "not-json\n", "utf8");
    service = await createManagedSshService(managedDirectory);
    const fallback = await service.fleetStatus();
    assert.equal(fallback.state, "ready");
    assert.equal(fallback.configured, true);
    assert.equal(fallback.revision, legacyRevision);
    assert.equal(fallback.profile?.targets.xiaoxu_deploy?.targetId,
      "t-dc1d6cb226567e5ea355527c1526e104");
    assert.equal(fallback.keys.length, 0);
    assert.equal(fallback.keyError?.code, "KEY_STORAGE_INVALID");
    await service.close();
    service = undefined;
    await rm(keyDirectory, { recursive: true, force: true });

    service = await createManagedSshService(managedDirectory);
    const migrated = await service.fleetStatus();
    assert.equal(migrated.state, "ready");
    assert.notEqual(migrated.revision, legacyRevision);
    assert.equal(await rollbackRevision(managedDirectory), legacyRevision);
    assert.equal(migrated.keys.length, 1);
    const migratedTarget = migrated.profile?.targets.xiaoxu_deploy;
    assert.equal(
      migratedTarget?.targetId,
      "t-dc1d6cb226567e5ea355527c1526e104",
    );
    assert.deepEqual(migratedTarget?.previousAliases, ["managed-ssh"]);
    assert.equal(migratedTarget?.policyMode, "full-access");
    assert.equal(migratedTarget?.target.host, "127.0.0.1");
    assert.equal(
      migrated.profile?.targets.shared_key_host?.target.keyId,
      migratedTarget?.target.keyId,
    );

    const migratedRevision = migrated.revision!;
    const migratedKeyId = migrated.keys[0]!.keyId;
    await service.close();
    service = await createManagedSshService(managedDirectory);
    const reopened = await service.fleetStatus();
    assert.equal(reopened.revision, migratedRevision);
    assert.equal(reopened.keys[0]?.keyId, migratedKeyId);
  },
);

test(
  "managed keys remain protected by retained and untrusted revisions",
  { skip: process.platform !== "win32", timeout: 240_000 },
  async (t) => {
    const sandbox = await mkdtemp(
      path.join(os.tmpdir(), "agent-ssh-managed-key-references-"),
    );
    const managedDirectory = path.join(sandbox, "managed");
    const knownHostsSource = path.join(sandbox, "known_hosts");
    let service: TestUiConfigurationService | undefined;
    t.after(async () => {
      await service?.close().catch(() => undefined);
      await rm(sandbox, { recursive: true, force: true });
    });

    service = await createManagedSshService(managedDirectory);
    const initialKeys = await service.generateManagedKey(
      "initial key",
      (await service.keyStatus()).keyRevision,
    );
    const initialKey = initialKeys.keys.find(
      (candidate) => candidate.label === "initial key",
    )!;
    const generatedRotation = await service.generateManagedKey(
      "rotation key",
      initialKeys.keyRevision,
    );
    const rotationKey = generatedRotation.keys.find(
      (candidate) => candidate.label === "rotation key",
    )!;
    const hostKey = initialKey.publicKey.trim().split(/\s+/u).slice(0, 2);
    await writeFile(
      knownHostsSource,
      `127.0.0.1 ${hostKey.join(" ")}\n`,
      { encoding: "utf8", mode: 0o600 },
    );

    const original = await service.applyFleet({
      version: 3,
      targets: {
        protected: {
          description: "Retained key reference",
          enabled: true,
          target: {
            host: "127.0.0.1",
            port: 22,
            username: "agent_test",
            keyId: initialKey.keyId,
          },
          knownHostsFile: knownHostsSource,
          platform: "linux",
          policyMode: "allow-list",
          allowedCommands: ["hostname"],
          maxTimeoutMs: 30_000,
        },
      },
    });
    const rotatedProfile = structuredClone(original.profile!);
    rotatedProfile.targets.protected!.target.keyId = rotationKey.keyId;
    const firstRotation = await service.applyFleet(
      rotatedProfile,
      original.revision,
    );
    await assert.rejects(
      service.removeManagedKey(initialKey.keyId, generatedRotation.keyRevision),
      (error: unknown) =>
        error instanceof ManagedSshError && error.code === "KEY_IN_USE",
    );
    rotatedProfile.targets.protected!.description = "Rotation committed";
    const secondRotation = await service.applyFleet(
      rotatedProfile,
      firstRotation.revision,
    );
    const removed = await service.removeManagedKey(
      initialKey.keyId,
      generatedRotation.keyRevision,
    );
    assert.equal(
      removed.keys.some((candidate) => candidate.keyId === initialKey.keyId),
      false,
    );
    await service.close();
    service = await createManagedSshService(managedDirectory);
    const afterRemoval = await service.fleetStatus();
    assert.equal(afterRemoval.revision, secondRotation.revision);
    assert.equal(afterRemoval.keys.length, 1);
    assert.equal(afterRemoval.keys[0]?.keyId, rotationKey.keyId);
    await service.close();
    service = undefined;
    await writeFile(
      path.join(managedDirectory, "active.json"),
      "{\"version\":1,\"revision\":\"invalid\"}\n",
      "utf8",
    );
    service = await createManagedSshService(managedDirectory);
    const untrusted = await service.fleetStatus();
    assert.equal(untrusted.state, "error");
    await assert.rejects(
      service.removeManagedKey(rotationKey.keyId, untrusted.keyRevision),
      (error: unknown) =>
        error instanceof ManagedSshError &&
        error.code === "KEY_REFERENCE_CHECK_FAILED",
    );
  },
);

test(
  "fleet revisions reload multiple targets and retain managed credential sources",
  { skip: process.platform !== "win32", timeout: 240_000 },
  async (t) => {
    const sandbox = await mkdtemp(
      path.join(os.tmpdir(), "agent-ssh-managed-fleet-"),
    );
    const managedDirectory = path.join(sandbox, "managed");
    const knownHostsSource = path.join(sandbox, "known_hosts");
    let service: TestUiConfigurationService | undefined;
    let gateway: Awaited<ReturnType<TestUiConfigurationService["gatewayFactory"]>> | undefined;
    t.after(async () => {
      gateway?.close();
      await service?.close().catch(() => undefined);
      await rm(sandbox, { recursive: true, force: true });
    });

    service = await createManagedSshService(managedDirectory);
    const generatedKey = (await service.generateKey()).generatedKey!;
    const managedKeyId = await importGeneratedKey(
      service,
      generatedKey.privateKeyPath,
      "fleet shared key",
    );
    const hostKey = generatedKey.publicKey.trim().split(/\s+/u).slice(0, 2);
    const knownHostsBody = `127.0.0.1 ${hostKey.join(" ")}\n`;
    const compatibilityLocalRoot = path.join(
      sandbox,
      "legacy-transfer-root",
    );
    await mkdir(compatibilityLocalRoot);
    await writeFile(knownHostsSource, knownHostsBody, {
      encoding: "utf8",
      mode: 0o600,
    });
    const endpoint = {
      host: "127.0.0.1",
      port: 22,
      username: "agent_test",
      keyId: managedKeyId,
    };
    const firstProfile: ManagedSshFleetProfile = {
      version: 3,
      targets: {
        "linux-a": {
          description: "Linux A",
          group: "A 组",
          enabled: true,
          target: endpoint,
          knownHostsFile: knownHostsSource,
          platform: "linux",
          policyMode: "allow-list",
          allowedCommands: ["hostname", "custom status --json"],
          maxTimeoutMs: 40_000,
        },
        "windows-b": {
          description: "Windows B",
          group: "B 组",
          enabled: false,
          target: endpoint,
          knownHostsFile: knownHostsSource,
          platform: "windows",
          policyMode: "full-access",
          allowedCommands: [],
          maxTimeoutMs: 90_000,
          transferMode: "deny",
          localRootPath: compatibilityLocalRoot,
          remoteRoots: ["D:/legacy-transfer-root"],
          maxTransferTimeoutMs: 654_321,
        },
      },
    };
    const firstStatus = await service.applyFleet(firstProfile);
    const firstRevision = firstStatus.revision!;
    assert.equal(firstStatus.state, "ready");
    assert.equal(firstStatus.configured, true);
    const generatedGatewayPath = path.join(
      managedDirectory,
      "revisions",
      firstRevision,
      "gateway.yaml",
    );
    const generatedGatewaySource = await readFile(generatedGatewayPath, "utf8");
    const generatedGateway = parseConfigText(generatedGatewaySource);
    assert.equal(generatedGateway.targets["linux-a"]?.group, "A 组");
    assert.equal(generatedGateway.targets["windows-b"]?.group, "B 组");
    assert.equal(
      generatedGateway.targets["windows-b"]?.policy.mode,
      "full-access",
    );
    assert.doesNotMatch(generatedGatewaySource, /^    transfer:/mu);
    const legacyGatewaySource = generatedGatewaySource.replace(
      "inlineOutputBytes: 8192",
      "inlineOutputBytes: 65536",
    );
    assert.notEqual(legacyGatewaySource, generatedGatewaySource);
    await writeFile(generatedGatewayPath, legacyGatewaySource, "utf8");
    await service.close();
    service = undefined;
    service = await createManagedSshService(managedDirectory);
    const reopened = await service.fleetStatus();
    assert.equal(reopened.state, "ready");
    assert.equal(reopened.revision, firstRevision);
    assert.equal(reopened.profile?.targets["linux-a"]?.group, "A 组");
    assert.equal(reopened.profile?.targets["windows-b"]?.group, "B 组");
    assert.equal(
      reopened.profile?.targets["windows-b"]?.maxTransferTimeoutMs,
      654_321,
    );
    assert.equal(
      reopened.profile?.targets["windows-b"]?.transferMode,
      "deny",
    );
    assert.equal(
      reopened.profile?.targets["windows-b"]?.localRootPath,
      compatibilityLocalRoot,
    );
    assert.deepEqual(
      reopened.profile?.targets["windows-b"]?.remoteRoots,
      ["D:/legacy-transfer-root"],
    );
    assert.equal(
      await readFile(
        path.join(
          managedDirectory,
          "revisions",
          firstRevision,
          "known_hosts",
        ),
        "utf8",
      ),
      knownHostsBody,
    );

    gateway = await service.gatewayFactory();
    assert.deepEqual(await listTargetsWithoutIds(gateway), {
      targets: [
        {
          alias: "linux-a",
          description: "Linux A",
          group: "A 组",
          enabled: true,
          platform: "linux",
          connectionMode: "openssh",
          policyMode: "allow-list",
          transferMode: "deny",
          transferScope: "restricted",
          transferRoots: [],
          maxTimeoutMs: 40_000,
          maxTransferTimeoutMs: 3_600_000,
        },
        {
          alias: "windows-b",
          description: "Windows B",
          group: "B 组",
          enabled: false,
          platform: "windows",
          connectionMode: "openssh",
          policyMode: "full-access",
          transferMode: "bidirectional",
          transferScope: "all",
          transferRoots: [],
          maxTimeoutMs: 90_000,
          maxTransferTimeoutMs: 3_600_000,
        },
      ],
    });

    await Promise.all([
      unlink(generatedKey.privateKeyPath),
      unlink(`${generatedKey.privateKeyPath}.pub`),
      unlink(knownHostsSource),
    ]);
    const retainedTarget = firstStatus.profile!.targets["linux-a"]!;
    const secondProfile: ManagedSshFleetProfile = {
      version: 3,
      targets: {
        "linux-a": {
          ...retainedTarget,
          description: "Linux A retained",
          policyMode: "deny",
          allowedCommands: [],
        },
      },
    };
    await assert.rejects(
      service.applyFleet(
        secondProfile,
        `r-stale-${"b".repeat(32)}`,
      ),
      (error: unknown) =>
        error instanceof ManagedSshError &&
        error.code === "CONFIG_CONFLICT" &&
        error.status === 409,
    );
    assert.equal(await activeRevision(managedDirectory), firstRevision);
    const runtimeDirectory = path.join(managedDirectory, "runtime");
    const firstGenerationWrappers = await sshWrapperNames(runtimeDirectory);
    assert.equal(firstGenerationWrappers.length, 1);
    await replaceSshWrapperWithDirectory(
      runtimeDirectory,
      firstGenerationWrappers[0]!,
    );
    const secondStatus = await service.applyFleet(
      secondProfile,
      firstRevision,
    );
    const secondRevision = secondStatus.revision!;
    assert.notEqual(secondRevision, firstRevision);
    assert.equal(secondStatus.state, "ready");
    assert.equal(secondStatus.profile?.targets["linux-a"]?.group, "A 组");
    assert.equal(secondStatus.error?.code, "CONFIG_RETENTION_FAILED");
    assert.equal(
      secondStatus.profile?.targets["linux-a"]?.description,
      "Linux A retained",
    );
    assert.equal(await activeRevision(managedDirectory), secondRevision);
    assert.equal(
      (await revisionDirectories(managedDirectory)).includes(secondRevision),
      true,
    );
    const committedStatus = await service.fleetStatus();
    assert.equal(committedStatus.revision, secondRevision);
    assert.equal(committedStatus.error?.code, "CONFIG_RETENTION_FAILED");
    assert.equal(await rollbackRevision(managedDirectory), firstRevision);
    assert.deepEqual(await listTargetsWithoutIds(gateway), {
      targets: [
        {
          alias: "linux-a",
          description: "Linux A retained",
          group: "A 组",
          enabled: true,
          platform: "linux",
          connectionMode: "openssh",
          policyMode: "deny",
          transferMode: "deny",
          transferScope: "restricted",
          transferRoots: [],
          maxTimeoutMs: 40_000,
          maxTransferTimeoutMs: 3_600_000,
        },
      ],
    });

    await rmdir(
      path.join(runtimeDirectory, firstGenerationWrappers[0]!),
    );

    const emptyStatus = await service.applyFleet(
      { version: 3, targets: {} },
      secondRevision,
    );
    assert.equal(emptyStatus.state, "ready");
    assert.equal(emptyStatus.configured, false);
    assert.equal(emptyStatus.error, undefined);
    assert.equal(await activeRevision(managedDirectory), emptyStatus.revision);
    assert.deepEqual(await listTargetsWithoutIds(gateway), { targets: [] });
  },
);

test(
  "managed setup recovers a missing pointer and falls back from an invalid active revision",
  { skip: process.platform !== "win32", timeout: 240_000 },
  async (t) => {
    const sandbox = await mkdtemp(
      path.join(os.tmpdir(), "agent-ssh-managed-recovery-"),
    );
    const managedDirectory = path.join(sandbox, "managed");
    const knownHostsSource = path.join(sandbox, "known_hosts");
    let service: TestUiConfigurationService | undefined;
    t.after(async () => {
      await service?.close().catch(() => undefined);
      await rm(sandbox, { recursive: true, force: true });
    });

    service = await createManagedSshService(managedDirectory);
    const generatedKey = (await service.generateKey()).generatedKey!;
    const managedKeyId = await importGeneratedKey(
      service,
      generatedKey.privateKeyPath,
      "recovery key",
    );
    const hostKey = generatedKey.publicKey.trim().split(/\s+/u).slice(0, 2);
    await writeFile(
      knownHostsSource,
      `127.0.0.1 ${hostKey.join(" ")}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
    const firstStatus = await service.applyFleet({
      version: 3,
      targets: {
        recovery: {
          description: "Recovery v1",
          enabled: true,
          target: {
            host: "127.0.0.1",
            port: 22,
            username: "agent_test",
            keyId: managedKeyId,
          },
          knownHostsFile: knownHostsSource,
          platform: "windows",
          policyMode: "allow-list",
          allowedCommands: ["hostname"],
          maxTimeoutMs: 30_000,
        },
      },
    });
    const firstRevision = firstStatus.revision!;
    await delay(5);
    const secondStatus = await service.applyFleet(
      {
        version: 3,
        targets: {
          recovery: {
            ...firstStatus.profile!.targets.recovery!,
            description: "Recovery v2",
          },
        },
      },
      firstRevision,
    );
    const secondRevision = secondStatus.revision!;
    assert.notEqual(secondRevision, firstRevision);
    await service.close();
    service = undefined;

    const activePointerPath = path.join(managedDirectory, "active.json");
    const invalidRevision = `r-zzzzzzzz-${"f".repeat(32)}`;
    await cp(
      path.join(managedDirectory, "revisions", secondRevision),
      path.join(managedDirectory, "revisions", invalidRevision),
      { recursive: true },
    );
    await unlink(activePointerPath);
    service = await createManagedSshService(managedDirectory);
    const recovered = await service.fleetStatus();
    assert.equal(recovered.state, "ready");
    assert.equal(recovered.revision, secondRevision);
    assert.equal(
      recovered.profile?.targets.recovery?.description,
      "Recovery v2",
    );
    assert.equal(await rollbackRevision(managedDirectory), firstRevision);
    const recoveredPointer = JSON.parse(
      await readFile(activePointerPath, "utf8"),
    ) as Record<string, unknown>;
    assert.deepEqual(recoveredPointer.quarantinedRevisions, [invalidRevision]);
    assert.deepEqual(
      await revisionDirectories(managedDirectory),
      [firstRevision, secondRevision, invalidRevision].sort(),
    );
    await service.close();
    service = undefined;

    service = await createManagedSshService(managedDirectory);
    const reopenedRecovery = await service.fleetStatus();
    assert.equal(reopenedRecovery.state, "ready");
    assert.equal(reopenedRecovery.revision, secondRevision);
    assert.deepEqual(
      await revisionDirectories(managedDirectory),
      [firstRevision, secondRevision, invalidRevision].sort(),
    );
    await service.close();
    service = undefined;

    const firstProfilePath = path.join(
      managedDirectory,
      "revisions",
      firstRevision,
      "profile.json",
    );
    const secondProfilePath = path.join(
      managedDirectory,
      "revisions",
      secondRevision,
      "profile.json",
    );
    const [firstProfileSource, pointerBeforeFailure] = await Promise.all([
      readFile(firstProfilePath, "utf8"),
      readFile(activePointerPath, "utf8"),
    ]);
    await Promise.all([
      writeFile(firstProfilePath, "{}\n", "utf8"),
      writeFile(secondProfilePath, "{}\n", "utf8"),
    ]);
    service = await createManagedSshService(managedDirectory);
    const unrecoverable = await service.fleetStatus();
    assert.equal(unrecoverable.state, "error");
    assert.equal(await readFile(activePointerPath, "utf8"), pointerBeforeFailure);
    assert.deepEqual(
      await revisionDirectories(managedDirectory),
      [firstRevision, secondRevision, invalidRevision].sort(),
    );
    await service.close();
    service = undefined;

    await writeFile(firstProfilePath, firstProfileSource, "utf8");
    service = await createManagedSshService(managedDirectory);
    const rolledBack = await service.fleetStatus();
    assert.equal(rolledBack.state, "ready");
    assert.equal(rolledBack.revision, firstRevision);
    assert.equal(
      rolledBack.profile?.targets.recovery?.description,
      "Recovery v1",
    );
    const restoredPointer = JSON.parse(
      await readFile(activePointerPath, "utf8"),
    ) as Record<string, unknown>;
    assert.equal(restoredPointer.revision, firstRevision);
    assert.equal(restoredPointer.previousRevision, secondRevision);
    assert.deepEqual(restoredPointer.quarantinedRevisions, [invalidRevision]);
    assert.deepEqual(
      await revisionDirectories(managedDirectory),
      [firstRevision, secondRevision, invalidRevision].sort(),
    );

    await service.close();
    service = undefined;
    service = await createManagedSshService(managedDirectory);
    const reopenedRollback = await service.fleetStatus();
    assert.equal(reopenedRollback.state, "ready");
    assert.equal(reopenedRollback.revision, firstRevision);
    assert.deepEqual(
      await revisionDirectories(managedDirectory),
      [firstRevision, secondRevision, invalidRevision].sort(),
    );

    const replacement = await service.applyFleet(
      {
        version: 3,
        targets: {
          recovery: {
            ...reopenedRollback.profile!.targets.recovery!,
            description: "Recovery saved",
          },
        },
      },
      firstRevision,
    );
    const replacementRevision = replacement.revision!;
    const replacementPointer = JSON.parse(
      await readFile(activePointerPath, "utf8"),
    ) as Record<string, unknown>;
    assert.equal(replacementPointer.revision, replacementRevision);
    assert.equal(replacementPointer.previousRevision, firstRevision);
    assert.equal(Object.hasOwn(replacementPointer, "quarantinedRevisions"), false);
    assert.deepEqual(
      await revisionDirectories(managedDirectory),
      [firstRevision, replacementRevision].sort(),
    );
  },
);

test(
  "managed setup imports credentials and reopens an immutable active revision",
  { skip: process.platform !== "win32", timeout: 240_000 },
  async (t) => {
    const sandbox = await mkdtemp(
      path.join(os.tmpdir(), "agent-ssh-managed-integration-"),
    );
    const managedDirectory = path.join(sandbox, "managed");
    const knownHostsSource = path.join(sandbox, "known_hosts");
    let service: TestUiConfigurationService | undefined;
    t.after(async () => {
      await service?.close().catch(() => undefined);
      await rm(sandbox, { recursive: true, force: true });
    });

    service = await createManagedSshService(managedDirectory);
    const generated = await service.generateKey();
    assert.equal(generated.state, "unconfigured");
    assert.notEqual(generated.generatedKey, undefined);
    const generatedKey = generated.generatedKey!;
    const hostKey = generatedKey.publicKey.trim().split(/\s+/u).slice(0, 2);
    assert.equal(hostKey.length, 2);

    const generatedPublicKey = `${generatedKey.privateKeyPath}.pub`;
    await t.test("re-hardens an existing generated key pair before reading it", async () => {
      await Promise.all([
        grantEveryoneFullControl(generatedKey.privateKeyPath),
        grantEveryoneFullControl(generatedPublicKey),
      ]);
      assert.equal(
        (await readAcl(generatedKey.privateKeyPath)).everyoneAllowed,
        true,
      );
      assert.equal(
        (await readAcl(generatedPublicKey)).everyoneAllowed,
        true,
      );

      const rehardened = await service!.status();
      assert.notEqual(rehardened.generatedKey, undefined);
      await Promise.all([
        assertHardenedAcl(generatedKey.privateKeyPath),
        assertHardenedAcl(generatedPublicKey),
      ]);
    });

    await writeFile(
      knownHostsSource,
      `127.0.0.1 ${hostKey.join(" ")}\n`,
      { encoding: "utf8", mode: 0o600 },
    );

    const legacyProfile: ManagedSshProfile = {
      target: {
        host: "127.0.0.1",
        port: 22,
        username: "agent_test",
        identityFile: generatedKey.privateKeyPath,
      },
      knownHostsFile: knownHostsSource,
      allowedCommands: ["hostname"],
    };
    const firstProfile: CurrentManagedSshProfile = {
      ...legacyProfile,
      platform: "linux",
      policyMode: "allow-list",
    };
    const firstStatus = await service.apply(firstProfile);
    assert.equal(firstStatus.state, "ready");
    assert.equal(firstStatus.configured, true);

    const gateway = await service.gatewayFactory();
    try {
      assert.equal((await gateway.ping()).ok, true);
      assert.deepEqual(await listTargetsWithoutIds(gateway), {
        targets: [
          {
            alias: "managed-ssh",
            description: "agent_test@127.0.0.1:22",
            enabled: true,
            platform: "linux",
            connectionMode: "openssh",
            policyMode: "allow-list",
            transferMode: "deny",
            transferScope: "restricted",
            transferRoots: [],
            maxTimeoutMs: 30_000,
          },
        ],
      });
    } finally {
      gateway.close();
    }

    await assert.rejects(
      createManagedSshService(managedDirectory),
      (error: unknown) =>
        error instanceof ManagedSshError && error.code === "CONFIG_IN_USE",
    );

    const firstRevision = await activeRevision(managedDirectory);
    await assertManagedCopies(
      managedDirectory,
      firstRevision,
      generatedKey.privateKeyPath,
      knownHostsSource,
    );

    await service.close();
    const firstRevisionDirectory = path.join(
      managedDirectory,
      "revisions",
      firstRevision,
    );
    await convertFleetRevisionToSingle(
      firstRevisionDirectory,
      legacyProfile,
      true,
    );
    service = await createManagedSshService(managedDirectory);
    const legacyReopened = await service.status();
    assert.equal(legacyReopened.state, "unconfigured");
    assert.equal(legacyReopened.configured, true);
    assert.equal("platform" in legacyReopened.profile!, false);
    assert.equal("policyMode" in legacyReopened.profile!, false);

    const baseProfile: CurrentManagedSshProfile = {
      ...legacyProfile,
      platform: "windows",
      policyMode: "allow-list",
    };

    const secondStatus = await service.apply({
      ...baseProfile,
      allowedCommands: ["hostname", "whoami"],
    });
    assert.equal(secondStatus.state, "ready");
    const secondRevision = await activeRevision(managedDirectory);
    assert.notEqual(secondRevision, firstRevision);
    assert.equal(await rollbackRevision(managedDirectory), firstRevision);
    await assertManagedCopies(
      managedDirectory,
      secondRevision,
      generatedKey.privateKeyPath,
      knownHostsSource,
    );

    const thirdStatus = await service.apply({
      ...baseProfile,
      allowedCommands: [
        "hostname",
        "whoami",
        "Get-Culture | Format-List Name, DisplayName",
      ],
    });
    assert.equal(thirdStatus.state, "ready");
    const thirdRevision = await activeRevision(managedDirectory);
    assert.notEqual(thirdRevision, secondRevision);
    assert.equal(await rollbackRevision(managedDirectory), secondRevision);
    await t.test("retains only the active and rollback revisions", async () => {
      assert.deepEqual(
        await revisionDirectories(managedDirectory),
        [secondRevision, thirdRevision].sort(),
      );
    });

    await service.close();
    service = undefined;

    const revisionsDirectory = path.join(managedDirectory, "revisions");
    const stagingRevision = path.join(
      revisionsDirectory,
      `.staging-r-orphan-${"e".repeat(32)}`,
    );
    const orphanRevision = path.join(
      revisionsDirectory,
      `r-orphan-${"f".repeat(32)}`,
    );
    await Promise.all([
      mkdir(path.join(stagingRevision, "credentials"), { recursive: true }),
      mkdir(path.join(orphanRevision, "credentials"), { recursive: true }),
    ]);
    await Promise.all([
      writeFile(path.join(stagingRevision, "known_hosts"), "staging\n", "utf8"),
      writeFile(path.join(orphanRevision, "known_hosts"), "orphan\n", "utf8"),
    ]);

    service = await createManagedSshService(managedDirectory);
    const reopened = await service.status();
    assert.equal(reopened.state, "ready");
    assert.deepEqual(reopened.profile?.allowedCommands, [
      "hostname",
      "whoami",
      "Get-Culture | Format-List Name, DisplayName",
    ]);
    assert.equal(reopened.profile !== undefined && "platform" in reopened.profile, true);
    assert.equal(reopened.profile !== undefined && "policyMode" in reopened.profile, true);
    await t.test(
      "removes staging and orphan revisions without deleting active or rollback",
      async () => {
        assert.deepEqual(
          await revisionDirectories(managedDirectory),
          [secondRevision, thirdRevision].sort(),
        );
      },
    );
  },
);

interface AclSnapshot {
  readonly protected: boolean;
  readonly everyoneAllowed: boolean;
}

async function assertDaemonNotActive(request: Promise<unknown>): Promise<void> {
  await assert.rejects(request, (error: unknown) => {
    assert.ok(error instanceof RpcRemoteError);
    assert.equal(error.rpcCode, -32011);
    assert.deepEqual(error.data, {
      gatewayCode: GATEWAY_ERROR_CODES.daemonNotActive,
    });
    return true;
  });
}

async function findUnavailableDriveLetter(): Promise<string | undefined> {
  const script = String.raw`
$ErrorActionPreference = "Stop"
$drives = @{}
foreach ($drive in [System.IO.DriveInfo]::GetDrives()) {
  $drives[$drive.Name.Substring(0, 1).ToUpperInvariant()] = $drive.IsReady
}
foreach ($code in 90..65) {
  $letter = ([char]$code).ToString()
  if (-not $drives.ContainsKey($letter) -or -not $drives[$letter]) {
    Write-Output $letter
    break
  }
}
`;
  const { stdout } = await execFileAsync(
    POWERSHELL,
    ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
    { encoding: "utf8", windowsHide: true, timeout: 10_000 },
  );
  const drive = stdout.trim();
  if (drive.length === 0) {
    return undefined;
  }
  assert.match(drive, /^[A-Z]$/u);
  return drive;
}

async function grantEveryoneFullControl(targetPath: string): Promise<void> {
  await execFileAsync(ICACLS, [targetPath, "/grant", "*S-1-1-0:F"], {
    windowsHide: true,
    timeout: 10_000,
  });
}

async function assertHardenedAcl(targetPath: string): Promise<void> {
  const acl = await readAcl(targetPath);
  assert.equal(acl.protected, true, `${targetPath} must disable ACL inheritance`);
  assert.equal(
    acl.everyoneAllowed,
    false,
    `${targetPath} must remove the Everyone allow ACE`,
  );
}

async function readAcl(targetPath: string): Promise<AclSnapshot> {
  const script = String.raw`
$ErrorActionPreference = "Stop"
$acl = Get-Acl -LiteralPath ([Environment]::GetEnvironmentVariable("AGENT_SSH_MANAGED_ACL_TARGET", "Process"))
$everyoneAllowed = @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | Where-Object {
  $_.IdentityReference.Value -eq "S-1-1-0" -and $_.AccessControlType.ToString() -eq "Allow"
}).Count -gt 0
[ordered]@{
  protected = $acl.AreAccessRulesProtected
  everyoneAllowed = $everyoneAllowed
} | ConvertTo-Json -Compress
`;
  const { stdout } = await execFileAsync(
    POWERSHELL,
    ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
    {
      encoding: "utf8",
      env: { ...process.env, AGENT_SSH_MANAGED_ACL_TARGET: targetPath },
      windowsHide: true,
      timeout: 10_000,
    },
  );
  return JSON.parse(stdout) as AclSnapshot;
}

async function activeRevision(managedDirectory: string): Promise<string> {
  const raw = await readFile(path.join(managedDirectory, "active.json"), "utf8");
  const value = JSON.parse(raw) as unknown;
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  const revision = (value as Record<string, unknown>).revision;
  assert.equal(typeof revision, "string");
  assert.match(revision as string, /^r-[a-z0-9]+-[a-f0-9]{32}$/u);
  return revision as string;
}

async function importGeneratedKey(
  service: TestUiConfigurationService,
  privateKeyPath: string,
  label: string,
): Promise<string> {
  const before = await service.fleetStatus();
  const after = await service.importManagedKey(
    label,
    privateKeyPath,
    before.keyRevision,
  );
  const key = after.keys.find((candidate) => candidate.label === label);
  assert.notEqual(key, undefined);
  return key!.keyId;
}

async function rollbackRevision(managedDirectory: string): Promise<string> {
  const raw = await readFile(path.join(managedDirectory, "active.json"), "utf8");
  const value = JSON.parse(raw) as Record<string, unknown>;
  const revision = value.previousRevision;
  assert.equal(typeof revision, "string");
  assert.match(revision as string, /^r-[a-z0-9]+-[a-f0-9]{32}$/u);
  return revision as string;
}

async function revisionDirectories(managedDirectory: string): Promise<string[]> {
  const entries = await readdir(path.join(managedDirectory, "revisions"), {
    withFileTypes: true,
  });
  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
}

async function sshWrapperNames(runtimeDirectory: string): Promise<string[]> {
  return (await readdir(runtimeDirectory))
    .filter(
      (entry) =>
        entry.startsWith(".ssh-wrapper-") && entry.endsWith(".conf"),
    )
    .sort();
}

function exitedChildProcessId(): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const child = execFile(process.execPath, ["-e", ""], {
      windowsHide: true,
    });
    const pid = child.pid;
    if (pid === undefined) {
      reject(new Error("test child process did not receive a PID"));
      return;
    }
    child.once("error", reject);
    child.once("exit", () => resolve(pid));
  });
}

async function replaceSshWrapperWithDirectory(
  runtimeDirectory: string,
  wrapperName: string,
): Promise<void> {
  const wrapperPath = path.join(runtimeDirectory, wrapperName);
  await rm(wrapperPath, { force: true });
  await mkdir(wrapperPath);
}

async function convertFleetRevisionToSingle(
  revisionDirectory: string,
  profile: ManagedSshProfile,
  removePlatform: boolean,
): Promise<void> {
  const credentialDirectory = path.join(revisionDirectory, "credentials");
  const fleetCredentials = path.join(credentialDirectory, "managed-ssh");
  await rename(
    path.join(fleetCredentials, "target.key"),
    path.join(credentialDirectory, "target.key"),
  );
  if (profile.bastion !== undefined) {
    await rename(
      path.join(fleetCredentials, "bastion.key"),
      path.join(credentialDirectory, "bastion.key"),
    );
  }
  await unlink(path.join(fleetCredentials, "known_hosts"));
  await rmdir(fleetCredentials);

  const sshConfigPath = path.join(revisionDirectory, "ssh_config");
  const gatewayPath = path.join(revisionDirectory, "gateway.yaml");
  const [fleetSsh, fleetGateway] = await Promise.all([
    readFile(sshConfigPath, "utf8"),
    readFile(gatewayPath, "utf8"),
  ]);
  let singleSsh = fleetSsh
    .replaceAll("managed-target-0001", "managed-ssh")
    .replaceAll("credentials/managed-ssh/target.key", "credentials/target.key");
  if (profile.bastion !== undefined) {
    singleSsh = singleSsh
      .replaceAll("managed-bastion-0001", "managed-bastion")
      .replaceAll(
        "credentials/managed-ssh/bastion.key",
        "credentials/bastion.key",
      );
  }
  let singleGateway = fleetGateway.replaceAll(
    "sshAlias: managed-target-0001",
    "sshAlias: managed-ssh",
  );
  singleGateway = singleGateway.replace(
    /^    targetId: [^\r\n]+\r?\n/mu,
    "",
  );
  if (removePlatform) {
    singleGateway = singleGateway.replace(/^    platform: [^\r\n]+\r?\n/mu, "");
  }
  assert.notEqual(singleSsh, fleetSsh);
  assert.notEqual(singleGateway, fleetGateway);
  await Promise.all([
    writeFile(sshConfigPath, singleSsh, "utf8"),
    writeFile(gatewayPath, singleGateway, "utf8"),
    writeFile(
      path.join(revisionDirectory, "profile.json"),
      `${JSON.stringify(profile, null, 2)}\n`,
      "utf8",
    ),
  ]);
}

async function convertFleetRevisionToV2(
  managedDirectory: string,
  revision: string,
): Promise<void> {
  const revisionDirectory = path.join(managedDirectory, "revisions", revision);
  const profilePath = path.join(revisionDirectory, "profile.json");
  const current = JSON.parse(await readFile(profilePath, "utf8")) as {
    version: number;
    targets: Record<string, Record<string, unknown>>;
  };
  assert.equal(current.version, 3);
  const targets: Record<string, unknown> = {};
  for (const [alias, rawTarget] of Object.entries(current.targets)) {
    const target = structuredClone(rawTarget);
    const endpoint = target.target as Record<string, unknown>;
    delete endpoint.keyId;
    endpoint.identityFile = path.join(
      revisionDirectory,
      "credentials",
      alias,
      "target.key",
    );
    if (target.bastion !== undefined) {
      const bastion = target.bastion as Record<string, unknown>;
      delete bastion.keyId;
      bastion.identityFile = path.join(
        revisionDirectory,
        "credentials",
        alias,
        "bastion.key",
      );
    }
    targets[alias] = target;
  }
  await writeFile(
    profilePath,
    `${JSON.stringify({ version: 2, targets }, null, 2)}\n`,
    "utf8",
  );
}

async function assertManagedCopies(
  managedDirectory: string,
  revision: string,
  sourceKey: string,
  sourceKnownHosts: string,
): Promise<void> {
  const revisionDirectory = path.join(
    managedDirectory,
    "revisions",
    revision,
  );
  const [sshConfig, gatewayConfig] = await Promise.all([
    readFile(path.join(revisionDirectory, "ssh_config"), "utf8"),
    readFile(path.join(revisionDirectory, "gateway.yaml"), "utf8"),
  ]);
  assert.match(
    sshConfig,
    /credentials[\\/]managed-ssh[\\/]target\.key/u,
  );
  assert.equal(sshConfig.includes(sourceKey.replaceAll("\\", "/")), false);
  assert.match(gatewayConfig, /known_hosts/u);
  assert.equal(gatewayConfig.includes(sourceKnownHosts), false);
  assert.equal(
    await readFile(
      path.join(
        revisionDirectory,
        "credentials",
        "managed-ssh",
        "known_hosts",
      ),
      "utf8",
    ),
    await readFile(sourceKnownHosts, "utf8"),
  );
}

async function listTargetsWithoutIds(gateway: {
  listTargets(): Promise<TargetListResult>;
}): Promise<{ readonly targets: readonly Record<string, unknown>[] }> {
  const listed = await gateway.listTargets();
  return {
    targets: listed.targets.map(({ targetId, ...target }) => {
      assert.match(targetId, /^t-[a-f0-9]{32}$/u);
      return target;
    }),
  };
}
