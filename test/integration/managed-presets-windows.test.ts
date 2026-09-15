import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { parseConfigText } from "../../src/config/load-config.js";
import { RpcRemoteError } from "../../src/shared/rpc-client.js";
import { createManagedSshService, type TestUiConfigurationService } from "../../src/test-ui/managed.js";

test("managed preset save renders enforced gateway policy and reload retains selection", { skip: process.platform !== "win32", timeout: 180_000 }, async (t) => {
  const sandbox = await mkdtemp(path.join(os.tmpdir(), "agent-ssh-presets-integration-"));
  const managed = path.join(sandbox, "managed");
  let service: TestUiConfigurationService | undefined;
  let gateway: Awaited<ReturnType<TestUiConfigurationService["gatewayFactory"]>> | undefined;
  t.after(async () => {
    gateway?.close();
    await service?.close().catch(() => undefined);
    await rm(sandbox, { recursive: true, force: true });
  });
  service = await createManagedSshService(managed);
  const generated = (await service.generateKey()).generatedKey!;
  const imported = await service.importManagedKey("preset integration", generated.privateKeyPath, (await service.keyStatus()).keyRevision);
  const keyId = imported.keys[0]!.keyId;
  const knownHosts = path.join(sandbox, "known_hosts");
  await writeFile(knownHosts, `127.0.0.1 ${generated.publicKey.trim().split(/\s+/u).slice(0, 2).join(" ")}\n`);
  const saved = await service.applyFleet({ version: 3, targets: {
    alpha: {
      enabled: true,
      target: { host: "127.0.0.1", port: 22, username: "agent_test", keyId },
      knownHostsFile: knownHosts,
      platform: "linux",
      policyMode: "presets",
      permissionPresets: ["basic-inspection", "log-inspection", "docker-readonly", "docker-protection"],
      logPaths: ["/var/log/app.log"], logServices: ["app.service"],
      allowedCommands: [], maxTimeoutMs: 30_000, transferMode: "deny",
    },
  } });
  assert.equal(saved.state, "ready");
  const generatedConfig = parseConfigText(await readFile(path.join(managed, "revisions", saved.revision!, "gateway.yaml"), "utf8"));
  assert.deepEqual(generatedConfig.targets.alpha!.policy, {
    mode: "presets", presets: ["basic-inspection", "log-inspection", "docker-readonly", "docker-protection"],
    logPaths: ["/var/log/app.log"], logServices: ["app.service"], maxTimeoutMs: 30_000,
  });
  gateway = await service.gatewayFactory();
  assert.equal((await gateway.listTargets()).targets[0]!.policyMode, "presets");
  // Authorization must fail before any SSH connection is attempted.
  await assert.rejects(gateway.run({ target: "alpha", command: "hostname", timeoutMs: 1000 }, new AbortController().signal), (error: unknown) => {
    assert.ok(error instanceof RpcRemoteError);
    assert.equal((error.data as { gatewayCode: string }).gatewayCode, "COMMAND_DENIED");
    return true;
  });
  gateway.close(); gateway = undefined;
  await service.close(); service = await createManagedSshService(managed);
  const reopened = await service.fleetStatus();
  assert.equal(reopened.state, "ready", JSON.stringify(reopened.error));
  assert.equal(reopened.revision, saved.revision);
  assert.deepEqual(reopened.profile, saved.profile);
  gateway = await service.gatewayFactory();
  const listed = await gateway.listTargets();
  assert.equal(listed.targets[0]!.policyMode, "presets");
  assert.equal(listed.targets[0]!.transferMode, "deny");
});
