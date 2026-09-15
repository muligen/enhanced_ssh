import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createManagedSshService, type TestUiConfigurationService } from "../../src/test-ui/managed.js";

test("metadata saves retain immutable credentials and live RPC while surviving restart and full save", { skip: process.platform !== "win32", timeout: 240_000 }, async (t) => {
  const sandbox = await mkdtemp(path.join(os.tmpdir(), "agent-ssh-metadata-"));
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
  const imported = await service.importManagedKey("metadata test", generated.privateKeyPath, (await service.keyStatus()).keyRevision);
  const keyId = imported.keys[0]!.keyId;
  const knownHosts = path.join(sandbox, "known_hosts");
  await writeFile(knownHosts, `127.0.0.1 ${generated.publicKey.trim().split(/\s+/u).slice(0, 2).join(" ")}\n`);
  const original = await service.applyFleet({ version: 3, targets: {
    alpha: { enabled: true, description: "Original", target: { host: "127.0.0.1", port: 22, username: "agent_test", keyId }, knownHostsFile: knownHosts, platform: "linux", policyMode: "allow-list", allowedCommands: ["hostname"], maxTimeoutMs: 20_000 },
  } });
  assert.equal(original.state, "ready");
  const activeBefore = await readFile(path.join(managed, "active.json"), "utf8");
  const revisionsBefore = await readdir(path.join(managed, "revisions"));
  const immutablePath = path.join(managed, "revisions", original.revision!, "profile.json");
  const immutableBefore = await readFile(immutablePath, "utf8");
  gateway = await service.gatewayFactory();
  const metadataStart = performance.now();
  const saved = await service.applyFleet({ ...original.profile!, groups: ["A组", "空组"], targets: { alpha: { ...original.profile!.targets.alpha!, group: "A组", description: "Updated" } } }, original.revision);
  t.diagnostic(`metadata save: ${Math.round(performance.now() - metadataStart)} ms`);
  assert.notEqual(saved.revision, original.revision);
  assert.equal(saved.state, "ready");
  assert.equal(await readFile(path.join(managed, "active.json"), "utf8"), activeBefore);
  assert.deepEqual(await readdir(path.join(managed, "revisions")), revisionsBefore);
  assert.equal(await readFile(immutablePath, "utf8"), immutableBefore);
  const listed = await gateway.listTargets();
  assert.deepEqual(listed.groups, ["A组", "空组"]);
  assert.equal(listed.targets[0]?.description, "Updated");
  assert.equal(listed.targets[0]?.group, "A组");
  await assert.rejects(service.applyFleet(saved.profile!, original.revision), { code: "CONFIG_CONFLICT" });
  assert.equal((await service.applyFleet(saved.profile!, saved.revision)).revision, saved.revision, "no-op must not create another revision");
  gateway.close(); gateway = undefined;
  await service.close(); service = await createManagedSshService(managed);
  const reopened = await service.fleetStatus();
  assert.equal(reopened.state, "ready", JSON.stringify(reopened.error));
  assert.equal(reopened.revision, saved.revision);
  assert.deepEqual(reopened.profile, saved.profile);
  gateway = await service.gatewayFactory();
  assert.deepEqual((await gateway.listTargets()).groups, ["A组", "空组"]);

  const full = await service.applyFleet({ ...reopened.profile!, targets: { alpha: { ...reopened.profile!.targets.alpha!, enabled: false } } }, reopened.revision);
  assert.notEqual(full.revision, saved.revision);
  assert.notEqual(await readFile(path.join(managed, "active.json"), "utf8"), activeBefore);
  assert.deepEqual(full.profile!.groups, ["A组", "空组"]);
  gateway.close(); gateway = undefined;
  await service.close(); service = await createManagedSshService(managed);
  const final = await service.fleetStatus();
  assert.equal(final.state, "ready", JSON.stringify(final.error));
  assert.equal(final.revision, full.revision, "old overlay must not replace full revision");
  assert.equal(final.profile!.targets.alpha!.enabled, false);
  assert.equal(final.profile!.targets.alpha!.description, "Updated");
});
