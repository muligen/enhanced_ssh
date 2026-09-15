import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createManagedSshService, type TestUiConfigurationService } from "../../src/test-ui/managed.js";

test("incremental removal persists across metadata edits and restart without rebuilding credentials", { skip: process.platform !== "win32", timeout: 300_000 }, async (t) => {
  const sandbox = await mkdtemp(path.join(os.tmpdir(), "agent-ssh-removal-"));
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
  const imported = await service.importManagedKey("removal test", generated.privateKeyPath, (await service.keyStatus()).keyRevision);
  const keyId = imported.keys[0]!.keyId;
  const knownHostsFile = path.join(sandbox, "known_hosts");
  await writeFile(knownHostsFile, `127.0.0.1 ${generated.publicKey.trim().split(/\s+/u).slice(0, 2).join(" ")}\n`);
  const original = await service.applyFleet({ version: 3, targets: Object.fromEntries(Array.from({ length: 5 }, (_, i) => [`bench${i}`, {
    enabled: true, description: "Original", target: { host: "127.0.0.1", port: 22, username: "agent_test", keyId },
    knownHostsFile, platform: "linux" as const, policyMode: "allow-list" as const, allowedCommands: ["hostname"], maxTimeoutMs: 20_000,
  }])) });
  assert.equal(original.state, "ready");
  const pointerBefore = await readFile(path.join(managed, "active.json"), "utf8");
  const revisionsBefore = await readdir(path.join(managed, "revisions"));
  const immutablePath = path.join(managed, "revisions", original.revision!, "profile.json");
  const immutableBefore = await readFile(immutablePath, "utf8");
  gateway = await service.gatewayFactory();
  const remaining = { ...original.profile!.targets };
  delete remaining.bench4;
  const start = performance.now();
  const removed = await service.applyFleet({ ...original.profile!, targets: remaining }, original.revision);
  t.diagnostic(`delete one of five machines: ${Math.round(performance.now() - start)} ms`);
  assert.equal(removed.state, "ready");
  assert.notEqual(removed.revision, original.revision);
  assert.equal((await gateway.listTargets()).targets.length, 4);
  await assert.rejects(service.applyFleet(original.profile!, original.revision), { code: "CONFIG_CONFLICT" });
  const edited = await service.applyFleet({ ...removed.profile!, groups: ["Remaining"] }, removed.revision);
  const three = { ...edited.profile!.targets };
  delete three.bench3;
  const removedAgain = await service.applyFleet({ ...edited.profile!, targets: three }, edited.revision);
  assert.equal(await readFile(path.join(managed, "active.json"), "utf8"), pointerBefore);
  assert.deepEqual(await readdir(path.join(managed, "revisions")), revisionsBefore);
  assert.equal(await readFile(immutablePath, "utf8"), immutableBefore);
  const overlay = JSON.parse(await readFile(path.join(managed, "metadata", `${original.revision!}.json`), "utf8")) as { removedTargets: string[] };
  assert.deepEqual(overlay.removedTargets, ["bench3", "bench4"]);
  gateway.close(); gateway = undefined;
  await service.close(); service = await createManagedSshService(managed);
  const reopened = await service.fleetStatus();
  assert.equal(reopened.state, "ready", JSON.stringify(reopened.error));
  assert.deepEqual(reopened.profile, removedAgain.profile);
  assert.equal(reopened.revision, removedAgain.revision);
  gateway = await service.gatewayFactory();
  assert.equal((await gateway.listTargets()).targets.length, 3);

  // A subsequent operational change must publish a full version of the
  // surviving fleet, never allowing an older revocation overlay to restore it.
  const full = await service.applyFleet({ ...reopened.profile!, targets: {
    ...reopened.profile!.targets, bench0: { ...reopened.profile!.targets.bench0!, enabled: false },
  } }, reopened.revision);
  assert.notEqual(await readFile(path.join(managed, "active.json"), "utf8"), pointerBefore);
  assert.equal(Object.keys(full.profile!.targets).length, 3);
  const empty = await service.applyFleet({ ...full.profile!, targets: {} }, full.revision);
  assert.equal((await gateway.listTargets()).targets.length, 0);
  gateway.close(); gateway = undefined;
  await service.close(); service = await createManagedSshService(managed);
  const final = await service.fleetStatus();
  assert.equal(final.state, "ready", JSON.stringify(final.error));
  assert.equal(final.revision, empty.revision);
  assert.deepEqual(final.profile!.targets, {});
  gateway = await service.gatewayFactory();
  assert.equal((await gateway.listTargets()).targets.length, 0);
});
