import assert from "node:assert/strict";
import test from "node:test";

import { TargetRegistry, type GatewayMetadataUpdate } from "../../src/core/target-registry.js";
import { deferred, FakeSshExecutor, sshOutcome, testExecService, testRegistry } from "../helpers/fakes.js";

test("metadata replacement preserves target identity, aliases, policies and transport", () => {
  const initial = new TargetRegistry({
    alpha: {
      targetId: "t-11111111111111111111111111111111",
      previousAliases: ["legacy-alpha"],
      sshAlias: "internal-alpha",
      connection: { mode: "accessclient-share", gatewayHost: "example.test", gatewayPort: 22, gatewayUsername: "user" },
      platform: "linux", enabled: true,
      description: "Before", group: "Old",
      policy: { mode: "allow-list", allowedCommands: ["hostname"], maxTimeoutMs: 1000 },
    },
  }, {}, ["Old"]);
  const updated = initial.withMetadata({ groups: ["New", "Empty"], targets: { alpha: { description: "After", group: "New" } } });
  assert.deepEqual(updated.listGroups(), ["New", "Empty"]);
  assert.equal(updated.list()[0]?.description, "After");
  assert.equal(initial.list()[0]?.description, "Before");
  assert.equal(updated.require("legacy-alpha").sshAlias, "internal-alpha");
  assert.equal(updated.require("legacy-alpha").connectionMode, "accessclient-share");
  assert.equal(updated.require("t-11111111111111111111111111111111").alias, "alpha");
  assert.equal(updated.authorize("alpha", "hostname").timeoutMs, 1000);
  assert.throws(() => updated.authorize("alpha", "rm -rf /"), /not allowed/iu);
  const cleared = updated.withMetadata({ groups: [], targets: { alpha: {} } });
  assert.equal(cleared.list()[0]?.group, undefined);
  assert.equal(cleared.list()[0]?.description, undefined);
});

test("metadata updates fail closed on operational changes and incomplete inventories", () => {
  const registry = testRegistry();
  const invalid: unknown[] = [
    { targets: {} },
    { targets: { other: {} } },
    { targets: { alpha: {}, extra: {} } },
    ...["enabled", "sshAlias", "targetId", "previousAliases", "connection", "policy", "transfer", "platform"].map((field) => ({ targets: { alpha: { [field]: true } } })),
    { groups: ["默认分组"], targets: { alpha: {} } },
    { groups: ["A", "A"], targets: { alpha: {} } },
    { groups: [], targets: { alpha: { group: "missing" } } },
    { targets: { alpha: { description: "bad\ntext" } } },
    { targets: { alpha: {} }, runtime: {} },
  ];
  for (const input of invalid) {
    assert.throws(() => registry.withMetadata(input as GatewayMetadataUpdate));
  }
  assert.equal(registry.list()[0]?.description, "Test target");
  assert.equal(registry.authorize("alpha", "echo ok").target.sshAlias, "internal-alpha");
});

test("metadata updates while command is active retain its runner and do not interrupt it", async (t) => {
  const started = deferred<void>();
  const release = deferred<void>();
  const executor = new FakeSshExecutor(async () => {
    started.resolve();
    await release.promise;
    return sshOutcome({ exitCode: 0 });
  });
  const service = testExecService({ executor });
  t.after(() => service.shutdown());
  const running = service.run({ sessionId: "test" }, "active", { target: "alpha", command: "echo ok" });
  await started.promise;
  service.updateMetadata({ groups: ["Team"], targets: { alpha: { group: "Team", description: "Renamed" } } });
  assert.equal(service.listTargets()[0]?.group, "Team");
  assert.equal(executor.calls[0]?.signal?.aborted, false);
  release.resolve();
  assert.equal((await running).exitCode, 0);
  assert.equal((await service.run({ sessionId: "test" }, "after", { target: "alpha", command: "echo ok" })).exitCode, 0);
  assert.equal(executor.calls.length, 2);
  assert.deepEqual(executor.calls.map((input) => input.sshAlias), ["internal-alpha", "internal-alpha"]);
});

test("metadata update respects full reload and shutdown guards", async () => {
  const service = testExecService({ executor: new FakeSshExecutor(async () => sshOutcome({ exitCode: 0 })) });
  const metadata = { groups: [], targets: { alpha: {} } };
  const lease = service.beginReload();
  assert.throws(() => service.updateMetadata(metadata), /reload is already in progress/iu);
  lease.release();
  service.updateMetadata(metadata);
  await service.shutdown();
  assert.throws(() => service.updateMetadata(metadata), /stopping/iu);
});

test("target removal atomically revokes IDs and old aliases, retains groups and permits later metadata updates", async (t) => {
  const config = { sshAlias: "internal-alpha", platform: "linux" as const, enabled: true,
    policy: { mode: "allow-list" as const, allowedCommands: ["hostname"], maxTimeoutMs: 1000 } };
  const registry = new TargetRegistry({
    alpha: { ...config, targetId: "t-11111111111111111111111111111111", previousAliases: ["old-alpha"], enabled: false },
    beta: { ...config, sshAlias: "internal-beta", group: "Team" },
  }, {}, ["Team", "Empty"]);
  const executor = new FakeSshExecutor(async () => sshOutcome({ exitCode: 0 }));
  const service = testExecService({ executor, registry });
  t.after(() => service.shutdown());
  assert.throws(() => service.removeTargets(["alpha", "missing"]), /canonical aliases/iu);
  assert.throws(() => service.removeTargets(["old-alpha"]), /canonical aliases/iu);
  assert.throws(() => service.removeTargets(["alpha"], { targets: {} }), /preserve every target/iu);
  assert.equal(service.listTargets().length, 2);
  const removed = service.removeTargets(["alpha"], { groups: ["Team", "Empty"], targets: { beta: { group: "Team", description: "Retained" } } });
  assert.deepEqual(removed.sshAliases, ["internal-alpha"]);
  for (const target of ["alpha", "old-alpha", "t-11111111111111111111111111111111"]) {
    assert.throws(() => removed.registry.require(target), /not found/iu);
  }
  assert.deepEqual(service.listGroups(), ["Team", "Empty"]);
  assert.deepEqual(service.listTargets().map((target) => target.alias), ["beta"]);
  await service.run({ sessionId: "test" }, "retained", { target: "beta", command: "hostname" });
  assert.equal(executor.calls[0]?.sshAlias, "internal-beta");
  service.updateMetadata({ targets: { beta: { description: "After" } } });
  assert.equal(service.listTargets()[0]?.description, "After");
  service.removeTargets(["beta"]);
  assert.deepEqual(service.listTargets(), []);
});

test("target removal rejects active work, concurrent reload and shutdown without mutating inventory", async () => {
  const entered = deferred<void>();
  const finish = deferred<void>();
  const service = testExecService({ executor: new FakeSshExecutor(async () => {
    entered.resolve(); await finish.promise; return sshOutcome({ exitCode: 0 });
  }) });
  const running = service.run({ sessionId: "test" }, "active", { target: "alpha", command: "echo ok" });
  await entered.promise;
  assert.throws(() => service.removeTargets(["alpha"]), /executions are active/iu);
  assert.equal(service.listTargets().length, 1);
  finish.resolve(); await running;
  const lease = service.beginReload();
  assert.throws(() => service.removeTargets(["alpha"]), /already in progress/iu);
  lease.release();
  await service.shutdown();
  assert.throws(() => service.removeTargets(["alpha"]), /stopping/iu);
});
