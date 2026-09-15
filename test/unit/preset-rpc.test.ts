import assert from "node:assert/strict";
import test from "node:test";
import { GatewayDispatcher } from "../../src/daemon/dispatcher.js";
import { TargetRegistry } from "../../src/core/target-registry.js";
import { operationListResultSchema, parseRpcParams, parseRpcResult } from "../../src/shared/protocol.js";
import { FakeSshExecutor, sshOutcome, testExecService } from "../helpers/fakes.js";

test("preset RPC rejects shell/command injection before execution and returns discoverable bounded operations", async () => {
  const executor = new FakeSshExecutor(async input => {
    await input.outputSink?.append("stdout", Buffer.from("fixture-host\n"));
    return sshOutcome();
  });
  const service = testExecService({ executor, registry: new TargetRegistry({
    restricted: { sshAlias: "restricted", enabled: true, platform: "linux", policy: {
      mode: "presets", presets: ["basic-inspection", "docker-protection"], logPaths: [], logServices: [], maxTimeoutMs: 20_000,
    } },
  }) });
  const dispatcher = new GatewayDispatcher(service);
  const context = { sessionId: "preset-rpc-test" };
  try {
    const listed = operationListResultSchema.parse(await dispatcher.dispatch("operation.list", { target: "restricted" }, context, "list"));
    assert.equal(listed.presets.length, 4);
    assert.ok(listed.operations.some(operation => operation["id"] === "system.cpu"));
    assert.ok(!listed.operations.some(operation => operation["id"] === "docker.logs"));
    for (const extra of [{ command: "reboot" }, { script: "reboot" }, { env: { PATH: "/tmp" } }, { timeoutMs: 15_001 }]) {
      await assert.rejects(dispatcher.dispatch("operation.run", { target: "restricted", operation: "system.identity", parameters: {}, ...extra }, context, "bad"));
    }
    await assert.rejects(dispatcher.dispatch("operation.run", { target: "restricted", operation: "system.identity", parameters: { script: "reboot" } }, context, "bad-arg"));
    assert.equal(executor.calls.length, 0);
    const result = parseRpcResult("operation.run", await dispatcher.dispatch("operation.run", {
      target: "restricted", operation: "system.identity", parameters: {},
    }, context, "good"));
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout.text, "fixture-host\n");
    assert.equal(executor.calls.length, 1);
    assert.throws(() => parseRpcParams("operation.list", { target: "restricted", all: true }));
  } finally { await service.shutdown(); }
});
