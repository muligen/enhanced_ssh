import assert from "node:assert/strict";
import test from "node:test";
import { gatewayConfigSchema, targetPolicySchema, type TargetConfig } from "../../src/config/load-config.js";
import { TargetRegistry } from "../../src/core/target-registry.js";
import { GATEWAY_ERROR_CODES, GatewayError } from "../../src/shared/errors.js";
import { FakeAuditWriter, FakeSshExecutor, deferred, sshOutcome, testExecService } from "../helpers/fakes.js";

const caller = { sessionId: "preset-test" };
const policy = {
  mode: "presets" as const,
  presets: ["basic-inspection", "docker-protection"] as ("basic-inspection" | "docker-protection")[],
  logPaths: [], logServices: [], maxTimeoutMs: 30_000,
};
const config = {
  sshAlias: "internal-host", enabled: true, platform: "linux" as const,
  policy,
};
const isDenied = (error: unknown) => error instanceof GatewayError && error.code === GATEWAY_ERROR_CODES.commandDenied;

function registry(overrides: Partial<TargetConfig> = {}) {
  return new TargetRegistry({ host: { ...config, ...overrides } });
}

test("preset policy is strict and cannot combine full access, raw commands, or enabled transfer", () => {
  assert.equal(targetPolicySchema.safeParse(policy).success, true);
  assert.equal(targetPolicySchema.safeParse({ ...policy, allowedCommands: ["docker stop x"] }).success, false);
  assert.equal(targetPolicySchema.safeParse({ ...policy, mode: "full-access" }).success, false);
  assert.equal(targetPolicySchema.safeParse({ ...policy, presets: ["invented"] }).success, false);
  assert.equal(gatewayConfigSchema.shape.targets.safeParse({ host: config }).success, true);
  assert.equal(gatewayConfigSchema.shape.targets.safeParse({ host: {
    ...config, transfer: { mode: "download", localRoots: ["data"], remoteRoots: ["/tmp"] },
  } }).success, false);
});

test("preset policies deny every caller-controlled command route and all transfer directions", () => {
  const targets = registry();
  assert.throws(() => targets.authorize("host", "hostname"), isDenied);
  assert.throws(() => targets.authorizeStructured("host"), isDenied);
  assert.throws(() => targets.authorizeDockerPreflight("host"), isDenied);
  for (const direction of ["upload", "download", "sync"] as const) {
    assert.throws(() => targets.authorizeTransfer("host", direction, undefined),
      (error) => error instanceof GatewayError && error.code === GATEWAY_ERROR_CODES.transferDenied);
  }
  assert.equal(targets.authorizeCheck("host").target.alias, "host");
  assert.equal(targets.authorizeInspect("host").target.alias, "host");
});

test("operation discovery retains selection on metadata update and resolves historical aliases", () => {
  const targets = registry({ previousAliases: ["old-host"] });
  const initial = targets.listAllowedOperations("old-host");
  assert.equal(initial.target, "host");
  assert.ok(initial.operations.length > 0);
  const changed = targets.withMetadata({ groups: ["A"], targets: { host: { description: "new", group: "A" } } });
  assert.deepEqual(changed.listAllowedOperations("host"), initial);
  assert.equal(changed.list()[0]?.group, "A");
  assert.throws(() => registry({ enabled: false }).listAllowedOperations("host"),
    (error) => error instanceof GatewayError && error.code === GATEWAY_ERROR_CODES.targetDisabled);
  assert.equal(registry({ policy: { mode: "full-access", maxTimeoutMs: 30_000 } }).listAllowedOperations("host").operations.length, 0);
});

test("raw execution and background tasks cannot use preset templates as arbitrary commands", async () => {
  const executor = new FakeSshExecutor(async () => sshOutcome());
  const service = testExecService({ registry: registry(), executor });
  assert.throws(() => service.run(caller, "raw", { target: "host", command: "hostname" }), isDenied);
  assert.throws(() => service.startTask({ target: "host", shell: "bash", script: "hostname", encoding: "utf-8" }), isDenied);
  assert.equal(executor.calls.length, 0);
  await service.shutdown();
});

test("vetted operation executes only after durable audit and keeps standard output handling", async () => {
  const targets = registry();
  const operation = targets.listAllowedOperations("host").operations[0]!.id;
  const entered = deferred<void>();
  const durable = deferred<void>();
  const audit = new FakeAuditWriter(async (event) => {
    if (event.event === "exec.started") { entered.resolve(); await durable.promise; }
  });
  const executor = new FakeSshExecutor(async (input) => {
    await input.outputSink?.append("stdout", Buffer.from("ok\n"));
    await input.outputSink?.append("stderr", Buffer.from("warning\n"));
    return sshOutcome();
  });
  const service = testExecService({ registry: targets, executor, audit });
  const pending = service.runOperation(caller, "safe", { target: "host", operation, parameters: {} });
  await entered.promise;
  assert.equal(executor.calls.length, 0);
  durable.resolve();
  const result = await pending;
  assert.equal(result.stdout.text, "ok\n");
  assert.equal(result.stderr.text, "warning\n");
  assert.equal(executor.calls[0]?.sshAlias, "internal-host");
  assert.equal(executor.calls[0]?.command, "bash --noprofile --norc -s");
  assert.ok(executor.calls[0]?.stdin);
  assert.deepEqual(audit.events.map(event => event.event), ["exec.started", "exec.completed"]);
  assert.throws(() => service.runOperation(caller, "injected", {
    target: "host", operation, parameters: { script: "docker stop prod", shell: "bash" },
  }), (error) => error instanceof GatewayError);
  assert.equal(executor.calls.length, 1);
  await service.shutdown();
});

test("preset operation authorization bounds timeout and denies unselected operations", () => {
  const targets = registry();
  const operation = targets.listAllowedOperations("host").operations[0]!.id;
  assert.equal(targets.authorizeOperation("host", { operation, parameters: {} }).timeoutMs, 15_000);
  const limited = registry({ policy: { ...policy, maxTimeoutMs: 200 } });
  assert.equal(limited.authorizeOperation("host", { operation, parameters: {} }).timeoutMs, 200);
  for (const timeout of [0, -1, 200.1, 15_001, NaN]) {
    assert.throws(() => targets.authorizeOperation("host", { operation, parameters: {} }, timeout),
      (error) => error instanceof GatewayError && error.code === GATEWAY_ERROR_CODES.invalidParams);
  }
  assert.throws(() => targets.authorizeOperation("host", { operation: "docker.logs", parameters: {} }),
    (error) => error instanceof GatewayError);
  assert.throws(() => registry({ policy: { mode: "full-access", maxTimeoutMs: 30_000 } })
    .authorizeOperation("host", { operation, parameters: {} }), isDenied);
});

test("preset execution enforces aggregate output ceiling and standard cancellation audit", async () => {
  const targets = registry();
  const operation = targets.listAllowedOperations("host").operations[0]!.id;
  const audit = new FakeAuditWriter();
  const executor = new FakeSshExecutor(async (input) => {
    await input.outputSink?.append("stdout", Buffer.from("first\n"));
    await input.outputSink?.append("stderr", Buffer.alloc(256 * 1024));
    return sshOutcome();
  });
  const service = testExecService({ registry: targets, executor, audit });
  const result = await service.runOperation(caller, "bounded", { target: "host", operation, parameters: {} });
  assert.equal(result.termination, "output_limit");
  assert.equal(result.stdout.text, "first\n");
  assert.equal(result.stderr.bytes, 0);
  assert.ok(audit.events.some(event => event.event === "exec.cancelled" && event.reasonCode === "output_limit"));
  await service.shutdown();
});

test("preset execution uses concurrency, timeout and reload gates", async () => {
  const targets = registry({ policy: { ...policy, maxTimeoutMs: 20 } });
  const operation = targets.listAllowedOperations("host").operations[0]!.id;
  const entered = deferred<void>();
  const executor = new FakeSshExecutor(async input => {
    entered.resolve();
    return new Promise(resolve => {
      const done = () => resolve(sshOutcome({ aborted: true, exitCode: null }));
      if (input.signal?.aborted) done();
      else input.signal?.addEventListener("abort", done, { once: true });
    });
  });
  const service = testExecService({ registry: targets, executor, maxConcurrentExecutions: 1 });
  const params = { target: "host", operation, parameters: {} };
  const pending = service.runOperation(caller, "timed", params);
  await entered.promise;
  await assert.rejects(service.runOperation(caller, "second", params),
    error => error instanceof GatewayError && error.code === GATEWAY_ERROR_CODES.executionLimitReached);
  assert.equal((await pending).termination, "timeout");
  assert.equal(executor.calls.length, 1);
  const lease = service.beginReload();
  assert.throws(() => service.runOperation(caller, "reload", params),
    error => error instanceof GatewayError && error.code === GATEWAY_ERROR_CODES.executionLimitReached);
  lease.release();
  await service.shutdown();
});
