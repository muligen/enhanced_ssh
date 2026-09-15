import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { GroupController, CPU_SCRIPTS, groupStartSchema, parseCpuOutput } from "../../src/mcp/groups.js";
import { RpcRemoteError, type GatewayRpcClient } from "../../src/shared/rpc-client.js";
import { targetSummarySchema, type ExecRunParams, type TargetSummary } from "../../src/shared/protocol.js";

function id(alias: string) { return `t-${createHash("md5").update(alias).digest("hex")}`; }
function target(alias: string, options: Partial<TargetSummary> = {}): TargetSummary {
  return targetSummarySchema.parse({ targetId: id(alias), alias, enabled: true, platform: "linux",
    policyMode: "full-access", maxTimeoutMs: 10_000, maxTransferTimeoutMs: 300_000, group: "A", ...options });
}
function harness(targets: TargetSummary[], options: {
  request?: (method: string, params: Record<string, unknown>) => Promise<unknown>;
  run?: (params: ExecRunParams) => Promise<unknown>;
  now?: () => number;
  groups?: string[];
} = {}) {
  const calls: { method: string; params: Record<string, unknown> }[] = [];
  let closed = 0;
  const controller = new GroupController(async () => ({
    close: () => { closed++; },
    request: async (method: string, params: Record<string, unknown>) => {
      calls.push({ method, params });
      if (method === "target.list") return { targets, ...(options.groups ? { groups: options.groups } : {}) };
      if (options.request) return options.request(method, params);
      if (method === "task.start") return { runId: `run-${params.target}`, state: "running" };
      if (method === "task.status") return { state: "succeeded" };
      if (method === "task.cancel") return { state: "running", accepted: true };
      throw new Error("unexpected call");
    },
    run: async (params: ExecRunParams) => {
      calls.push({ method: "exec.run", params });
      return options.run ? options.run(params) : cpuResult(25, 4);
    },
  }) as unknown as GatewayRpcClient, options.now);
  return { controller, calls, closed: () => closed };
}
function cpuResult(percent: number, cores: number) {
  return { exitCode: 0, termination: "exit", stdout: { text: `AGENT_SSH_CPU ${percent} ${cores}\r\n` } };
}

test("lists exact groups, never alias-falls-back, excludes disabled and snapshots immutable IDs", async () => {
  const targets = [target("one"), target("two", { enabled: false }), target("three", { group: "B" }), target("four", { group: undefined })];
  const { controller, calls, closed } = harness(targets);
  const list = await controller.list();
  assert.deepEqual(list.groups.map(group => [group.group, group.total, group.enabled]), [["默认分组", 1, 1], ["A", 2, 1], ["B", 1, 1]]);
  assert.equal(list.ungroupedCount, 1);
  await assert.rejects(controller.start({ group: "one", common: { command: "hostname" } }), /GROUP_NOT_FOUND/);
  await assert.rejects(controller.start({ group: "*", common: { command: "hostname" } }), /GROUP_NOT_FOUND/);
  const batch = await controller.start({ group: "A", common: { command: "hostname" } });
  await controller.status(batch.groupRunId);
  assert.equal(batch.members[1]?.state, "skipped");
  assert.equal(batch.members[1]?.errorCode, "TARGET_DISABLED");
  assert.deepEqual(calls.filter(call => call.method === "task.start").map(call => call.params.target), [id("one")]);
  targets[0]!.alias = "renamed";
  targets[0]!.group = "B";
  const status = await controller.status(batch.groupRunId);
  assert.equal(status.members[0]?.alias, "one");
  assert.equal(status.members[0]?.targetId, id("one"));
  assert.equal(status.complete, true);
  assert.equal(closed(), calls.length);
});

test("formal catalog includes ordered empty groups and permanent default, and default controls only its members", async () => {
  const { controller, calls } = harness([target("one", { group: undefined }), target("two", { group: "A" })], { groups: ["B", "A"] });
  const list = await controller.list();
  assert.deepEqual(list.groups.map(group => [group.group, group.total, group.isDefault]), [["默认分组", 1, true], ["B", 0, false], ["A", 1, false]]);
  const empty = await controller.start({ group: "B", common: { command: "hostname" } });
  assert.equal(empty.complete, true);
  assert.equal((await controller.cpu({ group: "B" })).sampled, 0);
  const batch = await controller.start({ group: "默认分组", common: { command: "hostname" } });
  await controller.status(batch.groupRunId);
  assert.deepEqual(calls.filter(call => call.method === "task.start").map(call => call.params.target), [id("one")]);
});

test("requires every OS variant before starting, validates legacy/structured payload, explicit common supports mixed groups", async () => {
  const { controller, calls } = harness([target("linux"), target("win", { platform: "windows" })]);
  await assert.rejects(controller.start({ group: "A", platforms: { linux: { command: "hostname" } } }), /PLATFORM_COMMAND_REQUIRED/);
  assert.equal(calls.filter(call => call.method === "task.start").length, 0);
  assert.equal(groupStartSchema.safeParse({ group: "A", common: { command: "x\ny" } }).success, false);
  assert.equal(groupStartSchema.safeParse({ group: "A", common: { script: "x" } }).success, false);
  assert.equal(groupStartSchema.safeParse({ group: "A", common: { command: "x", shell: "bash", script: "x" } }).success, false);
  assert.equal(groupStartSchema.safeParse({ group: "A", common: { command: "x", target: "other" } }).success, false);
  assert.equal(groupStartSchema.safeParse({ group: "A", common: { command: "x" }, platforms: {} }).success, false);
  const variantBatch = await controller.start({ group: "A", platforms: { linux: { shell: "bash", script: "uname\nhostname" }, windows: { shell: "powershell", script: "$env:COMPUTERNAME", env: { DEMO: "yes" } } } });
  await controller.status(variantBatch.groupRunId);
  const starts = calls.filter(call => call.method === "task.start");
  assert.equal(starts[0]?.params.shell, "bash");
  assert.equal(starts[1]?.params.shell, "powershell");
  assert.equal(starts[1]?.params.encoding, "utf-8");
  const commonBatch = await controller.start({ group: "A", common: { command: "hostname" } });
  await controller.status(commonBatch.groupRunId);
  assert.equal(calls.filter(call => call.method === "task.start").length, 4);
});

test("gateway policy/capacity failures remain isolated and do not expose remote error details", async () => {
  const { controller } = harness([target("denied", { policyMode: "allow-list" }), target("busy"), target("ok")], {
    request: async (_method, params) => {
      if (params.target === id("denied")) throw new RpcRemoteError(-32022, "SECRET", { gatewayCode: "COMMAND_DENIED", details: "SECRET" });
      if (params.target === id("busy")) throw new RpcRemoteError(-32031, "SECRET", { gatewayCode: "EXECUTION_LIMIT_REACHED" });
      return { runId: "ok", state: "running" };
    },
  });
  const started = await controller.start({ group: "A", common: { command: "hostname", timeoutMs: 9000 }, concurrency: 3 });
  const batch = await controller.status(started.groupRunId);
  assert.equal(batch.members[0]?.errorCode, "COMMAND_DENIED");
  assert.equal(batch.members[1]?.errorCode, "EXECUTION_LIMIT_REACHED");
  assert.equal(batch.members[2]?.runId, "ok");
  assert.equal(JSON.stringify(batch).includes("SECRET"), false);
});

test("CPU probes use target OS and timeout limits; aggregation excludes failed and disabled members", async () => {
  let active = 0;
  let peak = 0;
  const { controller, calls } = harness([target("linux"), target("win", { platform: "windows", maxTimeoutMs: 1234 }),
    target("mac", { platform: "macos" }), target("denied", { policyMode: "deny" }), target("off", { enabled: false })], {
    run: async params => {
      active++;
      peak = Math.max(peak, active);
      await new Promise(resolve => setTimeout(resolve, 5));
      active--;
      if (params.target === id("denied")) throw new RpcRemoteError(-32022, "SECRET", { gatewayCode: "COMMAND_DENIED" });
      if (params.target === id("mac")) return { exitCode: 0, termination: "exit", stdout: { text: "invalid" } };
      return params.target === id("linux") ? cpuResult(20, 2) : cpuResult(80, 6);
    },
  });
  const result = await controller.cpu({ group: "A", concurrency: 2 });
  assert.equal(peak, 2);
  assert.equal(result.sampled, 2);
  assert.equal(result.failed, 2);
  assert.equal(result.skipped, 1);
  assert.equal(result.averageCpuPercent, 50);
  assert.equal(result.coreWeightedCpuPercent, 65);
  const probes = calls.filter(call => call.method === "exec.run");
  assert.equal(probes.length, 4);
  assert.equal(probes[1]?.params.shell, "powershell");
  assert.equal(probes[1]?.params.timeoutMs, 1234);
  assert.equal(probes[2]?.params.script, CPU_SCRIPTS.macos);
  assert.equal(JSON.stringify(result).includes("SECRET"), false);
});

test("preset group CPU uses the vetted operation endpoint and retains permission failures", async () => {
  const { controller, calls } = harness([target("allowed", { policyMode: "presets" }), target("denied", { policyMode: "presets" })], {
    request: async (method, params) => {
      assert.equal(method, "operation.run");
      assert.equal(params.operation, "system.cpu");
      assert.deepEqual(params.parameters, {});
      if (params.target === id("denied")) throw new RpcRemoteError(-32022, "denied", { gatewayCode: "COMMAND_DENIED" });
      return cpuResult(40, 8);
    },
  });
  const result = await controller.cpu({ group: "A" });
  assert.equal(result.sampled, 1);
  assert.equal(result.failed, 1);
  assert.equal(result.averageCpuPercent, 40);
  assert.equal(calls.filter(call => call.method === "exec.run").length, 0);
});

test("CPU output parser rejects missing, invalid, and impossible observations", () => {
  assert.deepEqual(parseCpuOutput("banner\r\nAGENT_SSH_CPU 33.25 8\r\n"), { cpuPercent: 33.25, logicalCpus: 8 });
  for (const text of ["AGENT_SSH_CPU 101 4", "AGENT_SSH_CPU 5 0", "AGENT_SSH_CPU NaN 4", "33%", "AGENT_SSH_CPU -5 2"]) assert.equal(parseCpuOutput(text), undefined);
  assert.match(CPU_SCRIPTS.windows, /\$null -eq \$cpu\.PercentProcessorTime/);
});

test("cancellation acceptance is not terminal; status failures are unknown and recoverable", async () => {
  let mode = "running";
  const { controller } = harness([target("one")], {
    request: async (method) => {
      if (method === "task.start") return { runId: "run1", state: "running" };
      if (method === "task.cancel") return { state: "running", accepted: true };
      if (mode === "error") throw new Error("SECRET connection detail");
      return { state: mode };
    },
  });
  const started = await controller.start({ group: "A", common: { command: "hostname" } });
  await controller.status(started.groupRunId);
  const cancelled = await controller.cancel(started.groupRunId);
  assert.equal(cancelled.members[0]?.cancelAccepted, true);
  assert.equal(cancelled.complete, false);
  mode = "error";
  const unknown = await controller.status(started.groupRunId);
  assert.equal(unknown.members[0]?.state, "unknown");
  assert.equal(unknown.complete, false);
  assert.equal(JSON.stringify(unknown).includes("SECRET"), false);
  mode = "cancelled";
  const done = await controller.status(started.groupRunId);
  assert.equal(done.members[0]?.state, "cancelled");
  assert.equal(done.complete, true);
});

test("expired and restarted MCP handles explain how to recover individual tasks", async () => {
  let now = Date.now();
  const { controller } = harness([target("one")], { now: () => now });
  const initial = await controller.start({ group: "A", common: { command: "hostname" } });
  const batch = await controller.status(initial.groupRunId);
  assert.ok(batch.members[0]?.runId);
  const fresh = harness([target("one")]).controller;
  await assert.rejects(fresh.status(batch.groupRunId), /MCP restarted.*per-machine runIds/);
  now += 24 * 60 * 60 * 1000 + 1;
  const completed = await controller.status(batch.groupRunId);
  assert.equal(completed.complete, true, "active handles must survive beyond 24 hours");
  now += 24 * 60 * 60 * 1000 + 1;
  await assert.rejects(controller.cancel(batch.groupRunId), /GROUP_RUN_NOT_FOUND/);
});

test("group queue bounds active child tasks, releases slots on terminal status and cancels undispatched members", async () => {
  const active = new Set<string>();
  const finished = new Set<string>();
  let peak = 0;
  const { controller, calls } = harness(Array.from({ length: 6 }, (_, index) => target(`node${index}`)), {
    request: async (method, params) => {
      if (method === "task.start") {
        const runId = String(params.target);
        active.add(runId);
        peak = Math.max(peak, active.size);
        return { runId, state: "running" };
      }
      const runId = String(params.runId);
      if (method === "task.cancel") { active.delete(runId); return { accepted: true, state: "cancelled" }; }
      if (finished.has(runId)) { active.delete(runId); return { state: "succeeded" }; }
      return { state: "running" };
    },
  });
  const initial = await controller.start({ group: "A", common: { command: "hostname" }, concurrency: 2 });
  assert.equal(initial.counts.queued, 6);
  assert.equal(calls.filter(call => call.method === "task.start").length, 0);
  let status = await controller.status(initial.groupRunId);
  assert.equal(status.counts.running, 2);
  assert.equal(status.counts.queued, 4);
  status = await controller.status(initial.groupRunId);
  assert.equal(status.counts.queued, 4, "polling must not start jobs beyond active capacity");
  finished.add(id("node0"));
  status = await controller.status(initial.groupRunId);
  assert.equal(status.counts.succeeded, 1);
  assert.equal(status.counts.running, 2);
  assert.equal(status.counts.queued, 3);
  assert.equal(peak, 2);
  const cancelled = await controller.cancel(initial.groupRunId);
  assert.equal(cancelled.complete, true);
  assert.equal(cancelled.counts.cancelled, 5);
  await controller.status(initial.groupRunId);
  assert.equal(calls.filter(call => call.method === "task.start").length, 3);
});

test("cancel catches a runId from an in-flight start and prevents the next queued machine from starting", async () => {
  let release!: () => void;
  let entered!: () => void;
  const starting = new Promise<void>(resolve => { entered = resolve; });
  const gate = new Promise<void>(resolve => { release = resolve; });
  const { controller, calls } = harness([target("one"), target("two")], {
    request: async (method) => {
      if (method === "task.start") { entered(); await gate; return { runId: "inflight", state: "running" }; }
      if (method === "task.cancel") return { state: "cancelled", accepted: true };
      return { state: "running" };
    },
  });
  const batch = await controller.start({ group: "A", common: { command: "hostname" }, concurrency: 1 });
  const polling = controller.status(batch.groupRunId);
  await starting;
  const cancelling = controller.cancel(batch.groupRunId);
  release();
  await polling;
  const result = await cancelling;
  assert.equal(result.complete, true);
  assert.equal(result.counts.cancelled, 2);
  assert.deepEqual(calls.filter(call => call.method === "task.cancel").map(call => call.params.runId), ["inflight"]);
  assert.equal(calls.filter(call => call.method === "task.start").length, 1);
});

test("lost task.start response reserves an unknown active slot without retry or false cancellation success", async () => {
  const { controller, calls } = harness([target("one"), target("two")], {
    request: async () => { throw new Error("transport closed after daemon accepted task SECRET"); },
  });
  const initial = await controller.start({ group: "A", common: { command: "hostname" }, concurrency: 1 });
  const status = await controller.status(initial.groupRunId);
  assert.equal(status.members[0]?.state, "unknown");
  assert.equal(status.members[0]?.errorCode, "TASK_START_OUTCOME_UNKNOWN");
  assert.equal(status.members[0]?.runId, undefined);
  assert.equal(status.members[1]?.state, "queued");
  assert.equal(status.complete, false);
  await controller.status(initial.groupRunId);
  assert.equal(calls.filter(call => call.method === "task.start").length, 1);
  const cancelled = await controller.cancel(initial.groupRunId);
  assert.equal(cancelled.members[0]?.state, "unknown");
  assert.equal(cancelled.members[1]?.state, "cancelled");
  assert.equal(cancelled.complete, false);
  assert.equal(JSON.stringify(cancelled).includes("SECRET"), false);
});
