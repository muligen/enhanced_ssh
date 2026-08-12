import assert from "node:assert/strict";
import test from "node:test";

import { GatewayDispatcher } from "../../src/daemon/dispatcher.js";
import { TargetRegistry } from "../../src/core/target-registry.js";
import type { SshRunInput } from "../../src/infra/openssh-executor.js";
import type {
  TaskCancelResult,
  TaskStartResult,
  TaskStatusResult,
  TaskTailResult,
} from "../../src/shared/protocol.js";
import {
  FakeSshExecutor,
  deferred,
  sshOutcome,
  testExecService,
} from "../helpers/fakes.js";

const context = { sessionId: "dispatcher-test-session" };

test("dispatcher routes strict target.check params through the fixed probe", async () => {
  const executor = new FakeSshExecutor(async (input) => {
    await input.outputSink?.append("stdout", Buffer.from("probe-01\n"));
    return sshOutcome({ exitCode: 0, durationMs: 3 });
  });
  const registry = new TargetRegistry({
    probe: {
      sshAlias: "internal-probe",
      platform: "linux",
      enabled: true,
      policy: { mode: "deny", maxTimeoutMs: 30_000 },
    },
  });
  const service = testExecService({ executor, registry });
  const dispatcher = new GatewayDispatcher(service);

  const result = await dispatcher.dispatch(
    "target.check",
    { target: "probe" },
    context,
    "check-1",
  );

  assert.deepEqual(result, {
    target: "probe",
    connected: true,
    termination: "exit",
    exitCode: 0,
    durationMs: 3,
    hostname: "probe-01",
  });
  assert.equal(executor.calls[0]?.command, "hostname");

  await assert.rejects(
    dispatcher.dispatch(
      "target.check",
      { target: "probe", command: "whoami" },
      context,
      "check-command-injection",
    ),
  );
  await assert.rejects(
    dispatcher.dispatch(
      "target.check",
      { target: "probe", timeoutMs: 60_000 },
      context,
      "check-timeout-injection",
    ),
  );
  assert.equal(executor.calls.length, 1);
});

test("dispatcher validates and routes daemon-owned task lifecycle methods", async (t) => {
  const started = deferred<SshRunInput>();
  const executor = new FakeSshExecutor(async (input) => {
    await input.outputSink?.append("stdout", Buffer.from("building\n", "utf8"));
    started.resolve(input);
    return new Promise((resolve) => {
      const finish = (): void => {
        resolve(
          sshOutcome({
            exitCode: null,
            aborted: true,
            durationMs: 9,
          }),
        );
      };
      if (input.signal?.aborted === true) finish();
      else input.signal?.addEventListener("abort", finish, { once: true });
    });
  });
  const registry = new TargetRegistry({
    builder: {
      sshAlias: "internal-builder",
      platform: "linux",
      enabled: true,
      policy: { mode: "full-access", maxTimeoutMs: 5_000 },
    },
  });
  const service = testExecService({ executor, registry });
  const dispatcher = new GatewayDispatcher(service);
  t.after(() => service.shutdown());

  await assert.rejects(
    dispatcher.dispatch(
      "task.start",
      {
        target: "builder",
        shell: "bash",
        script: "npm run build",
        host: "attacker.example",
      },
      context,
      "start-invalid",
    ),
  );
  assert.equal(executor.calls.length, 0);

  const task = (await dispatcher.dispatch(
    "task.start",
    {
      target: "builder",
      shell: "bash",
      cwd: "/srv/app",
      env: { NODE_ENV: "production" },
      script: "npm run build",
    },
    context,
    "start-valid",
  )) as TaskStartResult;
  const input = await started.promise;
  assert.equal(task.state, "running");

  dispatcher.disconnected(context);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(input.signal?.aborted, false);

  const observerContext = { sessionId: "dispatcher-observer-session" };
  const running = (await dispatcher.dispatch(
    "task.status",
    { runId: task.runId },
    observerContext,
    "status-running",
  )) as TaskStatusResult;
  assert.equal(running.state, "running");
  assert.equal(running.stdoutBytes, Buffer.byteLength("building\n", "utf8"));

  const tail = (await dispatcher.dispatch(
    "task.tail",
    { runId: task.runId },
    observerContext,
    "tail-running",
  )) as TaskTailResult;
  assert.equal(tail.stdout.text, "building\n");
  assert.equal(tail.eof, false);

  await assert.rejects(
    dispatcher.dispatch(
      "task.cancel",
      { runId: task.runId, requestId: "not-allowed" },
      observerContext,
      "cancel-invalid",
    ),
  );
  const cancelled = (await dispatcher.dispatch(
    "task.cancel",
    { runId: task.runId },
    observerContext,
    "cancel-valid",
  )) as TaskCancelResult;
  assert.equal(cancelled.accepted, true);

  let terminal: TaskStatusResult | undefined;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    terminal = (await dispatcher.dispatch(
      "task.status",
      { runId: task.runId },
      observerContext,
      `status-${attempt}`,
    )) as TaskStatusResult;
    if (terminal.state !== "running") break;
    await new Promise<void>((resolve) => setTimeout(resolve, 5));
  }
  assert.equal(terminal?.state, "cancelled");
  assert.equal(terminal?.termination, "cancel");
  assert.equal(executor.calls.length, 1);
});
