import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { GATEWAY_ERROR_CODES, GatewayError } from "../../src/shared/errors.js";
import {
  SshExecutionError,
  type SshRunInput,
} from "../../src/infra/openssh-executor.js";
import type { OutputSink as StoredOutputSink } from "../../src/core/output-store.js";
import { ExecServiceReloadError } from "../../src/core/exec-service.js";
import { TargetRegistry } from "../../src/core/target-registry.js";
import {
  POSIX_BASH_REMOTE_COMMAND,
  WINDOWS_POWERSHELL_REMOTE_COMMAND,
} from "../../src/core/remote-command.js";
import { MAX_COMMAND_BYTES } from "../../src/shared/protocol.js";
import {
  FakeAuditWriter,
  FakeSshExecutor,
  MemoryOutputStore,
  deferred,
  sshOutcome,
  testExecService,
  testRegistry,
} from "../helpers/fakes.js";

const caller = { sessionId: "test-session" };

function outcomeAfterAbort(
  input: SshRunInput,
  durationMs = 10,
): Promise<ReturnType<typeof sshOutcome>> {
  return new Promise((resolve) => {
    const finish = (): void => {
      resolve(
        sshOutcome({
          exitCode: null,
          aborted: true,
          durationMs,
        }),
      );
    };
    if (input.signal?.aborted === true) {
      finish();
      return;
    }
    input.signal?.addEventListener("abort", finish, { once: true });
  });
}

async function settlesWithin<Value>(
  operation: Promise<Value>,
  timeoutMs = 250,
): Promise<Value> {
  let timeout: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(
          () => reject(new Error("Operation did not settle before the deadline")),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

async function waitForTerminalTask(
  service: ReturnType<typeof testExecService>,
  runId: string,
): Promise<ReturnType<typeof service.taskStatus>> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const status = service.taskStatus(runId);
    if (status.state !== "running") return status;
    await new Promise<void>((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("Task did not reach a terminal state");
}

test("executes successfully only after the started audit record is durable", async () => {
  const auditEntered = deferred<void>();
  const auditGate = deferred<void>();
  const timeline: string[] = [];
  const audit = new FakeAuditWriter(async (event) => {
    if (event.event === "exec.started") {
      timeline.push("audit-started");
      auditEntered.resolve();
      await auditGate.promise;
      timeline.push("audit-durable");
    }
  });
  const executor = new FakeSshExecutor(async (input) => {
    timeline.push("spawn");
    await input.outputSink?.append("stdout", Buffer.from("ok\n"));
    await input.outputSink?.append("stderr", Buffer.from("warn"));
    return sshOutcome({ exitCode: 0, durationMs: 12.6 });
  });
  const service = testExecService({ executor, audit });

  const resultPromise = service.run(caller, "success-1", {
    target: "alpha",
    command: "echo ok",
    timeoutMs: 1_000,
  });
  await auditEntered.promise;

  assert.deepEqual(timeline, ["audit-started"]);
  assert.equal(executor.calls.length, 0);
  auditGate.resolve();

  const result = await resultPromise;
  assert.deepEqual(timeline, ["audit-started", "audit-durable", "spawn"]);
  assert.equal(executor.calls[0]?.sshAlias, "internal-alpha");
  assert.equal(executor.calls[0]?.command, "echo ok");
  assert.equal(executor.calls[0]?.maxCapturedOutputBytes, 0);
  assert.deepEqual(result, {
    requestId: "success-1",
    termination: "exit",
    exitCode: 0,
    durationMs: 13,
    stdout: { text: "ok\n", bytes: 3, inlineTruncated: false },
    stderr: { text: "warn", bytes: 4, inlineTruncated: false },
  });

  const started = audit.events[0];
  assert.ok(started?.event === "exec.started");
  assert.equal(
    started.commandSha256,
    createHash("sha256").update("echo ok", "utf8").digest("hex"),
  );
  assert.equal(started.commandBytes, 7);
  assert.equal(JSON.stringify(audit.events).includes("echo ok"), false);
  assert.deepEqual(
    audit.events.map((event) => event.event),
    ["exec.started", "exec.completed"],
  );
  const completed = audit.events[1];
  assert.ok(completed?.event === "exec.completed");
  assert.match(started.executionId, /^[0-9a-f-]{36}$/);
  assert.equal(completed.executionId, started.executionId);
  assert.equal(JSON.stringify(audit.events).includes("success-1"), false);
});

test("executes an arbitrary command only for an explicit full-access target", async () => {
  const command =
    'Write-Output "password=hunter2 & %PATH% | Get-Service | Select-Object -First 1"';
  const audit = new FakeAuditWriter();
  const executor = new FakeSshExecutor(async () => sshOutcome());
  const registry = new TargetRegistry({
    admin: {
      sshAlias: "internal-admin",
      platform: "windows",
      enabled: true,
      policy: { mode: "full-access", maxTimeoutMs: 5_000 },
    },
  });
  const service = testExecService({ executor, audit, registry });

  const result = await service.run(caller, "full-access-1", {
    target: "admin",
    command,
  });

  assert.equal(result.termination, "exit");
  assert.equal(
    executor.calls[0]?.command,
    WINDOWS_POWERSHELL_REMOTE_COMMAND,
  );
  assert.ok(executor.calls[0]?.stdin !== undefined);
  const wrapper = Buffer.from(executor.calls[0].stdin).toString("ascii");
  assert.equal(wrapper.includes(command), false);
  assert.equal(wrapper.includes("hunter2"), false);
  const started = audit.events[0];
  assert.ok(started?.event === "exec.started");
  assert.equal(
    started.commandSha256,
    createHash("sha256").update(command, "utf8").digest("hex"),
  );
  assert.equal(JSON.stringify(audit.events).includes(command), false);
  assert.equal(JSON.stringify(audit.events).includes("hunter2"), false);
});

test("executes structured shell context through the fixed remote entry point", async () => {
  const secret = "candidate-中文-&|'";
  const audit = new FakeAuditWriter();
  const executor = new FakeSshExecutor(async (input) => {
    await input.outputSink?.append("stdout", Buffer.from("built\n", "utf8"));
    return sshOutcome({ exitCode: 0, durationMs: 4 });
  });
  const registry = new TargetRegistry({
    builder: {
      sshAlias: "internal-builder",
      platform: "linux",
      enabled: true,
      policy: { mode: "full-access", maxTimeoutMs: 5_000 },
    },
  });
  const service = testExecService({ executor, audit, registry });

  const result = await service.run(caller, "structured-sync", {
    target: "builder",
    shell: "bash",
    cwd: "/srv/project with spaces",
    env: { RELEASE_TOKEN: secret },
    script: "printf '%s\\n' \"$RELEASE_TOKEN\"\nnpm run build",
    encoding: "utf-8",
  });

  assert.equal(result.termination, "exit");
  assert.equal(result.stdout.text, "built\n");
  assert.equal(executor.calls[0]?.sshAlias, "internal-builder");
  assert.equal(executor.calls[0]?.command, POSIX_BASH_REMOTE_COMMAND);
  assert.equal(
    Buffer.from(executor.calls[0]?.stdin ?? []).toString("utf8"),
    [
      `if ! export RELEASE_TOKEN='candidate-中文-&|'\\''' 2>/dev/null; then printf '%s\\n' 'Remote environment setup failed.' >&2; exit 1; fi`,
      `if ! cd -- '/srv/project with spaces' 2>/dev/null; then printf '%s\\n' 'Remote working directory is unavailable.' >&2; exit 1; fi`,
      "printf '%s\\n' \"$RELEASE_TOKEN\"",
      "npm run build",
      "",
    ].join("\n"),
  );
  assert.equal(JSON.stringify(audit.events).includes(secret), false);
});

test("daemon-owned tasks return immediately, stream UTF-8, and survive caller disconnect", async (t) => {
  const started = deferred<SshRunInput>();
  const release = deferred<void>();
  const completeOutput = Buffer.from("phase-1:中文\n", "utf8");
  const splitAt = Buffer.byteLength("phase-1:", "utf8") + 2;
  const executor = new FakeSshExecutor(async (input) => {
    await input.outputSink?.append("stdout", completeOutput.subarray(0, splitAt));
    started.resolve(input);
    await release.promise;
    await input.outputSink?.append("stdout", completeOutput.subarray(splitAt));
    await input.outputSink?.append("stderr", Buffer.from("warning\n", "utf8"));
    return sshOutcome({ exitCode: 0, durationMs: 41 });
  });
  const service = testExecService({ executor });
  t.after(() => service.shutdown());

  const task = service.startTask({
    target: "alpha",
    command: "long-command",
  });
  assert.equal(task.state, "running");
  assert.equal(task.kind, "exec");
  assert.match(task.runId, /^[A-Za-z0-9_-]{43}$/u);

  const input = await started.promise;
  service.disconnect("mcp-request-session");
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(input.signal?.aborted, false);
  assert.throws(
    () => service.beginReload(),
    (error: unknown) =>
      error instanceof ExecServiceReloadError &&
      error.code === "ACTIVE_EXECUTIONS",
  );

  const firstTail = service.taskTail(task.runId, undefined, 64);
  assert.equal(firstTail.state, "running");
  assert.equal(firstTail.stdout.text, "phase-1:");
  assert.equal(firstTail.stdout.bytesRead, Buffer.byteLength("phase-1:", "utf8"));
  assert.equal(firstTail.stdout.hadDecodingErrors, false);
  assert.equal(firstTail.eof, false);

  release.resolve();
  const status = await waitForTerminalTask(service, task.runId);
  assert.equal(status.state, "succeeded");
  assert.equal(status.termination, "exit");
  assert.equal(status.exitCode, 0);
  assert.equal(status.stdoutBytes, completeOutput.byteLength);
  assert.equal(status.stderrBytes, Buffer.byteLength("warning\n", "utf8"));
  assert.deepEqual(status.result, {
    durationMs: 41,
    stdoutBytes: completeOutput.byteLength,
    stderrBytes: Buffer.byteLength("warning\n", "utf8"),
  });

  const finalTail = service.taskTail(task.runId, firstTail.nextCursor, 64);
  assert.equal(finalTail.state, "succeeded");
  assert.equal(finalTail.stdout.text, "中文\n");
  assert.equal(finalTail.stderr.text, "warning\n");
  assert.equal(finalTail.eof, true);
});

test("daemon-owned task cancellation and authorization timeout become stable terminal states", async (t) => {
  const starts: SshRunInput[] = [];
  const bothStarted = deferred<void>();
  const executor = new FakeSshExecutor(async (input) => {
    starts.push(input);
    if (starts.length === 2) bothStarted.resolve();
    return outcomeAfterAbort(input, 18);
  });
  const registry = new TargetRegistry({
    admin: {
      sshAlias: "internal-admin",
      platform: "linux",
      enabled: true,
      policy: { mode: "full-access", maxTimeoutMs: 5_000 },
    },
  });
  const service = testExecService({ executor, registry });
  t.after(() => service.shutdown());

  const cancelledTask = service.startTask({
    target: "admin",
    shell: "bash",
    script: "sleep 60",
    encoding: "utf-8",
    timeoutMs: 5_000,
  });
  const timedOutTask = service.startTask({
    target: "admin",
    shell: "bash",
    script: "sleep 60",
    encoding: "utf-8",
    timeoutMs: 25,
  });
  await bothStarted.promise;

  assert.deepEqual(service.cancelTask(cancelledTask.runId), {
    runId: cancelledTask.runId,
    accepted: true,
    state: "running",
  });
  const [cancelled, timedOut] = await Promise.all([
    waitForTerminalTask(service, cancelledTask.runId),
    waitForTerminalTask(service, timedOutTask.runId),
  ]);
  assert.equal(cancelled.state, "cancelled");
  assert.equal(cancelled.termination, "cancel");
  assert.equal(cancelled.exitCode, null);
  assert.deepEqual(service.cancelTask(cancelledTask.runId), {
    runId: cancelledTask.runId,
    accepted: false,
    state: "cancelled",
  });
  assert.equal(timedOut.state, "timed_out");
  assert.equal(timedOut.termination, "timeout");
  assert.equal(timedOut.exitCode, null);
  assert.equal(starts.every((input) => input.signal?.aborted === true), true);
});

test("rejects a Windows command over the protocol limit without auditing or spawning", () => {
  const audit = new FakeAuditWriter();
  const executor = new FakeSshExecutor(async () => sshOutcome());
  const registry = new TargetRegistry({
    admin: {
      sshAlias: "internal-admin",
      platform: "windows",
      enabled: true,
      policy: { mode: "full-access", maxTimeoutMs: 5_000 },
    },
  });
  const service = testExecService({ executor, audit, registry });

  assert.throws(
    () =>
      service.run(caller, "full-access-too-long", {
        target: "admin",
        command: "x".repeat(MAX_COMMAND_BYTES + 1),
      }),
    (error: unknown) =>
      error instanceof GatewayError &&
      error.code === GATEWAY_ERROR_CODES.invalidParams,
  );
  assert.equal(executor.calls.length, 0);
  assert.deepEqual(audit.events, []);
});

test("times out an execution and aborts its executor", async () => {
  const started = deferred<SshRunInput>();
  const audit = new FakeAuditWriter();
  const executor = new FakeSshExecutor(async (input) => {
    started.resolve(input);
    return outcomeAfterAbort(input, 25);
  });
  const service = testExecService({
    executor,
    audit,
    registry: testRegistry(100),
  });

  const resultPromise = service.run(caller, "timeout-1", {
    target: "alpha",
    command: "sleep",
    timeoutMs: 15,
  });
  const input = await started.promise;
  const result = await resultPromise;

  assert.equal(input.signal?.aborted, true);
  assert.equal(result.termination, "timeout");
  assert.equal(result.exitCode, null);
  assert.deepEqual(
    audit.events.map((event) => event.event),
    ["exec.started", "exec.cancelled", "exec.completed"],
  );
  const cancelled = audit.events[1];
  assert.ok(cancelled?.event === "exec.cancelled");
  assert.equal(cancelled.reasonCode, "timeout");
});

test("cancels an execution by session and request ID", async () => {
  const started = deferred<SshRunInput>();
  const audit = new FakeAuditWriter();
  const executor = new FakeSshExecutor(async (input) => {
    started.resolve(input);
    return outcomeAfterAbort(input);
  });
  const service = testExecService({ executor, audit });

  const resultPromise = service.run(caller, "cancel-1", {
    target: "alpha",
    command: "long-command",
  });
  const input = await started.promise;

  assert.equal(service.cancel("other-session", "cancel-1"), false);
  assert.equal(service.cancel(caller.sessionId, "cancel-1"), true);
  const result = await resultPromise;

  assert.equal(input.signal?.aborted, true);
  assert.equal(result.termination, "cancel");
  assert.equal(result.exitCode, null);
  const cancelled = audit.events.find(
    (event) => event.event === "exec.cancelled",
  );
  assert.ok(cancelled?.event === "exec.cancelled");
  assert.equal(cancelled.reasonCode, "cancel");
});

test("cancellation does not wait for a permanently blocked output sink", async () => {
  const appendStarted = deferred<void>();
  const neverAppend = new Promise<void>(() => undefined);
  const neverAbort = new Promise<void>(() => undefined);
  let cancelCalls = 0;
  let abortCalls = 0;
  let finalizeCalls = 0;
  const sink: StoredOutputSink = {
    append: () => {
      appendStarted.resolve();
      return neverAppend;
    },
    finalize: () => {
      finalizeCalls += 1;
      return new Promise(() => undefined);
    },
    cancel: () => {
      cancelCalls += 1;
    },
    abort: () => {
      abortCalls += 1;
      return neverAbort;
    },
  };
  const outputStore = {
    create: async () => sink,
  } as unknown as MemoryOutputStore;
  const executor = new FakeSshExecutor(async (input) => {
    void Promise.resolve(
      input.outputSink?.append("stdout", Buffer.from("partial")),
    ).catch(() => undefined);
    return outcomeAfterAbort(input);
  });
  const service = testExecService({ executor, outputStore });

  const execution = service.run(caller, "blocked-sink-cancel", {
    target: "alpha",
    command: "long-command",
  });
  await appendStarted.promise;
  assert.equal(service.cancel(caller.sessionId, "blocked-sink-cancel"), true);

  const result = await settlesWithin(execution);
  assert.equal(result.termination, "cancel");
  assert.deepEqual(result.stdout, {
    text: "",
    bytes: 0,
    inlineTruncated: false,
  });
  assert.equal(cancelCalls, 1);
  assert.equal(abortCalls, 1);
  assert.equal(finalizeCalls, 0);
});

test("timeout does not wait for a permanently blocked output sink", async () => {
  const appendStarted = deferred<void>();
  const neverSettles = new Promise<void>(() => undefined);
  let cancelCalls = 0;
  let abortCalls = 0;
  let finalizeCalls = 0;
  const sink: StoredOutputSink = {
    append: () => {
      appendStarted.resolve();
      return neverSettles;
    },
    finalize: () => {
      finalizeCalls += 1;
      return new Promise(() => undefined);
    },
    cancel: () => {
      cancelCalls += 1;
    },
    abort: () => {
      abortCalls += 1;
      return neverSettles;
    },
  };
  const outputStore = {
    create: async () => sink,
  } as unknown as MemoryOutputStore;
  const executor = new FakeSshExecutor(async (input) => {
    void Promise.resolve(
      input.outputSink?.append("stdout", Buffer.from("partial")),
    ).catch(() => undefined);
    return outcomeAfterAbort(input);
  });
  const service = testExecService({
    executor,
    outputStore,
    registry: testRegistry(100),
  });

  const execution = service.run(caller, "blocked-sink-timeout", {
    target: "alpha",
    command: "long-command",
    timeoutMs: 15,
  });
  await appendStarted.promise;
  const result = await settlesWithin(execution);

  assert.equal(result.termination, "timeout");
  assert.equal(cancelCalls, 1);
  assert.equal(abortCalls, 1);
  assert.equal(finalizeCalls, 0);
});

test("spawn failures quarantine a permanently blocked output sink", async () => {
  const appendStarted = deferred<void>();
  const neverSettles = new Promise<void>(() => undefined);
  let cancelCalls = 0;
  let abortCalls = 0;
  let finalizeCalls = 0;
  const sink: StoredOutputSink = {
    append: () => {
      appendStarted.resolve();
      return neverSettles;
    },
    finalize: () => {
      finalizeCalls += 1;
      return new Promise(() => undefined);
    },
    cancel: () => {
      cancelCalls += 1;
    },
    abort: () => {
      abortCalls += 1;
      return neverSettles;
    },
  };
  const outputStore = {
    create: async () => sink,
  } as unknown as MemoryOutputStore;
  const executor = new FakeSshExecutor(async (input) => {
    void Promise.resolve(
      input.outputSink?.append("stderr", Buffer.from("uncertain")),
    ).catch(() => undefined);
    throw new SshExecutionError("spawn failed");
  });
  const service = testExecService({ executor, outputStore });

  const execution = service.run(caller, "blocked-sink-error", {
    target: "alpha",
    command: "echo ok",
  });
  await appendStarted.promise;
  const result = await settlesWithin(execution);

  assert.equal(result.termination, "spawn_error");
  assert.deepEqual(result.stderr, {
    text: "",
    bytes: 0,
    inlineTruncated: false,
  });
  assert.equal(cancelCalls, 1);
  assert.equal(abortCalls, 1);
  assert.equal(finalizeCalls, 0);
});

test("returns capped output and an opaque reference when storage is exhausted", async () => {
  let runInput: SshRunInput | undefined;
  const outputStore = new MemoryOutputStore({
    inlineBytesPerStream: 2,
    maxStoredBytes: 4,
  });
  const audit = new FakeAuditWriter();
  const executor = new FakeSshExecutor(async (input) => {
    runInput = input;
    await input.outputSink?.append("stdout", Buffer.from("abcdef"));
    return sshOutcome();
  });
  const service = testExecService({ executor, outputStore, audit });

  const result = await service.run(caller, "output-limit-1", {
    target: "alpha",
    command: "emit-output",
  });

  assert.equal(runInput?.signal?.aborted, true);
  assert.equal(result.termination, "output_limit");
  assert.equal(result.exitCode, null);
  assert.deepEqual(result.stdout, {
    text: "ab",
    bytes: 4,
    inlineTruncated: true,
  });
  assert.deepEqual(result.stderr, {
    text: "",
    bytes: 0,
    inlineTruncated: false,
  });
  assert.match(result.outputRef ?? "", /^[A-Za-z0-9_-]{43}$/);
  assert.equal(result.outputExpiresAt, "2099-01-01T00:00:00.000Z");

  const completed = audit.events.at(-1);
  assert.ok(completed?.event === "exec.completed");
  assert.equal(completed.termination, "output_limit");
  assert.equal(completed.truncated, true);
});

test("reads retained UTF-8 text with bound cursors and legacy offset alignment", async () => {
  const payload = Buffer.from("ab\u4e2d\ud83d\ude00z", "utf8");
  const outputStore = new MemoryOutputStore({ inlineBytesPerStream: 1 });
  const executor = new FakeSshExecutor(async (input) => {
    await input.outputSink?.append("stdout", payload);
    return sshOutcome();
  });
  const service = testExecService({ executor, outputStore });
  const execution = await service.run(caller, "cursor-output-1", {
    target: "alpha",
    command: "emit-output",
  });
  assert.ok(execution.outputRef);

  const pages: string[] = [];
  let cursor: string | undefined;
  for (let pageNumber = 0; pageNumber < 8; pageNumber += 1) {
    const page = await service.readOutputText({
      outputRef: execution.outputRef,
      stream: "stdout",
      ...(cursor === undefined ? {} : { cursor }),
      limit: 1,
    });
    pages.push(page.text);
    assert.equal(page.hadDecodingErrors, false);
    assert.equal(page.text.includes("\ufffd"), false);
    assert.equal("nextOffset" in page, false);
    if (page.nextCursor === null) break;
    assert.ok(page.nextCursor);
    cursor = page.nextCursor;
  }
  assert.equal(pages.join(""), payload.toString("utf8"));

  const legacy = await service.readOutputText({
    outputRef: execution.outputRef,
    stream: "stdout",
    offset: 3,
    limit: 4,
  });
  assert.equal(legacy.text, "\ud83d\ude00");
  assert.equal(legacy.hadDecodingErrors, false);
  assert.equal(legacy.nextOffset, 9);
  assert.equal("nextCursor" in legacy, false);

  assert.ok(cursor);
  await assert.rejects(
    service.readOutputText({
      outputRef: execution.outputRef,
      stream: "stderr",
      cursor,
      limit: 4,
    }),
    (error: unknown) => {
      assert.ok(error instanceof GatewayError);
      assert.equal(error.code, GATEWAY_ERROR_CODES.invalidParams);
      return true;
    },
  );
});

test("rejects work beyond the global concurrency limit without spawning it", async () => {
  const started = deferred<SshRunInput>();
  const executor = new FakeSshExecutor(async (input) => {
    started.resolve(input);
    return outcomeAfterAbort(input);
  });
  const service = testExecService({
    executor,
    maxConcurrentExecutions: 1,
  });

  const firstResult = service.run(caller, "concurrency-1", {
    target: "alpha",
    command: "first",
  });
  await started.promise;

  await assert.rejects(
    service.run(caller, "concurrency-2", {
      target: "alpha",
      command: "second",
    }),
    (error: unknown) => {
      assert.ok(error instanceof GatewayError);
      assert.equal(error.code, GATEWAY_ERROR_CODES.executionLimitReached);
      assert.deepEqual(error.details, { maximum: 1 });
      return true;
    },
  );
  assert.equal(executor.calls.length, 1);

  assert.equal(service.cancel(caller.sessionId, "concurrency-1"), true);
  assert.equal((await firstResult).termination, "cancel");
});

test("connectivity check runs the fixed platform command and returns no stderr", async () => {
  const audit = new FakeAuditWriter();
  const executor = new FakeSshExecutor(async (input) => {
    await input.outputSink?.append(
      "stdout",
      Buffer.from("WIN-BUILD-01\r\nignored second line\r\n", "utf8"),
    );
    await input.outputSink?.append(
      "stderr",
      Buffer.from("remote diagnostic must stay private", "utf8"),
    );
    return sshOutcome({ exitCode: 0, durationMs: 7.6 });
  });
  const registry = new TargetRegistry({
    probe: {
      sshAlias: "internal-probe",
      platform: "windows",
      enabled: true,
      policy: { mode: "deny", maxTimeoutMs: 30_000 },
    },
  });
  const service = testExecService({ executor, audit, registry });

  const result = await service.check(caller, "check-success", {
    target: "probe",
  });

  assert.deepEqual(result, {
    target: "probe",
    connected: true,
    termination: "exit",
    exitCode: 0,
    durationMs: 8,
    hostname: "WIN-BUILD-01",
  });
  assert.equal(JSON.stringify(result).includes("diagnostic"), false);
  assert.equal(executor.calls[0]?.sshAlias, "internal-probe");
  assert.equal(
    executor.calls[0]?.command,
    WINDOWS_POWERSHELL_REMOTE_COMMAND,
  );
  assert.ok(executor.calls[0]?.stdin !== undefined);
  const started = audit.events[0];
  assert.ok(started?.event === "exec.started");
  assert.equal(
    started.commandSha256,
    createHash("sha256").update("hostname", "utf8").digest("hex"),
  );
  assert.deepEqual(
    audit.events.map((event) => event.event),
    ["exec.started", "exec.completed"],
  );
});

test("connectivity check shares cancellation, concurrency, and reload gates", async () => {
  const started = deferred<SshRunInput>();
  const executor = new FakeSshExecutor(async (input) => {
    started.resolve(input);
    return outcomeAfterAbort(input);
  });
  const registry = new TargetRegistry({
    probe: {
      sshAlias: "internal-probe",
      platform: "linux",
      enabled: true,
      policy: { mode: "deny", maxTimeoutMs: 30_000 },
    },
  });
  const service = testExecService({
    executor,
    registry,
    maxConcurrentExecutions: 1,
  });

  const check = service.check(caller, "check-active", { target: "probe" });
  await started.promise;
  assert.throws(
    () => service.beginReload(),
    (error: unknown) =>
      error instanceof ExecServiceReloadError &&
      error.code === "ACTIVE_EXECUTIONS",
  );
  await assert.rejects(
    service.check(caller, "check-overflow", { target: "probe" }),
    (error: unknown) =>
      error instanceof GatewayError &&
      error.code === GATEWAY_ERROR_CODES.executionLimitReached,
  );
  assert.equal(service.cancel(caller.sessionId, "check-active"), true);
  assert.deepEqual(await check, {
    target: "probe",
    connected: false,
    termination: "cancel",
    exitCode: null,
    durationMs: 10,
  });

  const reload = service.beginReload();
  await assert.rejects(
    service.check(caller, "check-reload", { target: "probe" }),
    /configuration is reloading/iu,
  );
  reload.release();
  assert.equal(executor.calls.length, 1);
});

test("connectivity check enforces output limits without exposing output", async () => {
  let runInput: SshRunInput | undefined;
  const outputStore = new MemoryOutputStore({
    inlineBytesPerStream: 2,
    maxStoredBytes: 4,
  });
  const executor = new FakeSshExecutor(async (input) => {
    runInput = input;
    await input.outputSink?.append("stdout", Buffer.from("abcdef"));
    return sshOutcome();
  });
  const service = testExecService({ executor, outputStore });

  const result = await service.check(caller, "check-output-limit", {
    target: "alpha",
  });

  assert.equal(runInput?.signal?.aborted, true);
  assert.deepEqual(result, {
    target: "alpha",
    connected: false,
    termination: "output_limit",
    exitCode: null,
    durationMs: result.durationMs,
  });
  assert.equal("stdout" in result, false);
  assert.equal("stderr" in result, false);
  assert.equal("outputRef" in result, false);
});

test("connectivity checks expose only closed failure reasons and exec.run strips them", async () => {
  const privateDiagnostic = "PRIVATE-REMOTE-STDERR-MUST-NOT-LEAK";
  let callCount = 0;
  const executor = new FakeSshExecutor(async (input) => {
    callCount += 1;
    await input.outputSink?.append(
      "stderr",
      Buffer.from(privateDiagnostic, "utf8"),
    );
    return sshOutcome({
      exitCode: 255,
      durationMs: 4,
      failureReason:
        callCount === 3
          ? ("remote-controlled-text" as never)
          : "accessclient-session-unavailable",
    });
  });
  const service = testExecService({ executor });

  const check = await service.check(caller, "check-safe-reason", {
    target: "alpha",
  });
  assert.deepEqual(check, {
    target: "alpha",
    connected: false,
    termination: "exit",
    exitCode: 255,
    durationMs: 4,
    failureReason: "accessclient-session-unavailable",
  });
  assert.equal(JSON.stringify(check).includes(privateDiagnostic), false);
  assert.equal("stderr" in check, false);
  assert.equal("outputRef" in check, false);

  const execution = await service.run(caller, "exec-private-reason", {
    target: "alpha",
    command: "echo ok",
  });
  assert.equal("failureReason" in execution, false);
  assert.equal(execution.stderr.text, privateDiagnostic);

  const untrustedReason = await service.check(caller, "check-untrusted-reason", {
    target: "alpha",
  });
  assert.equal("failureReason" in untrustedReason, false);
});

test("connectivity check truncates safe hostnames and omits unsafe text", async () => {
  let callCount = 0;
  const executor = new FakeSshExecutor(async (input) => {
    callCount += 1;
    await input.outputSink?.append(
      "stdout",
      Buffer.from(
        callCount === 1
          ? `${"a".repeat(300)}\nignored\n`
          : "<script>not-a-hostname</script>\n",
        "utf8",
      ),
    );
    return sshOutcome({ exitCode: 0 });
  });
  const service = testExecService({ executor });

  const truncated = await service.check(caller, "check-long-hostname", {
    target: "alpha",
  });
  assert.equal(truncated.hostname, "a".repeat(255));

  const unsafe = await service.check(caller, "check-unsafe-hostname", {
    target: "alpha",
  });
  assert.equal(unsafe.connected, true);
  assert.equal("hostname" in unsafe, false);
});
