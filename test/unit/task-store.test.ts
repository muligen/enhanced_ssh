import assert from "node:assert/strict";
import test from "node:test";

import {
  TaskStore,
  type TaskCompletion,
  type TaskStoreOptions,
  type TaskWorkerContext,
} from "../../src/core/task-store.js";
import { GATEWAY_ERROR_CODES, GatewayError } from "../../src/shared/errors.js";
import {
  taskStartResultSchema,
  taskStatusResultSchema,
  taskTailResultSchema,
  type TaskState,
} from "../../src/shared/protocol.js";

interface Deferred<Value> {
  readonly promise: Promise<Value>;
  resolve(value: Value): void;
  reject(error: unknown): void;
}

function deferred<Value>(): Deferred<Value> {
  let resolvePromise!: (value: Value) => void;
  let rejectPromise!: (error: unknown) => void;
  const promise = new Promise<Value>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  return {
    promise,
    resolve: resolvePromise,
    reject: rejectPromise,
  };
}

interface TestStoreOptions {
  readonly ttlMs?: number;
  readonly maxRetainedTasks?: number;
  readonly maxConcurrentTasks?: number;
  readonly maxLogBytesPerStream?: number;
  readonly now?: () => number;
}

function createStore(options: TestStoreOptions = {}): TaskStore {
  let nextRunId = 1;
  const storeOptions: TaskStoreOptions = {
    ttlMs: options.ttlMs ?? 1_000,
    maxRetainedTasks: options.maxRetainedTasks ?? 16,
    maxConcurrentTasks: options.maxConcurrentTasks ?? 4,
    maxLogBytesPerStream: options.maxLogBytesPerStream ?? 1_024,
    createRunId: () =>
      Buffer.alloc(32, nextRunId++ % 256).toString("base64url"),
    ...(options.now === undefined ? {} : { now: options.now }),
  };
  return new TaskStore(storeOptions);
}

async function waitForState(
  store: TaskStore,
  runId: string,
  expected: TaskState,
): Promise<ReturnType<TaskStore["status"]>> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const status = store.status(runId);
    if (status.state === expected) {
      return status;
    }
    await delay(2);
  }
  throw new Error(`Task did not reach state ${expected}`);
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function waitForAbort(signal: AbortSignal): Promise<void> {
  if (signal.aborted) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    signal.addEventListener("abort", () => resolve(), { once: true });
  });
}

function hasGatewayCode(code: string): (error: unknown) => boolean {
  return (error: unknown): boolean =>
    error instanceof GatewayError && error.code === code;
}

test("start returns a running handle before invoking or completing the worker", async () => {
  let now = Date.parse("2026-08-07T01:02:03.000Z");
  const store = createStore({ now: () => now });
  const entered = deferred<TaskWorkerContext>();
  const release = deferred<TaskCompletion>();
  let invoked = false;

  const started = store.start({
    kind: "exec",
    target: "build-windows",
    worker: async (context) => {
      invoked = true;
      entered.resolve(context);
      return release.promise;
    },
  });

  assert.equal(invoked, false);
  assert.equal(Object.isFrozen(started), true);
  assert.equal(started.state, "running");
  assert.equal(started.startedAt, "2026-08-07T01:02:03.000Z");
  taskStartResultSchema.parse(started);
  const running = store.status(started.runId);
  assert.equal(running.state, "running");
  assert.equal(running.durationMs, 0);

  const context = await entered.promise;
  assert.equal(invoked, true);
  context.append("stdout", "ready\n");
  now += 25;
  release.resolve({
    termination: "exit",
    exitCode: 0,
    result: { artifact: "image-id" },
  });

  const completed = await waitForState(store, started.runId, "succeeded");
  assert.equal(completed.durationMs, 25);
  assert.equal(completed.termination, "exit");
  assert.equal(completed.exitCode, 0);
  assert.deepEqual(completed.result, { artifact: "image-id" });
  assert.equal(completed.stdoutBytes, 6);
  taskStatusResultSchema.parse(completed);
});

test("tail follows stdout and stderr incrementally with an opaque cursor", async () => {
  const store = createStore();
  const entered = deferred<TaskWorkerContext>();
  const release = deferred<TaskCompletion>();
  const started = store.start({
    kind: "exec",
    target: "logs",
    worker: async (context) => {
      entered.resolve(context);
      return release.promise;
    },
  });
  const context = await entered.promise;

  context.append("stdout", "one");
  context.append("stderr", Buffer.from("warn", "utf8"));
  const first = store.tail(started.runId, undefined, 64);
  assert.equal(first.state, "running");
  assert.equal(first.stdout.text, "one");
  assert.equal(first.stderr.text, "warn");
  assert.equal(first.stdout.bytesRead, 3);
  assert.equal(first.stderr.bytesRead, 4);
  assert.equal(first.eof, false);
  taskTailResultSchema.parse(first);

  context.append("stdout", "-two");
  context.append("stderr", "-more");
  const second = store.tail(started.runId, first.nextCursor, 64);
  assert.equal(second.stdout.text, "-two");
  assert.equal(second.stderr.text, "-more");
  assert.equal(second.stdout.totalBytes, 7);
  assert.equal(second.stderr.totalBytes, 9);
  assert.equal(second.stdout.droppedBytes, 0);
  assert.equal(second.stderr.droppedBytes, 0);

  assert.throws(
    () => store.tail(started.runId, "not-a-cursor", 64),
    hasGatewayCode(GATEWAY_ERROR_CODES.invalidParams),
  );
  const futureCursor = Buffer.from(
    JSON.stringify({ v: 1, o: 999, e: 0 }),
    "utf8",
  ).toString("base64url");
  assert.throws(
    () => store.tail(started.runId, futureCursor, 64),
    hasGatewayCode(GATEWAY_ERROR_CODES.invalidParams),
  );

  release.resolve({ termination: "exit", exitCode: 0 });
  await waitForState(store, started.runId, "succeeded");
  const final = store.tail(started.runId, second.nextCursor, 64);
  assert.equal(final.stdout.text, "");
  assert.equal(final.stderr.text, "");
  assert.equal(final.eof, true);
  taskTailResultSchema.parse(final);
});

test("tail preserves UTF-8 characters split across appends and pages", async () => {
  const store = createStore();
  const entered = deferred<TaskWorkerContext>();
  const release = deferred<TaskCompletion>();
  const started = store.start({
    kind: "exec",
    target: "unicode-live",
    worker: async (context) => {
      entered.resolve(context);
      return release.promise;
    },
  });
  const context = await entered.promise;
  const chinese = Buffer.from("\u4e2d", "utf8");
  context.append("stdout", chinese.subarray(0, 2));

  const incomplete = store.tail(started.runId, undefined, 32);
  assert.equal(incomplete.stdout.text, "");
  assert.equal(incomplete.stdout.bytesRead, 0);
  assert.equal(incomplete.stdout.hadDecodingErrors, false);

  context.append("stdout", Buffer.concat([chinese.subarray(2), Buffer.from("A")]));
  const complete = store.tail(started.runId, incomplete.nextCursor, 32);
  assert.equal(complete.stdout.text, "\u4e2dA");
  assert.equal(complete.stdout.bytesRead, 4);
  assert.equal(complete.stdout.hadDecodingErrors, false);

  context.append("stdout", Buffer.from([0xff]));
  const invalid = store.tail(started.runId, complete.nextCursor, 32);
  assert.equal(invalid.stdout.text, "\ufffd");
  assert.equal(invalid.stdout.bytesRead, 1);
  assert.equal(invalid.stdout.hadDecodingErrors, true);
  release.resolve({ termination: "exit", exitCode: 0 });
  await waitForState(store, started.runId, "succeeded");

  const paged = store.start({
    kind: "exec",
    target: "unicode-pages",
    worker: async (workerContext) => {
      workerContext.append("stdout", "\u4e2d\u6587");
      return { termination: "exit", exitCode: 0 };
    },
  });
  await waitForState(store, paged.runId, "succeeded");
  const firstPage = store.tail(paged.runId, undefined, 4);
  assert.equal(firstPage.stdout.text, "\u4e2d");
  assert.equal(firstPage.stdout.bytesRead, 3);
  assert.equal(firstPage.stdout.hadDecodingErrors, false);
  assert.equal(firstPage.eof, false);
  const secondPage = store.tail(paged.runId, firstPage.nextCursor, 4);
  assert.equal(secondPage.stdout.text, "\u6587");
  assert.equal(secondPage.stdout.bytesRead, 3);
  assert.equal(secondPage.stdout.hadDecodingErrors, false);
  assert.equal(secondPage.eof, true);
});

test("tail completes a UTF-8 code point when the requested page is smaller", async () => {
  for (const limit of [1, 2, 3]) {
    const store = createStore();
    const started = store.start({
      kind: "exec",
      target: `unicode-limit-${limit}`,
      worker: async (context) => {
        context.append("stdout", "\u4e2d\ud83d\ude00");
        return { termination: "exit", exitCode: 0 };
      },
    });
    await waitForState(store, started.runId, "succeeded");

    const first = store.tail(started.runId, undefined, limit);
    assert.equal(first.stdout.text, "\u4e2d", `limit ${limit}`);
    assert.equal(first.stdout.bytesRead, 3, `limit ${limit}`);
    assert.equal(first.stdout.hadDecodingErrors, false, `limit ${limit}`);
    assert.equal(first.eof, false, `limit ${limit}`);

    const second = store.tail(started.runId, first.nextCursor, limit);
    assert.equal(second.stdout.text, "\ud83d\ude00", `limit ${limit}`);
    assert.equal(second.stdout.bytesRead, 4, `limit ${limit}`);
    assert.equal(second.stdout.hadDecodingErrors, false, `limit ${limit}`);
    assert.equal(second.eof, true, `limit ${limit}`);
    assert.notEqual(second.nextCursor, first.nextCursor, `limit ${limit}`);
  }
});

test("task cursors are versioned and bound to their runId", async () => {
  const store = createStore();
  const firstTask = store.start({
    kind: "exec",
    target: "cursor-first",
    worker: async (context) => {
      context.append("stdout", "abc");
      return { termination: "exit", exitCode: 0 };
    },
  });
  const secondTask = store.start({
    kind: "exec",
    target: "cursor-second",
    worker: async (context) => {
      context.append("stdout", "XYZ");
      return { termination: "exit", exitCode: 0 };
    },
  });
  await Promise.all([
    waitForState(store, firstTask.runId, "succeeded"),
    waitForState(store, secondTask.runId, "succeeded"),
  ]);

  const firstPage = store.tail(firstTask.runId, undefined, 1);
  const decoded = JSON.parse(
    Buffer.from(firstPage.nextCursor, "base64url").toString("utf8"),
  ) as Record<string, unknown>;
  assert.equal(decoded["v"], 2);
  assert.equal(typeof decoded["b"], "string");
  assert.throws(
    () => store.tail(secondTask.runId, firstPage.nextCursor, 64),
    hasGatewayCode(GATEWAY_ERROR_CODES.invalidParams),
  );

  const continued = store.tail(firstTask.runId, firstPage.nextCursor, 64);
  assert.equal(continued.stdout.text, "bc");
  assert.equal(continued.eof, true);
});

test("rolling logs report discarded bytes and resume from retained offsets", async () => {
  const store = createStore({ maxLogBytesPerStream: 5 });
  const entered = deferred<TaskWorkerContext>();
  const release = deferred<TaskCompletion>();
  const started = store.start({
    kind: "exec",
    target: "rolling",
    worker: async (context) => {
      entered.resolve(context);
      return release.promise;
    },
  });
  const context = await entered.promise;
  context.append("stdout", "abcdefghi");

  const first = store.tail(started.runId, undefined, 64);
  assert.equal(first.stdout.text, "efghi");
  assert.equal(first.stdout.bytesRead, 5);
  assert.equal(first.stdout.totalBytes, 9);
  assert.equal(first.stdout.droppedBytes, 4);

  context.append("stdout", "jkl");
  const continued = store.tail(started.runId, first.nextCursor, 64);
  assert.equal(continued.stdout.text, "jkl");
  assert.equal(continued.stdout.droppedBytes, 0);
  assert.equal(continued.stdout.totalBytes, 12);

  const replayedFromStart = store.tail(started.runId, undefined, 64);
  assert.equal(replayedFromStart.stdout.text, "hijkl");
  assert.equal(replayedFromStart.stdout.droppedBytes, 7);
  release.resolve({ termination: "exit", exitCode: 0 });
  await waitForState(store, started.runId, "succeeded");
});

test("the first cancellation reason wins and normal worker completion cannot override it", async () => {
  const store = createStore();
  const aborted = deferred<void>();
  const release = deferred<TaskCompletion>();
  const started = store.start({
    kind: "exec",
    target: "cancelled",
    timeoutMs: 20,
    worker: async ({ signal }) => {
      await waitForAbort(signal);
      aborted.resolve();
      return release.promise;
    },
  });

  assert.deepEqual(store.cancel(started.runId), {
    runId: started.runId,
    accepted: true,
    state: "running",
  });
  await aborted.promise;
  await delay(30);
  assert.equal(store.cancel(started.runId).accepted, false);
  release.resolve({ termination: "exit", exitCode: 0 });

  const status = await waitForState(store, started.runId, "cancelled");
  assert.equal(status.termination, "cancel");
  assert.equal(status.exitCode, null);
  assert.equal(status.error, undefined);
  assert.equal(store.cancel(started.runId).accepted, false);
});

test("timeout owns the terminal state and suppresses abort rejection details", async () => {
  const store = createStore();
  const aborted = deferred<void>();
  const release = deferred<void>();
  const secret = "password=never-return-this";
  const started = store.start({
    kind: "exec",
    target: "timeout",
    timeoutMs: 10,
    worker: async ({ signal }) => {
      await waitForAbort(signal);
      aborted.resolve();
      await release.promise;
      throw new Error(secret);
    },
  });

  await aborted.promise;
  assert.equal(store.cancel(started.runId).accepted, false);
  release.resolve();
  const status = await waitForState(store, started.runId, "timed_out");
  assert.equal(status.termination, "timeout");
  assert.equal(status.exitCode, null);
  assert.equal(status.error, undefined);
  assert.equal(JSON.stringify(status).includes(secret), false);
});

test("unexpected failures are redacted while public Gateway errors stay stable", async () => {
  const secret = "token=top-secret";
  const internalStore = createStore();
  const internal = internalStore.start({
    kind: "exec",
    target: "internal-failure",
    worker: async () => {
      throw new Error(secret);
    },
  });
  const internalStatus = await waitForState(
    internalStore,
    internal.runId,
    "failed",
  );
  assert.deepEqual(internalStatus.error, {
    gatewayCode: GATEWAY_ERROR_CODES.internalError,
    message: "Task failed inside the SSH Gateway",
  });
  assert.equal(JSON.stringify(internalStatus).includes(secret), false);

  const publicStore = createStore();
  const publicFailure = publicStore.start({
    kind: "exec",
    target: "public-failure",
    worker: async () => {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.commandDenied,
        "Command is not allowed for this target",
        { cause: new Error(secret) },
      );
    },
  });
  const publicStatus = await waitForState(
    publicStore,
    publicFailure.runId,
    "failed",
  );
  assert.deepEqual(publicStatus.error, {
    gatewayCode: GATEWAY_ERROR_CODES.commandDenied,
    message: "Command is not allowed for this target",
  });
  assert.equal(JSON.stringify(publicStatus).includes(secret), false);
});

test("TTL expiry and retained-task capacity remove only terminal tasks", async () => {
  let now = 1_000;
  const ttlStore = createStore({ ttlMs: 100, now: () => now });
  const expiring = ttlStore.start({
    kind: "exec",
    target: "expires",
    worker: async () => ({ termination: "exit", exitCode: 0 }),
  });
  const completed = await waitForState(ttlStore, expiring.runId, "succeeded");
  assert.equal(completed.finishedAt, new Date(1_000).toISOString());
  assert.equal(completed.expiresAt, new Date(1_100).toISOString());
  now = 1_099;
  assert.equal(ttlStore.status(expiring.runId).state, "succeeded");
  now = 1_100;
  assert.throws(
    () => ttlStore.status(expiring.runId),
    hasGatewayCode(GATEWAY_ERROR_CODES.executionNotFound),
  );

  now = 2_000;
  const capacityStore = createStore({
    ttlMs: 10_000,
    maxRetainedTasks: 2,
    now: () => now,
  });
  const first = capacityStore.start({
    kind: "exec",
    target: "first",
    worker: async () => ({ termination: "exit", exitCode: 0 }),
  });
  await waitForState(capacityStore, first.runId, "succeeded");
  now += 10;
  const second = capacityStore.start({
    kind: "exec",
    target: "second",
    worker: async () => ({ termination: "exit", exitCode: 0 }),
  });
  await waitForState(capacityStore, second.runId, "succeeded");
  now += 10;
  const third = capacityStore.start({
    kind: "exec",
    target: "third",
    worker: async () => ({ termination: "exit", exitCode: 0 }),
  });
  assert.throws(
    () => capacityStore.status(first.runId),
    hasGatewayCode(GATEWAY_ERROR_CODES.executionNotFound),
  );
  assert.equal(capacityStore.status(second.runId).state, "succeeded");
  await waitForState(capacityStore, third.runId, "succeeded");
});

test("invalid timeouts and concurrency limits do not leak task slots", async () => {
  const store = createStore({
    maxRetainedTasks: 1,
    maxConcurrentTasks: 1,
  });
  assert.throws(
    () =>
      store.start({
        kind: "exec",
        target: "invalid-timeout",
        timeoutMs: 0,
        worker: async () => ({ termination: "exit", exitCode: 0 }),
      }),
    RangeError,
  );

  const release = deferred<TaskCompletion>();
  const running = store.start({
    kind: "exec",
    target: "running",
    worker: async () => release.promise,
  });
  assert.throws(
    () =>
      store.start({
        kind: "exec",
        target: "overflow",
        worker: async () => ({ termination: "exit", exitCode: 0 }),
      }),
    hasGatewayCode(GATEWAY_ERROR_CODES.executionLimitReached),
  );
  release.resolve({ termination: "exit", exitCode: 0 });
  await waitForState(store, running.runId, "succeeded");
});

test("shutdown aborts and awaits every running worker, then rejects new work", async () => {
  const store = createStore({ maxConcurrentTasks: 2 });
  const cleanupGate = deferred<void>();
  let abortedWorkers = 0;
  const worker = async ({ signal }: TaskWorkerContext): Promise<TaskCompletion> => {
    await waitForAbort(signal);
    abortedWorkers += 1;
    await cleanupGate.promise;
    return { termination: "exit", exitCode: 0 };
  };
  const first = store.start({ kind: "exec", target: "first", worker });
  const second = store.start({ kind: "sync", target: "second", worker });

  let shutdownFinished = false;
  const shutdown = store.shutdown().then(() => {
    shutdownFinished = true;
  });
  for (let attempt = 0; attempt < 100 && abortedWorkers !== 2; attempt += 1) {
    await delay(2);
  }
  assert.equal(abortedWorkers, 2);
  assert.equal(shutdownFinished, false);

  cleanupGate.resolve();
  await shutdown;
  assert.equal(store.status(first.runId).state, "cancelled");
  assert.equal(store.status(first.runId).termination, "cancel");
  assert.equal(store.status(second.runId).state, "cancelled");
  assert.equal(store.status(second.runId).termination, "cancel");
  assert.throws(
    () =>
      store.start({
        kind: "exec",
        target: "after-shutdown",
        worker: async () => ({ termination: "exit", exitCode: 0 }),
      }),
    hasGatewayCode(GATEWAY_ERROR_CODES.executionLimitReached),
  );
});
