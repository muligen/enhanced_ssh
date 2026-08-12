import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  FileAccessClientRecoveryStore,
  ManagedAccessClientSessionPreparer,
  WindowsPuttyLogHostRegistry,
  WindowsPuttyProcessSource,
  type AccessClientRecoveryMarker,
  type AccessClientRecoveryStore,
  type LogHostRegistry,
  type PuttyProcessSource,
  type WindowsCommandRunner,
} from "../../src/test-ui/accessclient-session.js";

const REQUEST = {
  alias: "gpu-build",
  revision: `r-test-${"a".repeat(32)}`,
  sharingHost: "120.92.76.66",
  sharingPort: 22,
} as const;
const SHARING_IDENTITY = "120.92.76.66:22";

class FakeRegistry implements LogHostRegistry {
  public value: string | undefined;
  public readonly writes: string[] = [];
  public removeCalls = 0;

  public constructor(value?: string) {
    this.value = value;
  }

  public read(): Promise<string | undefined> {
    return Promise.resolve(this.value);
  }

  public write(value: string): Promise<void> {
    this.value = value;
    this.writes.push(value);
    return Promise.resolve();
  }

  public remove(): Promise<void> {
    this.value = undefined;
    this.removeCalls += 1;
    return Promise.resolve();
  }
}

class FakeProcesses implements PuttyProcessSource {
  public processIds = new Set<number>();
  public failure: Error | undefined;

  public listProcessIds(): Promise<ReadonlySet<number>> {
    if (this.failure !== undefined) return Promise.reject(this.failure);
    return Promise.resolve(new Set(this.processIds));
  }
}

class MemoryRecoveryStore implements AccessClientRecoveryStore {
  public marker: AccessClientRecoveryMarker | undefined;

  public read(): Promise<AccessClientRecoveryMarker | undefined> {
    return Promise.resolve(this.marker);
  }

  public write(marker: AccessClientRecoveryMarker): Promise<void> {
    if (this.marker !== undefined) return Promise.reject(new Error("marker exists"));
    this.marker = marker;
    return Promise.resolve();
  }

  public remove(): Promise<void> {
    this.marker = undefined;
    return Promise.resolve();
  }
}

test("keeps LogHost armed until the detected PuTTY session is verified", async () => {
  const registry = new FakeRegistry("original-log-host");
  const processes = new FakeProcesses();
  const recoveryStore = new MemoryRecoveryStore();
  processes.processIds.add(101);
  const preparer = createPreparer(registry, processes, recoveryStore, {
    armTimeoutMs: 2_000,
    pollIntervalMs: 5,
  });

  const armed = await preparer.prepare(REQUEST);
  assert.equal(armed.state, "armed");
  assert.equal(registry.value, SHARING_IDENTITY);
  assert.ok(recoveryStore.marker);

  processes.processIds.add(202);
  await waitFor(() => preparer.status().state === "detected");
  await delay(150);
  assert.equal(registry.value, SHARING_IDENTITY);
  assert.equal(preparer.status().state, "detected");

  const ready = await preparer.verify(REQUEST.alias, {
    hostname: "gpu-build-01",
    durationMs: 42,
  });
  assert.equal(ready.state, "ready");
  assert.equal(ready.hostname, "gpu-build-01");
  assert.equal(ready.durationMs, 42);
  assert.equal(registry.value, "original-log-host");
  assert.equal(recoveryStore.marker, undefined);
  await preparer.close();
});

test("continues waiting when a detected PuTTY process exits before verification", async () => {
  const registry = new FakeRegistry("before");
  const processes = new FakeProcesses();
  processes.processIds.add(101);
  const preparer = createPreparer(
    registry,
    processes,
    new MemoryRecoveryStore(),
    { armTimeoutMs: 2_000, pollIntervalMs: 5 },
  );
  await preparer.prepare(REQUEST);

  processes.processIds.add(202);
  await waitFor(() => preparer.status().state === "detected");
  processes.processIds.delete(202);
  await waitFor(() => preparer.status().state === "armed");
  assert.equal(registry.value, SHARING_IDENTITY);

  processes.processIds.add(303);
  await waitFor(() => preparer.status().state === "detected");
  const ready = await preparer.verify(REQUEST.alias, { hostname: "gpu-build-02" });
  assert.equal(ready.state, "ready");
  assert.equal(ready.hostname, "gpu-build-02");
  assert.equal(registry.value, "before");
  await preparer.close();
});

test("reject restores LogHost and records an identity verification error", async () => {
  const registry = new FakeRegistry("before");
  const processes = new FakeProcesses();
  const preparer = createPreparer(
    registry,
    processes,
    new MemoryRecoveryStore(),
    { armTimeoutMs: 2_000, pollIntervalMs: 5 },
  );
  await preparer.prepare(REQUEST);
  processes.processIds.add(202);
  await waitFor(() => preparer.status().state === "detected");

  const rejected = await preparer.reject(
    REQUEST.alias,
    "The detected PuTTY session belongs to another machine",
  );
  assert.equal(rejected.state, "error");
  assert.match(rejected.message ?? "", /another machine/u);
  assert.equal(registry.value, "before");
  await preparer.close();
});

test("timeout, cancellation, and close restore the previous registry state", async (t) => {
  await t.test("timeout removes a value that did not previously exist", async () => {
    const registry = new FakeRegistry();
    const preparer = createPreparer(
      registry,
      new FakeProcesses(),
      new MemoryRecoveryStore(),
      { armTimeoutMs: 30, pollIntervalMs: 5 },
    );
    await preparer.prepare(REQUEST);
    await waitFor(() => preparer.status().state === "timed-out");
    assert.equal(registry.value, undefined);
    assert.equal(registry.removeCalls, 1);
    await preparer.close();
  });

  await t.test("cancel restores the exact prior value", async () => {
    const registry = new FakeRegistry("before");
    const preparer = createPreparer(
      registry,
      new FakeProcesses(),
      new MemoryRecoveryStore(),
    );
    await preparer.prepare(REQUEST);
    const cancelled = await preparer.cancel(REQUEST.alias);
    assert.equal(cancelled.state, "cancelled");
    assert.equal(registry.value, "before");
    await preparer.close();
  });

  await t.test("service close restores an armed preparation", async () => {
    const registry = new FakeRegistry("before-close");
    const preparer = createPreparer(
      registry,
      new FakeProcesses(),
      new MemoryRecoveryStore(),
    );
    await preparer.prepare(REQUEST);
    await preparer.close();
    assert.equal(registry.value, "before-close");
  });
});

test("formats an IPv6 sharing identity with its logical port", async () => {
  const registry = new FakeRegistry();
  const preparer = createPreparer(
    registry,
    new FakeProcesses(),
    new MemoryRecoveryStore(),
  );
  await preparer.prepare({
    ...REQUEST,
    sharingHost: "2001:db8::20",
    sharingPort: 2_222,
  });
  assert.equal(registry.value, "[2001:db8::20]:2222");
  await preparer.cancel(REQUEST.alias);
  await preparer.close();
});

test("a completed process query cannot overwrite a cancelled snapshot", async () => {
  let releaseQuery: ((processIds: ReadonlySet<number>) => void) | undefined;
  let calls = 0;
  const processes: PuttyProcessSource = {
    listProcessIds() {
      calls += 1;
      if (calls === 1) return Promise.resolve(new Set([101]));
      return new Promise((resolve) => {
        releaseQuery = resolve;
      });
    },
  };
  const preparer = createPreparer(
    new FakeRegistry(),
    processes,
    new MemoryRecoveryStore(),
    { pollIntervalMs: 5 },
  );
  await preparer.prepare(REQUEST);
  await waitFor(() => releaseQuery !== undefined);
  const cancelled = await preparer.cancel(REQUEST.alias);
  assert.equal(cancelled.state, "cancelled");
  releaseQuery!(new Set([101, 202]));
  await delay(25);
  assert.equal(preparer.status().state, "cancelled");
  await preparer.close();
});

test("a failed rollback after a registry side effect fails closed", async () => {
  let readCalls = 0;
  const registry: LogHostRegistry = {
    read() {
      readCalls += 1;
      return readCalls === 1
        ? Promise.resolve("before")
        : Promise.reject(new Error("registry unavailable"));
    },
    write() {
      return Promise.reject(new Error("write result was uncertain"));
    },
    remove() {
      return Promise.reject(new Error("registry unavailable"));
    },
  };
  const recoveryStore = new MemoryRecoveryStore();
  const preparer = createPreparer(
    registry,
    new FakeProcesses(),
    recoveryStore,
  );
  await assert.rejects(
    preparer.prepare(REQUEST),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "ACCESSCLIENT_RECOVERY_FAILED",
  );
  assert.equal(preparer.status().state, "error");
  assert.ok(recoveryStore.marker);
  await assert.rejects(
    preparer.prepare(REQUEST),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "ACCESSCLIENT_PREPARER_CLOSED",
  );
  await preparer.close();
});

test("only one target can be armed and an existing marker fails closed", async () => {
  const registry = new FakeRegistry("before");
  const recoveryStore = new MemoryRecoveryStore();
  const preparer = createPreparer(
    registry,
    new FakeProcesses(),
    recoveryStore,
  );
  await preparer.prepare(REQUEST);

  await assert.rejects(
    preparer.prepare({ ...REQUEST, alias: "another-target" }),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "ACCESSCLIENT_PREPARATION_BUSY",
  );
  await preparer.cancel(REQUEST.alias);

  recoveryStore.marker = recoveryMarker("other-target", "other-temp", "other-old");
  const second = createPreparer(
    registry,
    new FakeProcesses(),
    recoveryStore,
  );
  await second.initialize();
  assert.equal(registry.value, "before");
  assert.equal(recoveryStore.marker, undefined);
  await second.close();
});

test("crash recovery restores only a temporary value still owned by the marker", async (t) => {
  await t.test("restores the prior value", async () => {
    const registry = new FakeRegistry(SHARING_IDENTITY);
    const recoveryStore = new MemoryRecoveryStore();
    recoveryStore.marker = recoveryMarker(
      REQUEST.alias,
      SHARING_IDENTITY,
      "previous",
    );
    const preparer = createPreparer(registry, new FakeProcesses(), recoveryStore);
    await preparer.initialize();
    assert.equal(registry.value, "previous");
    assert.equal(recoveryStore.marker, undefined);
    await preparer.close();
  });

  await t.test("does not overwrite a later user change", async () => {
    const registry = new FakeRegistry("user-changed-value");
    const recoveryStore = new MemoryRecoveryStore();
    recoveryStore.marker = recoveryMarker(
      REQUEST.alias,
      SHARING_IDENTITY,
      "previous",
    );
    const preparer = createPreparer(registry, new FakeProcesses(), recoveryStore);
    await preparer.initialize();
    assert.equal(registry.value, "user-changed-value");
    assert.equal(recoveryStore.marker, undefined);
    await preparer.close();
  });
});

test("Windows adapters use fixed executables and argument arrays", async () => {
  const calls: Array<{
    readonly executable: string;
    readonly arguments_: readonly string[];
  }> = [];
  const runner: WindowsCommandRunner = {
    run(executable, arguments_) {
      calls.push({ executable, arguments_: [...arguments_] });
      if (executable.endsWith("tasklist.exe")) {
        return Promise.resolve({
          stdout: '"putty.exe","72808","Console","1","1 K"\r\n',
          stderr: "",
        });
      }
      if (arguments_[0] === "QUERY") {
        return Promise.resolve({
          stdout: "    LogHost    REG_SZ    gate.example.test\r\n",
          stderr: "",
        });
      }
      return Promise.resolve({ stdout: "", stderr: "" });
    },
  };
  const registry = new WindowsPuttyLogHostRegistry(runner, String.raw`C:\Windows`);
  const processes = new WindowsPuttyProcessSource(runner, String.raw`C:\Windows`);

  assert.equal(await registry.read(), "gate.example.test");
  await registry.write(SHARING_IDENTITY);
  await registry.remove();
  assert.deepEqual(await processes.listProcessIds(), new Set([72_808]));

  assert.deepEqual(calls[1]?.arguments_, [
    "ADD",
    String.raw`HKCU\Software\SimonTatham\PuTTY\Sessions\Default%20Settings`,
    "/v",
    "LogHost",
    "/t",
    "REG_SZ",
    "/d",
    SHARING_IDENTITY,
    "/f",
  ]);
  assert.deepEqual(calls[3]?.arguments_, [
    "/FI",
    "IMAGENAME eq putty.exe",
    "/FO",
    "CSV",
    "/NH",
  ]);
});

test("file recovery markers refuse replacement", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "accessclient-marker-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new FileAccessClientRecoveryStore(
    path.join(directory, "accessclient-recovery.json"),
  );
  const marker = recoveryMarker(REQUEST.alias, SHARING_IDENTITY, "before");
  await store.write(marker);
  await assert.rejects(store.write(marker));
  assert.deepEqual(await store.read(), marker);
});

function createPreparer(
  registry: LogHostRegistry,
  processes: PuttyProcessSource,
  recoveryStore: AccessClientRecoveryStore,
  timings: {
    readonly armTimeoutMs?: number;
    readonly pollIntervalMs?: number;
  } = {},
): ManagedAccessClientSessionPreparer {
  return new ManagedAccessClientSessionPreparer({
    registry,
    processes,
    recoveryStore,
    armTimeoutMs: timings.armTimeoutMs ?? 5_000,
    pollIntervalMs: timings.pollIntervalMs ?? 10,
  });
}

function recoveryMarker(
  alias: string,
  temporaryValue: string,
  previousValue: string | null,
): AccessClientRecoveryMarker {
  return {
    version: 1,
    alias,
    revision: REQUEST.revision,
    temporaryValue,
    previousValue,
    createdAt: "2026-08-11T00:00:00.000Z",
  };
}

async function waitFor(predicate: () => boolean, timeoutMs = 500): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("condition was not reached");
    await delay(5);
  }
}

function delay(durationMs: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, durationMs));
}
