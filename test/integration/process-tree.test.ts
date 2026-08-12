import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { resolve } from "node:path";
import test from "node:test";

import {
  resolveWindowsSupervisorPath,
  spawnManagedProcess,
  type ManagedProcess,
} from "../../src/infra/process-tree.js";

const fixturePath = resolve("test", "fixtures", "fake-ssh.mjs");
const streamParentFixturePath = resolve(
  "test",
  "fixtures",
  "stream-supervisor-parent.mjs",
);

test(
  "the Windows Job supervisor preserves argv exactly",
  { skip: process.platform !== "win32", timeout: 15_000 },
  async (t) => {
    const supervisor = resolveWindowsSupervisorPath();
    if (supervisor === undefined) {
      t.skip("the Windows Job supervisor has not been built");
      return;
    }
    const expected = [
      "",
      "plain",
      "with spaces",
      'quote"inside',
      "trailing\\",
      "space and trailing \\",
      String.raw`slashes\\before"quote`,
      "&|<>^()%!",
      "-leading",
      "unicode-\u5821\u5792\u673a",
    ];

    const managed = await spawnManagedProcess({
      executable: process.execPath,
      arguments: [fixturePath, "argv", ...expected],
      windowsSupervisorPath: supervisor,
    });
    t.after(() => managed.terminate());
    const [stdout, stderr, result] = await Promise.all([
      readEntireStream(managed.child.stdout),
      readEntireStream(managed.child.stderr),
      waitForClose(managed.child),
    ]);

    assert.equal(result.code, 0, stderr);
    assert.deepEqual(JSON.parse(stdout), expected);
    assert.equal(stderr, "");
  },
);

test(
  "terminating the Windows Job supervisor kills root, child, and grandchild",
  { skip: process.platform !== "win32", timeout: 20_000 },
  async (t) => {
    const supervisor = resolveWindowsSupervisorPath();
    if (supervisor === undefined) {
      t.skip("the Windows Job supervisor has not been built");
      return;
    }

    const managed = await spawnManagedProcess({
      executable: process.execPath,
      arguments: [fixturePath, "tree"],
      windowsSupervisorPath: supervisor,
    });
    t.after(() => managed.terminate());
    const pids = await collectTreePids(managed.child.stdout);

    assert.equal(managed.terminationMode, "windows-job");
    assert.deepEqual([...pids.keys()].sort(), ["child", "grandchild", "root"]);
    await managed.terminate();
    await Promise.all([...pids.values()].map((pid) => waitForProcessExit(pid)));
    for (const pid of pids.values()) {
      assert.equal(isProcessRunning(pid), false, `process ${pid} survived Job termination`);
    }
  },
);

test(
  "the Windows Job supervisor forwards child stdin without using argv or disk",
  { skip: process.platform !== "win32", timeout: 15_000 },
  async (t) => {
    const supervisor = resolveWindowsSupervisorPath();
    if (supervisor === undefined) {
      t.skip("the Windows Job supervisor has not been built");
      return;
    }
    const payload = Buffer.from("wrapper-input-中文", "utf8");
    const managed = await spawnManagedProcess({
      executable: process.execPath,
      arguments: [fixturePath, "stdin"],
      stdinPayload: payload,
      windowsSupervisorPath: supervisor,
    });
    t.after(() => managed.terminate());
    const [stdout, stderr, result] = await Promise.all([
      readEntireStream(managed.child.stdout),
      readEntireStream(managed.child.stderr),
      waitForClose(managed.child),
    ]);

    assert.equal(result.code, 0, stderr);
    assert.equal(stdout, payload.toString("utf8"));
    assert.equal(stderr, "");
  },
);

test(
  "terminating a payload-enabled supervisor still kills the managed tree",
  { skip: process.platform !== "win32", timeout: 20_000 },
  async (t) => {
    const supervisor = resolveWindowsSupervisorPath();
    if (supervisor === undefined) {
      t.skip("the Windows Job supervisor has not been built");
      return;
    }

    const managed = await spawnManagedProcess({
      executable: process.execPath,
      arguments: [fixturePath, "stdin-tree"],
      stdinPayload: Buffer.from("single-line-wrapper\n", "ascii"),
      windowsSupervisorPath: supervisor,
    });
    t.after(() => managed.terminate());
    const pids = await collectTreePids(managed.child.stdout);

    assert.equal(managed.terminationMode, "windows-job");
    assert.deepEqual([...pids.keys()].sort(), ["child", "grandchild", "root"]);
    await managed.terminate();
    await Promise.all([...pids.values()].map((pid) => waitForProcessExit(pid)));
    for (const pid of pids.values()) {
      assert.equal(isProcessRunning(pid), false, `process ${pid} survived Job termination`);
    }
  },
);

test(
  "managed streaming stdin forwards multiple writes without closing the child",
  { timeout: 20_000 },
  async (t) => {
    const supervisor =
      process.platform === "win32" ? resolveWindowsSupervisorPath() : undefined;
    if (process.platform === "win32" && supervisor === undefined) {
      t.skip("the Windows Job supervisor has not been built");
      return;
    }

    const managed = await spawnManagedProcess({
      executable: process.execPath,
      arguments: [fixturePath, "stdin-stream"],
      streamStdin: true,
      ...(supervisor === undefined ? {} : { windowsSupervisorPath: supervisor }),
    });
    t.after(() => managed.terminate());
    const lines = createLineReader(managed.child.stdout);

    await writeChunk(managed.child.stdin, "first\n");
    assert.equal(await lines.next(), "received:first");
    assert.equal(managed.child.exitCode, null);

    await writeChunk(managed.child.stdin, "second\n");
    assert.equal(await lines.next(), "received:second");
    assert.equal(managed.child.exitCode, null);
  },
);

test(
  "closing streamed supervisor stdin kills the complete Windows Job tree",
  { skip: process.platform !== "win32", timeout: 20_000 },
  async (t) => {
    const supervisor = resolveWindowsSupervisorPath();
    if (supervisor === undefined) {
      t.skip("the Windows Job supervisor has not been built");
      return;
    }

    const managed = await spawnManagedProcess({
      executable: process.execPath,
      arguments: [fixturePath, "stdin-stream-tree"],
      streamStdin: true,
      windowsSupervisorPath: supervisor,
    });
    t.after(() => managed.terminate());
    const pids = await collectTreePids(managed.child.stdout);
    assert.deepEqual([...pids.keys()].sort(), ["child", "grandchild", "root"]);

    managed.child.stdin.end();
    await Promise.all([...pids.values()].map((pid) => waitForProcessExit(pid)));
    for (const pid of pids.values()) {
      assert.equal(isProcessRunning(pid), false, `process ${pid} survived stdin EOF`);
    }
  },
);

test(
  "stream EOF kills the Windows Job even when the child never reads stdin",
  { skip: process.platform !== "win32", timeout: 20_000 },
  async (t) => {
    const supervisor = resolveWindowsSupervisorPath();
    if (supervisor === undefined) {
      t.skip("the Windows Job supervisor has not been built");
      return;
    }

    const managed = await spawnManagedProcess({
      executable: process.execPath,
      arguments: [fixturePath, "stdin-stream-blocked-tree"],
      streamStdin: true,
      windowsSupervisorPath: supervisor,
    });
    t.after(() => managed.terminate());
    const pids = await collectTreePids(managed.child.stdout);
    assert.deepEqual([...pids.keys()].sort(), ["child", "grandchild", "root"]);

    managed.child.stdin.on("error", () => undefined);
    managed.child.stdin.end(Buffer.alloc(2 * 1024 * 1024, 0x61));
    await Promise.all([...pids.values()].map((pid) => waitForProcessExit(pid)));
    for (const pid of pids.values()) {
      assert.equal(
        isProcessRunning(pid),
        false,
        `process ${pid} survived backpressured stdin EOF`,
      );
    }
  },
);

test(
  "excessive backpressured stream input fails the Windows Job closed",
  { skip: process.platform !== "win32", timeout: 20_000 },
  async (t) => {
    const supervisor = resolveWindowsSupervisorPath();
    if (supervisor === undefined) {
      t.skip("the Windows Job supervisor has not been built");
      return;
    }

    const managed = await spawnManagedProcess({
      executable: process.execPath,
      arguments: [fixturePath, "stdin-stream-blocked-tree"],
      streamStdin: true,
      windowsSupervisorPath: supervisor,
    });
    t.after(() => managed.terminate());
    const pids = await collectTreePids(managed.child.stdout);
    assert.deepEqual([...pids.keys()].sort(), ["child", "grandchild", "root"]);

    managed.child.stdin.on("error", () => undefined);
    managed.child.stdin.write(Buffer.alloc(5 * 1024 * 1024, 0x62));
    await Promise.all([...pids.values()].map((pid) => waitForProcessExit(pid)));
    for (const pid of pids.values()) {
      assert.equal(
        isProcessRunning(pid),
        false,
        `process ${pid} survived excessive buffered stream input`,
      );
    }
  },
);

test(
  "a broken parent stream kills the complete Windows Job tree",
  { skip: process.platform !== "win32", timeout: 20_000 },
  async (t) => {
    const supervisor = resolveWindowsSupervisorPath();
    if (supervisor === undefined) {
      t.skip("the Windows Job supervisor has not been built");
      return;
    }

    const managed = await spawnManagedProcess({
      executable: process.execPath,
      arguments: [fixturePath, "stdin-stream-blocked-tree"],
      streamStdin: true,
      windowsSupervisorPath: supervisor,
    });
    t.after(() => managed.terminate());
    const pids = await collectTreePids(managed.child.stdout);
    assert.deepEqual([...pids.keys()].sort(), ["child", "grandchild", "root"]);

    managed.child.stdin.on("error", () => undefined);
    managed.child.stdin.destroy(new Error("simulated parent stream failure"));
    await Promise.all([...pids.values()].map((pid) => waitForProcessExit(pid)));
    for (const pid of pids.values()) {
      assert.equal(
        isProcessRunning(pid),
        false,
        `process ${pid} survived a broken parent stream`,
      );
    }
  },
);

test(
  "parent process death kills a backpressured streamed Windows Job",
  { skip: process.platform !== "win32", timeout: 20_000 },
  async (t) => {
    const supervisor = resolveWindowsSupervisorPath();
    if (supervisor === undefined) {
      t.skip("the Windows Job supervisor has not been built");
      return;
    }

    const parent = spawn(
      process.execPath,
      [streamParentFixturePath, supervisor, fixturePath],
      {
        detached: false,
        shell: false,
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    t.after(() => {
      if (parent.exitCode === null && parent.signalCode === null) {
        parent.kill("SIGKILL");
      }
    });
    const stderr = bufferStream(parent.stderr);
    const pids = await collectNamedPids(
      parent.stdout,
      new Set(["supervisor", "root", "child", "grandchild"]),
    ).catch((error: unknown) => {
      throw new Error(
        `stream parent failed before reporting its process tree: ${stderr()}`,
        { cause: error },
      );
    });

    assert.equal(parent.kill("SIGKILL"), true);
    assert.notEqual(parent.pid, undefined);
    await waitForProcessExit(parent.pid!);
    await Promise.all([...pids.values()].map((pid) => waitForProcessExit(pid)));
    for (const [name, pid] of pids) {
      assert.equal(
        isProcessRunning(pid),
        false,
        `${name} process ${pid} survived its Node parent`,
      );
    }
  },
);

test(
  "the native parent handle kills a stream Job while its control pipe stays open",
  { skip: process.platform !== "win32", timeout: 20_000 },
  async (t) => {
    const supervisorPath = resolveWindowsSupervisorPath();
    if (supervisorPath === undefined) {
      t.skip("the Windows Job supervisor has not been built");
      return;
    }

    const sentinel = spawn(
      process.execPath,
      ["-e", "setInterval(() => undefined, 1000)"],
      { shell: false, windowsHide: true, stdio: "ignore" },
    );
    assert.notEqual(sentinel.pid, undefined);
    const supervised = spawn(
      supervisorPath,
      [
        "--stdin-stream",
        "--parent-pid",
        String(sentinel.pid),
        "--",
        process.execPath,
        fixturePath,
        "stdin-stream-blocked-tree",
      ],
      {
        detached: false,
        shell: false,
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    t.after(() => {
      if (sentinel.exitCode === null && sentinel.signalCode === null) {
        sentinel.kill("SIGKILL");
      }
      if (supervised.exitCode === null && supervised.signalCode === null) {
        supervised.kill("SIGKILL");
      }
    });
    supervised.stdin.on("error", () => undefined);
    const pids = await collectTreePids(supervised.stdout);
    assert.deepEqual([...pids.keys()].sort(), ["child", "grandchild", "root"]);

    await writeChunk(
      supervised.stdin,
      Buffer.alloc(2 * 1024 * 1024, 0x64),
    );
    assert.equal(supervised.stdin.destroyed, false);
    assert.equal(sentinel.kill("SIGKILL"), true);
    await waitForProcessExit(sentinel.pid!);
    await Promise.all([
      waitForProcessExit(supervised.pid!),
      ...[...pids.values()].map((pid) => waitForProcessExit(pid)),
    ]);
    for (const pid of pids.values()) {
      assert.equal(
        isProcessRunning(pid),
        false,
        `process ${pid} survived its monitored parent`,
      );
    }
  },
);

test("streaming stdin and a one-shot payload are mutually exclusive", async () => {
  await assert.rejects(
    spawnManagedProcess({
      executable: process.execPath,
      arguments: [fixturePath, "stdin"],
      stdinPayload: Buffer.from("payload", "utf8"),
      streamStdin: true,
    }),
    /mutually exclusive/iu,
  );
});

test(
  "POSIX termination kills the process group after its root has exited",
  { skip: process.platform === "win32", timeout: 20_000 },
  async (t) => {
    const managed = await spawnManagedProcess({
      executable: process.execPath,
      arguments: [fixturePath, "orphan-tree"],
    });
    t.after(() => managed.terminate());
    const pids = await collectTreePids(managed.child.stdout);
    await waitForProcessExit(pids.get("root")!);

    assert.equal(managed.child.exitCode, 0);
    assert.equal(isProcessRunning(pids.get("child")!), true);
    assert.equal(isProcessRunning(pids.get("grandchild")!), true);

    await managed.terminate();
    await Promise.all(
      [...pids.values()].map((pid) => waitForProcessExit(pid)),
    );
    for (const pid of pids.values()) {
      assert.equal(
        isProcessRunning(pid),
        false,
        `process ${pid} survived process-group termination`,
      );
    }
  },
);

function readEntireStream(stream: NodeJS.ReadableStream): Promise<string> {
  return new Promise((resolveStream, reject) => {
    const chunks: Buffer[] = [];
    stream.on("data", (chunk: Buffer | Uint8Array) => {
      chunks.push(Buffer.from(chunk));
    });
    stream.once("error", reject);
    stream.once("end", () => {
      resolveStream(Buffer.concat(chunks).toString("utf8"));
    });
  });
}

function bufferStream(stream: NodeJS.ReadableStream): () => string {
  const chunks: Buffer[] = [];
  stream.on("data", (chunk: Buffer | Uint8Array) => {
    chunks.push(Buffer.from(chunk));
  });
  return () => Buffer.concat(chunks).toString("utf8");
}

function createLineReader(stream: NodeJS.ReadableStream): {
  next(): Promise<string>;
} {
  const queued: string[] = [];
  const waiting: Array<{
    resolve(value: string): void;
    reject(error: unknown): void;
  }> = [];
  let buffered = "";
  let ended = false;
  let streamError: unknown;

  const settle = (): void => {
    while (queued.length > 0 && waiting.length > 0) {
      waiting.shift()!.resolve(queued.shift()!);
    }
    if (streamError !== undefined) {
      for (const waiter of waiting.splice(0)) waiter.reject(streamError);
    } else if (ended) {
      for (const waiter of waiting.splice(0)) {
        waiter.reject(new Error(`stream ended before the next line: ${buffered}`));
      }
    }
  };
  stream.on("data", (chunk: Buffer | Uint8Array) => {
    buffered += Buffer.from(chunk).toString("utf8");
    for (;;) {
      const newline = buffered.indexOf("\n");
      if (newline < 0) break;
      queued.push(buffered.slice(0, newline).replace(/\r$/u, ""));
      buffered = buffered.slice(newline + 1);
    }
    settle();
  });
  stream.once("error", (error) => {
    streamError = error;
    settle();
  });
  stream.once("end", () => {
    ended = true;
    settle();
  });

  return {
    next(): Promise<string> {
      if (queued.length > 0) return Promise.resolve(queued.shift()!);
      if (streamError !== undefined) return Promise.reject(streamError);
      if (ended) {
        return Promise.reject(
          new Error(`stream ended before the next line: ${buffered}`),
        );
      }
      return new Promise<string>((resolveLine, rejectLine) => {
        waiting.push({ resolve: resolveLine, reject: rejectLine });
      });
    },
  };
}

function writeChunk(
  stream: NodeJS.WritableStream,
  chunk: string | Uint8Array,
): Promise<void> {
  return new Promise((resolveWrite, rejectWrite) => {
    stream.write(chunk, (error?: Error | null) => {
      if (error === undefined || error === null) resolveWrite();
      else rejectWrite(error);
    });
  });
}

function waitForClose(
  child: ManagedProcess["child"],
): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  return new Promise((resolveClose, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolveClose({ code, signal }));
  });
}

function collectTreePids(stream: NodeJS.ReadableStream): Promise<Map<string, number>> {
  return collectNamedPids(stream, new Set(["root", "child", "grandchild"]));
}

function collectNamedPids(
  stream: NodeJS.ReadableStream,
  requiredNames: ReadonlySet<string>,
): Promise<Map<string, number>> {
  return new Promise((resolvePids, reject) => {
    const pids = new Map<string, number>();
    let buffered = "";
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`timed out waiting for process tree PIDs: ${buffered}`));
    }, 8_000);
    const cleanup = (): void => {
      clearTimeout(timer);
      stream.off("data", onData);
      stream.off("error", onError);
      stream.off("end", onEnd);
    };
    const onError = (error: Error): void => {
      cleanup();
      reject(error);
    };
    const onEnd = (): void => {
      cleanup();
      reject(new Error(`process tree ended before reporting all PIDs: ${buffered}`));
    };
    const onData = (chunk: Buffer | Uint8Array): void => {
      buffered += Buffer.from(chunk).toString("utf8");
      for (;;) {
        const newline = buffered.indexOf("\n");
        if (newline < 0) {
          break;
        }
        const line = buffered.slice(0, newline).trim();
        buffered = buffered.slice(newline + 1);
        const match = /^([a-z][a-z0-9-]*):(\d+)$/u.exec(line);
        if (match !== null && requiredNames.has(match[1]!)) {
          pids.set(match[1]!, Number(match[2]));
        }
      }
      if (pids.size === requiredNames.size) {
        cleanup();
        resolvePids(pids);
      }
    };

    stream.on("data", onData);
    stream.once("error", onError);
    stream.once("end", onEnd);
  });
}

async function waitForProcessExit(pid: number): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    if (!isProcessRunning(pid)) {
      return;
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 25));
  }
}

function isProcessRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error: unknown) {
    return !(
      error instanceof Error &&
      "code" in error &&
      (error as NodeJS.ErrnoException).code === "ESRCH"
    );
  }
}
