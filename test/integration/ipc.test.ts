import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";

import { GatewayDispatcher } from "../../src/daemon/dispatcher.js";
import { PipeRpcServer } from "../../src/daemon/pipe-server.js";
import {
  createRuntimeDescriptor,
  type RuntimeDescriptor,
} from "../../src/daemon/runtime-state.js";
import type { SshRunInput } from "../../src/infra/openssh-executor.js";
import { PROTOCOL_VERSION } from "../../src/shared/protocol.js";
import { GatewayRpcClient } from "../../src/shared/rpc-client.js";
import {
  FakeAuditWriter,
  FakeSshExecutor,
  MemoryOutputStore,
  deferred,
  sshOutcome,
  testExecService,
} from "../helpers/fakes.js";

interface TestResponse {
  readonly jsonrpc: "2.0";
  readonly id: string | number | null;
  readonly result?: unknown;
  readonly error?: {
    readonly code: number;
    readonly message: string;
    readonly data?: unknown;
  };
}

interface FrameWaiter {
  resolve(frame: TestResponse): void;
  reject(error: Error): void;
}

class JsonLinePeer {
  readonly #socket: net.Socket;
  readonly #frames: TestResponse[] = [];
  readonly #waiters: FrameWaiter[] = [];
  #buffer = Buffer.alloc(0);
  public readonly closed: Promise<void>;

  private constructor(socket: net.Socket) {
    this.#socket = socket;
    this.closed = new Promise((resolve) => socket.once("close", resolve));
    socket.on("data", (chunk: Buffer) => this.#acceptChunk(chunk));
    socket.on("error", (error) => this.#rejectWaiters(error));
    socket.on("close", () =>
      this.#rejectWaiters(new Error("Test RPC connection closed")),
    );
  }

  public static async connect(endpoint: string): Promise<JsonLinePeer> {
    const socket = net.createConnection(endpoint);
    await new Promise<void>((resolve, reject) => {
      socket.once("connect", resolve);
      socket.once("error", reject);
    });
    return new JsonLinePeer(socket);
  }

  public async request(frame: unknown): Promise<TestResponse> {
    const response = this.#nextFrame();
    this.send(frame);
    return response;
  }

  public send(frame: unknown): void {
    this.#socket.write(`${JSON.stringify(frame)}\n`, "utf8");
  }

  public async destroy(): Promise<void> {
    if (this.#socket.destroyed) {
      await this.closed;
      return;
    }
    this.#socket.destroy();
    await this.closed;
  }

  #nextFrame(): Promise<TestResponse> {
    const queued = this.#frames.shift();
    if (queued !== undefined) {
      return Promise.resolve(queued);
    }
    return new Promise<TestResponse>((resolve, reject) => {
      this.#waiters.push({ resolve, reject });
    });
  }

  #acceptChunk(chunk: Buffer): void {
    this.#buffer = Buffer.concat([this.#buffer, chunk]);
    let newline = this.#buffer.indexOf(0x0a);
    while (newline >= 0) {
      const line = this.#buffer.subarray(0, newline);
      this.#buffer = this.#buffer.subarray(newline + 1);
      if (line.length > 0) {
        const frame = JSON.parse(line.toString("utf8")) as TestResponse;
        const waiter = this.#waiters.shift();
        if (waiter === undefined) {
          this.#frames.push(frame);
        } else {
          waiter.resolve(frame);
        }
      }
      newline = this.#buffer.indexOf(0x0a);
    }
  }

  #rejectWaiters(error: Error): void {
    for (const waiter of this.#waiters.splice(0)) {
      waiter.reject(error);
    }
  }
}

interface IpcHarness {
  readonly runtime: RuntimeDescriptor;
  readonly server: PipeRpcServer;
  readonly service: ReturnType<typeof testExecService>;
  readonly audit: FakeAuditWriter;
}

async function createHarness(
  t: TestContext,
  executor = new FakeSshExecutor(async () => sshOutcome()),
  maxInflightRequestsPerConnection?: number,
): Promise<IpcHarness> {
  const endpoint =
    process.platform === "win32"
      ? `\\\\.\\pipe\\agent-ssh-ipc-test-${process.pid}-${randomUUID()}`
      : join(tmpdir(), `agent-ssh-ipc-test-${process.pid}-${randomUUID()}.sock`);
  const runtime: RuntimeDescriptor = {
    version: 1,
    pid: process.pid,
    endpoint,
    token: Buffer.alloc(32, 7).toString("base64url"),
    startedAt: new Date().toISOString(),
  };
  const audit = new FakeAuditWriter();
  const service = testExecService({
    executor,
    audit,
    outputStore: new MemoryOutputStore(),
  });
  const server = new PipeRpcServer({
    runtime,
    dispatcher: new GatewayDispatcher(service),
    serverVersion: "0.1.0-test",
    ...(maxInflightRequestsPerConnection === undefined
      ? {}
      : { maxInflightRequestsPerConnection }),
  });
  await server.listen();
  t.after(async () => {
    await server.close();
    await service.shutdown();
  });
  return { runtime, server, service, audit };
}

async function openSession(
  peer: JsonLinePeer,
  token: string,
): Promise<TestResponse> {
  return peer.request({
    jsonrpc: "2.0",
    id: "open",
    method: "session.open",
    params: {
      token,
      protocolVersion: PROTOCOL_VERSION,
      client: { name: "ipc-test", version: "1.0.0", pid: process.pid },
    },
  });
}

test("rejects unauthenticated requests and invalid handshake tokens", async (t) => {
  const harness = await createHarness(t);

  const unauthenticated = await JsonLinePeer.connect(harness.runtime.endpoint);
  const unauthenticatedResponse = await unauthenticated.request({
    jsonrpc: "2.0",
    id: "ping-before-open",
    method: "system.ping",
    params: {},
  });
  assert.equal(unauthenticatedResponse.error?.code, -32001);
  assert.equal(
    unauthenticatedResponse.error?.message,
    "Authentication required",
  );
  await unauthenticated.closed;

  const invalidToken = await JsonLinePeer.connect(harness.runtime.endpoint);
  const invalidTokenResponse = await openSession(invalidToken, "A".repeat(43));
  assert.equal(invalidTokenResponse.error?.code, -32001);
  assert.equal(invalidTokenResponse.error?.message, "Authentication failed");
  await invalidToken.closed;
});

test("rejects an authenticated client using a stale protocol version", async (t) => {
  const harness = await createHarness(t);
  const peer = await JsonLinePeer.connect(harness.runtime.endpoint);
  const response = await peer.request({
    jsonrpc: "2.0",
    id: "stale-open",
    method: "session.open",
    params: {
      token: harness.runtime.token,
      protocolVersion: PROTOCOL_VERSION - 1,
      client: { name: "stale-client", version: "0.1.0" },
    },
  });

  assert.equal(response.error?.code, -32002);
  assert.equal(response.error?.message, "Protocol version mismatch");
  assert.deepEqual(response.error?.data, {
    gatewayCode: "PROTOCOL_VERSION_MISMATCH",
    details: {
      expectedProtocolVersion: PROTOCOL_VERSION,
      receivedProtocolVersion: PROTOCOL_VERSION - 1,
    },
  });
  await peer.closed;
});

test("opens an authenticated session and serves ping and target.list RPCs", async (t) => {
  const harness = await createHarness(t);
  const peer = await JsonLinePeer.connect(harness.runtime.endpoint);

  const opened = await openSession(peer, harness.runtime.token);
  assert.equal(opened.error, undefined);
  const openResult = opened.result as Record<string, unknown>;
  assert.equal(openResult.protocolVersion, PROTOCOL_VERSION);
  assert.equal(openResult.serverVersion, "0.1.0-test");
  assert.match(String(openResult.sessionId), /^[A-Za-z0-9_-]{43}$/);

  const ping = await peer.request({
    jsonrpc: "2.0",
    id: "ping",
    method: "system.ping",
    params: {},
  });
  const pingResult = ping.result as Record<string, unknown>;
  assert.equal(pingResult.ok, true);
  assert.equal(pingResult.protocolVersion, PROTOCOL_VERSION);
  assert.equal(Number.isNaN(Date.parse(String(pingResult.serverTime))), false);

  const listed = await peer.request({
    jsonrpc: "2.0",
    id: "list",
    method: "target.list",
    params: {},
  });
  const listedTargetId = String(
    ((listed.result as { targets: Array<{ targetId: unknown }> }).targets[0]!)
      .targetId,
  );
  assert.match(listedTargetId, /^t-[a-f0-9]{32}$/u);
  assert.deepEqual(listed.result, {
    targets: [
      {
        targetId: listedTargetId,
        alias: "alpha",
        description: "Test target",
        enabled: true,
        platform: "linux",
        connectionMode: "openssh",
        policyMode: "allow-list",
        transferMode: "deny",
        transferScope: "restricted",
        transferRoots: [],
        maxTimeoutMs: 5_000,
      },
    ],
  });
  assert.equal(JSON.stringify(listed.result).includes("internal-alpha"), false);

  await peer.destroy();
});

test("disconnecting an authenticated client cancels its in-flight execution", async (t) => {
  const started = deferred<SshRunInput>();
  const aborted = deferred<void>();
  const executor = new FakeSshExecutor(async (input) => {
    started.resolve(input);
    return new Promise((resolve) => {
      const finish = (): void => {
        aborted.resolve();
        resolve(
          sshOutcome({
            exitCode: null,
            aborted: true,
            durationMs: 5,
          }),
        );
      };
      if (input.signal?.aborted === true) {
        finish();
      } else {
        input.signal?.addEventListener("abort", finish, { once: true });
      }
    });
  });
  const harness = await createHarness(t, executor);
  const peer = await JsonLinePeer.connect(harness.runtime.endpoint);
  await openSession(peer, harness.runtime.token);

  peer.send({
    jsonrpc: "2.0",
    id: "disconnect-run",
    method: "exec.run",
    params: { target: "alpha", command: "long-command" },
  });
  const input = await started.promise;

  await peer.destroy();
  await aborted.promise;
  await harness.service.shutdown();

  assert.equal(input.signal?.aborted, true);
  assert.equal(executor.calls.length, 1);
  const cancelled = harness.audit.events.find(
    (event) => event.event === "exec.cancelled",
  );
  assert.ok(cancelled?.event === "exec.cancelled");
  assert.equal(cancelled.reasonCode, "cancel");
});

test("RPC client abort cancels an in-flight target.check by request ID", async (t) => {
  const dataDirectory = await mkdtemp(
    join(tmpdir(), "agent-ssh-check-client-test-"),
  );
  const lease = await createRuntimeDescriptor(dataDirectory);
  const started = deferred<SshRunInput>();
  const executor = new FakeSshExecutor(async (input) => {
    started.resolve(input);
    return new Promise((resolve) => {
      const finish = (): void => {
        resolve(
          sshOutcome({
            exitCode: null,
            aborted: true,
            durationMs: 6,
          }),
        );
      };
      if (input.signal?.aborted === true) {
        finish();
      } else {
        input.signal?.addEventListener("abort", finish, { once: true });
      }
    });
  });
  const service = testExecService({ executor });
  const server = new PipeRpcServer({
    runtime: lease.descriptor,
    dispatcher: new GatewayDispatcher(service),
    serverVersion: "0.1.0-test",
  });
  await server.listen();
  const client = await GatewayRpcClient.connect(dataDirectory, {
    name: "target-check-test",
    version: "1.0.0",
  });
  t.after(async () => {
    client.close();
    await server.close();
    await service.shutdown();
    await lease.release();
    await rm(dataDirectory, { recursive: true, force: true });
  });

  const controller = new AbortController();
  const checked = client.check({ target: "alpha" }, controller.signal);
  const input = await started.promise;
  controller.abort();
  const result = await checked;

  assert.equal(input.signal?.aborted, true);
  assert.deepEqual(result, {
    target: "alpha",
    connected: false,
    termination: "cancel",
    exitCode: null,
    durationMs: 6,
  });
  assert.equal(executor.calls.length, 1);
});

test("daemon-owned task survives its starting RPC connection and is followed from a new connection", async (t) => {
  const started = deferred<SshRunInput>();
  const release = deferred<void>();
  const executor = new FakeSshExecutor(async (input) => {
    await input.outputSink?.append("stdout", Buffer.from("step-1\n", "utf8"));
    started.resolve(input);
    await release.promise;
    await input.outputSink?.append(
      "stdout",
      Buffer.from("step-2:完成\n", "utf8"),
    );
    return sshOutcome({ exitCode: 0, durationMs: 32 });
  });
  const harness = await createHarness(t, executor);
  const starter = await JsonLinePeer.connect(harness.runtime.endpoint);
  await openSession(starter, harness.runtime.token);

  const startResponse = await starter.request({
    jsonrpc: "2.0",
    id: "task-start",
    method: "task.start",
    params: { target: "alpha", command: "long-command" },
  });
  assert.equal(startResponse.error, undefined);
  const task = startResponse.result as {
    runId: string;
    state: string;
    kind: string;
  };
  assert.equal(task.state, "running");
  assert.equal(task.kind, "exec");
  assert.match(task.runId, /^[A-Za-z0-9_-]{43}$/u);

  const input = await started.promise;
  await starter.destroy();
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(input.signal?.aborted, false);

  const observer = await JsonLinePeer.connect(harness.runtime.endpoint);
  await openSession(observer, harness.runtime.token);
  const runningResponse = await observer.request({
    jsonrpc: "2.0",
    id: "task-status-running",
    method: "task.status",
    params: { runId: task.runId },
  });
  assert.equal(
    (runningResponse.result as { state: string }).state,
    "running",
  );

  const firstTailResponse = await observer.request({
    jsonrpc: "2.0",
    id: "task-tail-first",
    method: "task.tail",
    params: { runId: task.runId },
  });
  const firstTail = firstTailResponse.result as {
    nextCursor: string;
    eof: boolean;
    stdout: { text: string };
  };
  assert.equal(firstTail.stdout.text, "step-1\n");
  assert.equal(firstTail.eof, false);

  release.resolve();
  let terminalState = "running";
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const statusResponse = await observer.request({
      jsonrpc: "2.0",
      id: `task-status-${attempt}`,
      method: "task.status",
      params: { runId: task.runId },
    });
    terminalState = (statusResponse.result as { state: string }).state;
    if (terminalState !== "running") break;
    await new Promise<void>((resolve) => setTimeout(resolve, 5));
  }
  assert.equal(terminalState, "succeeded");

  const finalTailResponse = await observer.request({
    jsonrpc: "2.0",
    id: "task-tail-final",
    method: "task.tail",
    params: { runId: task.runId, cursor: firstTail.nextCursor },
  });
  const finalTail = finalTailResponse.result as {
    eof: boolean;
    stdout: { text: string; hadDecodingErrors: boolean };
  };
  assert.equal(finalTail.stdout.text, "step-2:完成\n");
  assert.equal(finalTail.stdout.hadDecodingErrors, false);
  assert.equal(finalTail.eof, true);
  assert.equal(executor.calls.length, 1);
  await observer.destroy();
});

test("closes a session that exceeds its in-flight request limit", { timeout: 10_000 }, async (t) => {
  const started: Array<ReturnType<typeof deferred<void>>> = [];
  const bothStarted = deferred<void>();
  const executor = new FakeSshExecutor(async (input) => {
    const gate = deferred<void>();
    started.push(gate);
    if (started.length === 2) {
      bothStarted.resolve();
    }
    await gate.promise;
    return sshOutcome({ aborted: input.signal?.aborted ?? false });
  });
  const harness = await createHarness(t, executor, 2);
  const peer = await JsonLinePeer.connect(harness.runtime.endpoint);
  await openSession(peer, harness.runtime.token);

  for (const [id, command] of [
    ["first", "first"],
    ["second", "second"],
    ["overflow", "echo ok"],
  ] as const) {
    peer.send({
      jsonrpc: "2.0",
      id,
      method: "exec.run",
      params: { target: "alpha", command },
    });
  }

  await Promise.all([peer.closed, bothStarted.promise]);
  assert.equal(executor.calls.length, 2);
  assert.equal(executor.calls[0]?.signal?.aborted, true);
  assert.equal(executor.calls[1]?.signal?.aborted, true);
  for (const gate of started) {
    gate.resolve();
  }
});
