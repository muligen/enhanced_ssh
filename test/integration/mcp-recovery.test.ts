import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createInterface, type Interface } from "node:readline";
import test from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

import { GatewayDispatcher } from "../../src/daemon/dispatcher.js";
import { PipeRpcServer, type RpcDispatcher } from "../../src/daemon/pipe-server.js";
import {
  createRuntimeDescriptor,
  type RuntimeDescriptor,
  type RuntimeLease,
} from "../../src/daemon/runtime-state.js";
import { TargetRegistry } from "../../src/core/target-registry.js";
import type { SshRunInput } from "../../src/infra/openssh-executor.js";
import { PROTOCOL_VERSION } from "../../src/shared/protocol.js";
import { publishAdminDescriptor } from "../../src/service/control-plane.js";
import {
  FakeSshExecutor,
  deferred,
  sshOutcome,
  testExecService,
} from "../helpers/fakes.js";

const MCP_PROTOCOL_VERSION = "2025-11-25";

interface JsonRpcResponse {
  readonly jsonrpc: "2.0";
  readonly id: string | number | null;
  readonly result?: unknown;
  readonly error?: Readonly<{
    code: number;
    message: string;
  }>;
}

interface PendingResponse {
  readonly resolve: (response: JsonRpcResponse) => void;
  readonly reject: (error: Error) => void;
  readonly timeout: NodeJS.Timeout;
}

class StdioMcpPeer {
  readonly #child: ChildProcessWithoutNullStreams;
  readonly #lines: Interface;
  readonly #pending = new Map<number, PendingResponse>();
  readonly #exit: Promise<void>;
  #nextId = 1;
  #stderr = "";

  public constructor(child: ChildProcessWithoutNullStreams) {
    this.#child = child;
    this.#lines = createInterface({ input: child.stdout });
    this.#lines.on("line", (line) => this.#acceptLine(line));
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      this.#stderr += chunk;
    });
    this.#exit = new Promise<void>((resolve) => {
      child.once("exit", (code, signal) => {
        const detail = signal === null ? `code ${String(code)}` : `signal ${signal}`;
        const error = new Error(
          `MCP process exited with ${detail}${this.#stderr.length === 0 ? "" : `: ${this.#stderr.trim()}`}`,
        );
        for (const pending of this.#pending.values()) {
          clearTimeout(pending.timeout);
          pending.reject(error);
        }
        this.#pending.clear();
        resolve();
      });
    });
  }

  public async initialize(): Promise<void> {
    const response = await this.request("initialize", {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "mcp-recovery-test", version: "1.0.0" },
    });
    assert.equal(response.error, undefined);
    await this.notify("notifications/initialized", {});
  }

  public request(method: string, params: object): Promise<JsonRpcResponse> {
    const id = this.#nextId;
    this.#nextId += 1;
    return new Promise<JsonRpcResponse>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.#pending.delete(id);
        reject(
          new Error(
            `Timed out waiting for MCP response to ${method}${this.#stderr.length === 0 ? "" : `: ${this.#stderr.trim()}`}`,
          ),
        );
      }, 5_000);
      this.#pending.set(id, { resolve, reject, timeout });
      this.#write({ jsonrpc: "2.0", id, method, params });
    });
  }

  public notify(method: string, params: object): Promise<void> {
    return this.#write({ jsonrpc: "2.0", method, params });
  }

  public async close(): Promise<void> {
    if (this.#child.exitCode !== null || this.#child.signalCode !== null) {
      await this.#exit;
      return;
    }
    this.#child.stdin.end();
    const exited = await Promise.race([
      this.#exit.then(() => true),
      new Promise<false>((resolve) => {
        const timeout = setTimeout(() => resolve(false), 2_000);
        timeout.unref();
      }),
    ]);
    if (!exited) {
      this.#child.kill("SIGKILL");
      const forcedExit = await Promise.race([
        this.#exit.then(() => true),
        new Promise<false>((resolve) => setTimeout(() => resolve(false), 2_000)),
      ]);
      if (!forcedExit) {
        throw new Error("MCP process did not exit after forced termination");
      }
    }
  }

  #write(message: object): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      this.#child.stdin.write(`${JSON.stringify(message)}\n`, "utf8", (error) =>
        error === null || error === undefined ? resolve() : reject(error),
      );
    });
  }

  #acceptLine(line: string): void {
    let response: JsonRpcResponse;
    try {
      response = JSON.parse(line) as JsonRpcResponse;
    } catch (error) {
      for (const pending of this.#pending.values()) {
        clearTimeout(pending.timeout);
        pending.reject(new Error("MCP returned invalid JSON", { cause: error }));
      }
      this.#pending.clear();
      return;
    }
    if (typeof response.id !== "number") {
      return;
    }
    const pending = this.#pending.get(response.id);
    if (pending === undefined) {
      return;
    }
    this.#pending.delete(response.id);
    clearTimeout(pending.timeout);
    pending.resolve(response);
  }
}

interface RunningTestGateway {
  readonly runtime: RuntimeDescriptor;
  executionCount(): number;
  stop(): Promise<void>;
}

async function startTestGateway(
  dataDirectory: string,
  targetAlias: string,
): Promise<RunningTestGateway> {
  const lease: RuntimeLease = await createRuntimeDescriptor(dataDirectory);
  let executionCount = 0;
  const dispatcher: RpcDispatcher = {
    async dispatch(method): Promise<unknown> {
      switch (method) {
        case "system.ping":
          return {
            ok: true,
            protocolVersion: PROTOCOL_VERSION,
            serverTime: new Date().toISOString(),
          };
        case "target.list":
          return {
            targets: [
              {
                targetId: "t-44444444444444444444444444444444",
                alias: targetAlias,
                description: `Test target ${targetAlias}`,
                enabled: true,
                platform: "linux",
                policyMode: "allow-list",
                maxTimeoutMs: 5_000,
              },
            ],
          };
        case "target.check":
          return {
            target: targetAlias,
            connected: true,
            termination: "exit",
            exitCode: 0,
            durationMs: 1,
            hostname: `${targetAlias}.example`,
          };
        case "exec.run":
          executionCount += 1;
          throw new Error("Simulated execution response failure");
        default:
          throw new Error(`Unexpected test RPC method: ${method}`);
      }
    },
  };
  const server = new PipeRpcServer({
    runtime: lease.descriptor,
    dispatcher,
    serverVersion: "mcp-recovery-test",
  });
  try {
    await server.listen();
  } catch (error) {
    await lease.release().catch(() => undefined);
    throw error;
  }

  let stopping: Promise<void> | undefined;
  return {
    runtime: lease.descriptor,
    executionCount: () => executionCount,
    stop(): Promise<void> {
      stopping ??= (async () => {
        await server.close();
        await lease.release();
      })();
      return stopping;
    },
  };
}

function spawnMcp(dataDirectory: string): StdioMcpPeer {
  const entrypoint = fileURLToPath(new URL("../../src/mcp/main.js", import.meta.url));
  const child = spawn(
    process.execPath,
    [entrypoint, "--data-directory", dataDirectory],
    {
      cwd: process.cwd(),
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    },
  );
  return new StdioMcpPeer(child);
}

function toolResult(response: JsonRpcResponse): Record<string, unknown> {
  assert.equal(response.error, undefined);
  assert.equal(typeof response.result, "object");
  assert.notEqual(response.result, null);
  return response.result as Record<string, unknown>;
}

function structuredContent(response: JsonRpcResponse): Record<string, unknown> {
  const result = toolResult(response);
  assert.notEqual(result.isError, true);
  assert.equal(typeof result.structuredContent, "object");
  assert.notEqual(result.structuredContent, null);
  return result.structuredContent as Record<string, unknown>;
}

test(
  "stdio MCP survives late gateway startup and reconnects after gateway restart",
  { timeout: 40_000 },
  async (t) => {
    const root = await mkdtemp(path.join(tmpdir(), "agent-ssh-mcp-recovery-"));
    const dataDirectory = path.join(root, "runtime");
    const peer = spawnMcp(dataDirectory);
    let gateway: RunningTestGateway | undefined;
    t.after(async () => {
      await peer.close();
      await gateway?.stop().catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    });

    await peer.initialize();
    const tools = toolResult(await peer.request("tools/list", {}));
    const listedTools = tools.tools as Array<Record<string, unknown>>;
    assert.deepEqual(
      listedTools.map((tool) => tool.name).sort(),
      [
        "ssh_cancel",
        "ssh_check_connection",
        "ssh_docker_preflight",
        "ssh_download",
        "ssh_exec",
        "ssh_gateway_status",
        "ssh_list_targets",
        "ssh_open_admin",
        "ssh_ping",
        "ssh_read_output",
        "ssh_read_output_text",
        "ssh_start",
        "ssh_status",
        "ssh_sync",
        "ssh_tail",
        "ssh_target_info",
        "ssh_upload",
      ],
    );
    const checkTool = listedTools.find(
      (tool) => tool.name === "ssh_check_connection",
    );
    assert.ok(checkTool !== undefined);
    const checkOutputSchema = checkTool.outputSchema as Record<string, unknown>;
    const checkProperties = checkOutputSchema.properties as Record<
      string,
      unknown
    >;
    const failureReasonSchema = checkProperties.failureReason as Record<
      string,
      unknown
    >;
    assert.deepEqual(failureReasonSchema.enum, [
      "accessclient-session-unavailable",
      "accessclient-session-timeout",
      "accessclient-host-mismatch",
      "accessclient-session-ended",
    ]);

    const initialStatus = structuredContent(
      await peer.request("tools/call", {
        name: "ssh_gateway_status",
        arguments: {},
      }),
    );
    assert.equal(initialStatus.serviceRunning, false);
    assert.equal(initialStatus.gatewayReady, false);
    assert.equal(initialStatus.adminAvailable, false);
    assert.deepEqual(initialStatus.targets, []);

    const initialAdmin = structuredContent(
      await peer.request("tools/call", {
        name: "ssh_open_admin",
        arguments: {},
      }),
    );
    assert.equal(initialAdmin.opened, false);

    const unavailable = toolResult(
      await peer.request("tools/call", {
        name: "ssh_ping",
        arguments: {},
      }),
    );
    assert.equal(unavailable.isError, true);

    gateway = await startTestGateway(dataDirectory, "first-target");
    const adminUrl = `http://127.0.0.1:43123/#token=${"A".repeat(43)}`;
    await publishAdminDescriptor(dataDirectory, {
      version: 1,
      pid: process.pid,
      origin: "http://127.0.0.1:43123",
      url: adminUrl,
      startedAt: new Date().toISOString(),
    });
    const readyStatus = structuredContent(
      await peer.request("tools/call", {
        name: "ssh_gateway_status",
        arguments: {},
      }),
    );
    assert.equal(readyStatus.serviceRunning, true);
    assert.equal(readyStatus.gatewayReady, true);
    assert.equal(readyStatus.adminAvailable, true);
    assert.equal(
      (readyStatus.targets as Array<{ alias: string }>)[0]?.alias,
      "first-target",
    );
    const ping = structuredContent(
      await peer.request("tools/call", {
        name: "ssh_ping",
        arguments: {},
      }),
    );
    assert.equal(ping.ok, true);
    assert.equal(ping.protocolVersion, PROTOCOL_VERSION);

    const check = structuredContent(
      await peer.request("tools/call", {
        name: "ssh_check_connection",
        arguments: { target: "first-target" },
      }),
    );
    assert.equal(check.connected, true);
    assert.equal(check.hostname, "first-target.example");

    const firstRuntime = gateway.runtime;
    const firstTargets = structuredContent(
      await peer.request("tools/call", {
        name: "ssh_list_targets",
        arguments: {},
      }),
    );
    assert.equal(
      (firstTargets.targets as Array<{ alias: string }>)[0]?.alias,
      "first-target",
    );

    await gateway.stop();
    gateway = await startTestGateway(dataDirectory, "second-target");
    assert.notEqual(gateway.runtime.endpoint, firstRuntime.endpoint);
    assert.notEqual(gateway.runtime.token, firstRuntime.token);

    const secondTargets = structuredContent(
      await peer.request("tools/call", {
        name: "ssh_list_targets",
        arguments: {},
      }),
    );
    assert.equal(
      (secondTargets.targets as Array<{ alias: string }>)[0]?.alias,
      "second-target",
    );

    const failedExecution = toolResult(
      await peer.request("tools/call", {
        name: "ssh_exec",
        arguments: { target: "second-target", command: "hostname" },
      }),
    );
    assert.equal(failedExecution.isError, true);
    assert.equal(gateway.executionCount(), 1);
  },
);

test(
  "stdio MCP tasks survive the starting MCP process and remain controllable from a new process",
  { timeout: 40_000 },
  async (t) => {
    const root = await mkdtemp(path.join(tmpdir(), "agent-ssh-mcp-task-"));
    const dataDirectory = path.join(root, "runtime");
    const lease = await createRuntimeDescriptor(dataDirectory);
    const firstStarted = deferred<SshRunInput>();
    const firstRelease = deferred<void>();
    const secondStarted = deferred<SshRunInput>();
    let callCount = 0;
    const executor = new FakeSshExecutor(async (input) => {
      callCount += 1;
      if (callCount === 1) {
        await input.outputSink?.append(
          "stdout",
          Buffer.from("build:开始\n", "utf8"),
        );
        firstStarted.resolve(input);
        await firstRelease.promise;
        await input.outputSink?.append(
          "stdout",
          Buffer.from("build:完成\n", "utf8"),
        );
        return sshOutcome({ exitCode: 0, durationMs: 27 });
      }

      secondStarted.resolve(input);
      return new Promise((resolve) => {
        const finish = (): void => {
          resolve(
            sshOutcome({
              exitCode: null,
              aborted: true,
              durationMs: 11,
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
        policy: { mode: "full-access", maxTimeoutMs: 30_000 },
      },
    });
    const service = testExecService({ executor, registry });
    const server = new PipeRpcServer({
      runtime: lease.descriptor,
      dispatcher: new GatewayDispatcher(service),
      serverVersion: "mcp-task-test",
    });
    await server.listen();

    const starter = spawnMcp(dataDirectory);
    let observer: StdioMcpPeer | undefined;
    t.after(async () => {
      await starter.close().catch(() => undefined);
      await observer?.close().catch(() => undefined);
      await server.close();
      await service.shutdown();
      await lease.release();
      await rm(root, { recursive: true, force: true });
    });

    await starter.initialize();
    const startedTask = structuredContent(
      await starter.request("tools/call", {
        name: "ssh_start",
        arguments: {
          target: "builder",
          shell: "bash",
          cwd: "/srv/project",
          env: { BUILD_MODE: "release" },
          script: "npm run build",
        },
      }),
    );
    assert.equal(startedTask.state, "running");
    assert.equal(startedTask.kind, "exec");
    const firstRunId = String(startedTask.runId);
    assert.match(firstRunId, /^[A-Za-z0-9_-]{43}$/u);

    const firstInput = await firstStarted.promise;
    await starter.close();
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(firstInput.signal?.aborted, false);
    firstRelease.resolve();

    observer = spawnMcp(dataDirectory);
    await observer.initialize();
    let completedStatus: Record<string, unknown> | undefined;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      completedStatus = structuredContent(
        await observer.request("tools/call", {
          name: "ssh_status",
          arguments: { runId: firstRunId },
        }),
      );
      if (completedStatus.state !== "running") break;
      await new Promise<void>((resolve) => setTimeout(resolve, 5));
    }
    assert.equal(completedStatus?.state, "succeeded");
    assert.equal(completedStatus?.termination, "exit");

    const tail = structuredContent(
      await observer.request("tools/call", {
        name: "ssh_tail",
        arguments: { runId: firstRunId },
      }),
    );
    assert.equal(
      (tail.stdout as { text: string }).text,
      "build:开始\nbuild:完成\n",
    );
    assert.equal((tail.stdout as { hadDecodingErrors: boolean }).hadDecodingErrors, false);
    assert.equal(tail.eof, true);

    const cancellableTask = structuredContent(
      await observer.request("tools/call", {
        name: "ssh_start",
        arguments: {
          target: "builder",
          shell: "bash",
          script: "sleep 600",
        },
      }),
    );
    const secondRunId = String(cancellableTask.runId);
    const secondInput = await secondStarted.promise;
    const cancellation = structuredContent(
      await observer.request("tools/call", {
        name: "ssh_cancel",
        arguments: { runId: secondRunId },
      }),
    );
    assert.equal(cancellation.accepted, true);

    let cancelledStatus: Record<string, unknown> | undefined;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      cancelledStatus = structuredContent(
        await observer.request("tools/call", {
          name: "ssh_status",
          arguments: { runId: secondRunId },
        }),
      );
      if (cancelledStatus.state !== "running") break;
      await new Promise<void>((resolve) => setTimeout(resolve, 5));
    }
    assert.equal(secondInput.signal?.aborted, true);
    assert.equal(cancelledStatus?.state, "cancelled");
    assert.equal(cancelledStatus?.termination, "cancel");
    assert.equal(executor.calls.length, 2);
  },
);
