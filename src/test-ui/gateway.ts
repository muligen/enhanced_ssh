import { randomBytes, randomUUID } from "node:crypto";

import {
  GATEWAY_ERROR_CODES,
} from "../shared/errors.js";
import {
  GatewayRpcClient,
  RpcRemoteError,
} from "../shared/rpc-client.js";
import {
  PROTOCOL_VERSION,
  type DockerPreflightParams,
  type DockerPreflightResult,
  type DownloadParams,
  type ExecResult,
  type ExecRunParams,
  type OutputChunk,
  type OutputReadParams,
  type PingResult,
  type SyncParams,
  type TargetCheckParams,
  type TargetCheckResult,
  type TargetInspectResult,
  type TargetListResult,
  type TaskCancelResult,
  type TaskStartResult,
  type TaskStatusParams,
  type TaskStatusResult,
  type TaskTailParams,
  type TaskTailResult,
  type UploadParams,
} from "../shared/protocol.js";
import { GATEWAY_VERSION } from "../shared/version.js";

export interface TestUiGatewaySession {
  ping(): Promise<PingResult>;
  listTargets(): Promise<TargetListResult>;
  checkTarget(
    params: TargetCheckParams,
    signal: AbortSignal,
  ): Promise<TargetCheckResult>;
  inspectTarget?(
    params: TargetCheckParams,
    signal: AbortSignal,
  ): Promise<TargetInspectResult>;
  dockerPreflight?(
    params: DockerPreflightParams,
    signal: AbortSignal,
  ): Promise<DockerPreflightResult>;
  run(params: ExecRunParams, signal: AbortSignal): Promise<ExecResult>;
  startTask?(params: ExecRunParams): Promise<TaskStartResult>;
  taskStatus?(params: TaskStatusParams): Promise<TaskStatusResult>;
  taskTail?(params: TaskTailParams): Promise<TaskTailResult>;
  cancelTask?(params: TaskStatusParams): Promise<TaskCancelResult>;
  upload?(params: UploadParams): Promise<TaskStartResult>;
  download?(params: DownloadParams): Promise<TaskStartResult>;
  sync?(params: SyncParams): Promise<TaskStartResult>;
  readOutput(params: OutputReadParams): Promise<OutputChunk>;
  close(): void;
}

export type TestUiGatewayFactory = () => Promise<TestUiGatewaySession>;

export function createRpcGatewayFactory(
  dataDirectory: string,
): TestUiGatewayFactory {
  return async () => {
    const client = await GatewayRpcClient.connect(dataDirectory, {
      name: "agent-ssh-test-ui",
      version: GATEWAY_VERSION,
    });
    return new RpcGatewaySession(client);
  };
}

class RpcGatewaySession implements TestUiGatewaySession {
  readonly #client: GatewayRpcClient;

  public constructor(client: GatewayRpcClient) {
    this.#client = client;
  }

  public ping(): Promise<PingResult> {
    return this.#client.request("system.ping", {});
  }

  public listTargets(): Promise<TargetListResult> {
    return this.#client.request("target.list", {});
  }

  public checkTarget(
    params: TargetCheckParams,
    signal: AbortSignal,
  ): Promise<TargetCheckResult> {
    return this.#client.check(params, signal);
  }

  public inspectTarget(
    params: TargetCheckParams,
    signal: AbortSignal,
  ): Promise<TargetInspectResult> {
    const tracked = this.#client.requestTracked("target.inspect", params, {
      timeoutMs: 35_000,
      onTimeout: (requestId) => {
        void this.#client.request("exec.cancel", { requestId }).catch(() => undefined);
      },
    });
    return this.#settleCancellable(tracked, signal);
  }

  public dockerPreflight(
    params: DockerPreflightParams,
    signal: AbortSignal,
  ): Promise<DockerPreflightResult> {
    const tracked = this.#client.requestTracked("docker.preflight", params, {
      timeoutMs: 130_000,
      onTimeout: (requestId) => {
        void this.#client.request("exec.cancel", { requestId }).catch(() => undefined);
      },
    });
    return this.#settleCancellable(tracked, signal);
  }

  public run(params: ExecRunParams, signal: AbortSignal): Promise<ExecResult> {
    return this.#client.run(params, signal);
  }

  public startTask(params: ExecRunParams): Promise<TaskStartResult> {
    return this.#client.request("task.start", params);
  }

  public taskStatus(params: TaskStatusParams): Promise<TaskStatusResult> {
    return this.#client.request("task.status", params);
  }

  public taskTail(params: TaskTailParams): Promise<TaskTailResult> {
    return this.#client.request("task.tail", params);
  }

  public cancelTask(params: TaskStatusParams): Promise<TaskCancelResult> {
    return this.#client.request("task.cancel", params);
  }

  public upload(params: UploadParams): Promise<TaskStartResult> {
    return this.#client.request("transfer.upload", params);
  }

  public download(params: DownloadParams): Promise<TaskStartResult> {
    return this.#client.request("transfer.download", params);
  }

  public sync(params: SyncParams): Promise<TaskStartResult> {
    return this.#client.request("transfer.sync", params);
  }

  public readOutput(params: OutputReadParams): Promise<OutputChunk> {
    return this.#client.request("output.read", params);
  }

  async #settleCancellable<Result>(
    tracked: { readonly id: string | number; readonly result: Promise<Result> },
    signal: AbortSignal,
  ): Promise<Result> {
    const cancel = (): void => {
      void this.#client
        .request("exec.cancel", { requestId: tracked.id })
        .catch(() => undefined);
    };
    if (signal.aborted) cancel();
    else signal.addEventListener("abort", cancel, { once: true });
    try {
      return await tracked.result;
    } finally {
      signal.removeEventListener("abort", cancel);
    }
  }

  public close(): void {
    this.#client.close();
  }
}

interface DemoOutput {
  readonly expiresAtMs: number;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
}

const DEMO_INLINE_BYTES = 2_048;
const DEMO_OUTPUT_TTL_MS = 15 * 60 * 1_000;

export function createDemoGatewayFactory(): TestUiGatewayFactory {
  const state = new DemoGatewayState();
  return () => Promise.resolve(new DemoGatewaySession(state));
}

class DemoGatewayState {
  readonly outputs = new Map<string, DemoOutput>();

  public storeOutput(stdout: Buffer, stderr: Buffer): {
    readonly outputRef: string;
    readonly outputExpiresAt: string;
  } {
    this.cleanup();
    while (this.outputs.size >= 16) {
      const oldest = this.outputs.keys().next().value as string | undefined;
      if (oldest === undefined) {
        break;
      }
      this.outputs.delete(oldest);
    }
    const outputRef = randomBytes(32).toString("base64url");
    const expiresAtMs = Date.now() + DEMO_OUTPUT_TTL_MS;
    this.outputs.set(outputRef, { expiresAtMs, stdout, stderr });
    return {
      outputRef,
      outputExpiresAt: new Date(expiresAtMs).toISOString(),
    };
  }

  public requireOutput(reference: string): DemoOutput {
    this.cleanup();
    const output = this.outputs.get(reference);
    if (output === undefined) {
      throw new RpcRemoteError(-32040, "Output reference was not found", {
        gatewayCode: GATEWAY_ERROR_CODES.outputNotFound,
      });
    }
    return output;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [reference, output] of this.outputs) {
      if (output.expiresAtMs <= now) {
        this.outputs.delete(reference);
      }
    }
  }
}

class DemoGatewaySession implements TestUiGatewaySession {
  readonly #state: DemoGatewayState;

  public constructor(state: DemoGatewayState) {
    this.#state = state;
  }

  public ping(): Promise<PingResult> {
    return Promise.resolve({
      ok: true,
      protocolVersion: PROTOCOL_VERSION,
      serverTime: new Date().toISOString(),
    });
  }

  public listTargets(): Promise<TargetListResult> {
    return Promise.resolve({
      targets: [
        {
          targetId: "t-00000000000000000000000000000001",
          alias: "demo-linux",
          description: "Local demo target",
          enabled: true,
          platform: "linux",
          connectionMode: "openssh",
          policyMode: "allow-list",
          transferMode: "deny",
          transferScope: "restricted",
          transferRoots: [],
          maxTimeoutMs: 30_000,
        },
        {
          targetId: "t-00000000000000000000000000000002",
          alias: "frozen-production",
          description: "Disabled target example",
          enabled: false,
          platform: "linux",
          connectionMode: "openssh",
          policyMode: "deny",
          transferMode: "deny",
          transferScope: "restricted",
          transferRoots: [],
          maxTimeoutMs: 10_000,
        },
      ],
    });
  }

  public checkTarget(
    params: TargetCheckParams,
    signal: AbortSignal,
  ): Promise<TargetCheckResult> {
    if (params.target === "frozen-production") {
      return Promise.reject(
        new RpcRemoteError(-32021, "Target is disabled", {
          gatewayCode: GATEWAY_ERROR_CODES.targetDisabled,
        }),
      );
    }
    if (params.target !== "demo-linux") {
      return Promise.reject(
        new RpcRemoteError(-32020, "Target was not found", {
          gatewayCode: GATEWAY_ERROR_CODES.targetNotFound,
        }),
      );
    }
    if (signal.aborted) {
      return Promise.resolve({
        target: params.target,
        connected: false,
        termination: "cancel",
        exitCode: null,
        durationMs: 0,
      });
    }
    return Promise.resolve({
      target: params.target,
      connected: true,
      termination: "exit",
      exitCode: 0,
      durationMs: 1,
      hostname: "demo-linux-01",
    });
  }

  public async run(
    params: ExecRunParams,
    signal: AbortSignal,
  ): Promise<ExecResult> {
    const startedAt = performance.now();
    if (params.target === "frozen-production") {
      throw new RpcRemoteError(-32021, "Target is disabled", {
        gatewayCode: GATEWAY_ERROR_CODES.targetDisabled,
      });
    }
    if (params.target !== "demo-linux") {
      throw new RpcRemoteError(-32020, "Target was not found", {
        gatewayCode: GATEWAY_ERROR_CODES.targetNotFound,
      });
    }
    if ((params.timeoutMs ?? 30_000) > 30_000) {
      throw new RpcRemoteError(-32602, "Timeout exceeds target policy", {
        gatewayCode: GATEWAY_ERROR_CODES.invalidParams,
      });
    }
    if (!("command" in params)) {
      throw new RpcRemoteError(-32022, "Structured execution is not allowed", {
        gatewayCode: GATEWAY_ERROR_CODES.commandDenied,
      });
    }

    if (params.command === "sleep 5") {
      const timeoutMs = params.timeoutMs ?? 30_000;
      const cancelled = await waitForAbortOrDelay(
        signal,
        Math.min(5_000, timeoutMs),
      );
      if (cancelled) {
        return executionResult(
          "cancel",
          null,
          Buffer.alloc(0),
          Buffer.alloc(0),
          performance.now() - startedAt,
        );
      }
      if (timeoutMs < 5_000) {
        return executionResult(
          "timeout",
          null,
          Buffer.alloc(0),
          Buffer.alloc(0),
          performance.now() - startedAt,
        );
      }
    } else if (signal.aborted) {
      return executionResult(
        "cancel",
        null,
        Buffer.alloc(0),
        Buffer.alloc(0),
        performance.now() - startedAt,
      );
    }

    switch (params.command) {
      case "hostname":
        return executionResult(
          "exit",
          0,
          Buffer.from("demo-linux-01\n", "utf8"),
          Buffer.alloc(0),
          performance.now() - startedAt,
        );
      case "uname -a":
        return executionResult(
          "exit",
          0,
          Buffer.from(
            "Linux demo-linux-01 6.8.0 agent-ssh-demo x86_64 GNU/Linux\n",
            "utf8",
          ),
          Buffer.alloc(0),
          performance.now() - startedAt,
        );
      case "exit 7":
        return executionResult(
          "exit",
          7,
          Buffer.alloc(0),
          Buffer.from("demo command exited with status 7\n", "utf8"),
          performance.now() - startedAt,
        );
      case "large-output": {
        const stdout = Buffer.from(
          Array.from(
            { length: 4_096 },
            (_, index) => `demo output line ${String(index + 1).padStart(4, "0")}\n`,
          ).join(""),
          "utf8",
        );
        const reference = this.#state.storeOutput(stdout, Buffer.alloc(0));
        return executionResult(
          "exit",
          0,
          stdout,
          Buffer.alloc(0),
          performance.now() - startedAt,
          reference,
        );
      }
      case "render-test":
        return executionResult(
          "exit",
          0,
          Buffer.from(
            "<script>window.__agentSshXss = true</script>\n\u001b[31mplain ANSI text\u001b[0m\n",
            "utf8",
          ),
          Buffer.alloc(0),
          performance.now() - startedAt,
        );
      case "sleep 5":
        return executionResult(
          "exit",
          0,
          Buffer.from("demo wait completed\n", "utf8"),
          Buffer.alloc(0),
          performance.now() - startedAt,
        );
      default:
        throw new RpcRemoteError(-32022, "Command is not allowed", {
          gatewayCode: GATEWAY_ERROR_CODES.commandDenied,
        });
    }
  }

  public inspectTarget(): Promise<TargetInspectResult> {
    return Promise.reject(demoUnsupported());
  }

  public dockerPreflight(): Promise<DockerPreflightResult> {
    return Promise.reject(demoUnsupported());
  }

  public startTask(): Promise<TaskStartResult> {
    return Promise.reject(demoUnsupported());
  }

  public taskStatus(): Promise<TaskStatusResult> {
    return Promise.reject(demoUnsupported());
  }

  public taskTail(): Promise<TaskTailResult> {
    return Promise.reject(demoUnsupported());
  }

  public cancelTask(): Promise<TaskCancelResult> {
    return Promise.reject(demoUnsupported());
  }

  public upload(): Promise<TaskStartResult> {
    return Promise.reject(demoUnsupported());
  }

  public download(): Promise<TaskStartResult> {
    return Promise.reject(demoUnsupported());
  }

  public sync(): Promise<TaskStartResult> {
    return Promise.reject(demoUnsupported());
  }

  public readOutput(params: OutputReadParams): Promise<OutputChunk> {
    const output = this.#state.requireOutput(params.outputRef);
    const payload = output[params.stream];
    const start = Math.min(params.offset, payload.length);
    const end = Math.min(start + params.limit, payload.length);
    const eof = end >= payload.length;
    return Promise.resolve({
      dataBase64: payload.subarray(start, end).toString("base64"),
      nextOffset: eof ? null : end,
      eof,
      totalBytes: payload.length,
    });
  }

  public close(): void {}
}

function demoUnsupported(): RpcRemoteError {
  return new RpcRemoteError(-32601, "This operation requires a real gateway", {
    gatewayCode: GATEWAY_ERROR_CODES.internalError,
  });
}

function executionResult(
  termination: ExecResult["termination"],
  exitCode: number | null,
  stdout: Buffer,
  stderr: Buffer,
  durationMs: number,
  reference?: {
    readonly outputRef: string;
    readonly outputExpiresAt: string;
  },
): ExecResult {
  const stdoutInline = stdout.subarray(0, DEMO_INLINE_BYTES);
  const stderrInline = stderr.subarray(0, DEMO_INLINE_BYTES);
  return {
    requestId: randomUUID(),
    termination,
    exitCode,
    durationMs: Math.max(0, Math.round(durationMs)),
    stdout: {
      text: stdoutInline.toString("utf8"),
      bytes: stdout.length,
      inlineTruncated: stdoutInline.length < stdout.length,
    },
    stderr: {
      text: stderrInline.toString("utf8"),
      bytes: stderr.length,
      inlineTruncated: stderrInline.length < stderr.length,
    },
    ...(reference === undefined ? {} : reference),
  };
}

function waitForAbortOrDelay(
  signal: AbortSignal,
  delayMs: number,
): Promise<boolean> {
  if (signal.aborted) {
    return Promise.resolve(true);
  }
  return new Promise((resolve) => {
    let settled = false;
    const finish = (cancelled: boolean): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      resolve(cancelled);
    };
    const onAbort = (): void => finish(true);
    const timer = setTimeout(() => finish(false), delayMs);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}
