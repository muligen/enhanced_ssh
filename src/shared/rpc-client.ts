import { randomUUID } from "node:crypto";
import { isUtf8 } from "node:buffer";
import net from "node:net";
import { z } from "zod/v4";
import { loadRuntimeDescriptor } from "../daemon/runtime-state.js";
import {
  MAX_RPC_FRAME_BYTES,
  MAX_TIMEOUT_MS,
  PROTOCOL_VERSION,
  parseRpcResult,
  type ExecResult,
  type RpcId,
  type RpcMethod,
  type RpcParamsByMethod,
  type RpcResultByMethod,
  type TargetCheckResult,
} from "./protocol.js";

type JsonRpcId = RpcId;

const JsonRpcResponseSchema = z.union([
  z.strictObject({
    jsonrpc: z.literal("2.0"),
    id: z.union([z.string().min(1).max(128), z.number().int().safe()]),
    result: z.unknown(),
  }),
  z.strictObject({
    jsonrpc: z.literal("2.0"),
    id: z.union([
      z.string().min(1).max(128),
      z.number().int().safe(),
      z.null(),
    ]),
    error: z.strictObject({
      code: z.number().int(),
      message: z.string(),
      data: z.unknown().optional(),
    }),
  }),
]);

type JsonRpcResponse = z.infer<typeof JsonRpcResponseSchema>;

export class RpcRemoteError extends Error {
  public readonly rpcCode: number;
  public readonly data: unknown;

  public constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = "RpcRemoteError";
    this.rpcCode = code;
    this.data = data;
  }
}

export interface RpcClientIdentity {
  name: string;
  version: string;
}

export interface TrackedRpcRequest<Result> {
  readonly id: RpcId;
  readonly result: Promise<Result>;
}

interface PendingRequest {
  resolve(value: unknown): void;
  reject(error: Error): void;
  readonly timeout: NodeJS.Timeout;
}

interface RequestDeadlineOptions {
  readonly timeoutMs?: number;
  readonly onTimeout?: (requestId: RpcId) => void;
}

const RPC_HANDSHAKE_TIMEOUT_MS = 5_000;
const RPC_REQUEST_TIMEOUT_MS = 30_000;
const RPC_EXEC_RESPONSE_GRACE_MS = 10_000;
// AccessClient probes may consume the full 30-second server allowance. Keep
// transport and response handling outside that execution deadline.
const RPC_CHECK_RESPONSE_TIMEOUT_MS = 35_000;

export class RpcTimeoutError extends Error {
  public readonly method: RpcMethod;
  public readonly timeoutMs: number;

  public constructor(method: RpcMethod, timeoutMs: number) {
    super(`Gateway RPC ${method} timed out after ${timeoutMs} ms`);
    this.name = "RpcTimeoutError";
    this.method = method;
    this.timeoutMs = timeoutMs;
  }
}

export class GatewayRpcClient {
  readonly #socket: net.Socket;
  readonly #pending = new Map<JsonRpcId, PendingRequest>();
  #buffer = Buffer.alloc(0);
  #closed = false;

  private constructor(socket: net.Socket) {
    this.#socket = socket;
    socket.on("data", (chunk: Buffer) => this.#acceptChunk(chunk));
    socket.on("error", (error) => this.#failAll(error));
    socket.on("close", () =>
      this.#failAll(new Error("Gateway RPC connection closed")),
    );
  }

  public static async connect(
    dataDirectory: string,
    identity: RpcClientIdentity,
  ): Promise<GatewayRpcClient> {
    const runtime = await loadRuntimeDescriptor(dataDirectory);
    const socket = await connectSocket(runtime.endpoint);
    const client = new GatewayRpcClient(socket);
    try {
      await client.requestTracked(
        "session.open",
        {
          token: runtime.token,
          protocolVersion: PROTOCOL_VERSION,
          client: {
            ...identity,
            pid: process.pid,
          },
        },
        { timeoutMs: RPC_HANDSHAKE_TIMEOUT_MS },
      ).result;
      return client;
    } catch (error) {
      client.close();
      throw error;
    }
  }

  public request<Method extends RpcMethod>(
    method: Method,
    params: RpcParamsByMethod[Method],
  ): Promise<RpcResultByMethod[Method]> {
    return this.requestTracked(method, params).result;
  }

  public requestTracked<Method extends RpcMethod>(
    method: Method,
    params: RpcParamsByMethod[Method],
    options: RequestDeadlineOptions = {},
  ): TrackedRpcRequest<RpcResultByMethod[Method]> {
    const timeoutMs = options.timeoutMs ?? RPC_REQUEST_TIMEOUT_MS;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
      throw new RangeError("Gateway RPC timeout must be a positive integer");
    }
    const id = randomUUID();
    return {
      id,
      result: this.#sendRequest(
        id,
        method,
        params,
        timeoutMs,
        options.onTimeout,
      ).then((result) => parseRpcResult(method, result)),
    };
  }

  public async run(
    params: RpcParamsByMethod["exec.run"],
    signal?: AbortSignal,
  ): Promise<ExecResult> {
    const tracked = this.requestTracked("exec.run", params, {
      timeoutMs:
        (params.timeoutMs ?? MAX_TIMEOUT_MS) + RPC_EXEC_RESPONSE_GRACE_MS,
      onTimeout: (requestId) => {
        void this.request("exec.cancel", { requestId }).catch(() => undefined);
      },
    });
    const cancel = (): void => {
      void this.request("exec.cancel", { requestId: tracked.id }).catch(
        () => undefined,
      );
    };

    if (signal?.aborted) {
      cancel();
    } else {
      signal?.addEventListener("abort", cancel, { once: true });
    }

    try {
      const result = await tracked.result;
      if (result.requestId !== tracked.id) {
        throw new Error("Gateway returned a mismatched execution request ID");
      }
      return result;
    } finally {
      signal?.removeEventListener("abort", cancel);
    }
  }

  public async check(
    params: RpcParamsByMethod["target.check"],
    signal?: AbortSignal,
  ): Promise<TargetCheckResult> {
    const tracked = this.requestTracked("target.check", params, {
      timeoutMs: RPC_CHECK_RESPONSE_TIMEOUT_MS,
      onTimeout: (requestId) => {
        void this.request("exec.cancel", { requestId }).catch(() => undefined);
      },
    });
    const cancel = (): void => {
      void this.request("exec.cancel", { requestId: tracked.id }).catch(
        () => undefined,
      );
    };

    if (signal?.aborted) {
      cancel();
    } else {
      signal?.addEventListener("abort", cancel, { once: true });
    }

    try {
      const result = await tracked.result;
      if (result.target !== params.target) {
        throw new Error("Gateway returned a mismatched target check result");
      }
      return result;
    } finally {
      signal?.removeEventListener("abort", cancel);
    }
  }

  #sendRequest(
    id: RpcId,
    method: RpcMethod,
    params: unknown,
    timeoutMs: number,
    onTimeout?: (requestId: RpcId) => void,
  ): Promise<unknown> {
    if (this.#closed) {
      return Promise.reject(new Error("Gateway RPC client is closed"));
    }

    const frame = Buffer.from(
      `${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`,
      "utf8",
    );
    if (frame.length > MAX_RPC_FRAME_BYTES) {
      return Promise.reject(new Error("Gateway RPC request exceeds 1 MiB"));
    }

    return new Promise<unknown>((resolve, reject) => {
      const timeout = setTimeout(() => {
        if (!this.#pending.delete(id)) {
          return;
        }
        try {
          onTimeout?.(id);
        } finally {
          reject(new RpcTimeoutError(method, timeoutMs));
        }
      }, timeoutMs);
      this.#pending.set(id, {
        resolve,
        reject,
        timeout,
      });
      this.#socket.write(frame, (error) => {
        if (error && this.#pending.delete(id)) {
          clearTimeout(timeout);
          reject(error);
        }
      });
    });
  }

  public close(): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#socket.end();
    this.#failAll(new Error("Gateway RPC client closed"));
  }

  #acceptChunk(chunk: Buffer): void {
    this.#buffer = Buffer.concat([this.#buffer, chunk]);
    if (
      this.#buffer.length > MAX_RPC_FRAME_BYTES &&
      !this.#buffer.includes(0x0a)
    ) {
      this.#failAll(new Error("Gateway RPC response exceeds 1 MiB"));
      this.#socket.destroy();
      return;
    }

    let newlineIndex = this.#buffer.indexOf(0x0a);
    while (newlineIndex >= 0) {
      const line = this.#buffer.subarray(0, newlineIndex);
      this.#buffer = this.#buffer.subarray(newlineIndex + 1);
      if (line.length > MAX_RPC_FRAME_BYTES) {
        this.#failAll(new Error("Gateway RPC response exceeds 1 MiB"));
        this.#socket.destroy();
        return;
      }
      if (line.length > 0) {
        this.#acceptResponse(line);
      }
      newlineIndex = this.#buffer.indexOf(0x0a);
    }
  }

  #acceptResponse(line: Buffer): void {
    let response: JsonRpcResponse;
    try {
      if (!isUtf8(line)) {
        throw new SyntaxError("Response is not valid UTF-8");
      }
      response = JsonRpcResponseSchema.parse(
        JSON.parse(line.toString("utf8")) as unknown,
      );
    } catch (error) {
      this.#failAll(new Error("Gateway returned invalid JSON", { cause: error }));
      this.#socket.destroy();
      return;
    }

    if (response.jsonrpc !== "2.0" || response.id === null) {
      this.#failAll(new Error("Gateway returned an invalid JSON-RPC response"));
      this.#socket.destroy();
      return;
    }
    const pending = this.#pending.get(response.id);
    if (!pending) {
      return;
    }
    this.#pending.delete(response.id);
    clearTimeout(pending.timeout);
    if ("error" in response) {
      pending.reject(
        new RpcRemoteError(
          response.error.code,
          response.error.message,
          response.error.data,
        ),
      );
    } else {
      pending.resolve(response.result);
    }
  }

  #failAll(error: Error): void {
    if (!this.#closed) {
      this.#closed = true;
    }
    for (const pending of this.#pending.values()) {
      clearTimeout(pending.timeout);
      pending.reject(error);
    }
    this.#pending.clear();
  }
}

function connectSocket(endpoint: string): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(endpoint);
    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error("Timed out connecting to the SSH Gateway"));
    }, 5_000);
    socket.once("connect", () => {
      clearTimeout(timeout);
      resolve(socket);
    });
    socket.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });
}
