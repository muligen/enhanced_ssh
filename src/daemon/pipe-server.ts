import { randomBytes } from "node:crypto";
import { isUtf8 } from "node:buffer";
import net from "node:net";
import { unlink } from "node:fs/promises";
import { z } from "zod/v4";
import {
  GATEWAY_ERROR_CODES,
  JSON_RPC_ERROR_CODES,
  toPublicError,
} from "../shared/errors.js";
import {
  MAX_RPC_FRAME_BYTES,
  PROTOCOL_VERSION,
  rpcIdSchema,
  sessionOpenParamsSchema,
  type RpcId,
} from "../shared/protocol.js";
import {
  constantTimeTokenEquals,
  type RuntimeDescriptor,
} from "./runtime-state.js";

const HANDSHAKE_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_INFLIGHT_REQUESTS = 16;
const MAX_PENDING_RESPONSE_BYTES = MAX_RPC_FRAME_BYTES * 4;

const JsonRpcRequestSchema = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: rpcIdSchema,
    method: z.string().min(1).max(128),
    params: z.unknown().optional(),
  })
  .strict();
const SessionOpenAttemptSchema = sessionOpenParamsSchema.extend({
  protocolVersion: z.number().int().safe(),
});

export interface RpcSessionContext {
  sessionId: string;
}

export interface RpcDispatcher {
  dispatch(
    method: string,
    params: unknown,
    context: RpcSessionContext,
    requestId: RpcId,
  ): Promise<unknown>;
  disconnected?(context: RpcSessionContext): Promise<void> | void;
}

export interface PipeRpcServerOptions {
  runtime: RuntimeDescriptor;
  dispatcher: RpcDispatcher;
  serverVersion: string;
  maxConnections?: number;
  maxInflightRequestsPerConnection?: number;
}

interface ConnectionState {
  socket: net.Socket;
  buffer: Buffer;
  context?: RpcSessionContext;
  handshakeTimer: NodeJS.Timeout;
  inflightRequests: number;
}

export class PipeRpcServer {
  readonly #server: net.Server;
  readonly #runtime: RuntimeDescriptor;
  readonly #dispatcher: RpcDispatcher;
  readonly #serverVersion: string;
  readonly #connections = new Set<ConnectionState>();
  readonly #maxConnections: number;
  readonly #maxInflightRequestsPerConnection: number;

  public constructor(options: PipeRpcServerOptions) {
    this.#runtime = options.runtime;
    this.#dispatcher = options.dispatcher;
    this.#serverVersion = options.serverVersion;
    this.#maxConnections = requirePositiveInteger(
      options.maxConnections ?? 32,
      "maxConnections",
    );
    this.#maxInflightRequestsPerConnection = requirePositiveInteger(
      options.maxInflightRequestsPerConnection ?? DEFAULT_MAX_INFLIGHT_REQUESTS,
      "maxInflightRequestsPerConnection",
    );
    this.#server = net.createServer((socket) => this.#acceptConnection(socket));
  }

  public async listen(): Promise<void> {
    if (process.platform !== "win32") {
      if (Buffer.byteLength(this.#runtime.endpoint) > 103) {
        throw new Error("Runtime directory is too long for a Unix socket; use a shorter managed directory");
      }
      await unlink(this.#runtime.endpoint).catch((error: NodeJS.ErrnoException) => {
        if (error.code !== "ENOENT") {
          throw error;
        }
      });
    }

    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => reject(error);
      this.#server.once("error", onError);
      this.#server.listen(this.#runtime.endpoint, () => {
        this.#server.off("error", onError);
        resolve();
      });
    });
  }

  public async close(): Promise<void> {
    for (const connection of this.#connections) {
      connection.socket.destroy();
    }
    await new Promise<void>((resolve, reject) => {
      if (!this.#server.listening) {
        resolve();
        return;
      }
      this.#server.close((error) => (error ? reject(error) : resolve()));
    });
    if (process.platform !== "win32") {
      await unlink(this.#runtime.endpoint).catch(() => undefined);
    }
  }

  #acceptConnection(socket: net.Socket): void {
    if (this.#connections.size >= this.#maxConnections) {
      socket.destroy();
      return;
    }
    socket.setNoDelay(true);
    const state: ConnectionState = {
      socket,
      buffer: Buffer.alloc(0),
      handshakeTimer: setTimeout(() => socket.destroy(), HANDSHAKE_TIMEOUT_MS),
      inflightRequests: 0,
    };
    this.#connections.add(state);
    socket.on("data", (chunk: Buffer) => this.#acceptChunk(state, chunk));
    socket.on("error", () => undefined);
    socket.on("close", () => void this.#closeConnection(state));
  }

  #acceptChunk(state: ConnectionState, chunk: Buffer): void {
    state.buffer = Buffer.concat([state.buffer, chunk]);
    if (
      state.buffer.length > MAX_RPC_FRAME_BYTES &&
      !state.buffer.includes(0x0a)
    ) {
      this.#writeError(state.socket, null, -32600, "Request frame exceeds 1 MiB");
      state.socket.destroy();
      return;
    }

    let newlineIndex = state.buffer.indexOf(0x0a);
    while (newlineIndex >= 0) {
      const line = state.buffer.subarray(0, newlineIndex);
      state.buffer = state.buffer.subarray(newlineIndex + 1);
      if (line.length > MAX_RPC_FRAME_BYTES) {
        this.#writeError(state.socket, null, -32600, "Request frame exceeds 1 MiB");
        state.socket.destroy();
        return;
      }
      if (line.length > 0) {
        void this.#acceptFrame(state, line);
      }
      newlineIndex = state.buffer.indexOf(0x0a);
    }
  }

  async #acceptFrame(state: ConnectionState, line: Buffer): Promise<void> {
    if (state.socket.destroyed) {
      return;
    }
    let raw: unknown;
    try {
      if (!isUtf8(line)) {
        throw new SyntaxError("Request is not valid UTF-8");
      }
      raw = JSON.parse(line.toString("utf8")) as unknown;
    } catch {
      this.#writeError(state.socket, null, -32700, "Parse error");
      if (state.context === undefined) {
        state.socket.destroy();
      }
      return;
    }

    const parsed = JsonRpcRequestSchema.safeParse(raw);
    if (!parsed.success) {
      this.#writeError(state.socket, null, -32600, "Invalid Request");
      if (state.context === undefined) {
        state.socket.destroy();
      }
      return;
    }
    const request = parsed.data;

    if (!state.context) {
      if (request.method !== "session.open") {
        this.#writeError(state.socket, request.id, -32001, "Authentication required");
        state.socket.destroy();
        return;
      }
      const params = SessionOpenAttemptSchema.safeParse(request.params);
      if (
        !params.success ||
        !constantTimeTokenEquals(params.data.token, this.#runtime.token)
      ) {
        this.#writeError(state.socket, request.id, -32001, "Authentication failed");
        state.socket.destroy();
        return;
      }
      if (params.data.protocolVersion !== PROTOCOL_VERSION) {
        this.#writeError(
          state.socket,
          request.id,
          -32002,
          "Protocol version mismatch",
          {
            gatewayCode: GATEWAY_ERROR_CODES.protocolVersionMismatch,
            details: {
              expectedProtocolVersion: PROTOCOL_VERSION,
              receivedProtocolVersion: params.data.protocolVersion,
            },
          },
        );
        state.socket.destroy();
        return;
      }
      clearTimeout(state.handshakeTimer);
      state.context = {
        sessionId: randomBytes(32).toString("base64url"),
      };
      this.#writeResult(state.socket, request.id, {
        protocolVersion: PROTOCOL_VERSION,
        serverVersion: this.#serverVersion,
        sessionId: state.context.sessionId,
      });
      return;
    }

    if (request.method === "session.open") {
      this.#writeError(state.socket, request.id, -32600, "Session is already open");
      return;
    }

    if (
      state.inflightRequests >= this.#maxInflightRequestsPerConnection
    ) {
      state.socket.destroy(new Error("Too many in-flight RPC requests"));
      return;
    }
    state.inflightRequests += 1;

    try {
      const result = await this.#dispatcher.dispatch(
        request.method,
        request.params,
        state.context,
        request.id,
      );
      this.#writeResult(state.socket, request.id, result);
    } catch (error) {
      if (error instanceof z.ZodError) {
        this.#writeError(
          state.socket,
          request.id,
          JSON_RPC_ERROR_CODES.invalidParams,
          "Invalid params",
        );
        return;
      }
      const publicError = toPublicError(error);
      this.#writeError(
        state.socket,
        request.id,
        publicError.code,
        publicError.message,
        publicError.data,
      );
    } finally {
      state.inflightRequests -= 1;
    }
  }

  async #closeConnection(state: ConnectionState): Promise<void> {
    clearTimeout(state.handshakeTimer);
    this.#connections.delete(state);
    if (state.context && this.#dispatcher.disconnected) {
      await Promise.resolve(this.#dispatcher.disconnected(state.context)).catch(
        () => undefined,
      );
    }
  }

  #writeResult(socket: net.Socket, id: string | number, result: unknown): void {
    this.#writeFrame(socket, { jsonrpc: "2.0", id, result });
  }

  #writeError(
    socket: net.Socket,
    id: string | number | null,
    code: number,
    message: string,
    data?: unknown,
  ): void {
    this.#writeFrame(socket, {
      jsonrpc: "2.0",
      id,
      error: data === undefined ? { code, message } : { code, message, data },
    });
  }

  #writeFrame(socket: net.Socket, value: unknown): void {
    if (socket.destroyed) {
      return;
    }
    const frame = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
    if (frame.length > MAX_RPC_FRAME_BYTES) {
      socket.destroy(new Error("Response frame exceeds 1 MiB"));
      return;
    }
    if (socket.writableLength + frame.length > MAX_PENDING_RESPONSE_BYTES) {
      socket.destroy(new Error("RPC response backpressure limit exceeded"));
      return;
    }
    socket.write(frame);
  }
}

function requirePositiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${name} must be a positive safe integer`);
  }
  return value;
}
