import { ExecService } from "../core/exec-service.js";
import type { TransferService } from "../core/transfer-service.js";
import {
  GATEWAY_ERROR_CODES,
  GatewayError,
  JSON_RPC_ERROR_CODES,
} from "../shared/errors.js";
import {
  PROTOCOL_VERSION,
  parseRpcParams,
  rpcMethodSchema,
  type RpcId,
} from "../shared/protocol.js";
import type { RpcDispatcher, RpcSessionContext } from "./pipe-server.js";

export class GatewayDispatcher implements RpcDispatcher {
  readonly #service: ExecService;
  readonly #transfers: TransferService | undefined;

  public constructor(service: ExecService, transfers?: TransferService) {
    this.#service = service;
    this.#transfers = transfers;
  }

  public async dispatch(
    methodName: string,
    rawParams: unknown,
    context: RpcSessionContext,
    requestId: RpcId,
  ): Promise<unknown> {
    const parsedMethod = rpcMethodSchema.safeParse(methodName);
    if (!parsedMethod.success || parsedMethod.data === "session.open") {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.invalidParams,
        "Method not found",
        { rpcCode: JSON_RPC_ERROR_CODES.methodNotFound },
      );
    }
    const method = parsedMethod.data;

    switch (method) {
      case "system.ping": {
        parseRpcParams("system.ping", rawParams ?? {});
        return {
          ok: true,
          protocolVersion: PROTOCOL_VERSION,
          serverTime: new Date().toISOString(),
        };
      }
      case "target.list":
        parseRpcParams("target.list", rawParams ?? {});
        return { targets: [...this.#service.listTargets()], groups: [...this.#service.listGroups()] };
      case "operation.list": {
        const params = parseRpcParams("operation.list", rawParams);
        return this.#service.listAllowedOperations(params.target);
      }
      case "operation.run": {
        const params = parseRpcParams("operation.run", rawParams);
        return this.#service.runOperation({ sessionId: context.sessionId }, requestId, params);
      }
      case "target.check": {
        const params = parseRpcParams("target.check", rawParams);
        return this.#service.check(
          { sessionId: context.sessionId },
          requestId,
          params,
        );
      }
      case "target.inspect": {
        const params = parseRpcParams("target.inspect", rawParams);
        return this.#service.inspect(
          { sessionId: context.sessionId },
          requestId,
          params,
        );
      }
      case "docker.preflight": {
        const params = parseRpcParams("docker.preflight", rawParams);
        return this.#service.dockerPreflight(
          { sessionId: context.sessionId },
          requestId,
          params,
        );
      }
      case "transfer.upload": {
        const params = parseRpcParams("transfer.upload", rawParams);
        return this.#requireTransfers().startUpload(params);
      }
      case "transfer.download": {
        const params = parseRpcParams("transfer.download", rawParams);
        return this.#requireTransfers().startDownload(params);
      }
      case "transfer.sync": {
        const params = parseRpcParams("transfer.sync", rawParams);
        return this.#requireTransfers().startSync(params);
      }
      case "exec.run": {
        const params = parseRpcParams("exec.run", rawParams);
        return this.#service.run(
          { sessionId: context.sessionId },
          requestId,
          params,
        );
      }
      case "task.start": {
        const params = parseRpcParams("task.start", rawParams);
        return this.#service.startTask(params);
      }
      case "task.status": {
        const params = parseRpcParams("task.status", rawParams);
        return this.#service.taskStatus(params.runId);
      }
      case "task.tail": {
        const params = parseRpcParams("task.tail", rawParams);
        return this.#service.taskTail(params.runId, params.cursor, params.limit);
      }
      case "task.cancel": {
        const params = parseRpcParams("task.cancel", rawParams);
        return this.#service.cancelTask(params.runId);
      }
      case "exec.cancel": {
        const params = parseRpcParams("exec.cancel", rawParams);
        return {
          accepted: this.#service.cancel(context.sessionId, params.requestId),
        };
      }
      case "output.read": {
        const params = parseRpcParams("output.read", rawParams);
        return this.#service.readOutput(params);
      }
      case "output.readText": {
        const params = parseRpcParams("output.readText", rawParams);
        return this.#service.readOutputText(params);
      }
    }
  }

  public disconnected(context: RpcSessionContext): void {
    this.#service.disconnect(context.sessionId);
  }

  #requireTransfers(): TransferService {
    if (this.#transfers === undefined) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.internalError,
        "File transfer capability is not initialized",
      );
    }
    return this.#transfers;
  }
}
