import {
  GATEWAY_ERROR_CODES,
  GatewayError,
} from "../shared/errors.js";
import type { RpcId } from "../shared/protocol.js";
import type { RpcDispatcher, RpcSessionContext } from "./pipe-server.js";

/**
 * Keeps a listening candidate daemon fail-closed until its configuration has
 * been committed as active.
 */
export class ActivationGateDispatcher implements RpcDispatcher {
  readonly #delegate: RpcDispatcher;
  #active = false;

  public constructor(delegate: RpcDispatcher) {
    this.#delegate = delegate;
  }

  public activate(): void {
    this.#active = true;
  }

  public async dispatch(
    method: string,
    params: unknown,
    context: RpcSessionContext,
    requestId: RpcId,
  ): Promise<unknown> {
    if (!this.#active) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.daemonNotActive,
        "Gateway daemon is not active",
      );
    }
    return this.#delegate.dispatch(method, params, context, requestId);
  }

  public disconnected(context: RpcSessionContext): Promise<void> | void {
    return this.#delegate.disconnected?.(context);
  }
}
