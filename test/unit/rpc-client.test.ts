import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import {
  GatewayRpcClient,
  RpcTimeoutError,
} from "../../src/shared/rpc-client.js";

class MemorySocket extends EventEmitter {
  readonly frames: Buffer[] = [];

  public write(
    frame: Buffer,
    callback?: (error?: Error | null) => void,
  ): boolean {
    this.frames.push(Buffer.from(frame));
    callback?.();
    return true;
  }

  public end(): this {
    return this;
  }
}

function createMemoryClient(socket: MemorySocket): GatewayRpcClient {
  return Reflect.construct(
    GatewayRpcClient as unknown as Function,
    [socket],
  ) as GatewayRpcClient;
}

test("target.check leaves response grace beyond the 30-second AccessClient probe", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const socket = new MemorySocket();
  const client = createMemoryClient(socket);
  t.after(() => client.close());

  const checked = client.check({ target: "accessclient" });
  let settled = false;
  void checked.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    },
  );

  t.mock.timers.tick(34_999);
  await Promise.resolve();
  assert.equal(settled, false);

  t.mock.timers.tick(1);
  await assert.rejects(checked, (error: unknown) => {
    assert.ok(error instanceof RpcTimeoutError);
    assert.equal(error.method, "target.check");
    assert.equal(error.timeoutMs, 35_000);
    return true;
  });
  assert.equal(socket.frames.length, 2);
});
