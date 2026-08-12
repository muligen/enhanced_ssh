import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { PipeRpcServer, type RpcDispatcher } from "../../src/daemon/pipe-server.js";
import { createRuntimeDescriptor } from "../../src/daemon/runtime-state.js";
import {
  GatewayRpcClient,
  RpcTimeoutError,
} from "../../src/shared/rpc-client.js";

test("Gateway RPC requests fail at their deadline when the daemon stops responding", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agent-ssh-rpc-timeout-"));
  const dataDirectory = path.join(root, "runtime");
  const lease = await createRuntimeDescriptor(dataDirectory);
  const dispatcher: RpcDispatcher = {
    dispatch(): Promise<never> {
      return new Promise<never>(() => undefined);
    },
  };
  const server = new PipeRpcServer({
    runtime: lease.descriptor,
    dispatcher,
    serverVersion: "rpc-timeout-test",
  });
  await server.listen();
  let client: GatewayRpcClient | undefined;
  t.after(async () => {
    client?.close();
    await server.close();
    await lease.release();
    await rm(root, { recursive: true, force: true });
  });

  client = await GatewayRpcClient.connect(dataDirectory, {
    name: "rpc-timeout-test",
    version: "1.0.0",
  });
  const result = client.requestTracked("system.ping", {}, { timeoutMs: 50 }).result;
  await assert.rejects(result, (error: unknown) => {
    assert.ok(error instanceof RpcTimeoutError);
    assert.equal(error.method, "system.ping");
    assert.equal(error.timeoutMs, 50);
    return true;
  });
});
