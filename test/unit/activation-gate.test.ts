import assert from "node:assert/strict";
import test from "node:test";

import { ActivationGateDispatcher } from "../../src/daemon/activation-gate.js";
import type {
  RpcDispatcher,
  RpcSessionContext,
} from "../../src/daemon/pipe-server.js";
import {
  GATEWAY_ERROR_CODES,
  GatewayError,
} from "../../src/shared/errors.js";

const context: RpcSessionContext = { sessionId: "test-session" };

test("rejects business RPCs without invoking the delegate before activation", async () => {
  let dispatchCalls = 0;
  const delegate: RpcDispatcher = {
    async dispatch() {
      dispatchCalls += 1;
      return { ok: true };
    },
  };
  const gate = new ActivationGateDispatcher(delegate);

  await assert.rejects(
    gate.dispatch("system.ping", {}, context, "request-1"),
    (error: unknown) => {
      assert.ok(error instanceof GatewayError);
      assert.equal(error.code, GATEWAY_ERROR_CODES.daemonNotActive);
      assert.equal(error.rpcCode, -32011);
      return true;
    },
  );
  assert.equal(dispatchCalls, 0);
});

test("activation is synchronous and idempotently enables the delegate", async () => {
  const calls: unknown[][] = [];
  const expected = { targets: [] };
  const delegate: RpcDispatcher = {
    async dispatch(...args) {
      calls.push(args);
      return expected;
    },
  };
  const gate = new ActivationGateDispatcher(delegate);

  assert.doesNotThrow(() => {
    gate.activate();
    gate.activate();
  });
  const result = await gate.dispatch("target.list", {}, context, 42);

  assert.equal(result, expected);
  assert.deepEqual(calls, [["target.list", {}, context, 42]]);
});

test("forwards disconnects to the delegate in the deferred state", async () => {
  const disconnected: RpcSessionContext[] = [];
  const delegate: RpcDispatcher = {
    async dispatch() {
      return undefined;
    },
    async disconnected(disconnectedContext) {
      await Promise.resolve();
      disconnected.push(disconnectedContext);
    },
  };
  const gate = new ActivationGateDispatcher(delegate);

  await gate.disconnected(context);

  assert.deepEqual(disconnected, [context]);
});
