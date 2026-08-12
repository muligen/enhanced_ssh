import assert from "node:assert/strict";
import test from "node:test";

import {
  REDACTED,
  REDACTED_BINARY,
  REDACTED_CIRCULAR,
  REDACTED_TRUNCATED,
  isSensitiveKey,
  redact,
  redactText,
} from "../../src/infra/redact.js";

test("redacts sensitive keys recursively without mutating the input", () => {
  const input = {
    target: "dev-linux",
    password: "hunter2",
    nested: {
      authorization: "Bearer abc",
      command: "cat /etc/shadow",
      stdout: "secret output",
      outputRef: "A".repeat(43),
      filePath: "C:\\secret\\audit.jsonl",
      sessionId: "session-credential",
    },
    commandSha256: "a".repeat(64),
    commandBytes: 10,
    stdoutBytes: 20,
    stderrBytes: 2,
  };

  const output = redact(input) as Record<string, unknown>;
  assert.equal(output.password, REDACTED);
  const nested = output.nested as Record<string, unknown>;
  assert.equal(nested.authorization, REDACTED);
  assert.equal(nested.command, REDACTED);
  assert.equal(nested.stdout, REDACTED);
  assert.equal(nested.outputRef, REDACTED);
  assert.equal(nested.filePath, REDACTED);
  assert.equal(nested.sessionId, REDACTED);
  assert.equal(output.commandSha256, "a".repeat(64));
  assert.equal(output.commandBytes, 10);
  assert.equal(output.stdoutBytes, 20);
  assert.equal(output.stderrBytes, 2);
  assert.equal(input.password, "hunter2");
});

test("redacts credentials, private keys, opaque refs, and absolute paths in text", () => {
  const opaqueReference = "B".repeat(43);
  const value = [
    "Authorization: Bearer token-value",
    "password=hunter2",
    "api_key='abc123'",
    "C:\\Users\\operator\\secret.txt",
    "D:/ProgramData/gateway/audit.jsonl",
    "/etc/ssh/ssh_config",
    "/Users/operator/.ssh/config",
    "file:///var/lib/gateway/output.bin",
    opaqueReference,
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "private-material",
    "-----END OPENSSH PRIVATE KEY-----",
  ].join("\n");

  const result = redactText(value);
  for (const secret of [
    "token-value",
    "hunter2",
    "abc123",
    "operator",
    "ssh_config",
    opaqueReference,
    "private-material",
  ]) {
    assert.equal(result.includes(secret), false);
  }
  assert.match(result, /\[REDACTED\]/);
});

test("does not invoke accessors and handles binary and cyclic values", () => {
  let getterInvoked = false;
  const input: Record<string, unknown> = {
    bytes: Buffer.from("secret"),
  };
  Object.defineProperty(input, "computed", {
    enumerable: true,
    get() {
      getterInvoked = true;
      return "secret";
    },
  });
  input.self = input;

  const output = redact(input) as Record<string, unknown>;
  assert.equal(getterInvoked, false);
  assert.equal(output.bytes, REDACTED_BINARY);
  assert.equal(output.computed, REDACTED);
  assert.equal(output.self, REDACTED_CIRCULAR);
});

test("bounds recursion and recognizes derived safe audit fields", () => {
  assert.equal(isSensitiveKey("command"), true);
  assert.equal(isSensitiveKey("remote_command"), true);
  assert.equal(isSensitiveKey("commandSha256"), false);
  assert.equal(isSensitiveKey("commandBytes"), false);
  assert.equal(isSensitiveKey("stdoutBytes"), false);

  const output = redact({ one: { two: { three: true } } }, { maxDepth: 1 });
  assert.deepEqual(output, {
    one: {
      two: REDACTED_TRUNCATED,
    },
  });
});
