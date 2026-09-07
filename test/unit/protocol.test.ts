import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_COMMAND_BYTES,
  MAX_TASK_TAIL_BYTES,
  PROTOCOL_VERSION,
  execResultSchema,
  outputChunkSchema,
  outputReadTextParamsSchema,
  outputTextChunkSchema,
  parseRpcRequest,
  parseRpcResult,
  targetCheckResultSchema,
  targetSummarySchema,
} from "../../src/shared/protocol.js";

test("parseRpcRequest validates the session.open handshake", () => {
  assert.equal(PROTOCOL_VERSION, 7);
  const request = parseRpcRequest({
    jsonrpc: "2.0",
    id: "handshake-1",
    method: "session.open",
    params: {
      token: "a".repeat(43),
      protocolVersion: PROTOCOL_VERSION,
      client: { name: "unit-test", version: "1.0.0", pid: 42 },
    },
  });

  assert.equal(request.method, "session.open");
  assert.equal(request.params.protocolVersion, PROTOCOL_VERSION);

  assert.throws(() =>
    parseRpcRequest({
      jsonrpc: "2.0",
      id: "old-handshake",
      method: "session.open",
      params: {
        token: "a".repeat(43),
        protocolVersion: 3,
        client: { name: "unit-test", version: "1.0.0" },
      },
    }),
  );
});

test("parseRpcRequest rejects unknown methods and fields", () => {
  assert.throws(() =>
    parseRpcRequest({
      jsonrpc: "2.0",
      id: 1,
      method: "ssh.raw",
      params: {},
    }),
  );

  assert.throws(() =>
    parseRpcRequest({
      jsonrpc: "2.0",
      id: 2,
      method: "exec.run",
      params: {
        target: "dev-linux",
        command: "hostname",
        host: "attacker.example",
      },
    }),
  );
});

test("exec.run rejects blank and oversized UTF-8 commands", () => {
  assert.throws(() =>
    parseRpcRequest({
      jsonrpc: "2.0",
      id: 1,
      method: "exec.run",
      params: { target: "dev-linux", command: "  \r\n " },
    }),
  );

  assert.throws(() =>
    parseRpcRequest({
      jsonrpc: "2.0",
      id: 2,
      method: "exec.run",
      params: { target: "dev-linux", command: "hostname\nwhoami" },
    }),
  );

  const oversized = "\u754c".repeat(Math.floor(MAX_COMMAND_BYTES / 3) + 1);
  assert.ok(Buffer.byteLength(oversized, "utf8") > MAX_COMMAND_BYTES);
  assert.throws(() =>
    parseRpcRequest({
      jsonrpc: "2.0",
      id: 3,
      method: "exec.run",
      params: { target: "dev-linux", command: oversized },
    }),
  );
});

test("exec.run and task.start accept the same strict structured execution shape", () => {
  for (const method of ["exec.run", "task.start"] as const) {
    const request = parseRpcRequest({
      jsonrpc: "2.0",
      id: method,
      method,
      params: {
        target: "build-linux",
        shell: "bash",
        cwd: "/srv/project with spaces",
        env: { RELEASE_CHANNEL: "candidate", LANG: "zh_CN.UTF-8" },
        script: "npm ci\nnpm run build",
      },
    });

    assert.equal(request.method, method);
    assert.equal("script" in request.params, true);
    if (!("script" in request.params)) {
      throw new Error("Expected structured execution params");
    }
    assert.equal(request.params.encoding, "utf-8");
    assert.equal(request.params.script, "npm ci\nnpm run build");
  }

  for (const params of [
    {
      target: "build-linux",
      command: "hostname",
      shell: "bash",
      script: "hostname",
    },
    { target: "build-linux", shell: "zsh", script: "hostname" },
    { target: "build-linux", shell: "bash", script: "hostname", cwd: "bad\npath" },
    { target: "build-linux", shell: "bash", script: "hostname", env: { "BAD-NAME": "x" } },
    { target: "build-linux", shell: "bash", script: "hostname", encoding: "gbk" },
  ]) {
    assert.throws(() =>
      parseRpcRequest({
        jsonrpc: "2.0",
        id: "structured-invalid",
        method: "task.start",
        params,
      }),
    );
  }
});

test("task RPC schemas apply bounded tail defaults and validate results", () => {
  const runId = Buffer.alloc(32, 9).toString("base64url");
  const tail = parseRpcRequest({
    jsonrpc: "2.0",
    id: "tail-default",
    method: "task.tail",
    params: { runId },
  });
  assert.equal(tail.method, "task.tail");
  assert.equal(tail.params.limit, 32_768);

  assert.throws(() =>
    parseRpcRequest({
      jsonrpc: "2.0",
      id: "tail-too-large",
      method: "task.tail",
      params: { runId, limit: MAX_TASK_TAIL_BYTES + 1 },
    }),
  );
  assert.throws(() =>
    parseRpcRequest({
      jsonrpc: "2.0",
      id: "bad-run-id",
      method: "task.status",
      params: { runId: "predictable-id" },
    }),
  );

  assert.deepEqual(
    parseRpcResult("task.start", {
      runId,
      target: "build-linux",
      kind: "exec",
      state: "running",
      startedAt: "2026-08-07T10:00:00.000Z",
    }),
    {
      runId,
      target: "build-linux",
      kind: "exec",
      state: "running",
      startedAt: "2026-08-07T10:00:00.000Z",
    },
  );
});

test("docker preflight rejects duplicate ports and allows standalone disk checks", () => {
  const valid = parseRpcRequest({
    jsonrpc: "2.0",
    id: "preflight-valid",
    method: "docker.preflight",
    params: {
      target: "build-linux",
      intent: "update",
      project: { directory: "/srv/build" },
      ports: [
        { protocol: "tcp", port: 18_080 },
        { protocol: "udp", port: 18_080 },
      ],
      requiredFreeBytes: 1_048_576,
    },
  });
  assert.equal(valid.method, "docker.preflight");
  assert.equal(valid.params.intent, "update");

  const diskOnly = parseRpcRequest({
    jsonrpc: "2.0",
    id: "preflight-disk-only",
    method: "docker.preflight",
    params: {
      target: "build-linux",
      requiredFreeBytes: 1_048_576,
    },
  });
  assert.equal(diskOnly.method, "docker.preflight");
  assert.equal(diskOnly.params.project, undefined);
  assert.equal(diskOnly.params.intent, "create");
  assert.equal(diskOnly.params.requiredFreeBytes, 1_048_576);

  const result = parseRpcResult("docker.preflight", {
    target: "build-linux",
    intent: "update",
    checkedAt: "2026-08-08T00:00:00.000Z",
    durationMs: 25,
    overall: "ready",
    daemon: {
      status: "ok",
      installed: true,
      reachable: true,
      context: { name: "desktop-linux", scope: "local" },
    },
    compose: { status: "ok", installed: true, config: "valid" },
    ports: [{
      protocol: "tcp",
      port: 18_080,
      observation: "listener-observed",
      ownership: "requested-project",
    }],
    containers: {
      status: "ok",
      filter: "label=com.docker.compose.project=app",
      truncated: false,
      total: 7,
      running: 7,
      healthy: 6,
      unhealthy: 0,
      starting: 0,
      exited: 0,
    },
    warnings: [],
  });
  assert.equal(result.ports[0]?.ownership, "requested-project");
  assert.equal(result.containers.total, 7);

  assert.throws(() =>
    parseRpcRequest({
      jsonrpc: "2.0",
      id: "preflight-invalid",
      method: "docker.preflight",
      params: {
        target: "build-linux",
        ports: [
          { protocol: "tcp", port: 18_080 },
          { protocol: "tcp", port: 18_080 },
        ],
      },
    }),
  );
});

test("target.check accepts only a target alias", () => {
  const request = parseRpcRequest({
    jsonrpc: "2.0",
    id: "check-1",
    method: "target.check",
    params: { target: "dev-linux" },
  });
  assert.equal(request.method, "target.check");
  assert.deepEqual(request.params, { target: "dev-linux" });

  for (const extra of [
    { command: "whoami" },
    { timeoutMs: 60_000 },
  ]) {
    assert.throws(() =>
      parseRpcRequest({
        jsonrpc: "2.0",
        id: "check-invalid",
        method: "target.check",
        params: { target: "dev-linux", ...extra },
      }),
    );
  }
});

test("transfer requests support full-access absolute paths and rooted compatibility", () => {
  const uppercaseSha256 = "ABCDEF01".repeat(8);
  const unrestricted = parseRpcRequest({
    jsonrpc: "2.0",
    id: "upload-unrestricted",
    method: "transfer.upload",
    params: {
      target: "admin-windows",
      localPath: String.raw`C:\build\release.zip`,
      remotePath: String.raw`D:\services\release.zip`,
      expectedSha256: uppercaseSha256,
    },
  });
  assert.equal(unrestricted.method, "transfer.upload");
  assert.equal(unrestricted.params.localRoot, undefined);
  assert.equal(unrestricted.params.localPath, String.raw`C:\build\release.zip`);
  assert.equal(unrestricted.params.expectedSha256, uppercaseSha256);
  assert.equal(unrestricted.params.verify, "sha256");

  const rooted = parseRpcRequest({
    jsonrpc: "2.0",
    id: "download-rooted",
    method: "transfer.download",
    params: {
      target: "admin-windows",
      localRoot: "workspace",
      localPath: "release/app.zip",
      remotePath: String.raw`D:\services\release.zip`,
    },
  });
  assert.equal(rooted.method, "transfer.download");
  assert.equal(rooted.params.localRoot, "workspace");
  assert.equal(rooted.params.localPath, "release/app.zip");

  for (const params of [
    { target: "admin-windows", remotePath: "D:/release.zip" },
    {
      target: "admin-windows",
      localPath: "C:/build/release.zip\nsecond-command",
      remotePath: "D:/release.zip",
    },
  ]) {
    assert.throws(() =>
      parseRpcRequest({
        jsonrpc: "2.0",
        id: "upload-invalid",
        method: "transfer.upload",
        params,
      }),
    );
  }
});

test("target check results expose no remote output and derive connected exactly", () => {
  const success = {
    target: "dev-linux",
    connected: true,
    termination: "exit",
    exitCode: 0,
    durationMs: 12,
    hostname: "dev-linux-01",
  } as const;
  assert.equal(targetCheckResultSchema.safeParse(success).success, true);
  const failure = {
    target: "dev-linux",
    connected: false,
    termination: "exit",
    exitCode: 255,
    durationMs: 12,
    failureReason: "accessclient-session-unavailable",
  } as const;
  assert.equal(targetCheckResultSchema.safeParse(failure).success, true);
  assert.equal(
    targetCheckResultSchema.safeParse({
      ...failure,
      failureReason: "remote-controlled-text",
    }).success,
    false,
  );
  assert.equal(
    targetCheckResultSchema.safeParse({
      ...success,
      failureReason: "accessclient-host-mismatch",
    }).success,
    false,
  );
  assert.equal(
    targetCheckResultSchema.safeParse({
      ...failure,
      termination: "timeout",
      exitCode: null,
    }).success,
    false,
  );
  assert.equal(
    targetCheckResultSchema.safeParse({ ...success, connected: false }).success,
    false,
  );
  assert.equal(
    targetCheckResultSchema.safeParse({
      ...success,
      connected: false,
      termination: "timeout",
      exitCode: null,
    }).success,
    false,
  );
  assert.equal(
    targetCheckResultSchema.safeParse({ ...success, stderr: "secret" }).success,
    false,
  );
  assert.equal(
    targetCheckResultSchema.safeParse({ ...failure, stderr: "secret" }).success,
    false,
  );
});

test("public target summaries cannot contain sshAlias", () => {
  assert.equal(
    targetSummarySchema.safeParse({
      targetId: "t-11111111111111111111111111111111",
      alias: "dev-linux",
      sshAlias: "internal-host",
      enabled: true,
      policyMode: "allow-list",
      maxTimeoutMs: 30_000,
      maxTransferTimeoutMs: 30_000,
    }).success,
    false,
  );
});

test("public target summaries expose effective full-access transfer permissions", () => {
  const parsed = targetSummarySchema.safeParse({
    targetId: "t-22222222222222222222222222222222",
    alias: "admin-windows",
    enabled: true,
    platform: "windows",
    policyMode: "full-access",
    transferMode: "bidirectional",
    transferScope: "all",
    transferRoots: [],
    maxTimeoutMs: 30_000,
    maxTransferTimeoutMs: 3_600_000,
  });
  assert.equal(parsed.success, true);
  assert.equal(parsed.data?.platform, "windows");
  assert.equal(parsed.data?.transferMode, "bidirectional");
  assert.equal(parsed.data?.transferScope, "all");
  assert.deepEqual(parsed.data?.transferRoots, []);
  assert.equal(parsed.data?.maxTimeoutMs, 30_000);
  assert.equal(parsed.data?.maxTransferTimeoutMs, 3_600_000);
});

test("public target summaries default legacy platform metadata to linux", () => {
  const parsed = targetSummarySchema.parse({
    targetId: "t-33333333333333333333333333333333",
    alias: "legacy-target",
    enabled: true,
    policyMode: "allow-list",
    maxTimeoutMs: 30_000,
    maxTransferTimeoutMs: 30_000,
  });
  assert.equal(parsed.platform, "linux");
  assert.equal(parsed.transferMode, "deny");
  assert.equal(parsed.transferScope, "restricted");
  assert.deepEqual(parsed.transferRoots, []);
});

test("exec result requires retained output metadata for truncated previews", () => {
  const base = {
    requestId: "exec-1",
    termination: "exit",
    exitCode: 0,
    durationMs: 12,
    stdout: { text: "ok\n", bytes: 3, inlineTruncated: false },
    stderr: { text: "", bytes: 0, inlineTruncated: false },
  } as const;

  assert.equal(execResultSchema.safeParse(base).success, true);
  assert.equal(
    execResultSchema.safeParse({ ...base, outputRef: "a".repeat(43) }).success,
    false,
  );
  for (const stream of ["stdout", "stderr"] as const) {
    const truncated = {
      ...base,
      [stream]: { ...base[stream], inlineTruncated: true },
    };
    assert.equal(execResultSchema.safeParse(truncated).success, false, stream);
    assert.equal(
      execResultSchema.safeParse({
        ...truncated,
        outputRef: "a".repeat(43),
        outputExpiresAt: "2099-01-01T00:00:00.000Z",
      }).success,
      true,
      stream,
    );
  }
});

test("output chunks use null nextOffset exactly at EOF", () => {
  assert.equal(
    outputChunkSchema.safeParse({
      dataBase64: Buffer.from("hello").toString("base64"),
      nextOffset: null,
      eof: true,
      totalBytes: 5,
    }).success,
    true,
  );
  assert.equal(
    outputChunkSchema.safeParse({
      dataBase64: "",
      nextOffset: 5,
      eof: true,
      totalBytes: 5,
    }).success,
    false,
  );
});

test("text output pagination supports cursor mode and legacy offsets", () => {
  const base = {
    outputRef: "a".repeat(43),
    stream: "stdout",
    limit: 1_024,
  } as const;
  assert.equal(outputReadTextParamsSchema.safeParse(base).success, true);
  assert.equal(
    outputReadTextParamsSchema.safeParse({ ...base, offset: 0 }).success,
    true,
  );
  assert.equal(
    outputReadTextParamsSchema.safeParse({
      ...base,
      cursor: Buffer.from('{"v":1,"o":2}', "utf8").toString("base64url"),
    }).success,
    true,
  );
  assert.equal(
    outputReadTextParamsSchema.safeParse({
      ...base,
      offset: 0,
      cursor: Buffer.from('{"v":1,"o":2}', "utf8").toString("base64url"),
    }).success,
    false,
  );

  const resultBase = {
    text: "page",
    bytesRead: 4,
    eof: false,
    totalBytes: 8,
    hadDecodingErrors: false,
  } as const;
  assert.equal(
    outputTextChunkSchema.safeParse({
      ...resultBase,
      nextCursor: Buffer.from('{"v":1,"o":4}', "utf8").toString("base64url"),
    }).success,
    true,
  );
  assert.equal(
    outputTextChunkSchema.safeParse({ ...resultBase, nextOffset: 4 }).success,
    true,
  );
  assert.equal(
    outputTextChunkSchema.safeParse({
      ...resultBase,
      nextOffset: 4,
      nextCursor: Buffer.from('{"v":1,"o":4}', "utf8").toString("base64url"),
    }).success,
    false,
  );
});
