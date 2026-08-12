import assert from "node:assert/strict";
import {
  request as httpRequest,
  type IncomingHttpHeaders,
} from "node:http";
import test, { type TestContext } from "node:test";

import {
  PROTOCOL_VERSION,
  type DockerPreflightParams,
  type DownloadParams,
  type ExecResult,
  type ExecRunParams,
  type PingResult,
  type SyncParams,
  type TargetCheckParams,
  type TargetListResult,
  type TaskStatusParams,
  type TaskTailParams,
  type UploadParams,
} from "../../src/shared/protocol.js";
import {
  createDemoGatewayFactory,
  type TestUiGatewayFactory,
  type TestUiGatewaySession,
} from "../../src/test-ui/gateway.js";
import {
  startTestUiServer,
  type RunningTestUiServer,
} from "../../src/test-ui/server.js";

const TEST_SESSION_TOKEN = Buffer.alloc(32, 0x5a).toString("base64url");

interface JsonObject {
  readonly [key: string]: unknown;
}

interface RawHttpResponse {
  readonly statusCode: number;
  readonly headers: IncomingHttpHeaders;
  readonly body: string;
}

interface Deferred<Value> {
  readonly promise: Promise<Value>;
  resolve(value: Value): void;
}

async function startDemoServer(
  t: TestContext,
  gatewayFactory: TestUiGatewayFactory = createDemoGatewayFactory(),
): Promise<RunningTestUiServer> {
  const server = await startTestUiServer({
    gatewayFactory,
    mode: "demo",
    sessionToken: TEST_SESSION_TOKEN,
  });
  t.after(() => server.close());
  return server;
}

function postJson(
  server: RunningTestUiServer,
  path: string,
  body: unknown,
  options: {
    readonly origin?: string;
    readonly token?: string;
    readonly omitToken?: boolean;
    readonly contentType?: string;
    readonly secFetchSite?: string;
    readonly rawBody?: string;
  } = {},
): Promise<Response> {
  const headers: Record<string, string> = {
    Origin: options.origin ?? server.origin,
    "Content-Type": options.contentType ?? "application/json",
  };
  if (options.omitToken !== true) {
    headers["X-Agent-Ssh-Ui-Token"] = options.token ?? server.sessionToken;
  }
  if (options.secFetchSite !== undefined) {
    headers["Sec-Fetch-Site"] = options.secFetchSite;
  }
  return fetch(`${server.origin}${path}`, {
    method: "POST",
    headers,
    body: options.rawBody ?? JSON.stringify(body),
  });
}

async function readObject(response: Response): Promise<JsonObject> {
  const value: unknown = await response.json();
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  assert.equal(Array.isArray(value), false);
  return value as JsonObject;
}

function requireObject(value: unknown): JsonObject {
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  assert.equal(Array.isArray(value), false);
  return value as JsonObject;
}

async function assertProblem(
  response: Response,
  expectedStatus: number,
  expectedCode: string,
): Promise<void> {
  assert.equal(response.status, expectedStatus);
  assert.match(
    response.headers.get("content-type") ?? "",
    /^application\/json\b/u,
  );
  const body = await readObject(response);
  const error = requireObject(body.error);
  assert.equal(error.code, expectedCode);
  assert.equal(typeof error.message, "string");
}

function requestRaw(
  origin: string,
  path: string,
  headers: Readonly<Record<string, string>>,
): Promise<RawHttpResponse> {
  const url = new URL(origin);
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      {
        hostname: url.hostname,
        port: url.port,
        path,
        method: "GET",
        headers,
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
        response.once("end", () => {
          resolve({
            statusCode: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    request.once("error", reject);
    request.end();
  });
}

function deferred<Value>(): Deferred<Value> {
  let resolvePromise!: (value: Value) => void;
  const promise = new Promise<Value>((resolve) => {
    resolvePromise = resolve;
  });
  return { promise, resolve: resolvePromise };
}

test("serves token-free HTML with strict browser security headers", async (t) => {
  const server = await startDemoServer(t);
  const response = await fetch(server.origin);

  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/u);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(response.headers.get("cross-origin-opener-policy"), "same-origin");
  assert.equal(response.headers.get("cross-origin-resource-policy"), "same-origin");
  const csp = response.headers.get("content-security-policy") ?? "";
  assert.match(csp, /default-src 'none'/u);
  assert.match(csp, /connect-src 'self'/u);
  assert.match(csp, /frame-ancestors 'none'/u);

  const html = await response.text();
  assert.equal(html.includes(server.sessionToken), false);
  assert.equal(html.includes(server.url), false);
  assert.equal(response.headers.get("set-cookie"), null);
});

test("rejects invalid browser requests before calling the gateway", async (t) => {
  let factoryCalls = 0;
  const delegate = createDemoGatewayFactory();
  const server = await startDemoServer(t, async () => {
    factoryCalls += 1;
    return delegate();
  });

  const badHost = await requestRaw(server.origin, "/", {
    Host: "attacker.invalid",
  });
  assert.equal(badHost.statusCode, 421);
  assert.equal(
    requireObject(
      requireObject(JSON.parse(badHost.body) as unknown).error,
    ).code,
    "INVALID_HOST",
  );

  await assertProblem(
    await postJson(server, "/api/ping", {}, { origin: "http://attacker.invalid" }),
    403,
    "INVALID_ORIGIN",
  );
  await assertProblem(
    await postJson(server, "/api/ping", {}, { token: "A".repeat(43) }),
    403,
    "INVALID_SESSION",
  );
  await assertProblem(
    await postJson(server, "/api/ping", {}, { omitToken: true }),
    403,
    "INVALID_SESSION",
  );
  await assertProblem(
    await postJson(server, "/api/ping", {}, { secFetchSite: "cross-site" }),
    403,
    "CROSS_SITE_REQUEST",
  );

  const optionsResponse = await fetch(`${server.origin}/api/ping`, {
    method: "OPTIONS",
  });
  await assertProblem(optionsResponse, 405, "METHOD_NOT_ALLOWED");

  await assertProblem(
    await postJson(server, "/api/ping", {}, { contentType: "text/plain" }),
    415,
    "JSON_REQUIRED",
  );
  await assertProblem(
    await postJson(server, "/api/ping", {}, { rawBody: "{" }),
    400,
    "INVALID_JSON",
  );
  await assertProblem(
    await postJson(server, "/api/ping", {}, {
      rawBody: JSON.stringify({ padding: "x".repeat(96 * 1_024) }),
    }),
    413,
    "BODY_TOO_LARGE",
  );

  assert.equal(factoryCalls, 0);
});

test("forwards ping and exposes only public target summaries", async (t) => {
  const server = await startDemoServer(t);

  const pingResponse = await postJson(server, "/api/ping", {});
  assert.equal(pingResponse.status, 200);
  const ping = await readObject(pingResponse);
  assert.equal(ping.mode, "demo");
  const gateway = requireObject(ping.gateway);
  assert.equal(gateway.ok, true);
  assert.equal(gateway.protocolVersion, PROTOCOL_VERSION);
  assert.equal(Number.isNaN(Date.parse(String(gateway.serverTime))), false);

  const targetsResponse = await postJson(server, "/api/targets", {});
  assert.equal(targetsResponse.status, 200);
  const targets = await readObject(targetsResponse);
  assert.deepEqual(targets.targets, [
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
  ]);
  assert.equal(JSON.stringify(targets).includes("sshAlias"), false);
  assert.equal(JSON.stringify(targets).includes(server.sessionToken), false);
});

test("reports successful, non-zero, timeout, and policy-rejected runs without RPC secrets", async (t) => {
  const server = await startDemoServer(t);

  const successResponse = await postJson(server, "/api/run", {
    target: "demo-linux",
    command: "hostname",
    timeoutMs: 1_000,
  });
  assert.equal(successResponse.status, 200);
  const success = await readObject(successResponse);
  assert.equal(success.termination, "exit");
  assert.equal(success.exitCode, 0);
  assert.equal(typeof success.durationMs, "number");
  assert.equal(requireObject(success.stdout).text, "demo-linux-01\n");
  assert.equal(requireObject(success.stderr).text, "");
  const serializedSuccess = JSON.stringify(success);
  assert.equal(serializedSuccess.includes("requestId"), false);
  assert.equal(serializedSuccess.includes("outputRef"), false);

  const nonZeroResponse = await postJson(server, "/api/run", {
    target: "demo-linux",
    command: "exit 7",
  });
  assert.equal(nonZeroResponse.status, 200);
  const nonZero = await readObject(nonZeroResponse);
  assert.equal(nonZero.termination, "exit");
  assert.equal(nonZero.exitCode, 7);
  assert.match(String(requireObject(nonZero.stderr).text), /status 7/u);

  const timeoutResponse = await postJson(server, "/api/run", {
    target: "demo-linux",
    command: "sleep 5",
    timeoutMs: 10,
  });
  assert.equal(timeoutResponse.status, 200);
  const timeout = await readObject(timeoutResponse);
  assert.equal(timeout.termination, "timeout");
  assert.equal(timeout.exitCode, null);

  await assertProblem(
    await postJson(server, "/api/run", {
      target: "demo-linux",
      command: "not-allowed",
    }),
    403,
    "COMMAND_DENIED",
  );
  await assertProblem(
    await postJson(server, "/api/run", {
      target: "frozen-production",
      command: "hostname",
    }),
    403,
    "TARGET_DISABLED",
  );
});

test("forwards structured execution, machine inspection, and Docker preflight", async (t) => {
  let runParams: ExecRunParams | undefined;
  let inspectParams: TargetCheckParams | undefined;
  let dockerParams: DockerPreflightParams | undefined;
  const gatewayFactory: TestUiGatewayFactory = () =>
    Promise.resolve({
      ping: () =>
        Promise.resolve({
          ok: true as const,
          protocolVersion: PROTOCOL_VERSION,
          serverTime: "2026-08-05T00:00:00.000Z",
        }),
      listTargets: () => Promise.resolve({ targets: [] }),
      checkTarget: ({ target }) =>
        Promise.resolve({
          target,
          connected: true,
          termination: "exit" as const,
          exitCode: 0,
          durationMs: 1,
          hostname: "windows-host",
        }),
      inspectTarget: (params) => {
        inspectParams = params;
        return Promise.resolve({
          target: params.target,
          connected: true,
          observedAt: "2026-08-05T00:00:00.000Z",
          durationMs: 12,
          sshHostKeyFingerprints: [`SHA256:${"A".repeat(43)}`],
          machine: {
            machineId: `mid_${"B".repeat(43)}`,
            hostname: "windows-host",
            configuredPlatform: "windows" as const,
            reportedPlatform: "windows" as const,
            platformMatch: true,
            os: { name: "Windows", version: "11", architecture: "x64" },
            disk: { totalBytes: 1_000_000, availableBytes: 500_000 },
            docker: {
              installed: true,
              daemonReachable: true,
              clientVersion: "28.0.0",
              serverVersion: "28.0.0",
              composeVersion: "2.35.0",
            },
          },
          warnings: [],
        });
      },
      dockerPreflight: (params) => {
        dockerParams = params;
        return Promise.resolve({
          target: params.target,
          intent: params.intent,
          checkedAt: "2026-08-05T00:00:00.000Z",
          durationMs: 25,
          overall: "ready" as const,
          daemon: {
            status: "ok" as const,
            installed: true,
            reachable: true,
            clientVersion: "28.0.0",
            serverVersion: "28.0.0",
            context: { name: "desktop-linux", scope: "local" as const },
          },
          compose: {
            status: "ok" as const,
            installed: true,
            version: "2.35.0",
            config: "valid" as const,
          },
          ports: [
            {
              protocol: "tcp" as const,
              port: 18_080,
              observation: "not-observed" as const,
              ownership: "unknown" as const,
            },
          ],
          containers: {
            status: "ok" as const,
            filter: "label=com.docker.compose.project=app",
            truncated: false,
            total: 1,
            running: 1,
            healthy: 1,
            unhealthy: 0,
            starting: 0,
            exited: 0,
          },
          disk: {
            status: "ok" as const,
            totalBytes: 1_000_000,
            availableBytes: 500_000,
            requiredBytes: 100_000,
          },
          warnings: [],
        });
      },
      run: (params) => {
        runParams = params;
        return Promise.resolve({
          requestId: "structured-ui-run",
          termination: "exit" as const,
          exitCode: 0,
          durationMs: 8,
          stdout: { text: "中文输出\n", bytes: 13, inlineTruncated: false },
          stderr: { text: "", bytes: 0, inlineTruncated: false },
        });
      },
      readOutput: () => Promise.reject(new Error("No retained output")),
      close: () => undefined,
    });
  const server = await startDemoServer(t, gatewayFactory);

  const structured = {
    target: "windows-target",
    shell: "powershell",
    script: "$env:DEPLOY_ENV\nGet-Location",
    cwd: String.raw`D:\services\app`,
    env: { DEPLOY_ENV: "测试" },
    encoding: "utf-8",
    timeoutMs: 120_000,
  } as const;
  const runResponse = await postJson(server, "/api/run", structured);
  assert.equal(runResponse.status, 200);
  assert.equal(requireObject((await readObject(runResponse)).stdout).text, "中文输出\n");
  assert.deepEqual(runParams, structured);

  const inspectResponse = await postJson(server, "/api/inspect", {
    target: "windows-target",
  });
  assert.equal(inspectResponse.status, 200);
  assert.equal(requireObject((await readObject(inspectResponse)).machine).hostname, "windows-host");
  assert.deepEqual(inspectParams, { target: "windows-target" });

  const preflight = {
    target: "windows-target",
    intent: "update" as const,
    project: {
      directory: "D:/services/app",
      composeFiles: ["compose.yaml"],
      name: "app",
    },
    ports: [{ protocol: "tcp", port: 18_080 }],
    requiredFreeBytes: 100_000,
  } as const;
  const preflightResponse = await postJson(
    server,
    "/api/docker/preflight",
    preflight,
  );
  assert.equal(preflightResponse.status, 200);
  assert.equal((await readObject(preflightResponse)).overall, "ready");
  assert.deepEqual(dockerParams, preflight);
});

test("forwards daemon task lifecycle and transfer defaults", async (t) => {
  const runId = "R".repeat(43);
  const cursor = Buffer.from('{"v":1,"o":5,"e":0}', "utf8").toString(
    "base64url",
  );
  let taskStartParams: ExecRunParams | undefined;
  let statusParams: TaskStatusParams | undefined;
  let tailParams: TaskTailParams | undefined;
  let cancelParams: TaskStatusParams | undefined;
  let uploadParams: UploadParams | undefined;
  let downloadParams: DownloadParams | undefined;
  let syncParams: SyncParams | undefined;
  const gatewayFactory: TestUiGatewayFactory = () =>
    Promise.resolve({
      ping: () =>
        Promise.resolve({
          ok: true as const,
          protocolVersion: PROTOCOL_VERSION,
          serverTime: "2026-08-05T00:00:00.000Z",
        }),
      listTargets: () => Promise.resolve({ targets: [] }),
      checkTarget: ({ target }) =>
        Promise.resolve({
          target,
          connected: true,
          termination: "exit" as const,
          exitCode: 0,
          durationMs: 1,
          hostname: "task-host",
        }),
      run: () => Promise.reject(new Error("Foreground run was not expected")),
      startTask: (params) => {
        taskStartParams = params;
        return Promise.resolve({
          runId,
          target: params.target,
          kind: "exec" as const,
          state: "running" as const,
          startedAt: "2026-08-05T00:00:00.000Z",
        });
      },
      taskStatus: (params) => {
        statusParams = params;
        return Promise.resolve({
          runId,
          target: "windows-target",
          kind: "exec" as const,
          state: "succeeded" as const,
          startedAt: "2026-08-05T00:00:00.000Z",
          updatedAt: "2026-08-05T00:00:01.000Z",
          finishedAt: "2026-08-05T00:00:01.000Z",
          expiresAt: "2026-08-05T00:15:01.000Z",
          durationMs: 1_000,
          stdoutBytes: 5,
          stderrBytes: 0,
          termination: "exit" as const,
          exitCode: 0,
          result: { files: 1 },
        });
      },
      taskTail: (params) => {
        tailParams = params;
        return Promise.resolve({
          runId,
          state: "succeeded" as const,
          stdout: {
            text: "done\n",
            bytesRead: 5,
            totalBytes: 5,
            droppedBytes: 0,
            hadDecodingErrors: false,
          },
          stderr: {
            text: "",
            bytesRead: 0,
            totalBytes: 0,
            droppedBytes: 0,
            hadDecodingErrors: false,
          },
          nextCursor: cursor,
          eof: true,
        });
      },
      cancelTask: (params) => {
        cancelParams = params;
        return Promise.resolve({
          runId,
          accepted: false,
          state: "succeeded" as const,
        });
      },
      upload: (params) => {
        uploadParams = params;
        return Promise.resolve({
          runId,
          target: params.target,
          kind: "upload" as const,
          state: "running" as const,
          startedAt: "2026-08-05T00:00:00.000Z",
        });
      },
      download: (params) => {
        downloadParams = params;
        return Promise.resolve({
          runId,
          target: params.target,
          kind: "download" as const,
          state: "running" as const,
          startedAt: "2026-08-05T00:00:00.000Z",
        });
      },
      sync: (params) => {
        syncParams = params;
        return Promise.resolve({
          runId,
          target: params.target,
          kind: "sync" as const,
          state: "running" as const,
          startedAt: "2026-08-05T00:00:00.000Z",
        });
      },
      readOutput: () => Promise.reject(new Error("No retained output")),
      close: () => undefined,
    });
  const server = await startDemoServer(t, gatewayFactory);

  const startResponse = await postJson(server, "/api/task/start", {
    target: "windows-target",
    command: "hostname",
  });
  assert.equal(startResponse.status, 202);
  assert.deepEqual(taskStartParams, {
    target: "windows-target",
    command: "hostname",
  });

  assert.equal(
    (await postJson(server, "/api/task/status", { runId })).status,
    200,
  );
  assert.deepEqual(statusParams, { runId });
  assert.equal(
    (
      await postJson(server, "/api/task/tail", {
        runId,
        limit: 1_024,
      })
    ).status,
    200,
  );
  assert.deepEqual(tailParams, { runId, limit: 1_024 });
  assert.equal(
    (await postJson(server, "/api/task/cancel", { runId })).status,
    200,
  );
  assert.deepEqual(cancelParams, { runId });

  const commonTransfer = {
    target: "windows-target",
    localRoot: "windows-target",
    localPath: "release/app.zip",
    remotePath: "D:/services/app/app.zip",
  };
  assert.equal(
    (await postJson(server, "/api/transfer/upload", commonTransfer)).status,
    202,
  );
  assert.deepEqual(uploadParams, {
    ...commonTransfer,
    overwrite: false,
    resume: true,
    dryRun: false,
    verify: "sha256",
  });
  assert.equal(
    (await postJson(server, "/api/transfer/download", commonTransfer)).status,
    202,
  );
  assert.deepEqual(downloadParams, {
    ...commonTransfer,
    overwrite: false,
    resume: true,
    dryRun: false,
  });
  assert.equal(
    (
      await postJson(server, "/api/transfer/sync", {
        ...commonTransfer,
        localPath: "release",
        remotePath: "D:/services/app",
      })
    ).status,
    202,
  );
  assert.deepEqual(syncParams, {
    ...commonTransfer,
    localPath: "release",
    remotePath: "D:/services/app",
    overwrite: false,
    resume: true,
    dryRun: false,
    exclude: [],
    verifyExisting: false,
  });
});

test("cancels the active run promptly and closes its gateway session", { timeout: 5_000 }, async (t) => {
  const started = deferred<AbortSignal>();
  let closeCalls = 0;
  const gatewayFactory: TestUiGatewayFactory = () =>
    Promise.resolve(
      createControlledGatewaySession(started, () => {
        closeCalls += 1;
      }),
    );
  const server = await startDemoServer(t, gatewayFactory);

  const runResponsePromise = postJson(server, "/api/run", {
    target: "demo-linux",
    command: "wait",
  });
  const runSignal = await started.promise;
  assert.equal(runSignal.aborted, false);

  const cancelResponse = await postJson(server, "/api/cancel", {});
  assert.equal(cancelResponse.status, 200);
  assert.deepEqual(await readObject(cancelResponse), { accepted: true });

  const runResponse = await runResponsePromise;
  assert.equal(runResponse.status, 200);
  const run = await readObject(runResponse);
  assert.equal(run.termination, "cancel");
  assert.equal(run.exitCode, null);
  assert.equal(runSignal.aborted, true);
  assert.equal(closeCalls, 1);

  const secondCancel = await postJson(server, "/api/cancel", {});
  assert.deepEqual(await readObject(secondCancel), { accepted: false });
});

test("paginates retained output through a resultId without exposing outputRef", async (t) => {
  const server = await startDemoServer(t);
  const runResponse = await postJson(server, "/api/run", {
    target: "demo-linux",
    command: "large-output",
  });
  assert.equal(runResponse.status, 200);
  const run = await readObject(runResponse);
  assert.equal(requireObject(run.stdout).inlineTruncated, true);
  assert.match(String(run.resultId), /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(Number.isNaN(Date.parse(String(run.outputExpiresAt))), false);
  const serializedRun = JSON.stringify(run);
  assert.equal(serializedRun.includes("requestId"), false);
  assert.equal(serializedRun.includes("outputRef"), false);

  const firstResponse = await postJson(server, "/api/output", {
    resultId: run.resultId,
    stream: "stdout",
    offset: 0,
    limit: 32,
  });
  assert.equal(firstResponse.status, 200);
  const first = await readObject(firstResponse);
  assert.equal(first.eof, false);
  assert.equal(first.nextOffset, 32);
  const firstBytes = Buffer.from(String(first.dataBase64), "base64");
  assert.equal(firstBytes.length, 32);

  const secondResponse = await postJson(server, "/api/output", {
    resultId: run.resultId,
    stream: "stdout",
    offset: first.nextOffset,
    limit: 32,
  });
  assert.equal(secondResponse.status, 200);
  const second = await readObject(secondResponse);
  assert.equal(second.nextOffset, 64);
  const secondBytes = Buffer.from(String(second.dataBase64), "base64");
  const expectedPrefix = Buffer.from(
    "demo output line 0001\ndemo output line 0002\ndemo output line 0003\n",
    "utf8",
  ).subarray(0, 64);
  assert.deepEqual(Buffer.concat([firstBytes, secondBytes]), expectedPrefix);
  const serializedChunks = JSON.stringify([first, second]);
  assert.equal(serializedChunks.includes("requestId"), false);
  assert.equal(serializedChunks.includes("outputRef"), false);

  await assertProblem(
    await postJson(server, "/api/output", {
      resultId: "A".repeat(43),
      stream: "stdout",
      offset: 0,
      limit: 32,
    }),
    410,
    "OUTPUT_UNAVAILABLE",
  );
});

test("bridges retained task output through resultId and completes one-byte UTF-8 pages", async (t) => {
  const runId = "T".repeat(43);
  const outputRef = "O".repeat(43);
  const outputExpiresAt = "2099-01-01T00:00:00.000Z";
  const payload = Buffer.from("中A", "utf8");
  const reads: Array<{ readonly offset: number; readonly limit: number }> = [];
  const gatewayFactory: TestUiGatewayFactory = () =>
    Promise.resolve({
      ping: () =>
        Promise.resolve({
          ok: true,
          protocolVersion: PROTOCOL_VERSION,
          serverTime: "2026-08-05T00:00:00.000Z",
        }),
      listTargets: () => Promise.resolve({ targets: [] }),
      checkTarget: ({ target }) =>
        Promise.resolve({
          target,
          connected: true,
          termination: "exit" as const,
          exitCode: 0,
          durationMs: 1,
          hostname: "task-output-host",
        }),
      run: () => Promise.reject(new Error("Foreground run was not expected")),
      taskStatus: () =>
        Promise.resolve({
          runId,
          target: "windows-target",
          kind: "exec" as const,
          state: "succeeded" as const,
          startedAt: "2026-08-05T00:00:00.000Z",
          updatedAt: "2026-08-05T00:00:01.000Z",
          finishedAt: "2026-08-05T00:00:01.000Z",
          durationMs: 1_000,
          stdoutBytes: payload.length,
          stderrBytes: 0,
          termination: "exit" as const,
          exitCode: 0,
          result: {
            durationMs: 1_000,
            stdoutBytes: payload.length,
            stderrBytes: 0,
            artifact: "retained-log",
            outputRef,
            outputExpiresAt,
          },
        }),
      readOutput: (params) => {
        reads.push({ offset: params.offset, limit: params.limit });
        const end = Math.min(params.offset + params.limit, payload.length);
        const eof = end >= payload.length;
        return Promise.resolve({
          dataBase64: payload.subarray(params.offset, end).toString("base64"),
          nextOffset: eof ? null : end,
          eof,
          totalBytes: payload.length,
        });
      },
      close: () => undefined,
    });
  const server = await startDemoServer(t, gatewayFactory);

  const statusResponse = await postJson(server, "/api/task/status", { runId });
  assert.equal(statusResponse.status, 200);
  const status = await readObject(statusResponse);
  assert.match(String(status.resultId), /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(status.outputExpiresAt, outputExpiresAt);
  assert.equal(JSON.stringify(status).includes("outputRef"), false);
  assert.equal(JSON.stringify(status).includes(outputRef), false);
  const publicResult = requireObject(status.result);
  assert.equal(publicResult.artifact, "retained-log");
  assert.equal("outputExpiresAt" in publicResult, false);

  const firstResponse = await postJson(server, "/api/output", {
    resultId: status.resultId,
    stream: "stdout",
    offset: 0,
    limit: 1,
  });
  assert.equal(firstResponse.status, 200);
  const first = await readObject(firstResponse);
  assert.equal(
    new TextDecoder("utf-8", { fatal: true }).decode(
      Buffer.from(String(first.dataBase64), "base64"),
    ),
    "中",
  );
  assert.equal(first.nextOffset, 3);
  assert.equal(first.eof, false);

  const secondResponse = await postJson(server, "/api/output", {
    resultId: status.resultId,
    stream: "stdout",
    offset: first.nextOffset,
    limit: 1,
  });
  const second = await readObject(secondResponse);
  assert.equal(
    new TextDecoder("utf-8", { fatal: true }).decode(
      Buffer.from(String(second.dataBase64), "base64"),
    ),
    "A",
  );
  assert.equal(second.nextOffset, null);
  assert.equal(second.eof, true);
  assert.deepEqual(reads, [
    { offset: 0, limit: 1 },
    { offset: 1, limit: 2 },
    { offset: 3, limit: 1 },
  ]);
});

test("aligns browser text pages without changing gateway byte reads", async (t) => {
  const payload = Buffer.from("ab中😀z", "utf8");
  const reads: Array<{ readonly offset: number; readonly limit: number }> = [];
  const gatewayFactory: TestUiGatewayFactory = () =>
    Promise.resolve({
      ping: () =>
        Promise.resolve({
          ok: true,
          protocolVersion: PROTOCOL_VERSION,
          serverTime: "2026-08-05T00:00:00.000Z",
        }),
      listTargets: () => Promise.resolve({ targets: [] }),
      checkTarget: ({ target }) =>
        Promise.resolve({
          target,
          connected: true,
          termination: "exit" as const,
          exitCode: 0,
          durationMs: 1,
          hostname: "test-host",
        }),
      run: () =>
        Promise.resolve({
          requestId: "utf8-output-run",
          termination: "exit" as const,
          exitCode: 0,
          durationMs: 1,
          stdout: { text: "a", bytes: payload.length, inlineTruncated: true },
          stderr: { text: "", bytes: 0, inlineTruncated: false },
          outputRef: "private-utf8-output-reference",
          outputExpiresAt: "2099-01-01T00:00:00.000Z",
        }),
      readOutput: (params) => {
        reads.push({ offset: params.offset, limit: params.limit });
        const end = Math.min(params.offset + params.limit, payload.length);
        const eof = end === payload.length;
        return Promise.resolve({
          dataBase64: payload.subarray(params.offset, end).toString("base64"),
          nextOffset: eof ? null : end,
          eof,
          totalBytes: payload.length,
        });
      },
      close: () => undefined,
    });
  const server = await startDemoServer(t, gatewayFactory);
  const runResponse = await postJson(server, "/api/run", {
    target: "utf8-output",
    command: "generate-output",
  });
  assert.equal(runResponse.status, 200);
  const run = await readObject(runResponse);
  assert.match(String(run.resultId), /^[A-Za-z0-9_-]{43}$/u);

  const expectedPages = [
    { offset: 0, text: "ab", nextOffset: 2 },
    { offset: 2, text: "中", nextOffset: 5 },
    { offset: 5, text: "😀", nextOffset: 9 },
    { offset: 9, text: "z", nextOffset: null },
  ] as const;
  for (const expected of expectedPages) {
    const response = await postJson(server, "/api/output", {
      resultId: run.resultId,
      stream: "stdout",
      offset: expected.offset,
      limit: 4,
    });
    assert.equal(response.status, 200);
    const page = await readObject(response);
    assert.equal(
      new TextDecoder("utf-8", { fatal: true }).decode(
        Buffer.from(String(page.dataBase64), "base64"),
      ),
      expected.text,
    );
    assert.equal(page.nextOffset, expected.nextOffset);
  }

  const repeatedResponse = await postJson(server, "/api/output", {
    resultId: run.resultId,
    stream: "stdout",
    offset: 2,
    limit: 4,
  });
  const repeated = await readObject(repeatedResponse);
  assert.equal(
    new TextDecoder("utf-8", { fatal: true }).decode(
      Buffer.from(String(repeated.dataBase64), "base64"),
    ),
    "中",
  );
  assert.deepEqual(reads, [
    { offset: 0, limit: 4 },
    { offset: 2, limit: 4 },
    { offset: 5, limit: 4 },
    { offset: 9, limit: 4 },
    { offset: 2, limit: 4 },
  ]);
});

function createControlledGatewaySession(
  started: Deferred<AbortSignal>,
  onClose: () => void,
): TestUiGatewaySession {
  const ping: PingResult = {
    ok: true,
    protocolVersion: PROTOCOL_VERSION,
    serverTime: "2026-08-05T00:00:00.000Z",
  };
  const targets: TargetListResult = { targets: [] };
  return {
    ping: () => Promise.resolve(ping),
    listTargets: () => Promise.resolve(targets),
    checkTarget: ({ target }) =>
      Promise.resolve({
        target,
        connected: true,
        termination: "exit",
        exitCode: 0,
        durationMs: 1,
        hostname: "test-host",
      }),
    run: (_params, signal) => {
      started.resolve(signal);
      return waitForCancellation(signal);
    },
    readOutput: (_params) => Promise.reject(new Error("No retained output")),
    close: onClose,
  };
}

function waitForCancellation(signal: AbortSignal): Promise<ExecResult> {
  return new Promise((resolve) => {
    const finish = (): void => {
      resolve({
        requestId: "private-request-id",
        termination: "cancel",
        exitCode: null,
        durationMs: 1,
        stdout: { text: "", bytes: 0, inlineTruncated: false },
        stderr: { text: "", bytes: 0, inlineTruncated: false },
      });
    };
    if (signal.aborted) {
      finish();
    } else {
      signal.addEventListener("abort", finish, { once: true });
    }
  });
}
