import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { cp, mkdtemp, rm, stat } from "node:fs/promises";
import { createServer, type AddressInfo, type Server } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test, { type TestContext } from "node:test";

const TEST_UI_SOURCE_DIRECTORY = fileURLToPath(
  new URL("../../src/", import.meta.url),
);
const TEST_UI_MAIN = fileURLToPath(
  new URL("../../src/test-ui/main.js", import.meta.url),
);

interface CliResult {
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
}

interface CliOptions {
  readonly entryPoint?: string;
  readonly environment?: NodeJS.ProcessEnv;
  readonly timeoutMs?: number;
}

test("test UI help documents setup as an explicit mode", async () => {
  const result = await runCli(["--help"]);

  assert.equal(result.timedOut, false);
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /agent-ssh-test-ui --setup \[--port PORT\]/u);
  assert.doesNotMatch(result.stdout, /--managed(?:\s|$)/u);
  assert.doesNotMatch(result.stdout, /--managed-directory/u);
  assert.equal(result.stderr, "");
});

test("test UI refuses to enter setup mode implicitly", async () => {
  const result = await runCli([]);

  assert.equal(result.timedOut, false);
  assert.equal(result.exitCode, 1);
  assert.match(result.stderr, /Usage:/u);
  assert.match(result.stderr, /--setup/u);
  assert.equal(result.stdout, "");
});

test("test UI rejects legacy managed flags", async () => {
  for (const args of [
    ["--managed"],
    ["--managed-directory", String.raw`C:\managed-test`],
  ]) {
    const result = await runCli(args);
    assert.equal(result.timedOut, false, args.join(" "));
    assert.equal(result.exitCode, 1, args.join(" "));
    assert.match(result.stderr, /Unknown argument/u);
    assert.equal(result.stdout, "");
  }
});

test("setup cannot be combined with demo or gateway mode", async () => {
  const cases: ReadonlyArray<{
    readonly args: readonly string[];
    readonly message: RegExp;
  }> = [
    {
      args: ["--setup", "--demo"],
      message: /Choose exactly one of --demo, --setup, or --data-directory/u,
    },
    {
      args: ["--setup", "--data-directory", String.raw`C:\gateway-runtime`],
      message: /Choose exactly one of --demo, --setup, or --data-directory/u,
    },
  ];

  for (const entry of cases) {
    const result = await runCli(entry.args);
    assert.equal(result.timedOut, false, entry.args.join(" "));
    assert.equal(result.exitCode, 1, entry.args.join(" "));
    assert.match(result.stderr, entry.message);
    assert.equal(result.stdout, "");
  }
});

test(
  "setup releases its lease when static assets cannot be loaded",
  { skip: process.platform !== "win32", timeout: 60_000 },
  async (t) => {
    const sandbox = await createDistributionSandbox(
      t,
      "agent-ssh-test-ui-assets-",
    );
    const copiedSourceDirectory = path.join(sandbox, "src");
    await cp(TEST_UI_SOURCE_DIRECTORY, copiedSourceDirectory, {
      recursive: true,
    });
    await rm(path.join(copiedSourceDirectory, "test-ui", "public"), {
      recursive: true,
      force: true,
    });
    const localAppData = path.join(sandbox, "local-app-data");

    const result = await runCli(["--setup"], {
      entryPoint: path.join(copiedSourceDirectory, "test-ui", "main.js"),
      environment: { ...process.env, LOCALAPPDATA: localAppData },
      timeoutMs: 45_000,
    });

    assert.equal(result.timedOut, false);
    assert.equal(result.exitCode, 1);
    assert.match(result.stderr, /ENOENT|no such file/u);
    assert.equal(result.stdout, "");
    await assertSetupLeaseReleased(localAppData);
  },
);

test(
  "setup releases its lease when the HTTP port is unavailable",
  { skip: process.platform !== "win32", timeout: 60_000 },
  async (t) => {
    const sandbox = await createSandbox(t, "agent-ssh-test-ui-listen-");
    const localAppData = path.join(sandbox, "local-app-data");
    const blocker = createServer();
    t.after(async () => {
      if (blocker.listening) {
        await closeTcpServer(blocker);
      }
    });
    await listenOnLoopback(blocker);
    const address = blocker.address() as AddressInfo;

    const result = await runCli(
      ["--setup", "--port", String(address.port)],
      {
        environment: { ...process.env, LOCALAPPDATA: localAppData },
        timeoutMs: 45_000,
      },
    );

    assert.equal(result.timedOut, false);
    assert.equal(result.exitCode, 1);
    assert.match(result.stderr, /EADDRINUSE/u);
    assert.equal(result.stdout, "");
    await assertSetupLeaseReleased(localAppData);
  },
);

function runCli(
  args: readonly string[],
  options: CliOptions = {},
): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [options.entryPoint ?? TEST_UI_MAIN, ...args],
      {
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
        ...(options.environment === undefined
          ? {}
          : { env: options.environment }),
      },
    );
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, options.timeoutMs ?? 5_000);

    child.stdout.on("data", (chunk: Buffer) => stdout.push(Buffer.from(chunk)));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(Buffer.from(chunk)));
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (exitCode) => {
      clearTimeout(timer);
      resolve({
        exitCode,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        timedOut,
      });
    });
  });
}

async function createSandbox(
  t: TestContext,
  prefix: string,
): Promise<string> {
  const sandbox = await mkdtemp(path.join(os.tmpdir(), prefix));
  t.after(() => rm(sandbox, { recursive: true, force: true }));
  return sandbox;
}

async function createDistributionSandbox(
  t: TestContext,
  prefix: string,
): Promise<string> {
  const distributionDirectory = path.dirname(TEST_UI_SOURCE_DIRECTORY);
  const sandbox = await mkdtemp(path.join(distributionDirectory, prefix));
  t.after(() => rm(sandbox, { recursive: true, force: true }));
  return sandbox;
}

async function assertSetupLeaseReleased(localAppData: string): Promise<void> {
  const managedDirectory = path.join(
    localAppData,
    "agent-ssh-gateway",
    "managed",
  );
  assert.equal((await stat(managedDirectory)).isDirectory(), true);
  for (const name of ["runtime.json", "runtime.lock"]) {
    await assert.rejects(
      stat(path.join(managedDirectory, "setup-lease", name)),
      (error: unknown) =>
        (error as NodeJS.ErrnoException).code === "ENOENT",
    );
  }
}

function listenOnLoopback(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (error: Error): void => reject(error);
    server.once("error", onError);
    server.listen({ host: "127.0.0.1", port: 0, exclusive: true }, () => {
      server.off("error", onError);
      resolve();
    });
  });
}

function closeTcpServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) {
        resolve();
      } else {
        reject(error);
      }
    });
  });
}
