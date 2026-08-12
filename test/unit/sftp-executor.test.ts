import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { resolve } from "node:path";
import test from "node:test";

import {
  buildOpenSftpArguments,
  SftpExecutionError,
  SftpExecutor,
  type SftpExecutorDependencies,
} from "../../src/infra/sftp-executor.js";
import type { OutputSink } from "../../src/infra/openssh-executor.js";
import {
  MAX_MANAGED_STDIN_BYTES,
  type ManagedProcess,
  type ManagedProcessOptions,
} from "../../src/infra/process-tree.js";

const fixturePath = resolve("test", "fixtures", "fake-ssh.mjs");
const executorOptions = {
  executable: String.raw`C:\Windows\System32\OpenSSH\sftp.exe`,
  sshExecutable: String.raw`C:\Windows\System32\OpenSSH\ssh.exe`,
  configFile: String.raw`C:\ProgramData\agent ssh\ssh_config`,
  knownHostsFile: String.raw`C:\ProgramData\100% known\hosts`,
  connectTimeoutSeconds: 27,
};

test("builds hardened SFTP arguments around the managed SSH configuration", () => {
  const arguments_ = buildOpenSftpArguments(executorOptions, {
    sshAlias: "managed-target.internal",
    batch: "@pwd\n@quit\n",
  });

  assert.deepEqual(arguments_.slice(0, 6), [
    "-b",
    "-",
    "-S",
    executorOptions.sshExecutable,
    "-F",
    executorOptions.configFile,
  ]);
  assert.equal(arguments_.at(-1), "managed-target.internal");
  assert.equal(arguments_.includes("scp"), false);
  assert.equal(arguments_.includes("-O"), false);
  assertOption(arguments_, "StdinNull=no");
  assertOption(arguments_, "BatchMode=yes");
  assertOption(arguments_, "IdentityAgent=none");
  assertOption(arguments_, "IdentitiesOnly=yes");
  assertOption(arguments_, "PubkeyAuthentication=yes");
  assertOption(arguments_, "PasswordAuthentication=no");
  assertOption(arguments_, "KbdInteractiveAuthentication=no");
  assertOption(arguments_, "PreferredAuthentications=publickey");
  assertOption(arguments_, "StrictHostKeyChecking=yes");
  assertOption(arguments_, "KnownHostsCommand=none");
  assertOption(arguments_, "VerifyHostKeyDNS=no");
  assertOption(arguments_, "ClearAllForwardings=yes");
  assertOption(arguments_, "PermitLocalCommand=no");
  assertOption(arguments_, "ForwardAgent=no");
  assertOption(arguments_, "RequestTTY=no");
  assertOption(arguments_, "RemoteCommand=none");
  assertOption(arguments_, "ControlMaster=no");
  assertOption(arguments_, "ControlPath=none");
  assertOption(arguments_, "EnableEscapeCommandline=no");
  assertOption(arguments_, "ConnectTimeout=27");
  assertOption(
    arguments_,
    String.raw`UserKnownHostsFile="C:\\ProgramData\\100%% known\\hosts"`,
  );
  assertOption(arguments_, "GlobalKnownHostsFile=none");
});

test("delivers the exact UTF-8 batch through managed stdin", async () => {
  const batch = Buffer.from(
    '@put "C:/project/\u4e2d\u6587.txt" "D:/deploy/\u4e2d\u6587.txt"\n@quit\n',
    "utf8",
  );
  let spawned: ManagedProcessOptions | undefined;
  const executor = new SftpExecutor(executorOptions, {
    async spawnProcess(options) {
      spawned = options;
      return spawnFixture("stdin", options);
    },
  });

  const outcome = await executor.run({
    sshAlias: "target",
    batch,
  });

  assert.equal(spawned?.executable, executorOptions.executable);
  assert.deepEqual(spawned?.stdinPayload, batch);
  assert.equal(outcome.exitCode, 0);
  assert.equal(outcome.stdout, batch.toString("utf8"));
  assert.equal(outcome.stderr, "");
  assert.equal(outcome.aborted, false);
  assert.equal(outcome.terminationMode, "windows-taskkill-unsafe");
});

test("bounds captured diagnostics while draining and streaming both channels", async () => {
  const streamedBytes = { stdout: 0, stderr: 0 };
  const sink: OutputSink = {
    async append(stream, chunk) {
      await Promise.resolve();
      streamedBytes[stream] += chunk.byteLength;
    },
  };
  const executor = new SftpExecutor(
    { ...executorOptions, maxCapturedOutputBytes: 7 },
    fixtureDependencies("flood"),
  );

  const outcome = await executor.run({
    sshAlias: "target",
    batch: "@pwd\n@quit\n",
    outputSink: sink,
  });

  assert.equal(outcome.stdout, "a".repeat(7));
  assert.equal(outcome.stderr, "b".repeat(7));
  assert.equal(outcome.stdoutBytes, 128 * 1024);
  assert.equal(outcome.stderrBytes, 96 * 1024);
  assert.equal(outcome.stdoutTruncated, true);
  assert.equal(outcome.stderrTruncated, true);
  assert.deepEqual(streamedBytes, {
    stdout: 128 * 1024,
    stderr: 96 * 1024,
  });
});

test("preserves nonzero exit status and output sink failures", async () => {
  const failed = new SftpExecutor(
    executorOptions,
    fixtureDependencies("io-exit"),
  );
  const outcome = await failed.run({
    sshAlias: "target",
    batch: "@pwd\n@quit\n",
  });
  assert.equal(outcome.exitCode, 23);
  assert.equal(outcome.stdout, "stdout-data");
  assert.equal(outcome.stderr, "stderr-data");

  const sinkError = new Error("typed transfer output limit");
  const hanging = new SftpExecutor(
    executorOptions,
    fixtureDependencies("hang"),
  );
  await assert.rejects(
    hanging.run({
      sshAlias: "target",
      batch: "@pwd\n@quit\n",
      outputSink: {
        append() {
          throw sinkError;
        },
      },
    }),
    (error: unknown) => {
      assert.ok(error instanceof SftpExecutionError);
      assert.equal(error.cause, sinkError);
      return true;
    },
  );
});

test("does not lose cancellation while the process supervisor starts", async () => {
  const controller = new AbortController();
  let terminateCalls = 0;
  const dependencies: SftpExecutorDependencies = {
    async spawnProcess(options) {
      const managed = await spawnFixture("hang", options, () => {
        terminateCalls += 1;
      });
      controller.abort();
      return managed;
    },
  };
  const executor = new SftpExecutor(executorOptions, dependencies);

  const outcome = await executor.run({
    sshAlias: "target",
    batch: "@pwd\n@quit\n",
    signal: controller.signal,
  });

  assert.equal(outcome.aborted, true);
  assert.equal(outcome.exitCode, null);
  assert.equal(terminateCalls, 1);
});

test("does not spawn for a request that is already aborted", async () => {
  const controller = new AbortController();
  controller.abort();
  let spawnCalls = 0;
  const executor = new SftpExecutor(executorOptions, {
    spawnProcess() {
      spawnCalls += 1;
      return Promise.reject(new Error("must not be called"));
    },
  });

  const outcome = await executor.run({
    sshAlias: "target",
    batch: "@quit\n",
    signal: controller.signal,
  });

  assert.equal(outcome.aborted, true);
  assert.equal(outcome.terminationMode, null);
  assert.equal(spawnCalls, 0);
});

test("rejects option injection, local shell commands, and malformed batches", () => {
  assert.throws(
    () =>
      buildOpenSftpArguments(executorOptions, {
        sshAlias: "-oProxyCommand=bad",
        batch: "@quit\n",
      }),
    TypeError,
  );
  assert.throws(
    () => new SftpExecutor({ ...executorOptions, executable: "sftp" }),
    /absolute path/u,
  );
  assert.throws(
    () =>
      buildOpenSftpArguments(executorOptions, {
        sshAlias: "target",
        batch: "!cmd.exe /c whoami\n",
      }),
    /safe unique prefixes|not allowed/u,
  );
  assert.throws(
    () =>
      buildOpenSftpArguments(executorOptions, {
        sshAlias: "target",
        batch: "@lcd C:/Windows\n",
      }),
    /not allowed/u,
  );
  assert.throws(
    () =>
      buildOpenSftpArguments(executorOptions, {
        sshAlias: "target",
        batch: "pwd\n",
      }),
    /safe unique prefixes/u,
  );
  assert.throws(
    () =>
      buildOpenSftpArguments(executorOptions, {
        sshAlias: "target",
        batch: "@@pwd\n",
      }),
    /safe unique prefixes/u,
  );
  assert.throws(
    () =>
      buildOpenSftpArguments(executorOptions, {
        sshAlias: "target",
        batch: "@quit",
      }),
    /line feed/u,
  );
  assert.throws(
    () =>
      buildOpenSftpArguments(executorOptions, {
        sshAlias: "target",
        batch: Buffer.from([0xff, 0x0a]),
      }),
    /UTF-8/u,
  );
  assert.throws(
    () =>
      buildOpenSftpArguments(executorOptions, {
        sshAlias: "target",
        batch: Buffer.concat([
          Buffer.from("@put ", "utf8"),
          Buffer.alloc(MAX_MANAGED_STDIN_BYTES, 0x61),
          Buffer.from("\n", "utf8"),
        ]),
      }),
    /must not exceed/u,
  );
});

function fixtureDependencies(scenario: string): SftpExecutorDependencies {
  return {
    spawnProcess: (options) => spawnFixture(scenario, options),
  };
}

async function spawnFixture(
  scenario: string,
  options: ManagedProcessOptions,
  onTerminate: () => void = () => undefined,
): Promise<ManagedProcess> {
  const child = spawn(
    process.execPath,
    [fixturePath, scenario, ...options.arguments],
    {
      cwd: options.cwd,
      env: options.environment,
      detached: false,
      shell: false,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  if (options.stdinPayload !== undefined) {
    child.stdin.end(Buffer.from(options.stdinPayload));
  }
  let termination: Promise<void> | undefined;
  return {
    child,
    terminationMode: "windows-taskkill-unsafe",
    terminate() {
      termination ??= new Promise<void>((resolveTermination) => {
        onTerminate();
        if (child.exitCode !== null || child.signalCode !== null) {
          resolveTermination();
          return;
        }
        child.once("close", () => resolveTermination());
        child.kill("SIGKILL");
      });
      return termination;
    },
  };
}

function assertOption(arguments_: readonly string[], option: string): void {
  assert.ok(
    arguments_.some(
      (value, index) => value === "-o" && arguments_[index + 1] === option,
    ),
    `missing OpenSSH option: ${option}`,
  );
}
