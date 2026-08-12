import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { resolve } from "node:path";
import test from "node:test";

import {
  buildOpenSshArguments,
  SshExecutionError,
  SshExecutor,
  type OutputSink,
  type SshExecutorDependencies,
} from "../../src/infra/openssh-executor.js";
import type {
  ManagedProcess,
  ManagedProcessOptions,
} from "../../src/infra/process-tree.js";
import { MAX_MANAGED_STDIN_BYTES } from "../../src/infra/process-tree.js";

const fixturePath = resolve("test", "fixtures", "fake-ssh.mjs");

test("builds a hardened argv and keeps alias and command after --", () => {
  const options = {
    configFile: String.raw`C:\ProgramData\agent ssh\ssh_config`,
    knownHostsFile: String.raw`C:\ProgramData\100% known\hosts`,
    connectTimeoutSeconds: 27,
  };
  const input = {
    sshAlias: "bastion-prod.internal",
    command: "printf '%s' \"$HOME\"; uname -a",
  };

  const arguments_ = buildOpenSshArguments(options, input);

  assert.deepEqual(arguments_.slice(-3), [
    "--",
    input.sshAlias,
    input.command,
  ]);
  assert.equal(arguments_.filter((value) => value === "--").length, 1);
  assertOption(arguments_, "BatchMode=yes");
  assertOption(arguments_, "StrictHostKeyChecking=yes");
  assertOption(arguments_, "KnownHostsCommand=none");
  assertOption(arguments_, "VerifyHostKeyDNS=no");
  assertOption(arguments_, "ClearAllForwardings=yes");
  assertOption(arguments_, "PermitLocalCommand=no");
  assertOption(arguments_, "ForwardAgent=no");
  assertOption(arguments_, "ControlMaster=no");
  assertOption(arguments_, "RemoteCommand=none");
  assertOption(arguments_, "ConnectTimeout=27");
  assert.equal(arguments_.includes("-n"), true);
  assertOption(
    arguments_,
    String.raw`UserKnownHostsFile="C:\\ProgramData\\100%% known\\hosts"`,
  );
  assert.deepEqual(
    arguments_.slice(arguments_.indexOf("-F"), arguments_.indexOf("-F") + 2),
    ["-F", options.configFile],
  );
});

test("keeps stdin enabled only for an explicit payload and forwards it exactly", async () => {
  const input = {
    sshAlias: "windows-target",
    command: "powershell.exe -NoProfile -NonInteractive -Command -",
    stdin: Buffer.from("ASCII wrapper with UTF-8 payload: 中文", "utf8"),
  };
  const arguments_ = buildOpenSshArguments({}, input);
  assert.equal(arguments_.includes("-n"), false);
  assertOption(arguments_, "StdinNull=no");
  assert.deepEqual(arguments_.slice(-3), ["--", input.sshAlias, input.command]);

  const executor = new SshExecutor(
    { executable: "ssh" },
    fixtureDependencies("stdin"),
  );
  const outcome = await executor.run(input);
  assert.equal(outcome.exitCode, 0);
  assert.equal(outcome.stdout, Buffer.from(input.stdin).toString("utf8"));
  assert.equal(outcome.stderr, "");
});

test("runs with exact argv, streams both channels, and preserves exit code", async () => {
  const options = {
    executable: String.raw`C:\Windows\System32\OpenSSH\ssh.exe`,
    connectTimeoutSeconds: 9,
  };
  const input = { sshAlias: "target-one", command: "echo exact command" };
  const executor = new SshExecutor(options, fixtureDependencies("argv"));
  const streamed: Array<{ stream: string; chunk: Buffer }> = [];

  const outcome = await executor.run({
    ...input,
    outputSink: {
      append(stream, chunk) {
        streamed.push({ stream, chunk: Buffer.from(chunk) });
      },
    },
  });

  assert.deepEqual(JSON.parse(outcome.stdout), buildOpenSshArguments(options, input));
  assert.equal(outcome.exitCode, 0);
  assert.equal(outcome.stderr, "");
  assert.equal(outcome.stdoutBytes, Buffer.byteLength(outcome.stdout));
  assert.equal(outcome.stdoutTruncated, false);
  assert.equal(outcome.aborted, false);
  assert.equal(outcome.terminationMode, "windows-taskkill-unsafe");
  assert.equal(
    Buffer.concat(streamed.map(({ chunk }) => chunk)).toString("utf8"),
    outcome.stdout,
  );

  const nonzero = new SshExecutor(options, fixtureDependencies("io-exit"));
  const failedOutcome = await nonzero.run(input);
  assert.equal(failedOutcome.exitCode, 23);
  assert.equal(failedOutcome.stdout, "stdout-data");
  assert.equal(failedOutcome.stderr, "stderr-data");
});

test("bounds inline capture while draining and streaming all output", async () => {
  const executor = new SshExecutor(
    { executable: "ssh", maxCapturedOutputBytes: 7 },
    fixtureDependencies("flood"),
  );
  const streamedBytes = { stdout: 0, stderr: 0 };
  const sink: OutputSink = {
    async append(stream, chunk) {
      await Promise.resolve();
      streamedBytes[stream] += chunk.byteLength;
    },
  };

  const outcome = await executor.run({
    sshAlias: "large-output",
    command: "generate",
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

test("preserves an output sink error as the execution error cause", async () => {
  const sinkError = new Error("typed output limit marker");
  const executor = new SshExecutor(
    { executable: "ssh" },
    fixtureDependencies("hang"),
  );

  await assert.rejects(
    executor.run({
      sshAlias: "target",
      command: "hang",
      outputSink: {
        append() {
          throw sinkError;
        },
      },
    }),
    (error: unknown) => {
      assert.ok(error instanceof SshExecutionError);
      assert.equal(error.cause, sinkError);
      return true;
    },
  );
});

test("does not lose cancellation while the process supervisor is starting", async () => {
  const controller = new AbortController();
  let signalPreparationStarted!: () => void;
  const preparationStarted = new Promise<void>((resolveStarted) => {
    signalPreparationStarted = resolveStarted;
  });
  let terminateCalls = 0;
  const dependencies: SshExecutorDependencies = {
    async spawnProcess(options) {
      const managed = await spawnFixture("hang", options, () => {
        terminateCalls += 1;
      });
      signalPreparationStarted();
      assert.equal(options.signal, controller.signal);
      await new Promise<void>((resolveAbort) => {
        options.signal?.addEventListener("abort", () => resolveAbort(), {
          once: true,
        });
      });
      await managed.terminate();
      return managed;
    },
  };
  const executor = new SshExecutor({ executable: "ssh" }, dependencies);

  const running = executor.run({
    sshAlias: "target",
    command: "hang",
    signal: controller.signal,
  });
  await preparationStarted;
  controller.abort();
  const outcome = await running;

  assert.equal(outcome.aborted, true);
  assert.equal(outcome.exitCode, null);
  assert.equal(terminateCalls, 1);
});

test("an already aborted request does not start a process", async () => {
  const controller = new AbortController();
  controller.abort();
  let spawnCalls = 0;
  const executor = new SshExecutor(
    { executable: "ssh" },
    {
      spawnProcess() {
        spawnCalls += 1;
        return Promise.reject(new Error("must not be called"));
      },
    },
  );

  const outcome = await executor.run({
    sshAlias: "target",
    command: "true",
    signal: controller.signal,
  });

  assert.equal(outcome.aborted, true);
  assert.equal(outcome.terminationMode, null);
  assert.equal(spawnCalls, 0);
});

test("rejects option injection aliases, unsafe paths, and invalid commands", () => {
  assert.throws(
    () => buildOpenSshArguments({}, { sshAlias: "-oProxyCommand=bad", command: "id" }),
    TypeError,
  );
  assert.throws(
    () => buildOpenSshArguments({}, { sshAlias: "valid", command: " \t" }),
    TypeError,
  );
  assert.throws(
    () => buildOpenSshArguments({}, { sshAlias: "valid", command: "id\nuname" }),
    TypeError,
  );
  assert.throws(
    () => new SshExecutor({ executable: "ssh\nmalicious" }),
    TypeError,
  );
  assert.throws(
    () =>
      buildOpenSshArguments(
        { knownHostsFile: "C:\\literal\\${TEMP}\\known_hosts" },
        { sshAlias: "valid", command: "id" },
      ),
    /environment expansions/u,
  );
  assert.throws(
    () =>
      buildOpenSshArguments(
        {},
        {
          sshAlias: "valid",
          command: "run",
          stdin: Buffer.alloc(MAX_MANAGED_STDIN_BYTES + 1),
        },
      ),
    /stdin must not exceed/u,
  );
});

function fixtureDependencies(scenario: string): SshExecutorDependencies {
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
