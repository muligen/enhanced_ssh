import assert from "node:assert/strict";
import {
  spawn,
  spawnSync,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import test, { type TestContext } from "node:test";
import { gunzipSync } from "node:zlib";

import {
  buildPuttyBrokerBootstrap,
  buildPuttyCommandFrame,
  buildPuttyShellReadyProbe,
  buildPuttySharedArguments,
  PuttySharedExecutor,
  type PuttySharedExecutorDependencies,
  type PuttySharedExecutorOptions,
} from "../../src/infra/putty-shared-executor.js";
import type {
  ManagedProcess,
  ManagedProcessOptions,
} from "../../src/infra/process-tree.js";
import { createManagedProcess } from "../../src/infra/process-tree.js";
import {
  SshExecutionError,
  type OutputSink,
} from "../../src/infra/ssh-runner.js";
import { SHARED_SHELL_TRANSFER_CHUNK_BYTES } from "../../src/infra/shared-shell-transfer.js";

const TARGET_ALIAS = "accessclient-target";
const EXPECTED_HOSTNAME = "target-host";
const SESSION_NONCE = "0123456789abcdef0123456789abcdef";
const COMMAND_NONCE = "fedcba9876543210fedcba9876543210";
const WINDOWS_BOOTSTRAP_NONCE = "d2299094d30f46f7a44cdcc35bc1b64e";

test("shared-shell transfer chunks fit within one persistent protocol frame", () => {
  assert.equal(SHARED_SHELL_TRANSFER_CHUNK_BYTES, 96 * 1024);
  const frame = buildPuttyCommandFrame(
    SESSION_NONCE,
    1,
    COMMAND_NONCE,
    {
      command: "transfer-chunk",
      stdin: Buffer.alloc(SHARED_SHELL_TRANSFER_CHUNK_BYTES),
    },
  );
  assert.ok(frame.byteLength < 256 * 1024);
});

interface FakeCommandPlan {
  readonly behavior?: "complete" | "hang" | "incomplete" | "invalid-frame";
  readonly output?: string;
  readonly stderr?: string;
  readonly outputFromStdin?: boolean;
  readonly exitCode?: number;
  readonly delayBeforeBeginMs?: number;
  readonly delayBeforeEndMs?: number;
  readonly outputChunks?: readonly string[];
  readonly stderrChunks?: readonly string[];
}

interface FakeProcessPlan {
  readonly startup?: "ready" | "exit" | "hang";
  readonly shellReadyAfterProbes?: number;
  readonly hostname?: string;
  readonly commands?: readonly FakeCommandPlan[];
  readonly terminateFailures?: number;
  readonly terminateError?: string;
}

interface CapturedWrite {
  readonly spawnIndex: number;
  readonly bytes: Buffer;
}

interface ProcessHarness {
  readonly dependencies: PuttySharedExecutorDependencies;
  readonly calls: ManagedProcessOptions[];
  readonly writes: CapturedWrite[];
  readonly terminateCalls: { count: number };
}

interface Deferred<Value> {
  readonly promise: Promise<Value>;
  resolve(value: Value): void;
}

function fakePlinkMain(): void {
  interface ChildCommandPlan {
    readonly behavior?: "complete" | "hang" | "incomplete" | "invalid-frame";
    readonly output?: string;
    readonly stderr?: string;
    readonly outputFromStdin?: boolean;
    readonly exitCode?: number;
    readonly delayBeforeBeginMs?: number;
    readonly delayBeforeEndMs?: number;
    readonly outputChunks?: readonly string[];
    readonly stderrChunks?: readonly string[];
  }

  interface ChildProcessPlan {
    readonly startup?: "ready" | "exit" | "hang";
    readonly shellReadyAfterProbes?: number;
    readonly hostname?: string;
    readonly commands?: readonly ChildCommandPlan[];
  }

  const encodedPlan = process.env["FAKE_PLINK_PLAN"];
  if (encodedPlan === undefined) {
    process.stderr.write("missing fake Plink plan");
    process.exit(70);
  }
  const plan = JSON.parse(
    Buffer.from(encodedPlan, "base64").toString("utf8"),
  ) as ChildProcessPlan;
  const protocolMagic = "__ASH2__";
  let sessionNonce: string | undefined;
  let commandIndex = 0;
  let shellReadyProbeCount = 0;
  let shellReadyEmitted = false;
  const bootstrapLines: string[] = [];

  const wait = (milliseconds: number): Promise<void> =>
    new Promise((resolve) => setTimeout(resolve, milliseconds));

  const emitLine = async (line: string): Promise<void> => {
    const bytes = Buffer.from(line + "\n", "ascii");
    for (let offset = 0; offset < bytes.length; offset += 3) {
      const chunk = bytes.subarray(offset, offset + 3);
      await new Promise<void>((resolve, reject) => {
        process.stdout.write(chunk, (error) => {
          if (error === null || error === undefined) resolve();
          else reject(error);
        });
      });
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
  };

  const extractSessionFromScript = (script: string): string | undefined => {
    const match = /(?:__ash_session|\$ashSession)='([a-f0-9]{32})'/u.exec(
      script,
    );
    return match?.[1];
  };

  const extractSessionNonce = async (
    bootstrap: string,
  ): Promise<string | undefined> => {
    const windows = /-(?:EncodedCommand|enc)\s+([A-Za-z0-9+/=]+)\s*$/u.exec(
      bootstrap,
    );
    const scripts: string[] = [];
    if (windows !== null && windows[1] !== undefined) {
      const loader = Buffer.from(windows[1], "base64").toString("utf16le");
      const payload =
        /\[Convert\]::FromBase64String\('([A-Za-z0-9+/]+={0,2})'\)/u.exec(
          loader,
        );
      if (payload?.[1] === undefined) {
        throw new Error("invalid Windows broker loader");
      }
      const { gunzipSync } = await import("node:zlib");
      scripts.push(
        gunzipSync(Buffer.from(payload[1], "base64")).toString("utf8"),
      );
    }
    const posixChunks = [...bootstrap.matchAll(
      /^__ash_payload_[a-f0-9]{32}=.*'([A-Za-z0-9+/=]+)' \|\| exit 96$/gmu,
    )].flatMap((match) => (match[1] === undefined ? [] : [match[1]]));
    if (posixChunks.length > 0) {
      scripts.push(
        Buffer.from(posixChunks.join(""), "base64").toString("utf8"),
      );
    }
    for (const script of scripts) {
      const extracted = extractSessionFromScript(script);
      if (extracted !== undefined) return extracted;
    }
    return undefined;
  };

  const handleStartupInput = async (line: string): Promise<void> => {
    const shellReady = /(__ASH2__:[a-f0-9]{32}:SHELL_READY)/u.exec(line)?.[1];
    if (shellReady !== undefined) {
      shellReadyProbeCount += 1;
      await emitLine(`interactive-prompt ${line}`);
      if (
        shellReadyProbeCount >= (plan.shellReadyAfterProbes ?? 1) &&
        !shellReadyEmitted
      ) {
        shellReadyEmitted = true;
        await emitLine(shellReady);
      }
      return;
    }
    if (!shellReadyEmitted) {
      throw new Error("bootstrap arrived before the shell-ready marker");
    }
    bootstrapLines.push(line);
    const complete =
      /^powershell\.exe .* -enc [A-Za-z0-9+/=]+$/u.test(line) ||
      /^exec bash --noprofile --norc -c /u.test(line);
    if (!complete) return;
    await handleBootstrap(bootstrapLines.join("\n"));
  };

  const handleBootstrap = async (line: string): Promise<void> => {
    sessionNonce = await extractSessionNonce(line);
    if (sessionNonce === undefined) throw new Error("invalid bootstrap");
    if (plan.startup === "exit") {
      process.exit(1);
    }
    if (plan.startup === "hang") return;
    await emitLine("interactive login banner");
    const hostname = plan.hostname ?? "target-host";
    await emitLine(
      protocolMagic +
        ":" +
        sessionNonce +
        ":READY:" +
        Buffer.from(hostname, "utf8").toString("base64"),
    );
  };

  const handleRun = async (line: string): Promise<void> => {
    const parts = line.split(":");
    if (
      parts.length !== 8 ||
      parts[0] !== protocolMagic ||
      parts[1] !== sessionNonce ||
      parts[2] !== String(commandIndex + 1) ||
      !/^[a-f0-9]{32}$/u.test(parts[3] ?? "") ||
      parts[4] !== "RUN" ||
      !/^[A-Za-z0-9+/]+={0,2}$/u.test(parts[5] ?? "") ||
      !new Set(["N", "B"]).has(parts[6] ?? "") ||
      (parts[6] === "N" && parts[7] !== "") ||
      (parts[6] === "B" && !/^[A-Za-z0-9+/]*={0,2}$/u.test(parts[7] ?? ""))
    ) {
      throw new Error("invalid RUN frame");
    }

    const commandPlan = plan.commands?.[commandIndex];
    if (commandPlan === undefined) throw new Error("unexpected RUN frame");
    commandIndex += 1;
    const prefix = parts.slice(0, 4).join(":");
    const stdin = Buffer.from(parts[7] ?? "", "base64").toString("utf8");

    if ((commandPlan.delayBeforeBeginMs ?? 0) > 0) {
      await wait(commandPlan.delayBeforeBeginMs ?? 0);
    }
    await emitLine(prefix + ":BEGIN");

    const outputChunks =
      commandPlan.outputChunks ??
      [commandPlan.outputFromStdin === true ? stdin : commandPlan.output ?? ""];
    for (const output of outputChunks) {
      if (output.length === 0) continue;
      await emitLine(
        prefix + ":OUT:" + Buffer.from(output, "utf8").toString("base64"),
      );
    }
    for (const output of commandPlan.stderrChunks ?? [commandPlan.stderr ?? ""]) {
      if (output.length === 0) continue;
      await emitLine(
        prefix + ":ERR:" + Buffer.from(output, "utf8").toString("base64"),
      );
    }

    if (commandPlan.behavior === "invalid-frame") {
      // Legacy merged DATA frames are not valid in the split-stream protocol.
      await emitLine(prefix + ":DATA:not-valid-base64!");
      return;
    }
    if (commandPlan.behavior === "incomplete") {
      process.exit(1);
    }
    if (commandPlan.behavior === "hang") return;
    if ((commandPlan.delayBeforeEndMs ?? 0) > 0) {
      await wait(commandPlan.delayBeforeEndMs ?? 0);
    }
    await emitLine(prefix + ":END:" + String(commandPlan.exitCode ?? 0));
  };

  void import("node:readline").then(({ createInterface }) => {
    const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
    let operation = Promise.resolve();
    lines.on("line", (line) => {
      operation = operation.then(async () => {
        if (sessionNonce === undefined) await handleStartupInput(line);
        else await handleRun(line);
      });
      void operation.catch((error: unknown) => {
        process.stderr.write(
          error instanceof Error ? error.message : String(error),
        );
        process.exit(70);
      });
    });
  });
}

const CHILD_SOURCE = `(${fakePlinkMain.toString()})();`;

test("builds fail-closed shared-session arguments", () => {
  const options = baseOptions();
  const arguments_ = buildPuttySharedArguments(options);

  assert.ok(arguments_.includes("-batch"));
  assert.ok(arguments_.includes("-share"));
  assert.ok(arguments_.includes("-noagent"));
  assert.ok(arguments_.includes("-a"));
  assert.ok(arguments_.includes("-x"));
  assert.ok(arguments_.includes("-no-trivial-auth"));
  assert.ok(arguments_.includes("-t"));
  assert.deepEqual(
    arguments_.slice(
      arguments_.indexOf("-loghost"),
      arguments_.indexOf("-loghost") + 2,
    ),
    ["-loghost", options.sharingHost],
  );
  assert.deepEqual(
    arguments_.slice(
      arguments_.indexOf("-proxycmd"),
      arguments_.indexOf("-proxycmd") + 2,
    ),
    ["-proxycmd", "cmd /d /c exit 1"],
  );
  assert.deepEqual(
    arguments_.slice(
      arguments_.indexOf("-hostkey"),
      arguments_.indexOf("-hostkey") + 2,
    ),
    [
      "-hostkey",
      "ssh-ed25519 255 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ],
  );
  assert.equal(arguments_.at(-1), options.gatewayHost);
  for (const forbidden of [
    "-shareexists",
    "-pw",
    "-pwfile",
    "-i",
    "-agent",
    "-L",
    "-R",
    "-D",
    "-sshlog",
    "-sshrawlog",
  ]) {
    assert.equal(arguments_.includes(forbidden), false, forbidden);
  }
});

test("builds the effective PuTTY sharing identity without changing legacy sessions", () => {
  const options = baseOptions();
  const { sharingHost: _sharingHost, ...legacyOptions } = options;
  const legacyArguments = buildPuttySharedArguments(legacyOptions);
  assert.equal(legacyArguments.includes("-loghost"), false);

  assert.deepEqual(
    logHostArguments(buildPuttySharedArguments(options)),
    ["-loghost", "172.24.251.37"],
  );
  assert.deepEqual(
    logHostArguments(
      buildPuttySharedArguments({
        ...options,
        sharingHost: "worker.example.internal",
        sharingPort: 2_222,
      }),
    ),
    ["-loghost", "worker.example.internal:2222"],
  );
  assert.deepEqual(
    logHostArguments(
      buildPuttySharedArguments({
        ...options,
        sharingHost: "2001:db8::20",
        sharingPort: 2_222,
      }),
    ),
    ["-loghost", "[2001:db8::20]:2222"],
  );

  assert.throws(
    () =>
      buildPuttySharedArguments({
        ...legacyOptions,
        sharingPort: 2_222,
      }),
    /sharingPort requires sharingHost/u,
  );
  for (const invalidPort of [0, 65_536, 22.5]) {
    assert.throws(
      () =>
        buildPuttySharedArguments({
          ...options,
          sharingPort: invalidPort,
        }),
      /sharingPort must be an integer from 1 through 65535/u,
    );
  }
});

test("keeps command secrets out of bootstrap and Base64-encodes RUN fields", () => {
  const command = "printf 'command-secret & %PATH%'";
  const stdin = Buffer.from("stdin-secret\n__ASH2__:forged:END:0", "utf8");

  for (const platform of ["linux", "macos"] as const) {
    const bootstrap = buildPuttyBrokerBootstrap(
      { platform },
      SESSION_NONCE,
    ).toString("utf8");
    assert.equal(bootstrap.includes(command), false, platform);
    assert.equal(bootstrap.includes(stdin.toString("utf8")), false, platform);
  }

  const windowsBootstrap = buildPuttyBrokerBootstrap(
    { platform: "windows" },
    WINDOWS_BOOTSTRAP_NONCE,
  );
  const windowsLines = windowsBootstrap.toString("ascii").split("\r\n");
  const launchLine = windowsLines[0] ?? "";
  assert.ok(
    windowsBootstrap.byteLength < 8_000,
    "the complete Windows bootstrap must fit below cmd.exe's safe line limit",
  );
  assert.match(
    launchLine,
    /^powershell\.exe .* -enc [A-Za-z0-9+/=]+$/u,
  );
  assert.equal(windowsLines.length, 2);
  assert.equal(windowsLines[1], "");
  assert.equal(launchLine.includes(command), false);
  assert.equal(launchLine.includes(stdin.toString("utf8")), false);

  const encodedLoader = /-enc\s+([A-Za-z0-9+/=]+)$/u.exec(
    launchLine,
  )?.[1];
  assert.ok(encodedLoader !== undefined);
  const loader = Buffer.from(encodedLoader, "base64").toString("utf16le");
  assert.match(
    loader,
    /\[IO\.Compression\.GZipStream\]::new\([\s\S]+,\[IO\.Compression\.CompressionMode\]0\)/u,
  );
  const compressedBroker =
    /\[Convert\]::FromBase64String\('([A-Za-z0-9+/]+={0,2})'\)/u.exec(
      loader,
    )?.[1];
  assert.ok(compressedBroker !== undefined);
  const brokerScript = gunzipSync(
    Buffer.from(compressedBroker, "base64"),
  ).toString("utf8");
  assert.equal(
    /\$ashSession='([a-f0-9]{32})'/u.exec(brokerScript)?.[1],
    WINDOWS_BOOTSTRAP_NONCE,
  );
  assert.match(
    brokerScript,
    /\[Console\]::OutputEncoding=\$ashUtf8;\$OutputEncoding=\$ashUtf8/u,
  );
  assert.equal(brokerScript.includes(command), false);
  assert.equal(brokerScript.includes(stdin.toString("utf8")), false);

  const frame = buildPuttyCommandFrame(
    SESSION_NONCE,
    7,
    COMMAND_NONCE,
    { command, stdin },
  ).toString("ascii");
  assert.equal(frame.includes(command), false);
  assert.equal(frame.includes(stdin.toString("utf8")), false);
  const parts = frame.trimEnd().split(":");
  assert.deepEqual(parts.slice(0, 5), [
    "__ASH2__",
    SESSION_NONCE,
    "7",
    COMMAND_NONCE,
    "RUN",
  ]);
  assert.equal(Buffer.from(parts[5] ?? "", "base64").toString("utf8"), command);
  assert.equal(parts[6], "B");
  assert.deepEqual(Buffer.from(parts[7] ?? "", "base64"), stdin);
});

test("stages POSIX brokers below canonical line limits after an exact shell-ready probe", () => {
  for (const platform of ["linux", "macos"] as const) {
    const probe = buildPuttyShellReadyProbe(
      { platform },
      SESSION_NONCE,
    ).toString("ascii");
    assert.match(
      probe,
      new RegExp(`^printf .+${SESSION_NONCE}:SHELL_READY.+\\n$`, "u"),
      platform,
    );

    const bootstrap = buildPuttyBrokerBootstrap(
      { platform },
      SESSION_NONCE,
    ).toString("ascii");
    const lines = bootstrap.trimEnd().split("\n");
    assert.ok(lines.length > 4, platform);
    for (const line of lines) {
      assert.ok(
        Buffer.byteLength(`${line}\n`, "ascii") < 4_096,
        `${platform} bootstrap line exceeded the canonical TTY limit`,
      );
    }
    const broker = decodePosixBrokerBootstrap(bootstrap);
    assert.match(broker, new RegExp(`__ash_session='${SESSION_NONCE}'`, "u"));
  }
});

test("POSIX broker separates both output streams and fails closed on pipeline errors", () => {
  for (const platform of ["linux", "macos"] as const) {
    const bootstrap = buildPuttyBrokerBootstrap(
      { platform },
      SESSION_NONCE,
    ).toString("utf8");
    const broker = decodePosixBrokerBootstrap(bootstrap);

    assert.match(broker, /\$\{#__ash_delimiters\} == 7/u, platform);
    assert.match(
      broker,
      /exec 3> >\(base64 \| __ash_emit "\$__ash_prefix" OUT\)/u,
      platform,
    );
    assert.match(
      broker,
      /exec 4> >\(base64 \| __ash_emit "\$__ash_prefix" ERR\)/u,
      platform,
    );
    assert.match(broker, /bash -c "\$__ash_command" <\/dev\/null 1>&3 2>&4/u, platform);
    assert.match(broker, /\$\{#__ash_status\[@\]\} == 3/u, platform);
    assert.match(broker, /__ash_status\[0\] == 0/u, platform);
    assert.match(broker, /__ash_status\[1\] == 0/u, platform);
    assert.match(broker, /wait "\$__ash_out_pid"/u, platform);
    assert.match(broker, /wait "\$__ash_err_pid"/u, platform);
    assert.match(broker, /exec 5> >\(__ash_forward\)/u, platform);
    assert.match(broker, /wait "\$__ash_mux_pid"/u, platform);
    assert.equal(broker.includes("2>&1"), false, platform);
  }
});

test(
  "POSIX broker emits independent OUT and ERR frames",
  { skip: !hasBash(), timeout: 20_000 },
  () => {
    const platform = process.platform === "darwin" ? "macos" : "linux";
    const bootstrap = buildPuttyBrokerBootstrap(
      { platform },
      SESSION_NONCE,
    ).toString("utf8");
    const broker = decodePosixBrokerBootstrap(bootstrap);
    const frame = buildPuttyCommandFrame(
      SESSION_NONCE,
      1,
      COMMAND_NONCE,
      { command: "printf stdout-value; printf stderr-value >&2; exit 7" },
    );
    const result = spawnSync("bash", ["--noprofile", "--norc", "-c", broker], {
      input: frame,
      maxBuffer: 1024 * 1024,
      timeout: 15_000,
      windowsHide: true,
    });

    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr.toString("utf8"));
    const protocol = result.stdout.toString("ascii");
    assert.equal(decodeBrokerFrames(protocol, "OUT").toString("utf8"), "stdout-value");
    assert.equal(decodeBrokerFrames(protocol, "ERR").toString("utf8"), "stderr-value");
    assert.match(protocol, new RegExp(`:${COMMAND_NONCE}:END:7`, "u"));
  },
);

test(
  "POSIX broker multiplexes concurrent stdout and stderr frames through one writer",
  { skip: !hasBash(), timeout: 30_000 },
  () => {
    const platform = process.platform === "darwin" ? "macos" : "linux";
    const bootstrap = buildPuttyBrokerBootstrap(
      { platform },
      SESSION_NONCE,
    ).toString("utf8");
    const broker = decodePosixBrokerBootstrap(bootstrap);
    const iterations = 2_000;
    const command =
      "for ((__ash_i=1; __ash_i<=" +
      String(iterations) +
      "; __ash_i++)); do printf 'O%04d\\n' \"$__ash_i\"; printf 'E%04d\\n' \"$__ash_i\" >&2; done";
    const result = spawnSync("bash", ["--noprofile", "--norc", "-c", broker], {
      input: buildPuttyCommandFrame(
        SESSION_NONCE,
        1,
        COMMAND_NONCE,
        { command },
      ),
      maxBuffer: 4 * 1024 * 1024,
      timeout: 25_000,
      windowsHide: true,
    });

    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr.toString("utf8"));
    const protocol = result.stdout.toString("ascii");
    const expectedStdout = Array.from(
      { length: iterations },
      (_, index) => `O${String(index + 1).padStart(4, "0")}\n`,
    ).join("");
    const expectedStderr = Array.from(
      { length: iterations },
      (_, index) => `E${String(index + 1).padStart(4, "0")}\n`,
    ).join("");
    assert.equal(
      decodeBrokerFrames(protocol, "OUT").toString("utf8"),
      expectedStdout,
    );
    assert.equal(
      decodeBrokerFrames(protocol, "ERR").toString("utf8"),
      expectedStderr,
    );
    assert.match(protocol, new RegExp(`:${COMMAND_NONCE}:END:0`, "u"));
  },
);

test("streams one Windows bootstrap line before RUN frames", async (t) => {
  const harness = createProcessHarness(t, [
    { commands: [{ output: "windows-ready" }] },
  ]);
  const executor = createExecutor(t, harness, { platform: "windows" });

  const outcome = await executor.run({
    sshAlias: TARGET_ALIAS,
    command: "hostname",
  });

  assert.equal(outcome.exitCode, 0);
  assert.equal(outcome.stdout, "windows-ready");
  const writes = writesForSpawn(harness, 0);
  assert.equal(writes.length, 3);
  assert.match(writes[0] ?? "", /:SHELL_READY/u);
  assert.match(writes[1] ?? "", /-enc/u);
  assert.match(writes[2] ?? "", /:RUN:/u);
});

test(
  "Windows broker emits separate UTF-8 OUT and ERR frames for cmd output",
  { skip: process.platform !== "win32", timeout: 20_000 },
  () => {
    const bootstrap = buildPuttyBrokerBootstrap(
      { platform: "windows" },
      WINDOWS_BOOTSTRAP_NONCE,
    ).toString("ascii");
    const launchLine = bootstrap.trimEnd();
    const frame = buildPuttyCommandFrame(
      WINDOWS_BOOTSTRAP_NONCE,
      1,
      COMMAND_NONCE,
      { command: "echo \u4e2d\u6587&echo \u9519\u8bef 1>&2" },
    );
    const result = spawnSync(
      "cmd.exe",
      ["/d", "/s", "/c", launchLine],
      {
        input: frame,
        maxBuffer: 1024 * 1024,
        timeout: 15_000,
        windowsHide: true,
      },
    );

    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr.toString("utf8"));
    const stdout = result.stdout.toString("ascii");
    assert.match(
      stdout,
      new RegExp(
        `__ASH2__:${WINDOWS_BOOTSTRAP_NONCE}:1:${COMMAND_NONCE}:END:0`,
        "u",
      ),
    );
    assert.equal(
      decodeBrokerFrames(stdout, "OUT").toString("utf8").trim(),
      "\u4e2d\u6587",
    );
    assert.equal(
      decodeBrokerFrames(stdout, "ERR").toString("utf8").trim(),
      "\u9519\u8bef",
    );
  },
);

test("reuses one persistent Plink session for five sequential commands", async (t) => {
  const harness = createProcessHarness(t, [
    {
      commands: Array.from({ length: 5 }, (_, index) => ({
        output: `result-${index + 1}`,
        exitCode: index,
      })),
    },
  ]);
  const executor = createExecutor(t, harness);

  for (let index = 0; index < 5; index += 1) {
    const outcome = await executor.run({
      sshAlias: TARGET_ALIAS,
      command: `command-${index + 1}`,
    });
    assert.equal(outcome.exitCode, index);
    assert.equal(outcome.stdout, `result-${index + 1}`);
    assert.equal(outcome.aborted, false);
  }

  assert.equal(harness.calls.length, 1);
  assert.equal(harness.calls[0]?.streamStdin, true);
  assert.equal(harness.calls[0]?.stdinPayload, undefined);
  const runFrames = writesForSpawn(harness, 0).filter((line) =>
    line.includes(":RUN:"),
  );
  assert.deepEqual(
    runFrames.map((frame) => frame.split(":")[2]),
    ["1", "2", "3", "4", "5"],
  );
  assert.equal(harness.terminateCalls.count, 0);
});

test("serializes concurrent commands FIFO without crossing output streams", async (t) => {
  const harness = createProcessHarness(t, [
    {
      commands: [
        { outputChunks: ["first-a", "first-b"], delayBeforeEndMs: 40 },
        { outputChunks: ["second-a", "second-b"] },
        { output: "third" },
      ],
    },
  ]);
  const executor = createExecutor(t, harness);
  const observed: string[] = [];
  const makeSink = (name: string): OutputSink => ({
    append(stream, chunk) {
      assert.equal(stream, "stdout");
      observed.push(name + ":" + Buffer.from(chunk).toString("utf8"));
    },
  });

  const outcomes = await Promise.all([
    executor.run({
      sshAlias: TARGET_ALIAS,
      command: "first",
      outputSink: makeSink("first"),
    }),
    executor.run({
      sshAlias: TARGET_ALIAS,
      command: "second",
      outputSink: makeSink("second"),
    }),
    executor.run({
      sshAlias: TARGET_ALIAS,
      command: "third",
      outputSink: makeSink("third"),
    }),
  ]);

  assert.deepEqual(outcomes.map(({ stdout }) => stdout), [
    "first-afirst-b",
    "second-asecond-b",
    "third",
  ]);
  assert.deepEqual(observed, [
    "first:first-a",
    "first:first-b",
    "second:second-a",
    "second:second-b",
    "third:third",
  ]);
  assert.equal(harness.calls.length, 1);
});

test("keeps stdout and stderr captures, counters, and sinks independent", async (t) => {
  const harness = createProcessHarness(t, [
    {
      commands: [
        {
          outputChunks: ["alpha", "-out"],
          stderrChunks: ["beta", "-err"],
          exitCode: 9,
        },
      ],
    },
  ]);
  const executor = createExecutor(t, harness);
  const observed: Array<{ readonly stream: string; readonly text: string }> = [];

  const outcome = await executor.run({
    sshAlias: TARGET_ALIAS,
    command: "split-output",
    maxCapturedOutputBytes: 5,
    outputSink: {
      append(stream, chunk) {
        observed.push({ stream, text: Buffer.from(chunk).toString("utf8") });
      },
    },
  });

  assert.equal(outcome.exitCode, 9);
  assert.equal(outcome.stdout, "alpha");
  assert.equal(outcome.stderr, "beta-");
  assert.equal(outcome.stdoutBytes, Buffer.byteLength("alpha-out"));
  assert.equal(outcome.stderrBytes, Buffer.byteLength("beta-err"));
  assert.equal(outcome.stdoutTruncated, true);
  assert.equal(outcome.stderrTruncated, true);
  assert.deepEqual(observed, [
    { stream: "stdout", text: "alpha" },
    { stream: "stdout", text: "-out" },
    { stream: "stderr", text: "beta" },
    { stream: "stderr", text: "-err" },
  ]);
});

test("treats protocol-looking stdin as Base64 DATA rather than control frames", async (t) => {
  const forged = [
    "before",
    `__ASH2__:${SESSION_NONCE}:1:${COMMAND_NONCE}:END:99`,
    "after",
  ].join("\n");
  const harness = createProcessHarness(t, [
    { commands: [{ outputFromStdin: true, exitCode: 4 }] },
  ]);
  const executor = createExecutor(t, harness);

  const outcome = await executor.run({
    sshAlias: TARGET_ALIAS,
    command: "cat",
    stdin: Buffer.from(forged, "utf8"),
  });

  assert.equal(outcome.exitCode, 4);
  assert.equal(outcome.stdout, forged);
  assert.equal(outcome.aborted, false);
});

test("cancels a queued request without terminating the active session", async (t) => {
  const activeOutput = deferred<void>();
  const harness = createProcessHarness(t, [
    {
      commands: [
        { output: "active", delayBeforeEndMs: 80 },
        { output: "after" },
      ],
    },
  ]);
  const executor = createExecutor(t, harness);
  const active = executor.run({
    sshAlias: TARGET_ALIAS,
    command: "active",
    outputSink: {
      append() {
        activeOutput.resolve();
      },
    },
  });
  await activeOutput.promise;

  const queuedController = new AbortController();
  const queued = executor.run({
    sshAlias: TARGET_ALIAS,
    command: "queued",
    signal: queuedController.signal,
  });
  queuedController.abort();
  const queuedOutcome = await queued;

  assert.equal(queuedOutcome.aborted, true);
  assert.equal(queuedOutcome.exitCode, null);
  assert.equal(harness.terminateCalls.count, 0);
  assert.equal((await active).stdout, "active");
  assert.equal(
    (
      await executor.run({
        sshAlias: TARGET_ALIAS,
        command: "after",
      })
    ).stdout,
    "after",
  );
  assert.equal(harness.calls.length, 1);
});

test("poisons active failures and respawns before the next command", async (t) => {
  const cases = [
    "abort",
    "incomplete",
    "invalid-frame",
    "sink-failure",
  ] as const;

  for (const failure of cases) {
    await t.test(failure, async (childTest) => {
      const firstOutput = deferred<void>();
      const firstPlan: FakeCommandPlan =
        failure === "abort"
          ? { behavior: "hang", output: "partial" }
          : failure === "incomplete"
            ? {
                behavior: "incomplete",
                output: "partial",
                stderr: "remote-error",
              }
            : failure === "invalid-frame"
              ? { behavior: "invalid-frame", output: "partial" }
              : { output: "sink-data" };
      const harness = createProcessHarness(childTest, [
        { commands: [firstPlan] },
        { commands: [{ output: "recovered" }] },
      ]);
      const executor = createExecutor(childTest, harness);
      const controller = new AbortController();
      const first = executor.run({
        sshAlias: TARGET_ALIAS,
        command: "possibly-side-effecting-command",
        ...(failure === "abort" ? { signal: controller.signal } : {}),
        ...(failure === "abort"
          ? {
              outputSink: {
                append() {
                  firstOutput.resolve();
                },
              },
            }
          : failure === "sink-failure"
            ? {
                outputSink: {
                  append() {
                    throw new Error("sink failed");
                  },
                },
              }
            : {}),
      });

      if (failure === "abort") {
        await firstOutput.promise;
        controller.abort();
        const outcome = await first;
        assert.equal(outcome.aborted, true);
        assert.equal(outcome.stdout, "partial");
      } else if (failure === "sink-failure") {
        await assert.rejects(first, /SSH output sink failed/iu);
      } else {
        const outcome = await first;
        assert.equal(outcome.exitCode, 255);
        assert.equal(outcome.failureReason, "accessclient-session-ended");
        assert.equal(outcome.stdout, "partial");
        assert.match(outcome.stderr, /ended before the command completed/iu);
        if (failure === "incomplete") {
          assert.ok(outcome.stderr.startsWith("remote-error"));
          assert.equal(
            outcome.stderrBytes,
            Buffer.byteLength(outcome.stderr, "utf8"),
          );
        }
      }

      const recovered = await executor.run({
        sshAlias: TARGET_ALIAS,
        command: "next-command",
      });
      assert.equal(recovered.exitCode, 0);
      assert.equal(recovered.stdout, "recovered");
      assert.equal(harness.calls.length, 2);
      assert.ok(harness.terminateCalls.count >= 1);
      assert.equal(
        writesForSpawn(harness, 0).filter((line) => line.includes(":RUN:")).length,
        1,
      );
    });
  }
});

test("aborts a permanently blocked output sink and respawns in bounded time", async (t) => {
  const sinkEntered = deferred<void>();
  const neverSettles = new Promise<void>(() => undefined);
  const harness = createProcessHarness(t, [
    { commands: [{ output: "blocked-output" }] },
    { commands: [{ output: "recovered" }] },
  ]);
  const executor = createExecutor(t, harness);
  const controller = new AbortController();
  const running = executor.run({
    sshAlias: TARGET_ALIAS,
    command: "blocked-sink",
    signal: controller.signal,
    outputSink: {
      append() {
        sinkEntered.resolve();
        return neverSettles;
      },
    },
  });

  await withTimeout(sinkEntered.promise);
  controller.abort();
  const aborted = await withTimeout(running);
  assert.equal(aborted.aborted, true);
  assert.equal(aborted.stdout, "blocked-output");

  const recovered = await withTimeout(
    executor.run({
      sshAlias: TARGET_ALIAS,
      command: "after-blocked-sink",
    }),
  );
  assert.equal(recovered.exitCode, 0);
  assert.equal(recovered.stdout, "recovered");
  assert.equal(harness.calls.length, 2);
  assert.ok(harness.terminateCalls.count >= 1);
  await withTimeout(executor.close());
});

test("close interrupts a permanently blocked output sink in bounded time", async (t) => {
  const sinkEntered = deferred<void>();
  const neverSettles = new Promise<void>(() => undefined);
  const harness = createProcessHarness(t, [
    { commands: [{ output: "blocked-output" }] },
  ]);
  const executor = createExecutor(t, harness);
  const running = executor.run({
    sshAlias: TARGET_ALIAS,
    command: "blocked-sink",
    outputSink: {
      append() {
        sinkEntered.resolve();
        return neverSettles;
      },
    },
  });

  await withTimeout(sinkEntered.promise);
  const closing = executor.close();
  const [outcome] = await withTimeout(Promise.all([running, closing]));

  assert.equal(outcome.aborted, true);
  assert.equal(outcome.stdout, "blocked-output");
  assert.equal(harness.terminateCalls.count, 1);
});

test("rejects a READY hostname mismatch before sending a command", async (t) => {
  const harness = createProcessHarness(t, [
    { hostname: "other-host", commands: [] },
  ]);
  const executor = createExecutor(t, harness);

  const outcome = await executor.run({
    sshAlias: TARGET_ALIAS,
    command: "must-not-run",
  });

  assert.equal(outcome.exitCode, 255);
  assert.equal(outcome.failureReason, "accessclient-host-mismatch");
  assert.equal(outcome.stdout, "");
  assert.match(outcome.stderr, /connected to a different target/iu);
  assert.equal(harness.calls.length, 1);
  assert.equal(
    writesForSpawn(harness, 0).some((line) => line.includes(":RUN:")),
    false,
  );
  assert.equal(harness.terminateCalls.count, 1);
});

test("accepts the observed READY hostname before a target is bound", async (t) => {
  const harness = createProcessHarness(t, [
    {
      hostname: "newly-observed-host",
      commands: [{ output: "first-connection-ready" }],
    },
  ]);
  const { expectedHostname: _expectedHostname, ...unboundOptions } = baseOptions();
  const executor = new PuttySharedExecutor(unboundOptions, harness.dependencies);
  t.after(() => executor.close());

  const outcome = await executor.run({
    sshAlias: TARGET_ALIAS,
    command: "hostname",
  });

  assert.equal(outcome.exitCode, 0);
  assert.equal(outcome.stdout, "first-connection-ready");
  assert.equal(
    writesForSpawn(harness, 0).some((line) => line.includes(":RUN:")),
    true,
  );
});

test("retries shell-ready probes and ignores prompt echoes containing the marker", async (t) => {
  const harness = createProcessHarness(t, [
    {
      shellReadyAfterProbes: 3,
      commands: [{ output: "ready-after-retry" }],
    },
  ]);
  const executor = createExecutor(t, harness, { bootstrapTimeoutMs: 3_000 });

  const outcome = await executor.run({
    sshAlias: TARGET_ALIAS,
    command: "hostname",
  });

  assert.equal(outcome.exitCode, 0);
  assert.equal(outcome.stdout, "ready-after-retry");
  const writes = writesForSpawn(harness, 0);
  const probes = writes.filter((line) => line.includes(":SHELL_READY"));
  assert.equal(probes.length, 3);
  const firstBootstrap = writes.findIndex((line) =>
    line.startsWith("__ash_payload_"),
  );
  const lastProbe = writes.findLastIndex((line) =>
    line.includes(":SHELL_READY"),
  );
  assert.ok(firstBootstrap > lastProbe);
});

test("fails closed when no AccessClient shared session reaches READY", async (t) => {
  const harness = createProcessHarness(t, [{ startup: "exit" }]);
  const executor = createExecutor(t, harness);

  const outcome = await executor.run({
    sshAlias: TARGET_ALIAS,
    command: "must-not-run",
  });

  assert.equal(outcome.exitCode, 255);
  assert.equal(outcome.failureReason, "accessclient-session-unavailable");
  assert.equal(outcome.stdout, "");
  assert.match(outcome.stderr, /shared session is not available/iu);
  assert.equal(harness.calls.length, 1);
});

test("classifies a shared session bootstrap timeout without exposing diagnostics", async (t) => {
  const harness = createProcessHarness(t, [{ startup: "hang" }]);
  const executor = createExecutor(t, harness, { bootstrapTimeoutMs: 10 });

  const outcome = await executor.run({
    sshAlias: TARGET_ALIAS,
    command: "must-not-run",
  });

  assert.equal(outcome.exitCode, 255);
  assert.equal(outcome.failureReason, "accessclient-session-timeout");
  assert.match(outcome.stderr, /did not become ready/iu);
  assert.equal(harness.calls.length, 1);
});

test("times out before staging a broker when the remote shell never confirms readiness", async (t) => {
  const harness = createProcessHarness(t, [
    { shellReadyAfterProbes: 100, startup: "hang" },
  ]);
  const executor = createExecutor(t, harness, { bootstrapTimeoutMs: 30 });

  const outcome = await executor.run({
    sshAlias: TARGET_ALIAS,
    command: "must-not-run",
  });

  assert.equal(outcome.exitCode, 255);
  assert.equal(outcome.failureReason, "accessclient-session-timeout");
  const writes = writesForSpawn(harness, 0);
  assert.ok(writes.some((line) => line.includes(":SHELL_READY")));
  assert.equal(
    writes.some(
      (line) =>
        line.startsWith("__ash_payload_") ||
        line.includes("-enc") ||
        line.includes(":RUN:"),
    ),
    false,
  );
});

test("retains ownership when command-session termination fails", async (t) => {
  const harness = createProcessHarness(t, [
    {
      commands: [{ behavior: "incomplete", output: "partial" }],
      terminateFailures: 2,
      terminateError: "synthetic command termination failure",
    },
  ]);
  const executor = new PuttySharedExecutor(baseOptions(), harness.dependencies);
  t.after(() => executor.close().catch(() => undefined));

  await assert.rejects(
    executor.run({
      sshAlias: TARGET_ALIAS,
      command: "uncertain-command",
    }),
    (error: unknown) => {
      assert.ok(error instanceof SshExecutionError);
      assert.ok(error.cause instanceof AggregateError);
      assert.equal(error.cause.errors.length, 2);
      assert.equal(
        errorTreeContains(error, "synthetic command termination failure"),
        true,
      );
      assert.equal(
        errorTreeCount(error, "synthetic command termination failure"),
        1,
      );
      return true;
    },
  );
  assert.equal(harness.terminateCalls.count, 1);
  await assert.rejects(
    executor.run({ sshAlias: TARGET_ALIAS, command: "must-not-respawn" }),
    (error: unknown) => {
      assert.equal(
        errorTreeContains(error, "synthetic command termination failure"),
        true,
      );
      return true;
    },
  );
  assert.equal(harness.calls.length, 1);
  assert.equal(harness.terminateCalls.count, 2);
  await executor.close();
  assert.equal(harness.terminateCalls.count, 3);
});

test("does not hide a termination failure behind an aborted outcome", async (t) => {
  const outputObserved = deferred<void>();
  const harness = createProcessHarness(t, [
    {
      commands: [{ behavior: "hang", output: "partial" }],
      terminateFailures: 1,
      terminateError: "synthetic abort termination failure",
    },
  ]);
  const executor = new PuttySharedExecutor(baseOptions(), harness.dependencies);
  t.after(() => executor.close().catch(() => undefined));
  const controller = new AbortController();
  const running = executor.run({
    sshAlias: TARGET_ALIAS,
    command: "abort-with-cleanup-failure",
    signal: controller.signal,
    outputSink: {
      append() {
        outputObserved.resolve();
      },
    },
  });

  await outputObserved.promise;
  controller.abort();
  await assert.rejects(running, (error: unknown) => {
    assert.equal(
      errorTreeContains(error, "persistent AccessClient operation was aborted"),
      true,
    );
    assert.equal(
      errorTreeContains(error, "synthetic abort termination failure"),
      true,
    );
    return true;
  });

  assert.equal(harness.terminateCalls.count, 1);
  await executor.close();
  assert.equal(harness.terminateCalls.count, 2);
});

test("reports startup and cleanup failures while retaining the opening session", async (t) => {
  const harness = createProcessHarness(t, [
    {
      startup: "exit",
      terminateFailures: 1,
      terminateError: "synthetic startup termination failure",
    },
  ]);
  const executor = new PuttySharedExecutor(baseOptions(), harness.dependencies);
  t.after(() => executor.close().catch(() => undefined));

  await assert.rejects(
    executor.run({ sshAlias: TARGET_ALIAS, command: "must-not-run" }),
    (error: unknown) => {
      assert.ok(error instanceof SshExecutionError);
      assert.ok(error.cause instanceof AggregateError);
      assert.equal(
        errorTreeContains(error, "synthetic startup termination failure"),
        true,
      );
      assert.equal(
        errorTreeCount(error, "synthetic startup termination failure"),
        1,
      );
      return true;
    },
  );
  assert.equal(harness.calls.length, 1);
  assert.equal(harness.terminateCalls.count, 1);
  await executor.close();
  assert.equal(harness.terminateCalls.count, 2);
});

test("retries executor close after a termination failure", async (t) => {
  const harness = createProcessHarness(t, [
    {
      commands: [{ output: "ready" }],
      terminateFailures: 1,
      terminateError: "synthetic close termination failure",
    },
  ]);
  const executor = new PuttySharedExecutor(baseOptions(), harness.dependencies);
  t.after(() => executor.close().catch(() => undefined));

  assert.equal(
    (
      await executor.run({
        sshAlias: TARGET_ALIAS,
        command: "hostname",
      })
    ).stdout,
    "ready",
  );

  await assert.rejects(
    executor.close(),
    (error: unknown) => {
      assert.equal(
        errorTreeContains(error, "synthetic close termination failure"),
        true,
      );
      return true;
    },
  );
  await executor.close();

  assert.equal(harness.calls.length, 1);
  assert.equal(harness.terminateCalls.count, 2);
});

test("close is idempotent and terminates the persistent session once", async (t) => {
  const harness = createProcessHarness(t, [
    { commands: [{ output: "ready" }] },
  ]);
  const executor = createExecutor(t, harness);
  assert.equal(
    (
      await executor.run({
        sshAlias: TARGET_ALIAS,
        command: "hostname",
      })
    ).stdout,
    "ready",
  );

  await Promise.all([executor.close(), executor.close(), executor.close()]);

  assert.equal(harness.terminateCalls.count, 1);
  await assert.rejects(
    executor.run({ sshAlias: TARGET_ALIAS, command: "after-close" }),
    /executor is closed/iu,
  );
});

test("recycles sessions after idle timeout and maximum lifetime", async (t) => {
  for (const timer of ["idle", "lifetime"] as const) {
    await t.test(timer, async (childTest) => {
      const harness = createProcessHarness(childTest, [
        { commands: [{ output: "first" }] },
        { commands: [{ output: "second" }] },
      ]);
      const executor = createExecutor(childTest, harness, {
        idleTimeoutMs: timer === "idle" ? 30 : 1_000,
        maxLifetimeMs: timer === "lifetime" ? 50 : 1_000,
      });

      const first = await executor.run({
        sshAlias: TARGET_ALIAS,
        command: "first",
      });
      assert.equal(first.stdout, "first");
      await waitUntil(() => harness.terminateCalls.count === 1);

      const second = await executor.run({
        sshAlias: TARGET_ALIAS,
        command: "second",
      });
      assert.equal(second.stdout, "second");
      assert.equal(harness.calls.length, 2);
    });
  }
});

test("retires an over-age session only after its active command completes", async (t) => {
  const harness = createProcessHarness(t, [
    {
      commands: [
        {
          output: "long-command",
          delayBeforeEndMs: 80,
        },
      ],
    },
    { commands: [{ output: "new-session" }] },
  ]);
  const executor = createExecutor(t, harness, {
    idleTimeoutMs: 1_000,
    maxLifetimeMs: 30,
  });

  const first = await executor.run({
    sshAlias: TARGET_ALIAS,
    command: "long-command",
  });

  assert.equal(first.stdout, "long-command");
  assert.equal(first.aborted, false);
  assert.equal(harness.terminateCalls.count, 1);

  const second = await executor.run({
    sshAlias: TARGET_ALIAS,
    command: "next-command",
  });
  assert.equal(second.stdout, "new-session");
  assert.equal(harness.calls.length, 2);
});

function baseOptions(): PuttySharedExecutorOptions {
  return {
    executable: String.raw`C:\Program Files\PuTTY\plink.exe`,
    targetAlias: TARGET_ALIAS,
    gatewayHost: "bastion.example.internal",
    gatewayPort: 22,
    gatewayUsername: "portal/172.24.251.37/kxjdev",
    sharingHost: "172.24.251.37",
    expectedHostname: EXPECTED_HOSTNAME,
    platform: "linux",
    allowUnsafeProcessTermination: true,
  };
}

function logHostArguments(arguments_: readonly string[]): string[] {
  const index = arguments_.indexOf("-loghost");
  return index < 0 ? [] : arguments_.slice(index, index + 2);
}

function createExecutor(
  t: TestContext,
  harness: ProcessHarness,
  overrides: Partial<PuttySharedExecutorOptions> = {},
): PuttySharedExecutor {
  const executor = new PuttySharedExecutor(
    { ...baseOptions(), ...overrides },
    harness.dependencies,
  );
  t.after(() => executor.close());
  return executor;
}

function deferred<Value>(): Deferred<Value> {
  let resolvePromise!: (value: Value) => void;
  const promise = new Promise<Value>((resolve) => {
    resolvePromise = resolve;
  });
  return { promise, resolve: resolvePromise };
}

async function waitUntil(
  predicate: () => boolean,
  timeoutMs = 1_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("condition was not reached");
    await delay(5);
  }
}

function withTimeout<Value>(
  operation: Promise<Value>,
  timeoutMs = 2_000,
): Promise<Value> {
  return new Promise<Value>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error(`operation did not settle within ${timeoutMs} ms`));
    }, timeoutMs);
    void operation.then(
      (value) => {
        clearTimeout(timeout);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timeout);
        reject(error);
      },
    );
  });
}

function errorTreeContains(error: unknown, expected: string): boolean {
  return errorTreeCount(error, expected) > 0;
}

function errorTreeCount(error: unknown, expected: string): number {
  if (error instanceof AggregateError) {
    return error.errors.reduce(
      (count, entry) => count + errorTreeCount(entry, expected),
      0,
    );
  }
  if (!(error instanceof Error)) return 0;
  return (
    (error.message.includes(expected) ? 1 : 0) +
    ("cause" in error ? errorTreeCount(error.cause, expected) : 0)
  );
}

function hasBash(): boolean {
  const result = spawnSync("bash", ["--version"], {
    stdio: "ignore",
    timeout: 5_000,
    windowsHide: true,
  });
  return result.error === undefined && result.status === 0;
}

function decodeBrokerFrames(
  protocol: string,
  kind: "OUT" | "ERR",
): Buffer {
  return Buffer.concat(
    protocol
      .split(/\r?\n/u)
      .filter((line) => line.includes(`:${kind}:`))
      .map((line) =>
        Buffer.from(line.slice(line.lastIndexOf(":") + 1), "base64"),
      ),
  );
}

function decodePosixBrokerBootstrap(bootstrap: string): string {
  const chunks = [...bootstrap.matchAll(
    /^__ash_payload_[a-f0-9]{32}=.*'([A-Za-z0-9+/=]+)' \|\| exit 96$/gmu,
  )].flatMap((match) => (match[1] === undefined ? [] : [match[1]]));
  assert.ok(chunks.length > 1, "POSIX broker payload was not split into chunks");
  return Buffer.from(chunks.join(""), "base64").toString("utf8");
}

function writesForSpawn(harness: ProcessHarness, spawnIndex: number): string[] {
  return harness.writes
    .filter((write) => write.spawnIndex === spawnIndex)
    .flatMap((write) => write.bytes.toString("utf8").split(/(?<=\n)/u))
    .map((line) => line.trimEnd())
    .filter((line) => line.length > 0);
}

function createProcessHarness(
  t: TestContext,
  plans: readonly FakeProcessPlan[],
): ProcessHarness {
  const remaining = [...plans];
  const calls: ManagedProcessOptions[] = [];
  const writes: CapturedWrite[] = [];
  const children = new Set<ChildProcessWithoutNullStreams>();
  const terminateCalls = { count: 0 };

  t.after(() => {
    for (const child of children) {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
      }
    }
  });

  return {
    calls,
    writes,
    terminateCalls,
    dependencies: {
      async spawnProcess(options): Promise<ManagedProcess> {
        const plan = remaining.shift();
        if (plan === undefined) {
          throw new Error("unexpected fake Plink invocation");
        }
        const spawnIndex = calls.length;
        calls.push(options);
        const child = spawn(process.execPath, ["-e", CHILD_SOURCE], {
          detached: false,
          shell: false,
          windowsHide: true,
          stdio: ["pipe", "pipe", "pipe"],
          env: {
            ...process.env,
            FAKE_PLINK_PLAN: Buffer.from(JSON.stringify(plan), "utf8").toString(
              "base64",
            ),
          },
        });
        children.add(child);
        child.once("close", () => children.delete(child));

        type DynamicWrite = (...arguments_: unknown[]) => boolean;
        const originalWrite = child.stdin.write.bind(child.stdin) as DynamicWrite;
        const observedWrite: DynamicWrite = (...arguments_) => {
          const chunk = arguments_[0];
          if (typeof chunk === "string" || ArrayBuffer.isView(chunk)) {
            writes.push({
              spawnIndex,
              bytes:
                typeof chunk === "string"
                  ? Buffer.from(chunk)
                  : Buffer.from(
                      chunk.buffer,
                      chunk.byteOffset,
                      chunk.byteLength,
                    ),
            });
          }
          return Reflect.apply(originalWrite, child.stdin, arguments_) as boolean;
        };
        Object.defineProperty(child.stdin, "write", {
          configurable: true,
          value: observedWrite,
          writable: true,
        });

        let remainingTerminationFailures = plan.terminateFailures ?? 0;
        const terminationFailure = new Error(
          plan.terminateError ?? "synthetic termination failure",
        );
        return createManagedProcess(
          child,
          "windows-taskkill-unsafe",
          () => {
            terminateCalls.count += 1;
            if (remainingTerminationFailures > 0) {
              remainingTerminationFailures -= 1;
              return Promise.reject(terminationFailure);
            }
            return new Promise<void>((resolve) => {
              if (child.exitCode !== null || child.signalCode !== null) {
                resolve();
                return;
              }
              let settled = false;
              const finish = (): void => {
                if (settled) return;
                settled = true;
                clearTimeout(timeout);
                child.off("close", finish);
                resolve();
              };
              const timeout = setTimeout(finish, 1_000);
              child.once("close", finish);
              child.kill("SIGKILL");
            });
          },
        );
      },
    },
  };
}
