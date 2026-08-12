import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import process from "node:process";
import test from "node:test";

import {
  POSIX_BASH_REMOTE_COMMAND,
  prepareRemoteCommand,
  prepareStructuredRemoteCommand,
  WINDOWS_POWERSHELL_REMOTE_COMMAND,
  type PreparedRemoteCommand,
} from "../../src/core/remote-command.js";
import { GATEWAY_ERROR_CODES, GatewayError } from "../../src/shared/errors.js";
import { MAX_COMMAND_BYTES } from "../../src/shared/protocol.js";
import { MAX_MANAGED_STDIN_BYTES } from "../../src/infra/process-tree.js";

test("passes Linux and macOS commands through byte-for-byte without stdin", () => {
  const command = "printf '%s' \"$HOME\"; uname -a";
  assert.deepEqual(prepareRemoteCommand("linux", command), { command });
  assert.deepEqual(prepareRemoteCommand("macos", command), { command });
});

test("keeps Windows command text out of argv and the ASCII wrapper", () => {
  const command =
    'Write-Output "中文 & | < > ^ %PATH% ! \' ; { } ( ) $env:TEMP"';
  const prepared = prepareRemoteCommand("windows", command);

  assert.equal(prepared.command, WINDOWS_POWERSHELL_REMOTE_COMMAND);
  assert.equal(prepared.command.includes(command), false);
  assert.ok(prepared.stdin !== undefined);
  const wrapper = Buffer.from(prepared.stdin).toString("ascii");
  assert.equal(Buffer.from(prepared.stdin).every((byte) => byte <= 0x7f), true);
  assert.equal(wrapper.split("\n").filter(Boolean).length, 1);
  assert.equal(wrapper.includes(command), false);
  assert.doesNotMatch(wrapper, /EncodedCommand/u);

  const payloadMatch = /FromBase64String\('([A-Za-z0-9+/=]+)'\)/u.exec(wrapper);
  assert.ok(payloadMatch?.[1]);
  const decoded = Buffer.from(payloadMatch[1], "base64").toString("utf8");
  assert.equal(decoded.startsWith(`${command}\n\n`), true);
  assert.match(decoded, /\$agentSshCommandSucceeded=\$\?/u);
  assert.match(decoded, /exit \$agentSshNativeExitCode/u);
  assert.match(decoded, /exit 1$/u);
});

test("supports the protocol command limit without a Windows argv expansion", () => {
  const largest = prepareRemoteCommand("windows", "x".repeat(MAX_COMMAND_BYTES));
  assert.equal(largest.command, WINDOWS_POWERSHELL_REMOTE_COMMAND);
  assert.ok(largest.stdin !== undefined);
  assert.ok(largest.stdin.byteLength <= MAX_MANAGED_STDIN_BYTES);
  assert.throws(
    () => prepareRemoteCommand("windows", "x".repeat(MAX_COMMAND_BYTES + 1)),
    (error: unknown) =>
      error instanceof GatewayError &&
      error.code === GATEWAY_ERROR_CODES.invalidParams,
  );
});

test("renders structured commands through fixed platform shell entry points", () => {
  const bash = prepareStructuredRemoteCommand("linux", {
    shell: "bash",
    cwd: "/srv/a directory",
    env: {
      AGENT_VALUE: "literal '$HOME' & value",
      Path: "first",
      PATH: "second",
    },
    script: "printf '%s' \"$AGENT_VALUE\"\nprintf '%s' \"$PATH\"",
    encoding: "utf-8",
  });
  assert.equal(bash.command, POSIX_BASH_REMOTE_COMMAND);
  assert.ok(bash.stdin !== undefined);
  assert.equal(bash.command.includes("AGENT_VALUE"), false);
  assert.equal(bash.command.includes("/srv/a directory"), false);
  const bashStdin = Buffer.from(bash.stdin).toString("utf8");
  assert.match(bashStdin, /export AGENT_VALUE=/u);
  assert.match(bashStdin, /cd --/u);
  assert.match(bashStdin, /printf '%s'/u);

  for (const shell of ["powershell", "cmd"] as const) {
    const secret = `secret-${shell}-\u4e2d\u6587`;
    const prepared = prepareStructuredRemoteCommand("windows", {
      shell,
      cwd: String.raw`C:\Program Files\Agent SSH`,
      env: { AGENT_SECRET: secret },
      script: `echo ${secret}\necho second-line`,
      encoding: "utf-8",
    });
    assert.equal(prepared.command, WINDOWS_POWERSHELL_REMOTE_COMMAND);
    assert.ok(prepared.stdin !== undefined);
    assert.equal(prepared.command.includes(secret), false);
    const wrapper = Buffer.from(prepared.stdin).toString("ascii");
    assert.equal(Buffer.from(prepared.stdin).every((byte) => byte <= 0x7f), true);
    assert.equal(wrapper.split("\n").filter(Boolean).length, 1);
    assert.equal(wrapper.includes(secret), false);
    assert.equal(wrapper.includes("Agent SSH"), false);
  }

  assert.equal(
    prepareStructuredRemoteCommand("macos", {
      shell: "bash",
      script: "pwd",
    }).command,
    POSIX_BASH_REMOTE_COMMAND,
  );
});

test("rejects unsupported structured shell and malformed bounded context", () => {
  for (const [platform, shell] of [
    ["windows", "bash"],
    ["linux", "powershell"],
    ["linux", "cmd"],
    ["macos", "powershell"],
  ] as const) {
    assert.throws(
      () => prepareStructuredRemoteCommand(platform, { shell, script: "hostname" }),
      (error: unknown) =>
        error instanceof GatewayError &&
        error.code === GATEWAY_ERROR_CODES.invalidParams,
    );
  }

  const invalidInputs = [
    { shell: "bash" as const, script: " \r\n " },
    { shell: "bash" as const, script: "echo ok\0echo bad" },
    { shell: "bash" as const, script: "pwd", cwd: "bad\npath" },
    {
      shell: "bash" as const,
      script: "pwd",
      env: { "BAD-NAME": "value" },
    },
    {
      shell: "powershell" as const,
      script: "pwd",
      env: { Path: "one", PATH: "two" },
    },
    {
      shell: "bash" as const,
      script: "x".repeat(MAX_COMMAND_BYTES),
      cwd: "x",
    },
    {
      shell: "bash" as const,
      script: "pwd",
      encoding: "utf-16le" as "utf-8",
    },
  ];
  for (const input of invalidInputs) {
    assert.throws(
      () => prepareStructuredRemoteCommand(
        input.shell === "powershell" ? "windows" : "linux",
        input,
      ),
      (error: unknown) =>
        error instanceof GatewayError &&
        error.code === GATEWAY_ERROR_CODES.invalidParams,
    );
  }
});

test(
  "executes a structured Bash script with literal cwd and environment",
  { skip: process.platform === "win32", timeout: 30_000 },
  () => {
    const value = "line 1 '$HOME' & value\nline 2";
    const prepared = prepareStructuredRemoteCommand("linux", {
      shell: "bash",
      cwd: process.cwd(),
      env: { AGENT_VALUE: value },
      script: [
        `printf '%s\\n' \"$AGENT_VALUE\"`,
        `printf '%s\\n' \"$PWD\"`,
        `printf '%s\\n' 'stderr-text' >&2`,
        "exit 7",
      ].join("\n"),
    });
    assert.ok(prepared.stdin !== undefined);
    const result = spawnSync(
      "bash",
      ["--noprofile", "--norc", "-s"],
      { input: Buffer.from(prepared.stdin), encoding: "utf8" },
    );
    assert.equal(result.error, undefined);
    assert.equal(result.status, 7);
    assert.equal(result.stdout, `${value}\n${process.cwd()}\n`);
    assert.equal(result.stderr, "stderr-text\n");
  },
);

test(
  "executes structured PowerShell and cmd with UTF-8 context and exit codes",
  { skip: process.platform !== "win32", timeout: 30_000 },
  () => {
    const value = "structured-\u4e2d\u6587-&|%";
    const powershell = runPreparedWindows(
      prepareStructuredRemoteCommand("windows", {
        shell: "powershell",
        cwd: process.cwd(),
        env: { AGENT_VALUE: value },
        script: [
          "[Console]::Out.Write($env:AGENT_VALUE)",
          "[Console]::Out.Write('|'+$PWD.Path)",
          "[Console]::Error.Write('stderr-text')",
          "cmd.exe /d /c exit 7",
        ].join("\n"),
      }),
    );
    assert.equal(powershell.error, undefined);
    assert.equal(powershell.status, 7);
    assert.equal(powershell.stdout.toString("utf8"), `${value}|${process.cwd()}`);
    assert.equal(powershell.stderr.toString("utf8"), "stderr-text");

    const strictPowerShell = runPreparedWindows(
      prepareStructuredRemoteCommand("windows", {
        shell: "powershell",
        script: [
          "Set-StrictMode -Version 3.0",
          "[Console]::Out.Write('strict-without-native-command')",
        ].join("\n"),
      }),
    );
    assert.equal(strictPowerShell.error, undefined);
    assert.equal(strictPowerShell.status, 0);
    assert.equal(
      strictPowerShell.stdout.toString("utf8"),
      "strict-without-native-command",
    );
    assert.equal(strictPowerShell.stderr.toString("utf8"), "");

    const commandPrompt = runPreparedWindows(
      prepareStructuredRemoteCommand("windows", {
        shell: "cmd",
        cwd: process.cwd(),
        env: { AGENT_VALUE: value },
        script: [
          "set AGENT_VALUE",
          "cd",
          "echo stderr-text 1>&2",
          "exit /b 9",
        ].join("\r\n"),
      }),
    );
    assert.equal(commandPrompt.error, undefined);
    assert.equal(commandPrompt.status, 9);
    const cmdStdout = commandPrompt.stdout.toString("utf8");
    assert.equal(cmdStdout.includes(`AGENT_VALUE=${value}`), true);
    assert.equal(cmdStdout.includes(process.cwd()), true);
    assert.doesNotMatch(cmdStdout, /Microsoft Windows \[Version/u);
    assert.equal(commandPrompt.stderr.toString("utf8").trim(), "stderr-text");
  },
);

test(
  "preserves Windows output, errors, parsing confidentiality, and exit status",
  { skip: process.platform !== "win32", timeout: 30_000 },
  () => {
    const stdoutText = "中文标准输出";
    const stdout = runWindows(`[Console]::Out.Write('${stdoutText}')`);
    assert.equal(stdout.error, undefined);
    assert.equal(stdout.status, 0);
    assert.equal(stdout.stdout.toString("utf8"), stdoutText);
    assert.equal(stdout.stderr.toString("utf8"), "");

    const stderrText = "中文标准错误";
    const stderr = runWindows(`Write-Error '${stderrText}'`);
    assert.equal(stderr.status, 1);
    assert.equal(stderr.stderr.toString("utf8").trim(), stderrText);
    assert.equal(stderr.stderr.toString("utf8").startsWith("#< CLIXML"), false);

    assert.equal(runWindows("cmd.exe /d /c exit 7").status, 7);
    assert.equal(runWindows("exit 23").status, 23);

    const hostname = runWindows("hostname");
    assert.equal(hostname.status, 0);
    assert.notEqual(hostname.stdout.toString("utf8").trim(), "");

    const culture = runWindows(
      "Get-Culture | Format-List Name, DisplayName",
    );
    assert.equal(culture.status, 0);
    assert.match(culture.stdout.toString("utf8"), /Name\s*:/u);
    assert.match(culture.stdout.toString("utf8"), /DisplayName\s*:/u);

    const thrown = runWindows("throw 'expected runtime failure'");
    assert.equal(thrown.status, 1);
    assert.equal(
      thrown.stderr.toString("utf8").trim(),
      "expected runtime failure",
    );
    assert.equal(thrown.stderr.toString("utf8").startsWith("#< CLIXML"), false);

    const unicode = "\u4e2d\u6587";
    const complexCommand =
      `$values=@('${unicode}','&|<>^%!','\"quote\"','$env:TEMP');` +
      '$values|ForEach-Object{[Console]::Out.Write("[$_]")}';
    const complex = runWindows(complexCommand);
    assert.equal(complex.status, 0);
    assert.equal(
      complex.stdout.toString("utf8"),
      `[${unicode}][&|<>^%!][\"quote\"][$env:TEMP]`,
    );
    assert.equal(complex.stderr.toString("utf8"), "");

    const sentinel = "SENTINEL_8f191e";
    const failingCommand =
      `$marker='${sentinel}'; Get-Item Z:\\definitely-missing`;
    const failed = runWindows(failingCommand);
    const failedStderr = failed.stderr.toString("utf8");
    assert.equal(failed.status, 1);
    assert.equal(failedStderr.startsWith("#< CLIXML"), false);
    assert.equal(failedStderr.includes(sentinel), false);
    assert.equal(failedStderr.includes(failingCommand), false);

    const parseSentinel = "PARSE_SENTINEL_3ec4b2";
    const invalidCommand = `$marker='${parseSentinel}'; if (`;
    const invalid = runWindows(invalidCommand);
    const invalidStderr = invalid.stderr.toString("utf8");
    assert.equal(invalid.status, 1);
    assert.equal(invalidStderr.trim(), "PowerShell command parsing failed.");
    assert.equal(invalidStderr.includes(parseSentinel), false);
    assert.equal(invalidStderr.includes(invalidCommand), false);
  },
);

function runWindows(command: string): {
  readonly error?: Error;
  readonly status: number | null;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
} {
  const prepared: PreparedRemoteCommand = prepareRemoteCommand("windows", command);
  assert.ok(prepared.stdin !== undefined);
  const result = spawnSync(
    "cmd.exe",
    ["/d", "/s", "/c", prepared.command],
    {
      input: Buffer.from(prepared.stdin),
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    },
  );
  return {
    ...(result.error === undefined ? {} : { error: result.error }),
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

function runPreparedWindows(prepared: PreparedRemoteCommand): {
  readonly error?: Error;
  readonly status: number | null;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
} {
  assert.equal(prepared.command, WINDOWS_POWERSHELL_REMOTE_COMMAND);
  assert.ok(prepared.stdin !== undefined);
  const result = spawnSync(
    "cmd.exe",
    ["/d", "/s", "/c", prepared.command],
    {
      input: Buffer.from(prepared.stdin),
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    },
  );
  return {
    ...(result.error === undefined ? {} : { error: result.error }),
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}
