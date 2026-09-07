import assert from "node:assert/strict";
import test from "node:test";

import {
  SharedShellTransferError,
  SharedShellTransferExecutor,
} from "../../src/infra/shared-shell-transfer.js";
import type {
  SshOutcome,
  SshRunInput,
  SshRunner,
} from "../../src/infra/ssh-runner.js";

class RecordingRunner implements SshRunner {
  public readonly calls: SshRunInput[] = [];
  readonly #handler: (input: SshRunInput) => Promise<SshOutcome>;

  public constructor(handler: (input: SshRunInput) => Promise<SshOutcome>) {
    this.#handler = handler;
  }

  public async run(input: SshRunInput): Promise<SshOutcome> {
    this.calls.push(input);
    return this.#handler(input);
  }

  public async close(): Promise<void> {}
}

function outcome(overrides: Partial<SshOutcome> = {}): SshOutcome {
  return {
    exitCode: 0,
    signal: null,
    stdout: "",
    stderr: "",
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutTruncated: false,
    stderrTruncated: false,
    aborted: false,
    durationMs: 1,
    terminationMode: null,
    ...overrides,
  };
}

test("POSIX writes keep file bytes in the persistent command stdin", async () => {
  const bytes = Buffer.from([0, 1, 2, 10, 13, 255]);
  const runner = new RecordingRunner(async () => outcome());
  const executor = new SharedShellTransferExecutor(runner);

  await executor.write({
    target: { sshAlias: "shared", platform: "linux" },
    remotePath: "/tmp/a'b.bin",
    bytes,
    truncate: true,
    signal: new AbortController().signal,
  });

  assert.equal(runner.calls.length, 1);
  const call = runner.calls[0]!;
  assert.equal(call.sshAlias, "shared");
  assert.deepEqual(call.stdin, bytes);
  assert.match(call.command, /\/bin\/cat > "\$agentSshPath"/u);
  assert.match(call.command, /a'\\''b\.bin/u);
});

test("Windows writes use one encoded command and preserve binary stdin", async () => {
  const bytes = Buffer.from([255, 0, 128, 10]);
  const runner = new RecordingRunner(async () => outcome());
  const executor = new SharedShellTransferExecutor(runner);

  await executor.write({
    target: { sshAlias: "shared", platform: "windows" },
    remotePath: "D:/data/payload.bin",
    bytes,
    truncate: false,
    signal: new AbortController().signal,
  });

  const call = runner.calls[0]!;
  assert.deepEqual(call.stdin, bytes);
  assert.match(call.command, /^powershell\.exe .* -EncodedCommand /u);
  const encoded = call.command.split(" ").at(-1)!;
  const script = Buffer.from(encoded, "base64").toString("utf16le");
  assert.match(script, /FileMode\]::Append/u);
  assert.match(script, /OpenStandardInput\(\)\.CopyTo/u);
});

test("reads strictly decode the canonical Base64 returned by the shared shell", async () => {
  const bytes = Buffer.from("共享会话 binary \u0000 payload", "utf8");
  const runner = new RecordingRunner(async () =>
    outcome({ stdout: bytes.toString("base64") }),
  );
  const executor = new SharedShellTransferExecutor(runner);

  const read = await executor.read({
    target: { sshAlias: "shared", platform: "linux" },
    remotePath: "/tmp/payload.bin",
    offset: 7,
    length: bytes.length,
    signal: new AbortController().signal,
  });

  assert.deepEqual(read, bytes);
  assert.match(runner.calls[0]!.command, /^bash /u);
  assert.ok(runner.calls[0]!.stdin);
  assert.equal(Buffer.from(runner.calls[0]!.stdin!).toString("utf8").includes("(?:"), false);
});

test("reads reject non-canonical or noisy Base64", async () => {
  const runner = new RecordingRunner(async () => outcome({ stdout: "YQ==\n" }));
  const executor = new SharedShellTransferExecutor(runner);

  await assert.rejects(
    executor.read({
      target: { sshAlias: "shared", platform: "linux" },
      remotePath: "/tmp/payload.bin",
      offset: 0,
      length: 1,
      signal: new AbortController().signal,
    }),
    SharedShellTransferError,
  );
});
