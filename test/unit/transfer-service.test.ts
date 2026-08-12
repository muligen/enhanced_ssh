import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { TransferService } from "../../src/core/transfer-service.js";
import { MAX_TRANSFER_PATH_BYTES } from "../../src/core/transfer-paths.js";
import { TargetRegistry } from "../../src/core/target-registry.js";
import { TaskStore } from "../../src/core/task-store.js";
import {
  AuditWriter,
  type AuditEvent,
} from "../../src/infra/audit-writer.js";
import type {
  SftpExecutor,
  SftpOutcome,
  SftpRunInput,
} from "../../src/infra/sftp-executor.js";
import type {
  SshExecutor,
  SshOutcome,
  SshRunInput,
} from "../../src/infra/openssh-executor.js";
import { GATEWAY_ERROR_CODES, GatewayError } from "../../src/shared/errors.js";
import type {
  DownloadParams,
  SyncParams,
  TargetPlatform,
  UploadParams,
} from "../../src/shared/protocol.js";

class FakeSftpExecutor {
  public readonly calls: SftpRunInput[] = [];
  readonly #handler: (input: SftpRunInput) => Promise<SftpOutcome>;

  public constructor(
    handler: (input: SftpRunInput) => Promise<SftpOutcome> = async () =>
      sftpOutcome(),
  ) {
    this.#handler = handler;
  }

  public async run(input: SftpRunInput): Promise<SftpOutcome> {
    this.calls.push(input);
    return this.#handler(input);
  }
}

class FakeSshExecutor {
  public readonly calls: SshRunInput[] = [];
  readonly #handler: (input: SshRunInput) => Promise<SshOutcome>;

  public constructor(
    handler: (input: SshRunInput) => Promise<SshOutcome> = async (input) =>
      isUploadPathProbeCall(input)
        ? sshOutcome({ stdout: "SAFE" })
        : sshOutcome(),
  ) {
    this.#handler = handler;
  }

  public async run(input: SshRunInput): Promise<SshOutcome> {
    this.calls.push(input);
    return this.#handler(input);
  }
}

class RecordingAudit {
  public readonly events: AuditEvent[] = [];

  public async write(event: AuditEvent): Promise<void> {
    this.events.push(event);
  }
}

interface Harness {
  readonly directory: string;
  readonly localRoot: string;
  readonly spoolDirectory: string;
  readonly registry: TargetRegistry;
  readonly tasks: TaskStore;
  readonly sftp: FakeSftpExecutor;
  readonly ssh: FakeSshExecutor;
  readonly audit: RecordingAudit;
  readonly service: TransferService;
}

async function createHarness(options: {
  readonly platform?: TargetPlatform;
  readonly remoteRoot?: string;
  readonly fullAccess?: boolean;
  readonly maxFileBytes?: number;
  readonly maxTotalBytes?: number;
  readonly maxFiles?: number;
  readonly sftp?: FakeSftpExecutor;
  readonly ssh?: FakeSshExecutor;
} = {}): Promise<Harness> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "agent-ssh-transfer-service-"));
  const localRoot = path.join(directory, "workspace");
  const spoolDirectory = path.join(directory, "spool");
  await Promise.all([mkdir(localRoot), mkdir(spoolDirectory)]);
  const platform = options.platform ?? "linux";
  const remoteRoot =
    options.remoteRoot ?? (platform === "windows" ? "D:/services" : "/srv/services");
  const registry = new TargetRegistry(
    {
      managed: {
        sshAlias: "managed-internal",
        platform,
        enabled: true,
        policy:
          options.fullAccess === false
            ? {
                mode: "allow-list" as const,
                allowedCommands: ["hostname"],
                maxTimeoutMs: 5_000,
              }
            : { mode: "full-access" as const, maxTimeoutMs: 5_000 },
        transfer: {
          mode: "bidirectional",
          localRoots: ["workspace"],
          remoteRoots: [remoteRoot],
          maxFileBytes: options.maxFileBytes ?? 16 * 1_024 * 1_024,
          maxTotalBytes: options.maxTotalBytes ?? 32 * 1_024 * 1_024,
          maxFiles: options.maxFiles ?? 100,
          maxTimeoutMs: 5_000,
        },
      },
    },
    { workspace: localRoot },
  );
  const tasks = new TaskStore({
    ttlMs: 60_000,
    maxRetainedTasks: 100,
    maxConcurrentTasks: 8,
  });
  const sftp = options.sftp ?? new FakeSftpExecutor();
  const ssh = options.ssh ?? new FakeSshExecutor();
  const audit = new RecordingAudit();
  const service = new TransferService({
    registry,
    taskStore: tasks,
    spoolDirectory,
    sftp: sftp as unknown as SftpExecutor,
    ssh: ssh as unknown as SshExecutor,
    audit: audit as unknown as Pick<AuditWriter, "write">,
  });
  return {
    directory,
    localRoot,
    spoolDirectory,
    registry,
    tasks,
    sftp,
    ssh,
    audit,
    service,
  };
}

function uploadParams(overrides: Partial<UploadParams> = {}): UploadParams {
  return {
    target: "managed",
    localRoot: "workspace",
    localPath: "payload.bin",
    remotePath: "/srv/services/payload.bin",
    overwrite: false,
    resume: true,
    dryRun: false,
    verify: "sha256",
    ...overrides,
  };
}

function downloadParams(overrides: Partial<DownloadParams> = {}): DownloadParams {
  return {
    target: "managed",
    localRoot: "workspace",
    localPath: "download.bin",
    remotePath: "/srv/services/download.bin",
    overwrite: false,
    resume: true,
    dryRun: false,
    ...overrides,
  };
}

function syncParams(overrides: Partial<SyncParams> = {}): SyncParams {
  return {
    target: "managed",
    localRoot: "workspace",
    localPath: "source",
    remotePath: "/srv/services/app",
    overwrite: false,
    resume: true,
    dryRun: false,
    exclude: [],
    verifyExisting: false,
    ...overrides,
  };
}

function sftpOutcome(overrides: Partial<SftpOutcome> = {}): SftpOutcome {
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

function sshOutcome(overrides: Partial<SshOutcome> = {}): SshOutcome {
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

function batchText(input: SftpRunInput): string {
  return Buffer.from(input.batch).toString("utf8");
}

function downloadedLocalPath(input: SftpRunInput): string {
  const match = /^@(?:re)?get\s+"(?:\\.|[^"])*"\s+"((?:\\.|[^"])*)"/mu.exec(
    batchText(input),
  );
  assert.ok(match?.[1]);
  return match[1].replace(/\\(.)/gu, "$1");
}

function structuredCommandText(input: SshRunInput): string {
  const stdin = Buffer.from(input.stdin ?? []).toString(
    input.command.startsWith("powershell.exe") ? "ascii" : "utf8",
  );
  if (!input.command.startsWith("powershell.exe")) return stdin;
  return [...stdin.matchAll(/FromBase64String\('([^']+)'\)/gu)]
    .map((match) => Buffer.from(match[1]!, "base64").toString("utf8"))
    .join("\n");
}

function isUploadPathProbeCall(input: SshRunInput): boolean {
  const commandText = structuredCommandText(input);
  return (
    commandText.includes("AGENT_SSH_TRANSFER_DESTINATION") &&
    (commandText.includes("Get-AgentSshPathProbeStatus") ||
      commandText.includes("agentSshCheckPath"))
  );
}

function successfulTransferSsh(contents: Uint8Array | string): FakeSshExecutor {
  return new FakeSshExecutor(async (input) =>
    isUploadPathProbeCall(input)
      ? sshOutcome({ stdout: "SAFE" })
      : sshOutcome({ stdout: fingerprint(contents) }),
  );
}

function sha256(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

function fingerprint(value: Uint8Array | string): string {
  const bytes = typeof value === "string" ? Buffer.from(value, "utf8") : value;
  return `${bytes.byteLength}:${sha256(value)}`;
}

async function waitForTerminal(tasks: TaskStore, runId: string) {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    const status = tasks.status(runId);
    if (status.state !== "running") return status;
    await new Promise<void>((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("task did not finish");
}

function hasGatewayCode(code: string): (error: unknown) => boolean {
  return (error: unknown): boolean =>
    error instanceof GatewayError && error.code === code;
}

test("full access preserves rooted upload compatibility", async (t) => {
  const harness = await createHarness();
  t.after(() => rm(harness.directory, { recursive: true, force: true }));
  const contents = Buffer.from("dry run payload", "utf8");
  await writeFile(path.join(harness.localRoot, "payload.bin"), contents);

  const started = harness.service.startUpload(uploadParams({ dryRun: true }));
  const status = await waitForTerminal(harness.tasks, started.runId);

  assert.equal(status.state, "succeeded");
  assert.equal(status.result?.sha256, sha256(contents));
  assert.deepEqual(await readdir(harness.spoolDirectory), []);
  assert.equal(harness.sftp.calls.length, 0);
  assert.equal(harness.ssh.calls.length, 0);
  assert.deepEqual(
    harness.audit.events.map((event) => event.event),
    ["transfer.started", "transfer.completed"],
  );
});

test("upload checksum comparison accepts uppercase hexadecimal digests", async (t) => {
  const harness = await createHarness();
  t.after(() => rm(harness.directory, { recursive: true, force: true }));
  const contents = Buffer.from("uppercase checksum", "utf8");
  await writeFile(path.join(harness.localRoot, "payload.bin"), contents);

  const started = harness.service.startUpload(
    uploadParams({
      dryRun: true,
      expectedSha256: sha256(contents).toUpperCase(),
    }),
  );
  const status = await waitForTerminal(harness.tasks, started.runId);

  assert.equal(status.state, "succeeded");
  assert.equal(status.result?.sha256, sha256(contents));
});

test("full access accepts an absolute local path and any normalized remote root", async (t) => {
  const harness = await createHarness();
  t.after(() => rm(harness.directory, { recursive: true, force: true }));
  const contents = Buffer.from("unrestricted payload", "utf8");
  const absoluteLocalPath = path.join(harness.localRoot, "payload.bin");
  await writeFile(absoluteLocalPath, contents);

  const started = harness.service.startUpload(
    uploadParams({
      localRoot: undefined,
      localPath: absoluteLocalPath,
      remotePath: "/outside/configured/roots/payload.bin",
      dryRun: true,
    }),
  );
  const status = await waitForTerminal(harness.tasks, started.runId);

  assert.equal(status.state, "succeeded");
  assert.equal(status.result?.sha256, sha256(contents));
  assert.equal(harness.sftp.calls.length, 0);
  assert.equal(harness.ssh.calls.length, 0);
});

test("rooted and restricted transfers reject the wrong local path form", async (t) => {
  const full = await createHarness();
  const restricted = await createHarness({ fullAccess: false });
  t.after(() => rm(full.directory, { recursive: true, force: true }));
  t.after(() => rm(restricted.directory, { recursive: true, force: true }));
  const absoluteLocalPath = path.join(full.localRoot, "payload.bin");

  assert.throws(
    () =>
      full.service.startUpload(
        uploadParams({ localRoot: "workspace", localPath: absoluteLocalPath }),
      ),
    hasGatewayCode(GATEWAY_ERROR_CODES.invalidParams),
  );
  assert.throws(
    () =>
      restricted.service.startUpload(
        uploadParams({
          localRoot: undefined,
          localPath: path.join(restricted.localRoot, "payload.bin"),
        }),
      ),
    hasGatewayCode(GATEWAY_ERROR_CODES.transferDenied),
  );
});

test("remote fingerprints use fixed structured scripts on every target platform", async (t) => {
  const contents = Buffer.from("fingerprinted", "utf8");
  const cases: ReadonlyArray<{
    readonly platform: TargetPlatform;
    readonly remoteRoot: string;
    readonly remotePath: string;
    readonly scriptMarker: string;
    readonly ancestorMarker: string;
  }> = [
    {
      platform: "linux",
      remoteRoot: "/srv/services",
      remotePath: "/srv/services/file.bin",
      scriptMarker: "stat -c '%s'",
      ancestorMarker: "stat -c '%f'",
    },
    {
      platform: "macos",
      remoteRoot: "/srv/services",
      remotePath: "/srv/services/file.bin",
      scriptMarker: "stat -f '%z'",
      ancestorMarker: "stat -f '%p'",
    },
    {
      platform: "windows",
      remoteRoot: "D:/services",
      remotePath: "D:/services/file.bin",
      scriptMarker: "Get-FileHash",
      ancestorMarker: "Get-AgentSshPathProbeStatus",
    },
  ];

  for (const entry of cases) {
    const ssh = new FakeSshExecutor(async () =>
      sshOutcome({ stdout: fingerprint(contents) }),
    );
    const harness = await createHarness({
      platform: entry.platform,
      remoteRoot: entry.remoteRoot,
      fullAccess: false,
      ssh,
    });
    t.after(() => rm(harness.directory, { recursive: true, force: true }));
    const started = harness.service.startDownload(
      downloadParams({ remotePath: entry.remotePath, dryRun: true }),
    );
    const status = await waitForTerminal(harness.tasks, started.runId);

    assert.equal(status.state, "succeeded");
    assert.equal(status.result?.bytes, contents.byteLength);
    assert.equal(ssh.calls.length, 1);
    const call = ssh.calls[0]!;
    assert.ok(call.stdin);
    const script = structuredCommandText(call);
    assert.equal(script.includes(entry.scriptMarker), true);
    assert.equal(script.includes(entry.ancestorMarker), true);
    if (entry.platform === "windows") {
      assert.equal(call.command, "powershell.exe -NoLogo -NoProfile -NonInteractive -Command -");
      assert.equal(script.includes("ReparsePoint"), true);
      assert.equal(script.includes("Microsoft.PowerShell.Management\\Get-Item"), true);
    } else {
      assert.equal(call.command, "bash --noprofile --norc -s");
      assert.match(script, /\[ -L "\$AGENT_SSH_TRANSFER_PATH" \]/u);
      assert.equal(script.includes("agentSshCheckEntry / /"), true);
      assert.equal(script.includes("set -uf"), true);
    }
  }
});

test("download distinguishes missing paths from unsafe remote ancestors", async (t) => {
  const cases: ReadonlyArray<{
    readonly name: string;
    readonly outcome: Partial<SshOutcome>;
    readonly message: RegExp;
  }> = [
    {
      name: "missing",
      outcome: { exitCode: 10, stdout: "MISSING" },
      message: /not found or could not be read/u,
    },
    {
      name: "unsafe",
      outcome: { exitCode: 11, stdout: "UNSAFE" },
      message: /link or reparse point/u,
    },
    {
      name: "inspection error",
      outcome: { exitCode: 12, stdout: "ERROR" },
      message: /inspection failed/u,
    },
    {
      name: "mismatched status pair",
      outcome: { exitCode: 11, stdout: "MISSING" },
      message: /inspection failed/u,
    },
    {
      name: "noisy status",
      outcome: { exitCode: 11, stdout: "UNSAFE", stderr: "noise" },
      message: /response was invalid/u,
    },
    {
      name: "truncated status",
      outcome: { exitCode: 11, stdout: "UNSAFE", stdoutTruncated: true },
      message: /response was invalid/u,
    },
  ];

  for (const entry of cases) {
    const harness = await createHarness({
      ssh: new FakeSshExecutor(async () => sshOutcome(entry.outcome)),
    });
    t.after(() => rm(harness.directory, { recursive: true, force: true }));
    const started = harness.service.startDownload(downloadParams({ dryRun: true }));
    const status = await waitForTerminal(harness.tasks, started.runId);

    assert.equal(status.state, "failed", entry.name);
    assert.equal(
      status.error?.gatewayCode,
      GATEWAY_ERROR_CODES.transferFailed,
      entry.name,
    );
    assert.match(status.error?.message ?? "", entry.message, entry.name);
    assert.equal(harness.sftp.calls.length, 0, entry.name);
  }
});

test("remote fingerprint parser rejects extra text and unsafe sizes", async (t) => {
  const hash = "a".repeat(64);
  const cases = [
    `1:${hash}\n`,
    `01:${hash}`,
    `1:${hash.toUpperCase()}`,
    `9007199254740992:${hash}`,
    `1:${hash}:extra`,
  ];

  for (const output of cases) {
    const harness = await createHarness({
      ssh: new FakeSshExecutor(async () => sshOutcome({ stdout: output })),
    });
    t.after(() => rm(harness.directory, { recursive: true, force: true }));
    const started = harness.service.startDownload(downloadParams({ dryRun: true }));
    const status = await waitForTerminal(harness.tasks, started.runId);
    assert.equal(status.state, "failed");
    assert.equal(status.error?.gatewayCode, GATEWAY_ERROR_CODES.transferFailed);
    assert.equal(harness.sftp.calls.length, 0);
  }
});

test("download rejects a remote file over quota before starting SFTP", async (t) => {
  const harness = await createHarness({
    maxFileBytes: 4,
    maxTotalBytes: 8,
    ssh: new FakeSshExecutor(async () =>
      sshOutcome({ stdout: `5:${"a".repeat(64)}` }),
    ),
  });
  t.after(() => rm(harness.directory, { recursive: true, force: true }));

  const started = harness.service.startDownload(downloadParams({ resume: false }));
  const status = await waitForTerminal(harness.tasks, started.runId);

  assert.equal(status.state, "failed");
  assert.match(status.error?.message ?? "", /quota/u);
  assert.equal(harness.sftp.calls.length, 0);
});

test("transfer fails closed before staging or SSH when its start audit is unavailable", async (t) => {
  const harness = await createHarness();
  t.after(() => rm(harness.directory, { recursive: true, force: true }));
  await writeFile(path.join(harness.localRoot, "payload.bin"), "payload", "utf8");
  const blockingFile = path.join(harness.directory, "not-a-directory");
  await writeFile(blockingFile, "block", "utf8");
  const audit = new AuditWriter({
    filePath: path.join(blockingFile, "events.jsonl"),
  });
  const service = new TransferService({
    registry: harness.registry,
    taskStore: harness.tasks,
    spoolDirectory: harness.spoolDirectory,
    sftp: harness.sftp as unknown as SftpExecutor,
    ssh: harness.ssh as unknown as SshExecutor,
    audit,
  });

  const started = service.startUpload(uploadParams());
  const status = await waitForTerminal(harness.tasks, started.runId);

  assert.equal(status.state, "failed");
  assert.equal(status.error?.gatewayCode, "AUDIT_UNAVAILABLE");
  assert.equal(harness.sftp.calls.length, 0);
  assert.equal(harness.ssh.calls.length, 0);
  assert.deepEqual(await readdir(harness.spoolDirectory), []);
});

test("upload probes destination and partial ancestors before SFTP on every platform", async (t) => {
  const contents = Buffer.from("ancestor checked upload", "utf8");
  const cases: ReadonlyArray<{
    readonly platform: TargetPlatform;
    readonly remoteRoot: string;
    readonly remotePath: string;
    readonly ancestorMarker: string;
    readonly regularFileMarker: string;
  }> = [
    {
      platform: "linux",
      remoteRoot: "/srv/services",
      remotePath: "/srv/services/path with spaces/file.bin",
      ancestorMarker: "stat -c '%f'",
      regularFileMarker: "-ne 32768",
    },
    {
      platform: "macos",
      remoteRoot: "/srv/services",
      remotePath: "/srv/services/path with spaces/file.bin",
      ancestorMarker: "stat -f '%p'",
      regularFileMarker: "-ne 32768",
    },
    {
      platform: "windows",
      remoteRoot: "D:/services",
      remotePath: "D:/services/path with spaces/file.bin",
      ancestorMarker: "ReparsePoint",
      regularFileMarker: "[System.IO.FileInfo]",
    },
  ];

  for (const entry of cases) {
    const events: string[] = [];
    const ssh = new FakeSshExecutor(async (input) => {
      if (isUploadPathProbeCall(input)) {
        events.push("preflight");
        return sshOutcome({ stdout: "SAFE" });
      }
      events.push("fingerprint");
      return sshOutcome({ stdout: fingerprint(contents) });
    });
    const sftp = new FakeSftpExecutor(async () => {
      events.push("sftp");
      return sftpOutcome();
    });
    const harness = await createHarness({
      platform: entry.platform,
      remoteRoot: entry.remoteRoot,
      fullAccess: false,
      ssh,
      sftp,
    });
    t.after(() => rm(harness.directory, { recursive: true, force: true }));
    await writeFile(path.join(harness.localRoot, "payload.bin"), contents);

    const started = harness.service.startUpload(
      uploadParams({
        remotePath: entry.remotePath,
        overwrite: true,
        resume: false,
      }),
    );
    const status = await waitForTerminal(harness.tasks, started.runId);

    assert.equal(status.state, "succeeded", entry.platform);
    assert.equal(events[0], "preflight", entry.platform);
    const preflightCalls = ssh.calls.filter(isUploadPathProbeCall);
    assert.equal(preflightCalls.length, 1, entry.platform);
    const preflight = preflightCalls[0]!;
    assert.equal(preflight.maxCapturedOutputBytes, 64, entry.platform);
    const script = structuredCommandText(preflight);
    assert.equal(script.includes(entry.ancestorMarker), true, entry.platform);
    assert.equal(script.includes(entry.regularFileMarker), true, entry.platform);
    assert.equal(
      script.includes("AGENT_SSH_TRANSFER_DESTINATION"),
      true,
      entry.platform,
    );
    assert.equal(script.includes("AGENT_SSH_TRANSFER_PART"), true, entry.platform);
    assert.equal(script.includes("SAFE"), true, entry.platform);
    assert.equal(
      preflight.command,
      entry.platform === "windows"
        ? "powershell.exe -NoLogo -NoProfile -NonInteractive -Command -"
        : "bash --noprofile --norc -s",
      entry.platform,
    );
  }
});

test("upload rejects unsafe remote ancestors on every platform before SFTP", async (t) => {
  const cases: ReadonlyArray<{
    readonly platform: TargetPlatform;
    readonly remoteRoot: string;
    readonly remotePath: string;
  }> = [
    {
      platform: "linux",
      remoteRoot: "/srv/services",
      remotePath: "/srv/services/file.bin",
    },
    {
      platform: "macos",
      remoteRoot: "/srv/services",
      remotePath: "/srv/services/file.bin",
    },
    {
      platform: "windows",
      remoteRoot: "D:/services",
      remotePath: "D:/services/file.bin",
    },
  ];

  for (const entry of cases) {
    const harness = await createHarness({
      platform: entry.platform,
      remoteRoot: entry.remoteRoot,
      fullAccess: false,
      ssh: new FakeSshExecutor(async () =>
        sshOutcome({ exitCode: 11, stdout: "UNSAFE" }),
      ),
    });
    t.after(() => rm(harness.directory, { recursive: true, force: true }));
    await writeFile(path.join(harness.localRoot, "payload.bin"), "payload");

    const started = harness.service.startUpload(
      uploadParams({ remotePath: entry.remotePath, overwrite: true }),
    );
    const status = await waitForTerminal(harness.tasks, started.runId);

    assert.equal(status.state, "failed", entry.platform);
    assert.equal(status.error?.gatewayCode, GATEWAY_ERROR_CODES.transferFailed);
    assert.match(status.error?.message ?? "", /link or reparse point/u);
    assert.equal(harness.sftp.calls.length, 0, entry.platform);
    assert.equal(harness.ssh.calls.length, 1, entry.platform);
  }
});

test("upload path preflight rejects malformed, noisy, or truncated status responses", async (t) => {
  const cases: ReadonlyArray<{
    readonly name: string;
    readonly outcome: Partial<SshOutcome>;
  }> = [
    {
      name: "wrong token for success",
      outcome: { exitCode: 0, stdout: "MISSING" },
    },
    {
      name: "trailing newline",
      outcome: { exitCode: 0, stdout: "SAFE\n" },
    },
    {
      name: "wrong token for unsafe code",
      outcome: { exitCode: 11, stdout: "MISSING" },
    },
    {
      name: "directory or special leaf",
      outcome: { exitCode: 12, stdout: "ERROR" },
    },
    {
      name: "stderr noise",
      outcome: { exitCode: 0, stdout: "SAFE", stderr: "noise" },
    },
    {
      name: "truncated stdout",
      outcome: { exitCode: 0, stdout: "SAFE", stdoutTruncated: true },
    },
  ];

  for (const entry of cases) {
    const harness = await createHarness({
      ssh: new FakeSshExecutor(async () => sshOutcome(entry.outcome)),
    });
    t.after(() => rm(harness.directory, { recursive: true, force: true }));
    await writeFile(path.join(harness.localRoot, "payload.bin"), "payload");

    const started = harness.service.startUpload(uploadParams({ overwrite: true }));
    const status = await waitForTerminal(harness.tasks, started.runId);

    assert.equal(status.state, "failed", entry.name);
    assert.equal(status.error?.gatewayCode, GATEWAY_ERROR_CODES.transferFailed);
    assert.match(status.error?.message ?? "", /inspection failed/u, entry.name);
    assert.equal(harness.sftp.calls.length, 0, entry.name);
  }
});

test("restricted upload rejects a partial path outside the approved root", async (t) => {
  const contents = Buffer.from("root equality", "utf8");
  const restricted = await createHarness({
    fullAccess: false,
    remoteRoot: "/srv/services",
  });
  const full = await createHarness({
    fullAccess: true,
    remoteRoot: "/srv/services",
    ssh: successfulTransferSsh(contents),
  });
  t.after(() => rm(restricted.directory, { recursive: true, force: true }));
  t.after(() => rm(full.directory, { recursive: true, force: true }));
  await Promise.all([
    writeFile(path.join(restricted.localRoot, "payload.bin"), contents),
    writeFile(path.join(full.localRoot, "payload.bin"), contents),
  ]);

  const denied = restricted.service.startUpload(
    uploadParams({ remotePath: "/srv/services", overwrite: true, resume: false }),
  );
  const deniedStatus = await waitForTerminal(restricted.tasks, denied.runId);
  assert.equal(deniedStatus.state, "failed");
  assert.equal(
    deniedStatus.error?.gatewayCode,
    GATEWAY_ERROR_CODES.transferDenied,
  );
  assert.equal(restricted.ssh.calls.length, 0);
  assert.equal(restricted.sftp.calls.length, 0);

  const allowed = full.service.startUpload(
    uploadParams({ remotePath: "/srv/services", overwrite: true, resume: false }),
  );
  const allowedStatus = await waitForTerminal(full.tasks, allowed.runId);
  assert.equal(allowedStatus.state, "succeeded");
  assert.equal(full.ssh.calls.filter(isUploadPathProbeCall).length, 1);
});

test("Windows upload creates parents only at and below the approved remote root", async (t) => {
  const contents = Buffer.from("windows payload", "utf8");
  const sftp = new FakeSftpExecutor();
  const ssh = successfulTransferSsh(contents);
  const harness = await createHarness({
    platform: "windows",
    remoteRoot: "D:/services/approved",
    fullAccess: false,
    sftp,
    ssh,
  });
  t.after(() => rm(harness.directory, { recursive: true, force: true }));
  await writeFile(path.join(harness.localRoot, "payload.bin"), contents);

  const started = harness.service.startUpload(
    uploadParams({
      remotePath: "D:\\services\\approved\\nested\\payload.bin",
      overwrite: true,
      resume: false,
    }),
  );
  const status = await waitForTerminal(harness.tasks, started.runId);

  assert.equal(status.state, "succeeded");
  const mkdirBatch = sftp.calls.map(batchText).find((batch) => batch.includes("mkdir"));
  assert.ok(mkdirBatch);
  const mkdirLines = mkdirBatch.split("\n").filter((line) => line.includes("mkdir"));
  assert.deepEqual(mkdirLines, [
    '-@mkdir "D:/services/approved"',
    '-@mkdir "D:/services/approved/nested"',
  ]);
  assert.equal(mkdirLines.some((line) => line === '-@mkdir "D:/services"'), false);
});

test("upload overwrite false uses an exclusive remote publish and removes its partial on a race", async (t) => {
  const contents = Buffer.from("exclusive upload", "utf8");
  const sftp = new FakeSftpExecutor(async (input) =>
    sftpOutcome({ exitCode: batchText(input).startsWith("@ls ") ? 1 : 0 }),
  );
  const ssh = new FakeSshExecutor(async (input) => {
    if (isUploadPathProbeCall(input)) {
      return sshOutcome({ stdout: "SAFE" });
    }
    return structuredCommandText(input).includes("sha256sum")
      ? sshOutcome({ stdout: fingerprint(contents) })
      : sshOutcome({ exitCode: 17 });
  });
  const harness = await createHarness({ sftp, ssh });
  t.after(() => rm(harness.directory, { recursive: true, force: true }));
  await writeFile(path.join(harness.localRoot, "payload.bin"), contents);

  const started = harness.service.startUpload(
    uploadParams({ resume: false, remotePath: "/srv/services/private-name.bin" }),
  );
  const status = await waitForTerminal(harness.tasks, started.runId);

  assert.equal(status.state, "failed");
  assert.equal(status.error?.gatewayCode, "TRANSFER_FAILED");
  assert.equal(status.error?.message.includes("private-name"), false);
  assert.equal(sftp.calls.some((call) => batchText(call).includes("@rename")), false);
  assert.equal(sftp.calls.some((call) => batchText(call).includes("@rm ")), true);
  const auditText = JSON.stringify(harness.audit.events);
  assert.equal(auditText.includes("private-name"), false);
  assert.deepEqual(
    harness.audit.events.map((event) => event.event),
    ["transfer.started", "transfer.failed"],
  );
});

test("download overwrite false preserves a racing destination and cleans private staging", async (t) => {
  const remoteContents = Buffer.from("remote download", "utf8");
  let destinationPath = "";
  const sftp = new FakeSftpExecutor(async (input) => {
    await writeFile(downloadedLocalPath(input), remoteContents);
    await writeFile(destinationPath, "racing writer", "utf8");
    return sftpOutcome();
  });
  const ssh = new FakeSshExecutor(async () =>
    sshOutcome({ stdout: fingerprint(remoteContents) }),
  );
  const harness = await createHarness({ sftp, ssh });
  t.after(() => rm(harness.directory, { recursive: true, force: true }));
  destinationPath = path.join(harness.localRoot, "download.bin");

  const started = harness.service.startDownload(
    downloadParams({ resume: false, remotePath: "/srv/services/secret.bin" }),
  );
  const status = await waitForTerminal(harness.tasks, started.runId);

  assert.equal(status.state, "failed");
  assert.equal(await readFile(destinationPath, "utf8"), "racing writer");
  assert.deepEqual(await readdir(harness.spoolDirectory), []);
  assert.equal(status.error?.message.includes("secret.bin"), false);
  assert.equal(JSON.stringify(harness.audit.events).includes("secret.bin"), false);
});

test("download resumes only a gateway-owned partial with matching metadata", async (t) => {
  const remoteContents = Buffer.from("complete resumed download", "utf8");
  let transferCall = 0;
  const sftp = new FakeSftpExecutor(async (input) => {
    transferCall += 1;
    const localPath = downloadedLocalPath(input);
    if (transferCall === 1) {
      await writeFile(localPath, remoteContents.subarray(0, 8));
      return sftpOutcome({ exitCode: 1 });
    }
    assert.match(batchText(input), /^@reget /mu);
    await writeFile(localPath, remoteContents);
    return sftpOutcome();
  });
  const ssh = new FakeSshExecutor(async () =>
    sshOutcome({ stdout: fingerprint(remoteContents) }),
  );
  const harness = await createHarness({ sftp, ssh });
  t.after(() => rm(harness.directory, { recursive: true, force: true }));

  const first = harness.service.startDownload(downloadParams());
  assert.equal((await waitForTerminal(harness.tasks, first.runId)).state, "failed");
  const retainedNames = await readdir(harness.spoolDirectory);
  assert.deepEqual(
    retainedNames.map((name) => name.slice(64)).sort(),
    [".download.json", ".download.part"],
  );
  const metadataName = retainedNames.find((name) => name.endsWith(".json"));
  assert.ok(metadataName);
  const metadataText = await readFile(
    path.join(harness.spoolDirectory, metadataName),
    "utf8",
  );
  assert.equal(metadataText.includes("download.bin"), false);
  assert.equal(metadataText.includes("/srv/services"), false);

  const second = harness.service.startDownload(downloadParams());
  assert.equal((await waitForTerminal(harness.tasks, second.runId)).state, "succeeded");
  assert.deepEqual(
    await readFile(path.join(harness.localRoot, "download.bin")),
    remoteContents,
  );
  assert.deepEqual(await readdir(harness.spoolDirectory), []);
});

test("download discards a partial whose sidecar no longer matches its binding", async (t) => {
  const remoteContents = Buffer.from("sidecar-bound download", "utf8");
  let transferCall = 0;
  const sftp = new FakeSftpExecutor(async (input) => {
    transferCall += 1;
    const localPath = downloadedLocalPath(input);
    if (transferCall === 1) {
      await writeFile(localPath, "partial", "utf8");
      return sftpOutcome({ exitCode: 1 });
    }
    assert.match(batchText(input), /^@get /mu);
    assert.doesNotMatch(batchText(input), /^@reget /mu);
    await writeFile(localPath, remoteContents);
    return sftpOutcome();
  });
  const ssh = new FakeSshExecutor(async () =>
    sshOutcome({ stdout: fingerprint(remoteContents) }),
  );
  const harness = await createHarness({ sftp, ssh });
  t.after(() => rm(harness.directory, { recursive: true, force: true }));

  const first = harness.service.startDownload(downloadParams());
  assert.equal((await waitForTerminal(harness.tasks, first.runId)).state, "failed");
  const metadataName = (await readdir(harness.spoolDirectory)).find((name) =>
    name.endsWith(".download.json"),
  );
  assert.ok(metadataName);
  const metadataPath = path.join(harness.spoolDirectory, metadataName);
  const metadata = JSON.parse(await readFile(metadataPath, "utf8")) as Record<
    string,
    unknown
  >;
  await writeFile(
    metadataPath,
    `${JSON.stringify({ ...metadata, remoteSha256: "0".repeat(64) })}\n`,
    "utf8",
  );

  const second = harness.service.startDownload(downloadParams());
  assert.equal((await waitForTerminal(harness.tasks, second.runId)).state, "succeeded");
  assert.deepEqual(
    await readFile(path.join(harness.localRoot, "download.bin")),
    remoteContents,
  );
  assert.deepEqual(await readdir(harness.spoolDirectory), []);
});

test("download checksum failure never publishes and removes an unusable partial", async (t) => {
  const expectedContents = Buffer.from("expected", "utf8");
  const sftp = new FakeSftpExecutor(async (input) => {
    await writeFile(downloadedLocalPath(input), "corrupt", "utf8");
    return sftpOutcome();
  });
  const ssh = new FakeSshExecutor(async () =>
    sshOutcome({ stdout: fingerprint(expectedContents) }),
  );
  const harness = await createHarness({ sftp, ssh });
  t.after(() => rm(harness.directory, { recursive: true, force: true }));

  const started = harness.service.startDownload(downloadParams());
  const status = await waitForTerminal(harness.tasks, started.runId);

  assert.equal(status.state, "failed");
  assert.equal(status.error?.gatewayCode, "CHECKSUM_MISMATCH");
  await assert.rejects(readFile(path.join(harness.localRoot, "download.bin")));
  assert.deepEqual(await readdir(harness.spoolDirectory), []);
});

test("download checksum comparison accepts uppercase hexadecimal digests", async (t) => {
  const remoteContents = Buffer.from("uppercase download checksum", "utf8");
  const sftp = new FakeSftpExecutor(async (input) => {
    await writeFile(downloadedLocalPath(input), remoteContents);
    return sftpOutcome();
  });
  const ssh = new FakeSshExecutor(async () =>
    sshOutcome({ stdout: fingerprint(remoteContents) }),
  );
  const harness = await createHarness({ sftp, ssh });
  t.after(() => rm(harness.directory, { recursive: true, force: true }));

  const started = harness.service.startDownload(
    downloadParams({ expectedSha256: sha256(remoteContents).toUpperCase() }),
  );
  const status = await waitForTerminal(harness.tasks, started.runId);

  assert.equal(status.state, "succeeded");
  assert.deepEqual(
    await readFile(path.join(harness.localRoot, "download.bin")),
    remoteContents,
  );
});

test("download requires the transferred size to match the remote fingerprint", async (t) => {
  const remoteContents = Buffer.from("same hash but declared size differs", "utf8");
  const sftp = new FakeSftpExecutor(async (input) => {
    await writeFile(downloadedLocalPath(input), remoteContents);
    return sftpOutcome();
  });
  const ssh = new FakeSshExecutor(async () =>
    sshOutcome({
      stdout: `${remoteContents.byteLength + 1}:${sha256(remoteContents)}`,
    }),
  );
  const harness = await createHarness({ sftp, ssh });
  t.after(() => rm(harness.directory, { recursive: true, force: true }));

  const started = harness.service.startDownload(
    downloadParams({ resume: false }),
  );
  const status = await waitForTerminal(harness.tasks, started.runId);

  assert.equal(status.state, "failed");
  assert.equal(status.error?.gatewayCode, GATEWAY_ERROR_CODES.checksumMismatch);
  await assert.rejects(readFile(path.join(harness.localRoot, "download.bin")));
  assert.deepEqual(await readdir(harness.spoolDirectory), []);
});

test("sync excludes matching directories and uploads only included files", async (t) => {
  const included = Buffer.from("included", "utf8");
  const sftp = new FakeSftpExecutor();
  const ssh = successfulTransferSsh(included);
  const harness = await createHarness({ sftp, ssh });
  t.after(() => rm(harness.directory, { recursive: true, force: true }));
  await Promise.all([
    mkdir(path.join(harness.localRoot, "source", "node_modules"), {
      recursive: true,
    }),
    mkdir(path.join(harness.localRoot, "source", "nested"), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(path.join(harness.localRoot, "source", "nested", "keep.txt"), included),
    writeFile(
      path.join(harness.localRoot, "source", "node_modules", "ignored.txt"),
      "ignored",
      "utf8",
    ),
  ]);

  const started = harness.service.startSync(
    syncParams({ overwrite: true, resume: false, exclude: ["node_modules"] }),
  );
  const status = await waitForTerminal(harness.tasks, started.runId);

  assert.equal(status.state, "succeeded");
  assert.equal(status.result?.files, 1);
  const batches = sftp.calls.map(batchText).join("\n");
  assert.match(batches, /nested\/keep\.txt/u);
  assert.equal(batches.includes("ignored.txt"), false);
  assert.equal(batches.includes("node_modules"), false);
  assert.equal(ssh.calls.filter(isUploadPathProbeCall).length, 1);
});

test("sync enforces file count, per-file, and aggregate byte quotas while scanning", async (t) => {
  const cases: ReadonlyArray<{
    readonly name: string;
    readonly options: {
      readonly maxFiles?: number;
      readonly maxFileBytes?: number;
      readonly maxTotalBytes?: number;
    };
    readonly files: readonly string[];
  }> = [
    {
      name: "file count",
      options: { maxFiles: 1 },
      files: ["", ""],
    },
    {
      name: "per-file bytes",
      options: { maxFileBytes: 3 },
      files: ["four"],
    },
    {
      name: "aggregate bytes",
      options: { maxFileBytes: 4, maxTotalBytes: 5 },
      files: ["abc", "def"],
    },
  ];

  for (const entry of cases) {
    const harness = await createHarness(entry.options);
    t.after(() => rm(harness.directory, { recursive: true, force: true }));
    await mkdir(path.join(harness.localRoot, "source"));
    await Promise.all(
      entry.files.map((contents, index) =>
        writeFile(
          path.join(harness.localRoot, "source", `${index}.bin`),
          contents,
          "utf8",
        ),
      ),
    );

    const started = harness.service.startSync(syncParams({ dryRun: true }));
    const status = await waitForTerminal(harness.tasks, started.runId);

    assert.equal(status.state, "failed", entry.name);
    assert.equal(
      status.error?.gatewayCode,
      GATEWAY_ERROR_CODES.transferFailed,
      entry.name,
    );
    assert.match(status.error?.message ?? "", /quota/u, entry.name);
    assert.equal(harness.sftp.calls.length, 0, entry.name);
    assert.equal(harness.ssh.calls.length, 0, entry.name);
  }
});

test("sync exclusion globs keep segment-aware matching semantics", async (t) => {
  const harness = await createHarness();
  t.after(() => rm(harness.directory, { recursive: true, force: true }));
  await Promise.all([
    mkdir(path.join(harness.localRoot, "source", "nested"), { recursive: true }),
    mkdir(path.join(harness.localRoot, "source", "assets"), { recursive: true }),
    mkdir(path.join(harness.localRoot, "source", "literal"), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(path.join(harness.localRoot, "source", "top.log"), "1"),
    writeFile(path.join(harness.localRoot, "source", "nested", "deep.log"), "22"),
    writeFile(path.join(harness.localRoot, "source", "nested", "keep.txt"), "4444"),
    writeFile(path.join(harness.localRoot, "source", "assets", "image.bin"), "88888888"),
    writeFile(
      path.join(harness.localRoot, "source", "literal", "[abc].txt"),
      "6666666666666666",
    ),
  ]);
  const cases: ReadonlyArray<{
    readonly pattern: string;
    readonly expectedBytes: number;
  }> = [
    { pattern: "*.log", expectedBytes: 30 },
    { pattern: "nested/*.log", expectedBytes: 29 },
    { pattern: "nested/?eep.txt", expectedBytes: 27 },
    { pattern: "nested/**", expectedBytes: 25 },
    { pattern: "assets", expectedBytes: 23 },
    { pattern: "literal/[abc].txt", expectedBytes: 15 },
  ];

  for (const entry of cases) {
    const started = harness.service.startSync(
      syncParams({ dryRun: true, exclude: [entry.pattern] }),
    );
    const status = await waitForTerminal(harness.tasks, started.runId);
    assert.equal(status.state, "succeeded", entry.pattern);
    assert.equal(status.result?.bytes, entry.expectedBytes, entry.pattern);
  }
});

test("sync rejects excessive aggregate exclusion complexity before scanning", async (t) => {
  const harness = await createHarness();
  t.after(() => rm(harness.directory, { recursive: true, force: true }));
  await mkdir(path.join(harness.localRoot, "source"));

  const started = harness.service.startSync(
    syncParams({
      dryRun: true,
      exclude: ["a".repeat(400), "b".repeat(400), "c".repeat(400)],
    }),
  );
  const status = await waitForTerminal(harness.tasks, started.runId);

  assert.equal(status.state, "failed");
  assert.equal(status.error?.gatewayCode, GATEWAY_ERROR_CODES.invalidParams);
  assert.match(status.error?.message ?? "", /too complex/u);
  assert.equal(harness.sftp.calls.length, 0);
  assert.equal(harness.ssh.calls.length, 0);
});

test("sync rejects descendant paths over the safe UTF-8 byte limit", async (t) => {
  const harness = await createHarness();
  t.after(() => rm(harness.directory, { recursive: true, force: true }));
  let absoluteDirectory = path.join(harness.localRoot, "source");
  let relativeDirectory = "";
  await mkdir(absoluteDirectory);
  for (let index = 0; Buffer.byteLength(relativeDirectory, "utf8") <= MAX_TRANSFER_PATH_BYTES; index += 1) {
    const segment = `d${index.toString().padStart(3, "0")}${"x".repeat(196)}`;
    absoluteDirectory = path.join(absoluteDirectory, segment);
    relativeDirectory = relativeDirectory
      ? `${relativeDirectory}/${segment}`
      : segment;
    await mkdir(absoluteDirectory);
  }

  const started = harness.service.startSync(syncParams({ dryRun: true }));
  const status = await waitForTerminal(harness.tasks, started.runId);

  assert.equal(status.state, "failed");
  assert.equal(status.error?.gatewayCode, GATEWAY_ERROR_CODES.transferFailed);
  assert.match(status.error?.message ?? "", /safe transfer limit/u);
  assert.equal(harness.sftp.calls.length, 0);
  assert.equal(harness.ssh.calls.length, 0);
});

test("sync overwrite false stops before replacing an existing remote file", async (t) => {
  const events: string[] = [];
  const harness = await createHarness({
    ssh: new FakeSshExecutor(async (input) => {
      assert.equal(isUploadPathProbeCall(input), true);
      events.push("preflight");
      return sshOutcome({ stdout: "SAFE" });
    }),
    sftp: new FakeSftpExecutor(async (input) => {
      events.push(batchText(input).startsWith("@ls ") ? "exists" : "sftp");
      return sftpOutcome();
    }),
  });
  t.after(() => rm(harness.directory, { recursive: true, force: true }));
  await mkdir(path.join(harness.localRoot, "source"));
  await writeFile(path.join(harness.localRoot, "source", "keep.txt"), "new", "utf8");

  const started = harness.service.startSync(
    syncParams({ overwrite: false, resume: false }),
  );
  const status = await waitForTerminal(harness.tasks, started.runId);

  assert.equal(status.state, "failed");
  assert.equal(status.error?.gatewayCode, "TRANSFER_FAILED");
  assert.deepEqual(events, ["preflight", "exists"]);
  assert.equal(
    harness.sftp.calls.some((call) => /^@put /mu.test(batchText(call))),
    false,
  );
});

test("service startup removes abandoned upload staging and download locks", async (t) => {
  const harness = await createHarness();
  t.after(() => rm(harness.directory, { recursive: true, force: true }));
  await Promise.all([
    writeFile(path.join(harness.spoolDirectory, `${"a".repeat(43)}.upload`), "stale"),
    writeFile(
      path.join(harness.spoolDirectory, `${"b".repeat(64)}.download.lock`),
      "stale",
    ),
  ]);
  await writeFile(path.join(harness.localRoot, "payload.bin"), "payload", "utf8");
  const restarted = new TransferService({
    registry: harness.registry,
    taskStore: harness.tasks,
    spoolDirectory: harness.spoolDirectory,
    sftp: harness.sftp as unknown as SftpExecutor,
    ssh: harness.ssh as unknown as SshExecutor,
    audit: harness.audit as unknown as Pick<AuditWriter, "write">,
  });

  const started = restarted.startUpload(uploadParams({ dryRun: true }));
  assert.equal((await waitForTerminal(harness.tasks, started.runId)).state, "succeeded");
  assert.deepEqual(await readdir(harness.spoolDirectory), []);
});
