import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdtemp,
  link,
  mkdir,
  rename,
  rm,
  stat,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";
import { promisify } from "node:util";

import {
  createRuntimeDescriptor,
  hardenPrivatePath,
  loadRuntimeDescriptor,
  runtimeDescriptorPath,
  runtimeLockPath,
  type RuntimeLease,
} from "../../src/daemon/runtime-state.js";

const execFileAsync = promisify(execFile);
const ICACLS = "C:\\Windows\\System32\\icacls.exe";
const POWERSHELL =
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

async function temporaryDirectory(t: TestContext): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "agent-ssh-runtime-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

async function assertMissing(filePath: string): Promise<void> {
  await assert.rejects(stat(filePath), (error: unknown) => {
    return (error as NodeJS.ErrnoException).code === "ENOENT";
  });
}

test(
  "an atomic runtime lease admits only one concurrent creator",
  { timeout: 120_000 },
  async (t) => {
    const dataDirectory = path.join(await temporaryDirectory(t), "data");
    const results = await Promise.allSettled([
      createRuntimeDescriptor(dataDirectory),
      createRuntimeDescriptor(dataDirectory),
    ]);
    const successful = results.filter(
      (result): result is PromiseFulfilledResult<RuntimeLease> =>
        result.status === "fulfilled",
    );
    const rejected = results.filter(
      (result): result is PromiseRejectedResult => result.status === "rejected",
    );

    assert.equal(successful.length, 1);
    assert.equal(rejected.length, 1);
    assert.match(String(rejected[0]!.reason), /already running/u);
    assert.deepEqual(
      await loadRuntimeDescriptor(dataDirectory),
      successful[0]!.value.descriptor,
    );

    await successful[0]!.value.release();
    await assertMissing(runtimeDescriptorPath(dataDirectory));
    await assertMissing(runtimeLockPath(dataDirectory));
  },
);

test(
  "runtime initialization failure releases its lock",
  { timeout: 120_000 },
  async (t) => {
    const dataDirectory = path.join(await temporaryDirectory(t), "data");
    const first = await createRuntimeDescriptor(dataDirectory);
    await first.release();
    await writeFile(runtimeDescriptorPath(dataDirectory), "not-json\n", "utf8");
    await hardenPrivatePath(runtimeDescriptorPath(dataDirectory), false);

    await assert.rejects(
      createRuntimeDescriptor(dataDirectory),
      /Refusing to replace invalid runtime descriptor/u,
    );
    await assertMissing(runtimeLockPath(dataDirectory));

    await unlink(runtimeDescriptorPath(dataDirectory));
    const recovered = await createRuntimeDescriptor(dataDirectory);
    await recovered.release();
  },
);

test(
  "startup recovers cleanup states left without a lock owner",
  { timeout: 120_000 },
  async (t) => {
    const dataDirectory = path.join(await temporaryDirectory(t), "data");
    const interruptedRelease = await createRuntimeDescriptor(dataDirectory);
    await unlink(path.join(runtimeLockPath(dataDirectory), "owner.json"));
    await interruptedRelease.release();

    const afterEmptyLock = await createRuntimeDescriptor(dataDirectory);
    await afterEmptyLock.release();

    await mkdir(runtimeLockPath(dataDirectory));
    await writeFile(
      path.join(runtimeLockPath(dataDirectory), "reclaim.json"),
      `${JSON.stringify({
        version: 1,
        pid: 2_147_483_647,
        ownerToken: Buffer.alloc(32, 9).toString("base64url"),
        createdAt: new Date().toISOString(),
      })}\n`,
      "utf8",
    );
    const afterInterruptedReclaim = await createRuntimeDescriptor(dataDirectory);
    await afterInterruptedReclaim.release();
  },
);

test(
  "an old lease refuses to remove another instance's descriptor or lock",
  { timeout: 120_000 },
  async (t) => {
    const dataDirectory = path.join(await temporaryDirectory(t), "data");
    const first = await createRuntimeDescriptor(dataDirectory);
    const displacedLock = `${runtimeLockPath(dataDirectory)}.displaced`;
    const displacedDescriptor = `${runtimeDescriptorPath(dataDirectory)}.displaced`;
    await rename(runtimeLockPath(dataDirectory), displacedLock);
    await rename(runtimeDescriptorPath(dataDirectory), displacedDescriptor);

    const second = await createRuntimeDescriptor(dataDirectory);
    await assert.rejects(
      first.release(),
      /Runtime cleanup was incomplete/u,
    );
    assert.deepEqual(await loadRuntimeDescriptor(dataDirectory), second.descriptor);
    assert.equal((await stat(runtimeLockPath(dataDirectory))).isDirectory(), true);

    await second.release();
  },
);

interface AclSnapshot {
  readonly protected: boolean;
  readonly owner: string;
  readonly rules: readonly {
    readonly sid: string;
    readonly type: string;
  }[];
}

test(
  "Windows hardening removes inherited and unrelated explicit allow ACEs",
  { skip: process.platform !== "win32", timeout: 30_000 },
  async (t) => {
    const directory = await temporaryDirectory(t);
    const filePath = path.join(directory, "private.txt");
    await writeFile(filePath, "private\n", "utf8");
    const currentSid = await windowsUserSid();
    const junctionTarget = path.join(directory, "junction-target");
    const junctionPath = path.join(directory, "junction");
    await mkdir(junctionTarget);
    await symlink(junctionTarget, junctionPath, "junction");
    await assert.rejects(
      hardenPrivatePath(junctionPath, true),
      /directly referenced directory|reparse point/u,
    );

    for (const [targetPath, isDirectory] of [
      [directory, true],
      [filePath, false],
    ] as const) {
      const everyoneGrant = isDirectory
        ? "*S-1-1-0:(OI)(CI)F"
        : "*S-1-1-0:F";
      const usersGrant = isDirectory
        ? "*S-1-5-32-545:(OI)(CI)F"
        : "*S-1-5-32-545:F";
      await execFileAsync(
        ICACLS,
        [targetPath, "/grant", everyoneGrant, "/grant", usersGrant],
        { windowsHide: true, timeout: 10_000 },
      );

      await hardenPrivatePath(targetPath, isDirectory);
      const snapshot = await readAcl(targetPath);
      assert.equal(snapshot.protected, true);
      assert.equal(snapshot.owner, currentSid);
      assert.deepEqual(
        snapshot.rules,
        [
          { sid: "S-1-5-18", type: "Allow" },
          { sid: currentSid, type: "Allow" },
        ].sort((left, right) => left.sid.localeCompare(right.sid)),
      );
    }

    const hardlinkSource = path.join(directory, "hardlink-source.txt");
    const hardlinkAlias = path.join(directory, "hardlink-alias.txt");
    await writeFile(hardlinkSource, "linked\n", "utf8");
    await link(hardlinkSource, hardlinkAlias);
    await assert.rejects(
      hardenPrivatePath(hardlinkSource, false),
      /single-link regular file/u,
    );
  },
);

async function windowsUserSid(): Promise<string> {
  const { stdout } = await execFileAsync(
    "C:\\Windows\\System32\\whoami.exe",
    ["/user", "/fo", "csv", "/nh"],
    { encoding: "utf8", windowsHide: true, timeout: 5_000 },
  );
  const match = stdout.match(/"(S-[0-9-]+)"\s*$/m);
  assert.ok(match?.[1]);
  return match[1];
}

async function readAcl(targetPath: string): Promise<AclSnapshot> {
  const script = String.raw`
$ErrorActionPreference = "Stop"
$acl = Get-Acl -LiteralPath ([Environment]::GetEnvironmentVariable("AGENT_SSH_ACL_TEST_TARGET", "Process"))
$rules = @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
  [ordered]@{ sid = $_.IdentityReference.Value; type = $_.AccessControlType.ToString() }
})
[ordered]@{
  protected = $acl.AreAccessRulesProtected
  owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  rules = $rules
} | ConvertTo-Json -Compress -Depth 4
`;
  const { stdout } = await execFileAsync(
    POWERSHELL,
    ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
    {
      encoding: "utf8",
      env: { ...process.env, AGENT_SSH_ACL_TEST_TARGET: targetPath },
      windowsHide: true,
      timeout: 10_000,
    },
  );
  const parsed = JSON.parse(stdout) as AclSnapshot;
  return {
    protected: parsed.protected,
    owner: parsed.owner,
    rules: [...parsed.rules].sort((left, right) => left.sid.localeCompare(right.sid)),
  };
}
