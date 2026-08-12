import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
  rename,
  rmdir,
  unlink,
} from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { z } from "zod/v4";

const execFileAsync = promisify(execFile);
const RUNTIME_FILENAME = "runtime.json";
const RUNTIME_LOCK_DIRECTORY = "runtime.lock";
const RUNTIME_LOCK_OWNER_FILENAME = "owner.json";
const RUNTIME_LOCK_RECLAIM_FILENAME = "reclaim.json";
const WINDOWS_POWERSHELL =
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

const RuntimeLockOwnerSchema = z
  .object({
    version: z.literal(1),
    pid: z.number().int().positive(),
    ownerToken: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    createdAt: z.iso.datetime(),
  })
  .strict();

type RuntimeLockOwner = z.infer<typeof RuntimeLockOwnerSchema>;

interface RuntimeLock {
  release(): Promise<void>;
}

export const RuntimeDescriptorSchema = z
  .object({
    version: z.literal(1),
    pid: z.number().int().positive(),
    endpoint: z.string().min(1).max(512),
    token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    startedAt: z.iso.datetime(),
  })
  .strict();

export type RuntimeDescriptor = z.infer<typeof RuntimeDescriptorSchema>;

export interface RuntimeLease {
  readonly descriptor: RuntimeDescriptor;
  release(): Promise<void>;
}

export function runtimeDescriptorPath(dataDirectory: string): string {
  return path.join(dataDirectory, RUNTIME_FILENAME);
}

export function runtimeLockPath(dataDirectory: string): string {
  return path.join(dataDirectory, RUNTIME_LOCK_DIRECTORY);
}

export async function createRuntimeDescriptor(
  dataDirectory: string,
): Promise<RuntimeLease> {
  await ensurePrivateDirectory(dataDirectory);
  const runtimeLock = await acquireRuntimeLock(dataDirectory);
  let descriptor: RuntimeDescriptor | undefined;

  try {
    const descriptorPath = runtimeDescriptorPath(dataDirectory);
    await rejectLiveDaemonOrRemoveStale(descriptorPath);
    descriptor = await writeRuntimeDescriptor(descriptorPath, dataDirectory);

    let releasePromise: Promise<void> | undefined;
    return {
      descriptor,
      release(): Promise<void> {
        releasePromise ??= releaseRuntimeLease(
          dataDirectory,
          descriptor!,
          runtimeLock,
        );
        return releasePromise;
      },
    };
  } catch (error) {
    const cleanupErrors: unknown[] = [];
    if (descriptor !== undefined) {
      await removeRuntimeDescriptor(dataDirectory, descriptor).catch(
        (cleanupError: unknown) => cleanupErrors.push(cleanupError),
      );
    }
    await runtimeLock
      .release()
      .catch((cleanupError: unknown) => cleanupErrors.push(cleanupError));
    if (cleanupErrors.length > 0) {
      throw new AggregateError(
        [error, ...cleanupErrors],
        "Runtime initialization failed and cleanup was incomplete",
      );
    }
    throw error;
  }
}

export async function loadRuntimeDescriptor(
  dataDirectory: string,
): Promise<RuntimeDescriptor> {
  const descriptorPath = runtimeDescriptorPath(dataDirectory);
  await assertPrivateRuntimePath(dataDirectory, descriptorPath);
  const raw = await readFile(descriptorPath, "utf8");
  return RuntimeDescriptorSchema.parse(JSON.parse(raw) as unknown);
}

export async function removeRuntimeDescriptor(
  dataDirectory: string,
  expected: RuntimeDescriptor,
): Promise<void> {
  const descriptorPath = runtimeDescriptorPath(dataDirectory);
  try {
    const current = await loadRuntimeDescriptor(dataDirectory);
    if (
      current.pid === expected.pid &&
      constantTimeTokenEquals(current.token, expected.token) &&
      current.endpoint === expected.endpoint
    ) {
      await unlink(descriptorPath);
    }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== "ENOENT") {
      throw error;
    }
  }
}

export function constantTimeTokenEquals(left: string, right: string): boolean {
  const leftHash = createHash("sha256").update(left, "utf8").digest();
  const rightHash = createHash("sha256").update(right, "utf8").digest();
  return leftHash.equals(rightHash);
}

async function writeRuntimeDescriptor(
  descriptorPath: string,
  dataDirectory: string,
): Promise<RuntimeDescriptor> {
  const nonce = randomBytes(16).toString("hex");
  const endpoint =
    process.platform === "win32"
      ? `\\\\.\\pipe\\agent-ssh-gateway-${nonce}`
      : path.join(dataDirectory, `gateway-${nonce}.sock`);
  const descriptor: RuntimeDescriptor = {
    version: 1,
    pid: process.pid,
    endpoint,
    token: randomBytes(32).toString("base64url"),
    startedAt: new Date().toISOString(),
  };

  const temporaryPath = `${descriptorPath}.tmp-${process.pid}-${nonce}`;
  const handle = await open(
    temporaryPath,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
    0o600,
  );
  try {
    await handle.writeFile(`${JSON.stringify(descriptor, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }

  let published = false;
  try {
    await hardenPrivatePath(temporaryPath, false);
    await rename(temporaryPath, descriptorPath);
    published = true;
    await hardenPrivatePath(descriptorPath, false);
  } catch (error) {
    await unlink(published ? descriptorPath : temporaryPath).catch(
      () => undefined,
    );
    throw error;
  }

  return descriptor;
}

async function releaseRuntimeLease(
  dataDirectory: string,
  descriptor: RuntimeDescriptor,
  runtimeLock: RuntimeLock,
): Promise<void> {
  const errors: unknown[] = [];
  await removeRuntimeDescriptor(dataDirectory, descriptor).catch(
    (error: unknown) => errors.push(error),
  );
  await runtimeLock.release().catch((error: unknown) => errors.push(error));
  if (errors.length > 0) {
    throw new AggregateError(errors, "Runtime cleanup was incomplete");
  }
}

async function ensurePrivateDirectory(dataDirectory: string): Promise<void> {
  if (!path.isAbsolute(dataDirectory)) {
    throw new Error("runtime.dataDirectory must be an absolute path");
  }
  const nativeResolved = path.resolve(dataDirectory);
  const windowsResolved = path.win32.resolve(dataDirectory);
  if (
    nativeResolved === path.parse(nativeResolved).root ||
    windowsResolved === path.win32.parse(windowsResolved).root
  ) {
    throw new Error("runtime.dataDirectory must not be a filesystem root");
  }
  await mkdir(dataDirectory, { recursive: true, mode: 0o700 });
  await hardenPrivatePath(dataDirectory, true);
}

async function assertPrivateRuntimePath(
  dataDirectory: string,
  descriptorPath: string,
): Promise<void> {
  const directoryStat = await lstat(dataDirectory);
  const fileStat = await lstat(descriptorPath);
  if (
    !directoryStat.isDirectory() ||
    directoryStat.isSymbolicLink() ||
    !fileStat.isFile() ||
    fileStat.isSymbolicLink()
  ) {
    throw new Error("Gateway runtime paths have an unexpected type");
  }

  if (process.platform !== "win32") {
    if ((directoryStat.mode & 0o077) !== 0 || (fileStat.mode & 0o077) !== 0) {
      throw new Error("Gateway runtime paths are accessible by other users");
    }
    if (typeof process.getuid === "function") {
      const uid = process.getuid();
      if (directoryStat.uid !== uid || fileStat.uid !== uid) {
        throw new Error("Gateway runtime paths are not owned by this user");
      }
    }
  }
}

const WINDOWS_ACL_SCRIPT = String.raw`
$ErrorActionPreference = "Stop"
$targetsJson = [Environment]::GetEnvironmentVariable("AGENT_SSH_ACL_TARGETS", "Process")
$userSidValue = [Environment]::GetEnvironmentVariable("AGENT_SSH_ACL_USER_SID", "Process")
$systemSidValue = "S-1-5-18"
$targets = ConvertFrom-Json -InputObject $targetsJson
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
$userSid = [System.Security.Principal.SecurityIdentifier]::new($userSidValue)
$systemSid = [System.Security.Principal.SecurityIdentifier]::new($systemSidValue)

foreach ($target in $targets) {
$targetPath = [string]$target.path
$isDirectory = [bool]$target.directory
$attributes = [System.IO.File]::GetAttributes($targetPath)
if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
  throw "Refusing to harden a reparse point"
}
$actualIsDirectory = ($attributes -band [System.IO.FileAttributes]::Directory) -ne 0
if ($actualIsDirectory -ne $isDirectory) {
  throw "Private path type changed during ACL hardening"
}
$existingAcl = Get-Acl -LiteralPath $targetPath
$existingOwner = $existingAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value

$acl = if ($isDirectory) {
  [System.Security.AccessControl.DirectorySecurity]::new()
} else {
  [System.Security.AccessControl.FileSecurity]::new()
}
$acl.SetAccessRuleProtection($true, $false)

$inheritance = [System.Security.AccessControl.InheritanceFlags]::None
if ($isDirectory) {
  $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
}
$propagation = [System.Security.AccessControl.PropagationFlags]::None
if ($existingOwner -ne $userSidValue) {
  $acl.SetOwner($userSid)
}
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($userSid, $fullControl, $inheritance, $propagation, $allow))
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($systemSid, $fullControl, $inheritance, $propagation, $allow))
if ($isDirectory) {
  [System.IO.Directory]::SetAccessControl($targetPath, $acl)
} else {
  [System.IO.File]::SetAccessControl($targetPath, $acl)
}

$verifiedAcl = Get-Acl -LiteralPath $targetPath
$verifiedAttributes = [System.IO.File]::GetAttributes($targetPath)
if (($verifiedAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
  throw "Private path became a reparse point during ACL hardening"
}
$verifiedIsDirectory = ($verifiedAttributes -band [System.IO.FileAttributes]::Directory) -ne 0
if ($verifiedIsDirectory -ne $isDirectory) {
  throw "Private path type changed during ACL hardening"
}
if (-not $verifiedAcl.AreAccessRulesProtected) {
  throw "ACL inheritance remains enabled"
}
$verifiedOwner = $verifiedAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($verifiedOwner -ne $userSidValue) {
  throw "ACL owner is not the daemon user"
}
$foundUser = $false
$foundSystem = $false
$verifiedRules = @($verifiedAcl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
foreach ($rule in $verifiedRules) {
  $ruleSid = $rule.IdentityReference.Value
  if ($rule.AccessControlType -ne $allow -or ($ruleSid -ne $userSidValue -and $ruleSid -ne $systemSidValue)) {
    throw "Unexpected explicit ACL entry for $ruleSid"
  }
  if (($rule.FileSystemRights -band $fullControl) -ne $fullControl) {
    throw "Explicit ACL entry for $ruleSid does not grant FullControl"
  }
  if ($ruleSid -eq $userSidValue) { $foundUser = $true }
  if ($ruleSid -eq $systemSidValue) { $foundSystem = $true }
}
if (-not $foundUser -or -not $foundSystem) {
  throw "Required explicit ACL entries are missing"
}
}
`;

const MAX_WINDOWS_ACL_BATCH_JSON_CHARS = 12_000;

export interface PrivatePathSpec {
  readonly path: string;
  readonly directory: boolean;
}

export async function hardenPrivatePath(
  targetPath: string,
  directory: boolean,
): Promise<void> {
  return hardenPrivatePaths([{ path: targetPath, directory }]);
}

export async function hardenPrivatePaths(
  paths: readonly PrivatePathSpec[],
): Promise<void> {
  if (paths.length === 0) {
    return;
  }
  const snapshots = await Promise.all(
    paths.map(async (specification) => {
      const entry = await lstat(specification.path);
      assertExpectedPrivatePath(entry, specification.directory);
      return { specification, entry };
    }),
  );

  if (process.platform !== "win32") {
    await Promise.all(
      snapshots.map(({ specification }) =>
        chmod(specification.path, specification.directory ? 0o700 : 0o600),
      ),
    );
    await Promise.all(
      snapshots.map(({ specification, entry }) =>
        assertPrivatePathUnchanged(
          specification.path,
          specification.directory,
          entry.dev,
          entry.ino,
        ),
      ),
    );
    return;
  }

  const sid = await currentWindowsSid();
  for (const batch of aclBatches(paths)) {
    await execFileAsync(
      WINDOWS_POWERSHELL,
      ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_ACL_SCRIPT],
      {
        env: {
          ...process.env,
          AGENT_SSH_ACL_TARGETS: JSON.stringify(batch),
          AGENT_SSH_ACL_USER_SID: sid,
        },
        windowsHide: true,
        timeout: 30_000,
      },
    );
  }
  await Promise.all(
    snapshots.map(({ specification, entry }) =>
      assertPrivatePathUnchanged(
        specification.path,
        specification.directory,
        entry.dev,
        entry.ino,
      ),
    ),
  );
}

function aclBatches(paths: readonly PrivatePathSpec[]): PrivatePathSpec[][] {
  const batches: PrivatePathSpec[][] = [];
  let current: PrivatePathSpec[] = [];
  for (const specification of paths) {
    const candidate = [...current, specification];
    if (
      JSON.stringify(candidate).length > MAX_WINDOWS_ACL_BATCH_JSON_CHARS
    ) {
      if (current.length === 0) {
        throw new Error("Private path is too long for Windows ACL hardening");
      }
      batches.push(current);
      current = [specification];
      if (
        JSON.stringify(current).length > MAX_WINDOWS_ACL_BATCH_JSON_CHARS
      ) {
        throw new Error("Private path is too long for Windows ACL hardening");
      }
    } else {
      current = candidate;
    }
  }
  if (current.length > 0) {
    batches.push(current);
  }
  return batches;
}

function assertExpectedPrivatePath(
  entry: Awaited<ReturnType<typeof lstat>>,
  directory: boolean,
): void {
  const expectedType = directory ? entry.isDirectory() : entry.isFile();
  if (
    !expectedType ||
    entry.isSymbolicLink() ||
    (!directory && entry.nlink !== 1)
  ) {
    throw new Error(
      `Private path must be a directly referenced ${directory ? "directory" : "single-link regular file"}`,
    );
  }
}

async function assertPrivatePathUnchanged(
  targetPath: string,
  directory: boolean,
  expectedDevice: number,
  expectedInode: number,
): Promise<void> {
  const verified = await lstat(targetPath);
  assertExpectedPrivatePath(verified, directory);
  if (verified.dev !== expectedDevice || verified.ino !== expectedInode) {
    throw new Error("Private path changed during ACL hardening");
  }
}

let windowsSidPromise: Promise<string> | undefined;

function currentWindowsSid(): Promise<string> {
  windowsSidPromise ??= resolveCurrentWindowsSid();
  return windowsSidPromise;
}

async function resolveCurrentWindowsSid(): Promise<string> {
  const { stdout } = await execFileAsync(
    "C:\\Windows\\System32\\whoami.exe",
    ["/user", "/fo", "csv", "/nh"],
    { encoding: "utf8", windowsHide: true, timeout: 5_000 },
  );
  const match = stdout.match(/"(S-[0-9-]+)"\s*$/m);
  if (!match?.[1]) {
    throw new Error("Unable to determine the Windows user SID");
  }
  return match[1];
}

async function acquireRuntimeLock(dataDirectory: string): Promise<RuntimeLock> {
  const lockDirectory = runtimeLockPath(dataDirectory);

  for (let attempt = 0; attempt < 4; attempt += 1) {
    const owner: RuntimeLockOwner = {
      version: 1,
      pid: process.pid,
      ownerToken: randomBytes(32).toString("base64url"),
      createdAt: new Date().toISOString(),
    };
    const pendingDirectory = `${lockDirectory}.pending-${process.pid}-${owner.ownerToken}`;
    await createPendingLockDirectory(pendingDirectory, owner);

    try {
      await rename(pendingDirectory, lockDirectory);
      let releasePromise: Promise<void> | undefined;
      return {
        release(): Promise<void> {
          releasePromise ??= removeOwnedLockDirectory(lockDirectory, owner);
          return releasePromise;
        },
      };
    } catch (error) {
      await removeLockDirectory(pendingDirectory).catch(() => undefined);
      const existing = await lstat(lockDirectory).catch(
        (statError: unknown) => {
          if ((statError as NodeJS.ErrnoException).code === "ENOENT") {
            return undefined;
          }
          throw statError;
        },
      );
      if (existing === undefined) {
        if (attempt < 3) {
          continue;
        }
        throw error;
      }
      if (!existing.isDirectory() || existing.isSymbolicLink()) {
        throw new Error(`Refusing to replace invalid runtime lock: ${lockDirectory}`);
      }
      await hardenExistingLock(lockDirectory);
      await rejectLiveLockOrRemoveStale(lockDirectory);
    }
  }

  throw new Error("Unable to acquire the gateway runtime lock");
}

async function hardenExistingLock(lockDirectory: string): Promise<void> {
  try {
    await hardenPrivatePath(lockDirectory, true);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return;
    }
    throw error;
  }
  let entries;
  try {
    entries = await readdir(lockDirectory, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return;
    }
    throw error;
  }
  for (const entry of entries) {
    if (
      entry.name === RUNTIME_LOCK_OWNER_FILENAME ||
      entry.name === RUNTIME_LOCK_RECLAIM_FILENAME
    ) {
      await hardenPrivatePath(path.join(lockDirectory, entry.name), false).catch(
        (error: unknown) => {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
            throw error;
          }
        },
      );
    }
  }
}

async function createPendingLockDirectory(
  pendingDirectory: string,
  owner: RuntimeLockOwner,
): Promise<void> {
  await mkdir(pendingDirectory, { mode: 0o700 });
  try {
    await hardenPrivatePath(pendingDirectory, true);
    await writeExclusiveJson(
      path.join(pendingDirectory, RUNTIME_LOCK_OWNER_FILENAME),
      owner,
    );
  } catch (error) {
    await removeLockDirectory(pendingDirectory).catch(() => undefined);
    throw error;
  }
}

async function writeExclusiveJson(
  filePath: string,
  value: RuntimeLockOwner,
): Promise<void> {
  const handle = await open(
    filePath,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
    0o600,
  );
  try {
    await handle.writeFile(`${JSON.stringify(value)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await hardenPrivatePath(filePath, false);
  } catch (error) {
    await unlink(filePath).catch(() => undefined);
    throw error;
  }
}

async function readRuntimeLockOwner(
  lockDirectory: string,
): Promise<RuntimeLockOwner> {
  const ownerPath = path.join(lockDirectory, RUNTIME_LOCK_OWNER_FILENAME);
  try {
    const ownerStat = await lstat(ownerPath);
    if (!ownerStat.isFile() || ownerStat.isSymbolicLink()) {
      throw new Error("Runtime lock owner has an unexpected type");
    }
    const raw = await readFile(ownerPath, "utf8");
    return RuntimeLockOwnerSchema.parse(JSON.parse(raw) as unknown);
  } catch (error) {
    if (error instanceof SyntaxError || error instanceof z.ZodError) {
      throw new Error(`Refusing to replace invalid runtime lock: ${lockDirectory}`, {
        cause: error,
      });
    }
    throw error;
  }
}

async function rejectLiveLockOrRemoveStale(
  lockDirectory: string,
): Promise<void> {
  let owner: RuntimeLockOwner;
  try {
    owner = await readRuntimeLockOwner(lockDirectory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      await recoverIncompleteLockDirectory(lockDirectory);
      return;
    }
    throw error;
  }
  if (isProcessAlive(owner.pid)) {
    throw new Error(`Gateway daemon is already running with PID ${owner.pid}`);
  }

  const reclaimPath = path.join(
    lockDirectory,
    RUNTIME_LOCK_RECLAIM_FILENAME,
  );
  const claimant: RuntimeLockOwner = {
    version: 1,
    pid: process.pid,
    ownerToken: randomBytes(32).toString("base64url"),
    createdAt: new Date().toISOString(),
  };
  try {
    await writeExclusiveJson(reclaimPath, claimant);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
      throw error;
    }
    const existingClaim = await readOwnedJson(reclaimPath);
    if (isProcessAlive(existingClaim.pid)) {
      throw new Error(
        `Gateway runtime lock is being recovered by PID ${existingClaim.pid}`,
      );
    }
    await removeOwnedFile(reclaimPath, existingClaim);
    await writeExclusiveJson(reclaimPath, claimant);
  }

  try {
    const verifiedOwner = await readRuntimeLockOwner(lockDirectory);
    if (!sameLockOwner(verifiedOwner, owner) || isProcessAlive(verifiedOwner.pid)) {
      throw new Error("Runtime lock ownership changed during stale recovery");
    }
    await unlink(path.join(lockDirectory, RUNTIME_LOCK_OWNER_FILENAME));
    await removeOwnedFile(reclaimPath, claimant);
    await rmdir(lockDirectory).catch((error: unknown) => {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
    });
  } catch (error) {
    await removeOwnedFile(reclaimPath, claimant).catch(() => undefined);
    throw error;
  }
}

async function removeOwnedLockDirectory(
  lockDirectory: string,
  expected: RuntimeLockOwner,
): Promise<void> {
  let current: RuntimeLockOwner;
  try {
    current = await readRuntimeLockOwner(lockDirectory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return;
    }
    throw error;
  }
  if (!sameLockOwner(current, expected)) {
    throw new Error("Runtime lock ownership changed; refusing to remove it");
  }
  await unlink(path.join(lockDirectory, RUNTIME_LOCK_OWNER_FILENAME));
  await rmdir(lockDirectory).catch((error: unknown) => {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  });
}

async function recoverIncompleteLockDirectory(
  lockDirectory: string,
): Promise<void> {
  let entries;
  try {
    entries = await readdir(lockDirectory, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return;
    }
    throw error;
  }

  if (entries.length === 0) {
    await removeIncompleteLockDirectory(lockDirectory);
    return;
  }
  const onlyEntry = entries.length === 1 ? entries[0] : undefined;
  if (
    onlyEntry?.name !== RUNTIME_LOCK_RECLAIM_FILENAME ||
    !onlyEntry.isFile() ||
    onlyEntry.isSymbolicLink()
  ) {
    throw new Error(`Refusing to replace invalid runtime lock: ${lockDirectory}`);
  }

  const reclaimPath = path.join(
    lockDirectory,
    RUNTIME_LOCK_RECLAIM_FILENAME,
  );
  let claimant: RuntimeLockOwner;
  try {
    claimant = await readOwnedJson(reclaimPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      await removeIncompleteLockDirectory(lockDirectory);
      return;
    }
    throw new Error(`Refusing to replace invalid runtime lock: ${lockDirectory}`, {
      cause: error,
    });
  }
  if (isProcessAlive(claimant.pid)) {
    throw new Error(
      `Gateway runtime lock is being recovered by PID ${claimant.pid}`,
    );
  }
  await removeOwnedFile(reclaimPath, claimant).catch((error: unknown) => {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  });
  await removeIncompleteLockDirectory(lockDirectory);
}

async function removeIncompleteLockDirectory(
  lockDirectory: string,
): Promise<void> {
  await rmdir(lockDirectory).catch((error: unknown) => {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== "ENOENT" && code !== "ENOTEMPTY" && code !== "EEXIST") {
      throw error;
    }
  });
}

async function readOwnedJson(filePath: string): Promise<RuntimeLockOwner> {
  const raw = await readFile(filePath, "utf8");
  return RuntimeLockOwnerSchema.parse(JSON.parse(raw) as unknown);
}

async function removeOwnedFile(
  filePath: string,
  expected: RuntimeLockOwner,
): Promise<void> {
  const current = await readOwnedJson(filePath);
  if (!sameLockOwner(current, expected)) {
    throw new Error("Runtime lock helper ownership changed; refusing to remove it");
  }
  await unlink(filePath);
}

async function removeLockDirectory(lockDirectory: string): Promise<void> {
  await unlink(path.join(lockDirectory, RUNTIME_LOCK_OWNER_FILENAME)).catch(
    (error: unknown) => {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
    },
  );
  await rmdir(lockDirectory);
}

function sameLockOwner(
  left: RuntimeLockOwner,
  right: RuntimeLockOwner,
): boolean {
  return (
    left.version === right.version &&
    left.pid === right.pid &&
    constantTimeTokenEquals(left.ownerToken, right.ownerToken) &&
    left.createdAt === right.createdAt
  );
}

async function rejectLiveDaemonOrRemoveStale(
  descriptorPath: string,
): Promise<void> {
  try {
    const raw = await readFile(descriptorPath, "utf8");
    const current = RuntimeDescriptorSchema.parse(JSON.parse(raw) as unknown);
    if (isProcessAlive(current.pid)) {
      throw new Error(`Gateway daemon is already running with PID ${current.pid}`);
    }
    await unlink(descriptorPath);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      return;
    }
    if (error instanceof SyntaxError || error instanceof z.ZodError) {
      throw new Error(
        `Refusing to replace invalid runtime descriptor: ${descriptorPath}`,
        { cause: error },
      );
    }
    throw error;
  }
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}
