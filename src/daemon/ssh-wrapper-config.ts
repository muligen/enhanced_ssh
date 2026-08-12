import { randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, readdir, unlink } from "node:fs/promises";
import path from "node:path";

import { hardenPrivatePath } from "./runtime-state.js";

export interface GeneratedSshConfig {
  readonly path: string;
  remove(): Promise<void>;
}

const SSH_WRAPPER_CONFIG_NAME_PATTERN =
  /^\.ssh-wrapper-([1-9][0-9]{0,9})-[a-f0-9]{32}\.conf$/u;
const MAX_PROCESS_ID = 2_147_483_647;

export interface SshWrapperCleanupOptions {
  readonly isProcessAlive?: (pid: number) => boolean;
}

export async function cleanupOrphanedSshWrapperConfigs(
  dataDirectory: string,
  options: SshWrapperCleanupOptions = {},
): Promise<number> {
  const runtimeDirectory = path.resolve(dataDirectory);
  const isProcessAlive = options.isProcessAlive ?? processIsAlive;
  let entries;
  try {
    entries = await readdir(runtimeDirectory, { withFileTypes: true });
  } catch (error) {
    throw new Error("Unable to inspect managed SSH wrapper configuration storage", {
      cause: error,
    });
  }

  let removed = 0;
  for (const entry of entries) {
    const match = SSH_WRAPPER_CONFIG_NAME_PATTERN.exec(entry.name);
    if (match === null || !entry.isFile() || entry.isSymbolicLink()) {
      continue;
    }
    const ownerPid = Number(match[1]);
    if (
      !Number.isSafeInteger(ownerPid) ||
      ownerPid < 1 ||
      ownerPid > MAX_PROCESS_ID ||
      ownerPid === process.pid ||
      probeProcessAlive(ownerPid, isProcessAlive)
    ) {
      continue;
    }

    const wrapperPath = path.resolve(runtimeDirectory, entry.name);
    if (path.dirname(wrapperPath) !== runtimeDirectory) {
      continue;
    }
    const initial = await inspectCleanupCandidate(wrapperPath);
    if (initial === undefined) {
      continue;
    }
    if (probeProcessAlive(ownerPid, isProcessAlive)) {
      continue;
    }
    const verified = await inspectCleanupCandidate(wrapperPath);
    if (verified === undefined || !sameFileIdentity(initial, verified)) {
      continue;
    }
    if (probeProcessAlive(ownerPid, isProcessAlive)) {
      continue;
    }

    try {
      await unlink(wrapperPath);
      removed += 1;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        continue;
      }
      throw new Error("Unable to remove an orphaned SSH wrapper configuration", {
        cause: error,
      });
    }
  }
  return removed;
}

async function inspectCleanupCandidate(
  wrapperPath: string,
): Promise<Awaited<ReturnType<typeof lstat>> | undefined> {
  try {
    const entry = await lstat(wrapperPath);
    if (
      !entry.isFile() ||
      entry.isSymbolicLink() ||
      entry.nlink !== 1
    ) {
      return undefined;
    }
    return entry;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return undefined;
    }
    throw new Error("Unable to verify an orphaned SSH wrapper configuration", {
      cause: error,
    });
  }
}

function sameFileIdentity(
  left: Awaited<ReturnType<typeof lstat>>,
  right: Awaited<ReturnType<typeof lstat>>,
): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.birthtimeMs === right.birthtimeMs &&
    left.mtimeMs === right.mtimeMs
  );
}

function probeProcessAlive(
  pid: number,
  isProcessAlive: (pid: number) => boolean,
): boolean {
  try {
    return isProcessAlive(pid);
  } catch (error) {
    throw new Error("Unable to verify an SSH wrapper owner process", {
      cause: error,
    });
  }
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

export async function createSshWrapperConfig(
  dataDirectory: string,
  administratorConfigPath: string,
  knownHostsPath: string,
  connectTimeoutSeconds: number,
): Promise<GeneratedSshConfig> {
  const nonce = randomBytes(16).toString("hex");
  const wrapperPath = path.join(
    dataDirectory,
    ".ssh-wrapper-" + process.pid + "-" + nonce + ".conf",
  );
  const handle = await open(
    wrapperPath,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
    0o600,
  );
  try {
    await handle.writeFile(
      renderSshWrapperConfig(
        administratorConfigPath,
        knownHostsPath,
        connectTimeoutSeconds,
      ),
      "utf8",
    );
    await handle.sync();
  } catch (error) {
    await handle.close().catch(() => undefined);
    await unlink(wrapperPath).catch(() => undefined);
    throw error;
  }
  await handle.close();

  try {
    await hardenPrivatePath(wrapperPath, false);
  } catch (error) {
    await unlink(wrapperPath).catch(() => undefined);
    throw error;
  }

  let removed = false;
  let removalOperation: Promise<void> | undefined;
  return {
    path: wrapperPath,
    remove(): Promise<void> {
      if (removed) {
        return Promise.resolve();
      }
      if (removalOperation === undefined) {
        const operation = unlink(wrapperPath)
          .catch((error: NodeJS.ErrnoException) => {
            if (error.code !== "ENOENT") {
              throw error;
            }
          })
          .then(() => {
            removed = true;
          });
        removalOperation = operation;
        const clearOperation = (): void => {
          if (removalOperation === operation) {
            removalOperation = undefined;
          }
        };
        void operation.then(clearOperation, clearOperation);
      }
      return removalOperation;
    },
  };
}

export function renderSshWrapperConfig(
  administratorConfigPath: string,
  knownHostsPath: string,
  connectTimeoutSeconds: number,
): string {
  if (
    !Number.isSafeInteger(connectTimeoutSeconds) ||
    connectTimeoutSeconds < 1 ||
    connectTimeoutSeconds > 120
  ) {
    throw new RangeError("connectTimeoutSeconds must be an integer from 1 to 120");
  }

  return [
    "# Generated by Agent SSH Gateway. Do not edit.",
    "Host *",
    "    BatchMode yes",
    "    NumberOfPasswordPrompts 0",
    "    ConnectionAttempts 1",
    "    ConnectTimeout " + connectTimeoutSeconds,
    "    StrictHostKeyChecking yes",
    "    UserKnownHostsFile " + quoteConfigPath(knownHostsPath),
    "    GlobalKnownHostsFile none",
    "    KnownHostsCommand none",
    "    VerifyHostKeyDNS no",
    "    ClearAllForwardings yes",
    "    PermitLocalCommand no",
    "    ForwardAgent no",
    "    ForwardX11 no",
    "    ForkAfterAuthentication no",
    "    RequestTTY no",
    "    SessionType default",
    "    RemoteCommand none",
    "    AddKeysToAgent no",
    "    ControlMaster no",
    "    ControlPersist no",
    "    ControlPath none",
    "    EscapeChar none",
    "    EnableEscapeCommandline no",
    "    UpdateHostKeys no",
    "Include " + quoteConfigPath(administratorConfigPath),
    "",
  ].join("\n");
}

function quoteConfigPath(value: string): string {
  if (!path.isAbsolute(value) && !path.win32.isAbsolute(value)) {
    throw new TypeError("SSH configuration paths must be absolute");
  }
  if (/[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError("SSH configuration paths must not contain control characters");
  }
  if (value.includes("$")) {
    throw new TypeError(
      "SSH configuration paths must not contain OpenSSH environment expansions",
    );
  }
  return (
    '"' +
    value
      .replaceAll("\\", "/")
      .replaceAll('"', '\\"')
      .replaceAll("%", "%%") +
    '"'
  );
}
