import { createHmac, randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, unlink } from "node:fs/promises";
import path from "node:path";

import { hardenPrivatePath } from "../daemon/runtime-state.js";
import type { FixedProbePlatform } from "./fixed-probe.js";

export const MACHINE_IDENTITY_KEY_BYTES = 32;
export const MACHINE_ID_PREFIX = "mid_" as const;
export const MACHINE_ID_PATTERN = /^mid_[A-Za-z0-9_-]{43}$/;

const MACHINE_ID_HMAC_CONTEXT = "agent-ssh-machine-id-v1\0";

export class MachineIdentityKeyStore {
  #key: Buffer | undefined;

  private constructor(key: Buffer) {
    this.#key = Buffer.from(key);
  }

  public static async open(filePath: string): Promise<MachineIdentityKeyStore> {
    return new MachineIdentityKeyStore(await loadOrCreateMachineIdentityKey(filePath));
  }

  public derive(platform: FixedProbePlatform, nativeMachineId: string): string {
    const key = this.#key;
    if (key === undefined) {
      throw new Error("Machine identity key store is closed");
    }
    return deriveMachineId(key, platform, nativeMachineId);
  }

  public close(): void {
    this.#key?.fill(0);
    this.#key = undefined;
  }
}

export function openMachineIdentityKey(filePath: string): Promise<MachineIdentityKeyStore> {
  return MachineIdentityKeyStore.open(filePath);
}

export async function loadOrCreateMachineIdentityKey(filePath: string): Promise<Buffer> {
  assertAbsoluteKeyPath(filePath);
  let created = false;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(
      filePath,
      fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
      0o600,
    );
    created = true;
    const key = randomBytes(MACHINE_IDENTITY_KEY_BYTES);
    try {
      await handle.writeFile(key);
      await handle.sync();
    } finally {
      key.fill(0);
    }
  } catch (error) {
    if (!isNodeError(error, "EEXIST")) {
      await handle?.close().catch(() => undefined);
      handle = undefined;
      if (created) {
        await unlink(filePath).catch(() => undefined);
      }
      throw error;
    }
  } finally {
    await handle?.close();
  }

  if (created) {
    try {
      await hardenPrivatePath(filePath, false);
    } catch (error) {
      await unlink(filePath).catch(() => undefined);
      throw error;
    }
  }
  return readValidatedIdentityKey(filePath);
}

export function deriveMachineId(
  key: Uint8Array,
  platform: FixedProbePlatform,
  nativeMachineId: string,
): string {
  if (key.byteLength !== MACHINE_IDENTITY_KEY_BYTES) {
    throw new RangeError("Machine identity key must contain exactly 32 bytes");
  }
  const normalized = normalizeNativeMachineId(platform, nativeMachineId);
  const digest = createHmac("sha256", key)
    .update(MACHINE_ID_HMAC_CONTEXT, "utf8")
    .update(platform, "utf8")
    .update("\0", "utf8")
    .update(normalized, "ascii")
    .digest("base64url");
  return `${MACHINE_ID_PREFIX}${digest}`;
}

export function normalizeNativeMachineId(
  platform: FixedProbePlatform,
  nativeMachineId: string,
): string {
  const normalized = nativeMachineId.toLowerCase();
  const valid =
    platform === "linux"
      ? /^[0-9a-f]{32}$/u.test(normalized)
      : platform === "windows" || platform === "macos"
        ? /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(
            normalized,
          )
        : false;
  if (!valid || /^0+(?:-0+)*$/u.test(normalized)) {
    throw new TypeError("Remote platform returned an invalid native machine identifier");
  }
  return normalized;
}

async function readValidatedIdentityKey(filePath: string): Promise<Buffer> {
  const before = await lstat(filePath);
  assertKeyFile(before);
  await hardenPrivatePath(filePath, false);
  const flags =
    process.platform === "win32" || fsConstants.O_NOFOLLOW === undefined
      ? fsConstants.O_RDONLY
      : fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW;
  const handle = await open(filePath, flags);
  try {
    const opened = await handle.stat();
    assertKeyFile(opened);
    if (opened.dev !== before.dev || opened.ino !== before.ino) {
      throw new Error("Machine identity key changed while it was being opened");
    }
    const key = Buffer.alloc(MACHINE_IDENTITY_KEY_BYTES);
    let offset = 0;
    while (offset < key.length) {
      const { bytesRead } = await handle.read(key, offset, key.length - offset, offset);
      if (bytesRead === 0) {
        key.fill(0);
        throw new Error("Machine identity key is incomplete");
      }
      offset += bytesRead;
    }
    const after = await lstat(filePath);
    assertKeyFile(after);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size) {
      key.fill(0);
      throw new Error("Machine identity key changed while it was being read");
    }
    return key;
  } finally {
    await handle.close();
  }
}

function assertAbsoluteKeyPath(filePath: string): void {
  if (!path.isAbsolute(filePath) || filePath === path.parse(filePath).root) {
    throw new TypeError("Machine identity key path must be an absolute file path");
  }
}

function assertKeyFile(entry: Awaited<ReturnType<typeof lstat>>): void {
  if (
    !entry.isFile() ||
    entry.isSymbolicLink() ||
    entry.nlink !== 1 ||
    entry.size !== MACHINE_IDENTITY_KEY_BYTES
  ) {
    throw new Error("Machine identity key must be a single-link 32-byte regular file");
  }
}

function isNodeError(error: unknown, code: string): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error && error.code === code;
}
