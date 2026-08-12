import { randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import path from "node:path";

import { z } from "zod";

import { hardenPrivatePath } from "../daemon/runtime-state.js";

export const ADMIN_DESCRIPTOR_FILENAME = "admin.json";

const UI_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const adminDescriptorSchema = z
  .strictObject({
    version: z.literal(1),
    pid: z.number().int().positive(),
    origin: z.string().min(1).max(256),
    url: z.string().min(1).max(512),
    startedAt: z.string().datetime({ offset: true }),
  })
  .superRefine((descriptor, context) => {
    let origin: URL;
    let url: URL;
    try {
      origin = new URL(descriptor.origin);
      url = new URL(descriptor.url);
    } catch {
      context.addIssue({ code: "custom", message: "admin URL is invalid" });
      return;
    }
    const validOrigin =
      origin.protocol === "http:" &&
      origin.hostname === "127.0.0.1" &&
      origin.username === "" &&
      origin.password === "" &&
      origin.pathname === "/" &&
      origin.search === "" &&
      origin.hash === "";
    const token = url.hash.startsWith("#token=")
      ? url.hash.slice("#token=".length)
      : "";
    if (
      !validOrigin ||
      url.origin !== origin.origin ||
      url.username !== "" ||
      url.password !== "" ||
      url.pathname !== "/" ||
      url.search !== "" ||
      !UI_TOKEN_PATTERN.test(token)
    ) {
      context.addIssue({
        code: "custom",
        message: "admin URL must be a tokenized IPv4 loopback URL",
      });
    }
  });

export type AdminDescriptor = z.infer<typeof adminDescriptorSchema>;

export function adminDescriptorPath(dataDirectory: string): string {
  return path.join(path.resolve(dataDirectory), ADMIN_DESCRIPTOR_FILENAME);
}

export async function readAdminDescriptor(
  dataDirectory: string,
): Promise<AdminDescriptor | undefined> {
  const descriptorPath = adminDescriptorPath(dataDirectory);
  let entry;
  try {
    entry = await lstat(descriptorPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
  if (!entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1) {
    throw new Error("Admin descriptor must be a single-link regular file");
  }
  if (entry.size > 16_384) {
    throw new Error("Admin descriptor is too large");
  }
  const descriptor = adminDescriptorSchema.parse(
    JSON.parse(await readFile(descriptorPath, "utf8")) as unknown,
  );
  return isProcessAlive(descriptor.pid) ? descriptor : undefined;
}

export async function publishAdminDescriptor(
  dataDirectory: string,
  descriptor: AdminDescriptor,
): Promise<void> {
  const validated = adminDescriptorSchema.parse(descriptor);
  const resolvedDirectory = path.resolve(dataDirectory);
  await mkdir(resolvedDirectory, { recursive: true, mode: 0o700 });
  await hardenPrivatePath(resolvedDirectory, true);

  const descriptorPath = adminDescriptorPath(resolvedDirectory);
  const pendingPath = `${descriptorPath}.pending-${process.pid}-${randomBytes(12).toString("hex")}`;
  const handle = await open(
    pendingPath,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
    0o600,
  );
  try {
    await handle.writeFile(`${JSON.stringify(validated)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }

  try {
    await hardenPrivatePath(pendingPath, false);
    await removeReplaceableDescriptor(descriptorPath);
    await rename(pendingPath, descriptorPath);
    await hardenPrivatePath(descriptorPath, false);
  } catch (error) {
    await unlink(pendingPath).catch(() => undefined);
    throw error;
  }
}

export async function removeAdminDescriptor(
  dataDirectory: string,
  expected: Pick<AdminDescriptor, "pid" | "startedAt">,
): Promise<void> {
  const descriptorPath = adminDescriptorPath(dataDirectory);
  let current: AdminDescriptor | undefined;
  try {
    const raw = await readFile(descriptorPath, "utf8");
    current = adminDescriptorSchema.parse(JSON.parse(raw) as unknown);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return;
    }
    throw error;
  }
  if (current.pid !== expected.pid || current.startedAt !== expected.startedAt) {
    throw new Error("Admin descriptor ownership changed; refusing to remove it");
  }
  await unlink(descriptorPath);
}

async function removeReplaceableDescriptor(descriptorPath: string): Promise<void> {
  let entry;
  try {
    entry = await lstat(descriptorPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return;
    }
    throw error;
  }
  if (!entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1) {
    throw new Error("Refusing to replace an unsafe admin descriptor");
  }
  const existing = adminDescriptorSchema.parse(
    JSON.parse(await readFile(descriptorPath, "utf8")) as unknown,
  );
  if (existing.pid !== process.pid && isProcessAlive(existing.pid)) {
    throw new Error(`SSH management service is already running with PID ${existing.pid}`);
  }
  await unlink(descriptorPath);
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}
