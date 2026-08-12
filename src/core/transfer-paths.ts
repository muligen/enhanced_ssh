import type { Stats } from "node:fs";
import { lstat, realpath } from "node:fs/promises";
import path from "node:path";

import { MAX_MANAGED_STDIN_BYTES } from "../infra/process-tree.js";
import type { TargetPlatform } from "../shared/protocol.js";

export const MAX_TRANSFER_PATH_BYTES = 4_096;

export type TransferPathErrorCode =
  | "INVALID_PATH"
  | "PATH_NOT_FOUND"
  | "OUTSIDE_ROOT"
  | "UNSAFE_LINK"
  | "UNSAFE_FILE_TYPE"
  | "WRONG_ENTRY_TYPE";

export class TransferPathError extends Error {
  public readonly code: TransferPathErrorCode;
  public override readonly cause: unknown;

  public constructor(
    code: TransferPathErrorCode,
    message: string,
    options?: { readonly cause?: unknown },
  ) {
    super(message);
    this.name = "TransferPathError";
    this.code = code;
    this.cause = options?.cause;
  }
}

export type LocalTransferEntryKind = "file" | "directory";

export interface ResolvedLocalTransferPath {
  readonly rootPath: string;
  readonly absolutePath: string;
  readonly relativePath: string;
  readonly exists: boolean;
  readonly kind?: LocalTransferEntryKind;
  readonly size?: number;
}

export interface UnrestrictedLocalTransferPath {
  readonly rootPath: string;
  readonly relativePath: string;
}

/**
 * Validates a source path at one point in time. Callers that pass the result to
 * another process must first stage the source in private storage to close the
 * unavoidable path-based TOCTOU window.
 */
export async function resolveLocalTransferSource(
  rootDirectory: string,
  relativePath: string,
  expectedKind: LocalTransferEntryKind = "file",
): Promise<ResolvedLocalTransferPath> {
  return resolveLocalTransferPath(
    rootDirectory,
    relativePath,
    expectedKind,
    true,
  );
}

export async function resolveLocalTransferDestination(
  rootDirectory: string,
  relativePath: string,
  expectedKind: LocalTransferEntryKind = "file",
): Promise<ResolvedLocalTransferPath> {
  return resolveLocalTransferPath(
    rootDirectory,
    relativePath,
    expectedKind,
    false,
  );
}

export function normalizeLocalTransferRelativePath(value: string): string {
  validatePathText(value);
  if (
    path.isAbsolute(value) ||
    path.win32.isAbsolute(value) ||
    value.startsWith("\\\\") ||
    value.startsWith("//")
  ) {
    throw invalidPath("Local transfer paths must be relative to a configured root");
  }

  if (value === ".") {
    return ".";
  }
  const segments = value.split(/[\\/]+/u).filter((segment) => segment.length > 0);
  if (segments.length === 0) {
    throw invalidPath("Local transfer path must not be empty");
  }
  for (const segment of segments) {
    if (segment === "." || segment === "..") {
      throw invalidPath("Local transfer path must not contain traversal segments");
    }
    if (process.platform === "win32") {
      validateWindowsSegment(segment);
    }
  }
  return segments.join("/");
}

export function splitUnrestrictedLocalTransferPath(
  value: string,
): UnrestrictedLocalTransferPath {
  validatePathText(value);
  if (
    !path.isAbsolute(value) ||
    (process.platform === "win32" && !/^[A-Za-z]:[\\/]/u.test(value))
  ) {
    throw invalidPath("Full access local transfer paths must be absolute");
  }
  if (value.startsWith("\\\\") || value.startsWith("//")) {
    throw invalidPath("Full access local transfer paths must not use network or device syntax");
  }

  const absolutePath = path.resolve(value);
  const rootPath = path.parse(absolutePath).root;
  if (rootPath.length === 0) {
    throw invalidPath("Full access local transfer path has no filesystem root");
  }
  const relative = path.relative(rootPath, absolutePath);
  return {
    rootPath,
    relativePath:
      relative.length === 0
        ? "."
        : normalizeLocalTransferRelativePath(relative),
  };
}

export function normalizeRemoteTransferPath(
  platform: TargetPlatform,
  value: string,
): string {
  validatePathText(value);
  if (platform === "windows") {
    return normalizeWindowsRemotePath(value);
  }
  if (!value.startsWith("/") || value.startsWith("//")) {
    throw invalidPath("Remote POSIX paths must be absolute");
  }
  const segments = value.split("/").filter((segment) => segment.length > 0);
  for (const segment of segments) {
    if (segment === "." || segment === "..") {
      throw invalidPath("Remote path must not contain traversal segments");
    }
  }
  return segments.length === 0 ? "/" : `/${segments.join("/")}`;
}

export function quoteSftpBatchPath(value: string): string {
  validatePathText(value);
  const escaped = value.replace(/[\\"*?\[\]]/gu, (character) => `\\${character}`);
  return `"${escaped}"`;
}

export type SftpBatchCommand =
  | Readonly<{
      operation: "get" | "reget";
      remotePath: string;
      localPath: string;
    }>
  | Readonly<{
      operation: "put" | "reput";
      localPath: string;
      remotePath: string;
    }>
  | Readonly<{
      operation: "mkdir" | "rm" | "rmdir";
      remotePath: string;
      ignoreFailure?: boolean;
    }>
  | Readonly<{
      operation: "rename";
      sourceRemotePath: string;
      destinationRemotePath: string;
    }>;

export function buildSftpBatch(
  commands: readonly SftpBatchCommand[],
): Buffer {
  if (commands.length === 0 || commands.length > 4_096) {
    throw new RangeError("SFTP batch must contain from 1 through 4096 commands");
  }
  const lines = commands.map((command) => renderSftpBatchCommand(command));
  lines.push("@quit");
  const batch = Buffer.from(`${lines.join("\n")}\n`, "utf8");
  if (batch.byteLength > MAX_MANAGED_STDIN_BYTES) {
    throw new RangeError(
      `SFTP batch must not exceed ${MAX_MANAGED_STDIN_BYTES} bytes`,
    );
  }
  return batch;
}

async function resolveLocalTransferPath(
  rootDirectory: string,
  relativeInput: string,
  expectedKind: LocalTransferEntryKind,
  mustExist: boolean,
): Promise<ResolvedLocalTransferPath> {
  validateLocalRoot(rootDirectory);
  const normalizedRelative = normalizeLocalTransferRelativePath(relativeInput);
  const rootLexical = path.resolve(rootDirectory);
  const rootEntry = await safeLstat(rootLexical, "PATH_NOT_FOUND");
  if (rootEntry.isSymbolicLink()) {
    throw new TransferPathError(
      "UNSAFE_LINK",
      "Configured local transfer root must not be a symbolic link or reparse point",
    );
  }
  if (!rootEntry.isDirectory()) {
    throw new TransferPathError(
      "UNSAFE_FILE_TYPE",
      "Configured local transfer root must be a directory",
    );
  }

  const canonicalRoot = await realpath(rootLexical).catch((error: unknown) => {
    throw new TransferPathError(
      "PATH_NOT_FOUND",
      "Configured local transfer root could not be resolved",
      { cause: error },
    );
  });
  const canonicalRootEntry = await safeLstat(canonicalRoot, "PATH_NOT_FOUND");
  if (canonicalRootEntry.isSymbolicLink() || !canonicalRootEntry.isDirectory()) {
    throw new TransferPathError(
      "UNSAFE_LINK",
      "Configured local transfer root did not resolve to a direct directory",
    );
  }
  const segments = normalizedRelative === "." ? [] : normalizedRelative.split("/");
  const candidate = path.resolve(canonicalRoot, ...segments);
  assertContained(canonicalRoot, candidate);

  let current = canonicalRoot;
  let leafEntry: Stats | undefined;
  let missing = false;
  for (const [index, segment] of segments.entries()) {
    current = path.join(current, segment);
    if (missing) {
      continue;
    }
    try {
      leafEntry = await lstat(current);
    } catch (error: unknown) {
      if (isNotFound(error)) {
        missing = true;
        leafEntry = undefined;
        continue;
      }
      throw new TransferPathError(
        "UNSAFE_FILE_TYPE",
        "Local transfer path could not be inspected safely",
        { cause: error },
      );
    }
    if (leafEntry.isSymbolicLink()) {
      throw new TransferPathError(
        "UNSAFE_LINK",
        "Local transfer path must not contain symbolic links or reparse points",
      );
    }
    if (index < segments.length - 1 && !leafEntry.isDirectory()) {
      throw new TransferPathError(
        "UNSAFE_FILE_TYPE",
        "Local transfer path contains a non-directory ancestor",
      );
    }
  }

  if (segments.length === 0) {
    leafEntry = rootEntry;
  }
  if (missing) {
    if (mustExist) {
      throw new TransferPathError(
        "PATH_NOT_FOUND",
        "Local transfer source was not found",
      );
    }
    return {
      rootPath: canonicalRoot,
      absolutePath: candidate,
      relativePath: normalizedRelative,
      exists: false,
    };
  }

  if (leafEntry === undefined) {
    throw new TransferPathError(
      "UNSAFE_FILE_TYPE",
      "Local transfer path could not be inspected safely",
    );
  }
  const kind = classifyEntry(leafEntry);
  if (kind !== expectedKind) {
    throw new TransferPathError(
      "WRONG_ENTRY_TYPE",
      `Local transfer path must resolve to a ${expectedKind}`,
    );
  }
  const canonicalCandidate = await realpath(candidate).catch((error: unknown) => {
    throw new TransferPathError(
      "PATH_NOT_FOUND",
      "Local transfer path could not be resolved",
      { cause: error },
    );
  });
  assertContained(canonicalRoot, canonicalCandidate);
  const finalEntry = await safeLstat(canonicalCandidate, "PATH_NOT_FOUND");
  if (finalEntry.isSymbolicLink()) {
    throw new TransferPathError(
      "UNSAFE_LINK",
      "Local transfer path must not resolve through a symbolic link",
    );
  }
  const finalKind = classifyEntry(finalEntry);
  if (finalKind !== expectedKind) {
    throw new TransferPathError(
      "WRONG_ENTRY_TYPE",
      `Local transfer path must resolve to a ${expectedKind}`,
    );
  }
  if (
    finalKind === "file" &&
    (!Number.isSafeInteger(finalEntry.size) || finalEntry.size < 0)
  ) {
    throw new TransferPathError(
      "UNSAFE_FILE_TYPE",
      "Local transfer file size cannot be represented safely",
    );
  }
  return {
    rootPath: canonicalRoot,
    absolutePath: canonicalCandidate,
    relativePath: normalizedRelative,
    exists: true,
    kind: finalKind,
    ...(finalKind === "file" ? { size: finalEntry.size } : {}),
  };
}

function renderSftpBatchCommand(command: SftpBatchCommand): string {
  switch (command.operation) {
    case "get":
    case "reget":
      requireAbsoluteRemoteBatchPath(command.remotePath);
      requireAbsoluteLocalBatchPath(command.localPath);
      return `@${command.operation} ${quoteSftpBatchPath(command.remotePath)} ${quoteSftpBatchPath(command.localPath)}`;
    case "put":
    case "reput":
      requireAbsoluteLocalBatchPath(command.localPath);
      requireAbsoluteRemoteBatchPath(command.remotePath);
      return `@${command.operation} ${quoteSftpBatchPath(command.localPath)} ${quoteSftpBatchPath(command.remotePath)}`;
    case "mkdir":
    case "rm":
    case "rmdir":
      requireAbsoluteRemoteBatchPath(command.remotePath);
      return `${command.ignoreFailure === true ? "-@" : "@"}${command.operation} ${quoteSftpBatchPath(command.remotePath)}`;
    case "rename":
      requireAbsoluteRemoteBatchPath(command.sourceRemotePath);
      requireAbsoluteRemoteBatchPath(command.destinationRemotePath);
      return `@rename ${quoteSftpBatchPath(command.sourceRemotePath)} ${quoteSftpBatchPath(command.destinationRemotePath)}`;
  }
}

function normalizeWindowsRemotePath(value: string): string {
  if (
    value.startsWith("\\\\") ||
    value.startsWith("//") ||
    value.startsWith("\\\\?\\") ||
    value.startsWith("\\\\.\\")
  ) {
    throw invalidPath("Remote Windows paths must not use UNC or device syntax");
  }
  const match = /^([A-Za-z]):[\\/](.*)$/u.exec(value);
  if (match === null) {
    throw invalidPath("Remote Windows paths must be drive-absolute");
  }
  const drive = match[1]?.toUpperCase();
  const rest = match[2] ?? "";
  if (drive === undefined) {
    throw invalidPath("Remote Windows path has an invalid drive");
  }
  const segments = rest.split(/[\\/]+/u).filter((segment) => segment.length > 0);
  for (const segment of segments) {
    if (segment === "." || segment === "..") {
      throw invalidPath("Remote path must not contain traversal segments");
    }
    validateWindowsSegment(segment);
  }
  return segments.length === 0
    ? `${drive}:/`
    : `${drive}:/${segments.join("/")}`;
}

function validateWindowsSegment(segment: string): void {
  if (
    /[<>:"|?*]/u.test(segment) ||
    segment.endsWith(".") ||
    segment.endsWith(" ")
  ) {
    throw invalidPath("Windows path contains an invalid segment");
  }
  const deviceName = segment.split(".", 1)[0]?.toUpperCase();
  if (
    deviceName !== undefined &&
    /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/u.test(deviceName)
  ) {
    throw invalidPath("Windows path contains a reserved device name");
  }
}

function validateLocalRoot(value: string): void {
  if (!path.isAbsolute(value)) {
    throw invalidPath("Configured local transfer root must be absolute");
  }
  validatePathText(value);
}

function validatePathText(value: string): void {
  if (
    value.length === 0 ||
    Buffer.byteLength(value, "utf8") > MAX_TRANSFER_PATH_BYTES ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw invalidPath(
      `Transfer path must be non-empty, valid text of at most ${MAX_TRANSFER_PATH_BYTES} UTF-8 bytes`,
    );
  }
}

function assertContained(root: string, candidate: string): void {
  const relative = path.relative(root, candidate);
  if (
    relative === "" ||
    (!path.isAbsolute(relative) &&
      relative !== ".." &&
      !relative.startsWith(`..${path.sep}`))
  ) {
    return;
  }
  throw new TransferPathError(
    "OUTSIDE_ROOT",
    "Local transfer path escapes its configured root",
  );
}

function classifyEntry(entry: Stats): LocalTransferEntryKind {
  if (entry.isFile()) {
    return "file";
  }
  if (entry.isDirectory()) {
    return "directory";
  }
  throw new TransferPathError(
    "UNSAFE_FILE_TYPE",
    "Local transfer path must be a regular file or directory",
  );
}

async function safeLstat(
  value: string,
  notFoundCode: TransferPathErrorCode,
): Promise<Stats> {
  try {
    return await lstat(value);
  } catch (error: unknown) {
    if (isNotFound(error)) {
      throw new TransferPathError(
        notFoundCode,
        "Local transfer path was not found",
        { cause: error },
      );
    }
    throw new TransferPathError(
      "UNSAFE_FILE_TYPE",
      "Local transfer path could not be inspected safely",
      { cause: error },
    );
  }
}

function requireAbsoluteLocalBatchPath(value: string): void {
  validatePathText(value);
  if (!path.isAbsolute(value) && !path.win32.isAbsolute(value)) {
    throw invalidPath("SFTP local batch paths must be absolute");
  }
}

function requireAbsoluteRemoteBatchPath(value: string): void {
  validatePathText(value);
  let normalized: string;
  if (value.startsWith("/")) {
    normalized = normalizeRemoteTransferPath("linux", value);
  } else if (/^[A-Za-z]:\//u.test(value)) {
    normalized = normalizeRemoteTransferPath("windows", value);
  } else {
    throw invalidPath("SFTP remote batch paths must be normalized and absolute");
  }
  if (normalized !== value) {
    throw invalidPath("SFTP remote batch paths must use their canonical form");
  }
}

function isNotFound(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}

function invalidPath(message: string): TransferPathError {
  return new TransferPathError("INVALID_PATH", message);
}
