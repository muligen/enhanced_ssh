import {
  lstat,
  mkdir,
  readdir,
} from "node:fs/promises";
import path from "node:path";

import {
  hardenPrivatePaths,
  type PrivatePathSpec,
} from "./runtime-state.js";

export interface PreparedRuntimeStorage {
  readonly auditFile: string;
  readonly outputsDirectory: string;
  readonly transfersDirectory: string;
  readonly machineIdentityKeyFile: string;
}

export async function prepareRuntimeStorage(
  dataDirectory: string,
): Promise<PreparedRuntimeStorage> {
  const auditDirectory = path.join(dataDirectory, "audit");
  const auditFile = path.join(auditDirectory, "gateway.jsonl");
  const outputsDirectory = path.join(dataDirectory, "outputs");
  const transfersDirectory = path.join(dataDirectory, "transfers");
  const machineIdentityKeyFile = path.join(dataDirectory, "machine-identity.key");

  await Promise.all([
    mkdir(auditDirectory, { recursive: true, mode: 0o700 }),
    mkdir(outputsDirectory, { recursive: true, mode: 0o700 }),
    mkdir(transfersDirectory, { recursive: true, mode: 0o700 }),
  ]);
  await hardenPrivatePaths([
    { path: auditDirectory, directory: true },
    { path: outputsDirectory, directory: true },
    { path: transfersDirectory, directory: true },
  ]);

  const existingPaths = await existingAuditPaths(auditFile);
  existingPaths.push(...(await existingOutputPaths(outputsDirectory)));
  existingPaths.push(...(await existingTransferPaths(transfersDirectory)));
  await hardenPrivatePaths(existingPaths);

  return {
    auditFile,
    outputsDirectory,
    transfersDirectory,
    machineIdentityKeyFile,
  };
}

async function existingTransferPaths(
  directory: string,
): Promise<PrivatePathSpec[]> {
  const paths: PrivatePathSpec[] = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const entryPath = path.join(directory, entry.name);
    const stats = await lstat(entryPath);
    if (!stats.isFile() || stats.isSymbolicLink()) {
      throw new Error("Transfer staging must contain only regular files");
    }
    paths.push({ path: entryPath, directory: false });
  }
  return paths;
}

async function existingAuditPaths(
  filePath: string,
): Promise<PrivatePathSpec[]> {
  try {
    await lstat(filePath);
    return [{ path: filePath, directory: false }];
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return [];
    }
    throw error;
  }
}

async function existingOutputPaths(
  directory: string,
): Promise<PrivatePathSpec[]> {
  const paths: PrivatePathSpec[] = [];
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    const entryStat = await lstat(entryPath);
    if (entryStat.isSymbolicLink()) {
      throw new Error("Retained output storage must not contain reparse points");
    }
    if (entryStat.isFile()) {
      paths.push({ path: entryPath, directory: false });
      continue;
    }
    if (!entryStat.isDirectory()) {
      throw new Error("Retained output storage contains an unsupported entry type");
    }

    paths.push({ path: entryPath, directory: true });
    const children = await readdir(entryPath, { withFileTypes: true });
    for (const child of children) {
      const childPath = path.join(entryPath, child.name);
      const childStat = await lstat(childPath);
      if (!childStat.isFile() || childStat.isSymbolicLink()) {
        throw new Error(
          "Retained output entries must contain only directly referenced regular files",
        );
      }
      paths.push({ path: childPath, directory: false });
    }
  }
  return paths;
}
