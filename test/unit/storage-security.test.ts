import assert from "node:assert/strict";
import {
  chmod,
  lstat,
  link,
  mkdir,
  mkdtemp,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { prepareRuntimeStorage } from "../../src/daemon/storage-security.js";

async function temporaryDataDirectory(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), "agent-ssh-storage-security-"));
  const dataDirectory = path.join(root, "data");
  await mkdir(dataDirectory);
  return dataDirectory;
}

test(
  "hardens existing audit and retained output paths",
  { timeout: 120_000 },
  async (t) => {
    const dataDirectory = await temporaryDataDirectory();
    t.after(() => rm(path.dirname(dataDirectory), { recursive: true, force: true }));
    const auditDirectory = path.join(dataDirectory, "audit");
    const auditFile = path.join(auditDirectory, "gateway.jsonl");
    const outputEntry = path.join(dataDirectory, "outputs", "A".repeat(43));
    const outputFile = path.join(outputEntry, "stdout.bin");
    await mkdir(auditDirectory);
    await writeFile(auditFile, "{}\n", "utf8");
    await mkdir(outputEntry, { recursive: true });
    await writeFile(outputFile, "secret", "utf8");
    await chmod(auditDirectory, 0o777);
    await chmod(auditFile, 0o666);
    await chmod(outputEntry, 0o777);
    await chmod(outputFile, 0o666);

    const prepared = await prepareRuntimeStorage(dataDirectory);
    assert.equal(prepared.auditFile, auditFile);
    assert.equal(prepared.outputsDirectory, path.join(dataDirectory, "outputs"));

    if (process.platform !== "win32") {
      assert.equal((await lstat(auditDirectory)).mode & 0o777, 0o700);
      assert.equal((await lstat(auditFile)).mode & 0o777, 0o600);
      assert.equal((await lstat(outputEntry)).mode & 0o777, 0o700);
      assert.equal((await lstat(outputFile)).mode & 0o777, 0o600);
    }
  },
);

test(
  "rejects a reparse point in retained output storage",
  { timeout: 120_000 },
  async (t) => {
    const dataDirectory = await temporaryDataDirectory();
    t.after(() => rm(path.dirname(dataDirectory), { recursive: true, force: true }));
    const outputsDirectory = path.join(dataDirectory, "outputs");
    const targetDirectory = path.join(path.dirname(dataDirectory), "redirected");
    await mkdir(outputsDirectory);
    await mkdir(targetDirectory);
    await symlink(
      targetDirectory,
      path.join(outputsDirectory, "A".repeat(43)),
      process.platform === "win32" ? "junction" : "dir",
    );

    await assert.rejects(
      prepareRuntimeStorage(dataDirectory),
      /reparse point|directly referenced directory/u,
    );
  },
);

test(
  "rejects a hard-linked retained output file",
  { timeout: 120_000 },
  async (t) => {
    const dataDirectory = await temporaryDataDirectory();
    t.after(() => rm(path.dirname(dataDirectory), { recursive: true, force: true }));
    const outsideFile = path.join(path.dirname(dataDirectory), "outside.bin");
    const outputEntry = path.join(dataDirectory, "outputs", "A".repeat(43));
    await mkdir(outputEntry, { recursive: true });
    await writeFile(outsideFile, "outside", "utf8");
    await link(outsideFile, path.join(outputEntry, "stdout.bin"));

    await assert.rejects(
      prepareRuntimeStorage(dataDirectory),
      /single-link|hard link/u,
    );
  },
);
