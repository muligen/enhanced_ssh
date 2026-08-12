import assert from "node:assert/strict";
import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import test from "node:test";

import {
  buildSftpBatch,
  normalizeLocalTransferRelativePath,
  normalizeRemoteTransferPath,
  quoteSftpBatchPath,
  resolveLocalTransferDestination,
  resolveLocalTransferSource,
  splitUnrestrictedLocalTransferPath,
  TransferPathError,
  type TransferPathErrorCode,
} from "../../src/core/transfer-paths.js";

test("resolves regular sources and missing destinations below a canonical root", async (t) => {
  const root = await createTemporaryRoot(t);
  await mkdir(path.join(root, "source"));
  await writeFile(path.join(root, "source", "file.bin"), Buffer.from("payload"));

  const source = await resolveLocalTransferSource(root, "source/file.bin");
  assert.equal(source.rootPath, await realpath(root));
  assert.equal(source.relativePath, "source/file.bin");
  assert.equal(source.exists, true);
  assert.equal(source.kind, "file");
  assert.equal(source.size, 7);

  const destination = await resolveLocalTransferDestination(
    root,
    "new/nested/file.bin",
  );
  assert.equal(destination.rootPath, await realpath(root));
  assert.equal(
    destination.absolutePath,
    path.join(await realpath(root), "new", "nested", "file.bin"),
  );
  assert.equal(destination.exists, false);
  assert.equal(destination.relativePath, "new/nested/file.bin");
});

test("rejects absolute, traversal, missing, and wrong-kind local paths", async (t) => {
  const root = await createTemporaryRoot(t);
  await mkdir(path.join(root, "directory"));
  await writeFile(path.join(root, "file.txt"), "content");

  assert.throws(
    () => normalizeLocalTransferRelativePath("../outside.txt"),
    hasCode("INVALID_PATH"),
  );
  assert.throws(
    () => normalizeLocalTransferRelativePath(path.resolve(root, "file.txt")),
    hasCode("INVALID_PATH"),
  );
  await assert.rejects(
    resolveLocalTransferSource(root, "missing.txt"),
    hasCode("PATH_NOT_FOUND"),
  );
  await assert.rejects(
    resolveLocalTransferSource(root, "directory"),
    hasCode("WRONG_ENTRY_TYPE"),
  );
  await assert.rejects(
    resolveLocalTransferSource(root, "file.txt", "directory"),
    hasCode("WRONG_ENTRY_TYPE"),
  );
  await assert.rejects(
    resolveLocalTransferDestination(root, "file.txt/child.bin"),
    hasCode("UNSAFE_FILE_TYPE"),
  );
});

test("splits unrestricted native absolute paths without accepting relative or device syntax", () => {
  const absolute = path.resolve(os.tmpdir(), "full access", "payload.bin");
  const split = splitUnrestrictedLocalTransferPath(absolute);
  assert.equal(split.rootPath, path.parse(absolute).root);
  assert.equal(
    path.resolve(split.rootPath, split.relativePath),
    absolute,
  );
  assert.deepEqual(splitUnrestrictedLocalTransferPath(split.rootPath), {
    rootPath: split.rootPath,
    relativePath: ".",
  });

  assert.throws(
    () => splitUnrestrictedLocalTransferPath("relative/payload.bin"),
    hasCode("INVALID_PATH"),
  );
  const unsafeAbsolutePaths = ["//server/share/payload.bin"];
  if (process.platform === "win32") {
    unsafeAbsolutePaths.push(
      String.raw`\\?\C:\device\payload.bin`,
      String.raw`\rooted-without-drive\payload.bin`,
      "/rooted-without-drive/payload.bin",
    );
  }
  for (const unsafeAbsolute of unsafeAbsolutePaths) {
    assert.throws(
      () => splitUnrestrictedLocalTransferPath(unsafeAbsolute),
      hasCode("INVALID_PATH"),
    );
  }
});

test("rejects symbolic links and directory reparse points", async (t) => {
  const parent = await createTemporaryRoot(t);
  const root = path.join(parent, "root");
  const outside = path.join(parent, "outside");
  await mkdir(root);
  await mkdir(outside);
  await writeFile(path.join(outside, "secret.txt"), "secret");

  const link = path.join(root, "link");
  try {
    await symlink(
      outside,
      link,
      process.platform === "win32" ? "junction" : "dir",
    );
  } catch (error: unknown) {
    if (isPermissionDenied(error)) {
      t.skip("creating a test reparse point is not permitted on this host");
      return;
    }
    throw error;
  }

  await assert.rejects(
    resolveLocalTransferSource(root, "link/secret.txt"),
    hasCode("UNSAFE_LINK"),
  );
  await assert.rejects(
    resolveLocalTransferSource(link, "secret.txt"),
    hasCode("UNSAFE_LINK"),
  );
});

test(
  "rejects special filesystem entries",
  { skip: process.platform === "win32" },
  async (t) => {
    const root = await createTemporaryRoot(t);
    const socketPath = path.join(root, "unix.socket");
    const server = net.createServer();
    t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketPath, resolve);
    });

    await assert.rejects(
      resolveLocalTransferSource(root, "unix.socket"),
      hasCode("UNSAFE_FILE_TYPE"),
    );
  },
);

test("normalizes target-native absolute paths without accepting traversal", () => {
  assert.equal(
    normalizeRemoteTransferPath("windows", String.raw`d:\services\app\file.zip`),
    "D:/services/app/file.zip",
  );
  assert.equal(normalizeRemoteTransferPath("windows", "c:/"), "C:/");
  assert.equal(
    normalizeRemoteTransferPath("linux", "/srv//app/file.zip"),
    "/srv/app/file.zip",
  );
  assert.equal(normalizeRemoteTransferPath("macos", "/Users/build"), "/Users/build");

  for (const value of [
    String.raw`D:relative\file`,
    String.raw`D:\services\..\secret`,
    String.raw`\\server\share\file`,
    String.raw`\\?\D:\device\file`,
    String.raw`D:\services\CON.txt`,
  ]) {
    assert.throws(
      () => normalizeRemoteTransferPath("windows", value),
      hasCode("INVALID_PATH"),
    );
  }
  assert.throws(
    () => normalizeRemoteTransferPath("linux", "srv/app"),
    hasCode("INVALID_PATH"),
  );
  assert.throws(
    () => normalizeRemoteTransferPath("linux", "/srv/../etc/passwd"),
    hasCode("INVALID_PATH"),
  );
});

test("quotes SFTP batch tokens and suppresses command echo", () => {
  assert.equal(
    quoteSftpBatchPath('C:/space dir/"quoted"/name*[1]?.txt'),
    String.raw`"C:/space dir/\"quoted\"/name\*\[1\]\?.txt"`,
  );
  assert.throws(
    () => quoteSftpBatchPath("safe\n!cmd.exe /c whoami"),
    hasCode("INVALID_PATH"),
  );

  const batch = buildSftpBatch([
    {
      operation: "put",
      localPath: String.raw`C:\Project Files\archive[1].zip`,
      remotePath: "/srv/releases/archive[1].zip",
    },
    {
      operation: "mkdir",
      remotePath: "/srv/cache",
      ignoreFailure: true,
    },
    {
      operation: "rename",
      sourceRemotePath: "/srv/releases/archive[1].zip",
      destinationRemotePath: "/srv/releases/current.zip",
    },
  ]).toString("utf8");

  assert.equal(
    batch,
    String.raw`@put "C:\\Project Files\\archive\[1\].zip" "/srv/releases/archive\[1\].zip"
-@mkdir "/srv/cache"
@rename "/srv/releases/archive\[1\].zip" "/srv/releases/current.zip"
@quit
`,
  );
  assert.equal(batch.includes("\n!"), false);
  assert.throws(
    () =>
      buildSftpBatch([
        {
          operation: "put",
          localPath: "relative.txt",
          remotePath: "/srv/relative.txt",
        },
      ]),
    hasCode("INVALID_PATH"),
  );
  assert.throws(
    () =>
      buildSftpBatch([
        {
          operation: "put",
          localPath: String.raw`C:\project\file.txt`,
          remotePath: "/srv/../etc/file.txt",
        },
      ]),
    hasCode("INVALID_PATH"),
  );
});

async function createTemporaryRoot(t: test.TestContext): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), "agent-ssh-transfer-paths-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function hasCode(code: TransferPathErrorCode): (error: unknown) => boolean {
  return (error: unknown): boolean =>
    error instanceof TransferPathError && error.code === code;
}

function isPermissionDenied(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    ["EPERM", "EACCES"].includes(String((error as NodeJS.ErrnoException).code))
  );
}
