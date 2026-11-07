import assert from "node:assert/strict";
import { lstat, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import {
  buildOpenSshArguments,
  buildOpenSshControlCommandArguments,
  buildOpenSshControlMasterArguments,
} from "../../src/infra/openssh-executor.js";
import { buildOpenSftpArguments } from "../../src/infra/sftp-executor.js";
import { SshControlMasterPool } from "../../src/infra/ssh-control-master.js";

const fakeSsh = resolve("test", "fixtures", "fake-ssh-master.mjs");
const posixOnly = { skip: process.platform === "win32" };

test("commands stay multiplexing clients and never become masters", () => {
  const arguments_ = buildOpenSshArguments(
    { configFile: "/cfg" },
    { sshAlias: "target", command: "id" },
    "/run/mux-1/abc",
  );
  assert.deepEqual(arguments_.slice(arguments_.indexOf("-S"), arguments_.indexOf("-S") + 2), [
    "-S",
    "/run/mux-1/abc",
  ]);
  assertOption(arguments_, "ControlMaster=no");
  assertOption(arguments_, "ControlPersist=no");
  assert.equal(arguments_.includes("-M"), false);
  assert.deepEqual(
    buildOpenSshArguments({}, { sshAlias: "target", command: "id" }).slice(2, 4),
    ["-S", "none"],
  );
});

test("the master keeps hardened authentication and no contradicting options", () => {
  const arguments_ = buildOpenSshControlMasterArguments(
    { configFile: "/cfg", knownHostsFile: "/kh", connectTimeoutSeconds: 9 },
    "target",
    "/run/mux-1/abc",
    60,
  );
  for (const flag of ["-M", "-N", "-f"]) assert.equal(arguments_.includes(flag), true);
  assertOption(arguments_, "ControlPersist=60");
  assertOption(arguments_, "BatchMode=yes");
  assertOption(arguments_, "StrictHostKeyChecking=yes");
  assertOption(arguments_, "ConnectTimeout=9");
  for (const option of ["ControlMaster=no", "ControlPersist=no", "ForkAfterAuthentication=no", "SessionType=default"]) {
    assert.equal(arguments_.includes(option), false, option);
  }
  assert.deepEqual(arguments_.slice(-2), ["--", "target"]);
  assert.deepEqual(buildOpenSshControlCommandArguments("target", "/s", "stop"), [
    "-F", "none", "-S", "/s", "-O", "stop", "--", "target",
  ]);
});

test("control paths must be literal", () => {
  for (const bad of ["none", "/a/%C", "~/mux", "/a b", "/a/$HOME"]) {
    assert.throws(() =>
      buildOpenSshArguments({}, { sshAlias: "t", command: "id" }, bad),
    );
    assert.throws(() =>
      buildOpenSftpArguments(
        { sshExecutable: "/usr/bin/ssh", configFile: "/c", knownHostsFile: "/k" },
        { sshAlias: "t", batch: "@pwd\n@quit\n" },
        bad,
      ),
    );
  }
  const sftp = buildOpenSftpArguments(
    { sshExecutable: "/usr/bin/ssh", configFile: "/c", knownHostsFile: "/k" },
    { sshAlias: "t", batch: "@pwd\n@quit\n" },
    "/run/mux-1/abc",
  );
  assertOption(sftp, "ControlPath=/run/mux-1/abc");
  assertOption(sftp, "ControlMaster=no");
});

test("multiplexing is disabled on Windows", async () => {
  assert.equal(
    await SshControlMasterPool.create({
      executable: fakeSsh,
      runtimeDirectory: tmpdir(),
      platform: "win32",
    }),
    undefined,
  );
});

test("pool starts one master per alias, reuses it, and stops it on close", posixOnly, async () => {
  const root = await mkdtemp(join("/tmp", "acm-"));
  const log = join(root, "ssh.log");
  process.env.FAKE_SSH_LOG = log;
  try {
    const pool = await SshControlMasterPool.create({ executable: fakeSsh, runtimeDirectory: root });
    assert.ok(pool !== undefined);
    const [first, second] = await Promise.all([pool.acquire("alpha"), pool.acquire("alpha")]);
    assert.ok(first !== undefined);
    assert.equal(first, second);
    assert.equal(await pool.acquire("alpha"), first);
    assert.notEqual(await pool.acquire("beta"), first);
    assert.equal((await lstat(first)).isSocket(), true);

    await pool.close();
    const calls = (await readFile(log, "utf8")).trim().split("\n").map((line) => JSON.parse(line) as string[]);
    assert.equal(calls.filter((call) => call.includes("-M") && call.at(-1) === "alpha").length, 1);
    assert.equal(calls.filter((call) => call.includes("-O") && call.includes("stop")).length, 2);
    await assert.rejects(lstat(pool.directory), { code: "ENOENT" });
    assert.equal(await pool.acquire("alpha"), undefined);
  } finally {
    delete process.env.FAKE_SSH_LOG;
    await rm(root, { recursive: true, force: true });
  }
});

test("a failed master falls back to direct connections and backs off", posixOnly, async () => {
  const root = await mkdtemp(join("/tmp", "acm-"));
  const log = join(root, "ssh.log");
  process.env.FAKE_SSH_LOG = log;
  try {
    const pool = await SshControlMasterPool.create({ executable: fakeSsh, runtimeDirectory: root });
    assert.ok(pool !== undefined);
    assert.equal(await pool.acquire("unreachable"), undefined);
    assert.equal(await pool.acquire("unreachable"), undefined);
    const calls = (await readFile(log, "utf8")).trim().split("\n");
    assert.equal(calls.length, 1);
    await pool.close();
  } finally {
    delete process.env.FAKE_SSH_LOG;
    await rm(root, { recursive: true, force: true });
  }
});

test("release stops only the removed alias", posixOnly, async () => {
  const root = await mkdtemp(join("/tmp", "acm-"));
  try {
    const pool = await SshControlMasterPool.create({ executable: fakeSsh, runtimeDirectory: root });
    assert.ok(pool !== undefined);
    const alpha = await pool.acquire("alpha");
    const beta = await pool.acquire("beta");
    assert.ok(alpha !== undefined && beta !== undefined);
    await pool.release(["alpha"]);
    await assert.rejects(lstat(alpha), { code: "ENOENT" });
    assert.equal((await lstat(beta)).isSocket(), true);
    await pool.close();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

function assertOption(arguments_: readonly string[], option: string): void {
  const index = arguments_.indexOf(option);
  assert.notEqual(index, -1, option);
  assert.equal(arguments_[index - 1], "-o", option);
}
