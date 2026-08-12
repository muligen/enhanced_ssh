import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  link,
  mkdir,
  mkdtemp,
  readdir,
  rm,
  rmdir,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import {
  cleanupOrphanedSshWrapperConfigs,
  createSshWrapperConfig,
  renderSshWrapperConfig,
} from "../../src/daemon/ssh-wrapper-config.js";
import { hardenPrivatePath } from "../../src/daemon/runtime-state.js";

const execFileAsync = promisify(execFile);

test(
  "the wrapper applies gateway constraints to final and ProxyJump hosts",
  { skip: process.platform !== "win32", timeout: 15_000 },
  async (t) => {
    const directory = await mkdtemp(
      path.join(tmpdir(), "agent-ssh-wrapper-config-"),
    );
    t.after(() => rm(directory, { recursive: true, force: true }));
    const administratorConfig = path.join(directory, "administrator.conf");
    const wrapperConfig = path.join(directory, "wrapper.conf");
    const knownHosts = path.join(directory, "known_hosts");
    await writeFile(
      administratorConfig,
      [
        "Host final",
        "    HostName final.internal",
        "    ProxyJump jump",
        "    BatchMode no",
        "    StrictHostKeyChecking no",
        "    UserKnownHostsFile C:/unsafe-known-hosts",
        "    VerifyHostKeyDNS yes",
        "    ForwardAgent yes",
        "    RequestTTY force",
        "    ConnectionAttempts 9",
        "    ConnectTimeout 99",
        "    SessionType none",
        "    RemoteCommand echo unsafe",
        "    ControlPath C:/unsafe-control-socket",
        "Host jump",
        "    HostName jump.internal",
        "    StrictHostKeyChecking no",
        "",
      ].join("\n"),
      "utf8",
    );
    await hardenPrivatePath(administratorConfig, false);
    const rendered = renderSshWrapperConfig(
      administratorConfig,
      knownHosts,
      17,
    );
    assert.ok(
      rendered.indexOf("StrictHostKeyChecking yes") <
        rendered.indexOf("Include "),
    );
    await writeFile(wrapperConfig, rendered, "utf8");
    await hardenPrivatePath(wrapperConfig, false);

    const executable = "C:\\Windows\\System32\\OpenSSH\\ssh.exe";
    for (const [alias, hostname] of [
      ["final", "final.internal"],
      ["jump", "jump.internal"],
    ] as const) {
      const { stdout, stderr } = await execFileAsync(
        executable,
        ["-G", "-F", wrapperConfig, alias],
        { encoding: "utf8", windowsHide: true, timeout: 10_000 },
      );
      assert.equal(stderr, "");
      const values = parseSshG(stdout);
      assert.equal(values.get("hostname"), hostname);
      assert.equal(values.get("batchmode"), "yes");
      assert.equal(values.get("connectionattempts"), "1");
      assert.equal(values.get("connecttimeout"), "17");
      assert.equal(values.get("stricthostkeychecking"), "true");
      assert.equal(values.get("userknownhostsfile"), toSshPath(knownHosts));
      assert.equal(values.get("globalknownhostsfile"), "none");
      assert.equal(values.get("verifyhostkeydns"), "false");
      assert.equal(values.get("clearallforwardings"), "yes");
      assert.equal(values.get("permitlocalcommand"), "no");
      assert.equal(values.get("forwardagent"), "no");
      assert.equal(values.get("requesttty"), "false");
      assert.equal(values.get("sessiontype"), "default");
      // Windows OpenSSH omits RemoteCommand from `ssh -G` when it resolves to none.
      assert.equal(values.has("remotecommand"), false);
      assert.equal(values.get("controlmaster"), "false");
      assert.equal(values.has("controlpath"), false);
      assert.equal(values.get("updatehostkeys"), "false");
      assert.equal(values.has("knownhostscommand"), false);
    }
  },
);

test("rejects OpenSSH environment expansion syntax in injected paths", () => {
  assert.throws(
    () =>
      renderSshWrapperConfig(
        "C:\\literal\\${TEMP}\\ssh_config",
        String.raw`C:\literal\known_hosts`,
        10,
      ),
    /environment expansions/u,
  );
  assert.throws(
    () =>
      renderSshWrapperConfig(
        String.raw`C:\literal\ssh_config`,
        "C:\\literal\\${TEMP}\\known_hosts",
        10,
      ),
    /environment expansions/u,
  );
});

test("managed startup cleanup removes only strict dead-owner wrapper files", async (t) => {
  const directory = await mkdtemp(
    path.join(tmpdir(), "agent-ssh-wrapper-orphan-cleanup-"),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));

  const deadPid = 2_147_483_641;
  const livePid = 2_147_483_642;
  const hardLinkPid = 2_147_483_643;
  const deadName = wrapperName(deadPid, "a");
  const liveName = wrapperName(livePid, "b");
  const currentName = wrapperName(process.pid, "c");
  const hardLinkName = wrapperName(hardLinkPid, "d");
  const directoryName = wrapperName(2_147_483_644, "e");
  const hardLinkSource = path.join(directory, "hard-link-source");
  await Promise.all([
    writeFile(path.join(directory, deadName), "dead", "utf8"),
    writeFile(path.join(directory, liveName), "live", "utf8"),
    writeFile(path.join(directory, currentName), "current", "utf8"),
    writeFile(hardLinkSource, "linked", "utf8"),
    writeFile(
      path.join(directory, `.ssh-wrapper-${deadPid}-${"F".repeat(32)}.conf`),
      "uppercase nonce",
      "utf8",
    ),
    writeFile(
      path.join(directory, `.ssh-wrapper-0-${"f".repeat(32)}.conf`),
      "zero pid",
      "utf8",
    ),
    writeFile(path.join(directory, "unrelated.conf"), "other", "utf8"),
    mkdir(path.join(directory, directoryName)),
  ]);
  await link(hardLinkSource, path.join(directory, hardLinkName));

  const checkedPids: number[] = [];
  const removed = await cleanupOrphanedSshWrapperConfigs(directory, {
    isProcessAlive: (pid) => {
      checkedPids.push(pid);
      return pid === livePid;
    },
  });

  assert.equal(removed, 1);
  assert.equal((await readdir(directory)).includes(deadName), false);
  assert.equal((await readdir(directory)).includes(liveName), true);
  assert.equal((await readdir(directory)).includes(currentName), true);
  assert.equal((await readdir(directory)).includes(hardLinkName), true);
  assert.equal((await readdir(directory)).includes(directoryName), true);
  assert.equal(checkedPids.includes(process.pid), false);
  assert.equal(checkedPids.filter((pid) => pid === deadPid).length, 3);
});

test("orphan cleanup skips a PID that becomes live before removal", async (t) => {
  const directory = await mkdtemp(
    path.join(tmpdir(), "agent-ssh-wrapper-pid-reuse-"),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  const ownerPid = 2_147_483_640;
  const name = wrapperName(ownerPid, "a");
  await writeFile(path.join(directory, name), "retained", "utf8");

  let probes = 0;
  const removed = await cleanupOrphanedSshWrapperConfigs(directory, {
    isProcessAlive: () => {
      probes += 1;
      return probes >= 2;
    },
  });

  assert.equal(removed, 0);
  assert.equal(probes, 2);
  assert.equal((await readdir(directory)).includes(name), true);
});

test("orphan cleanup skips matching symbolic links and reparse points", async (t) => {
  const directory = await mkdtemp(
    path.join(tmpdir(), "agent-ssh-wrapper-reparse-"),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  const source = path.join(directory, "source-directory");
  const name = wrapperName(2_147_483_639, "a");
  await mkdir(source);
  try {
    await symlink(
      source,
      path.join(directory, name),
      process.platform === "win32" ? "junction" : "dir",
    );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EPERM") {
      t.skip("creating a symbolic link is not permitted on this host");
      return;
    }
    throw error;
  }

  assert.equal(
    await cleanupOrphanedSshWrapperConfigs(directory, {
      isProcessAlive: () => false,
    }),
    0,
  );
  assert.equal((await readdir(directory)).includes(name), true);
});

test("orphan cleanup reports owner verification failures without deletion", async (t) => {
  const directory = await mkdtemp(
    path.join(tmpdir(), "agent-ssh-wrapper-probe-failure-"),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  const name = wrapperName(2_147_483_638, "a");
  await writeFile(path.join(directory, name), "retained", "utf8");

  await assert.rejects(
    cleanupOrphanedSshWrapperConfigs(directory, {
      isProcessAlive: () => {
        throw new Error("synthetic process probe failure");
      },
    }),
    /Unable to verify an SSH wrapper owner process/u,
  );
  assert.equal((await readdir(directory)).includes(name), true);
});

test(
  "a failed generated wrapper removal remains retryable",
  { skip: process.platform !== "win32", timeout: 15_000 },
  async (t) => {
    const directory = await mkdtemp(
      path.join(tmpdir(), "agent-ssh-wrapper-removal-"),
    );
    t.after(() => rm(directory, { recursive: true, force: true }));
    const wrapper = await createSshWrapperConfig(
      directory,
      path.join(directory, "administrator.conf"),
      path.join(directory, "known_hosts"),
      10,
    );
    await rm(wrapper.path, { force: true });
    await mkdir(wrapper.path);

    await assert.rejects(
      wrapper.remove(),
      /EPERM|EISDIR|operation not permitted/iu,
    );
    await rmdir(wrapper.path);
    await wrapper.remove();
    await wrapper.remove();
  },
);

function parseSshG(output: string): ReadonlyMap<string, string> {
  const values = new Map<string, string>();
  for (const line of output.split(/\r?\n/u)) {
    const separator = line.indexOf(" ");
    if (separator > 0) {
      values.set(line.slice(0, separator), line.slice(separator + 1));
    }
  }
  return values;
}

function toSshPath(value: string): string {
  return value.replaceAll("\\", "/");
}

function wrapperName(pid: number, nonceCharacter: string): string {
  return `.ssh-wrapper-${pid}-${nonceCharacter.repeat(32)}.conf`;
}
