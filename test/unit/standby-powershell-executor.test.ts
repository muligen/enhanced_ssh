import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import test from "node:test";
import { setTimeout as sleep } from "node:timers/promises";

import { WINDOWS_POWERSHELL_REMOTE_COMMAND } from "../../src/core/remote-command.js";
import { SshExecutor } from "../../src/infra/openssh-executor.js";
import type { SshOutcome, SshRunInput } from "../../src/infra/ssh-runner.js";
import { SshControlMasterPool } from "../../src/infra/ssh-control-master.js";
import {
  StandbyPowerShellExecutor,
  type StandbyPowerShellExecutorOptions,
} from "../../src/infra/standby-powershell-executor.js";

const fakeSsh = resolve("test", "fixtures", "fake-ssh-master.mjs");
const posixOnly = { skip: process.platform === "win32" };

interface Session {
  readonly pid: number;
  readonly event: "start" | "exit";
  readonly startedAt?: number;
  readonly stdin?: string;
}

interface Harness {
  readonly standby: StandbyPowerShellExecutor;
  sessions(): Promise<Session[]>;
  waitForStarts(count: number): Promise<Session[]>;
}

test("a standby PowerShell process runs the next command and is replaced afterwards", posixOnly, async () => {
  await withStandby({}, async ({ standby, waitForStarts }) => {
    const first = reply(await standby.run(powershell("first")));
    assert.equal(first.stdin, "first");

    const [, waiting] = await waitForStarts(2);
    const requestedAt = Date.now();
    const second = reply(await standby.run(powershell("second")));
    assert.equal(second.stdin, "second");
    assert.equal(second.pid, waiting!.pid);
    assert.ok(second.startedAt <= requestedAt);

    const [, , next] = await waitForStarts(3);
    const exited = await standby.run(powershell("exit 7"));
    assert.equal(exited.exitCode, 7);
    assert.equal(reply(exited).pid, next!.pid);
  });
});

test("output written while waiting is reported with the command, as in a cold run", posixOnly, async () => {
  process.env.FAKE_SSH_BANNER = "notice\n";
  try {
    await withStandby({}, async ({ standby, waitForStarts }) => {
      const cold = await standby.run(powershell("first"));
      await waitForStarts(2);
      const warm = await standby.run(powershell("second"));
      assert.equal(cold.stderr, "notice\n");
      assert.equal(warm.stderr, "notice\n");
    });
  } finally {
    delete process.env.FAKE_SSH_BANNER;
  }
});

test("other commands bypass the standby process", posixOnly, async () => {
  await withStandby({}, async ({ standby, sessions }) => {
    await standby.run({ sshAlias: "win", command: "hostname" });
    await standby.run({ sshAlias: "win", command: "cmd.exe /d /c ver", stdin: Buffer.from("x") });
    await sleep(100);
    assert.equal((await sessions()).filter((entry) => entry.event === "start").length, 2);
  });
});

test("an idle standby ends without running anything and releases the connection", posixOnly, async () => {
  let released = 0;
  await withStandby(
    { idleTimeoutMs: 100, onIdle: async () => { released += 1; } },
    async ({ standby, sessions, waitForStarts }) => {
      await standby.run(powershell("first"));
      const [, waiting] = await waitForStarts(2);
      await waitFor(() => released === 1);
      const exit = (await sessions()).find((entry) => entry.event === "exit" && entry.pid === waiting!.pid);
      assert.equal(exit?.stdin, "");
    },
  );
});

test("a standby that dies before use falls back to a cold run and is not replaced at once", posixOnly, async () => {
  await withStandby({}, async ({ standby, sessions, waitForStarts }) => {
    await standby.run(powershell("first"));
    const [, waiting] = await waitForStarts(2);
    process.kill(waiting!.pid, "SIGKILL");
    await waitFor(() => !isAlive(waiting!.pid));
    await sleep(50);

    const second = reply(await standby.run(powershell("second")));
    assert.notEqual(second.pid, waiting!.pid);
    await sleep(100);
    assert.equal((await sessions()).filter((entry) => entry.event === "start").length, 3);
  });
});

test("a rejected command does not leave its standby process behind", posixOnly, async () => {
  await withStandby({}, async ({ standby, sessions, waitForStarts }) => {
    await standby.run(powershell("first"));
    const [, waiting] = await waitForStarts(2);
    await assert.rejects(
      standby.run({ ...powershell(""), stdin: Buffer.alloc(1024 * 1024 + 1) }),
      RangeError,
    );
    const exit = (await sessions()).find((entry) => entry.event === "exit" && entry.pid === waiting!.pid);
    assert.equal(exit?.stdin, "");
    await waitForStarts(3);
  });
});

test("closing ends the waiting process and rejects later commands", posixOnly, async () => {
  await withStandby({}, async ({ standby, sessions, waitForStarts }) => {
    await standby.run(powershell("first"));
    const [, waiting] = await waitForStarts(2);
    await standby.close();
    const exit = (await sessions()).find((entry) => entry.event === "exit" && entry.pid === waiting!.pid);
    assert.equal(exit?.stdin, "");
    assert.equal(isAlive(waiting!.pid), false);
    await assert.rejects(standby.run(powershell("late")), /closed/u);
  });
});

async function withStandby(
  options: Omit<StandbyPowerShellExecutorOptions, "sshAlias">,
  body: (harness: Harness) => Promise<void>,
): Promise<void> {
  const root = await mkdtemp(join("/tmp", "asb-"));
  const sessionsFile = join(root, "sessions.log");
  process.env.FAKE_SSH_SESSIONS = sessionsFile;
  const pool = await SshControlMasterPool.create({ executable: fakeSsh, runtimeDirectory: root });
  assert.ok(pool !== undefined);
  const standby = new StandbyPowerShellExecutor(
    new SshExecutor({ executable: fakeSsh, controlMasters: pool }),
    { sshAlias: "win", ...options },
  );
  const sessions = async (): Promise<Session[]> => {
    const text = await readFile(sessionsFile, "utf8").catch(() => "");
    return text.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line) as Session);
  };
  const waitForStarts = async (count: number): Promise<Session[]> => {
    let starts: Session[] = [];
    await waitFor(async () => {
      starts = (await sessions()).filter((entry) => entry.event === "start");
      return starts.length >= count;
    });
    return starts;
  };
  try {
    await body({ standby, sessions, waitForStarts });
  } finally {
    await standby.close();
    await pool.close();
    delete process.env.FAKE_SSH_SESSIONS;
    await rm(root, { recursive: true, force: true });
  }
}

function powershell(script: string): SshRunInput {
  return {
    sshAlias: "win",
    command: WINDOWS_POWERSHELL_REMOTE_COMMAND,
    stdin: Buffer.from(script),
  };
}

function reply(outcome: SshOutcome): { pid: number; startedAt: number; stdin: string } {
  return JSON.parse(outcome.stdout) as { pid: number; startedAt: number; stdin: string };
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitFor(
  predicate: () => boolean | Promise<boolean>,
  timeoutMs = 5_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await predicate())) {
    if (Date.now() > deadline) throw new Error("timed out waiting for the condition");
    await sleep(10);
  }
}
