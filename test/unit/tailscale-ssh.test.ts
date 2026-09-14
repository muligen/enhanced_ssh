import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { targetConfigSchema } from "../../src/config/load-config.js";
import { TargetRegistry } from "../../src/core/target-registry.js";
import { resolveTailscalePeer, TailscaleSshExecutor } from "../../src/infra/tailscale-ssh-executor.js";
import type { SshOutcome } from "../../src/infra/ssh-runner.js";
import { managedSshFleetProfileSchema } from "../../src/test-ui/managed.js";

const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGfrI8roAEbTUtqpPsI17OtG+PRRJdUQi5blEgpgPYVS";
function status(overrides = {}): string {
  return JSON.stringify({ BackendState: "Running", Peer: { node: {
    DNSName: "build.tail123.ts.net.", TailscaleIPs: ["100.101.102.103"], SSH_HostKeys: [KEY], ...overrides,
  }, unrelated: { DNSName: "other.tail123.ts.net.", TailscaleIPs: null, SSH_HostKeys: null } } });
}
function outcome(stdout = ""): SshOutcome {
  return { exitCode: 0, signal: null, stdout, stderr: "", stdoutBytes: Buffer.byteLength(stdout), stderrBytes: 0, stdoutTruncated: false, stderrTruncated: false, aborted: false, durationMs: 1, terminationMode: null };
}

for (const host of ["build", "BUILD", "build.tail123.ts.net", "build.tail123.ts.net.", "100.101.102.103"]) {
  test(`Tailscale resolves authenticated peer ${host}`, () => {
    assert.deepEqual(resolveTailscalePeer(status(), host), { address: "100.101.102.103", hostKeys: [KEY] });
  });
}
test("Tailscale refuses unavailable, ambiguous, untrusted and injected peer data", () => {
  assert.throws(() => resolveTailscalePeer('{"BackendState":"NeedsLogin"}', "build"), /tailscale-unavailable/u);
  assert.throws(() => resolveTailscalePeer(status(), "unknown"), /tailscale-peer-unavailable/u);
  assert.throws(() => resolveTailscalePeer(status({ TailscaleIPs: ["192.168.1.2"] }), "build"), /tailscale-peer-unavailable/u);
  assert.throws(() => resolveTailscalePeer(status({ SSH_HostKeys: [] }), "build"), /tailscale-host-key-unavailable/u);
  assert.throws(() => resolveTailscalePeer(status({ SSH_HostKeys: [KEY + "\nHost *"] }), "build"), /tailscale-host-key-unavailable/u);
  const ambiguous = JSON.parse(status());
  ambiguous.Peer.second = { ...ambiguous.Peer.node, DNSName: "build.tail456.ts.net." };
  assert.throws(() => resolveTailscalePeer(JSON.stringify(ambiguous), "build"), /tailscale-peer-unavailable/u);
});

test("Tailscale SSH uses isolated configuration, current host keys and managed stdin; cleans up", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "tailscale-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const stdin = Buffer.from("echo hello\n");
  let calls = 0;
  const executor = new TailscaleSshExecutor({ executable: process.execPath, tailscaleExecutable: process.execPath, runtimeDirectory: root, targetAlias: "ts-build", host: "build", username: "ubuntu" }, {
    execute: async (options, input) => {
      calls++;
      if (calls === 1) {
        assert.deepEqual(input.arguments, ["status", "--json"]);
        assert.equal(input.outputSink, undefined);
        assert.equal(input.stdin, undefined);
        return outcome(status());
      }
      assert.equal(options.executable, process.execPath);
      const configFile = input.arguments[input.arguments.indexOf("-F") + 1]!;
      const config = await readFile(configFile, "utf8");
      assert.match(config, /HostName 100\.101\.102\.103/u);
      assert.match(config, /User ubuntu/u);
      assert.match(config, /PreferredAuthentications none/u);
      assert.match(config, /IdentityAgent none/u);
      assert.match(config, /ProxyCommand none/u);
      assert.doesNotMatch(config, /Include/u);
      assert.equal(await readFile(path.join(path.dirname(configFile), "known_hosts"), "utf8"), `100.101.102.103 ${KEY}\n`);
      assert.ok(input.arguments.includes("StrictHostKeyChecking=yes"));
      assert.ok(input.arguments.includes("BatchMode=yes"));
      assert.deepEqual(input.arguments.slice(-3), ["--", "ts-build", "bash --noprofile --norc -s"]);
      assert.equal(input.stdin, stdin);
      return outcome("hello\n");
    },
  });
  assert.equal((await executor.run({ sshAlias: "ts-build", command: "bash --noprofile --norc -s", stdin })).stdout, "hello\n");
  assert.equal(calls, 2);
  assert.match(executor.fingerprints[0]!, /^SHA256:/u);
  assert.deepEqual(await readdir(root), []);
  await executor.close();
  await assert.rejects(executor.run({ sshAlias: "ts-build", command: "hostname" }), /closed/u);
});

test("Tailscale does not run SSH or expose status JSON when status fails", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "tailscale-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  let calls = 0;
  const executor = new TailscaleSshExecutor({ executable: process.execPath, tailscaleExecutable: process.execPath, runtimeDirectory: root, targetAlias: "ts", host: "build", username: "ubuntu" }, { execute: async () => { calls++; return outcome('{"BackendState":"NeedsLogin","User":{"secret":"private-user"}}'); } });
  const result = await executor.run({ sshAlias: "ts", command: "hostname" });
  assert.equal(calls, 1);
  assert.equal(result.failureReason, "tailscale-unavailable");
  assert.equal(result.exitCode, 255);
  assert.equal(result.stdout, "");
  assert.doesNotMatch(JSON.stringify(result), /private-user/u);
  assert.deepEqual(await readdir(root), []);
  await executor.close();
});

test("Tailscale full-access retains command authorization but refuses every transfer direction", () => {
  const target = targetConfigSchema.parse({ sshAlias: "ts", connection: { mode: "tailscale-ssh", host: "build", username: "ubuntu" }, enabled: true, policy: { mode: "full-access", maxTimeoutMs: 30000 } });
  const registry = new TargetRegistry({ build: target });
  assert.equal(registry.list()[0]!.connectionMode, "tailscale-ssh");
  assert.equal(registry.list()[0]!.transferMode, "deny");
  for (const direction of ["upload", "download", "sync"] as const) assert.throws(() => registry.authorizeTransfer("build", direction, undefined), /not supported/u);
});

test("Tailscale managed profile requires no key and rejects incompatible options", () => {
  const input = { version: 3, tailscale: { executable: process.execPath }, targets: { build: {
    connectionMode: "tailscale-ssh", target: { host: "build", port: 22, username: "ubuntu" }, platform: "linux", enabled: true, policyMode: "full-access", allowedCommands: [], maxTimeoutMs: 30000,
  } } };
  assert.equal(managedSshFleetProfileSchema.parse(input).targets.build?.target.keyId, undefined);
  assert.equal(managedSshFleetProfileSchema.safeParse({ ...input, tailscale: undefined }).success, false);
  for (const change of [{ platform: "windows" }, { knownHostsFile: process.execPath }, { transferMode: "upload" }, { localRootPath: process.cwd() }, { target: { ...input.targets.build.target, port: 2222 } }, { target: { ...input.targets.build.target, keyId: "k-" + "a".repeat(32) } }]) {
    assert.equal(managedSshFleetProfileSchema.safeParse({ ...input, targets: { build: { ...input.targets.build, ...change } } }).success, false);
  }
});


test("Tailscale accepts advertised key trailing whitespace and equivalent IPv6 spellings", () => {
  assert.deepEqual(resolveTailscalePeer(status({ SSH_HostKeys: [KEY + "\n"] }), "build").hostKeys, [KEY]);
  assert.equal(resolveTailscalePeer(status({ TailscaleIPs: ["fd7a:115c:a1e0::1234"] }), "FD7A:115C:A1E0:0:0:0:0:1234").address, "fd7a:115c:a1e0::1234");
});

test("closing Tailscale executor cancels an in-flight status query without starting SSH", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "tailscale-cancel-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  let calls = 0;
  const executor = new TailscaleSshExecutor({ executable: process.execPath, tailscaleExecutable: process.execPath, runtimeDirectory: root, targetAlias: "ts", host: "build", username: "ubuntu" }, {
    execute: async (_options, input) => {
      calls++;
      assert.ok(input.signal);
      await new Promise<void>((resolve) => input.signal!.aborted ? resolve() : input.signal!.addEventListener("abort", () => resolve(), { once: true }));
      return { ...outcome(), aborted: true };
    },
  });
  const running = executor.run({ sshAlias: "ts", command: "hostname" });
  await executor.close();
  assert.equal((await running).aborted, true);
  assert.equal(calls, 1);
  assert.deepEqual(await readdir(root), []);
});
