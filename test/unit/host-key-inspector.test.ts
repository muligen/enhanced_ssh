import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { access, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  HOST_KEY_INSPECTION_TIMEOUT_MS,
  HostKeyInspectionError,
  HostKeyInspector,
  MAX_HOST_KEY_INSPECTION_OUTPUT_BYTES,
  type HostKeyCommandRunner,
  type HostKeyCommandRunnerInput,
  type HostKeyCommandResult,
} from "../../src/infra/host-key-inspector.js";

interface Fixture {
  readonly root: string;
  readonly sshExecutable: string;
  readonly configFile: string;
  readonly knownHostsFile: string;
}

function fixture(): Fixture {
  const root = path.join(tmpdir(), "agent-ssh-host-key-inspector");
  return {
    root,
    sshExecutable: path.join(root, "ssh.exe"),
    configFile: path.join(root, "ssh_config"),
    knownHostsFile: path.join(root, "known_hosts"),
  };
}

function result(exitCode: number, stdout = ""): HostKeyCommandResult {
  return { exitCode, stdout: Buffer.from(stdout, "utf8") };
}

function keyBlob(keyType: string, seed: number): Buffer {
  const algorithm = Buffer.from(keyType, "utf8");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(algorithm.length);
  return Buffer.concat([length, algorithm, Buffer.alloc(32, seed)]);
}

function fingerprint(blob: Buffer): string {
  return `SHA256:${createHash("sha256").update(blob).digest("base64").replace(/=+$/u, "")}`;
}

function line(
  host: string,
  keyType: string,
  blob: Buffer,
  marker?: "@cert-authority" | "@revoked",
): string {
  return `${marker === undefined ? "" : `${marker} `}${host} ${keyType} ${blob.toString("base64")} comment`;
}

function inspector(
  runCommand: HostKeyCommandRunner,
  paths = fixture(),
): HostKeyInspector {
  return new HostKeyInspector(paths, { runCommand });
}

test("resolves standard-port targets and returns deduplicated trusted fingerprints", async () => {
  const paths = fixture();
  const hostKey = keyBlob("ssh-ed25519", 1);
  const caKey = keyBlob("ssh-rsa", 2);
  const revoked = keyBlob("ecdsa-sha2-nistp256", 3);
  const calls: HostKeyCommandRunnerInput[] = [];
  const runCommand: HostKeyCommandRunner = (input) => {
    calls.push(input);
    if (input.executable === paths.sshExecutable) {
      return Promise.resolve(
        result(0, "hostname build.example.internal\nport 22\nhostkeyalias none\n"),
      );
    }
    assert.equal(input.executable, path.join(paths.root, "ssh-keygen.exe"));
    const candidate = input.arguments[1];
    if (candidate === "build.example.internal") {
      return Promise.resolve(
        result(
          0,
          [
            "# Host build.example.internal found: line 1",
            line("build.example.internal", "ssh-ed25519", hostKey),
            line("build.example.internal", "ssh-rsa", caKey, "@cert-authority"),
            line("build.example.internal", "ecdsa-sha2-nistp256", revoked, "@revoked"),
            "",
          ].join("\n"),
        ),
      );
    }
    assert.equal(candidate, "[build.example.internal]:22");
    return Promise.resolve(
      result(0, `${line("[build.example.internal]:22", "ssh-ed25519", hostKey)}\n`),
    );
  };

  const service = inspector(runCommand, paths);
  const inspected = await service.inspect("build-target");
  assert.deepEqual(inspected, [
    {
      keyType: "ssh-rsa",
      fingerprintSha256: fingerprint(caKey),
      trust: "host-ca",
    },
    {
      keyType: "ssh-ed25519",
      fingerprintSha256: fingerprint(hostKey),
      trust: "host-key",
    },
  ]);
  assert.equal(Object.isFrozen(inspected), true);
  assert.equal(Object.isFrozen(inspected[0]), true);
  assert.deepEqual(calls[0]?.arguments, [
    "-G",
    "-F",
    paths.configFile,
    "--",
    "build-target",
  ]);
  assert.deepEqual(calls[1]?.arguments, [
    "-F",
    "build.example.internal",
    "-f",
    paths.knownHostsFile,
  ]);
  for (const call of calls) {
    assert.equal(call.timeoutMs, HOST_KEY_INSPECTION_TIMEOUT_MS);
    assert.equal(call.maxOutputBytes, MAX_HOST_KEY_INSPECTION_OUTPUT_BYTES);
  }

  assert.strictEqual(await service.inspect("build-target"), inspected);
  assert.equal(calls.length, 3, "successful inspections are cached per generation");
});

test("delegates hashed and nonstandard-port matching to ssh-keygen -F", async () => {
  const paths = fixture();
  const hostKey = keyBlob("ssh-ed25519", 4);
  const calls: HostKeyCommandRunnerInput[] = [];
  const runCommand: HostKeyCommandRunner = (input) => {
    calls.push(input);
    if (input.executable === paths.sshExecutable) {
      return Promise.resolve(result(0, "hostname 10.0.0.25\nport 2222\n"));
    }
    assert.equal(input.arguments[1], "[10.0.0.25]:2222");
    return Promise.resolve(
      result(
        0,
        `${line("|1|YWJjZGVmZ2hpamtsbW5vcA==|YWJjZGVmZ2hpamtsbW5vcHFyc3Q=", "ssh-ed25519", hostKey)}\n`,
      ),
    );
  };
  const inspected = await inspector(runCommand, paths).inspect("private-host");
  assert.equal(inspected[0]?.fingerprintSha256, fingerprint(hostKey));
  assert.equal(calls.length, 2);
});

test("uses HostKeyAlias exactly instead of the resolved hostname and port", async () => {
  const paths = fixture();
  const hostKey = keyBlob("ssh-ed25519", 5);
  const calls: HostKeyCommandRunnerInput[] = [];
  const runCommand: HostKeyCommandRunner = (input) => {
    calls.push(input);
    if (input.executable === paths.sshExecutable) {
      return Promise.resolve(
        result(
          0,
          "hostname transient.example.internal\nport 2200\nhostkeyalias stable-machine\n",
        ),
      );
    }
    assert.equal(input.arguments[1], "stable-machine");
    return Promise.resolve(
      result(0, `${line("stable-machine", "ssh-ed25519", hostKey)}\n`),
    );
  };
  await inspector(runCommand, paths).inspect("aliased-host");
  assert.equal(calls.length, 2);
});

test("fails closed for revoked-only, malformed, and inconsistent key data", async () => {
  const paths = fixture();
  const valid = keyBlob("ssh-ed25519", 6);
  const scenarios = [
    line("host.example", "ssh-ed25519", valid, "@revoked"),
    line("host.example", "ssh-rsa", valid),
    "host.example ssh-ed25519 ***",
  ];
  for (const matched of scenarios) {
    const runCommand: HostKeyCommandRunner = (input) =>
      Promise.resolve(
        input.executable === paths.sshExecutable
          ? result(0, "hostname host.example\nport 22\n")
          : result(0, `${matched}\n`),
      );
    await assert.rejects(
      inspector(runCommand, paths).inspect("host"),
      (error: unknown) =>
        error instanceof HostKeyInspectionError &&
        (error.code === "HOST_KEY_NOT_FOUND" || error.code === "HOST_KEY_INVALID"),
    );
  }
});

test("does not report a key that is also explicitly revoked", async () => {
  const paths = fixture();
  const revoked = keyBlob("ssh-ed25519", 7);
  const runCommand: HostKeyCommandRunner = (input) =>
    Promise.resolve(
      input.executable === paths.sshExecutable
        ? result(0, "hostname host.example\nport 22\n")
        : result(
            0,
            [
              line("host.example", "ssh-ed25519", revoked),
              line("host.example", "ssh-ed25519", revoked, "@revoked"),
              "",
            ].join("\n"),
          ),
    );
  await assert.rejects(
    inspector(runCommand, paths).inspect("host"),
    (error: unknown) =>
      error instanceof HostKeyInspectionError && error.code === "HOST_KEY_NOT_FOUND",
  );
});

test("maps local command failures to stable errors without leaking paths", async () => {
  const paths = fixture();
  const runCommand: HostKeyCommandRunner = () =>
    Promise.reject(new Error(`failed to open ${paths.knownHostsFile}`));
  await assert.rejects(
    inspector(runCommand, paths).inspect("host"),
    (error: unknown) => {
      assert.ok(error instanceof HostKeyInspectionError);
      assert.equal(error.code, "SSH_CONFIG_REJECTED");
      assert.equal(error.message.includes(paths.knownHostsFile), false);
      assert.equal("cause" in error, false);
      return true;
    },
  );
});

test("rejects invalid aliases, config output, result sizes, and path configuration", async () => {
  const paths = fixture();
  let calls = 0;
  const runCommand: HostKeyCommandRunner = () => {
    calls += 1;
    return Promise.resolve(result(0, "hostname one\nhostname two\nport 22\n"));
  };
  const service = inspector(runCommand, paths);
  await assert.rejects(service.inspect("-oProxyCommand=bad"), /alias is invalid/u);
  assert.equal(calls, 0);
  await assert.rejects(
    service.inspect("duplicate-hostname"),
    (error: unknown) =>
      error instanceof HostKeyInspectionError && error.code === "SSH_CONFIG_REJECTED",
  );

  const oversized = inspector(() =>
    Promise.resolve({
      exitCode: 0,
      stdout: Buffer.alloc(MAX_HOST_KEY_INSPECTION_OUTPUT_BYTES + 1, 0x41),
    }),
  );
  await assert.rejects(
    oversized.inspect("host"),
    (error: unknown) =>
      error instanceof HostKeyInspectionError && error.code === "SSH_CONFIG_REJECTED",
  );

  assert.throws(
    () =>
      new HostKeyInspector({
        sshExecutable: "relative/ssh",
        configFile: paths.configFile,
        knownHostsFile: paths.knownHostsFile,
      }),
    (error: unknown) =>
      error instanceof HostKeyInspectionError &&
      error.code === "INVALID_INSPECTION_CONFIGURATION",
  );
});

test(
  "uses the local OpenSSH tools for a hashed nonstandard-port entry",
  { timeout: 30_000 },
  async (t) => {
    const sshExecutable =
      process.platform === "win32"
        ? path.join(
            process.env.SystemRoot ?? String.raw`C:\Windows`,
            "System32",
            "OpenSSH",
            "ssh.exe",
          )
        : "/usr/bin/ssh";
    try {
      await access(sshExecutable);
      await access(
        path.join(
          path.dirname(sshExecutable),
          process.platform === "win32" ? "ssh-keygen.exe" : "ssh-keygen",
        ),
      );
    } catch {
      t.skip("OpenSSH client tools are unavailable");
      return;
    }

    const root = await mkdtemp(path.join(tmpdir(), "agent-ssh-host-key-real-"));
    t.after(() => rm(root, { recursive: true, force: true }));
    const configFile = path.join(root, "ssh_config");
    const knownHostsFile = path.join(root, "known_hosts");
    const lookupName = "[hashed.example.internal]:2222";
    const salt = Buffer.alloc(20, 0x2a);
    const hostHash = createHmac("sha1", salt).update(lookupName, "utf8").digest();
    const hashedHost = `|1|${salt.toString("base64")}|${hostHash.toString("base64")}`;
    const hostKey = keyBlob("ssh-ed25519", 8);
    await writeFile(
      configFile,
      [
        "Host inspected",
        "    HostName hashed.example.internal",
        "    Port 2222",
        "",
      ].join("\n"),
      "utf8",
    );
    await writeFile(
      knownHostsFile,
      `${line(hashedHost, "ssh-ed25519", hostKey)}\n`,
      "utf8",
    );

    const inspected = await new HostKeyInspector({
      sshExecutable,
      configFile,
      knownHostsFile,
    }).inspect("inspected");
    assert.deepEqual(inspected, [
      {
        keyType: "ssh-ed25519",
        fingerprintSha256: fingerprint(hostKey),
        trust: "host-key",
      },
    ]);
  },
);

test("does not cache failed host-key inspections", async () => {
  const paths = fixture();
  const hostKey = keyBlob("ssh-ed25519", 11);
  let configAttempts = 0;
  const instance = inspector((input) => {
    if (input.executable === paths.sshExecutable) {
      configAttempts += 1;
      return Promise.resolve(
        configAttempts === 1
          ? result(255)
          : result(0, "hostname retry.example.internal\nport 22\nhostkeyalias none\n"),
      );
    }
    return Promise.resolve(
      result(
        0,
        `${line("retry.example.internal", "ssh-ed25519", hostKey)}\n`,
      ),
    );
  }, paths);

  await assert.rejects(instance.inspect("retry-target"), HostKeyInspectionError);
  assert.deepEqual(await instance.inspect("retry-target"), [
    {
      keyType: "ssh-ed25519",
      fingerprintSha256: fingerprint(hostKey),
      trust: "host-key",
    },
  ]);
  assert.equal(configAttempts, 2);
});
