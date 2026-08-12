import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { stringify } from "yaml";

import {
  loadConfig,
  parseConfigText,
} from "../../src/config/load-config.js";
import { GATEWAY_ERROR_CODES, GatewayError } from "../../src/shared/errors.js";

function validConfig(): Record<string, unknown> {
  return {
    version: 1,
    runtime: {
      dataDirectory: "C:\\ProgramData\\agent-ssh-gateway",
      inlineOutputBytes: 65_536,
      maxStoredOutputBytes: 10_485_760,
      maxTotalRetainedOutputBytes: 104_857_600,
      maxAuditBytes: 104_857_600,
      maxRetainedOutputs: 1_024,
      outputTtlSeconds: 900,
      maxConcurrentExecutions: 4,
    },
    ssh: {
      executable: "C:\\Windows\\System32\\OpenSSH\\ssh.exe",
      configFile: "C:\\ProgramData\\agent-ssh-gateway\\ssh_config",
      knownHostsFile: "C:\\ProgramData\\agent-ssh-gateway\\known_hosts",
      connectTimeoutSeconds: 15,
    },
    targets: {
      "dev-linux": {
        description: "Development Linux host",
        sshAlias: "dev-linux-internal",
        enabled: true,
        policy: {
          mode: "allow-list",
          allowedCommands: ["hostname", "uname -a"],
          maxTimeoutMs: 30_000,
        },
      },
    },
  };
}

function isConfigError(error: unknown): boolean {
  return (
    error instanceof GatewayError &&
    error.code === GATEWAY_ERROR_CODES.configInvalid
  );
}

test("parseConfigText accepts and freezes a valid strict configuration", () => {
  const config = parseConfigText(stringify(validConfig()));

  assert.equal(config.version, 1);
  assert.equal(config.targets["dev-linux"]?.sshAlias, "dev-linux-internal");
  assert.equal(config.targets["dev-linux"]?.platform, "linux");
  assert.equal(Object.isFrozen(config), true);
  assert.equal(Object.isFrozen(config.targets["dev-linux"]), true);
});

test("parseConfigText validates explicit target platforms", () => {
  for (const platform of ["windows", "linux", "macos"] as const) {
    const input = validConfig();
    const targets = input["targets"] as Record<string, Record<string, unknown>>;
    const target = targets["dev-linux"];
    assert.ok(target);
    target["platform"] = platform;
    assert.equal(
      parseConfigText(stringify(input)).targets["dev-linux"]?.platform,
      platform,
    );
  }

  const invalid = validConfig();
  const targets = invalid["targets"] as Record<string, Record<string, unknown>>;
  const target = targets["dev-linux"];
  assert.ok(target);
  target["platform"] = "freebsd";
  assert.throws(() => parseConfigText(stringify(invalid)), isConfigError);
});

test("accepts a strict AccessClient shared-session connection", () => {
  const input = validConfig();
  input["putty"] = {
    executable: String.raw`C:\Program Files\PuTTY\plink.exe`,
  };
  const targets = input["targets"] as Record<
    string,
    Record<string, unknown>
  >;
  targets["dev-linux"]!["connection"] = {
    mode: "accessclient-share",
    gatewayHost: "123.207.128.188",
    gatewayPort: 22,
    gatewayUsername: "portal/172.24.251.37/kxjdev",
    sharingHost: "172.24.251.37",
    sharingPort: 2_222,
    expectedHostname: "test-ai-agent",
  };

  const parsed = parseConfigText(stringify(input));
  assert.equal(
    parsed.putty?.executable,
    String.raw`C:\Program Files\PuTTY\plink.exe`,
  );
  assert.deepEqual(parsed.targets["dev-linux"]?.connection, {
    mode: "accessclient-share",
    gatewayHost: "123.207.128.188",
    gatewayPort: 22,
    gatewayUsername: "portal/172.24.251.37/kxjdev",
    sharingHost: "172.24.251.37",
    sharingPort: 2_222,
    expectedHostname: "test-ai-agent",
  });
  assert.equal(parsed.targets["dev-linux"]?.transfer.mode, "deny");
});

test("keeps legacy AccessClient connections without a sharing host loadable", () => {
  const input = validConfig();
  input["putty"] = {
    executable: String.raw`C:\Program Files\PuTTY\plink.exe`,
  };
  const targets = input["targets"] as Record<
    string,
    Record<string, unknown>
  >;
  targets["dev-linux"]!["connection"] = {
    mode: "accessclient-share",
    gatewayHost: "bastion.example.internal",
    gatewayPort: 22,
    gatewayUsername: "portal-user",
    expectedHostname: "test-ai-agent",
  };

  const connection = parseConfigText(stringify(input)).targets["dev-linux"]
    ?.connection;
  assert.equal(connection?.mode, "accessclient-share");
  if (connection?.mode === "accessclient-share") {
    assert.equal(connection.sharingHost, undefined);
    assert.equal(connection.sharingPort, undefined);
  }
});

test("AccessClient connections require Plink and deny ambiguous or unsafe settings", () => {
  const accessClientConfig = (): Record<string, unknown> => {
    const input = validConfig();
    input["putty"] = {
      executable: String.raw`C:\Program Files\PuTTY\plink.exe`,
    };
    const targets = input["targets"] as Record<
      string,
      Record<string, unknown>
    >;
    targets["dev-linux"]!["connection"] = {
      mode: "accessclient-share",
      gatewayHost: "bastion.example.internal",
      gatewayPort: 22,
      gatewayUsername: "portal/172.24.251.37/kxjdev",
      expectedHostname: "test-ai-agent",
    };
    return input;
  };

  const missingPlink = accessClientConfig();
  delete missingPlink["putty"];
  assert.throws(
    () => parseConfigText(stringify(missingPlink)),
    isConfigError,
  );

  const enabledTransfer = accessClientConfig();
  enabledTransfer["transfer"] = {
    localRoots: { workspace: String.raw`C:\workspace` },
  };
  const transferTargets = enabledTransfer["targets"] as Record<
    string,
    Record<string, unknown>
  >;
  transferTargets["dev-linux"]!["transfer"] = {
    mode: "bidirectional",
    localRoots: ["workspace"],
    remoteRoots: ["/srv/workspace"],
  };
  assert.throws(
    () => parseConfigText(stringify(enabledTransfer)),
    isConfigError,
  );

  for (const mutate of [
    (input: Record<string, unknown>): void => {
      const putty = input["putty"] as Record<string, unknown>;
      putty["arguments"] = ["-pw", "secret"];
    },
    (input: Record<string, unknown>): void => {
      const targets = input["targets"] as Record<
        string,
        Record<string, unknown>
      >;
      const connection = targets["dev-linux"]!["connection"] as Record<
        string,
        unknown
      >;
      connection["password"] = "secret";
    },
    (input: Record<string, unknown>): void => {
      const targets = input["targets"] as Record<
        string,
        Record<string, unknown>
      >;
      const connection = targets["dev-linux"]!["connection"] as Record<
        string,
        unknown
      >;
      connection["gatewayHost"] = "-proxycmd";
    },
    (input: Record<string, unknown>): void => {
      const targets = input["targets"] as Record<
        string,
        Record<string, unknown>
      >;
      const connection = targets["dev-linux"]!["connection"] as Record<
        string,
        unknown
      >;
      connection["gatewayUsername"] = "portal\n-pw secret";
    },
    (input: Record<string, unknown>): void => {
      const targets = input["targets"] as Record<
        string,
        Record<string, unknown>
      >;
      const connection = targets["dev-linux"]!["connection"] as Record<
        string,
        unknown
      >;
      connection["sharingPort"] = 2_222;
    },
  ]) {
    const unsafe = accessClientConfig();
    mutate(unsafe);
    assert.throws(() => parseConfigText(stringify(unsafe)), isConfigError);
  }
});

test("AccessClient targets have unique effective PuTTY sharing identities", () => {
  const baseAccessClientConfig = (): Record<string, unknown> => {
    const input = validConfig();
    input["putty"] = {
      executable: String.raw`C:\Program Files\PuTTY\plink.exe`,
    };
    const targets = input["targets"] as Record<
      string,
      Record<string, unknown>
    >;
    targets["dev-linux"]!["connection"] = {
      mode: "accessclient-share",
      gatewayHost: "target.example.internal",
      gatewayPort: 2_222,
      gatewayUsername: "portal-user",
      expectedHostname: "dev-linux",
    };
    targets["second-target"] = {
      ...structuredClone(targets["dev-linux"]!),
      sshAlias: "second-target-internal",
      connection: {
        mode: "accessclient-share",
        gatewayHost: "bastion.example.internal",
        gatewayPort: 22,
        gatewayUsername: "portal-user",
        sharingHost: "target.example.internal",
        sharingPort: 2_222,
        expectedHostname: "second-target",
      },
    };
    return input;
  };

  assert.throws(
    () => parseConfigText(stringify(baseAccessClientConfig())),
    isConfigError,
    "legacy physical host and port must collide with an equal explicit identity",
  );

  const defaultPortCollision = baseAccessClientConfig();
  const defaultPortTargets = defaultPortCollision["targets"] as Record<
    string,
    Record<string, unknown>
  >;
  defaultPortTargets["dev-linux"]!["connection"] = {
    mode: "accessclient-share",
    gatewayHost: "first-bastion.example.internal",
    gatewayPort: 2_222,
    gatewayUsername: "portal-user",
    sharingHost: "target.example.internal",
    expectedHostname: "dev-linux",
  };
  const secondConnection = defaultPortTargets["second-target"]![
    "connection"
  ] as Record<string, unknown>;
  secondConnection["sharingPort"] = 22;
  assert.throws(
    () => parseConfigText(stringify(defaultPortCollision)),
    isConfigError,
    "an explicit sharing host without a port must use PuTTY's logical port 22",
  );

  secondConnection["sharingPort"] = 2_223;
  assert.doesNotThrow(() => parseConfigText(stringify(defaultPortCollision)));
});

test("target identities accept stable IDs and reject ambiguous references", () => {
  const identified = validConfig();
  const identifiedTargets = identified["targets"] as Record<
    string,
    Record<string, unknown>
  >;
  identifiedTargets["dev-linux"]!["targetId"] =
    "t-11111111111111111111111111111111";
  identifiedTargets["dev-linux"]!["previousAliases"] = [
    "managed-ssh",
    "old-dev-linux",
  ];
  const parsed = parseConfigText(stringify(identified));
  assert.equal(
    parsed.targets["dev-linux"]?.targetId,
    "t-11111111111111111111111111111111",
  );
  assert.deepEqual(parsed.targets["dev-linux"]?.previousAliases, [
    "managed-ssh",
    "old-dev-linux",
  ]);

  for (const conflictingReference of [
    "DEV-LINUX",
    "t-11111111111111111111111111111111",
    "managed-ssh",
  ]) {
    const input = structuredClone(identified);
    const targets = input["targets"] as Record<string, Record<string, unknown>>;
    targets[conflictingReference] = {
      ...targets["dev-linux"]!,
      targetId: "t-22222222222222222222222222222222",
      previousAliases: [],
    };
    assert.throws(() => parseConfigText(stringify(input)), isConfigError);
  }
});

test("parseConfigText rejects duplicate internal SSH aliases", () => {
  const input = validConfig();
  const targets = input["targets"] as Record<
    string,
    Record<string, unknown>
  >;
  targets["second-target"] = {
    ...targets["dev-linux"]!,
    sshAlias: "DEV-LINUX-INTERNAL",
  };

  assert.throws(() => parseConfigText(stringify(input)), isConfigError);
});

test("parseConfigText accepts only the strict full-access policy shape", () => {
  const fullAccess = validConfig();
  const targets = fullAccess["targets"] as Record<
    string,
    Record<string, unknown>
  >;
  const target = targets["dev-linux"];
  assert.ok(target);
  target["policy"] = { mode: "full-access", maxTimeoutMs: 30_000 };

  const parsed = parseConfigText(stringify(fullAccess));
  assert.deepEqual(parsed.targets["dev-linux"]?.policy, {
    mode: "full-access",
    maxTimeoutMs: 30_000,
  });

  const ambiguous = validConfig();
  const ambiguousTargets = ambiguous["targets"] as Record<
    string,
    Record<string, unknown>
  >;
  const ambiguousTarget = ambiguousTargets["dev-linux"];
  assert.ok(ambiguousTarget);
  ambiguousTarget["policy"] = {
    mode: "full-access",
    allowedCommands: ["hostname"],
    maxTimeoutMs: 30_000,
  };
  assert.throws(() => parseConfigText(stringify(ambiguous)), isConfigError);
});

test("enabled transfer requires roots for every command policy", () => {
  for (const policy of [
    {
      mode: "allow-list",
      allowedCommands: ["hostname"],
      maxTimeoutMs: 30_000,
    },
    { mode: "full-access", maxTimeoutMs: 30_000 },
  ]) {
    const input = validConfig();
    const targets = input["targets"] as Record<
      string,
      Record<string, unknown>
    >;
    const target = targets["dev-linux"];
    assert.ok(target);
    target["policy"] = policy;
    target["transfer"] = {
      mode: "bidirectional",
      localRoots: [],
      remoteRoots: [],
      maxTimeoutMs: 654_321,
    };
    assert.throws(() => parseConfigText(stringify(input)), isConfigError);
  }
});

test("transfer roots may be filesystem roots while runtime storage may not", () => {
  const transferAtFilesystemRoot = validConfig();
  transferAtFilesystemRoot["transfer"] = {
    localRoots: { "system-drive": "C:\\", "posix-root": "/" },
  };
  const targets = transferAtFilesystemRoot["targets"] as Record<
    string,
    Record<string, unknown>
  >;
  const target = targets["dev-linux"];
  assert.ok(target);
  target["transfer"] = {
    mode: "bidirectional",
    localRoots: ["system-drive"],
    remoteRoots: ["/"],
  };

  const parsed = parseConfigText(stringify(transferAtFilesystemRoot));
  assert.equal(parsed.transfer.localRoots["system-drive"], "C:\\");
  assert.equal(parsed.transfer.localRoots["posix-root"], "/");
  assert.deepEqual(parsed.targets["dev-linux"]?.transfer.localRoots, [
    "system-drive",
  ]);

  const runtimeAtFilesystemRoot = validConfig();
  const runtime = runtimeAtFilesystemRoot["runtime"] as Record<string, unknown>;
  runtime["dataDirectory"] = "C:\\";
  assert.throws(
    () => parseConfigText(stringify(runtimeAtFilesystemRoot)),
    isConfigError,
  );
});

test("transfer roots reject UNC, network, and device path syntax", () => {
  for (const unsafeRoot of [
    String.raw`\\server\share`,
    "//server/share",
    String.raw`\\?\C:\device`,
    String.raw`\??\C:\device`,
  ]) {
    const input = validConfig();
    input["transfer"] = { localRoots: { unsafe: unsafeRoot } };
    assert.throws(
      () => parseConfigText(stringify(input)),
      isConfigError,
      unsafeRoot,
    );
  }
});

test("parseConfigText rejects duplicate YAML keys", () => {
  const source = `${stringify(validConfig())}\nversion: 1\n`;
  assert.throws(() => parseConfigText(source), isConfigError);
});

test("parseConfigText rejects unknown fields at every policy boundary", () => {
  const topLevel = validConfig();
  topLevel["unexpected"] = true;
  assert.throws(() => parseConfigText(stringify(topLevel)), isConfigError);

  const nested = validConfig();
  const targets = nested["targets"] as Record<string, Record<string, unknown>>;
  const target = targets["dev-linux"];
  assert.ok(target);
  target["username"] = "root";
  assert.throws(() => parseConfigText(stringify(nested)), isConfigError);

  const policyConfig = validConfig();
  const policyTargets = policyConfig["targets"] as Record<
    string,
    Record<string, unknown>
  >;
  const policyTarget = policyTargets["dev-linux"];
  assert.ok(policyTarget);
  const policy = policyTarget["policy"] as Record<string, unknown>;
  policy["shell"] = true;
  assert.throws(() => parseConfigText(stringify(policyConfig)), isConfigError);

  const arbitrarySshArguments = validConfig();
  const ssh = arbitrarySshArguments["ssh"] as Record<string, unknown>;
  ssh["executableArguments"] = ["-o", "StrictHostKeyChecking=no"];
  assert.throws(
    () => parseConfigText(stringify(arbitrarySshArguments)),
    isConfigError,
  );
});

test("parseConfigText rejects unsafe aliases, unsafe commands, and bounds", () => {
  const unsafeAlias = validConfig();
  const targets = unsafeAlias["targets"] as Record<string, unknown>;
  targets["-oStrictHostKeyChecking=no"] = targets["dev-linux"];
  delete targets["dev-linux"];
  assert.throws(() => parseConfigText(stringify(unsafeAlias)), isConfigError);

  const unsafeCommand = validConfig();
  const commandTargets = unsafeCommand["targets"] as Record<
    string,
    Record<string, unknown>
  >;
  const commandTarget = commandTargets["dev-linux"];
  assert.ok(commandTarget);
  const policy = commandTarget["policy"] as Record<string, unknown>;
  policy["allowedCommands"] = ["hostname\nwhoami"];
  assert.throws(() => parseConfigText(stringify(unsafeCommand)), isConfigError);

  const duplicateCommands = validConfig();
  const duplicateTargets = duplicateCommands["targets"] as Record<
    string,
    Record<string, unknown>
  >;
  const duplicateTarget = duplicateTargets["dev-linux"];
  assert.ok(duplicateTarget);
  const duplicatePolicy = duplicateTarget["policy"] as Record<string, unknown>;
  duplicatePolicy["allowedCommands"] = ["hostname", "hostname"];
  assert.throws(
    () => parseConfigText(stringify(duplicateCommands)),
    isConfigError,
  );

  const invalidBounds = validConfig();
  const runtime = invalidBounds["runtime"] as Record<string, unknown>;
  runtime["inlineOutputBytes"] = 100_000;
  runtime["maxStoredOutputBytes"] = 50_000;
  runtime["maxTotalRetainedOutputBytes"] = 40_000;
  assert.throws(() => parseConfigText(stringify(invalidBounds)), isConfigError);

  const rootDataDirectory = validConfig();
  const rootRuntime = rootDataDirectory["runtime"] as Record<string, unknown>;
  rootRuntime["dataDirectory"] = "C:\\";
  assert.throws(
    () => parseConfigText(stringify(rootDataDirectory)),
    isConfigError,
  );

  for (const field of ["configFile", "knownHostsFile"] as const) {
    const environmentPath = validConfig();
    const ssh = environmentPath["ssh"] as Record<string, unknown>;
    ssh[field] = "C:\\literal\\${TEMP}\\ssh-file";
    assert.throws(
      () => parseConfigText(stringify(environmentPath)),
      isConfigError,
    );
  }
});

test("loadConfig reads regular files and rejects directories", async () => {
  const temporaryDirectory = await mkdtemp(
    path.join(os.tmpdir(), "agent-ssh-config-test-"),
  );
  try {
    const configPath = path.join(temporaryDirectory, "gateway.yaml");
    await writeFile(configPath, stringify(validConfig()), "utf8");
    const config = await loadConfig(configPath);
    assert.equal(config.version, 1);

    await assert.rejects(loadConfig(temporaryDirectory), isConfigError);
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
});
