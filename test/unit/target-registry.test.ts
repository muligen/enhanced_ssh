import assert from "node:assert/strict";
import test from "node:test";

import { stringify } from "yaml";

import { parseConfigText } from "../../src/config/load-config.js";
import { TargetRegistry } from "../../src/core/target-registry.js";
import { GATEWAY_ERROR_CODES, GatewayError } from "../../src/shared/errors.js";

function registry(): TargetRegistry {
  const config = parseConfigText(
    stringify({
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
      transfer: {
        localRoots: {
          "legacy-workspace": "C:\\AgentSsh\\workspace",
        },
      },
      targets: {
        disabled: {
          sshAlias: "secret-disabled-host",
          enabled: false,
          policy: { mode: "deny", maxTimeoutMs: 10_000 },
        },
        alpha: {
          description: "Allowed host",
          sshAlias: "secret-internal-host",
          enabled: true,
          policy: {
            mode: "allow-list",
            allowedCommands: ["hostname", "uname -a", "(a+)+"],
            maxTimeoutMs: 30_000,
          },
        },
        full: {
          targetId: "t-11111111111111111111111111111111",
          previousAliases: ["managed-ssh", "old-full"],
          description: "Explicit full access host",
          sshAlias: "secret-full-access-host",
          platform: "windows",
          enabled: true,
          policy: {
            mode: "full-access",
            maxTimeoutMs: 20_000,
          },
        },
      },
    }),
  );
  return TargetRegistry.fromConfig(config);
}

function hasGatewayCode(code: string): (error: unknown) => boolean {
  return (error: unknown): boolean =>
    error instanceof GatewayError && error.code === code;
}

test("list is deterministic, immutable, and does not expose sshAlias", () => {
  const summaries = registry().list();

  assert.deepEqual(
    summaries.map((target) => target.alias),
    ["alpha", "disabled", "full"],
  );
  assert.equal(JSON.stringify(summaries).includes("sshAlias"), false);
  assert.equal(JSON.stringify(summaries).includes("secret-internal-host"), false);
  assert.equal(JSON.stringify(summaries).includes("allowedCommands"), false);
  assert.equal(JSON.stringify(summaries).includes("managed-ssh"), false);
  assert.equal(
    summaries.find((target) => target.alias === "full")?.targetId,
    "t-11111111111111111111111111111111",
  );
  assert.deepEqual(
    summaries.map(({ alias, connectionMode, transferMode, transferScope, transferRoots }) => ({
      alias,
      connectionMode,
      transferMode,
      transferScope,
      transferRoots,
    })),
    [
      {
        alias: "alpha",
        connectionMode: "openssh",
        transferMode: "deny",
        transferScope: "restricted",
        transferRoots: [],
      },
      {
        alias: "disabled",
        connectionMode: "openssh",
        transferMode: "deny",
        transferScope: "restricted",
        transferRoots: [],
      },
      {
        alias: "full",
        connectionMode: "openssh",
        transferMode: "bidirectional",
        transferScope: "all",
        transferRoots: [],
      },
    ],
  );
  assert.equal(Object.isFrozen(summaries), true);
  assert.equal(Object.isFrozen(summaries[0]), true);
});

test("require rejects unknown, malformed, and disabled aliases", () => {
  const targets = registry();

  assert.throws(
    () => targets.require("missing"),
    hasGatewayCode(GATEWAY_ERROR_CODES.targetNotFound),
  );
  assert.throws(
    () => targets.require("-oProxyCommand=bad"),
    hasGatewayCode(GATEWAY_ERROR_CODES.invalidParams),
  );
  assert.throws(
    () => targets.require("disabled"),
    hasGatewayCode(GATEWAY_ERROR_CODES.targetDisabled),
  );
});

test("stable IDs and historical aliases resolve without exposing alias history", () => {
  const targets = registry();

  for (const reference of [
    "full",
    "FULL",
    "managed-ssh",
    "old-full",
    "t-11111111111111111111111111111111",
  ]) {
    const target = targets.require(reference);
    assert.equal(target.alias, "full");
    assert.equal(target.targetId, "t-11111111111111111111111111111111");
  }

  assert.throws(
    () => targets.require("missing"),
    (error: unknown) => {
      assert.ok(error instanceof GatewayError);
      assert.equal(error.code, GATEWAY_ERROR_CODES.targetNotFound);
      assert.equal(error.details?.["candidates"], "alpha, disabled, full");
      assert.equal(JSON.stringify(error.details).includes("managed-ssh"), false);
      assert.equal(JSON.stringify(error.details).includes("secret-"), false);
      return true;
    },
  );
});

test("authorize applies allow-list and timeout policy", () => {
  const targets = registry();

  const authorized = targets.authorize("alpha", "uname -a", 5_000);
  assert.equal(authorized.target.sshAlias, "secret-internal-host");
  assert.equal(authorized.timeoutMs, 5_000);
  assert.equal(targets.authorize("alpha", "hostname").timeoutMs, 30_000);
  assert.equal(targets.authorize("alpha", "(a+)+").timeoutMs, 30_000);

  assert.throws(
    () => targets.authorize("alpha", "rm -rf /"),
    hasGatewayCode(GATEWAY_ERROR_CODES.commandDenied),
  );
  assert.throws(
    () => targets.authorize("alpha", "prefixhostname"),
    hasGatewayCode(GATEWAY_ERROR_CODES.commandDenied),
  );
  assert.throws(
    () => targets.authorize("alpha", "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"),
    hasGatewayCode(GATEWAY_ERROR_CODES.commandDenied),
  );
  assert.throws(
    () => targets.authorize("alpha", "hostname\nwhoami"),
    hasGatewayCode(GATEWAY_ERROR_CODES.invalidParams),
  );
  assert.throws(
    () => targets.authorize("alpha", "hostname", 30_001),
    hasGatewayCode(GATEWAY_ERROR_CODES.invalidParams),
  );
});

test("deny policy never authorizes commands", () => {
  const targets = registry();
  assert.throws(
    () => targets.authorize("disabled", "hostname"),
    hasGatewayCode(GATEWAY_ERROR_CODES.targetDisabled),
  );
});

test("full-access authorizes arbitrary single-line commands but preserves bounds", () => {
  const targets = registry();
  const command = 'powershell -NoProfile -Command "Get-Process | Select-Object -First 1"';

  const authorized = targets.authorize("full", command, 10_000);
  assert.equal(authorized.target.policyMode, "full-access");
  assert.equal(authorized.target.platform, "windows");
  assert.equal(authorized.target.sshAlias, "secret-full-access-host");
  assert.equal(authorized.timeoutMs, 10_000);

  assert.throws(
    () => targets.authorize("full", "hostname\nwhoami"),
    hasGatewayCode(GATEWAY_ERROR_CODES.invalidParams),
  );
  assert.throws(
    () => targets.authorize("full", "hostname", 20_001),
    hasGatewayCode(GATEWAY_ERROR_CODES.invalidParams),
  );
});

test("full-access authorizes every transfer direction and optional rooted compatibility", () => {
  const targets = registry();

  for (const direction of ["upload", "download", "sync"] as const) {
    const unrestricted = targets.authorizeTransfer("full", direction, undefined);
    assert.equal(unrestricted.target.transferMode, "bidirectional");
    assert.equal(unrestricted.scope, "all");
    assert.equal(unrestricted.localRootPath, undefined);
    assert.deepEqual(unrestricted.remoteRoots, []);
  }

  const rooted = targets.authorizeTransfer(
    "full",
    "upload",
    "legacy-workspace",
    10_000,
  );
  assert.equal(rooted.scope, "all");
  assert.equal(rooted.localRootPath, "C:\\AgentSsh\\workspace");
  assert.equal(rooted.timeoutMs, 10_000);

  assert.throws(
    () => targets.authorizeTransfer("full", "upload", "missing-root"),
    hasGatewayCode(GATEWAY_ERROR_CODES.configInvalid),
  );
  assert.throws(
    () => targets.authorizeTransfer("alpha", "upload", undefined),
    hasGatewayCode(GATEWAY_ERROR_CODES.transferDenied),
  );
});

test("AccessClient full-access exposes unrestricted bidirectional transfer", () => {
  const targets = new TargetRegistry({
    shared: {
      sshAlias: "accessclient-internal",
      connection: {
        mode: "accessclient-share",
        gatewayHost: "gateway.example.test",
        gatewayPort: 22,
        gatewayUsername: "portal-user",
        expectedHostname: "target-host",
      },
      platform: "linux",
      enabled: true,
      policy: { mode: "full-access", maxTimeoutMs: 60_000 },
    },
  });

  const summary = targets.list()[0]!;
  assert.equal(summary.connectionMode, "accessclient-share");
  assert.equal(summary.transferMode, "bidirectional");
  assert.equal(summary.transferScope, "all");
  assert.equal(summary.maxTimeoutMs, 60_000);
  assert.equal(summary.maxTransferTimeoutMs, 3_600_000);
  for (const direction of ["upload", "download", "sync"] as const) {
    const authorization = targets.authorizeTransfer(
      "shared",
      direction,
      undefined,
      3_600_000,
    );
    assert.equal(authorization.scope, "all");
    assert.equal(authorization.timeoutMs, 3_600_000);
  }
  assert.throws(
    () => targets.authorize("shared", "hostname", 60_001),
    hasGatewayCode(GATEWAY_ERROR_CODES.invalidParams),
  );
});

test("structured execution is restricted to full-access targets", () => {
  const targets = registry();

  const defaultTimeout = targets.authorizeStructured("full");
  assert.equal(defaultTimeout.target.sshAlias, "secret-full-access-host");
  assert.equal(defaultTimeout.target.platform, "windows");
  assert.equal(defaultTimeout.target.policyMode, "full-access");
  assert.equal(defaultTimeout.timeoutMs, 20_000);
  assert.equal(targets.authorizeStructured("full", 4_000).timeoutMs, 4_000);

  assert.throws(
    () => targets.authorizeStructured("alpha"),
    hasGatewayCode(GATEWAY_ERROR_CODES.commandDenied),
  );
  assert.throws(
    () => targets.authorizeStructured("disabled"),
    hasGatewayCode(GATEWAY_ERROR_CODES.targetDisabled),
  );
  assert.throws(
    () => targets.authorizeStructured("missing"),
    hasGatewayCode(GATEWAY_ERROR_CODES.targetNotFound),
  );
  for (const timeoutMs of [0, 20_001, 1.5]) {
    assert.throws(
      () => targets.authorizeStructured("full", timeoutMs),
      hasGatewayCode(GATEWAY_ERROR_CODES.invalidParams),
    );
  }

  const denied = new TargetRegistry({
    denied: {
      sshAlias: "structured-denied-host",
      platform: "linux",
      enabled: true,
      policy: { mode: "deny", maxTimeoutMs: 10_000 },
      transfer: {
        mode: "deny",
        localRoots: [],
        remoteRoots: [],
        maxFileBytes: 1,
        maxTotalBytes: 1,
        maxFiles: 1,
        maxTimeoutMs: 10_000,
      },
    },
  });
  assert.throws(
    () => denied.authorizeStructured("denied"),
    hasGatewayCode(GATEWAY_ERROR_CODES.commandDenied),
  );
});

test("connectivity checks bypass command policy but require enabled targets", () => {
  const targets = new TargetRegistry({
    denied: {
      sshAlias: "probe-denied-host",
      platform: "macos",
      enabled: true,
      policy: { mode: "deny", maxTimeoutMs: 30_000 },
    },
    short: {
      sshAlias: "probe-short-host",
      platform: "linux",
      enabled: true,
      policy: {
        mode: "allow-list",
        allowedCommands: ["echo ok"],
        maxTimeoutMs: 4_000,
      },
    },
    accessClient: {
      sshAlias: "probe-accessclient-host",
      connection: {
        mode: "accessclient-share",
        gatewayHost: "gate.example.test",
        gatewayPort: 22,
        gatewayUsername: "portal-user",
        expectedHostname: "target-host",
      },
      platform: "linux",
      enabled: true,
      policy: {
        mode: "allow-list",
        allowedCommands: ["hostname"],
        maxTimeoutMs: 60_000,
      },
    },
    disabled: {
      sshAlias: "probe-disabled-host",
      platform: "windows",
      enabled: false,
      policy: { mode: "full-access", maxTimeoutMs: 30_000 },
    },
  });

  const denied = targets.authorizeCheck("denied");
  assert.equal(denied.target.sshAlias, "probe-denied-host");
  assert.equal(denied.target.policyMode, "deny");
  assert.equal(denied.timeoutMs, 15_000);
  assert.equal(targets.authorizeCheck("accessClient").timeoutMs, 30_000);
  assert.equal(targets.authorizeCheck("short").timeoutMs, 4_000);
  assert.throws(
    () => targets.authorizeCheck("disabled"),
    hasGatewayCode(GATEWAY_ERROR_CODES.targetDisabled),
  );
  assert.throws(
    () => targets.authorizeCheck("missing"),
    hasGatewayCode(GATEWAY_ERROR_CODES.targetNotFound),
  );
});
