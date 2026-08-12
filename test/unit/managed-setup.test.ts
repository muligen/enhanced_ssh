import assert from "node:assert/strict";
import test from "node:test";

import {
  MANAGED_PLATFORM_COMMANDS,
  MANAGED_PLATFORMS,
  currentManagedSshProfileSchema,
  managedSshFleetProfileSchema,
  managedSshProfileSchema,
  type CurrentManagedSshProfile,
  type ManagedSshFleetProfile,
} from "../../src/test-ui/managed.js";

function validProfile(): CurrentManagedSshProfile {
  return {
    target: {
      host: "target.example.internal",
      port: 22,
      username: "automation_user",
      identityFile: String.raw`C:\Users\operator\.ssh\target_ed25519`,
    },
    knownHostsFile: String.raw`C:\Users\operator\.ssh\known_hosts`,
    platform: "linux",
    policyMode: "allow-list",
    allowedCommands: ["hostname", "uname -a"],
  };
}

function cloneProfile(): Record<string, unknown> {
  return structuredClone(validProfile()) as unknown as Record<string, unknown>;
}

function validFleetProfile(): ManagedSshFleetProfile {
  return {
    version: 3,
    targets: {
      "dev-linux": {
        description: "Development Linux host",
        enabled: true,
        target: {
          host: validProfile().target.host,
          port: validProfile().target.port,
          username: validProfile().target.username,
          keyId: "k-11111111111111111111111111111111",
        },
        knownHostsFile: validProfile().knownHostsFile,
        platform: "linux",
        policyMode: "allow-list",
        allowedCommands: ["hostname", "systemctl status api.service"],
        maxTimeoutMs: 45_000,
      },
    },
  };
}

function validAccessClientFleetProfile(): Record<string, unknown> {
  return {
    version: 3,
    accessClient: {
      plinkExecutable: String.raw`C:\Program Files\PuTTY\plink.exe`,
    },
    targets: {
      "gpu-build": {
        description: "GPU build host",
        enabled: true,
        connectionMode: "accessclient-share",
        target: {
          host: "172.24.251.37",
          port: 2_222,
          username: "build-user",
        },
        accessClient: {
          gatewayHost: "bastion.example.internal",
          gatewayPort: 22,
          gatewayUsername: "portal/172.24.251.37/build-user",
          sharingHost: "172.24.251.37",
          sharingPort: 2_222,
          expectedHostname: "gpu-build",
        },
        platform: "windows",
        policyMode: "full-access",
        allowedCommands: [],
        maxTimeoutMs: 45_000,
        transferMode: "deny",
      },
    },
  };
}

test("managed profile accepts strict target and optional bastion endpoints", () => {
  const profile = validProfile();
  const withBastion = {
    ...profile,
    target: { ...profile.target, host: "2001:db8::20", port: 65_535 },
    bastion: {
      host: "bastion.example.internal",
      port: 2_222,
      username: "jump-user",
      identityFile: String.raw`C:\Users\operator\.ssh\bastion_ed25519`,
    },
    allowedCommands: [...MANAGED_PLATFORM_COMMANDS.linux],
  };

  assert.deepEqual(managedSshProfileSchema.parse(withBastion), withBastion);
  assert.equal(managedSshProfileSchema.safeParse(profile).success, true);
});

test("managed profile accepts portal-routed SSH usernames", () => {
  const profile = validProfile();
  profile.target.username = "portal.user/192.0.2.24/Administrator";
  profile.bastion = {
    host: "bastion.example.internal",
    port: 22,
    username: "ops-user/198.51.100.8/root_user",
    identityFile: String.raw`C:\Users\operator\.ssh\bastion_ed25519`,
  };

  assert.deepEqual(managedSshProfileSchema.parse(profile), profile);

  const fleet = validFleetProfile();
  fleet.targets["dev-linux"]!.target.username =
    "portal.user/192.0.2.24/Administrator";
  assert.deepEqual(managedSshFleetProfileSchema.parse(fleet), fleet);
});

test("managed AccessClient profiles preserve ports and reject ambiguous shares", () => {
  const fleet = validAccessClientFleetProfile();
  assert.deepEqual(managedSshFleetProfileSchema.parse(fleet), fleet);

  const portWithoutHost = structuredClone(fleet);
  const portWithoutHostTargets = portWithoutHost["targets"] as Record<
    string,
    Record<string, unknown>
  >;
  const portWithoutHostSession = portWithoutHostTargets["gpu-build"]![
    "accessClient"
  ] as Record<string, unknown>;
  delete portWithoutHostSession["sharingHost"];
  assert.equal(
    managedSshFleetProfileSchema.safeParse(portWithoutHost).success,
    false,
  );

  const duplicate = structuredClone(fleet);
  const duplicateTargets = duplicate["targets"] as Record<
    string,
    Record<string, unknown>
  >;
  duplicateTargets["second-build"] = structuredClone(
    duplicateTargets["gpu-build"]!,
  );
  const duplicateSession = duplicateTargets["second-build"]![
    "accessClient"
  ] as Record<string, unknown>;
  duplicateSession["gatewayHost"] = "second-bastion.example.internal";
  assert.equal(managedSshFleetProfileSchema.safeParse(duplicate).success, false);

  duplicateSession["sharingPort"] = 2_223;
  assert.equal(managedSshFleetProfileSchema.safeParse(duplicate).success, true);
});

test("managed profile rejects malformed portal-routed SSH usernames", () => {
  const invalidUsernames = [
    "portal/system",
    "portal//system",
    "/192.0.2.24/system",
    "portal/192.0.2.24/",
    "portal/192.0.2.24/system/extra",
    "portal/not-an-ip/system",
    "portal/2001:db8::24/system",
    "portal user/192.0.2.24/system",
    "portal/192.0.2.24/system user",
    "portal/192.0.2.24/system\nLocalCommand",
  ];

  for (const username of invalidUsernames) {
    const profile = validProfile();
    profile.target.username = username;
    const result = managedSshProfileSchema.safeParse(profile);
    assert.equal(result.success, false, username);
    if (!result.success) {
      assert.match(result.error.issues[0]?.message ?? "", /portalUser\/targetIPv4\/systemUser/u);
    }
  }
});

test("managed profile accepts platform presets and preserves legacy revisions", () => {
  for (const platform of MANAGED_PLATFORMS) {
    const profile = {
      ...validProfile(),
      platform,
      allowedCommands: [...MANAGED_PLATFORM_COMMANDS[platform]],
    };
    assert.deepEqual(managedSshProfileSchema.parse(profile), profile);
  }

  const legacy = { ...validProfile() } as Record<string, unknown>;
  delete legacy.platform;
  delete legacy.policyMode;
  assert.deepEqual(managedSshProfileSchema.parse(legacy), legacy);
  assert.equal(currentManagedSshProfileSchema.safeParse(legacy).success, false);
});

test("managed profile accepts explicit full access only without allow-list commands", () => {
  const fullAccess = {
    ...validProfile(),
    platform: "windows" as const,
    policyMode: "full-access" as const,
    allowedCommands: [],
  };
  assert.deepEqual(managedSshProfileSchema.parse(fullAccess), fullAccess);

  assert.equal(
    managedSshProfileSchema.safeParse({
      ...fullAccess,
      allowedCommands: ["hostname"],
    }).success,
    false,
  );
  assert.equal(
    managedSshProfileSchema.safeParse({
      ...validProfile(),
      policyMode: "full-access",
    }).success,
    false,
  );
});

test("managed profile rejects host, user, and path injection", () => {
  const mutations: Array<(profile: Record<string, unknown>) => void> = [
    (profile) => endpoint(profile).host = "server\nProxyCommand calc.exe",
    (profile) => endpoint(profile).host = "server name",
    (profile) => endpoint(profile).host = "-oProxyCommand=calc.exe",
    (profile) => endpoint(profile).host = "server.example.",
    (profile) => endpoint(profile).username = "root\nLocalCommand calc.exe",
    (profile) => endpoint(profile).username = "-root",
    (profile) => endpoint(profile).identityFile = "relative\\id_ed25519",
    (profile) =>
      endpoint(profile).identityFile = String.raw`\\server\share\id_ed25519`,
    (profile) => endpoint(profile).identityFile = "//server/share/id_ed25519",
    (profile) =>
      endpoint(profile).identityFile = String.raw`\\?\C:\keys\id_ed25519`,
    (profile) =>
      endpoint(profile).identityFile = String.raw`\??\C:\keys\id_ed25519`,
    (profile) => endpoint(profile).identityFile = String.raw`C:\keys\bad"key`,
    (profile) => endpoint(profile).identityFile = String.raw`C:\${TEMP}\id_ed25519`,
    (profile) => profile.knownHostsFile = "relative\\known_hosts",
    (profile) => profile.knownHostsFile = String.raw`C:\${TEMP}\known_hosts`,
  ];

  for (const mutate of mutations) {
    const profile = cloneProfile();
    mutate(profile);
    assert.equal(
      managedSshProfileSchema.safeParse(profile).success,
      false,
      JSON.stringify(profile),
    );
  }
});

test("managed profile enforces port, command, and strict object boundaries", () => {
  const invalidProfiles: Record<string, unknown>[] = [];

  for (const port of [0, 65_536, 22.5]) {
    const profile = cloneProfile();
    endpoint(profile).port = port;
    invalidProfiles.push(profile);
  }

  for (const allowedCommands of [
    [],
    ["hostname", "hostname"],
    ["hostname", "  "],
    ["hostname", "whoami\nshutdown"],
    ["hostname", "whoami\0shutdown"],
  ]) {
    const profile = cloneProfile();
    profile.allowedCommands = allowedCommands;
    invalidProfiles.push(profile);
  }

  const unknownTopLevel = cloneProfile();
  unknownTopLevel.privateKey = "secret";
  invalidProfiles.push(unknownTopLevel);

  const unknownEndpointField = cloneProfile();
  endpoint(unknownEndpointField).proxyCommand = "calc.exe";
  invalidProfiles.push(unknownEndpointField);

  const unknownBastionField = cloneProfile();
  unknownBastionField.bastion = {
    host: "bastion.example.internal",
    port: 22,
    username: "jump",
    identityFile: String.raw`C:\keys\jump_ed25519`,
    localCommand: "calc.exe",
  };
  invalidProfiles.push(unknownBastionField);

  const unknownPlatform = cloneProfile();
  unknownPlatform.platform = "freebsd";
  invalidProfiles.push(unknownPlatform);

  const unknownPolicy = cloneProfile();
  unknownPolicy.policyMode = "allow-all";
  invalidProfiles.push(unknownPolicy);

  for (const profile of invalidProfiles) {
    assert.equal(
      managedSshProfileSchema.safeParse(profile).success,
      false,
      JSON.stringify(profile),
    );
  }
});

test("fleet v3 accepts multiple strict targets and arbitrary allow-list commands", () => {
  const fleet = validFleetProfile();
  fleet.targets["admin-windows"] = {
    enabled: false,
    target: {
      host: "windows.example.internal",
      port: 22,
      username: "Administrator",
      keyId: "k-22222222222222222222222222222222",
    },
    knownHostsFile: String.raw`C:\keys\known_hosts`,
    bastion: {
      host: "bastion.example.internal",
      port: 2_222,
      username: "jump-user",
      keyId: "k-33333333333333333333333333333333",
    },
    platform: "windows",
    policyMode: "full-access",
    allowedCommands: [],
    maxTimeoutMs: 120_000,
    transferMode: "deny",
    localRootPath: String.raw`C:\legacy\workspace`,
    remoteRoots: ["D:/legacy/workspace"],
  };
  fleet.targets["retired-macos"] = {
    enabled: true,
    target: {
      host: "mac.example.internal",
      port: 22,
      username: "operator",
      keyId: "k-44444444444444444444444444444444",
    },
    knownHostsFile: String.raw`C:\keys\known_hosts`,
    platform: "macos",
    policyMode: "deny",
    allowedCommands: [],
    maxTimeoutMs: 5_000,
  };

  assert.deepEqual(managedSshFleetProfileSchema.parse(fleet), fleet);
  assert.deepEqual(
    managedSshFleetProfileSchema.parse({ version: 3, targets: {} }),
    { version: 3, targets: {} },
  );
});

test("fleet v3 preserves optional stable identities and rejects reference collisions", () => {
  const fleet = validFleetProfile();
  fleet.targets["dev-linux"] = {
    ...fleet.targets["dev-linux"]!,
    targetId: "t-11111111111111111111111111111111",
    previousAliases: ["managed-ssh", "old-dev-linux"],
  };
  assert.deepEqual(managedSshFleetProfileSchema.parse(fleet), fleet);

  for (const conflictingAlias of [
    "DEV-LINUX",
    "t-11111111111111111111111111111111",
    "managed-ssh",
  ]) {
    const invalid = structuredClone(fleet);
    invalid.targets[conflictingAlias] = {
      ...validFleetProfile().targets["dev-linux"]!,
      targetId: "t-22222222222222222222222222222222",
    };
    assert.equal(
      managedSshFleetProfileSchema.safeParse(invalid).success,
      false,
      conflictingAlias,
    );
  }
});

test("fleet v3 preserves full-access transfer fields but deny policy fails closed", () => {
  const fullAccess = {
    ...validFleetProfile().targets["dev-linux"],
    policyMode: "full-access" as const,
    allowedCommands: [],
    transferMode: "upload" as const,
    localRootPath: String.raw`C:\legacy\workspace`,
    remoteRoots: ["/legacy/workspace"],
  };
  assert.deepEqual(
    managedSshFleetProfileSchema.parse({
      version: 3,
      targets: { full: fullAccess },
    }).targets.full,
    fullAccess,
  );

  assert.equal(
    managedSshFleetProfileSchema.safeParse({
      version: 3,
      targets: {
        denied: {
          ...fullAccess,
          policyMode: "deny",
          transferMode: "upload",
        },
      },
    }).success,
    false,
  );

  const historicalDeniedTransfer = {
    ...fullAccess,
    transferMode: "deny" as const,
  };
  assert.deepEqual(
    managedSshFleetProfileSchema.parse({
      version: 3,
      targets: { historical: historicalDeniedTransfer },
    }).targets.historical,
    historicalDeniedTransfer,
  );
});

test("fleet v3 rejects UNC, network, and device local transfer roots", () => {
  for (const unsafeRoot of [
    String.raw`\\server\share`,
    "//server/share",
    String.raw`\\?\C:\device`,
    String.raw`\??\C:\device`,
  ]) {
    const fleet = validFleetProfile();
    fleet.targets["dev-linux"] = {
      ...fleet.targets["dev-linux"]!,
      transferMode: "upload",
      localRootPath: unsafeRoot,
      remoteRoots: ["/workspace"],
    };
    assert.equal(
      managedSshFleetProfileSchema.safeParse(fleet).success,
      false,
      unsafeRoot,
    );
  }
});

test("fleet v3 requires policy-shaped commands and safe unique aliases", () => {
  const invalid: unknown[] = [];
  invalid.push({
    ...validFleetProfile(),
    targets: {
      ...validFleetProfile().targets,
      "bad/alias": validFleetProfile().targets["dev-linux"],
    },
  });
  invalid.push({
    ...validFleetProfile(),
    targets: {
      PROD: validFleetProfile().targets["dev-linux"],
      prod: validFleetProfile().targets["dev-linux"],
    },
  });
  invalid.push({
    ...validFleetProfile(),
    targets: {
      "dev-linux": {
        ...validFleetProfile().targets["dev-linux"],
        policyMode: "full-access",
      },
    },
  });
  invalid.push({
    ...validFleetProfile(),
    targets: {
      "dev-linux": {
        ...validFleetProfile().targets["dev-linux"],
        policyMode: "deny",
      },
    },
  });
  invalid.push({
    ...validFleetProfile(),
    targets: {
      "dev-linux": {
        ...validFleetProfile().targets["dev-linux"],
        allowedCommands: ["hostname", "hostname"],
      },
    },
  });
  invalid.push({
    ...validFleetProfile(),
    targets: {
      "dev-linux": {
        ...validFleetProfile().targets["dev-linux"],
        commandInjection: "ProxyCommand calc.exe",
      },
    },
  });

  for (const profile of invalid) {
    assert.equal(
      managedSshFleetProfileSchema.safeParse(profile).success,
      false,
      JSON.stringify(profile),
    );
  }
});

function endpoint(profile: Record<string, unknown>): Record<string, unknown> {
  const value = profile.target;
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  assert.equal(Array.isArray(value), false);
  return value as Record<string, unknown>;
}
