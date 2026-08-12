import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";

import {
  PROTOCOL_VERSION,
  type ExecResult,
  type PingResult,
  type TargetListResult,
} from "../../src/shared/protocol.js";
import type {
  TestUiGatewayFactory,
  TestUiGatewaySession,
} from "../../src/test-ui/gateway.js";
import type {
  AccessClientSessionArmRequest,
  AccessClientSessionPreparer,
  AccessClientSessionSnapshot,
  AccessClientSessionVerification,
} from "../../src/test-ui/accessclient-session.js";
import {
  MANAGED_PLATFORM_COMMANDS,
  MANAGED_SUPPORTED_COMMANDS,
  ManagedSshError,
  managedSshFleetProfileSchema,
  type CurrentManagedSshProfile,
  type ManagedSshFleetProfile,
  type ManagedSshFleetStatus,
  type ManagedSshFleetTarget,
  type ManagedSshKeyGenerationAlgorithm,
  type ManagedSshKeyStatus,
  type ManagedSshKeySummary,
  type ManagedSshProfile,
  type ManagedSshStatus,
  type TestUiConfigurationService,
} from "../../src/test-ui/managed.js";
import {
  startTestUiServer,
  type RunningTestUiServer,
} from "../../src/test-ui/server.js";

const TEST_SESSION_TOKEN = Buffer.alloc(32, 0x38).toString("base64url");
const PRIVATE_KEY_SENTINEL = "PRIVATE-KEY-CONTENTS-MUST-NOT-LEAK";
const INITIAL_KEY_REVISION = `kr-test0000-${"b".repeat(32)}`;
const TARGET_KEY_ID = `k-${"1".repeat(32)}`;
const BASTION_KEY_ID = `k-${"2".repeat(32)}`;

interface JsonObject {
  readonly [key: string]: unknown;
}

interface Deferred<Value> {
  readonly promise: Promise<Value>;
  resolve(value: Value): void;
}

class FakeConfigurationService implements TestUiConfigurationService {
  public readonly gatewayFactory: TestUiGatewayFactory;
  public statusCalls = 0;
  public generateCalls = 0;
  public readonly appliedProfiles: CurrentManagedSshProfile[] = [];
  public readonly appliedFleets: ManagedSshFleetProfile[] = [];
  public readonly appliedExpectedRevisions: (string | undefined)[] = [];
  public readonly generatedManagedKeys: Array<{
    readonly label: string;
    readonly expectedKeyRevision: string;
    readonly algorithm: ManagedSshKeyGenerationAlgorithm;
  }> = [];
  public readonly importedManagedKeys: Array<{
    readonly label: string;
    readonly sourcePath: string;
    readonly expectedKeyRevision: string;
  }> = [];
  public readonly renamedManagedKeys: Array<{
    readonly keyId: string;
    readonly label: string;
    readonly expectedKeyRevision: string;
  }> = [];
  public readonly removedManagedKeys: Array<{
    readonly keyId: string;
    readonly expectedKeyRevision: string;
  }> = [];
  public fleetStatusCalls = 0;
  public fleetProfile: ManagedSshFleetProfile | undefined;
  public fleetRevision: string | undefined;
  public keyRevision = INITIAL_KEY_REVISION;
  public keyError: Readonly<{ code: string; message: string }> | undefined;
  public keys: ManagedSshKeySummary[] = [
    managedKeySummary(TARGET_KEY_ID, "Target key", "generated"),
    managedKeySummary(BASTION_KEY_ID, "Bastion key", "imported"),
  ];
  public closeCalls = 0;
  public statusHandler: () => Promise<ManagedSshStatus> = () =>
    Promise.resolve(unconfiguredStatus());
  public generateHandler: () => Promise<ManagedSshStatus> = () =>
    Promise.resolve(generatedStatus());
  public applyHandler: (
    profile: CurrentManagedSshProfile,
  ) => Promise<ManagedSshStatus> = (profile) =>
    Promise.resolve(readyStatus(profile));
  public generateManagedKeyHandler: (
    label: string,
    expectedKeyRevision: string,
    algorithm: ManagedSshKeyGenerationAlgorithm,
  ) => Promise<ManagedSshKeyStatus> = (label, expectedKeyRevision, algorithm) => {
    this.assertKeyRevision(expectedKeyRevision);
    this.keys.push(
      managedKeySummary(
        `k-${"3".repeat(32)}`,
        label,
        "generated",
        algorithm === "rsa-3072" ? "ssh-rsa" : "ssh-ed25519",
      ),
    );
    return Promise.resolve(this.advanceKeyRevision());
  };

  public constructor(gatewayFactory: TestUiGatewayFactory = successfulGatewayFactory()) {
    this.gatewayFactory = gatewayFactory;
  }

  public status(): Promise<ManagedSshStatus> {
    this.statusCalls += 1;
    return this.statusHandler();
  }

  public fleetStatus(): Promise<ManagedSshFleetStatus> {
    this.fleetStatusCalls += 1;
    const configured =
      this.fleetProfile !== undefined &&
      Object.keys(this.fleetProfile.targets).length > 0;
    return Promise.resolve({
      state: configured ? "ready" : "unconfigured",
      configured,
      defaultKnownHostsFile: String.raw`C:\Users\operator\.ssh\known_hosts`,
      commandPresets: MANAGED_PLATFORM_COMMANDS,
      keyRevision: this.keyRevision,
      keys: [...this.keys],
      ...(this.keyError === undefined ? {} : { keyError: this.keyError }),
      ...(this.fleetRevision === undefined
        ? {}
        : { revision: this.fleetRevision }),
      ...(this.fleetProfile === undefined
        ? {}
        : { profile: this.fleetProfile }),
    });
  }

  public generateKey(): Promise<ManagedSshStatus> {
    this.generateCalls += 1;
    return this.generateHandler();
  }

  public keyStatus(): Promise<ManagedSshKeyStatus> {
    return Promise.resolve({
      keyRevision: this.keyRevision,
      keys: [...this.keys],
      ...(this.keyError === undefined ? {} : { keyError: this.keyError }),
    });
  }

  public generateManagedKey(
    label: string,
    expectedKeyRevision: string,
    algorithm: ManagedSshKeyGenerationAlgorithm = "ed25519",
  ): Promise<ManagedSshKeyStatus> {
    this.generatedManagedKeys.push({ label, expectedKeyRevision, algorithm });
    return this.generateManagedKeyHandler(label, expectedKeyRevision, algorithm);
  }

  public importManagedKey(
    label: string,
    sourcePath: string,
    expectedKeyRevision: string,
  ): Promise<ManagedSshKeyStatus> {
    this.importedManagedKeys.push({ label, sourcePath, expectedKeyRevision });
    this.assertKeyRevision(expectedKeyRevision);
    this.keys.push(managedKeySummary(`k-${"4".repeat(32)}`, label, "imported"));
    return Promise.resolve(this.advanceKeyRevision());
  }

  public renameManagedKey(
    keyId: string,
    label: string,
    expectedKeyRevision: string,
  ): Promise<ManagedSshKeyStatus> {
    this.renamedManagedKeys.push({ keyId, label, expectedKeyRevision });
    this.assertKeyRevision(expectedKeyRevision);
    this.keys = this.keys.map((key) =>
      key.keyId === keyId ? { ...key, label } : key,
    );
    return Promise.resolve(this.advanceKeyRevision());
  }

  public removeManagedKey(
    keyId: string,
    expectedKeyRevision: string,
  ): Promise<ManagedSshKeyStatus> {
    this.removedManagedKeys.push({ keyId, expectedKeyRevision });
    this.assertKeyRevision(expectedKeyRevision);
    this.keys = this.keys.filter((key) => key.keyId !== keyId);
    return Promise.resolve(this.advanceKeyRevision());
  }

  public apply(profile: CurrentManagedSshProfile): Promise<ManagedSshStatus> {
    this.appliedProfiles.push(profile);
    return this.applyHandler(profile);
  }

  public applyFleet(
    profile: ManagedSshFleetProfile,
    expectedRevision?: string,
  ): Promise<ManagedSshFleetStatus> {
    this.appliedFleets.push(profile);
    this.appliedExpectedRevisions.push(expectedRevision);
    this.fleetProfile = profile;
    this.fleetRevision = `r-test${String(this.appliedFleets.length).padStart(4, "0")}-${"a".repeat(32)}`;
    return Promise.resolve({
      state: "ready",
      configured: Object.keys(profile.targets).length > 0,
      defaultKnownHostsFile: String.raw`C:\Users\operator\.ssh\known_hosts`,
      commandPresets: MANAGED_PLATFORM_COMMANDS,
      keyRevision: this.keyRevision,
      keys: [...this.keys],
      revision: this.fleetRevision,
      profile,
    });
  }

  public close(): Promise<void> {
    this.closeCalls += 1;
    return Promise.resolve();
  }

  private assertKeyRevision(expectedKeyRevision: string): void {
    if (expectedKeyRevision !== this.keyRevision) {
      throw new ManagedSshError(
        409,
        "KEY_REVISION_CONFLICT",
        "The SSH key library changed after it was read",
      );
    }
  }

  private advanceKeyRevision(): ManagedSshKeyStatus {
    this.keyRevision = `kr-test${String(
      this.generatedManagedKeys.length +
        this.importedManagedKeys.length +
        this.renamedManagedKeys.length +
        this.removedManagedKeys.length,
    ).padStart(4, "0")}-${"c".repeat(32)}`;
    return { keyRevision: this.keyRevision, keys: [...this.keys] };
  }
}

class FakeAccessClientSessionPreparer implements AccessClientSessionPreparer {
  public readonly prepared: AccessClientSessionArmRequest[] = [];
  public readonly verified: Array<{
    readonly alias: string;
    readonly verification: AccessClientSessionVerification;
  }> = [];
  public readonly rejected: Array<{ readonly alias: string; readonly message: string }> = [];
  public readonly cancelled: string[] = [];
  public initializeCalls = 0;
  public closeCalls = 0;
  public snapshot: AccessClientSessionSnapshot = { state: "idle" };

  public initialize(): Promise<void> {
    this.initializeCalls += 1;
    return Promise.resolve();
  }

  public prepare(
    request: AccessClientSessionArmRequest,
  ): Promise<AccessClientSessionSnapshot> {
    this.prepared.push(request);
    this.snapshot = {
      state: "armed",
      alias: request.alias,
      sharingHost: request.sharingHost,
      sharingPort: request.sharingPort,
      startedAt: "2026-08-11T00:00:00.000Z",
      deadlineAt: "2026-08-11T00:01:00.000Z",
    };
    return Promise.resolve(this.snapshot);
  }

  public status(): AccessClientSessionSnapshot {
    return this.snapshot;
  }

  public verify(
    alias: string,
    verification: AccessClientSessionVerification,
  ): Promise<AccessClientSessionSnapshot> {
    this.verified.push({ alias, verification });
    this.snapshot = {
      state: "ready",
      alias,
      ...(verification.hostname === undefined
        ? {}
        : { hostname: verification.hostname }),
      ...(verification.durationMs === undefined
        ? {}
        : { durationMs: verification.durationMs }),
      completedAt: "2026-08-11T00:00:01.000Z",
    };
    return Promise.resolve(this.snapshot);
  }

  public reject(alias: string, message: string): Promise<AccessClientSessionSnapshot> {
    this.rejected.push({ alias, message });
    this.snapshot = {
      state: "error",
      alias,
      message,
      completedAt: "2026-08-11T00:00:01.000Z",
    };
    return Promise.resolve(this.snapshot);
  }

  public cancel(alias: string): Promise<AccessClientSessionSnapshot> {
    this.cancelled.push(alias);
    this.snapshot = {
      state: "cancelled",
      alias,
      completedAt: "2026-08-11T00:00:01.000Z",
    };
    return Promise.resolve(this.snapshot);
  }

  public close(): Promise<void> {
    this.closeCalls += 1;
    return Promise.resolve();
  }
}

async function startManagedServer(
  t: TestContext,
  configuration: FakeConfigurationService,
  accessClientSessionPreparer?: AccessClientSessionPreparer,
): Promise<RunningTestUiServer> {
  const server = await startTestUiServer({
    gatewayFactory: configuration.gatewayFactory,
    mode: "managed",
    configurationService: configuration,
    ...(accessClientSessionPreparer === undefined
      ? {}
      : { accessClientSessionPreparer }),
    legacySetupRoutes: true,
    sessionToken: TEST_SESSION_TOKEN,
  });
  t.after(() => server.close());
  return server;
}

function postJson(
  server: RunningTestUiServer,
  path: string,
  body: unknown,
): Promise<Response> {
  return fetch(`${server.origin}${path}`, {
    method: "POST",
    headers: {
      Origin: server.origin,
      "Content-Type": "application/json",
      "X-Agent-Ssh-Ui-Token": server.sessionToken,
    },
    body: JSON.stringify(body),
  });
}

function setupApplyRequest(profile: CurrentManagedSshProfile): JsonObject {
  return {
    profile,
    ...(profile.policyMode === "full-access"
      ? { fullAccessConfirmed: true }
      : {}),
  };
}

async function readObject(response: Response): Promise<JsonObject> {
  const value: unknown = await response.json();
  return requireObject(value);
}

function requireObject(value: unknown): JsonObject {
  assert.equal(typeof value, "object");
  assert.notEqual(value, null);
  assert.equal(Array.isArray(value), false);
  return value as JsonObject;
}

async function assertProblem(
  response: Response,
  expectedStatus: number,
  expectedCode: string,
): Promise<string> {
  assert.equal(response.status, expectedStatus);
  const raw = await response.text();
  const body = requireObject(JSON.parse(raw) as unknown);
  assert.equal(requireObject(body.error).code, expectedCode);
  return raw;
}

test("managed setup routes expose status, key generation, and validated apply", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startManagedServer(t, configuration);

  const statusResponse = await postJson(server, "/api/setup/status", {});
  assert.equal(statusResponse.status, 200);
  assert.deepEqual(await readObject(statusResponse), unconfiguredStatus());
  assert.equal(configuration.statusCalls, 1);

  const generateResponse = await postJson(
    server,
    "/api/setup/generate-key",
    {},
  );
  assert.equal(generateResponse.status, 200);
  const generatedRaw = await generateResponse.text();
  assert.deepEqual(JSON.parse(generatedRaw), generatedStatus());
  assert.equal(generatedRaw.includes(PRIVATE_KEY_SENTINEL), false);
  assert.equal(configuration.generateCalls, 1);

  const profile = validProfile();
  const applyResponse = await postJson(
    server,
    "/api/setup/apply",
    setupApplyRequest(profile),
  );
  assert.equal(applyResponse.status, 200);
  assert.deepEqual(await readObject(applyResponse), readyStatus(profile));
  assert.deepEqual(configuration.appliedProfiles, [profile]);

  await server.close();
  await server.close();
  assert.equal(configuration.closeCalls, 1);
});

test("admin bootstrap and target mutations carry optimistic revisions", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startManagedServer(t, configuration);

  const bootstrap = await postJson(server, "/api/admin/bootstrap", {});
  assert.equal(bootstrap.status, 200);
  assert.deepEqual(await readObject(bootstrap), {
    state: "unconfigured",
    configured: false,
    defaultKnownHostsFile: String.raw`C:\Users\operator\.ssh\known_hosts`,
    commandPresets: MANAGED_PLATFORM_COMMANDS,
    keyRevision: INITIAL_KEY_REVISION,
    keys: configuration.keys,
  });

  const createResponse = await postJson(server, "/api/admin/target/save", {
    alias: "dev-linux",
    target: validFleetTarget(),
  });
  assert.equal(createResponse.status, 200);
  const created = await readObject(createResponse);
  const firstRevision = created.revision;
  assert.equal(typeof firstRevision, "string");
  assert.deepEqual(configuration.appliedExpectedRevisions, [undefined]);
  const createdTarget = configuration.appliedFleets[0]?.targets["dev-linux"];
  assert.match(createdTarget?.targetId ?? "", /^t-[a-f0-9]{32}$/u);
  assert.deepEqual(
    { ...createdTarget, targetId: undefined },
    { ...validFleetTarget(), targetId: undefined },
  );

  const updatedTarget: ManagedSshFleetTarget = {
    ...validFleetTarget(),
    description: "Updated target",
    enabled: false,
  };
  const updateResponse = await postJson(server, "/api/admin/target/save", {
    alias: "dev-linux",
    previousAlias: "dev-linux",
    expectedRevision: firstRevision,
    target: updatedTarget,
  });
  assert.equal(updateResponse.status, 200);
  const updated = await readObject(updateResponse);
  const secondRevision = updated.revision;
  assert.equal(typeof secondRevision, "string");
  assert.notEqual(secondRevision, firstRevision);
  assert.deepEqual(configuration.appliedExpectedRevisions, [
    undefined,
    firstRevision,
  ]);

  await assertProblem(
    await postJson(server, "/api/admin/target/remove", {
      alias: "dev-linux",
      expectedRevision: firstRevision,
    }),
    409,
    "CONFIG_CONFLICT",
  );
  assert.equal(configuration.appliedFleets.length, 2);

  const removeResponse = await postJson(server, "/api/admin/target/remove", {
    alias: "dev-linux",
    expectedRevision: secondRevision,
  });
  assert.equal(removeResponse.status, 200);
  assert.deepEqual(configuration.appliedFleets.at(-1)?.targets, {});
  assert.equal((await readObject(removeResponse)).configured, false);
});

test("admin target enabled mutation changes only MCP availability", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startManagedServer(t, configuration);

  const createResponse = await postJson(server, "/api/admin/target/save", {
    alias: "dev-linux",
    target: validFleetTarget(),
  });
  const created = await readObject(createResponse);
  const createdRevision = created.revision;
  assert.equal(typeof createdRevision, "string");

  const disableResponse = await postJson(server, "/api/admin/target/enabled", {
    alias: "dev-linux",
    enabled: false,
    expectedRevision: createdRevision,
  });
  assert.equal(disableResponse.status, 200);
  const disabled = await readObject(disableResponse);
  const disabledTarget = requireObject(
    requireObject(requireObject(disabled.profile).targets)["dev-linux"],
  );
  assert.deepEqual(
    { ...disabledTarget, enabled: true },
    configuration.appliedFleets[0]?.targets["dev-linux"],
  );
  assert.equal(disabledTarget.enabled, false);

  await assertProblem(
    await postJson(server, "/api/admin/target/enabled", {
      alias: "dev-linux",
      enabled: true,
      expectedRevision: createdRevision,
    }),
    409,
    "CONFIG_CONFLICT",
  );
  await assertProblem(
    await postJson(server, "/api/admin/target/enabled", {
      alias: "missing",
      enabled: true,
      expectedRevision: disabled.revision,
    }),
    404,
    "TARGET_NOT_FOUND",
  );
  assert.equal(configuration.appliedFleets.length, 2);
});

test("admin AccessClient settings survive target save, update, removal, and bootstrap", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startManagedServer(t, configuration);
  const accessClient = { plinkExecutable: accessClientExecutablePath() };

  const settingsResponse = await postJson(
    server,
    "/api/admin/access-client/save",
    accessClient,
  );
  assert.equal(settingsResponse.status, 200);
  const settings = await readObject(settingsResponse);
  assert.deepEqual(configuration.appliedFleets.at(-1), {
    version: 3,
    accessClient,
    targets: {},
  });
  assert.deepEqual(settings.profile, configuration.appliedFleets.at(-1));

  const bootstrap = await postJson(server, "/api/admin/bootstrap", {});
  assert.equal(bootstrap.status, 200);
  assert.deepEqual((await readObject(bootstrap)).profile, {
    version: 3,
    accessClient,
    targets: {},
  });

  const accessClientTarget = validAccessClientFleetTarget();
  const createResponse = await postJson(server, "/api/admin/target/save", {
    alias: "accessclient-windows",
    expectedRevision: settings.revision,
    target: accessClientTarget,
  });
  assert.equal(createResponse.status, 200);
  const created = await readObject(createResponse);
  assert.deepEqual(configuration.fleetProfile?.accessClient, accessClient);
  assert.deepEqual(
    {
      ...configuration.fleetProfile?.targets["accessclient-windows"],
      targetId: undefined,
    },
    {
      ...accessClientTarget,
      accessClient: {
        ...accessClientTarget.accessClient,
        sharingHost: accessClientTarget.target.host,
        sharingPort: accessClientTarget.target.port,
      },
      targetId: undefined,
    },
  );

  const updateResponse = await postJson(server, "/api/admin/target/save", {
    alias: "accessclient-windows",
    previousAlias: "accessclient-windows",
    expectedRevision: created.revision,
    target: validFleetTarget(),
  });
  assert.equal(updateResponse.status, 200);
  const updated = await readObject(updateResponse);
  assert.deepEqual(configuration.fleetProfile?.accessClient, accessClient);
  assert.equal(
    configuration.fleetProfile?.targets["accessclient-windows"]?.connectionMode,
    undefined,
  );

  const removeResponse = await postJson(server, "/api/admin/target/remove", {
    alias: "accessclient-windows",
    expectedRevision: updated.revision,
  });
  assert.equal(removeResponse.status, 200);
  assert.deepEqual(configuration.fleetProfile, {
    version: 3,
    accessClient,
    targets: {},
  });
});

test("admin AccessClient contracts reject secret-bearing and transport fields", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startManagedServer(t, configuration);

  for (const injectedField of [
    { password: PRIVATE_KEY_SENTINEL },
    { ticket: PRIVATE_KEY_SENTINEL },
    { uri: PRIVATE_KEY_SENTINEL },
    { rawUri: PRIVATE_KEY_SENTINEL },
    { argv: [PRIVATE_KEY_SENTINEL] },
    { arguments: [PRIVATE_KEY_SENTINEL] },
  ]) {
    const raw = await assertProblem(
      await postJson(server, "/api/admin/access-client/save", {
        plinkExecutable: accessClientExecutablePath(),
        ...injectedField,
      }),
      400,
      "INVALID_REQUEST",
    );
    assert.equal(raw.includes(PRIVATE_KEY_SENTINEL), false);
  }

  for (const injectedField of [
    { password: PRIVATE_KEY_SENTINEL },
    { ticket: PRIVATE_KEY_SENTINEL },
    { uri: PRIVATE_KEY_SENTINEL },
    { rawUri: PRIVATE_KEY_SENTINEL },
    { argv: [PRIVATE_KEY_SENTINEL] },
    { arguments: [PRIVATE_KEY_SENTINEL] },
  ]) {
    const valid = validAccessClientFleetTarget();
    const raw = await assertProblem(
      await postJson(server, "/api/admin/target/save", {
        alias: "injected-accessclient",
        target: {
          ...valid,
          accessClient: {
            ...valid.accessClient,
            ...injectedField,
          },
        },
      }),
      400,
      "INVALID_REQUEST",
    );
    assert.equal(raw.includes(PRIVATE_KEY_SENTINEL), false);
  }

  assert.deepEqual(configuration.appliedFleets, []);
});

test("admin key mutations require key revisions and return public fleet state", async (t) => {
  const configuration = new FakeConfigurationService();
  configuration.keys = configuration.keys.map((key, index) =>
    index === 0
      ? ({
          ...key,
          privateKeyPath: PRIVATE_KEY_SENTINEL,
          sourcePath: PRIVATE_KEY_SENTINEL,
        } as ManagedSshKeySummary)
      : key,
  );
  const server = await startManagedServer(t, configuration);

  const bootstrapRaw = await (await postJson(server, "/api/admin/bootstrap", {})).text();
  assert.equal(bootstrapRaw.includes("privateKeyPath"), false);
  assert.equal(bootstrapRaw.includes("identityFile"), false);
  assert.equal(bootstrapRaw.includes("sourcePath"), false);
  assert.equal(bootstrapRaw.includes(PRIVATE_KEY_SENTINEL), false);

  const generateResponse = await postJson(server, "/api/admin/key/generate", {
    label: "部署密钥",
    expectedKeyRevision: INITIAL_KEY_REVISION,
  });
  assert.equal(generateResponse.status, 200);
  const generated = await readObject(generateResponse);
  assert.deepEqual(configuration.generatedManagedKeys, [
    {
      label: "部署密钥",
      expectedKeyRevision: INITIAL_KEY_REVISION,
      algorithm: "ed25519",
    },
  ]);
  assert.equal(Array.isArray(generated.keys), true);
  assert.equal(typeof generated.keyRevision, "string");

  const rsaResponse = await postJson(server, "/api/admin/key/generate", {
    label: "RSA 3072",
    expectedKeyRevision: generated.keyRevision,
    algorithm: "rsa-3072",
  });
  assert.equal(rsaResponse.status, 200);
  const rsa = await readObject(rsaResponse);
  assert.deepEqual(configuration.generatedManagedKeys.at(-1), {
    label: "RSA 3072",
    expectedKeyRevision: generated.keyRevision,
    algorithm: "rsa-3072",
  });
  assert.equal(
    (rsa.keys as Array<Record<string, unknown>>).some(
      (key) => key.label === "RSA 3072" && key.algorithm === "ssh-rsa",
    ),
    true,
  );

  const sourcePath = privateKeySourcePath();
  const importResponse = await postJson(server, "/api/admin/key/import", {
    label: "Imported key",
    sourcePath,
    expectedKeyRevision: rsa.keyRevision,
  });
  assert.equal(importResponse.status, 200);
  const importedRaw = await importResponse.text();
  assert.equal(importedRaw.includes(sourcePath), false);
  assert.equal(importedRaw.includes("sourcePath"), false);
  const imported = requireObject(JSON.parse(importedRaw) as unknown);
  assert.deepEqual(configuration.importedManagedKeys, [
    {
      label: "Imported key",
      sourcePath,
      expectedKeyRevision: rsa.keyRevision as string,
    },
  ]);

  const renameResponse = await postJson(server, "/api/admin/key/rename", {
    keyId: `k-${"4".repeat(32)}`,
    label: "Renamed key",
    expectedKeyRevision: imported.keyRevision,
  });
  assert.equal(renameResponse.status, 200);
  const renamed = await readObject(renameResponse);
  assert.equal(
    (renamed.keys as Array<Record<string, unknown>>).some(
      (key) => key.label === "Renamed key",
    ),
    true,
  );

  const removeResponse = await postJson(server, "/api/admin/key/remove", {
    keyId: `k-${"4".repeat(32)}`,
    expectedKeyRevision: renamed.keyRevision,
  });
  assert.equal(removeResponse.status, 200);
  const removed = await readObject(removeResponse);
  assert.equal(
    (removed.keys as Array<Record<string, unknown>>).some(
      (key) => key.keyId === `k-${"4".repeat(32)}`,
    ),
    false,
  );
});

test("admin bootstrap separates public key errors without hiding saved machines", async (t) => {
  const configuration = new FakeConfigurationService();
  configuration.fleetProfile = {
    version: 3,
    targets: {
      preserved: {
        ...validFleetTarget(),
        targetId: `t-${"5".repeat(32)}`,
      },
    },
  };
  configuration.fleetRevision = `r-test0001-${"d".repeat(32)}`;
  configuration.keyError = {
    code: "KEY_LIBRARY_INVALID",
    message: "The SSH key library could not be loaded",
    privateKeyPath: PRIVATE_KEY_SENTINEL,
  } as Readonly<{ code: string; message: string }>;
  const server = await startManagedServer(t, configuration);

  const response = await postJson(server, "/api/admin/bootstrap", {});
  assert.equal(response.status, 200);
  const raw = await response.text();
  assert.equal(raw.includes(PRIVATE_KEY_SENTINEL), false);
  assert.equal(raw.includes("privateKeyPath"), false);
  assert.equal(raw.includes("identityFile"), false);
  const status = requireObject(JSON.parse(raw) as unknown);
  assert.equal(status.configured, true);
  assert.deepEqual(status.keyError, {
    code: "KEY_LIBRARY_INVALID",
    message: "The SSH key library could not be loaded",
  });
  assert.equal(
    Object.hasOwn(
      requireObject(requireObject(status.profile).targets),
      "preserved",
    ),
    true,
  );
});

test("admin key routes reject stale revisions, unsafe paths, and injected fields", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startManagedServer(t, configuration);

  for (const [route, body] of [
    ["/api/admin/key/generate", { label: "Missing revision" }],
    [
      "/api/admin/key/import",
      { label: "Missing revision", sourcePath: privateKeySourcePath() },
    ],
    [
      "/api/admin/key/rename",
      { keyId: TARGET_KEY_ID, label: "Missing revision" },
    ],
    ["/api/admin/key/remove", { keyId: TARGET_KEY_ID }],
  ] as const) {
    await assertProblem(await postJson(server, route, body), 400, "INVALID_REQUEST");
  }

  await assertProblem(
    await postJson(server, "/api/admin/key/generate", {
      label: "Unsupported algorithm",
      expectedKeyRevision: INITIAL_KEY_REVISION,
      algorithm: "rsa-2048",
    }),
    400,
    "INVALID_REQUEST",
  );
  assert.equal(configuration.generatedManagedKeys.length, 0);

  for (const label of [
    " leading",
    "trailing ",
    "bad\u0000name",
    "bad\u202ename",
    "x".repeat(129),
  ]) {
    await assertProblem(
      await postJson(server, "/api/admin/key/generate", {
        label,
        expectedKeyRevision: INITIAL_KEY_REVISION,
      }),
      400,
      "INVALID_REQUEST",
    );
  }

  for (const sourcePath of [
    "relative.key",
    "//server/share/key",
    String.raw`\\server\share\key`,
    String.raw`C:\keys\id_ed25519:stream`,
    "$HOME/.ssh/id_ed25519",
  ]) {
    await assertProblem(
      await postJson(server, "/api/admin/key/import", {
        label: "Unsafe source",
        sourcePath,
        expectedKeyRevision: INITIAL_KEY_REVISION,
      }),
      400,
      "INVALID_REQUEST",
    );
  }

  const injectedRaw = await assertProblem(
    await postJson(server, "/api/admin/key/import", {
      label: "Injected",
      sourcePath: privateKeySourcePath(),
      expectedKeyRevision: INITIAL_KEY_REVISION,
      privateKey: PRIVATE_KEY_SENTINEL,
    }),
    400,
    "INVALID_REQUEST",
  );
  assert.equal(injectedRaw.includes(PRIVATE_KEY_SENTINEL), false);
  assert.equal(configuration.importedManagedKeys.length, 0);

  await assertProblem(
    await postJson(server, "/api/admin/key/rename", {
      keyId: "k-../../private",
      label: "Invalid ID",
      expectedKeyRevision: INITIAL_KEY_REVISION,
    }),
    400,
    "INVALID_REQUEST",
  );

  const first = await readObject(
    await postJson(server, "/api/admin/key/generate", {
      label: "First",
      expectedKeyRevision: INITIAL_KEY_REVISION,
    }),
  );
  assert.equal(typeof first.keyRevision, "string");
  const staleRaw = await assertProblem(
    await postJson(server, "/api/admin/key/import", {
      label: "Stale",
      sourcePath: privateKeySourcePath(),
      expectedKeyRevision: INITIAL_KEY_REVISION,
    }),
    409,
    "KEY_REVISION_CONFLICT",
  );
  assert.equal(staleRaw.includes(privateKeySourcePath()), false);
});

test("admin target save accepts key IDs but rejects private key paths", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startManagedServer(t, configuration);
  const valid = validFleetTarget();
  const targetWithPath = {
    ...valid,
    target: {
      host: valid.target.host,
      port: valid.target.port,
      username: valid.target.username,
      identityFile: PRIVATE_KEY_SENTINEL,
    },
  };

  const raw = await assertProblem(
    await postJson(server, "/api/admin/target/save", {
      alias: "path-injection",
      target: targetWithPath,
    }),
    400,
    "INVALID_REQUEST",
  );
  assert.equal(raw.includes(PRIVATE_KEY_SENTINEL), false);
  assert.deepEqual(configuration.appliedFleets, []);

  const savedResponse = await postJson(server, "/api/admin/target/save", {
    alias: "key-reference",
    target: valid,
  });
  assert.equal(savedResponse.status, 200);
  const savedRaw = await savedResponse.text();
  assert.equal(savedRaw.includes('"keyId"'), true);
  assert.equal(savedRaw.includes("identityFile"), false);
  assert.equal(savedRaw.includes("privateKeyPath"), false);
});

test("admin target save accepts only well-formed portal-routed usernames", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startManagedServer(t, configuration);
  const routed = validFleetTarget();
  routed.target.username = "portal.user/192.0.2.24/Administrator";
  if (routed.bastion !== undefined) {
    routed.bastion.username = "jump-user/198.51.100.8/root_user";
  }

  const accepted = await postJson(server, "/api/admin/target/save", {
    alias: "portal-routed",
    target: routed,
  });
  assert.equal(accepted.status, 200);
  assert.equal(
    configuration.fleetProfile?.targets["portal-routed"]?.target.username,
    routed.target.username,
  );

  for (const username of [
    "portal//system",
    "portal/192.0.2.24/system/extra",
    "portal/not-an-ip/system",
    "portal/192.0.2.24/system user",
  ]) {
    const invalid = validFleetTarget();
    invalid.target.username = username;
    await assertProblem(
      await postJson(server, "/api/admin/target/save", {
        alias: "invalid-route",
        target: invalid,
      }),
      400,
      "INVALID_REQUEST",
    );
  }
  assert.equal(configuration.appliedFleets.length, 1);
});

test("admin rename preserves the stable ID and reserves historical aliases", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startManagedServer(t, configuration);

  const createdResponse = await postJson(server, "/api/admin/target/save", {
    alias: "managed-ssh",
    target: validFleetTarget(),
  });
  assert.equal(createdResponse.status, 200);
  const created = await readObject(createdResponse);
  const createdTarget = configuration.fleetProfile?.targets["managed-ssh"];
  const targetId = createdTarget?.targetId;
  assert.match(targetId ?? "", /^t-[a-f0-9]{32}$/u);

  const renamedResponse = await postJson(server, "/api/admin/target/save", {
    alias: "xiaoxu_deploy",
    previousAlias: "managed-ssh",
    expectedRevision: created.revision,
    target: {
      ...validFleetTarget(),
      targetId: "t-ffffffffffffffffffffffffffffffff",
    },
  });
  assert.equal(renamedResponse.status, 200);
  const renamed = await readObject(renamedResponse);
  assert.deepEqual(configuration.fleetProfile?.targets["xiaoxu_deploy"], {
    ...validFleetTarget(),
    targetId,
    previousAliases: ["managed-ssh"],
  });

  await assertProblem(
    await postJson(server, "/api/admin/target/save", {
      alias: "managed-ssh",
      expectedRevision: renamed.revision,
      target: validFleetTarget(),
    }),
    409,
    "TARGET_EXISTS",
  );

  const renamedBackResponse = await postJson(server, "/api/admin/target/save", {
    alias: "managed-ssh",
    previousAlias: "xiaoxu_deploy",
    expectedRevision: renamed.revision,
    target: validFleetTarget(),
  });
  assert.equal(renamedBackResponse.status, 200);
  assert.deepEqual(configuration.fleetProfile?.targets["managed-ssh"], {
    ...validFleetTarget(),
    targetId,
    previousAliases: ["xiaoxu_deploy"],
  });
});

test("admin target save requires full-access confirmation and rejects alias conflicts", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startManagedServer(t, configuration);
  const fullAccessTarget: ManagedSshFleetTarget = {
    ...validFleetTarget(),
    policyMode: "full-access",
    allowedCommands: [],
    transferMode: "bidirectional",
    localRootPath: String.raw`C:\legacy-transfer-root`,
    remoteRoots: ["D:/legacy-transfer-root"],
  };

  await assertProblem(
    await postJson(server, "/api/admin/target/save", {
      alias: "admin-windows",
      target: fullAccessTarget,
    }),
    400,
    "INVALID_REQUEST",
  );
  await assertProblem(
    await postJson(server, "/api/admin/target/save", {
      alias: "admin-windows",
      target: fullAccessTarget,
      fullAccessConfirmed: false,
    }),
    400,
    "INVALID_REQUEST",
  );
  await assertProblem(
    await postJson(server, "/api/admin/target/save", {
      alias: "admin-windows",
      target: fullAccessTarget,
      transferAccessConfirmed: true,
    }),
    400,
    "INVALID_REQUEST",
  );
  await assertProblem(
    await postJson(server, "/api/admin/target/save", {
      alias: "admin-windows",
      target: {
        ...validFleetTarget(),
        policyMode: "full-access",
        allowedCommands: [],
        transferMode: "bidirectional",
      },
      fullAccessConfirmed: true,
    }),
    400,
    "INVALID_REQUEST",
  );

  const createResponse = await postJson(server, "/api/admin/target/save", {
    alias: "admin-windows",
    target: fullAccessTarget,
    fullAccessConfirmed: true,
  });
  assert.equal(createResponse.status, 200);
  const revision = (await readObject(createResponse)).revision;
  assert.equal(typeof revision, "string");
  assert.equal(
    configuration.appliedFleets[0]?.targets["admin-windows"]?.policyMode,
    "full-access",
  );
  assert.equal(
    configuration.appliedFleets[0]?.targets["admin-windows"]?.transferMode,
    "bidirectional",
  );

  await assertProblem(
    await postJson(server, "/api/admin/target/save", {
      alias: "admin-windows",
      expectedRevision: revision,
      target: validFleetTarget(),
    }),
    409,
    "TARGET_EXISTS",
  );
  assert.equal(configuration.appliedFleets.length, 1);
});

test("admin target save rejects isolated restricted fields for full access", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startManagedServer(t, configuration);
  const isolatedFields: ReadonlyArray<
    Partial<
      Pick<
        ManagedSshFleetTarget,
        "localRootPath" | "remoteRoots" | "maxTransferTimeoutMs"
      >
    >
  > = [
    { localRootPath: String.raw`C:\legacy-transfer-root` },
    { remoteRoots: ["D:/legacy-transfer-root"] },
    { maxTransferTimeoutMs: 654_321 },
  ];

  for (const transferMode of [undefined, "deny"] as const) {
    for (const isolatedField of isolatedFields) {
      const target: ManagedSshFleetTarget = {
        ...validFleetTarget(),
        policyMode: "full-access",
        allowedCommands: [],
        ...(transferMode === undefined ? {} : { transferMode }),
        ...isolatedField,
      };
      const historicalProfile: ManagedSshFleetProfile = {
        version: 3,
        targets: { historical: target },
      };
      assert.deepEqual(
        managedSshFleetProfileSchema.parse(historicalProfile),
        historicalProfile,
      );
      await assertProblem(
        await postJson(server, "/api/admin/target/save", {
          alias: "admin-windows",
          target,
          fullAccessConfirmed: true,
        }),
        400,
        "INVALID_REQUEST",
      );
    }
  }

  assert.deepEqual(configuration.appliedFleets, []);
});

test("admin target save requires independent transfer authorization", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startManagedServer(t, configuration);
  const transferTarget: ManagedSshFleetTarget = {
    ...validFleetTarget(),
    transferMode: "bidirectional",
    localRootPath: String.raw`C:\AgentSsh\transfer`,
    remoteRoots: ["D:/services/app"],
    maxTransferTimeoutMs: 600_000,
  };

  await assertProblem(
    await postJson(server, "/api/admin/target/save", {
      alias: "transfer-windows",
      target: transferTarget,
    }),
    400,
    "INVALID_REQUEST",
  );
  await assertProblem(
    await postJson(server, "/api/admin/target/save", {
      alias: "transfer-windows",
      target: transferTarget,
      transferAccessConfirmed: false,
    }),
    400,
    "INVALID_REQUEST",
  );

  const response = await postJson(server, "/api/admin/target/save", {
    alias: "transfer-windows",
    target: transferTarget,
    transferAccessConfirmed: true,
  });
  assert.equal(response.status, 200);
  assert.match(
    configuration.appliedFleets[0]?.targets["transfer-windows"]?.targetId ?? "",
    /^t-[a-f0-9]{32}$/u,
  );
  assert.deepEqual(
    {
      ...configuration.appliedFleets[0]?.targets["transfer-windows"],
      targetId: undefined,
    },
    { ...transferTarget, targetId: undefined },
  );
});

test("product management mode disables legacy setup mutations", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startTestUiServer({
    gatewayFactory: configuration.gatewayFactory,
    mode: "managed",
    configurationService: configuration,
    legacySetupRoutes: false,
    sessionToken: TEST_SESSION_TOKEN,
  });
  t.after(() => server.close());

  assert.equal(
    (await postJson(server, "/api/admin/bootstrap", {})).status,
    200,
  );
  await assertProblem(
    await postJson(server, "/api/setup/status", {}),
    404,
    "NOT_FOUND",
  );
  await assertProblem(
    await postJson(
      server,
      "/api/setup/apply",
      setupApplyRequest(validProfile()),
    ),
    404,
    "NOT_FOUND",
  );
  assert.deepEqual(configuration.appliedProfiles, []);
});

test("admin connection check accepts only a target alias", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startManagedServer(t, configuration);

  await assertProblem(
    await postJson(server, "/api/admin/target/check", {
      target: "managed-ssh",
      command: "whoami",
    }),
    400,
    "INVALID_REQUEST",
  );
  const response = await postJson(server, "/api/admin/target/check", {
    target: "managed-ssh",
  });
  assert.equal(response.status, 200);
  assert.deepEqual(await readObject(response), {
    target: "managed-ssh",
    connected: true,
    termination: "exit",
    exitCode: 0,
    durationMs: 1,
    hostname: "test-host",
  });
});

test("admin connection check learns an unbound AccessClient hostname once", async (t) => {
  const configuration = new FakeConfigurationService();
  const revision = `r-test-${"a".repeat(32)}`;
  configureAccessClientTarget(configuration, revision);
  const current = configuration.fleetProfile!.targets["gpu-build"]!;
  const { expectedHostname: _expectedHostname, ...unboundAccessClient } =
    current.accessClient!;
  configuration.fleetProfile = {
    ...configuration.fleetProfile!,
    targets: {
      ...configuration.fleetProfile!.targets,
      "gpu-build": {
        ...current,
        accessClient: unboundAccessClient,
      },
    },
  };
  const server = await startManagedServer(t, configuration);

  const firstResponse = await postJson(server, "/api/admin/target/check", {
    target: "gpu-build",
  });
  assert.equal(firstResponse.status, 200);
  const first = await readObject(firstResponse);
  assert.equal(requireObject(first.status).revision, configuration.fleetRevision);
  assert.equal(configuration.appliedFleets.length, 1);
  assert.equal(configuration.appliedExpectedRevisions[0], revision);
  assert.equal(
    configuration.appliedFleets[0]?.targets["gpu-build"]?.accessClient
      ?.expectedHostname,
    "test-host",
  );

  const secondResponse = await postJson(server, "/api/admin/target/check", {
    target: "gpu-build",
  });
  assert.equal(secondResponse.status, 200);
  assert.equal(configuration.appliedFleets.length, 1);
  assert.equal("status" in (await readObject(secondResponse)), false);
});

test("admin connection check never overwrites a bound AccessClient hostname", async (t) => {
  const configuration = new FakeConfigurationService();
  const revision = `r-test-${"a".repeat(32)}`;
  configureAccessClientTarget(configuration, revision);
  const server = await startManagedServer(t, configuration);

  const response = await postJson(server, "/api/admin/target/check", {
    target: "gpu-build",
  });

  assert.equal(response.status, 200);
  assert.equal(configuration.appliedFleets.length, 0);
  assert.equal(
    configuration.fleetProfile?.targets["gpu-build"]?.accessClient
      ?.expectedHostname,
    "target.example.internal",
  );
});

test("admin connection check forwards only a safe AccessClient failure reason", async (t) => {
  const configuration = new FakeConfigurationService(() =>
    Promise.resolve({
      ...successfulGatewaySession(),
      checkTarget: ({ target }) =>
        Promise.resolve({
          target,
          connected: false,
          termination: "exit" as const,
          exitCode: 255,
          durationMs: 4,
          failureReason: "accessclient-session-unavailable" as const,
        }),
    }),
  );
  const server = await startManagedServer(t, configuration);

  const response = await postJson(server, "/api/admin/target/check", {
    target: "managed-ssh",
  });
  assert.equal(response.status, 200);
  const result = await readObject(response);
  assert.deepEqual(result, {
    target: "managed-ssh",
    connected: false,
    termination: "exit",
    exitCode: 255,
    durationMs: 4,
    failureReason: "accessclient-session-unavailable",
  });
  assert.equal("stderr" in result, false);
  assert.equal("outputRef" in result, false);
});

test("admin prepares only a saved AccessClient target and keeps cancellation available", async (t) => {
  const configuration = new FakeConfigurationService();
  const revision = `r-test-${"a".repeat(32)}`;
  configuration.fleetRevision = revision;
  configuration.fleetProfile = {
    version: 3,
    accessClient: { plinkExecutable: accessClientExecutablePath() },
    targets: {
      "gpu-build": {
        ...validAccessClientFleetTarget(),
        accessClient: {
          ...validAccessClientFleetTarget().accessClient!,
          sharingHost: "120.92.76.66",
          sharingPort: 22,
        },
      },
    },
  };
  const preparer = new FakeAccessClientSessionPreparer();
  const server = await startManagedServer(t, configuration, preparer);

  await assertProblem(
    await postJson(server, "/api/admin/access-client/session/prepare", {
      alias: "gpu-build",
      expectedRevision: revision,
      registryPath: String.raw`HKCU\Software\untrusted`,
    }),
    400,
    "INVALID_REQUEST",
  );
  assert.deepEqual(preparer.prepared, []);

  const prepareResponse = await postJson(
    server,
    "/api/admin/access-client/session/prepare",
    { alias: "gpu-build", expectedRevision: revision },
  );
  assert.equal(prepareResponse.status, 202);
  assert.deepEqual(preparer.prepared, [
    {
      alias: "gpu-build",
      revision,
      sharingHost: "120.92.76.66",
      sharingPort: 22,
    },
  ]);

  await assertProblem(
    await postJson(server, "/api/admin/access-client/save", {
      plinkExecutable: accessClientExecutablePath(),
      expectedRevision: revision,
    }),
    409,
    "ACCESSCLIENT_PREPARATION_BUSY",
  );

  const changedRevision = `r-changed-${"b".repeat(32)}`;
  configuration.fleetRevision = changedRevision;
  const statusResponse = await postJson(
    server,
    "/api/admin/access-client/session/status",
    { alias: "gpu-build", expectedRevision: revision },
  );
  assert.equal(statusResponse.status, 200);
  assert.equal((await readObject(statusResponse))["state"], "armed");

  const cancelResponse = await postJson(
    server,
    "/api/admin/access-client/session/cancel",
    { alias: "gpu-build", expectedRevision: revision },
  );
  assert.equal(cancelResponse.status, 200);
  assert.equal((await readObject(cancelResponse))["state"], "cancelled");
  assert.deepEqual(preparer.cancelled, ["gpu-build"]);

  configuration.fleetProfile = {
    ...configuration.fleetProfile,
    targets: { "gpu-build": validAccessClientFleetTarget() },
  };
  await assertProblem(
    await postJson(
      server,
      "/api/admin/access-client/session/prepare",
      { alias: "gpu-build", expectedRevision: changedRevision },
    ),
    409,
    "ACCESSCLIENT_SHARING_HOST_REQUIRED",
  );
  assert.equal(preparer.prepared.length, 1);
});

test("admin verifies a newly detected PuTTY session through the fixed target check", async (t) => {
  const configuration = new FakeConfigurationService();
  const revision = `r-test-${"a".repeat(32)}`;
  configureAccessClientTarget(configuration, revision);
  const preparer = new FakeAccessClientSessionPreparer();
  preparer.snapshot = {
    state: "detected",
    alias: "gpu-build",
    sharingHost: "120.92.76.66",
    sharingPort: 22,
  };
  const server = await startManagedServer(t, configuration, preparer);

  configuration.fleetRevision = `r-changed-${"b".repeat(32)}`;
  const response = await postJson(
    server,
    "/api/admin/access-client/session/status",
    { alias: "gpu-build", expectedRevision: revision },
  );

  assert.equal(response.status, 200);
  assert.deepEqual(await readObject(response), {
    state: "ready",
    alias: "gpu-build",
    hostname: "test-host",
    durationMs: 1,
    completedAt: "2026-08-11T00:00:01.000Z",
  });
  assert.deepEqual(preparer.verified, [
    {
      alias: "gpu-build",
      verification: { hostname: "test-host", durationMs: 1 },
    },
  ]);
  assert.deepEqual(preparer.rejected, []);
});

test("admin session preparation learns an unbound AccessClient hostname", async (t) => {
  const configuration = new FakeConfigurationService();
  const revision = `r-test-${"a".repeat(32)}`;
  configureAccessClientTarget(configuration, revision);
  const current = configuration.fleetProfile!.targets["gpu-build"]!;
  const { expectedHostname: _expectedHostname, ...unboundAccessClient } =
    current.accessClient!;
  configuration.fleetProfile = {
    ...configuration.fleetProfile!,
    targets: {
      ...configuration.fleetProfile!.targets,
      "gpu-build": {
        ...current,
        accessClient: unboundAccessClient,
      },
    },
  };
  const preparer = new FakeAccessClientSessionPreparer();
  preparer.snapshot = {
    state: "detected",
    alias: "gpu-build",
    sharingHost: "120.92.76.66",
    sharingPort: 22,
  };
  const server = await startManagedServer(t, configuration, preparer);

  const response = await postJson(
    server,
    "/api/admin/access-client/session/status",
    { alias: "gpu-build", expectedRevision: revision },
  );
  const body = await readObject(response);

  assert.equal(response.status, 200);
  assert.equal(body.state, "ready");
  assert.equal(requireObject(body.status).revision, configuration.fleetRevision);
  assert.equal(configuration.appliedFleets.length, 1);
  assert.equal(
    configuration.appliedFleets[0]?.targets["gpu-build"]?.accessClient
      ?.expectedHostname,
    "test-host",
  );
});

test("admin keeps waiting while a detected AccessClient shared session is not ready", async (t) => {
  const configuration = new FakeConfigurationService(() =>
    Promise.resolve({
      ...successfulGatewaySession(),
      checkTarget: ({ target }) =>
        Promise.resolve({
          target,
          connected: false,
          termination: "exit" as const,
          exitCode: 255,
          durationMs: 4,
          failureReason: "accessclient-session-unavailable" as const,
        }),
    }),
  );
  const revision = `r-test-${"a".repeat(32)}`;
  configureAccessClientTarget(configuration, revision);
  const preparer = new FakeAccessClientSessionPreparer();
  preparer.snapshot = { state: "detected", alias: "gpu-build" };
  const server = await startManagedServer(t, configuration, preparer);

  const response = await postJson(
    server,
    "/api/admin/access-client/session/status",
    { alias: "gpu-build", expectedRevision: revision },
  );

  assert.equal(response.status, 200);
  assert.equal((await readObject(response))["state"], "detected");
  assert.deepEqual(preparer.verified, []);
  assert.deepEqual(preparer.rejected, []);
});

test("admin rejects a detected PuTTY session that resolves to another host", async (t) => {
  const configuration = new FakeConfigurationService(() =>
    Promise.resolve({
      ...successfulGatewaySession(),
      checkTarget: ({ target }) =>
        Promise.resolve({
          target,
          connected: false,
          termination: "exit" as const,
          exitCode: 255,
          durationMs: 4,
          failureReason: "accessclient-host-mismatch" as const,
        }),
    }),
  );
  const revision = `r-test-${"a".repeat(32)}`;
  configureAccessClientTarget(configuration, revision);
  const preparer = new FakeAccessClientSessionPreparer();
  preparer.snapshot = { state: "detected", alias: "gpu-build" };
  const server = await startManagedServer(t, configuration, preparer);

  const response = await postJson(
    server,
    "/api/admin/access-client/session/status",
    { alias: "gpu-build", expectedRevision: revision },
  );

  assert.equal(response.status, 200);
  assert.equal((await readObject(response))["state"], "error");
  assert.deepEqual(preparer.verified, []);
  assert.deepEqual(preparer.rejected, [
    {
      alias: "gpu-build",
      message: "The detected PuTTY session connected to a different machine",
    },
  ]);
});

test("managed setup apply accepts an explicitly shaped full-access profile", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startManagedServer(t, configuration);
  const profile: CurrentManagedSshProfile = {
    ...validProfile(),
    policyMode: "full-access",
    allowedCommands: [],
  };

  const response = await postJson(
    server,
    "/api/setup/apply",
    setupApplyRequest(profile),
  );
  assert.equal(response.status, 200);
  assert.deepEqual(await readObject(response), readyStatus(profile));
  assert.deepEqual(configuration.appliedProfiles, [profile]);
});

test("managed setup apply requires current fields and explicit full-access confirmation", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startManagedServer(t, configuration);
  const fullAccessProfile: CurrentManagedSshProfile = {
    target: validProfile().target,
    knownHostsFile: validProfile().knownHostsFile,
    platform: "windows",
    policyMode: "full-access",
    allowedCommands: [],
  };

  await assertProblem(
    await postJson(server, "/api/setup/apply", {
      profile: fullAccessProfile,
    }),
    400,
    "INVALID_REQUEST",
  );
  await assertProblem(
    await postJson(server, "/api/setup/apply", {
      profile: fullAccessProfile,
      fullAccessConfirmed: false,
    }),
    400,
    "INVALID_REQUEST",
  );

  const legacyProfile = structuredClone(validProfile()) as Record<
    string,
    unknown
  >;
  delete legacyProfile.platform;
  delete legacyProfile.policyMode;
  await assertProblem(
    await postJson(server, "/api/setup/apply", {
      profile: legacyProfile,
    }),
    400,
    "INVALID_REQUEST",
  );
  assert.deepEqual(configuration.appliedProfiles, []);
});

test("setup routes are unavailable outside managed mode", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startTestUiServer({
    gatewayFactory: configuration.gatewayFactory,
    mode: "gateway",
    configurationService: configuration,
    sessionToken: TEST_SESSION_TOKEN,
  });
  t.after(() => server.close());

  for (const route of [
    "/api/setup/status",
    "/api/setup/generate-key",
    "/api/setup/apply",
  ]) {
    const body = route.endsWith("/apply")
      ? setupApplyRequest(validProfile())
      : {};
    await assertProblem(await postJson(server, route, body), 404, "NOT_FOUND");
  }
  assert.equal(configuration.statusCalls, 0);
  assert.equal(configuration.generateCalls, 0);
  assert.equal(configuration.appliedProfiles.length, 0);
});

test("admin key routes require managed mode and the browser session", async (t) => {
  const configuration = new FakeConfigurationService();
  const gatewayServer = await startTestUiServer({
    gatewayFactory: configuration.gatewayFactory,
    mode: "gateway",
    configurationService: configuration,
    sessionToken: TEST_SESSION_TOKEN,
  });
  t.after(() => gatewayServer.close());

  await assertProblem(
    await postJson(gatewayServer, "/api/admin/key/generate", {
      label: "Unavailable",
      expectedKeyRevision: INITIAL_KEY_REVISION,
    }),
    404,
    "NOT_FOUND",
  );
  assert.deepEqual(configuration.generatedManagedKeys, []);

  const managedServer = await startManagedServer(t, configuration);
  const rejected = await fetch(`${managedServer.origin}/api/admin/key/generate`, {
    method: "POST",
    headers: {
      Origin: managedServer.origin,
      "Content-Type": "application/json",
      "X-Agent-Ssh-Ui-Token": Buffer.alloc(32, 0x39).toString("base64url"),
    },
    body: JSON.stringify({
      label: "Rejected",
      expectedKeyRevision: INITIAL_KEY_REVISION,
    }),
  });
  await assertProblem(rejected, 403, "INVALID_SESSION");
  assert.deepEqual(configuration.generatedManagedKeys, []);
});

test("setup apply rejects injected fields without echoing secret input", async (t) => {
  const configuration = new FakeConfigurationService();
  const server = await startManagedServer(t, configuration);
  const injected = {
    ...validProfile(),
    privateKey: PRIVATE_KEY_SENTINEL,
    target: {
      ...validProfile().target,
      host: "target.example\nProxyCommand calc.exe",
    },
  };

  const raw = await assertProblem(
    await postJson(server, "/api/setup/apply", { profile: injected }),
    400,
    "INVALID_REQUEST",
  );
  assert.equal(raw.includes(PRIVATE_KEY_SENTINEL), false);
  assert.equal(raw.includes("ProxyCommand"), false);
  assert.equal(raw.includes("stack"), false);
  assert.equal(configuration.appliedProfiles.length, 0);
});

test("setup failures expose only stable public errors", async (t) => {
  const configuration = new FakeConfigurationService();
  const publicError = new ManagedSshError(
    400,
    "PRIVATE_KEY_UNUSABLE",
    "The private key is invalid or requires a passphrase",
  );
  Object.defineProperty(publicError, "cause", {
    value: new Error(PRIVATE_KEY_SENTINEL),
  });
  configuration.applyHandler = () => Promise.reject(publicError);
  const server = await startManagedServer(t, configuration);

  const publicRaw = await assertProblem(
    await postJson(
      server,
      "/api/setup/apply",
      setupApplyRequest(validProfile()),
    ),
    400,
    "PRIVATE_KEY_UNUSABLE",
  );
  assert.equal(publicRaw.includes(PRIVATE_KEY_SENTINEL), false);
  assert.equal(publicRaw.includes("cause"), false);
  assert.equal(publicRaw.includes("stack"), false);

  configuration.generateHandler = () =>
    Promise.reject(new Error(PRIVATE_KEY_SENTINEL));
  const internalRaw = await assertProblem(
    await postJson(server, "/api/setup/generate-key", {}),
    500,
    "INTERNAL_ERROR",
  );
  assert.equal(internalRaw.includes(PRIVATE_KEY_SENTINEL), false);
});

test("an active run blocks apply and key generation", { timeout: 5_000 }, async (t) => {
  const runStarted = deferred<AbortSignal>();
  const configuration = new FakeConfigurationService(
    controlledRunGatewayFactory(runStarted),
  );
  const server = await startManagedServer(t, configuration);

  const runResponsePromise = postJson(server, "/api/run", {
    target: "managed-ssh",
    command: "hostname",
  });
  await runStarted.promise;

  await assertProblem(
    await postJson(
      server,
      "/api/setup/apply",
      setupApplyRequest(validProfile()),
    ),
    409,
    "RUN_ACTIVE",
  );
  await assertProblem(
    await postJson(server, "/api/setup/generate-key", {}),
    409,
    "RUN_ACTIVE",
  );
  await assertProblem(
    await postJson(server, "/api/admin/key/generate", {
      label: "Blocked key",
      expectedKeyRevision: INITIAL_KEY_REVISION,
    }),
    409,
    "RUN_ACTIVE",
  );
  assert.equal(configuration.appliedProfiles.length, 0);
  assert.equal(configuration.generateCalls, 0);
  assert.equal(configuration.generatedManagedKeys.length, 0);

  const cancelResponse = await postJson(server, "/api/cancel", {});
  assert.deepEqual(await readObject(cancelResponse), { accepted: true });
  const runResponse = await runResponsePromise;
  assert.equal((await readObject(runResponse)).termination, "cancel");
});

test("active key generation blocks run and apply", { timeout: 5_000 }, async (t) => {
  let gatewayCalls = 0;
  const gatewayDelegate = successfulGatewayFactory();
  const configuration = new FakeConfigurationService(async () => {
    gatewayCalls += 1;
    return gatewayDelegate();
  });
  const generationStarted = deferred<void>();
  const finishGeneration = deferred<ManagedSshStatus>();
  configuration.generateHandler = () => {
    generationStarted.resolve();
    return finishGeneration.promise;
  };
  const server = await startManagedServer(t, configuration);

  const generateResponsePromise = postJson(
    server,
    "/api/setup/generate-key",
    {},
  );
  await generationStarted.promise;

  await assertProblem(
    await postJson(server, "/api/run", {
      target: "managed-ssh",
      command: "hostname",
    }),
    409,
    "CONFIG_BUSY",
  );
  await assertProblem(
    await postJson(
      server,
      "/api/setup/apply",
      setupApplyRequest(validProfile()),
    ),
    409,
    "CONFIG_BUSY",
  );
  assert.equal(gatewayCalls, 0);
  assert.equal(configuration.appliedProfiles.length, 0);

  finishGeneration.resolve(generatedStatus());
  assert.equal((await generateResponsePromise).status, 200);
});

test("active managed key mutation blocks runs and configuration changes", { timeout: 5_000 }, async (t) => {
  let gatewayCalls = 0;
  const gatewayDelegate = successfulGatewayFactory();
  const configuration = new FakeConfigurationService(async () => {
    gatewayCalls += 1;
    return gatewayDelegate();
  });
  const generationStarted = deferred<void>();
  const finishGeneration = deferred<ManagedSshKeyStatus>();
  configuration.generateManagedKeyHandler = () => {
    generationStarted.resolve();
    return finishGeneration.promise;
  };
  const server = await startManagedServer(t, configuration);

  const generateResponsePromise = postJson(server, "/api/admin/key/generate", {
    label: "Long generation",
    expectedKeyRevision: INITIAL_KEY_REVISION,
  });
  await generationStarted.promise;

  await assertProblem(
    await postJson(server, "/api/run", {
      target: "managed-ssh",
      command: "hostname",
    }),
    409,
    "CONFIG_BUSY",
  );
  await assertProblem(
    await postJson(server, "/api/admin/target/save", {
      alias: "blocked-target",
      target: validFleetTarget(),
    }),
    409,
    "CONFIG_BUSY",
  );
  await assertProblem(
    await postJson(server, "/api/admin/key/remove", {
      keyId: TARGET_KEY_ID,
      expectedKeyRevision: INITIAL_KEY_REVISION,
    }),
    409,
    "CONFIG_BUSY",
  );
  assert.equal(gatewayCalls, 0);
  assert.deepEqual(configuration.appliedFleets, []);
  assert.deepEqual(configuration.removedManagedKeys, []);

  finishGeneration.resolve(await configuration.keyStatus());
  assert.equal((await generateResponsePromise).status, 200);
});

test("active apply blocks run and key generation", { timeout: 5_000 }, async (t) => {
  let gatewayCalls = 0;
  const gatewayDelegate = successfulGatewayFactory();
  const configuration = new FakeConfigurationService(async () => {
    gatewayCalls += 1;
    return gatewayDelegate();
  });
  const applyStarted = deferred<void>();
  const finishApply = deferred<ManagedSshStatus>();
  configuration.applyHandler = () => {
    applyStarted.resolve();
    return finishApply.promise;
  };
  const server = await startManagedServer(t, configuration);
  const profile = validProfile();

  const applyResponsePromise = postJson(
    server,
    "/api/setup/apply",
    setupApplyRequest(profile),
  );
  await applyStarted.promise;

  await assertProblem(
    await postJson(server, "/api/run", {
      target: "managed-ssh",
      command: "hostname",
    }),
    409,
    "CONFIG_BUSY",
  );
  await assertProblem(
    await postJson(server, "/api/setup/generate-key", {}),
    409,
    "CONFIG_BUSY",
  );
  assert.equal(gatewayCalls, 0);
  assert.equal(configuration.generateCalls, 0);

  finishApply.resolve(readyStatus(profile));
  assert.equal((await applyResponsePromise).status, 200);
});

function validProfile(): CurrentManagedSshProfile {
  return {
    target: {
      host: "target.example.internal",
      port: 22,
      username: "automation",
      identityFile: String.raw`C:\Users\operator\.ssh\target_ed25519`,
    },
    knownHostsFile: String.raw`C:\Users\operator\.ssh\known_hosts`,
    platform: "windows",
    policyMode: "allow-list",
    bastion: {
      host: "bastion.example.internal",
      port: 2_222,
      username: "jump-user",
      identityFile: String.raw`C:\Users\operator\.ssh\bastion_ed25519`,
    },
    allowedCommands: ["hostname", "whoami"],
  };
}

function validFleetTarget(): ManagedSshFleetTarget {
  const profile = validProfile();
  return {
    description: "Managed test target",
    enabled: true,
    target: {
      host: profile.target.host,
      port: profile.target.port,
      username: profile.target.username,
      keyId: TARGET_KEY_ID,
    },
    knownHostsFile: profile.knownHostsFile,
    ...(profile.bastion === undefined
      ? {}
      : {
          bastion: {
            host: profile.bastion.host,
            port: profile.bastion.port,
            username: profile.bastion.username,
            keyId: BASTION_KEY_ID,
          },
        }),
    platform: profile.platform,
    policyMode: "allow-list",
    allowedCommands: ["hostname", "custom status --json"],
    maxTimeoutMs: 45_000,
  };
}

function validAccessClientFleetTarget(): ManagedSshFleetTarget {
  return {
    description: "AccessClient shared target",
    enabled: true,
    connectionMode: "accessclient-share",
    target: {
      host: "target.example.internal",
      port: 22,
      username: "Administrator",
    },
    accessClient: {
      gatewayHost: "access.example.internal",
      gatewayPort: 22,
      gatewayUsername: "portal-user",
      expectedHostname: "target.example.internal",
    },
    platform: "windows",
    policyMode: "allow-list",
    allowedCommands: ["hostname", "whoami"],
    maxTimeoutMs: 45_000,
    transferMode: "deny",
  };
}

function configureAccessClientTarget(
  configuration: FakeConfigurationService,
  revision: string,
): void {
  configuration.fleetRevision = revision;
  configuration.fleetProfile = {
    version: 3,
    accessClient: { plinkExecutable: accessClientExecutablePath() },
    targets: {
      "gpu-build": {
        ...validAccessClientFleetTarget(),
        accessClient: {
          ...validAccessClientFleetTarget().accessClient!,
          sharingHost: "120.92.76.66",
          sharingPort: 22,
        },
      },
    },
  };
}

function accessClientExecutablePath(): string {
  return process.platform === "win32"
    ? String.raw`G:\PuTTY\plink.exe`
    : "/opt/putty/plink";
}

function managedKeySummary(
  keyId: string,
  label: string,
  origin: ManagedSshKeySummary["origin"],
  algorithm = "ssh-ed25519",
): ManagedSshKeySummary {
  return {
    keyId,
    label,
    algorithm,
    fingerprint: `SHA256:${"A".repeat(43)}`,
    publicKey: `${algorithm} ${Buffer.alloc(32, Number.parseInt(keyId.at(-1) ?? "1", 16)).toString("base64")}`,
    createdAt: "2026-08-10T00:00:00.000Z",
    origin,
    inUseBy: [],
  };
}

function privateKeySourcePath(): string {
  return process.platform === "win32"
    ? String.raw`C:\Users\operator\.ssh\id_ed25519`
    : "/home/operator/.ssh/id_ed25519";
}

function unconfiguredStatus(): ManagedSshStatus {
  return {
    state: "unconfigured",
    configured: false,
    defaultKnownHostsFile: String.raw`C:\Users\operator\.ssh\known_hosts`,
    allowedCommands: [...MANAGED_SUPPORTED_COMMANDS],
  };
}

function generatedStatus(): ManagedSshStatus {
  return {
    ...unconfiguredStatus(),
    generatedKey: {
      privateKeyPath: String.raw`C:\managed\keys\agent_ssh_ed25519`,
      publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest agent-ssh-gateway",
    },
  };
}

function readyStatus(profile: ManagedSshProfile): ManagedSshStatus {
  return {
    state: "ready",
    configured: true,
    defaultKnownHostsFile: profile.knownHostsFile,
    allowedCommands: [...MANAGED_SUPPORTED_COMMANDS],
    profile,
  };
}

function successfulGatewayFactory(): TestUiGatewayFactory {
  return () => Promise.resolve(successfulGatewaySession());
}

function successfulGatewaySession(): TestUiGatewaySession {
  const ping: PingResult = {
    ok: true,
    protocolVersion: PROTOCOL_VERSION,
    serverTime: "2026-08-06T00:00:00.000Z",
  };
  const targets: TargetListResult = { targets: [] };
  return {
    ping: () => Promise.resolve(ping),
    listTargets: () => Promise.resolve(targets),
    checkTarget: ({ target }) =>
      Promise.resolve({
        target,
        connected: true,
        termination: "exit",
        exitCode: 0,
        durationMs: 1,
        hostname: "test-host",
      }),
    run: () => Promise.resolve(exitResult()),
    readOutput: () => Promise.reject(new Error("No retained output")),
    close: () => undefined,
  };
}

function controlledRunGatewayFactory(
  started: Deferred<AbortSignal>,
): TestUiGatewayFactory {
  return () =>
    Promise.resolve({
      ...successfulGatewaySession(),
      run: (_params, signal) => {
        started.resolve(signal);
        return waitForCancellation(signal);
      },
    });
}

function waitForCancellation(signal: AbortSignal): Promise<ExecResult> {
  return new Promise((resolve) => {
    const finish = (): void => resolve(cancelResult());
    if (signal.aborted) {
      finish();
    } else {
      signal.addEventListener("abort", finish, { once: true });
    }
  });
}

function exitResult(): ExecResult {
  return {
    requestId: "private-request-id",
    termination: "exit",
    exitCode: 0,
    durationMs: 1,
    stdout: { text: "ok\n", bytes: 3, inlineTruncated: false },
    stderr: { text: "", bytes: 0, inlineTruncated: false },
  };
}

function cancelResult(): ExecResult {
  return {
    ...exitResult(),
    termination: "cancel",
    exitCode: null,
    stdout: { text: "", bytes: 0, inlineTruncated: false },
  };
}

function deferred<Value>(): Deferred<Value> {
  let resolvePromise!: (value: Value) => void;
  const promise = new Promise<Value>((resolve) => {
    resolvePromise = resolve;
  });
  return { promise, resolve: resolvePromise };
}
