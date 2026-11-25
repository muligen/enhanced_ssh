import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import {
  InMemoryTransport,
  type JSONRPCMessage,
} from "@modelcontextprotocol/server";

import { createMcpServer } from "../../src/mcp/server.js";
import { deriveAliasFromHost } from "../../src/mcp/admin.js";
import { publishAdminDescriptor } from "../../src/service/control-plane.js";
import {
  createInMemoryMcpAdminPolicy,
  loadMcpAdminPolicy,
  type McpAdminPolicyStore,
} from "../../src/service/mcp-admin-policy.js";
import {
  PROTOCOL_VERSION,
  type TargetCheckResult,
} from "../../src/shared/protocol.js";
import type {
  AccessClientSessionArmRequest,
  AccessClientSessionPreparer,
  AccessClientSessionSnapshot,
  AccessClientSessionVerification,
} from "../../src/test-ui/accessclient-session.js";
import type {
  TestUiGatewayFactory,
  TestUiGatewaySession,
} from "../../src/test-ui/gateway.js";
import {
  MANAGED_PLATFORM_COMMANDS,
  MANAGED_SUPPORTED_COMMANDS,
  ManagedSshError,
  managedSshFleetProfileSchema,
  type CurrentManagedSshProfile,
  type ManagedSshFleetProfile,
  type ManagedSshFleetStatus,
  type ManagedSshKeyGenerationAlgorithm,
  type ManagedSshKeyStatus,
  type ManagedSshKeySummary,
  type ManagedSshStatus,
  type TestUiConfigurationService,
} from "../../src/test-ui/managed.js";
import {
  startTestUiServer,
  type AdminActionEvent,
  type InteractiveSshInstallOptions,
  type RunningTestUiServer,
} from "../../src/test-ui/server.js";

const PRIVATE_KEY_SENTINEL = "PRIVATE-KEY-CONTENTS-MUST-NEVER-LEAK-TO-MCP";
const INITIAL_KEY_ID = `k-${"1".repeat(32)}`;

class FakeConfigurationService implements TestUiConfigurationService {
  public readonly gatewayFactory: TestUiGatewayFactory;
  public readonly defaultKnownHostsFile: string;
  public fleetProfile: ManagedSshFleetProfile | undefined;
  public fleetRevision: string | undefined;
  public keyRevision = `kr-init-${"a".repeat(32)}`;
  public keys: ManagedSshKeySummary[];
  public checkHandler: (target: string) => TargetCheckResult = (target) => ({
    target,
    connected: true,
    termination: "exit",
    exitCode: 0,
    hostname: `${target}.internal`,
    durationMs: 12,
  });
  #revisionSeq = 0;
  #keySeq = 1;

  public constructor(defaultKnownHostsFile: string) {
    this.defaultKnownHostsFile = defaultKnownHostsFile;
    this.keys = [
      {
        keyId: INITIAL_KEY_ID,
        label: "Existing key",
        algorithm: "ssh-ed25519",
        fingerprint: "SHA256:existingfingerprint0123456789abcdef",
        publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExistingKey existing",
        createdAt: "2026-08-01T00:00:00.000Z",
        origin: "generated",
        inUseBy: [],
        // Verify publicFleetStatus strips sensitive fields before returning to MCP.
        privateKeyPath: PRIVATE_KEY_SENTINEL,
      } as ManagedSshKeySummary,
    ];
    this.gatewayFactory = async (): Promise<TestUiGatewaySession> => ({
      ping: async () => ({
        ok: true,
        protocolVersion: PROTOCOL_VERSION,
        serverTime: "2026-08-01T00:00:00.000Z",
      }),
      listTargets: async () => ({ targets: [] }),
      checkTarget: async (params) => this.checkHandler(params.target),
      run: async () => {
        throw new Error("run not implemented in test fake");
      },
      readOutput: async () => {
        throw new Error("readOutput not implemented in test fake");
      },
      close: () => undefined,
    });
  }

  public async status(): Promise<ManagedSshStatus> {
    return {
      state: this.fleetProfile === undefined ? "unconfigured" : "ready",
      configured: this.fleetProfile !== undefined,
      defaultKnownHostsFile: this.defaultKnownHostsFile,
      allowedCommands: [...MANAGED_SUPPORTED_COMMANDS],
      ...(this.fleetRevision === undefined ? {} : { revision: this.fleetRevision }),
    };
  }

  public async fleetStatus(): Promise<ManagedSshFleetStatus> {
    return {
      state: this.fleetProfile === undefined ? "unconfigured" : "ready",
      configured: this.fleetProfile !== undefined,
      defaultKnownHostsFile: this.defaultKnownHostsFile,
      commandPresets: MANAGED_PLATFORM_COMMANDS,
      keyRevision: this.keyRevision,
      keys: this.keys.map((key) => ({ ...key, inUseBy: this.#referencesFor(key.keyId) })),
      ...(this.fleetRevision === undefined ? {} : { revision: this.fleetRevision }),
      ...(this.fleetProfile === undefined ? {} : { profile: this.fleetProfile }),
    };
  }

  public async keyStatus(): Promise<ManagedSshKeyStatus> {
    return {
      keyRevision: this.keyRevision,
      keys: this.keys.map((key) => ({ ...key, inUseBy: this.#referencesFor(key.keyId) })),
    };
  }

  public async generateKey(): Promise<ManagedSshStatus> {
    return this.status();
  }

  public async generateManagedKey(
    label: string,
    expectedKeyRevision: string,
    algorithm: ManagedSshKeyGenerationAlgorithm = "ed25519",
  ): Promise<ManagedSshKeyStatus> {
    this.#assertKeyRevision(expectedKeyRevision);
    if (this.keys.some((key) => key.label.toLowerCase() === label.toLowerCase())) {
      throw new ManagedSshError(409, "KEY_LABEL_EXISTS", "A key with this label already exists");
    }
    this.#keySeq += 1;
    const keyId = `k-${String(this.#keySeq).padStart(32, "0")}`;
    const keyType = algorithm === "rsa-3072" ? "ssh-rsa" : "ssh-ed25519";
    this.keys.push({
      keyId,
      label,
      algorithm: keyType,
      fingerprint: `SHA256:generated${this.#keySeq}`,
      publicKey: `${keyType} AAAAC3NzaC1lZDI1NTE5AAAAIGenerated${this.#keySeq} ${label}`,
      createdAt: "2026-08-02T00:00:00.000Z",
      origin: "generated",
      inUseBy: [],
    });
    this.#advanceKeyRevision();
    return this.keyStatus();
  }

  public async importManagedKey(): Promise<ManagedSshKeyStatus> {
    throw new Error("importManagedKey must never be called by MCP");
  }

  public async renameManagedKey(
    keyId: string,
    label: string,
    expectedKeyRevision: string,
  ): Promise<ManagedSshKeyStatus> {
    this.#assertKeyRevision(expectedKeyRevision);
    const index = this.keys.findIndex((key) => key.keyId === keyId);
    if (index < 0) {
      throw new ManagedSshError(404, "KEY_NOT_FOUND", "Key was not found");
    }
    this.keys[index] = { ...this.keys[index]!, label };
    this.#advanceKeyRevision();
    return this.keyStatus();
  }

  public async removeManagedKey(
    keyId: string,
    expectedKeyRevision: string,
  ): Promise<ManagedSshKeyStatus> {
    this.#assertKeyRevision(expectedKeyRevision);
    const index = this.keys.findIndex((key) => key.keyId === keyId);
    if (index < 0) {
      throw new ManagedSshError(404, "KEY_NOT_FOUND", "Key was not found");
    }
    if (this.#referencesFor(keyId).length > 0) {
      throw new ManagedSshError(409, "KEY_IN_USE", "Key is still referenced by a target");
    }
    this.keys.splice(index, 1);
    this.#advanceKeyRevision();
    return this.keyStatus();
  }

  public async apply(_profile: CurrentManagedSshProfile): Promise<ManagedSshStatus> {
    return this.status();
  }

  public async applyFleet(
    profile: ManagedSshFleetProfile,
    expectedRevision?: string,
  ): Promise<ManagedSshFleetStatus> {
    if (expectedRevision !== this.fleetRevision) {
      throw new ManagedSshError(409, "CONFIG_CONFLICT", "Configuration changed concurrently");
    }
    this.fleetProfile = managedSshFleetProfileSchema.parse(profile);
    this.#revisionSeq += 1;
    this.fleetRevision = `r-test-${this.#revisionSeq.toString(16).padStart(32, "0")}`;
    return this.fleetStatus();
  }

  public async close(): Promise<void> {}

  #assertKeyRevision(expected: string): void {
    if (expected !== this.keyRevision) {
      throw new ManagedSshError(409, "KEY_REVISION_CONFLICT", "Key revision changed");
    }
  }

  #advanceKeyRevision(): void {
    this.keyRevision = `kr-step-${this.#keySeq.toString(16).padStart(32, "0")}`;
  }

  #referencesFor(keyId: string): ManagedSshKeySummary["inUseBy"] {
    const refs: Array<{ alias: string; targetId?: string; role: "target" | "bastion" }> = [];
    for (const [alias, target] of Object.entries(this.fleetProfile?.targets ?? {})) {
      if (target.target.keyId === keyId) {
        refs.push({
          alias,
          ...(target.targetId === undefined ? {} : { targetId: target.targetId }),
          role: "target",
        });
      }
      if (target.bastion?.keyId === keyId) {
        refs.push({
          alias,
          ...(target.targetId === undefined ? {} : { targetId: target.targetId }),
          role: "bastion",
        });
      }
    }
    return refs;
  }
}

class FakeAccessClientPreparer implements AccessClientSessionPreparer {
  public snapshot: AccessClientSessionSnapshot = { state: "idle" };

  public async initialize(): Promise<void> {}

  public async prepare(
    request: AccessClientSessionArmRequest,
  ): Promise<AccessClientSessionSnapshot> {
    this.snapshot = {
      state: "detected",
      alias: request.alias,
      sharingHost: request.sharingHost,
      sharingPort: request.sharingPort,
      startedAt: "2026-08-03T00:00:00.000Z",
      deadlineAt: "2026-08-03T00:02:00.000Z",
    };
    return this.snapshot;
  }

  public status(): AccessClientSessionSnapshot {
    return this.snapshot;
  }

  public async verify(
    alias: string,
    verification: AccessClientSessionVerification,
  ): Promise<AccessClientSessionSnapshot> {
    this.snapshot = {
      state: "ready",
      alias,
      ...(verification.hostname === undefined
        ? {}
        : { hostname: verification.hostname }),
      ...(verification.durationMs === undefined
        ? {}
        : { durationMs: verification.durationMs }),
      completedAt: "2026-08-03T00:00:05.000Z",
    };
    return this.snapshot;
  }

  public async reject(
    alias: string,
    message: string,
  ): Promise<AccessClientSessionSnapshot> {
    this.snapshot = { state: "error", alias, message };
    return this.snapshot;
  }

  public async cancel(alias: string): Promise<AccessClientSessionSnapshot> {
    this.snapshot = { state: "cancelled", alias };
    return this.snapshot;
  }

  public async close(): Promise<void> {}
}

class InMemoryMcpPeer {
  readonly #clientTransport: InMemoryTransport;
  readonly #pending = new Map<
    number,
    { resolve: (msg: Record<string, unknown>) => void; reject: (err: Error) => void }
  >();
  #nextId = 1;

  public constructor(clientTransport: InMemoryTransport) {
    this.#clientTransport = clientTransport;
    clientTransport.onmessage = (message: JSONRPCMessage) => {
      if ("id" in message && typeof message.id === "number") {
        const entry = this.#pending.get(message.id);
        if (entry !== undefined) {
          this.#pending.delete(message.id);
          entry.resolve(message as unknown as Record<string, unknown>);
        }
      }
    };
  }

  public async initialize(): Promise<void> {
    await this.#clientTransport.start();
    const res = await this.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "mcp-admin-test", version: "1.0.0" },
    });
    assert.equal(res.error, undefined);
    await this.#clientTransport.send({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    });
  }

  public request(
    method: string,
    params: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      void this.#clientTransport
        .send({ jsonrpc: "2.0", id, method, params })
        .catch((error: unknown) => {
          this.#pending.delete(id);
          reject(error instanceof Error ? error : new Error(String(error)));
        });
    });
  }

  public async callTool(
    name: string,
    args: Record<string, unknown> = {},
  ): Promise<{
    isError: boolean;
    text: string;
    structured?: Record<string, unknown>;
  }> {
    const response = await this.request("tools/call", { name, arguments: args });
    assert.equal(response.error, undefined, `Unexpected JSON-RPC error: ${JSON.stringify(response.error)}`);
    const result = response.result as {
      isError?: boolean;
      content?: Array<{ type: string; text: string }>;
      structuredContent?: Record<string, unknown>;
    };
    return {
      isError: result.isError === true,
      text: result.content?.[0]?.text ?? "",
      ...(result.structuredContent === undefined
        ? {}
        : { structured: result.structuredContent }),
    };
  }

  public async close(): Promise<void> {
    await this.#clientTransport.close();
  }
}

async function createTestHarness(
  t: TestContext,
  options: {
    readonly policy?: McpAdminPolicyStore;
    readonly publishDescriptor?: boolean;
    readonly withPreparer?: boolean;
  } = {},
) {
  const sandbox = await mkdtemp(path.join(os.tmpdir(), "agent-ssh-mcp-admin-"));
  const runtimeDir = path.join(sandbox, "runtime");
  await mkdir(runtimeDir, { recursive: true });
  const defaultKnownHostsFile = path.join(sandbox, "known_hosts");
  const configuration = new FakeConfigurationService(defaultKnownHostsFile);
  const policy = options.policy ?? (await loadMcpAdminPolicy(sandbox));
  const installCalls: InteractiveSshInstallOptions[] = [];
  const adminActions: AdminActionEvent[] = [];
  const preparer = options.withPreparer ? new FakeAccessClientPreparer() : undefined;

  const server: RunningTestUiServer = await startTestUiServer({
    mode: "managed",
    gatewayFactory: configuration.gatewayFactory,
    configurationService: configuration,
    mcpAdminPolicy: policy,
    ...(preparer === undefined ? {} : { accessClientSessionPreparer: preparer }),
    launchSshInstall: (installOptions) => {
      installCalls.push(installOptions);
    },
    onAdminAction: (event) => {
      adminActions.push(event);
    },
  });

  if (options.publishDescriptor !== false) {
    await publishAdminDescriptor(runtimeDir, {
      version: 1,
      pid: process.pid,
      origin: server.origin,
      url: server.url,
      startedAt: new Date().toISOString(),
      mcpAdminToken: server.mcpAdminToken,
    });
  }

  const mcpServer = createMcpServer(
    async () => {
      throw new Error("Gateway RPC should not be needed for admin tools");
    },
    { dataDirectory: runtimeDir },
  );
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await mcpServer.connect(serverTransport);
  const peer = new InMemoryMcpPeer(clientTransport);
  await peer.initialize();

  t.after(async () => {
    await peer.close().catch(() => undefined);
    await mcpServer.close().catch(() => undefined);
    await server.close().catch(() => undefined);
    await rm(sandbox, { recursive: true, force: true });
  });

  return {
    sandbox,
    runtimeDir,
    defaultKnownHostsFile,
    configuration,
    policy,
    preparer,
    server,
    peer,
    installCalls,
    adminActions,
  };
}

function browserPost(
  server: RunningTestUiServer,
  route: string,
  body: object,
): Promise<Response> {
  return fetch(`${server.origin}${route}`, {
    method: "POST",
    headers: {
      Origin: server.origin,
      "Sec-Fetch-Site": "same-origin",
      "X-Agent-SSH-UI-Token": server.sessionToken,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

function mcpPost(
  server: RunningTestUiServer,
  route: string,
  body: object,
  extraHeaders: Record<string, string> = {},
): Promise<Response> {
  return fetch(`${server.origin}${route}`, {
    method: "POST",
    headers: {
      "X-Agent-SSH-MCP-Token": server.mcpAdminToken,
      "Content-Type": "application/json",
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  });
}

test("deriveAliasFromHost canonicalizes IPv4, IPv6, and valid DNS hostnames", () => {
  assert.equal(deriveAliasFromHost("10.0.1.50"), "10.0.1.50");
  assert.equal(deriveAliasFromHost("2001:0db8::1"), "ip-2001-db8--1");
  assert.equal(deriveAliasFromHost("web-prod.example.com"), "web-prod.example.com");
});

test("MCP admin is disabled by default, leaks no config, blocks self-enable/import, and activates live once browser enables it", async (t) => {
  const { server, peer, configuration } = await createTestHarness(t);

  // Verify tools/list exposes all 12 ssh_admin_* tools with valid object schemas.
  const listRes = await peer.request("tools/list", {});
  const tools = (listRes.result as { tools: Array<{ name: string; inputSchema?: { type?: string } }> }).tools;
  const adminTools = tools.filter((tool) => tool.name.startsWith("ssh_admin_"));
  assert.equal(adminTools.length, 12);
  for (const tool of adminTools) {
    assert.equal(tool.inputSchema?.type, "object", `${tool.name} must have an object JSON schema`);
  }

  // Default disabled: ssh_admin_get_config reports disabled and leaks zero config/keys/tokens.
  const disabledConfig = await peer.callTool("ssh_admin_get_config");
  assert.equal(disabledConfig.isError, false);
  assert.equal(disabledConfig.structured?.serviceRunning, true);
  assert.equal(disabledConfig.structured?.mcpAdminEnabled, false);
  assert.equal(disabledConfig.structured?.mcpAdminSource, "settings");
  assert.equal(disabledConfig.structured?.keys, undefined);
  assert.equal(disabledConfig.structured?.targets, undefined);
  assert.equal(disabledConfig.structured?.defaultKnownHostsFile, undefined);
  assert.equal(disabledConfig.text.includes(server.sessionToken), false);
  assert.equal(disabledConfig.text.includes(server.mcpAdminToken), false);
  assert.equal(disabledConfig.text.includes(PRIVATE_KEY_SENTINEL), false);

  // Disabled write tool fails cleanly with MCP_ADMIN_DISABLED.
  const blockedWrite = await peer.callTool("ssh_admin_manage_group", {
    action: "create",
    name: "生产组",
  });
  assert.equal(blockedWrite.isError, true);
  assert.match(blockedWrite.text, /MCP_ADMIN_DISABLED/u);

  // MCP token can NEVER toggle the switch or import private keys or send browser headers.
  assert.equal((await mcpPost(server, "/api/admin/mcp-admin/save", { enabled: true })).status, 403);
  assert.equal((await mcpPost(server, "/api/admin/key/import", {
    label: "stolen",
    sourcePath: path.resolve("/etc/passwd"),
    expectedKeyRevision: configuration.keyRevision,
  })).status, 403);
  assert.equal((await mcpPost(server, "/api/admin/mcp-admin/status", {}, { Origin: server.origin })).status, 403);
  assert.equal((await mcpPost(server, "/api/run", { target: "x", command: "id" })).status, 403);

  // Browser administrator enables MCP admin -> takes effect immediately without restart.
  const enableRes = await browserPost(server, "/api/admin/mcp-admin/save", { enabled: true });
  assert.equal(enableRes.status, 200);
  const enableBody = (await enableRes.json()) as { mcpAdmin: { enabled: boolean; persistedEnabled: boolean; source: string } };
  assert.deepEqual(enableBody.mcpAdmin, { enabled: true, persistedEnabled: true, source: "settings" });

  // Even when enabled, MCP STILL cannot toggle the switch or import keys from disk.
  const selfDisable = await mcpPost(server, "/api/admin/mcp-admin/save", { enabled: false });
  assert.equal(selfDisable.status, 403);
  assert.equal(((await selfDisable.json()) as { error: { code: string } }).error.code, "MCP_ADMIN_FORBIDDEN");

  const importAttempt = await mcpPost(server, "/api/admin/key/import", {
    label: "stolen",
    sourcePath: path.resolve("/tmp/id_ed25519"),
    expectedKeyRevision: configuration.keyRevision,
  });
  assert.equal(importAttempt.status, 403);
  assert.equal(((await importAttempt.json()) as { error: { code: string } }).error.code, "MCP_ADMIN_FORBIDDEN");

  // ssh_admin_get_config now returns full sanitized config without private keys or tokens.
  const enabledConfig = await peer.callTool("ssh_admin_get_config");
  assert.equal(enabledConfig.isError, false);
  assert.equal(enabledConfig.structured?.mcpAdminEnabled, true);
  assert.equal(enabledConfig.structured?.defaultGroup, "默认分组");
  assert.equal(Array.isArray(enabledConfig.structured?.keys), true);
  assert.equal(Array.isArray(enabledConfig.structured?.permissionPresets), true);
  assert.equal(enabledConfig.text.includes(PRIVATE_KEY_SENTINEL), false);
  assert.equal(enabledConfig.text.includes("privateKeyPath"), false);
  assert.equal(enabledConfig.text.includes(server.sessionToken), false);
  assert.equal(enabledConfig.text.includes(server.mcpAdminToken), false);
});

test("ssh_admin_get_config reports serviceRunning=false cleanly when admin.json is absent", async (t) => {
  const { peer } = await createTestHarness(t, { publishDescriptor: false });
  const result = await peer.callTool("ssh_admin_get_config");
  assert.equal(result.isError, false);
  assert.equal(result.structured?.serviceRunning, false);
  assert.equal(result.structured?.mcpAdminEnabled, false);
});

test("CLI --allow-mcp-admin enables MCP admin and locks browser toggle with 409", async (t) => {
  const policy = createInMemoryMcpAdminPolicy(false, { forceEnabledByCli: true });
  const { server, peer } = await createTestHarness(t, { policy });

  const config = await peer.callTool("ssh_admin_get_config");
  assert.equal(config.isError, false);
  assert.equal(config.structured?.mcpAdminEnabled, true);
  assert.equal(config.structured?.mcpAdminSource, "cli");

  const toggleRes = await browserPost(server, "/api/admin/mcp-admin/save", { enabled: false });
  assert.equal(toggleRes.status, 409);
  assert.equal(((await toggleRes.json()) as { error: { code: string } }).error.code, "MCP_ADMIN_CLI_OVERRIDE");
});

test("full onboarding and management lifecycle via MCP tools enforces confirmations and optimistic revisions", async (t) => {
  const policy = createInMemoryMcpAdminPolicy(true);
  const {
    sandbox,
    defaultKnownHostsFile,
    server,
    peer,
    installCalls,
    adminActions,
  } = await createTestHarness(t, { policy });

  let config = (await peer.callTool("ssh_admin_get_config")).structured!;
  let keyRevision = config.keyRevision as string;
  let revision = (config.revision as string | null) ?? undefined;

  // 1. Generate and rename SSH key.
  const genKey = await peer.callTool("ssh_admin_generate_key", {
    label: "Ubuntu 部署密钥",
    algorithm: "ed25519",
    expectedKeyRevision: keyRevision,
  });
  assert.equal(genKey.isError, false);
  const generatedKey = genKey.structured?.generatedKey as { keyId: string; publicKey: string };
  assert.ok(generatedKey.keyId.startsWith("k-"));
  keyRevision = genKey.structured?.keyRevision as string;

  const renamedKey = await peer.callTool("ssh_admin_rename_key", {
    keyId: generatedKey.keyId,
    label: "生产部署密钥",
    expectedKeyRevision: keyRevision,
  });
  assert.equal(renamedKey.isError, false);
  keyRevision = renamedKey.structured?.keyRevision as string;

  // 2. Launch local interactive SSH public key install (uses defaultKnownHostsFile when omitted).
  const install = await peer.callTool("ssh_admin_launch_ssh_install", {
    host: "10.0.1.50",
    port: 2222,
    username: "ubuntu",
    platform: "linux",
    keyId: generatedKey.keyId,
  });
  assert.equal(install.isError, false);
  assert.equal(installCalls.length, 1);
  assert.equal(installCalls[0]?.host, "10.0.1.50");
  assert.equal(installCalls[0]?.port, 2222);
  assert.equal(installCalls[0]?.knownHostsFile, defaultKnownHostsFile);
  assert.equal(installCalls[0]?.publicKey, generatedKey.publicKey);

  // 3. Create group, save OpenSSH presets machine with auto-derived alias from IPv4.
  const createdGroup = await peer.callTool("ssh_admin_manage_group", {
    action: "create",
    name: "生产组",
    ...(revision === undefined ? {} : { expectedRevision: revision }),
  });
  assert.equal(createdGroup.isError, false);
  revision = createdGroup.structured?.revision as string;

  const savedPresets = await peer.callTool("ssh_admin_save_target", {
    expectedRevision: revision,
    target: {
      description: "Ubuntu 生产节点",
      group: "生产组",
      enabled: true,
      connectionMode: "openssh",
      platform: "linux",
      target: {
        host: "10.0.1.50",
        port: 2222,
        username: "ubuntu",
        keyId: generatedKey.keyId,
      },
      policyMode: "presets",
      permissionPresets: ["basic-inspection", "docker-readonly"],
      maxTimeoutMs: 30_000,
    },
  });
  assert.equal(savedPresets.isError, false, savedPresets.text);
  assert.equal(savedPresets.structured?.alias, "10.0.1.50");
  revision = savedPresets.structured?.revision as string;

  // 4. High-risk confirmation checks: full-access and file transfer must be explicitly confirmed.
  const missingFullConfirm = await peer.callTool("ssh_admin_save_target", {
    alias: "10.0.1.50",
    previousAlias: "10.0.1.50",
    expectedRevision: revision,
    target: {
      enabled: true,
      connectionMode: "openssh",
      platform: "linux",
      target: {
        host: "10.0.1.50",
        port: 2222,
        username: "ubuntu",
        keyId: generatedKey.keyId,
      },
      policyMode: "full-access",
      maxTimeoutMs: 60_000,
    },
  });
  assert.equal(missingFullConfirm.isError, true);
  assert.match(missingFullConfirm.text, /CONFIRMATION_REQUIRED/u);

  const localRoot = path.join(sandbox, "uploads");
  const missingTransferConfirm = await peer.callTool("ssh_admin_save_target", {
    alias: "10.0.1.50",
    previousAlias: "10.0.1.50",
    expectedRevision: revision,
    target: {
      enabled: true,
      connectionMode: "openssh",
      platform: "linux",
      target: {
        host: "10.0.1.50",
        port: 2222,
        username: "ubuntu",
        keyId: generatedKey.keyId,
      },
      policyMode: "allow-list",
      allowedCommands: ["hostname", "uptime"],
      transferMode: "upload",
      localRootPath: localRoot,
      remoteRoots: ["/srv/uploads"],
      maxTimeoutMs: 60_000,
    },
  });
  assert.equal(missingTransferConfirm.isError, true);
  assert.match(missingTransferConfirm.text, /CONFIRMATION_REQUIRED/u);

  // With transferAccessConfirmed: true -> succeeds!
  const confirmedTransfer = await peer.callTool("ssh_admin_save_target", {
    alias: "10.0.1.50",
    previousAlias: "10.0.1.50",
    expectedRevision: revision,
    transferAccessConfirmed: true,
    target: {
      enabled: true,
      connectionMode: "openssh",
      platform: "linux",
      target: {
        host: "10.0.1.50",
        port: 2222,
        username: "ubuntu",
        keyId: generatedKey.keyId,
      },
      policyMode: "allow-list",
      allowedCommands: ["hostname", "uptime"],
      transferMode: "upload",
      localRootPath: localRoot,
      remoteRoots: ["/srv/uploads"],
      maxTimeoutMs: 60_000,
    },
  });
  assert.equal(confirmedTransfer.isError, false, confirmedTransfer.text);
  revision = confirmedTransfer.structured?.revision as string;

  // With fullAccessConfirmed: true -> succeeds!
  const confirmedFull = await peer.callTool("ssh_admin_save_target", {
    alias: "prod-ubuntu",
    previousAlias: "10.0.1.50",
    expectedRevision: revision,
    fullAccessConfirmed: true,
    target: {
      enabled: true,
      connectionMode: "openssh",
      platform: "linux",
      target: {
        host: "10.0.1.50",
        port: 2222,
        username: "ubuntu",
        keyId: generatedKey.keyId,
      },
      policyMode: "full-access",
      maxTimeoutMs: 60_000,
    },
  });
  assert.equal(confirmedFull.isError, false, confirmedFull.text);
  assert.equal(confirmedFull.structured?.alias, "prod-ubuntu");
  revision = confirmedFull.structured?.revision as string;

  // 5. Toggle enabled, check connection, rename/reorder/move/delete groups.
  const disabledTarget = await peer.callTool("ssh_admin_set_target_enabled", {
    alias: "prod-ubuntu",
    enabled: false,
    expectedRevision: revision,
  });
  assert.equal(disabledTarget.isError, false);
  revision = disabledTarget.structured?.revision as string;

  const checked = await peer.callTool("ssh_admin_check_target", {
    target: "prod-ubuntu",
  });
  assert.equal(checked.isError, false);
  assert.equal(checked.structured?.connected, true);

  const createdSecondGroup = await peer.callTool("ssh_admin_manage_group", {
    action: "create",
    name: "测试组",
    expectedRevision: revision,
  });
  assert.equal(createdSecondGroup.isError, false);
  revision = createdSecondGroup.structured?.revision as string;

  const reordered = await peer.callTool("ssh_admin_manage_group", {
    action: "reorder",
    groups: ["测试组", "生产组"],
    expectedRevision: revision,
  });
  assert.equal(reordered.isError, false);
  assert.deepEqual(reordered.structured?.groups, ["测试组", "生产组"]);
  revision = reordered.structured?.revision as string;

  const moved = await peer.callTool("ssh_admin_manage_group", {
    action: "move",
    aliases: ["prod-ubuntu"],
    group: "测试组",
    expectedRevision: revision,
  });
  assert.equal(moved.isError, false);
  revision = moved.structured?.revision as string;

  const renamedGroup = await peer.callTool("ssh_admin_manage_group", {
    action: "rename",
    group: "测试组",
    name: "灰度组",
    expectedRevision: revision,
  });
  assert.equal(renamedGroup.isError, false);
  revision = renamedGroup.structured?.revision as string;

  const deletedGroup = await peer.callTool("ssh_admin_manage_group", {
    action: "delete",
    group: "灰度组",
    expectedRevision: revision,
  });
  assert.equal(deletedGroup.isError, false);
  revision = deletedGroup.structured?.revision as string;

  // 6. Server-side removeConfirmed check for direct MCP HTTP call AND MCP removal tool.
  const unconfirmedRemoveTarget = await mcpPost(server, "/api/admin/target/remove", {
    alias: "prod-ubuntu",
    expectedRevision: revision,
  });
  assert.equal(unconfirmedRemoveTarget.status, 400);
  assert.equal(
    ((await unconfirmedRemoveTarget.json()) as { error: { code: string } }).error.code,
    "CONFIRMATION_REQUIRED",
  );

  // Removing a key still in use fails with KEY_IN_USE.
  const removeInUseKey = await peer.callTool("ssh_admin_remove_key", {
    keyId: generatedKey.keyId,
    expectedKeyRevision: keyRevision,
    removeConfirmed: true,
  });
  assert.equal(removeInUseKey.isError, true);
  assert.match(removeInUseKey.text, /KEY_IN_USE/u);

  // Remove target with confirmation -> succeeds, then unused key can be removed!
  const removedTarget = await peer.callTool("ssh_admin_remove_target", {
    alias: "prod-ubuntu",
    expectedRevision: revision,
    removeConfirmed: true,
  });
  assert.equal(removedTarget.isError, false);

  const unconfirmedRemoveKey = await mcpPost(server, "/api/admin/key/remove", {
    keyId: generatedKey.keyId,
    expectedKeyRevision: keyRevision,
  });
  assert.equal(unconfirmedRemoveKey.status, 400);
  assert.equal(
    ((await unconfirmedRemoveKey.json()) as { error: { code: string } }).error.code,
    "CONFIRMATION_REQUIRED",
  );

  const removedKey = await peer.callTool("ssh_admin_remove_key", {
    keyId: generatedKey.keyId,
    expectedKeyRevision: keyRevision,
    removeConfirmed: true,
  });
  assert.equal(removedKey.isError, false);
  assert.ok(adminActions.some((event) => event.caller === "mcp" && event.route === "/api/admin/target/save"));
});

test("provider settings (Tailscale & AccessClient) and AccessClient session preparation work end-to-end via MCP", async (t) => {
  const policy = createInMemoryMcpAdminPolicy(true);
  const { sandbox, peer, configuration } = await createTestHarness(t, {
    policy,
    withPreparer: true,
  });

  const tailscalePath = path.join(sandbox, "tailscale");
  const plinkPath = path.join(sandbox, "plink");

  const savedTailscale = await peer.callTool("ssh_admin_save_provider_settings", {
    provider: "tailscale",
    executable: tailscalePath,
  });
  assert.equal(savedTailscale.isError, false, savedTailscale.text);
  let revision = savedTailscale.structured?.revision as string;

  const savedTailscaleTarget = await peer.callTool("ssh_admin_save_target", {
    alias: "ts-node",
    expectedRevision: revision,
    target: {
      enabled: true,
      connectionMode: "tailscale-ssh",
      platform: "linux",
      target: { host: "100.101.102.103", port: 22, username: "ubuntu" },
      policyMode: "presets",
      permissionPresets: ["basic-inspection"],
      maxTimeoutMs: 30_000,
    },
  });
  assert.equal(savedTailscaleTarget.isError, false, savedTailscaleTarget.text);
  revision = savedTailscaleTarget.structured?.revision as string;

  const savedPlink = await peer.callTool("ssh_admin_save_provider_settings", {
    provider: "accessclient",
    executable: plinkPath,
    expectedRevision: revision,
  });
  assert.equal(savedPlink.isError, false, savedPlink.text);
  revision = savedPlink.structured?.revision as string;

  const savedAcTarget = await peer.callTool("ssh_admin_save_target", {
    alias: "corp-bastion",
    expectedRevision: revision,
    target: {
      enabled: true,
      connectionMode: "accessclient-share",
      platform: "linux",
      target: { host: "192.0.2.20", port: 22, username: "portal/192.0.2.20/ops" },
      accessClient: {
        gatewayHost: "bastion.corp.example",
        gatewayPort: 22,
        gatewayUsername: "portal",
      },
      policyMode: "deny",
      maxTimeoutMs: 30_000,
    },
  });
  assert.equal(savedAcTarget.isError, false, savedAcTarget.text);
  revision = savedAcTarget.structured?.revision as string;

  configuration.checkHandler = (target) => ({
    target,
    connected: true,
    termination: "exit",
    exitCode: 0,
    hostname: "corp-prod-01",
    durationMs: 18,
  });

  const prepared = await peer.callTool("ssh_admin_accessclient_session", {
    action: "prepare",
    alias: "corp-bastion",
    expectedRevision: revision,
  });
  assert.equal(prepared.isError, false, prepared.text);
  assert.equal(prepared.structured?.state, "detected");

  // Polling status verifies connection and learns expectedHostname automatically!
  const verified = await peer.callTool("ssh_admin_accessclient_session", {
    action: "status",
    alias: "corp-bastion",
    expectedRevision: revision,
  });
  assert.equal(verified.isError, false, verified.text);
  assert.equal(verified.structured?.state, "ready");
  assert.equal(verified.structured?.hostname, "corp-prod-01");
  assert.equal(
    configuration.fleetProfile?.targets["corp-bastion"]?.accessClient?.expectedHostname,
    "corp-prod-01",
  );

  const latestRevision = configuration.fleetRevision!;
  const cancelled = await peer.callTool("ssh_admin_accessclient_session", {
    action: "cancel",
    alias: "corp-bastion",
    expectedRevision: latestRevision,
  });
  assert.equal(cancelled.isError, false);
  assert.equal(cancelled.structured?.state, "cancelled");
});
