import assert from "node:assert/strict";
import test from "node:test";
import { MANAGED_PLATFORM_COMMANDS, managedSshFleetProfileSchema, type ManagedSshFleetProfile, type ManagedSshFleetStatus, type TestUiConfigurationService } from "../../src/test-ui/managed.js";
import { createDemoGatewayFactory } from "../../src/test-ui/gateway.js";
import { startTestUiServer } from "../../src/test-ui/server.js";

// Exercise HTTP validation, revision conflicts and profile preservation without a Windows daemon.
test("Tailscale settings and target mutations preserve both global transports and revision checks", async () => {
  let profile: ManagedSshFleetProfile = { version: 3, accessClient: { plinkExecutable: process.execPath }, targets: {} };
  let revision = `r-test-${"a".repeat(32)}`;
  let saves = 0;
  const fleetStatus = async (): Promise<ManagedSshFleetStatus> => ({ state: "ready", configured: true, defaultKnownHostsFile: process.execPath, commandPresets: MANAGED_PLATFORM_COMMANDS, keyRevision: `kr-${"a".repeat(32)}`, keys: [], revision, profile });
  const configuration: TestUiConfigurationService = {
    gatewayFactory: createDemoGatewayFactory(),
    status: async () => { throw new Error("not used"); },
    generateKey: async () => { throw new Error("not used"); },
    apply: async () => { throw new Error("not used"); },
    fleetStatus,
    keyStatus: async () => ({ keyRevision: `kr-${"a".repeat(32)}`, keys: [] }),
    generateManagedKey: async () => { throw new Error("not used"); },
    importManagedKey: async () => { throw new Error("not used"); },
    renameManagedKey: async () => { throw new Error("not used"); },
    removeManagedKey: async () => { throw new Error("not used"); },
    applyFleet: async (next: ManagedSshFleetProfile) => { profile = managedSshFleetProfileSchema.parse(next); revision = `r-test-${(++saves).toString(16).padStart(32, "0")}`; return fleetStatus(); },
    close: async () => {},
  };
  const server = await startTestUiServer({ mode: "managed", configurationService: configuration, gatewayFactory: createDemoGatewayFactory() });
  const post = (route: string, body: unknown) => fetch(`${server.origin}/api/admin/${route}`, {
    method: "POST", headers: { "Content-Type": "application/json", Origin: server.origin, "X-Agent-Ssh-Ui-Token": server.sessionToken }, body: JSON.stringify(body),
  });
  try {
    const before = revision;
    let result = await post("tailscale/save", { executable: process.execPath, expectedRevision: revision });
    assert.equal(result.status, 200, await result.text());
    assert.equal(profile.tailscale?.executable, process.execPath);
    assert.equal(profile.accessClient?.plinkExecutable, process.execPath);
    result = await post("tailscale/save", { executable: process.execPath, expectedRevision: before });
    assert.equal(result.status, 409);
    assert.equal(saves, 1);
    result = await post("target/save", { alias: "build", expectedRevision: revision, target: { enabled: true, connectionMode: "tailscale-ssh", target: { host: "build", port: 22, username: "ubuntu" }, platform: "linux", policyMode: "allow-list", allowedCommands: ["hostname"], maxTimeoutMs: 30000, transferMode: "deny" } });
    assert.equal(result.status, 200, await result.text());
    assert.equal(profile.targets.build?.connectionMode, "tailscale-ssh");
    assert.equal(profile.tailscale?.executable, process.execPath);
    assert.equal(profile.accessClient?.plinkExecutable, process.execPath);
    result = await post("access-client/save", { plinkExecutable: process.execPath, expectedRevision: revision });
    assert.equal(result.status, 200, await result.text());
    assert.equal(profile.tailscale?.executable, process.execPath);
    result = await post("target/enabled", { alias: "build", enabled: false, expectedRevision: revision });
    assert.equal(result.status, 200, await result.text());
    assert.equal(profile.targets.build?.enabled, false);
    assert.equal(profile.tailscale?.executable, process.execPath);
    result = await post("target/remove", { alias: "build", expectedRevision: revision });
    assert.equal(result.status, 200, await result.text());
    assert.equal(Object.keys(profile.targets).length, 0);
    assert.equal(profile.tailscale?.executable, process.execPath);
  } finally { await server.close(); }
});
