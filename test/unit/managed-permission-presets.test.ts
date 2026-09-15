import assert from "node:assert/strict";
import test from "node:test";

import { managedFleetTargetSchema, managedSshFleetProfileSchema } from "../../src/test-ui/managed.js";

const target = {
  enabled: true,
  connectionMode: "openssh",
  target: { host: "example.test", port: 22, username: "operator", keyId: `k-${"a".repeat(32)}` },
  knownHostsFile: "C:\\keys\\known_hosts",
  platform: "linux",
  policyMode: "presets",
  allowedCommands: [],
  permissionPresets: ["basic-inspection", "log-inspection", "docker-readonly", "docker-protection"],
  logPaths: ["/var/log/app.log"],
  logServices: ["app.service"],
  maxTimeoutMs: 30_000,
  transferMode: "deny",
};

test("managed preset selections survive fleet serialization without converting other machines", () => {
  const legacy = { ...target, policyMode: "full-access", permissionPresets: undefined, logPaths: undefined, logServices: undefined };
  const { permissionPresets: _presets, logPaths: _paths, logServices: _services, ...unrestricted } = legacy;
  const profile = { version: 3, targets: { restricted: target, existing: unrestricted } };
  const parsed = managedSshFleetProfileSchema.parse(JSON.parse(JSON.stringify(profile)));
  assert.deepEqual(parsed.targets.restricted, target);
  assert.equal(parsed.targets.existing!.policyMode, "full-access");
});

test("managed presets reject raw command and transfer bypasses and conflicting full access", () => {
  for (const patch of [
    { allowedCommands: ["docker stop app"] },
    { transferMode: "upload", localRootPath: "C:\\files", remoteRoots: ["/srv"] },
    { localRootPath: "C:\\files" },
    { policyMode: "full-access" },
    { permissionPresets: ["docker-protection", "docker-protection"] },
    { permissionPresets: ["unknown-preset"] },
    { logPaths: ["relative.log"] },
    { logServices: ["app;shutdown"] },
  ]) assert.equal(managedFleetTargetSchema.safeParse({ ...target, ...patch }).success, false, JSON.stringify(patch));
});
