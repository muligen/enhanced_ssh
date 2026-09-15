import assert from "node:assert/strict";
import test from "node:test";

import { applyMetadataOverlay, fleetMetadata, isMetadataOnlyFleetChange, isRemovalOnlyFleetChange, overlayRemovedTargets, managedMetadataOverlaySchema } from "../../src/test-ui/managed-metadata.js";
import type { ManagedSshFleetProfile } from "../../src/test-ui/managed.js";

const baseRevision = `r-base-${"a".repeat(32)}`;
const profile: ManagedSshFleetProfile = {
  version: 3, groups: ["A组"], targets: {
    alpha: { enabled: true, description: "Original", group: "A组", target: { host: "127.0.0.1", port: 22, username: "test" }, platform: "linux", policyMode: "full-access", allowedCommands: [], maxTimeoutMs: 20_000 },
  },
};
const overlay = { version: 1, baseRevision, revision: `r-next-${"b".repeat(32)}`, groups: ["B组", "空组"], targets: { alpha: { group: "B组", description: "Renamed" } } };

test("metadata overlay preserves all connection and security properties and supports clearing fields", () => {
  const updated = applyMetadataOverlay(profile, overlay, baseRevision)!;
  assert.deepEqual(updated.groups, ["B组", "空组"]);
  assert.equal(updated.targets.alpha!.description, "Renamed");
  assert.equal(isMetadataOnlyFleetChange(profile, updated), true);
  const cleared = applyMetadataOverlay(updated, { ...overlay, targets: { alpha: {} } }, baseRevision)!;
  assert.equal(cleared.targets.alpha!.group, undefined);
  assert.equal(cleared.targets.alpha!.description, undefined);
  assert.deepEqual(fleetMetadata(cleared).targets, { alpha: {} });
});

test("metadata fast path excludes aliases, endpoint, enabled flag, policy, key and transfer settings", () => {
  const original = profile.targets.alpha!;
  for (const patch of [
    { enabled: false }, { target: { ...original.target, host: "10.0.0.2" } },
    { target: { ...original.target, keyId: "different-key" } },
    { allowedCommands: ["hostname"] }, { maxTimeoutMs: 90_000 },
    { remoteRoots: ["/tmp"] }, { knownHostsFile: "/other/file" },
  ]) {
    assert.equal(isMetadataOnlyFleetChange(profile, { ...profile, targets: { alpha: { ...original, ...patch } } }), false, JSON.stringify(patch));
  }
  assert.equal(isMetadataOnlyFleetChange(profile, { ...profile, targets: { beta: original } }), false);
});

test("overlay is revision-bound, exact in alias coverage, and rejects operational payloads", () => {
  assert.equal(applyMetadataOverlay(profile, overlay, `r-other-${"c".repeat(32)}`), undefined);
  assert.throws(() => applyMetadataOverlay(profile, { ...overlay, targets: {} }, baseRevision));
  assert.throws(() => applyMetadataOverlay(profile, { ...overlay, targets: { ...overlay.targets, extra: {} } }, baseRevision));
  assert.throws(() => applyMetadataOverlay(profile, { ...overlay, targets: { alpha: { policyMode: "full-access" } } }, baseRevision));
  assert.throws(() => applyMetadataOverlay(profile, { ...overlay, targets: { alpha: { group: "Missing" } } }, baseRevision));
  assert.throws(() => applyMetadataOverlay(profile, { ...overlay, accessClient: {} }, baseRevision));
});

test("removal fast path permits only a strict subset with unchanged retained settings", () => {
  const two = { ...profile, targets: { ...profile.targets, beta: profile.targets.alpha! } };
  assert.equal(isRemovalOnlyFleetChange(two, profile), true);
  assert.equal(isRemovalOnlyFleetChange(profile, { ...profile, targets: {} }), true);
  assert.equal(isRemovalOnlyFleetChange(profile, profile), false);
  assert.equal(isRemovalOnlyFleetChange(two, { ...profile, groups: [] }), false);
  assert.equal(isRemovalOnlyFleetChange(two, { ...profile, targets: { gamma: profile.targets.alpha! } }), false);
  assert.equal(isRemovalOnlyFleetChange(two, { ...profile, targets: { alpha: { ...profile.targets.alpha!, enabled: false } } }), false);
  assert.equal(isRemovalOnlyFleetChange(profile, two), false);
});

test("explicit revocation overlay cannot reintroduce targets or alter security settings", () => {
  const revoked = { ...overlay, version: 2, removedTargets: ["alpha"], targets: {} };
  assert.deepEqual(applyMetadataOverlay(profile, revoked, baseRevision)!.targets, {});
  assert.deepEqual(overlayRemovedTargets(managedMetadataOverlaySchema.parse(revoked)), ["alpha"]);
  assert.deepEqual(overlayRemovedTargets(managedMetadataOverlaySchema.parse(overlay)), []);
  for (const invalid of [
    { ...revoked, removedTargets: [] },
    { ...revoked, removedTargets: ["alpha", "alpha"] },
    { ...revoked, removedTargets: ["missing"] },
    { ...revoked, targets: overlay.targets },
    { ...revoked, targets: { extra: {} } },
    { ...revoked, policyMode: "full-access" },
    { ...overlay, removedTargets: ["alpha"] },
  ]) assert.throws(() => applyMetadataOverlay(profile, invalid, baseRevision));
  const two = { ...profile, targets: { ...profile.targets, beta: profile.targets.alpha! } };
  const updated = applyMetadataOverlay(two, { ...revoked, targets: { beta: { description: "Kept" } } }, baseRevision)!;
  assert.deepEqual(Object.keys(updated.targets), ["beta"]);
  assert.deepEqual(updated.targets.beta!.target, two.targets.beta.target);
  assert.equal(updated.targets.beta!.description, "Kept");
});
