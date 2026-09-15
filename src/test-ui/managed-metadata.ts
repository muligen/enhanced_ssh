import { isDeepStrictEqual } from "node:util";
import { z } from "zod";

import { targetAliasSchema, targetGroupCatalogSchema, targetGroupSchema } from "../shared/protocol.js";
import type { ManagedSshFleetProfile } from "./managed.js";

const revisionSchema = z.string().regex(/^r-[a-z0-9]+-[a-f0-9]{32}$/u);
const targetMetadataSchema = z.strictObject({
  group: targetGroupSchema.optional(),
  description: z.string().min(1).max(256).regex(/^[^\u0000-\u001f\u007f]+$/u).optional(),
});

/** This overlay cannot contain credentials, endpoints, identities, or policy. */
export const managedMetadataOverlaySchema = z.strictObject({
  version: z.literal(1),
  baseRevision: revisionSchema,
  revision: revisionSchema,
  groups: targetGroupCatalogSchema,
  targets: z.record(targetAliasSchema, targetMetadataSchema),
});
export type ManagedMetadataOverlay = z.infer<typeof managedMetadataOverlaySchema>;

export function fleetMetadata(profile: ManagedSshFleetProfile): Pick<ManagedMetadataOverlay, "groups" | "targets"> {
  return {
    groups: [...(profile.groups ?? [])],
    targets: Object.fromEntries(Object.entries(profile.targets).map(([alias, target]) => [alias, {
      ...(target.group === undefined ? {} : { group: target.group }),
      ...(target.description === undefined ? {} : { description: target.description }),
    }])),
  };
}

function operationalProfile(profile: ManagedSshFleetProfile): unknown {
  const { groups: _groups, targets, ...operational } = profile;
  return { ...operational, targets: Object.fromEntries(Object.entries(targets).map(([alias, target]) => {
    const { group: _group, description: _description, ...connection } = target;
    return [alias, connection];
  })) };
}

export function isMetadataOnlyFleetChange(previous: ManagedSshFleetProfile, next: ManagedSshFleetProfile): boolean {
  return isDeepStrictEqual(operationalProfile(previous), operationalProfile(next));
}

export function applyMetadataOverlay(profile: ManagedSshFleetProfile, raw: unknown, baseRevision: string): ManagedSshFleetProfile | undefined {
  const overlay = managedMetadataOverlaySchema.parse(raw);
  if (overlay.baseRevision !== baseRevision) return undefined;
  const aliases = Object.keys(profile.targets).sort();
  if (!isDeepStrictEqual(aliases, Object.keys(overlay.targets).sort())) {
    throw new Error("Saved machine metadata does not match its base configuration");
  }
  for (const target of Object.values(overlay.targets)) {
    if (target.group !== undefined && !overlay.groups.includes(target.group)) {
      throw new Error("Saved machine metadata references an unknown group");
    }
  }
  return { ...profile, groups: overlay.groups, targets: Object.fromEntries(Object.entries(profile.targets).map(([alias, target]) => {
    const { group: _group, description: _description, ...operational } = target;
    return [alias, { ...operational, ...overlay.targets[alias] }];
  })) };
}
