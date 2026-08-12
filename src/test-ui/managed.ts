import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { constants as fsConstants, type BigIntStats } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rmdir,
  unlink,
} from "node:fs/promises";
import { isIP } from "node:net";
import os from "node:os";
import path from "node:path";

import { stringify } from "yaml";
import { z } from "zod";

import { parseConfigText } from "../config/load-config.js";
import {
  GatewayReloadCommittedCleanupError,
  startGatewayDaemon,
  type RunningGatewayDaemon,
} from "../daemon/service.js";
import {
  createRuntimeDescriptor,
  hardenPrivatePath,
  hardenPrivatePaths,
  type RuntimeLease,
} from "../daemon/runtime-state.js";
import {
  createRpcGatewayFactory,
  type TestUiGatewayFactory,
} from "./gateway.js";
import {
  ManagedSshKeyVault,
  ManagedSshKeyVaultError,
  managedSshKeyIdSchema,
  type ManagedSshKeyGenerationAlgorithm,
  type ManagedSshKeyRecord,
  type ManagedSshKeyVaultSnapshot,
} from "./managed-keys.js";

export {
  managedSshKeyIdSchema,
  managedSshKeyGenerationAlgorithmSchema,
  managedSshKeyLabelSchema,
  managedSshKeyRevisionSchema,
} from "./managed-keys.js";
export type { ManagedSshKeyGenerationAlgorithm } from "./managed-keys.js";
import {
  MAX_COMMAND_BYTES,
  MAX_INLINE_PREVIEW_BYTES,
  MAX_TIMEOUT_MS,
  targetAliasSchema,
  targetIdSchema,
} from "../shared/protocol.js";

const MANAGED_TARGET_ALIAS = "managed-ssh";
const MANAGED_BASTION_ALIAS = "managed-bastion";
const ACTIVE_POINTER_VERSION = 1;
const MAX_PRIVATE_KEY_BYTES = 1_048_576;
const MAX_KNOWN_HOSTS_BYTES = 16_777_216;
const MAX_MANAGED_TARGETS = 1_024;
const MAX_ALLOWED_COMMANDS = 128;
const LEGACY_INLINE_OUTPUT_BYTES = 65_536;
const REVISION_ID_PATTERN = /^r-[a-z0-9]+-[a-f0-9]{32}$/u;
const STAGING_REVISION_ID_PATTERN = /^\.staging-(r-[a-z0-9]+-[a-f0-9]{32})$/u;
const PUBLIC_KEY_PATTERN = /^ssh-ed25519 [A-Za-z0-9+/]+={0,3}(?: [^\r\n]+)?$/u;
const SSH_USERNAME_SEGMENT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;
const WINDOWS_POWERSHELL =
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

const WINDOWS_PLATFORM_COMMANDS = [
  "hostname",
  "whoami",
  "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture | Format-List",
  "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime",
  "Get-Culture | Format-List Name, DisplayName",
] as const;

const LINUX_PLATFORM_COMMANDS = [
  "hostname",
  "whoami",
  "uname -a",
  "uptime",
] as const;

const MACOS_PLATFORM_COMMANDS = [
  "hostname",
  "whoami",
  "sw_vers",
  "uptime",
] as const;

export const MANAGED_PLATFORMS = ["windows", "linux", "macos"] as const;

export const MANAGED_PLATFORM_COMMANDS = {
  windows: WINDOWS_PLATFORM_COMMANDS,
  linux: LINUX_PLATFORM_COMMANDS,
  macos: MACOS_PLATFORM_COMMANDS,
} as const;

export const MANAGED_SUPPORTED_COMMANDS = [
  "hostname",
  "whoami",
  "uname -a",
  "uptime",
  "sw_vers",
  "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture | Format-List",
  "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime",
  "Get-Culture | Format-List Name, DisplayName",
] as const;

const sshHostSchema = z
  .string()
  .min(1)
  .max(253)
  .refine(isValidSshHost, "must be an IPv4, IPv6, or DNS host name");

const sshUsernameSchema = z
  .string()
  .min(1)
  .max(128)
  .refine(
    isValidSshUsername,
    "must be a simple username or exactly portalUser/targetIPv4/systemUser; username segments may contain only letters, digits, dot, underscore, or hyphen",
  );

const sshPathSchema = z
  .string()
  .min(1)
  .max(4_096)
  .refine(
    isSafeAbsoluteInputPath,
    "must be a local absolute path without device, UNC, ADS, or expansion syntax",
  );

const managedEndpointSchema = z.strictObject({
  host: sshHostSchema,
  port: z.number().int().min(1).max(65_535),
  username: sshUsernameSchema,
  identityFile: sshPathSchema,
});

const managedKeyEndpointSchema = z.strictObject({
  host: sshHostSchema,
  port: z.number().int().min(1).max(65_535),
  username: sshUsernameSchema,
  keyId: managedSshKeyIdSchema.optional(),
});

const managedAccessClientSessionSchema = z.strictObject({
  gatewayHost: sshHostSchema,
  gatewayPort: z.number().int().min(1).max(65_535),
  gatewayUsername: sshUsernameSchema,
  sharingHost: sshHostSchema.optional(),
  sharingPort: z.number().int().min(1).max(65_535).optional(),
  expectedHostname: z
    .string()
    .min(1)
    .max(255)
    .regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/u)
    .optional(),
}).superRefine((connection, context) => {
  if (connection.sharingHost === undefined && connection.sharingPort !== undefined) {
    context.addIssue({
      code: "custom",
      path: ["sharingPort"],
      message: "requires sharingHost",
    });
  }
});

export const managedAccessClientSettingsSchema = z.strictObject({
  plinkExecutable: sshPathSchema,
});

const managedProfileFields = {
  target: managedEndpointSchema,
  knownHostsFile: sshPathSchema,
  bastion: managedEndpointSchema.optional(),
};

const managedCommandSchema = z
  .string()
  .min(1)
  .max(MAX_COMMAND_BYTES)
  .refine((command) => command.trim().length > 0, "must not be blank")
  .refine(
    (command) => !/[\0\r\n]/u.test(command),
    "must not contain NUL bytes or newlines",
  )
  .refine(
    (command) => Buffer.byteLength(command, "utf8") <= MAX_COMMAND_BYTES,
    `must not exceed ${MAX_COMMAND_BYTES} UTF-8 bytes`,
  );

const managedAllowedCommandsSchema = z
  .array(managedCommandSchema)
  .max(MAX_ALLOWED_COMMANDS)
  .refine(
    (commands) => new Set(commands).size === commands.length,
    "must not contain duplicate commands",
  );

const currentAllowListProfileSchema = z.strictObject({
  ...managedProfileFields,
  platform: z.enum(MANAGED_PLATFORMS),
  policyMode: z.literal("allow-list"),
  allowedCommands: managedAllowedCommandsSchema.min(1),
});

const currentFullAccessProfileSchema = z.strictObject({
  ...managedProfileFields,
  platform: z.enum(MANAGED_PLATFORMS),
  policyMode: z.literal("full-access"),
  allowedCommands: managedAllowedCommandsSchema.length(0),
});

export const currentManagedSshProfileSchema = z.union([
  currentAllowListProfileSchema,
  currentFullAccessProfileSchema,
]);

// Reopen immutable revisions created before platform and policy mode existed.
// Their missing fields are intentionally preserved so validation reproduces
// the exact historical gateway configuration.
const legacyManagedSshProfileSchema = z.strictObject({
  ...managedProfileFields,
  allowedCommands: z
    .array(z.enum(MANAGED_SUPPORTED_COMMANDS))
    .min(1)
    .max(MANAGED_SUPPORTED_COMMANDS.length)
    .refine(
      (commands) => new Set(commands).size === commands.length,
      "must not contain duplicate commands",
    ),
});

export const managedSshProfileSchema = z.union([
  currentManagedSshProfileSchema,
  legacyManagedSshProfileSchema,
]);

const managedDescriptionSchema = z
  .string()
  .min(1)
  .max(256)
  .refine(
    (value) => !/[\u0000-\u001f\u007f]/u.test(value),
    "must not contain control characters",
  );

const managedRemoteRootSchema = z
  .string()
  .min(1)
  .max(4_096)
  .refine(
    (value) => !/[\u0000-\u001f\u007f]/u.test(value),
    "must not contain control characters",
  );

const managedFleetCommonTargetFields = {
  targetId: targetIdSchema.optional(),
  previousAliases: z.array(targetAliasSchema).max(32).optional(),
  description: managedDescriptionSchema.optional(),
  enabled: z.boolean(),
  connectionMode: z
    .enum(["openssh", "accessclient-share"])
    .optional(),
  knownHostsFile: sshPathSchema.optional(),
  accessClient: managedAccessClientSessionSchema.optional(),
  platform: z.enum(MANAGED_PLATFORMS),
  maxTimeoutMs: z.number().int().min(1).max(MAX_TIMEOUT_MS),
  transferMode: z
    .enum(["deny", "upload", "download", "bidirectional"])
    .optional(),
  localRootPath: sshPathSchema.optional(),
  remoteRoots: z.array(managedRemoteRootSchema).max(32).optional(),
  maxTransferTimeoutMs: z
    .number()
    .int()
    .min(1)
    .max(MAX_TIMEOUT_MS)
    .optional(),
};

const storedManagedFleetTargetV2Fields = {
  ...managedFleetCommonTargetFields,
  target: managedEndpointSchema,
  bastion: managedEndpointSchema.optional(),
};

const managedFleetTargetFields = {
  ...managedFleetCommonTargetFields,
  target: managedKeyEndpointSchema,
  bastion: managedKeyEndpointSchema.optional(),
};

const managedFleetAllowListTargetSchema = z.strictObject({
  ...managedFleetTargetFields,
  policyMode: z.literal("allow-list"),
  allowedCommands: managedAllowedCommandsSchema.min(1),
});

const managedFleetFullAccessTargetSchema = z.strictObject({
  ...managedFleetTargetFields,
  policyMode: z.literal("full-access"),
  allowedCommands: managedAllowedCommandsSchema.length(0),
});

const managedFleetDenyTargetSchema = z.strictObject({
  ...managedFleetTargetFields,
  policyMode: z.literal("deny"),
  allowedCommands: managedAllowedCommandsSchema.length(0),
});

export const managedFleetTargetSchema = z.discriminatedUnion("policyMode", [
  managedFleetAllowListTargetSchema,
  managedFleetFullAccessTargetSchema,
  managedFleetDenyTargetSchema,
]).superRefine((target, context) => {
  const connectionMode = target.connectionMode ?? "openssh";
  if (connectionMode === "accessclient-share") {
    if (target.target.keyId !== undefined) {
      context.addIssue({
        code: "custom",
        path: ["target", "keyId"],
        message: "AccessClient targets must not reference a private key",
      });
    }
    if (target.knownHostsFile !== undefined) {
      context.addIssue({
        code: "custom",
        path: ["knownHostsFile"],
        message: "AccessClient targets must not reference OpenSSH known_hosts",
      });
    }
    if (target.bastion !== undefined) {
      context.addIssue({
        code: "custom",
        path: ["bastion"],
        message: "AccessClient targets cannot also use OpenSSH ProxyJump",
      });
    }
    if (target.accessClient === undefined) {
      context.addIssue({
        code: "custom",
        path: ["accessClient"],
        message: "AccessClient session settings are required",
      });
    }
    if ((target.transferMode ?? "deny") !== "deny") {
      context.addIssue({
        code: "custom",
        path: ["transferMode"],
        message: "AccessClient file transfer is not enabled",
      });
    }
  } else {
    if (target.target.keyId === undefined) {
      context.addIssue({
        code: "custom",
        path: ["target", "keyId"],
        message: "OpenSSH targets require a private key",
      });
    }
    if (target.knownHostsFile === undefined) {
      context.addIssue({
        code: "custom",
        path: ["knownHostsFile"],
        message: "OpenSSH targets require known_hosts",
      });
    }
    if (target.accessClient !== undefined) {
      context.addIssue({
        code: "custom",
        path: ["accessClient"],
        message: "OpenSSH targets must not include AccessClient settings",
      });
    }
    if (target.bastion !== undefined && target.bastion.keyId === undefined) {
      context.addIssue({
        code: "custom",
        path: ["bastion", "keyId"],
        message: "OpenSSH bastions require a private key",
      });
    }
  }
  const transferMode = target.transferMode ?? "deny";
  const remoteRoots = target.remoteRoots ?? [];
  if (target.policyMode === "full-access") {
    return;
  }
  if (target.policyMode === "deny" && transferMode !== "deny") {
    context.addIssue({
      code: "custom",
      path: ["transferMode"],
      message: "denied access must also deny file transfer",
    });
    return;
  }
  if (transferMode === "deny") {
    if (target.localRootPath !== undefined || remoteRoots.length !== 0) {
      context.addIssue({
        code: "custom",
        path: ["transferMode"],
        message: "denied file transfer must not configure roots",
      });
    }
    return;
  }
  if (target.localRootPath === undefined || remoteRoots.length === 0) {
    context.addIssue({
      code: "custom",
      path: ["transferMode"],
      message: "enabled file transfer requires a local root and remote roots",
    });
    return;
  }
  for (const [index, root] of remoteRoots.entries()) {
    const valid =
      target.platform === "windows"
        ? /^[A-Za-z]:[\\/](?![\\/])/u.test(root)
        : root.startsWith("/") && !root.startsWith("//");
    if (!valid || root.split(/[\\/]+/u).some((segment) => segment === "..")) {
      context.addIssue({
        code: "custom",
        path: ["remoteRoots", index],
        message: "must be an absolute path for the selected remote platform",
      });
    }
  }
});

const storedManagedFleetAllowListTargetV2Schema = z.strictObject({
  ...storedManagedFleetTargetV2Fields,
  policyMode: z.literal("allow-list"),
  allowedCommands: managedAllowedCommandsSchema.min(1),
});

const storedManagedFleetFullAccessTargetV2Schema = z.strictObject({
  ...storedManagedFleetTargetV2Fields,
  policyMode: z.literal("full-access"),
  allowedCommands: managedAllowedCommandsSchema.length(0),
});

const storedManagedFleetDenyTargetV2Schema = z.strictObject({
  ...storedManagedFleetTargetV2Fields,
  policyMode: z.literal("deny"),
  allowedCommands: managedAllowedCommandsSchema.length(0),
});

const storedManagedFleetTargetV2Schema = z
  .discriminatedUnion("policyMode", [
    storedManagedFleetAllowListTargetV2Schema,
    storedManagedFleetFullAccessTargetV2Schema,
    storedManagedFleetDenyTargetV2Schema,
  ])
  .superRefine((target, context) => {
    const transferMode = target.transferMode ?? "deny";
    const remoteRoots = target.remoteRoots ?? [];
    if (target.policyMode === "full-access") return;
    if (target.policyMode === "deny" && transferMode !== "deny") {
      context.addIssue({
        code: "custom",
        path: ["transferMode"],
        message: "denied access must also deny file transfer",
      });
      return;
    }
    if (transferMode === "deny") {
      if (target.localRootPath !== undefined || remoteRoots.length !== 0) {
        context.addIssue({
          code: "custom",
          path: ["transferMode"],
          message: "denied file transfer must not configure roots",
        });
      }
      return;
    }
    if (target.localRootPath === undefined || remoteRoots.length === 0) {
      context.addIssue({
        code: "custom",
        path: ["transferMode"],
        message: "enabled file transfer requires a local root and remote roots",
      });
      return;
    }
    for (const [index, root] of remoteRoots.entries()) {
      const valid =
        target.platform === "windows"
          ? /^[A-Za-z]:[\\/](?![\\/])/u.test(root)
          : root.startsWith("/") && !root.startsWith("//");
      if (!valid || root.split(/[\\/]+/u).some((segment) => segment === "..")) {
        context.addIssue({
          code: "custom",
          path: ["remoteRoots", index],
          message: "must be an absolute path for the selected remote platform",
        });
      }
    }
  });

const managedFleetTargetsSchema = z
  .record(targetAliasSchema, managedFleetTargetSchema)
  .superRefine((targets, context) => {
    const aliases = Object.keys(targets);
    if (aliases.length > MAX_MANAGED_TARGETS) {
      context.addIssue({
        code: "custom",
        message: `must contain at most ${MAX_MANAGED_TARGETS} targets`,
      });
    }
    const references = new Map<string, string>();
    const puttyShares = new Map<string, string>();
    for (const alias of aliases) {
      const target = targets[alias]!;
      if (
        target.connectionMode === "accessclient-share" &&
        target.accessClient !== undefined
      ) {
        const connection = target.accessClient;
        const sharingIdentity = puttySharingIdentity(
          connection.gatewayUsername,
          connection.sharingHost ?? connection.gatewayHost,
          connection.sharingHost === undefined
            ? connection.gatewayPort
            : (connection.sharingPort ?? 22),
        );
        const owner = puttyShares.get(sharingIdentity);
        if (owner !== undefined) {
          context.addIssue({
            code: "custom",
            path: [alias, "accessClient", "sharingHost"],
            message: `conflicts with the PuTTY shared identity owned by ${owner}`,
          });
        } else {
          puttyShares.set(sharingIdentity, alias);
        }
      }
      const identifiers = [
        { value: alias, path: [alias] as PropertyKey[] },
        ...(target.targetId === undefined
          ? []
          : [{ value: target.targetId, path: [alias, "targetId"] as PropertyKey[] }]),
        ...(target.previousAliases ?? []).map((value, index) => ({
          value,
          path: [alias, "previousAliases", index] as PropertyKey[],
        })),
      ];
      for (const identifier of identifiers) {
        const folded = identifier.value.toLowerCase();
        const owner = references.get(folded);
        if (owner !== undefined) {
          context.addIssue({
            code: "custom",
            path: identifier.path,
            message: `conflicts with a target reference owned by ${owner}`,
          });
        } else {
          references.set(folded, alias);
        }
      }
    }
  });

function puttySharingIdentity(
  username: string,
  host: string,
  port: number,
): string {
  return JSON.stringify([username, host.toLowerCase(), port]);
}

export const managedSshFleetProfileSchema = z.strictObject({
  version: z.literal(3),
  accessClient: managedAccessClientSettingsSchema.optional(),
  targets: managedFleetTargetsSchema,
}).superRefine((profile, context) => {
  if (
    profile.accessClient === undefined &&
    Object.values(profile.targets).some(
      (target) => target.connectionMode === "accessclient-share",
    )
  ) {
    context.addIssue({
      code: "custom",
      path: ["accessClient"],
      message: "AccessClient targets require global Plink settings",
    });
  }
});

const storedManagedFleetTargetsV2Schema = z.record(
  targetAliasSchema,
  storedManagedFleetTargetV2Schema,
);

const storedManagedSshFleetProfileV2Schema = z.strictObject({
  version: z.literal(2),
  targets: storedManagedFleetTargetsV2Schema,
});

const storedManagedSshFleetProfileSchema = z.union([
  managedSshFleetProfileSchema,
  storedManagedSshFleetProfileV2Schema,
]);

const activePointerSchema = z
  .strictObject({
    version: z.literal(ACTIVE_POINTER_VERSION),
    revision: z.string().regex(REVISION_ID_PATTERN),
    previousRevision: z.string().regex(REVISION_ID_PATTERN).optional(),
    quarantinedRevisions: z
      .array(z.string().regex(REVISION_ID_PATTERN))
      .max(MAX_MANAGED_TARGETS)
      .optional(),
  })
  .superRefine((pointer, context) => {
    const references = [
      pointer.revision,
      ...(pointer.previousRevision === undefined
        ? []
        : [pointer.previousRevision]),
      ...(pointer.quarantinedRevisions ?? []),
    ];
    if (new Set(references).size !== references.length) {
      context.addIssue({
        code: "custom",
        message: "active, previous, and quarantined revisions must be unique",
      });
    }
  });

type ActivePointer = z.infer<typeof activePointerSchema>;

export type ManagedSshProfile = z.infer<typeof managedSshProfileSchema>;
export type CurrentManagedSshProfile = z.infer<
  typeof currentManagedSshProfileSchema
>;
export type ManagedSshFleetTarget = z.infer<typeof managedFleetTargetSchema>;
export type ManagedSshFleetProfile = z.infer<
  typeof managedSshFleetProfileSchema
>;
type StoredManagedSshFleetTargetV2 = z.infer<
  typeof storedManagedFleetTargetV2Schema
>;
type StoredManagedSshFleetProfileV2 = z.infer<
  typeof storedManagedSshFleetProfileV2Schema
>;
type StoredManagedSshFleetProfile = z.infer<
  typeof storedManagedSshFleetProfileSchema
>;
type ManagedSshEndpoint = Readonly<{
  host: string;
  port: number;
  username: string;
}>;
export type ManagedSshPlatform = (typeof MANAGED_PLATFORMS)[number];
export type ManagedSshState =
  | "unconfigured"
  | "starting"
  | "ready"
  | "error";

export interface GeneratedSshKey {
  readonly privateKeyPath: string;
  readonly publicKey: string;
}

export interface ManagedSshStatus {
  readonly state: ManagedSshState;
  readonly configured: boolean;
  readonly defaultKnownHostsFile: string;
  readonly allowedCommands: readonly string[];
  readonly revision?: string;
  readonly profile?: ManagedSshProfile;
  readonly generatedKey?: GeneratedSshKey;
  readonly error?: Readonly<{ code: string; message: string }>;
}

export interface ManagedSshFleetStatus {
  readonly state: ManagedSshState;
  readonly configured: boolean;
  readonly defaultKnownHostsFile: string;
  readonly commandPresets: typeof MANAGED_PLATFORM_COMMANDS;
  readonly keyRevision: string;
  readonly keys: readonly ManagedSshKeySummary[];
  readonly revision?: string;
  readonly profile?: ManagedSshFleetProfile;
  readonly error?: Readonly<{ code: string; message: string }>;
  readonly keyError?: Readonly<{ code: string; message: string }>;
}

export interface ManagedSshKeyReference {
  readonly alias: string;
  readonly targetId?: string;
  readonly role: "target" | "bastion";
}

export interface ManagedSshKeySummary extends ManagedSshKeyRecord {
  readonly inUseBy: readonly ManagedSshKeyReference[];
}

export interface ManagedSshKeyStatus {
  readonly keyRevision: string;
  readonly keys: readonly ManagedSshKeySummary[];
  readonly error?: Readonly<{ code: string; message: string }>;
}

export interface TestUiConfigurationService {
  readonly gatewayFactory: TestUiGatewayFactory;
  status(): Promise<ManagedSshStatus>;
  fleetStatus(): Promise<ManagedSshFleetStatus>;
  keyStatus(): Promise<ManagedSshKeyStatus>;
  generateKey(): Promise<ManagedSshStatus>;
  generateManagedKey(
    label: string,
    expectedKeyRevision: string,
    algorithm?: ManagedSshKeyGenerationAlgorithm,
  ): Promise<ManagedSshKeyStatus>;
  importManagedKey(
    label: string,
    sourcePath: string,
    expectedKeyRevision: string,
  ): Promise<ManagedSshKeyStatus>;
  renameManagedKey(
    keyId: string,
    label: string,
    expectedKeyRevision: string,
  ): Promise<ManagedSshKeyStatus>;
  removeManagedKey(
    keyId: string,
    expectedKeyRevision: string,
  ): Promise<ManagedSshKeyStatus>;
  apply(profile: CurrentManagedSshProfile): Promise<ManagedSshStatus>;
  applyFleet(
    profile: ManagedSshFleetProfile,
    expectedRevision?: string,
  ): Promise<ManagedSshFleetStatus>;
  close(): Promise<void>;
}

export class ManagedSshError extends Error {
  public readonly status: number;
  public readonly code: string;

  public constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ManagedSshError";
    this.status = status;
    this.code = code;
  }
}

interface ManagedPaths {
  readonly root: string;
  readonly runtime: string;
  readonly revisions: string;
  readonly keys: string;
  readonly activePointer: string;
  readonly generatedKeyDirectory: string;
  readonly generatedPrivateKey: string;
  readonly generatedPublicKey: string;
  readonly setupLeaseDirectory: string;
}

interface RevisionPaths {
  readonly id: string;
  readonly root: string;
  readonly credentialDirectory: string;
  readonly targetPrivateKey: string;
  readonly bastionPrivateKey: string;
  readonly knownHosts: string;
  readonly sshConfig: string;
  readonly gatewayConfig: string;
  readonly profile: string;
}

interface FleetCredentialPaths {
  readonly root: string;
  readonly targetPrivateKey: string;
  readonly bastionPrivateKey: string;
  readonly knownHosts: string;
}

interface StagedRevision {
  readonly published: RevisionPaths;
  readonly profile: ManagedSshFleetProfile;
}

interface ValidatedRevision {
  readonly storedProfile: ManagedSshProfile | StoredManagedSshFleetProfile;
  readonly fleetProfile?: ManagedSshFleetProfile;
  readonly legacyFleetProfile?: StoredManagedSshFleetProfileV2;
  readonly legacySingleProfile?: CurrentManagedSshProfile;
}

interface RecoverableRevision {
  readonly revision: RevisionPaths;
  readonly validated: ValidatedRevision;
}

interface CommandResult {
  readonly stdout: string;
  readonly stderr: string;
}

export function defaultManagedSshDirectory(): string {
  const localAppData =
    process.env.LOCALAPPDATA ?? path.join(os.homedir(), "AppData", "Local");
  return path.join(localAppData, "agent-ssh-gateway", "managed");
}

export async function createManagedSshService(
  directory = defaultManagedSshDirectory(),
): Promise<TestUiConfigurationService> {
  const service = new ManagedSshService(createManagedPaths(directory));
  try {
    await service.initialize();
    return service;
  } catch (error) {
    await service.close().catch(() => undefined);
    throw error;
  }
}

class ManagedSshService implements TestUiConfigurationService {
  readonly #paths: ManagedPaths;
  readonly #sshExecutable: string;
  readonly #sshKeygenExecutable: string;
  readonly #keyVault: ManagedSshKeyVault;
  readonly gatewayFactory: TestUiGatewayFactory;
  #daemon: RunningGatewayDaemon | undefined;
  #fleetProfile: ManagedSshFleetProfile | undefined;
  #legacyProfile: ManagedSshProfile | undefined;
  #activeRevision: RevisionPaths | undefined;
  #activePointer: ActivePointer | undefined;
  #lease: RuntimeLease | undefined;
  #state: ManagedSshState = "unconfigured";
  #lastError: ManagedSshError | undefined;
  #keyError: ManagedSshError | undefined;
  readonly #fallbackKeyRevision = createManagedKeyRevision();
  #referenceStateTrusted = false;
  #operation: Promise<unknown> | undefined;
  #closed = false;

  public constructor(paths: ManagedPaths) {
    this.#paths = paths;
    const systemRoot = process.env.SystemRoot ?? String.raw`C:\Windows`;
    this.#sshExecutable = path.join(
      systemRoot,
      "System32",
      "OpenSSH",
      "ssh.exe",
    );
    this.#sshKeygenExecutable = path.join(
      systemRoot,
      "System32",
      "OpenSSH",
      "ssh-keygen.exe",
    );
    this.#keyVault = new ManagedSshKeyVault(
      paths.keys,
      this.#sshKeygenExecutable,
    );
    this.gatewayFactory = createRpcGatewayFactory(paths.runtime);
  }

  public async initialize(): Promise<void> {
    await prepareManagedRoot(this.#paths);
    this.#lease = await acquireSetupLease(this.#paths);
    try {
      await this.#keyVault.initialize();
    } catch (error) {
      this.#keyError = toManagedKeyError(error);
    }

    let pointer: ActivePointer | undefined;
    try {
      pointer = await readActivePointer(this.#paths);
    } catch (error) {
      if (!(error instanceof ManagedSshError) || error.code !== "FILE_NOT_FOUND") {
        this.#state = "error";
        this.#lastError = publicManagedError(
          "CONFIG_INVALID",
          "Saved SSH configuration could not be read",
        );
        return;
      }
    }

    this.#state = "starting";
    let startingDaemon = false;
    let candidateDaemon: RunningGatewayDaemon | undefined;
    try {
      let selected: RecoverableRevision;
      let selectedPointer: ActivePointer;
      let pointerNeedsCommit = false;
      if (pointer === undefined) {
        const recovery = await this.#findRecoverableRevisions();
        if (recovery.publishedCount === 0) {
          this.#referenceStateTrusted = true;
          this.#state = "unconfigured";
          return;
        }
        if (recovery.revisions.length === 0) {
          throw publicManagedError(
            "CONFIG_INVALID",
            "No saved SSH revision could be recovered",
          );
        }
        selected = recovery.revisions[0]!;
        selectedPointer = {
          version: ACTIVE_POINTER_VERSION,
          revision: selected.revision.id,
          ...(recovery.revisions[1] === undefined
            ? {}
            : { previousRevision: recovery.revisions[1].revision.id }),
          ...(recovery.quarantinedRevisionIds.length === 0
            ? {}
            : {
                quarantinedRevisions: [...recovery.quarantinedRevisionIds],
              }),
        };
        pointerNeedsCommit = true;
      } else {
        const activeRevision = createRevisionPaths(this.#paths, pointer.revision);
        try {
          selected = {
            revision: activeRevision,
            validated: await this.#validateRevision(activeRevision),
          };
          selectedPointer = pointer;
        } catch (activeError) {
          if (pointer.previousRevision === undefined) {
            throw activeError;
          }
          const rollbackRevision = createRevisionPaths(
            this.#paths,
            pointer.previousRevision,
          );
          try {
            selected = {
              revision: rollbackRevision,
              validated: await this.#validateRevision(rollbackRevision),
            };
          } catch (rollbackError) {
            throw new AggregateError(
              [activeError, rollbackError],
              "Neither the active nor rollback SSH revision is valid",
            );
          }
          selectedPointer = {
            version: ACTIVE_POINTER_VERSION,
            revision: rollbackRevision.id,
            previousRevision: pointer.revision,
            ...(pointer.quarantinedRevisions === undefined
              ? {}
              : { quarantinedRevisions: [...pointer.quarantinedRevisions] }),
          };
          pointerNeedsCommit = true;
        }
      }

      const { revision, validated } = selected;
      const runnableFleet =
        validated.fleetProfile ?? validated.legacyFleetProfile;
      const hasRunnableConfiguration =
        runnableFleet !== undefined || validated.legacySingleProfile !== undefined;
      if (hasRunnableConfiguration) {
        startingDaemon = true;
        candidateDaemon = await startGatewayDaemon(revision.gatewayConfig, {
          deferActivation: true,
          cleanupManagedSshWrapperOrphans: true,
        });
      }
      if (pointerNeedsCommit) {
        await writeActivePointer(this.#paths, selectedPointer);
      }

      this.#fleetProfile =
        validated.fleetProfile ??
        (validated.legacyFleetProfile !== undefined
          ? legacyFleetPublicFallback(revision, validated.legacyFleetProfile)
          : validated.legacySingleProfile === undefined
            ? undefined
            : legacySinglePublicFallback(
                revision,
                validated.legacySingleProfile,
              ));
      this.#legacyProfile =
        !hasRunnableConfiguration &&
        managedSshProfileSchema.safeParse(validated.storedProfile).success
          ? validated.storedProfile as ManagedSshProfile
          : undefined;
      this.#activeRevision = revision;
      this.#activePointer = selectedPointer;
      this.#referenceStateTrusted = true;
      if (!hasRunnableConfiguration) {
        // A historical profile cannot be assigned a remote shell safely. Keep
        // it available for migration, but do not expose a mislabelled target.
        this.#state = "unconfigured";
      } else {
        candidateDaemon!.activate();
        this.#daemon = candidateDaemon;
        candidateDaemon = undefined;
        this.#state = "ready";
      }

      try {
        await pruneManagedRevisions(
          this.#paths,
          [selectedPointer.revision, selectedPointer.previousRevision].filter(
            (revisionId): revisionId is string => revisionId !== undefined,
          ),
          false,
          2,
          selectedPointer.quarantinedRevisions ?? [],
        );
      } catch (cleanupError) {
        this.#lastError = publicManagedError(
          "CONFIG_RETENTION_FAILED",
          "SSH configuration is active, but old revision cleanup is incomplete",
          cleanupError,
        );
      }
      if (
        (validated.legacyFleetProfile !== undefined ||
          validated.legacySingleProfile !== undefined) &&
        this.#keyError === undefined
      ) {
        try {
          const migrated =
            validated.legacyFleetProfile !== undefined
              ? await this.#migrateFleetProfile(
                  revision,
                  validated.legacyFleetProfile,
                )
              : await this.#migrateSingleProfile(
                  revision,
                  validated.legacySingleProfile!,
                );
          await this.applyFleet(migrated, revision.id);
        } catch (migrationError) {
          this.#lastError = publicManagedError(
            "KEY_MIGRATION_FAILED",
            "The saved SSH configuration is active, but its keys could not be migrated",
            migrationError,
          );
        }
      }
    } catch (error) {
      await candidateDaemon?.stop().catch(() => undefined);
      this.#state = "error";
      this.#lastError = publicManagedError(
        startingDaemon ? "DAEMON_START_FAILED" : "CONFIG_INVALID",
        startingDaemon
          ? "The managed SSH gateway could not be started"
          : "Saved SSH configuration could not be recovered",
        error,
      );
    }
  }

  async #findRecoverableRevisions(): Promise<{
    readonly publishedCount: number;
    readonly revisions: readonly RecoverableRevision[];
    readonly quarantinedRevisionIds: readonly string[];
  }> {
    const revisionIds = await listPublishedRevisionsNewestFirst(this.#paths);
    const revisions: RecoverableRevision[] = [];
    const quarantinedRevisionIds: string[] = [];
    for (const revisionId of revisionIds) {
      if (revisions.length === 2) {
        quarantinedRevisionIds.push(revisionId);
        continue;
      }
      const revision = createRevisionPaths(this.#paths, revisionId);
      try {
        revisions.push({
          revision,
          validated: await this.#validateRevision(revision),
        });
      } catch {
        quarantinedRevisionIds.push(revisionId);
        continue;
      }
    }
    return { publishedCount: revisionIds.length, revisions, quarantinedRevisionIds };
  }

  public status(): Promise<ManagedSshStatus> {
    return this.#buildStatus();
  }

  public fleetStatus(): Promise<ManagedSshFleetStatus> {
    return this.#buildFleetStatus();
  }

  public keyStatus(): Promise<ManagedSshKeyStatus> {
    return Promise.resolve(this.#buildKeyStatus());
  }

  public generateManagedKey(
    label: string,
    expectedKeyRevision: string,
    algorithm: ManagedSshKeyGenerationAlgorithm = "ed25519",
  ): Promise<ManagedSshKeyStatus> {
    return this.#runExclusive(async () => {
      this.#assertOpen();
      try {
        await this.#keyVault.generate(label, expectedKeyRevision, algorithm);
        this.#keyError = undefined;
        return this.#buildKeyStatus();
      } catch (error) {
        throw toManagedKeyError(error);
      }
    });
  }

  public importManagedKey(
    label: string,
    sourcePath: string,
    expectedKeyRevision: string,
  ): Promise<ManagedSshKeyStatus> {
    return this.#runExclusive(async () => {
      this.#assertOpen();
      try {
        await this.#keyVault.importFromPath(
          label,
          sourcePath,
          expectedKeyRevision,
        );
        this.#keyError = undefined;
        return this.#buildKeyStatus();
      } catch (error) {
        throw toManagedKeyError(error);
      }
    });
  }

  public renameManagedKey(
    keyId: string,
    label: string,
    expectedKeyRevision: string,
  ): Promise<ManagedSshKeyStatus> {
    return this.#runExclusive(async () => {
      this.#assertOpen();
      try {
        await this.#keyVault.renameKey(keyId, label, expectedKeyRevision);
        this.#keyError = undefined;
        return this.#buildKeyStatus();
      } catch (error) {
        throw toManagedKeyError(error);
      }
    });
  }

  public removeManagedKey(
    keyId: string,
    expectedKeyRevision: string,
  ): Promise<ManagedSshKeyStatus> {
    return this.#runExclusive(async () => {
      this.#assertOpen();
      const references = await this.#retainedKeyReferences(keyId);
      if (references.length !== 0) {
        throw publicManagedError(
          "KEY_IN_USE",
          "The SSH key is still used by a managed target",
          undefined,
          409,
        );
      }
      try {
        await this.#keyVault.removeKey(keyId, expectedKeyRevision);
        this.#keyError = undefined;
        return this.#buildKeyStatus();
      } catch (error) {
        throw toManagedKeyError(error);
      }
    });
  }

  public generateKey(): Promise<ManagedSshStatus> {
    return this.#runExclusive(async () => {
      this.#assertOpen();
      await assertTrustedExecutable(this.#sshKeygenExecutable, "ssh-keygen");
      await ensurePrivateDirectory(this.#paths.generatedKeyDirectory);

      const privateExists = await fileExists(this.#paths.generatedPrivateKey);
      const publicExists = await fileExists(this.#paths.generatedPublicKey);
      if (privateExists !== publicExists) {
        throw publicManagedError(
          "KEY_FILES_INCOMPLETE",
          "The managed key pair is incomplete and was not overwritten",
        );
      }

      if (!privateExists) {
        try {
          await execFileNoInput(
            this.#sshKeygenExecutable,
            [
              "-q",
              "-t",
              "ed25519",
              "-N",
              "",
              "-C",
              "agent-ssh-gateway",
              "-f",
              this.#paths.generatedPrivateKey,
            ],
            15_000,
          );
          await hardenPrivatePaths([
            { path: this.#paths.generatedPrivateKey, directory: false },
            { path: this.#paths.generatedPublicKey, directory: false },
          ]);
        } catch (error) {
          await unlink(this.#paths.generatedPrivateKey).catch(() => undefined);
          await unlink(this.#paths.generatedPublicKey).catch(() => undefined);
          throw publicManagedError(
            "KEY_GENERATION_FAILED",
            "The dedicated SSH key could not be generated",
            error,
          );
        }
      }

      await validateGeneratedKeyPair(
        this.#sshKeygenExecutable,
        this.#paths,
      );
      return this.#buildStatus();
    });
  }

  public async apply(
    profile: CurrentManagedSshProfile,
  ): Promise<ManagedSshStatus> {
    const validated = currentManagedSshProfileSchema.parse(profile);
    const aliases = Object.keys(this.#fleetProfile?.targets ?? {});
    if (aliases.some((alias) => alias !== MANAGED_TARGET_ALIAS)) {
      throw publicManagedError(
        "CONFIG_CONFLICT",
        "Legacy single-target setup cannot replace a managed SSH fleet",
        undefined,
        409,
      );
    }
    let targetKey: ManagedSshKeyRecord;
    let bastionKey: ManagedSshKeyRecord | undefined;
    try {
      targetKey = await this.#keyVault.importMigrated(
        `${MANAGED_TARGET_ALIAS} target`,
        validated.target.identityFile,
      );
      bastionKey =
        validated.bastion === undefined
          ? undefined
          : await this.#keyVault.importMigrated(
              `${MANAGED_TARGET_ALIAS} bastion`,
              validated.bastion.identityFile,
            );
    } catch (error) {
      throw toManagedKeyError(error);
    }
    await this.applyFleet(
      singleProfileToFleet(validated, targetKey.keyId, bastionKey?.keyId),
      this.#activeRevision?.id,
    );
    return this.#buildStatus();
  }

  public applyFleet(
    profile: ManagedSshFleetProfile,
    expectedRevision?: string,
  ): Promise<ManagedSshFleetStatus> {
    return this.#runExclusive(async () => {
      this.#assertOpen();
      const validated = ensureFleetTargetIdentities(
        managedSshFleetProfileSchema.parse(profile),
        this.#fleetProfile,
      );
      if (
        expectedRevision !== undefined &&
        expectedRevision !== this.#activeRevision?.id
      ) {
        throw publicManagedError(
          "CONFIG_CONFLICT",
          "The managed SSH configuration changed after it was read",
          undefined,
          409,
        );
      }

      const staged = await this.#stageRevision(validated);
      const previousFleet = this.#fleetProfile;
      const previousLegacy = this.#legacyProfile;
      const previousRevision = this.#activeRevision;
      const previousPointer = this.#activePointer;
      const previousState = this.#state;
      const nextPointer: ActivePointer = {
        version: ACTIVE_POINTER_VERSION,
        revision: staged.published.id,
        ...(previousRevision === undefined
          ? {}
          : { previousRevision: previousRevision.id }),
      };
      let candidateDaemon: RunningGatewayDaemon | undefined;
      let pointerCommitted = false;
      const retentionFailures: unknown[] = [];

      try {
        await pruneManagedRevisions(
          this.#paths,
          [
            previousRevision?.id,
            previousPointer?.previousRevision,
            staged.published.id,
          ].filter(
            (revision): revision is string => revision !== undefined,
          ),
          false,
          3,
          previousPointer?.quarantinedRevisions ?? [],
        );
      } catch (error) {
        await removeInactiveRevision(this.#paths, staged.published.id).catch(
          () => undefined,
        );
        throw publicManagedError(
          "CONFIG_APPLY_FAILED",
          "SSH configuration revision storage could not be cleaned safely",
          error,
        );
      }

      this.#state = "starting";
      this.#lastError = undefined;
      try {
        if (this.#daemon === undefined) {
          candidateDaemon = await startGatewayDaemon(
            staged.published.gatewayConfig,
            {
              deferActivation: true,
              cleanupManagedSshWrapperOrphans: true,
            },
          );
        }
        await writeActivePointer(this.#paths, nextPointer);
        pointerCommitted = true;
        if (this.#daemon === undefined) {
          candidateDaemon!.activate();
          this.#daemon = candidateDaemon;
          candidateDaemon = undefined;
        } else {
          try {
            await this.#daemon.reload(staged.published.gatewayConfig);
          } catch (error) {
            if (error instanceof GatewayReloadCommittedCleanupError) {
              retentionFailures.push(error);
            } else {
              throw error;
            }
          }
        }

        this.#fleetProfile = staged.profile;
        this.#legacyProfile = undefined;
        this.#activeRevision = staged.published;
        this.#activePointer = nextPointer;
        this.#state = "ready";
        try {
          await pruneManagedRevisions(this.#paths, [
            nextPointer.revision,
            ...(nextPointer.previousRevision === undefined
              ? []
              : [nextPointer.previousRevision]),
          ]);
        } catch (cleanupError) {
          retentionFailures.push(cleanupError);
        }
        if (retentionFailures.length !== 0) {
          const cleanupError =
            retentionFailures.length === 1
              ? retentionFailures[0]
              : new AggregateError(
                  retentionFailures,
                  "Multiple SSH configuration retention operations failed",
                );
          this.#lastError = publicManagedError(
            "CONFIG_RETENTION_FAILED",
            "SSH configuration is active, but old resource cleanup is incomplete",
            cleanupError,
          );
        }
        return this.#buildFleetStatus();
      } catch (error) {
        await candidateDaemon?.stop().catch(() => undefined);
        let pointerRestored = !pointerCommitted;
        if (pointerCommitted) {
          pointerRestored = await restoreActivePointer(
            this.#paths,
            staged.published.id,
            previousPointer,
          ).catch(() => false);
        }

        if (pointerRestored) {
          this.#fleetProfile = previousFleet;
          this.#legacyProfile = previousLegacy;
          this.#activeRevision = previousRevision;
          this.#activePointer = previousPointer;
          this.#referenceStateTrusted = true;
          this.#state = previousState;
        } else {
          await this.#daemon?.stop().catch(() => undefined);
          this.#daemon = undefined;
          this.#fleetProfile = undefined;
          this.#legacyProfile = undefined;
          this.#state = "error";
          this.#activeRevision = undefined;
          this.#activePointer = undefined;
          this.#referenceStateTrusted = false;
        }

        const busy = isReloadBusyError(error);
        this.#lastError = busy
          ? undefined
          : publicManagedError(
              "CONFIG_APPLY_FAILED",
              "SSH configuration was not activated",
            );
        await removeInactiveRevision(this.#paths, staged.published.id).catch(
          () => undefined,
        );
        throw publicManagedError(
          busy ? "CONFIG_BUSY" : "CONFIG_APPLY_FAILED",
          busy
            ? "SSH configuration cannot change while executions are active"
            : "SSH configuration was not activated",
          error,
          busy ? 409 : 400,
        );
      }
    });
  }

  public async close(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    await this.#operation?.catch(() => undefined);
    await this.#daemon?.stop();
    this.#daemon = undefined;
    await this.#lease?.release();
    this.#lease = undefined;
  }

  async #stageRevision(
    profile: ManagedSshFleetProfile,
  ): Promise<StagedRevision> {
    await Promise.all([
      assertTrustedExecutable(this.#sshExecutable, "ssh"),
      assertTrustedExecutable(this.#sshKeygenExecutable, "ssh-keygen"),
      ...(profile.accessClient === undefined
        ? []
        : [
            assertTrustedExecutable(
              profile.accessClient.plinkExecutable,
              "plink",
            ),
          ]),
    ]);

    const id = createRevisionId();
    const published = createRevisionPaths(this.#paths, id);
    const staging = createRevisionPaths(this.#paths, `.staging-${id}`);
    let stagedDirectory = staging.root;
    await mkdir(staging.root, { mode: 0o700 });
    try {
      await hardenPrivatePath(staging.root, true);
      await mkdir(staging.credentialDirectory, { mode: 0o700 });
      await hardenPrivatePath(staging.credentialDirectory, true);
      const entries = sortedFleetEntries(profile);
      for (const [alias, target] of entries) {
        if (isAccessClientManagedTarget(target)) continue;
        const credentials = fleetCredentialPaths(staging, alias);
        await mkdir(credentials.root, { mode: 0o700 });
        await hardenPrivatePath(credentials.root, true);
      }

      await allSettledOrThrow(
        entries.flatMap(([alias, target]) => {
          if (isAccessClientManagedTarget(target)) return [];
          const credentials = fleetCredentialPaths(staging, alias);
          return [
            importPrivateFile(
              this.#keyVault.privateKeyPath(target.target.keyId!),
              credentials.targetPrivateKey,
              `${alias} target private key`,
              MAX_PRIVATE_KEY_BYTES,
            ),
            importPrivateFile(
              target.knownHostsFile!,
              credentials.knownHosts,
              `${alias} known_hosts`,
              MAX_KNOWN_HOSTS_BYTES,
            ),
            ...(target.bastion === undefined
              ? []
              : [
                  importPrivateFile(
                    this.#keyVault.privateKeyPath(target.bastion.keyId!),
                    credentials.bastionPrivateKey,
                    `${alias} bastion private key`,
                    MAX_PRIVATE_KEY_BYTES,
                  ),
                ]),
          ];
        }),
      );

      await allSettledOrThrow(
        entries.flatMap(([alias, target]) => {
          if (isAccessClientManagedTarget(target)) return [];
          const credentials = fleetCredentialPaths(staging, alias);
          return [
            validatePrivateKey(
              this.#sshKeygenExecutable,
              credentials.targetPrivateKey,
              `${alias} target private key`,
            ),
            verifyKnownHost(
              this.#sshKeygenExecutable,
              credentials.knownHosts,
              target.target.host,
              target.target.port,
            ),
            ...(target.bastion === undefined
              ? []
              : [
                  validatePrivateKey(
                    this.#sshKeygenExecutable,
                    credentials.bastionPrivateKey,
                    `${alias} bastion private key`,
                  ),
                  verifyKnownHost(
                    this.#sshKeygenExecutable,
                    credentials.knownHosts,
                    target.bastion.host,
                    target.bastion.port,
                  ),
                ]),
          ];
        }),
      );

      const managedProfile = normaliseFleetCredentialPaths(profile, published);
      await writeAggregateKnownHosts(
        staging,
        entries
          .filter(([, target]) => !isAccessClientManagedTarget(target))
          .map(([alias]) => alias),
      );
      await validateFleetCredentials(
        this.#sshKeygenExecutable,
        staging,
        managedProfile,
      );
      const sshSource = renderManagedFleetOpenSshConfiguration(
        managedProfile,
        published,
      );
      const gatewaySource = renderFleetGatewayConfiguration(
        published,
        this.#paths.runtime,
        this.#sshExecutable,
        managedProfile,
      );
      parseConfigText(gatewaySource);
      const profileSource = `${JSON.stringify(managedProfile, null, 2)}\n`;
      await allSettledOrThrow([
        writeExclusivePrivateFile(staging.sshConfig, sshSource),
        writeExclusivePrivateFile(staging.gatewayConfig, gatewaySource),
        writeExclusivePrivateFile(staging.profile, profileSource),
      ]);

      await validateFleetOpenSshConfiguration(
        this.#sshExecutable,
        staging.sshConfig,
        published,
        managedProfile,
      );
      await rename(staging.root, published.root);
      stagedDirectory = published.root;
      await hardenPrivatePath(published.root, true);
      await validateFleetOpenSshConfiguration(
        this.#sshExecutable,
        published.sshConfig,
        published,
        managedProfile,
      );
      return { published, profile: managedProfile };
    } catch (error) {
      if (stagedDirectory === published.root) {
        await removeInactiveRevision(this.#paths, published.id).catch(
          () => undefined,
        );
      } else {
        await removeRevisionDirectory(this.#paths, staging.root).catch(
          () => undefined,
        );
      }
      if (error instanceof ManagedSshKeyVaultError) {
        throw toManagedKeyError(error);
      }
      if (error instanceof ManagedSshError || error instanceof z.ZodError) {
        throw error;
      }
      throw publicManagedError(
        "CONFIG_FILE_INVALID",
        "An SSH configuration file is missing or unsafe",
        error,
      );
    }
  }

  async #validateRevision(revision: RevisionPaths): Promise<ValidatedRevision> {
    await assertDirectDirectory(revision.root, "managed revision");
    await assertDirectDirectory(
      revision.credentialDirectory,
      "managed credential directory",
    );
    await Promise.all([
      assertRegularFile(revision.knownHosts, "known_hosts"),
      assertRegularFile(revision.sshConfig, "managed ssh_config"),
      assertRegularFile(revision.gatewayConfig, "managed gateway config"),
      assertRegularFile(revision.profile, "managed profile"),
    ]);
    await hardenPrivatePaths([
      { path: revision.root, directory: true },
      { path: revision.credentialDirectory, directory: true },
      { path: revision.knownHosts, directory: false },
      { path: revision.sshConfig, directory: false },
      { path: revision.gatewayConfig, directory: false },
      { path: revision.profile, directory: false },
    ]);

    const profile = await readStoredProfile(revision.profile);
    if ("version" in profile) {
      await validateFleetCredentialStorage(revision, profile);
      const expectedSsh = renderManagedFleetOpenSshConfiguration(
        profile,
        revision,
      );
      const expectedGateway = renderFleetGatewayConfiguration(
        revision,
        this.#paths.runtime,
        this.#sshExecutable,
        profile,
      );
      const legacyGateway = renderFleetGatewayConfiguration(
        revision,
        this.#paths.runtime,
        this.#sshExecutable,
        profile,
        LEGACY_INLINE_OUTPUT_BYTES,
      );
      await assertStoredGeneratedConfiguration(
        revision,
        expectedSsh,
        expectedGateway,
        [legacyGateway],
      );
      await validateFleetCredentials(
        this.#sshKeygenExecutable,
        revision,
        profile,
      );
      await validateFleetOpenSshConfiguration(
        this.#sshExecutable,
        revision.sshConfig,
        revision,
        profile,
      );
      return profile.version === 3
        ? { storedProfile: profile, fleetProfile: profile }
        : { storedProfile: profile, legacyFleetProfile: profile };
    }

    await assertRegularFile(revision.targetPrivateKey, "target private key");
    await hardenPrivatePath(revision.targetPrivateKey, false);
    if (profile.bastion !== undefined) {
      await assertRegularFile(revision.bastionPrivateKey, "bastion private key");
      await hardenPrivatePath(revision.bastionPrivateKey, false);
    }

    const expectedSsh = renderManagedOpenSshConfiguration(profile, revision);
    const expectedGateway = renderGatewayConfiguration(
      revision,
      this.#paths.runtime,
      this.#sshExecutable,
      profile,
    );
    const legacyGateway = renderGatewayConfiguration(
      revision,
      this.#paths.runtime,
      this.#sshExecutable,
      profile,
      LEGACY_INLINE_OUTPUT_BYTES,
    );
    await assertStoredGeneratedConfiguration(
      revision,
      expectedSsh,
      expectedGateway,
      [legacyGateway],
    );

    await Promise.all([
      validatePrivateKey(
        this.#sshKeygenExecutable,
        revision.targetPrivateKey,
        "target private key",
      ),
      verifyKnownHost(
        this.#sshKeygenExecutable,
        revision.knownHosts,
        profile.target.host,
        profile.target.port,
      ),
      ...(profile.bastion === undefined
        ? []
        : [
            validatePrivateKey(
              this.#sshKeygenExecutable,
              revision.bastionPrivateKey,
              "bastion private key",
            ),
            verifyKnownHost(
              this.#sshKeygenExecutable,
              revision.knownHosts,
              profile.bastion.host,
              profile.bastion.port,
            ),
          ]),
    ]);
    await validateOpenSshConfiguration(
      this.#sshExecutable,
      revision.sshConfig,
      revision,
      profile,
    );
    return {
      storedProfile: profile,
      ...("platform" in profile ? { legacySingleProfile: profile } : {}),
    };
  }

  async #migrateFleetProfile(
    revision: RevisionPaths,
    profile: StoredManagedSshFleetProfileV2,
  ): Promise<ManagedSshFleetProfile> {
    const targets: Record<string, unknown> = {};
    const entries = Object.entries(profile.targets).sort(([left], [right]) =>
      left.localeCompare(right),
    );
    for (const [alias, legacyTarget] of entries) {
      const credentials = fleetCredentialPaths(revision, alias);
      const targetKey = await this.#keyVault.importMigrated(
        `${alias} target`,
        credentials.targetPrivateKey,
      );
      const bastionKey =
        legacyTarget.bastion === undefined
          ? undefined
          : await this.#keyVault.importMigrated(
              `${alias} bastion`,
              credentials.bastionPrivateKey,
            );
      const {
        target: legacyEndpoint,
        bastion: legacyBastion,
        ...common
      } = legacyTarget;
      targets[alias] = {
        ...common,
        target: {
          host: legacyEndpoint.host,
          port: legacyEndpoint.port,
          username: legacyEndpoint.username,
          keyId: targetKey.keyId,
        },
        ...(legacyBastion === undefined || bastionKey === undefined
          ? {}
          : {
              bastion: {
                host: legacyBastion.host,
                port: legacyBastion.port,
                username: legacyBastion.username,
                keyId: bastionKey.keyId,
              },
            }),
      };
    }
    return managedSshFleetProfileSchema.parse({ version: 3, targets });
  }

  async #migrateSingleProfile(
    revision: RevisionPaths,
    profile: CurrentManagedSshProfile,
  ): Promise<ManagedSshFleetProfile> {
    const targetKey = await this.#keyVault.importMigrated(
      `${MANAGED_TARGET_ALIAS} target`,
      revision.targetPrivateKey,
    );
    const bastionKey =
      profile.bastion === undefined
        ? undefined
        : await this.#keyVault.importMigrated(
            `${MANAGED_TARGET_ALIAS} bastion`,
            revision.bastionPrivateKey,
          );
    return singleProfileToFleet(
      { ...profile, knownHostsFile: revision.knownHosts },
      targetKey.keyId,
      bastionKey?.keyId,
    );
  }

  async #retainedKeyReferences(
    keyId: string,
  ): Promise<ManagedSshKeyReference[]> {
    if (!this.#referenceStateTrusted) {
      throw publicManagedError(
        "KEY_REFERENCE_CHECK_FAILED",
        "Saved SSH key references could not be verified",
      );
    }
    const references = new Map<string, ManagedSshKeyReference>();
    const addProfile = (profile: ManagedSshFleetProfile | undefined): void => {
      for (const reference of managedKeyReferences(profile).get(keyId) ?? []) {
        references.set(
          `${reference.alias.toLowerCase()}:${reference.role}`,
          reference,
        );
      }
    };
    addProfile(this.#fleetProfile);
    const revisionIds = new Set(await listPublishedRevisionsNewestFirst(this.#paths));
    for (const revisionId of revisionIds) {
      if (revisionId === undefined) continue;
      let stored: ManagedSshProfile | StoredManagedSshFleetProfile;
      try {
        stored = await readStoredProfile(
          createRevisionPaths(this.#paths, revisionId).profile,
        );
      } catch (error) {
        throw publicManagedError(
          "KEY_REFERENCE_CHECK_FAILED",
          "Saved SSH key references could not be verified",
          error,
        );
      }
      if ("version" in stored && stored.version === 3) addProfile(stored);
    }
    return [...references.values()];
  }

  async #buildStatus(): Promise<ManagedSshStatus> {
    const generatedKey = await readGeneratedKey(this.#paths).catch(
      () => undefined,
    );
    const profile =
      this.#legacyProfile ??
      compatibilityProfile(this.#fleetProfile, this.#activeRevision);
    return {
      state: this.#state,
      configured:
        this.#legacyProfile !== undefined || fleetHasTargets(this.#fleetProfile),
      defaultKnownHostsFile: path.join(os.homedir(), ".ssh", "known_hosts"),
      allowedCommands: [...MANAGED_SUPPORTED_COMMANDS],
      ...(this.#activeRevision === undefined
        ? {}
        : { revision: this.#activeRevision.id }),
      ...(profile === undefined ? {} : { profile }),
      ...(generatedKey === undefined ? {} : { generatedKey }),
      ...(this.#lastError === undefined
        ? {}
        : {
            error: {
              code: this.#lastError.code,
              message: this.#lastError.message,
            },
      }),
    };
  }

  async #buildFleetStatus(): Promise<ManagedSshFleetStatus> {
    const keyStatus = this.#buildKeyStatus();
    return {
      state: this.#state,
      configured: fleetHasTargets(this.#fleetProfile),
      defaultKnownHostsFile: path.join(os.homedir(), ".ssh", "known_hosts"),
      commandPresets: MANAGED_PLATFORM_COMMANDS,
      keyRevision: keyStatus.keyRevision,
      keys: keyStatus.keys,
      ...(this.#activeRevision === undefined
        ? {}
        : { revision: this.#activeRevision.id }),
      ...(this.#fleetProfile === undefined
        ? {}
        : { profile: this.#fleetProfile }),
      ...(this.#lastError === undefined
        ? {}
        : {
            error: {
              code: this.#lastError.code,
              message: this.#lastError.message,
            },
          }),
      ...(keyStatus.error === undefined
        ? {}
        : {
            keyError: {
              code: keyStatus.error.code,
              message: keyStatus.error.message,
            },
          }),
    };
  }

  #buildKeyStatus(): ManagedSshKeyStatus {
    let snapshot: ManagedSshKeyVaultSnapshot;
    try {
      snapshot = this.#keyVault.snapshot();
    } catch {
      return {
        keyRevision: this.#fallbackKeyRevision,
        keys: [],
        ...(this.#keyError === undefined
          ? {}
          : {
              error: {
                code: this.#keyError.code,
                message: this.#keyError.message,
              },
            }),
      };
    }
    const references = managedKeyReferences(this.#fleetProfile);
    return {
      keyRevision: snapshot.keyRevision,
      keys: snapshot.keys.map((key) => ({
        ...key,
        inUseBy: references.get(key.keyId) ?? [],
      })),
      ...(this.#keyError === undefined
        ? {}
        : {
            error: {
              code: this.#keyError.code,
              message: this.#keyError.message,
            },
          }),
    };
  }

  #runExclusive<Result>(operation: () => Promise<Result>): Promise<Result> {
    if (this.#operation !== undefined) {
      return Promise.reject(
        publicManagedError(
          "CONFIG_BUSY",
          "Another SSH configuration operation is still running",
          undefined,
          409,
        ),
      );
    }
    const pending = operation();
    this.#operation = pending;
    return pending.finally(() => {
      if (this.#operation === pending) {
        this.#operation = undefined;
      }
    });
  }

  #assertOpen(): void {
    if (this.#closed) {
      throw publicManagedError(
        "CONFIG_CLOSED",
        "The managed SSH configuration service is stopping",
        undefined,
        503,
      );
    }
  }
}

function createManagedPaths(directory: string): ManagedPaths {
  const root = resolveSafeManagedRoot(directory);
  const generatedKeyDirectory = path.join(root, "generated-key");
  return {
    root,
    runtime: path.join(root, "runtime"),
    revisions: path.join(root, "revisions"),
    keys: path.join(root, "keys"),
    activePointer: path.join(root, "active.json"),
    generatedKeyDirectory,
    generatedPrivateKey: path.join(generatedKeyDirectory, "agent_ssh_ed25519"),
    generatedPublicKey: path.join(
      generatedKeyDirectory,
      "agent_ssh_ed25519.pub",
    ),
    setupLeaseDirectory: path.join(root, "setup-lease"),
  };
}

function createRevisionPaths(paths: ManagedPaths, id: string): RevisionPaths {
  const root = path.join(paths.revisions, id);
  const credentialDirectory = path.join(root, "credentials");
  return {
    id,
    root,
    credentialDirectory,
    targetPrivateKey: path.join(credentialDirectory, "target.key"),
    bastionPrivateKey: path.join(credentialDirectory, "bastion.key"),
    knownHosts: path.join(root, "known_hosts"),
    sshConfig: path.join(root, "ssh_config"),
    gatewayConfig: path.join(root, "gateway.yaml"),
    profile: path.join(root, "profile.json"),
  };
}

function fleetCredentialPaths(
  revision: RevisionPaths,
  alias: string,
): FleetCredentialPaths {
  const safeAlias = targetAliasSchema.parse(alias);
  const root = path.join(revision.credentialDirectory, safeAlias);
  return {
    root,
    targetPrivateKey: path.join(root, "target.key"),
    bastionPrivateKey: path.join(root, "bastion.key"),
    knownHosts: path.join(root, "known_hosts"),
  };
}

function sortedFleetEntries(
  profile: ManagedSshFleetProfile,
): [string, ManagedSshFleetTarget][] {
  return Object.entries(profile.targets).sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
}

function sortedStoredFleetEntries(
  profile: ManagedSshFleetProfile | StoredManagedSshFleetProfileV2,
): [string, ManagedSshFleetTarget | StoredManagedSshFleetTargetV2][] {
  return Object.entries(profile.targets).sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
}

type AccessClientManagedTarget = ManagedSshFleetTarget & {
  readonly connectionMode: "accessclient-share";
  readonly accessClient: NonNullable<ManagedSshFleetTarget["accessClient"]>;
};

function isAccessClientManagedTarget(
  target: ManagedSshFleetTarget | StoredManagedSshFleetTargetV2,
): target is AccessClientManagedTarget {
  return (
    "connectionMode" in target &&
    target.connectionMode === "accessclient-share"
  );
}

function fleetSshAliases(index: number): {
  readonly target: string;
  readonly bastion: string;
} {
  const suffix = String(index + 1).padStart(4, "0");
  return {
    target: `managed-target-${suffix}`,
    bastion: `managed-bastion-${suffix}`,
  };
}

function createRevisionId(): string {
  return `r-${Date.now().toString(36)}-${randomBytes(16).toString("hex")}`;
}

function createManagedKeyRevision(): string {
  return `kr-${Date.now().toString(36)}-${randomBytes(16).toString("hex")}`;
}

function managedKeyReferences(
  profile: ManagedSshFleetProfile | undefined,
): Map<string, ManagedSshKeyReference[]> {
  const references = new Map<string, ManagedSshKeyReference[]>();
  if (profile === undefined) return references;
  for (const [alias, target] of sortedFleetEntries(profile)) {
    if (isAccessClientManagedTarget(target)) continue;
    const targetReference: ManagedSshKeyReference = {
      alias,
      ...(target.targetId === undefined ? {} : { targetId: target.targetId }),
      role: "target",
    };
    references.set(target.target.keyId!, [
      ...(references.get(target.target.keyId!) ?? []),
      targetReference,
    ]);
    if (target.bastion !== undefined) {
      const bastionReference: ManagedSshKeyReference = {
        alias,
        ...(target.targetId === undefined ? {} : { targetId: target.targetId }),
        role: "bastion",
      };
      references.set(target.bastion.keyId!, [
        ...(references.get(target.bastion.keyId!) ?? []),
        bastionReference,
      ]);
    }
  }
  return references;
}

export function createManagedTargetId(): string {
  return `t-${randomBytes(16).toString("hex")}`;
}

function ensureFleetTargetIdentities(
  profile: ManagedSshFleetProfile,
  current: ManagedSshFleetProfile | undefined,
): ManagedSshFleetProfile {
  const currentEntries = Object.entries(current?.targets ?? {});
  const currentById = new Map(
    currentEntries.flatMap(([alias, target]) =>
      target.targetId === undefined ? [] : [[target.targetId, [alias, target]] as const],
    ),
  );
  const targets: Record<string, ManagedSshFleetTarget> = {};
  for (const [alias, target] of sortedFleetEntries(profile)) {
    let previous = current?.targets[alias];
    let previousAlias = alias;
    if (previous === undefined && target.targetId !== undefined) {
      const matched = currentById.get(target.targetId);
      if (matched !== undefined) {
        [previousAlias, previous] = matched;
      }
    }
    if (previous === undefined) {
      const matches = currentEntries.filter(
        ([candidateAlias, candidate]) =>
          !Object.hasOwn(profile.targets, candidateAlias) &&
          sameManagedEndpoint(candidate, target),
      );
      if (matches.length === 1) {
        [previousAlias, previous] = matches[0]!;
      }
    }

    const historicalAliases = new Map<string, string>();
    for (const historicalAlias of [
      ...(previous?.previousAliases ?? []),
      ...(target.previousAliases ?? []),
      ...(previous !== undefined && previousAlias !== alias ? [previousAlias] : []),
    ]) {
      if (historicalAlias.toLowerCase() !== alias.toLowerCase()) {
        historicalAliases.set(historicalAlias.toLowerCase(), historicalAlias);
      }
    }
    targets[alias] = {
      ...target,
      targetId: previous?.targetId ?? target.targetId ?? createManagedTargetId(),
      ...(historicalAliases.size === 0
        ? {}
        : { previousAliases: [...historicalAliases.values()] }),
    };
  }
  return managedSshFleetProfileSchema.parse({
    version: 3,
    ...(profile.accessClient === undefined
      ? {}
      : { accessClient: profile.accessClient }),
    targets,
  });
}

function sameManagedEndpoint(
  left: ManagedSshFleetTarget,
  right: ManagedSshFleetTarget,
): boolean {
  return (
    (left.connectionMode ?? "openssh") ===
      (right.connectionMode ?? "openssh") &&
    left.target.host === right.target.host &&
    left.target.port === right.target.port &&
    left.target.username === right.target.username &&
    sameOptionalEndpoint(left.bastion, right.bastion)
  );
}

function sameOptionalEndpoint(
  left: ManagedSshEndpoint | undefined,
  right: ManagedSshEndpoint | undefined,
): boolean {
  return (
    left === right ||
    (left !== undefined &&
      right !== undefined &&
      left.host === right.host &&
      left.port === right.port &&
      left.username === right.username)
  );
}

function resolveSafeManagedRoot(directory: string): string {
  if (!isSafeAbsoluteInputPath(directory)) {
    throw new TypeError(
      "managed SSH directory must be a local absolute path without device, UNC, ADS, or expansion syntax",
    );
  }
  const root = path.resolve(directory);
  if (root === path.parse(root).root || root === path.win32.parse(root).root) {
    throw new TypeError("managed SSH directory must not be a filesystem root");
  }
  return root;
}

function isSafeAbsoluteInputPath(value: string): boolean {
  if (
    value.length === 0 ||
    /[\u0000-\u001f\u007f"$]/u.test(value) ||
    value.startsWith("//") ||
    value.startsWith("\\\\")
  ) {
    return false;
  }
  if (process.platform !== "win32") {
    return path.isAbsolute(value);
  }

  const windowsValue = value.replaceAll("/", "\\");
  if (!/^[A-Za-z]:\\/u.test(windowsValue)) {
    return false;
  }
  return !windowsValue.slice(3).includes(":");
}

async function prepareManagedRoot(paths: ManagedPaths): Promise<void> {
  await assertLocalFixedVolume(paths.root);
  await assertNoReparseAncestors(paths.root);
  await ensurePrivateDirectory(paths.root);
  await assertNoReparseAncestors(paths.root);
  await Promise.all([
    ensurePrivateDirectory(paths.revisions),
    ensurePrivateDirectory(paths.keys),
    ensurePrivateDirectory(paths.generatedKeyDirectory),
  ]);
}

async function assertLocalFixedVolume(directory: string): Promise<void> {
  if (process.platform !== "win32") {
    return;
  }
  const script = String.raw`
$ErrorActionPreference = "Stop"
$managedRoot = [Environment]::GetEnvironmentVariable("AGENT_SSH_MANAGED_ROOT", "Process")
if ([string]::IsNullOrWhiteSpace($managedRoot)) {
  throw "Managed root was not supplied"
}
$volumeRoot = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($managedRoot))
$drive = [System.IO.DriveInfo]::new($volumeRoot)
if (-not $drive.IsReady -or $drive.DriveType -ne [System.IO.DriveType]::Fixed) {
  throw "Managed root must be on a ready local fixed drive"
}
`;
  try {
    await execFileNoInput(
      WINDOWS_POWERSHELL,
      ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
      10_000,
      { ...process.env, AGENT_SSH_MANAGED_ROOT: directory },
    );
  } catch (error) {
    throw publicManagedError(
      "MANAGED_PATH_UNSAFE",
      "The managed SSH directory must be on a ready local fixed drive",
      error,
    );
  }
}

async function assertNoReparseAncestors(directory: string): Promise<void> {
  const root = path.parse(directory).root;
  const relative = path.relative(root, directory);
  let current = root;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    try {
      const entry = await lstat(current);
      if (!entry.isDirectory() || entry.isSymbolicLink()) {
        throw publicManagedError(
          "MANAGED_PATH_UNSAFE",
          "The managed SSH directory contains a reparse point or non-directory ancestor",
        );
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return;
      }
      throw error;
    }
  }
}

function isValidSshHost(value: string): boolean {
  if (isIP(value) !== 0) {
    return true;
  }
  if (value.endsWith(".") || !/^[A-Za-z0-9.-]+$/u.test(value)) {
    return false;
  }
  const labels = value.split(".");
  return labels.every(
    (label) =>
      label.length >= 1 &&
      label.length <= 63 &&
      /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u.test(label),
  );
}

function isValidSshUsername(value: string): boolean {
  if (!value.includes("/")) {
    return SSH_USERNAME_SEGMENT_PATTERN.test(value);
  }
  const segments = value.split("/");
  return (
    segments.length === 3 &&
    SSH_USERNAME_SEGMENT_PATTERN.test(segments[0] ?? "") &&
    isIP(segments[1] ?? "") === 4 &&
    SSH_USERNAME_SEGMENT_PATTERN.test(segments[2] ?? "")
  );
}

function singleProfileToFleet(
  profile: CurrentManagedSshProfile,
  targetKeyId: string,
  bastionKeyId?: string,
): ManagedSshFleetProfile {
  return managedSshFleetProfileSchema.parse({
    version: 3,
    targets: {
      [MANAGED_TARGET_ALIAS]: {
        description: `${profile.target.username}@${profile.target.host}:${profile.target.port}`,
        enabled: true,
        target: {
          host: profile.target.host,
          port: profile.target.port,
          username: profile.target.username,
          keyId: targetKeyId,
        },
        knownHostsFile: profile.knownHostsFile,
        ...(profile.bastion === undefined || bastionKeyId === undefined
          ? {}
          : {
              bastion: {
                host: profile.bastion.host,
                port: profile.bastion.port,
                username: profile.bastion.username,
                keyId: bastionKeyId,
              },
            }),
        platform: profile.platform,
        policyMode: profile.policyMode,
        allowedCommands: profile.allowedCommands,
        maxTimeoutMs: 30_000,
      },
    },
  });
}

function normaliseFleetCredentialPaths(
  profile: ManagedSshFleetProfile,
  revision: RevisionPaths,
): ManagedSshFleetProfile {
  const targets: Record<string, unknown> = {};
  for (const [alias, target] of sortedFleetEntries(profile)) {
    if (isAccessClientManagedTarget(target)) {
      targets[alias] = { ...target };
      continue;
    }
    const credentials = fleetCredentialPaths(revision, alias);
    targets[alias] = {
      ...target,
      knownHostsFile: credentials.knownHosts,
    };
  }
  return managedSshFleetProfileSchema.parse({
    version: 3,
    ...(profile.accessClient === undefined
      ? {}
      : { accessClient: profile.accessClient }),
    targets,
  });
}

function legacyFleetPublicFallback(
  revision: RevisionPaths,
  profile: StoredManagedSshFleetProfileV2,
): ManagedSshFleetProfile {
  const targets: Record<string, unknown> = {};
  for (const [alias, legacyTarget] of sortedStoredFleetEntries(profile)) {
    const {
      target: legacyEndpoint,
      bastion: legacyBastion,
      ...common
    } = legacyTarget;
    targets[alias] = {
      ...common,
      target: {
        host: legacyEndpoint.host,
        port: legacyEndpoint.port,
        username: legacyEndpoint.username,
        keyId: legacyFallbackKeyId(revision.id, alias, "target"),
      },
      ...(legacyBastion === undefined
        ? {}
        : {
            bastion: {
              host: legacyBastion.host,
              port: legacyBastion.port,
              username: legacyBastion.username,
              keyId: legacyFallbackKeyId(revision.id, alias, "bastion"),
            },
          }),
    };
  }
  return managedSshFleetProfileSchema.parse({ version: 3, targets });
}

function legacySinglePublicFallback(
  revision: RevisionPaths,
  profile: CurrentManagedSshProfile,
): ManagedSshFleetProfile {
  return singleProfileToFleet(
    { ...profile, knownHostsFile: revision.knownHosts },
    legacyFallbackKeyId(revision.id, MANAGED_TARGET_ALIAS, "target"),
    profile.bastion === undefined
      ? undefined
      : legacyFallbackKeyId(
          revision.id,
          MANAGED_TARGET_ALIAS,
          "bastion",
        ),
  );
}

function legacyFallbackKeyId(
  revisionId: string,
  alias: string,
  role: "target" | "bastion",
): string {
  return `k-${createHash("sha256")
    .update(`${revisionId}\0${alias}\0${role}`, "utf8")
    .digest("hex")
    .slice(0, 32)}`;
}

function compatibilityProfile(
  fleet: ManagedSshFleetProfile | undefined,
  revision: RevisionPaths | undefined,
): CurrentManagedSshProfile | undefined {
  const target = fleet?.targets[MANAGED_TARGET_ALIAS];
  if (
    target === undefined ||
    target.policyMode === "deny" ||
    isAccessClientManagedTarget(target) ||
    revision === undefined
  ) {
    return undefined;
  }
  const credentials = fleetCredentialPaths(revision, MANAGED_TARGET_ALIAS);
  return currentManagedSshProfileSchema.parse({
    target: {
      host: target.target.host,
      port: target.target.port,
      username: target.target.username,
      identityFile: credentials.targetPrivateKey,
    },
    knownHostsFile: target.knownHostsFile,
    ...(target.bastion === undefined
      ? {}
      : {
          bastion: {
            host: target.bastion.host,
            port: target.bastion.port,
            username: target.bastion.username,
            identityFile: credentials.bastionPrivateKey,
          },
        }),
    platform: target.platform,
    policyMode: target.policyMode,
    allowedCommands: target.allowedCommands,
  });
}

function fleetHasTargets(
  fleet: ManagedSshFleetProfile | undefined,
): boolean {
  return fleet !== undefined && Object.keys(fleet.targets).length > 0;
}

function renderManagedFleetOpenSshConfiguration(
  profile: ManagedSshFleetProfile | StoredManagedSshFleetProfileV2,
  revision: RevisionPaths,
): string {
  const sections = [
    "# Generated by Agent SSH Gateway managed setup. Do not edit.",
  ];
  for (const [index, [alias, target]] of sortedStoredFleetEntries(profile).entries()) {
    if (isAccessClientManagedTarget(target)) continue;
    const credentials = fleetCredentialPaths(revision, alias);
    const sshAliases = fleetSshAliases(index);
    if (target.bastion !== undefined) {
      sections.push(
        renderEndpoint(
          sshAliases.bastion,
          target.bastion,
          credentials.bastionPrivateKey,
        ),
      );
    }
    sections.push(
      renderEndpoint(
        sshAliases.target,
        target.target,
        credentials.targetPrivateKey,
        target.bastion === undefined ? undefined : sshAliases.bastion,
      ),
    );
  }
  return `${sections.join("\n\n")}\n`;
}

function renderManagedOpenSshConfiguration(
  profile: ManagedSshProfile,
  revision: RevisionPaths,
): string {
  const sections: string[] = [
    "# Generated by Agent SSH Gateway managed setup. Do not edit.",
  ];
  if (profile.bastion !== undefined) {
    sections.push(
      renderEndpoint(
        MANAGED_BASTION_ALIAS,
        profile.bastion,
        revision.bastionPrivateKey,
      ),
    );
  }
  sections.push(
    renderEndpoint(
      MANAGED_TARGET_ALIAS,
      profile.target,
      revision.targetPrivateKey,
      profile.bastion === undefined ? undefined : MANAGED_BASTION_ALIAS,
    ),
  );
  return `${sections.join("\n\n")}\n`;
}

function renderEndpoint(
  alias: string,
  endpoint: ManagedSshEndpoint,
  managedIdentityFile: string,
  proxyJump?: string,
): string {
  return [
    `Host ${alias}`,
    `    HostName ${endpoint.host}`,
    `    Port ${endpoint.port}`,
    `    User ${endpoint.username}`,
    `    IdentityFile ${quoteOpenSshPath(managedIdentityFile)}`,
    "    IdentityAgent none",
    "    IdentitiesOnly yes",
    "    PubkeyAuthentication yes",
    "    PasswordAuthentication no",
    "    KbdInteractiveAuthentication no",
    "    PreferredAuthentications publickey",
    "    NumberOfPasswordPrompts 0",
    ...(proxyJump === undefined ? [] : [`    ProxyJump ${proxyJump}`]),
  ].join("\n");
}

function quoteOpenSshPath(value: string): string {
  return `"${value.replaceAll("\\", "/").replaceAll("%", "%%")}"`;
}

function renderGatewayConfiguration(
  revision: RevisionPaths,
  runtimeDirectory: string,
  sshExecutable: string,
  profile: ManagedSshProfile,
  inlineOutputBytes = MAX_INLINE_PREVIEW_BYTES,
): string {
  const value = {
    version: 1,
    runtime: {
      dataDirectory: runtimeDirectory,
      inlineOutputBytes,
      maxStoredOutputBytes: 10_485_760,
      maxTotalRetainedOutputBytes: 104_857_600,
      maxAuditBytes: 104_857_600,
      maxRetainedOutputs: 1_024,
      outputTtlSeconds: 900,
      maxConcurrentExecutions: 2,
    },
    ssh: {
      executable: sshExecutable,
      configFile: revision.sshConfig,
      knownHostsFile: revision.knownHosts,
      connectTimeoutSeconds: 15,
    },
    targets: {
      [MANAGED_TARGET_ALIAS]: {
        description: `${profile.target.username}@${profile.target.host}:${profile.target.port}`,
        sshAlias: MANAGED_TARGET_ALIAS,
        enabled: true,
        ...("platform" in profile ? { platform: profile.platform } : {}),
        policy:
          "policyMode" in profile && profile.policyMode === "full-access"
            ? {
                mode: "full-access",
                maxTimeoutMs: 30_000,
              }
            : {
                mode: "allow-list",
                allowedCommands: [...profile.allowedCommands],
                maxTimeoutMs: 30_000,
              },
      },
    },
  };
  return stringify(value, { lineWidth: 0 });
}

function renderFleetGatewayConfiguration(
  revision: RevisionPaths,
  runtimeDirectory: string,
  sshExecutable: string,
  profile: ManagedSshFleetProfile | StoredManagedSshFleetProfileV2,
  inlineOutputBytes = MAX_INLINE_PREVIEW_BYTES,
): string {
  const targets: Record<string, unknown> = {};
  const localRoots: Record<string, string> = {};
  for (const [index, [alias, target]] of sortedStoredFleetEntries(profile).entries()) {
    const sshAliases = fleetSshAliases(index);
    const policy =
      target.policyMode === "allow-list"
        ? {
            mode: "allow-list",
            allowedCommands: [...target.allowedCommands],
            maxTimeoutMs: target.maxTimeoutMs,
          }
        : {
            mode: target.policyMode,
            maxTimeoutMs: target.maxTimeoutMs,
          };
    targets[alias] = {
      ...(target.targetId === undefined ? {} : { targetId: target.targetId }),
      ...((target.previousAliases ?? []).length === 0
        ? {}
        : { previousAliases: [...target.previousAliases!] }),
      ...(target.description === undefined
        ? {}
        : { description: target.description }),
      sshAlias: sshAliases.target,
      enabled: target.enabled,
      platform: target.platform,
      ...(isAccessClientManagedTarget(target)
        ? {
            connection: {
              mode: "accessclient-share",
              gatewayHost: target.accessClient!.gatewayHost,
              gatewayPort: target.accessClient!.gatewayPort,
              gatewayUsername: target.accessClient!.gatewayUsername,
              ...(target.accessClient!.sharingHost === undefined
                ? {}
                : { sharingHost: target.accessClient!.sharingHost }),
              ...(target.accessClient!.sharingPort === undefined
                ? {}
                : { sharingPort: target.accessClient!.sharingPort }),
              ...(target.accessClient!.expectedHostname === undefined
                ? {}
                : { expectedHostname: target.accessClient!.expectedHostname }),
            },
          }
        : {}),
      policy,
      ...((target.transferMode ?? "deny") === "deny"
        ? {}
        : {
            transfer: {
              mode: target.transferMode,
              localRoots: [alias],
              remoteRoots: [...(target.remoteRoots ?? [])],
              maxFileBytes: 10_737_418_240,
              maxTotalBytes: 107_374_182_400,
              maxFiles: 10_000,
              maxTimeoutMs: target.maxTransferTimeoutMs ?? MAX_TIMEOUT_MS,
            },
          }),
    };
    if (
      (target.transferMode ?? "deny") !== "deny" &&
      target.localRootPath !== undefined
    ) {
      localRoots[alias] = target.localRootPath;
    }
  }
  return stringify(
    {
      version: 1,
      runtime: {
        dataDirectory: runtimeDirectory,
        inlineOutputBytes,
        maxStoredOutputBytes: 10_485_760,
        maxTotalRetainedOutputBytes: 104_857_600,
        maxAuditBytes: 104_857_600,
        maxRetainedOutputs: 1_024,
        outputTtlSeconds: 900,
        maxConcurrentExecutions: 2,
      },
      ssh: {
        executable: sshExecutable,
        configFile: revision.sshConfig,
        knownHostsFile: revision.knownHosts,
        connectTimeoutSeconds: 15,
      },
      ...("accessClient" in profile && profile.accessClient !== undefined
        ? { putty: { executable: profile.accessClient.plinkExecutable } }
        : {}),
      ...(Object.keys(localRoots).length === 0
        ? {}
        : { transfer: { localRoots } }),
      targets,
    },
    { lineWidth: 0 },
  );
}

async function validateOpenSshConfiguration(
  sshExecutable: string,
  configFile: string,
  revision: RevisionPaths,
  profile: ManagedSshProfile,
): Promise<void> {
  if (profile.bastion !== undefined) {
    const bastion = await resolveOpenSshConfiguration(
      sshExecutable,
      configFile,
      MANAGED_BASTION_ALIAS,
    );
    assertResolvedEndpoint(
      bastion,
      profile.bastion,
      revision.bastionPrivateKey,
    );
  }
  const target = await resolveOpenSshConfiguration(
    sshExecutable,
    configFile,
    MANAGED_TARGET_ALIAS,
  );
  assertResolvedEndpoint(target, profile.target, revision.targetPrivateKey);
  if (
    profile.bastion !== undefined &&
    target.get("proxyjump") !== MANAGED_BASTION_ALIAS
  ) {
    throw publicManagedError(
      "SSH_CONFIG_INVALID",
      "The generated SSH configuration did not preserve the managed bastion",
    );
  }
}

async function validateFleetOpenSshConfiguration(
  sshExecutable: string,
  configFile: string,
  revision: RevisionPaths,
  profile: ManagedSshFleetProfile | StoredManagedSshFleetProfileV2,
): Promise<void> {
  for (const [index, [alias, managedTarget]] of sortedStoredFleetEntries(
    profile,
  ).entries()) {
    if (isAccessClientManagedTarget(managedTarget)) continue;
    const credentials = fleetCredentialPaths(revision, alias);
    const sshAliases = fleetSshAliases(index);
    if (managedTarget.bastion !== undefined) {
      const bastion = await resolveOpenSshConfiguration(
        sshExecutable,
        configFile,
        sshAliases.bastion,
      );
      assertResolvedEndpoint(
        bastion,
        managedTarget.bastion,
        credentials.bastionPrivateKey,
      );
    }
    const target = await resolveOpenSshConfiguration(
      sshExecutable,
      configFile,
      sshAliases.target,
    );
    assertResolvedEndpoint(
      target,
      managedTarget.target,
      credentials.targetPrivateKey,
    );
    if (
      managedTarget.bastion !== undefined &&
      target.get("proxyjump") !== sshAliases.bastion
    ) {
      throw publicManagedError(
        "SSH_CONFIG_INVALID",
        `The generated SSH configuration did not preserve the ${alias} bastion`,
      );
    }
  }
}

async function resolveOpenSshConfiguration(
  sshExecutable: string,
  configFile: string,
  alias: string,
): Promise<Map<string, string>> {
  let stdout: string;
  try {
    ({ stdout } = await execFileNoInput(
      sshExecutable,
      ["-G", "-F", configFile, alias],
      10_000,
    ));
  } catch (error) {
    throw publicManagedError(
      "SSH_CONFIG_INVALID",
      "OpenSSH rejected the generated configuration",
      error,
    );
  }
  const values = new Map<string, string>();
  for (const line of stdout.split(/\r?\n/u)) {
    const separator = line.indexOf(" ");
    if (separator <= 0) {
      continue;
    }
    const key = line.slice(0, separator).toLowerCase();
    if (!values.has(key)) {
      values.set(key, line.slice(separator + 1).trim());
    }
  }
  return values;
}

function assertResolvedEndpoint(
  values: ReadonlyMap<string, string>,
  endpoint: ManagedSshEndpoint,
  identityFile: string,
): void {
  const valid =
    values.get("hostname")?.toLowerCase() === endpoint.host.toLowerCase() &&
    values.get("port") === String(endpoint.port) &&
    values.get("user") === endpoint.username &&
    comparablePath(values.get("identityfile")) === comparablePath(identityFile) &&
    values.get("identityagent") === "none" &&
    values.get("identitiesonly") === "yes" &&
    isOpenSshEnabled(values.get("pubkeyauthentication")) &&
    values.get("passwordauthentication") === "no" &&
    values.get("kbdinteractiveauthentication") === "no" &&
    values.get("preferredauthentications") === "publickey" &&
    values.get("numberofpasswordprompts") === "0";
  if (!valid) {
    throw publicManagedError(
      "SSH_CONFIG_INVALID",
      "The generated SSH configuration did not resolve to the requested public-key-only endpoint",
    );
  }
}

function isOpenSshEnabled(value: string | undefined): boolean {
  return value === "yes" || value === "true";
}

function comparablePath(value: string | undefined): string {
  if (value === undefined) {
    return "";
  }
  const normalized = value.replace(/^"|"$/gu, "").replaceAll("\\", "/");
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

async function writeAggregateKnownHosts(
  revision: RevisionPaths,
  aliases: readonly string[],
): Promise<void> {
  await writeExclusivePrivateFile(
    revision.knownHosts,
    await aggregateKnownHosts(revision, aliases),
  );
}

async function aggregateKnownHosts(
  revision: RevisionPaths,
  aliases: readonly string[],
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  const seen = new Set<string>();
  let totalBytes = 0;
  for (const alias of aliases) {
    const source = await readFile(fleetCredentialPaths(revision, alias).knownHosts);
    const digest = createHash("sha256").update(source).digest("hex");
    if (seen.has(digest)) {
      continue;
    }
    seen.add(digest);
    const chunk = source.at(-1) === 0x0a ? source : Buffer.concat([source, Buffer.from("\n")]);
    totalBytes += chunk.length;
    if (totalBytes > MAX_KNOWN_HOSTS_BYTES) {
      throw publicManagedError(
        "FILE_UNSAFE",
        "The aggregate known_hosts file exceeds the managed size limit",
      );
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, totalBytes);
}

async function validateFleetCredentialStorage(
  revision: RevisionPaths,
  profile: ManagedSshFleetProfile | StoredManagedSshFleetProfileV2,
): Promise<void> {
  assertManagedFleetCredentialPaths(revision, profile);
  const entries = await readdir(revision.credentialDirectory, {
    withFileTypes: true,
  });
  const expectedAliases = new Set(
    sortedStoredFleetEntries(profile)
      .filter(([, target]) => !isAccessClientManagedTarget(target))
      .map(([alias]) => alias),
  );
  for (const entry of entries) {
    if (
      !expectedAliases.has(entry.name) ||
      !entry.isDirectory() ||
      entry.isSymbolicLink()
    ) {
      throw publicManagedError(
        "CONFIG_INVALID",
        "Managed SSH credential storage contains an unexpected entry",
      );
    }
  }
  if (entries.length !== expectedAliases.size) {
    throw publicManagedError(
      "CONFIG_INVALID",
      "Managed SSH credential storage is incomplete",
    );
  }

  for (const [alias, target] of sortedStoredFleetEntries(profile)) {
    if (isAccessClientManagedTarget(target)) continue;
    const credentials = fleetCredentialPaths(revision, alias);
    await assertDirectDirectory(credentials.root, `${alias} credential directory`);
    const expectedFiles = new Set([
      "target.key",
      "known_hosts",
      ...(target.bastion === undefined ? [] : ["bastion.key"]),
    ]);
    const children = await readdir(credentials.root, { withFileTypes: true });
    if (
      children.length !== expectedFiles.size ||
      children.some(
        (entry) =>
          !expectedFiles.has(entry.name) ||
          !entry.isFile() ||
          entry.isSymbolicLink(),
      )
    ) {
      throw publicManagedError(
        "CONFIG_INVALID",
        `${alias} credential storage contains an unexpected entry`,
      );
    }
    await Promise.all([
      assertRegularFile(credentials.targetPrivateKey, `${alias} target private key`),
      assertRegularFile(credentials.knownHosts, `${alias} known_hosts`),
      ...(target.bastion === undefined
        ? []
        : [
            assertRegularFile(
              credentials.bastionPrivateKey,
              `${alias} bastion private key`,
            ),
          ]),
    ]);
    await hardenPrivatePaths([
      { path: credentials.root, directory: true },
      { path: credentials.targetPrivateKey, directory: false },
      { path: credentials.knownHosts, directory: false },
      ...(target.bastion === undefined
        ? []
        : [{ path: credentials.bastionPrivateKey, directory: false }]),
    ]);
  }

  const expectedKnownHosts = await aggregateKnownHosts(
    revision,
    sortedStoredFleetEntries(profile)
      .filter(([, target]) => !isAccessClientManagedTarget(target))
      .map(([alias]) => alias),
  );
  const storedKnownHosts = await readFile(revision.knownHosts);
  if (!storedKnownHosts.equals(expectedKnownHosts)) {
    throw publicManagedError(
      "CONFIG_INVALID",
      "Saved aggregate known_hosts does not match target credential storage",
    );
  }
}

function assertManagedFleetCredentialPaths(
  revision: RevisionPaths,
  profile: ManagedSshFleetProfile | StoredManagedSshFleetProfileV2,
): void {
  for (const [alias, target] of sortedStoredFleetEntries(profile)) {
    if (isAccessClientManagedTarget(target)) continue;
    const credentials = fleetCredentialPaths(revision, alias);
    const valid =
      comparablePath(target.knownHostsFile) ===
        comparablePath(credentials.knownHosts) &&
      (profile.version === 3 ||
        ("identityFile" in target.target &&
          comparablePath(target.target.identityFile) ===
            comparablePath(credentials.targetPrivateKey) &&
          (target.bastion === undefined ||
            ("identityFile" in target.bastion &&
              comparablePath(target.bastion.identityFile) ===
                comparablePath(credentials.bastionPrivateKey)))));
    if (!valid) {
      throw publicManagedError(
        "CONFIG_INVALID",
        `${alias} profile does not reference its managed credentials`,
      );
    }
  }
}

async function validateFleetCredentials(
  sshKeygenExecutable: string,
  revision: RevisionPaths,
  profile: ManagedSshFleetProfile | StoredManagedSshFleetProfileV2,
): Promise<void> {
  await allSettledOrThrow(
    sortedStoredFleetEntries(profile).flatMap(([alias, target]) => {
      if (isAccessClientManagedTarget(target)) return [];
      const credentials = fleetCredentialPaths(revision, alias);
      return [
        validatePrivateKey(
          sshKeygenExecutable,
          credentials.targetPrivateKey,
          `${alias} target private key`,
        ),
        verifyKnownHost(
          sshKeygenExecutable,
          credentials.knownHosts,
          target.target.host,
          target.target.port,
        ),
        verifyKnownHost(
          sshKeygenExecutable,
          revision.knownHosts,
          target.target.host,
          target.target.port,
        ),
        ...(target.bastion === undefined
          ? []
          : [
              validatePrivateKey(
                sshKeygenExecutable,
                credentials.bastionPrivateKey,
                `${alias} bastion private key`,
              ),
              verifyKnownHost(
                sshKeygenExecutable,
                credentials.knownHosts,
                target.bastion.host,
                target.bastion.port,
              ),
              verifyKnownHost(
                sshKeygenExecutable,
                revision.knownHosts,
                target.bastion.host,
                target.bastion.port,
              ),
            ]),
      ];
    }),
  );
}

async function assertStoredGeneratedConfiguration(
  revision: RevisionPaths,
  expectedSsh: string,
  expectedGateway: string,
  compatibleGateways: readonly string[] = [],
): Promise<void> {
  const [storedSsh, storedGateway] = await Promise.all([
    readFile(revision.sshConfig, "utf8"),
    readFile(revision.gatewayConfig, "utf8"),
  ]);
  if (
    storedSsh !== expectedSsh ||
    (storedGateway !== expectedGateway && !compatibleGateways.includes(storedGateway))
  ) {
    throw publicManagedError(
      "CONFIG_INVALID",
      "Saved SSH configuration does not match its managed profile",
    );
  }
  parseConfigText(storedGateway);
}

async function ensurePrivateDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await hardenPrivatePath(directory, true);
}

async function assertDirectDirectory(
  directory: string,
  label: string,
): Promise<void> {
  let entry;
  try {
    entry = await lstat(directory);
  } catch (error) {
    const missing = isMissingFilesystemEntryError(error);
    throw publicManagedError(
      missing ? "FILE_NOT_FOUND" : "FILE_ACCESS_FAILED",
      missing ? `${label} was not found` : `${label} could not be inspected`,
      error,
    );
  }
  if (!entry.isDirectory() || entry.isSymbolicLink()) {
    throw publicManagedError(
      "FILE_UNSAFE",
      `${label} must be a directly referenced directory`,
    );
  }
}

async function assertRegularFile(filePath: string, label: string): Promise<void> {
  let entry;
  try {
    entry = await lstat(filePath);
  } catch (error) {
    const missing = isMissingFilesystemEntryError(error);
    throw publicManagedError(
      missing ? "FILE_NOT_FOUND" : "FILE_ACCESS_FAILED",
      missing
        ? `${label} file was not found`
        : `${label} file could not be inspected`,
      error,
    );
  }
  if (!entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1) {
    throw publicManagedError(
      "FILE_UNSAFE",
      `${label} must be a directly referenced single-link regular file`,
    );
  }
}

function isMissingFilesystemEntryError(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return code === "ENOENT" || code === "ENOTDIR";
}

async function assertTrustedExecutable(
  filePath: string,
  label: string,
): Promise<void> {
  let entry;
  try {
    entry = await lstat(filePath);
  } catch (error) {
    throw publicManagedError(
      "FILE_NOT_FOUND",
      `${label} executable was not found`,
      error,
    );
  }
  if (!entry.isFile() || entry.isSymbolicLink()) {
    throw publicManagedError(
      "FILE_UNSAFE",
      `${label} must be a directly referenced regular executable`,
    );
  }
}

async function importPrivateFile(
  sourcePath: string,
  destinationPath: string,
  label: string,
  maxBytes: number,
): Promise<void> {
  const inspected = await lstat(sourcePath, { bigint: true }).catch(
    (error: unknown) => {
      throw publicManagedError(
        "FILE_NOT_FOUND",
        `${label} file was not found`,
        error,
      );
    },
  );
  assertImportableFile(inspected, label, maxBytes);
  const noFollowFlag = process.platform === "win32" ? 0 : fsConstants.O_NOFOLLOW;
  const source = await open(sourcePath, fsConstants.O_RDONLY | noFollowFlag);
  let destinationCreated = false;
  try {
    const initial = await source.stat({ bigint: true });
    assertImportableFile(initial, label, maxBytes);
    assertSameImportSource(inspected, initial, label);
    const body = await source.readFile();
    const verified = await source.stat({ bigint: true });
    assertSameImportSource(initial, verified, label);
    if (BigInt(body.length) !== initial.size) {
      throwFileChanged(label);
    }
    await writeExclusivePrivateFile(destinationPath, body);
    destinationCreated = true;
    const pathVerified = await lstat(sourcePath, { bigint: true });
    assertSameImportSource(initial, pathVerified, label);
  } catch (error) {
    if (destinationCreated) {
      await unlink(destinationPath).catch(() => undefined);
    }
    throw error;
  } finally {
    await source.close();
  }
}

function assertImportableFile(
  entry: BigIntStats,
  label: string,
  maxBytes: number,
): void {
  if (
    !entry.isFile() ||
    entry.isSymbolicLink() ||
    entry.nlink !== 1n ||
    entry.size < 1n ||
    entry.size > BigInt(maxBytes)
  ) {
    throw publicManagedError(
      "FILE_UNSAFE",
      `${label} has an unsupported type or size`,
    );
  }
}

function assertSameImportSource(
  expected: BigIntStats,
  actual: BigIntStats,
  label: string,
): void {
  if (
    expected.dev !== actual.dev ||
    expected.ino !== actual.ino ||
    expected.nlink !== actual.nlink ||
    expected.size !== actual.size ||
    expected.mtimeNs !== actual.mtimeNs ||
    expected.ctimeNs !== actual.ctimeNs
  ) {
    throwFileChanged(label);
  }
}

function throwFileChanged(label: string): never {
  throw publicManagedError(
    "FILE_CHANGED",
    `${label} changed while it was being imported`,
  );
}

async function validatePrivateKey(
  sshKeygenExecutable: string,
  privateKeyPath: string,
  label: string,
): Promise<string> {
  await assertRegularFile(privateKeyPath, label);
  try {
    const { stdout } = await execFileNoInput(
      sshKeygenExecutable,
      ["-y", "-P", "", "-f", privateKeyPath],
      10_000,
    );
    const publicKey = stdout.trim();
    if (publicKey.length === 0 || /[\r\n]/u.test(publicKey)) {
      throw new Error("ssh-keygen returned an invalid public key");
    }
    return publicKey;
  } catch (error) {
    throw publicManagedError(
      "PRIVATE_KEY_UNUSABLE",
      `The ${label} is invalid or requires a passphrase`,
      error,
    );
  }
}

async function verifyKnownHost(
  sshKeygenExecutable: string,
  knownHostsFile: string,
  host: string,
  port: number,
): Promise<void> {
  const candidates =
    port === 22 ? [host, `[${host}]:22`] : [`[${host}]:${port}`];
  for (const candidate of candidates) {
    try {
      const { stdout } = await execFileNoInput(
        sshKeygenExecutable,
        ["-F", candidate, "-f", knownHostsFile],
        10_000,
      );
      if (stdout.trim().length > 0) {
        return;
      }
    } catch {
      // Try the alternate standard-port representation before rejecting.
    }
  }
  throw publicManagedError(
    "HOST_KEY_NOT_TRUSTED",
    `No trusted host key was found for ${host}:${port}`,
  );
}

async function validateGeneratedKeyPair(
  sshKeygenExecutable: string,
  paths: ManagedPaths,
): Promise<void> {
  const generated = await readGeneratedKey(paths);
  const derived = await validatePrivateKey(
    sshKeygenExecutable,
    paths.generatedPrivateKey,
    "managed private key",
  );
  if (keyMaterial(generated.publicKey) !== keyMaterial(derived)) {
    throw publicManagedError(
      "KEY_FILES_INCOMPLETE",
      "The managed public and private keys do not match",
    );
  }
}

function keyMaterial(publicKey: string): string {
  return publicKey.trim().split(/\s+/u).slice(0, 2).join(" ");
}

async function readGeneratedKey(paths: ManagedPaths): Promise<GeneratedSshKey> {
  await Promise.all([
    assertRegularFile(paths.generatedPrivateKey, "managed private key"),
    assertRegularFile(paths.generatedPublicKey, "managed public key"),
  ]);
  await hardenPrivatePaths([
    { path: paths.generatedPrivateKey, directory: false },
    { path: paths.generatedPublicKey, directory: false },
  ]);
  const publicKey = (await readFile(paths.generatedPublicKey, "utf8")).trim();
  if (!PUBLIC_KEY_PATTERN.test(publicKey)) {
    throw publicManagedError(
      "PUBLIC_KEY_INVALID",
      "The managed public key is invalid",
    );
  }
  return { privateKeyPath: paths.generatedPrivateKey, publicKey };
}

async function readStoredProfile(
  filePath: string,
): Promise<ManagedSshProfile | StoredManagedSshFleetProfile> {
  await assertRegularFile(filePath, "managed profile");
  const raw = await readFile(filePath, "utf8");
  return z
    .union([storedManagedSshFleetProfileSchema, managedSshProfileSchema])
    .parse(JSON.parse(raw) as unknown);
}

async function readActivePointer(paths: ManagedPaths): Promise<ActivePointer> {
  await assertRegularFile(paths.activePointer, "active configuration pointer");
  await hardenPrivatePath(paths.activePointer, false);
  const raw = await readFile(paths.activePointer, "utf8");
  return activePointerSchema.parse(JSON.parse(raw) as unknown);
}

async function readActivePointerIfPresent(
  paths: ManagedPaths,
): Promise<ActivePointer | undefined> {
  try {
    return await readActivePointer(paths);
  } catch (error) {
    if (error instanceof ManagedSshError && error.code === "FILE_NOT_FOUND") {
      return undefined;
    }
    throw error;
  }
}

async function writeActivePointer(
  paths: ManagedPaths,
  pointer: ActivePointer,
): Promise<void> {
  const validated = activePointerSchema.parse(pointer);
  await atomicWritePrivateFile(
    paths.activePointer,
    `${JSON.stringify(validated)}\n`,
  );
}

async function restoreActivePointer(
  paths: ManagedPaths,
  failedRevision: string,
  previous: ActivePointer | undefined,
): Promise<boolean> {
  const current = await readActivePointerIfPresent(paths);
  if (
    current !== undefined &&
    current.revision !== failedRevision &&
    (previous === undefined || !sameActivePointer(current, previous))
  ) {
    return false;
  }

  if (previous === undefined) {
    if (current !== undefined) {
      await unlinkIfExists(paths.activePointer);
    }
    return (await readActivePointerIfPresent(paths)) === undefined;
  }

  if (current === undefined || !sameActivePointer(current, previous)) {
    await writeActivePointer(paths, previous);
  }
  const restored = await readActivePointerIfPresent(paths);
  return restored !== undefined && sameActivePointer(restored, previous);
}

function sameActivePointer(left: ActivePointer, right: ActivePointer): boolean {
  return (
    left.version === right.version &&
    left.revision === right.revision &&
    left.previousRevision === right.previousRevision &&
    sameRevisionList(
      left.quarantinedRevisions ?? [],
      right.quarantinedRevisions ?? [],
    )
  );
}

function sameRevisionList(left: readonly string[], right: readonly string[]): boolean {
  return (
    left.length === right.length &&
    left.every((revision, index) => revision === right[index])
  );
}

async function writeExclusivePrivateFile(
  filePath: string,
  source: string | Buffer,
): Promise<void> {
  const handle = await open(
    filePath,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
    0o600,
  );
  try {
    await handle.writeFile(source, typeof source === "string" ? "utf8" : undefined);
    await handle.sync();
  } catch (error) {
    await handle.close().catch(() => undefined);
    await unlink(filePath).catch(() => undefined);
    throw error;
  }
  await handle.close();
  try {
    await hardenPrivatePath(filePath, false);
  } catch (error) {
    await unlink(filePath).catch(() => undefined);
    throw error;
  }
}

async function atomicWritePrivateFile(
  filePath: string,
  source: string,
): Promise<void> {
  const temporaryPath = `${filePath}.tmp-${process.pid}-${randomBytes(16).toString("hex")}`;
  await writeExclusivePrivateFile(temporaryPath, source);
  try {
    await rename(temporaryPath, filePath);
  } catch (error) {
    await unlink(temporaryPath).catch(() => undefined);
    throw error;
  }
}

async function acquireSetupLease(paths: ManagedPaths): Promise<RuntimeLease> {
  try {
    return await createRuntimeDescriptor(paths.setupLeaseDirectory);
  } catch (error) {
    const contention = errorTreeContains(
      error,
      /already running|being recovered|unable to acquire/iu,
    );
    throw publicManagedError(
      contention ? "CONFIG_IN_USE" : "CONFIG_LOCK_INVALID",
      contention
        ? "Another managed SSH setup interface is already running"
        : "The managed SSH setup lease is invalid and was not replaced",
      error,
      409,
    );
  }
}

function errorTreeContains(error: unknown, pattern: RegExp): boolean {
  if (pattern.test(String(error))) {
    return true;
  }
  if (error instanceof AggregateError) {
    return error.errors.some((nested: unknown) =>
      errorTreeContains(nested, pattern),
    );
  }
  return false;
}

async function allSettledOrThrow(
  operations: readonly Promise<unknown>[],
): Promise<void> {
  const results = await Promise.allSettled(operations);
  const rejected = results.find(
    (result): result is PromiseRejectedResult => result.status === "rejected",
  );
  if (rejected !== undefined) {
    throw rejected.reason;
  }
}

async function listPublishedRevisionsNewestFirst(
  paths: ManagedPaths,
): Promise<string[]> {
  const entries = await readdir(paths.revisions, { withFileTypes: true });
  return entries
    .filter((entry) => REVISION_ID_PATTERN.test(entry.name))
    .map((entry) => entry.name)
    .sort(compareRevisionIdsNewestFirst);
}

async function pruneManagedRevisions(
  paths: ManagedPaths,
  retainedRevisions: readonly string[],
  retainNewestUntracked = false,
  maximumPublishedRevisions = 2,
  additionalRetainedRevisions: readonly string[] = [],
): Promise<void> {
  if (
    !Number.isSafeInteger(maximumPublishedRevisions) ||
    maximumPublishedRevisions < 1 ||
    maximumPublishedRevisions > 3
  ) {
    throw new RangeError("managed revision retention limit is invalid");
  }
  const retained = new Set<string>();
  for (const revision of retainedRevisions) {
    if (!REVISION_ID_PATTERN.test(revision)) {
      throw new TypeError("managed revision id is invalid");
    }
    retained.add(revision);
  }
  const additionalRetained = new Set<string>();
  for (const revision of additionalRetainedRevisions) {
    if (!REVISION_ID_PATTERN.test(revision)) {
      throw new TypeError("managed revision id is invalid");
    }
    additionalRetained.add(revision);
    retained.add(revision);
  }

  const entries = await readdir(paths.revisions, { withFileTypes: true });
  const published = entries
    .filter((entry) => REVISION_ID_PATTERN.test(entry.name))
    .map((entry) => entry.name);
  const additionalPublishedCount = published.filter((revision) =>
    additionalRetained.has(revision),
  ).length;
  if (retainNewestUntracked) {
    const newest = published
      .filter((revision) => !retained.has(revision))
      .sort(compareRevisionIdsNewestFirst)[0];
    if (newest !== undefined) {
      retained.add(newest);
    }
  }

  for (const entry of entries) {
    const stagingMatch = entry.name.match(STAGING_REVISION_ID_PATTERN);
    if (REVISION_ID_PATTERN.test(entry.name)) {
      if (!retained.has(entry.name)) {
        await removeInactiveRevision(paths, entry.name);
      }
      continue;
    }
    if (stagingMatch !== null) {
      await removeRevisionDirectory(
        paths,
        path.join(paths.revisions, entry.name),
      );
      continue;
    }
    throw publicManagedError(
      "CONFIG_INVALID",
      "Managed SSH revision storage contains an unexpected entry",
    );
  }

  const remaining = await readdir(paths.revisions);
  const publishedCount = remaining.filter((entry) =>
    REVISION_ID_PATTERN.test(entry),
  ).length;
  const stagingCount = remaining.filter((entry) =>
    STAGING_REVISION_ID_PATTERN.test(entry),
  ).length;
  if (
    publishedCount > maximumPublishedRevisions + additionalPublishedCount ||
    stagingCount !== 0
  ) {
    throw publicManagedError(
      "CONFIG_INVALID",
      "Managed SSH revision retention could not be enforced",
    );
  }
}

function compareRevisionIdsNewestFirst(left: string, right: string): number {
  const leftTimestamp = Number.parseInt(left.split("-", 3)[1]!, 36);
  const rightTimestamp = Number.parseInt(right.split("-", 3)[1]!, 36);
  return rightTimestamp - leftTimestamp || right.localeCompare(left);
}

async function removeInactiveRevision(
  paths: ManagedPaths,
  revision: string,
): Promise<boolean> {
  if (!REVISION_ID_PATTERN.test(revision)) {
    throw new TypeError("managed revision id is invalid");
  }
  const active = await readActivePointerIfPresent(paths);
  if (
    active?.revision === revision ||
    active?.previousRevision === revision ||
    active?.quarantinedRevisions?.includes(revision) === true
  ) {
    return false;
  }
  await removeRevisionDirectory(
    paths,
    createRevisionPaths(paths, revision).root,
  );
  return true;
}

async function removeRevisionDirectory(
  paths: ManagedPaths,
  directory: string,
): Promise<void> {
  const relative = path.relative(paths.revisions, directory);
  if (
    relative.length === 0 ||
    relative.startsWith("..") ||
    path.isAbsolute(relative) ||
    relative.includes(path.sep)
  ) {
    throw new Error("Refusing to remove an unmanaged revision path");
  }
  if (
    !REVISION_ID_PATTERN.test(relative) &&
    !STAGING_REVISION_ID_PATTERN.test(relative)
  ) {
    throw new Error("Refusing to remove an invalid revision path");
  }
  const entry = await lstat(directory).catch((error: unknown) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return undefined;
    }
    throw error;
  });
  if (entry === undefined) {
    return;
  }
  if (!entry.isDirectory() || entry.isSymbolicLink()) {
    throw new Error("Refusing to remove an unsafe revision path");
  }
  const entries = await readdir(directory, { withFileTypes: true });
  for (const child of entries) {
    const childPath = path.join(directory, child.name);
    if (child.name === "credentials") {
      await removeCredentialDirectory(childPath);
      continue;
    }
    if (
      child.name === "known_hosts" ||
      child.name === "ssh_config" ||
      child.name === "gateway.yaml" ||
      child.name === "profile.json"
    ) {
      await removeSingleLinkFile(childPath);
      continue;
    }
    throw new Error("Refusing to remove an unexpected revision entry");
  }
  await rmdir(directory);
}

async function removeCredentialDirectory(directory: string): Promise<void> {
  const entry = await lstat(directory);
  if (!entry.isDirectory() || entry.isSymbolicLink()) {
    throw new Error("Refusing to remove an unsafe credential directory");
  }
  const entries = await readdir(directory, { withFileTypes: true });
  for (const child of entries) {
    const childPath = path.join(directory, child.name);
    if (child.name === "target.key" || child.name === "bastion.key") {
      await removeSingleLinkFile(childPath);
      continue;
    }
    if (
      child.isDirectory() &&
      !child.isSymbolicLink() &&
      targetAliasSchema.safeParse(child.name).success
    ) {
      await removeFleetCredentialDirectory(childPath);
      continue;
    }
    throw new Error("Refusing to remove an unexpected credential entry");
  }
  await rmdir(directory);
}

async function removeFleetCredentialDirectory(directory: string): Promise<void> {
  const entry = await lstat(directory);
  if (!entry.isDirectory() || entry.isSymbolicLink()) {
    throw new Error("Refusing to remove an unsafe target credential directory");
  }
  const children = await readdir(directory, { withFileTypes: true });
  for (const child of children) {
    if (
      child.name !== "target.key" &&
      child.name !== "bastion.key" &&
      child.name !== "known_hosts"
    ) {
      throw new Error("Refusing to remove an unexpected target credential entry");
    }
    await removeSingleLinkFile(path.join(directory, child.name));
  }
  await rmdir(directory);
}

async function removeSingleLinkFile(filePath: string): Promise<void> {
  const entry = await lstat(filePath);
  if (!entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1) {
    throw new Error("Refusing to remove an unsafe revision file");
  }
  await unlink(filePath);
}

async function unlinkIfExists(filePath: string): Promise<void> {
  await unlink(filePath).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") {
      throw error;
    }
  });
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await lstat(filePath);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

function execFileNoInput(
  executable: string,
  args: readonly string[],
  timeout: number,
  environment?: NodeJS.ProcessEnv,
): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      executable,
      [...args],
      {
        encoding: "utf8",
        windowsHide: true,
        timeout,
        maxBuffer: 1_048_576,
        ...(environment === undefined ? {} : { env: environment }),
      },
      (error, stdout, stderr) => {
        if (error !== null) {
          reject(error);
          return;
        }
        resolve({ stdout, stderr });
      },
    );
    child.stdin?.end();
  });
}

function isReloadBusyError(error: unknown): boolean {
  if (typeof error !== "object" || error === null) {
    return false;
  }
  const code = (error as { readonly code?: unknown }).code;
  return code === "ACTIVE_EXECUTIONS" || code === "RELOAD_IN_PROGRESS";
}

function toManagedKeyError(error: unknown): ManagedSshError {
  if (error instanceof ManagedSshError) return error;
  if (error instanceof ManagedSshKeyVaultError) {
    return publicManagedError(error.code, error.message, error, error.status);
  }
  return publicManagedError(
    "KEY_STORAGE_INVALID",
    "The SSH key library operation failed",
    error,
  );
}

function publicManagedError(
  code: string,
  message: string,
  cause?: unknown,
  status = 400,
): ManagedSshError {
  const error = new ManagedSshError(status, code, message);
  if (cause !== undefined) {
    Object.defineProperty(error, "cause", {
      value: cause,
      enumerable: false,
      configurable: false,
    });
  }
  return error;
}
