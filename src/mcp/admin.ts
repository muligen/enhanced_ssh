import { isIP } from "node:net";

import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";

import {
  PERMISSION_PRESETS,
  permissionPresetSelectionSchema,
} from "../shared/operation-presets.js";
import {
  DEFAULT_TARGET_GROUP,
  MAX_TIMEOUT_MS,
  targetAliasSchema,
  targetCheckParamsSchema,
  targetGroupCatalogSchema,
  targetGroupSchema,
  targetIdSchema,
} from "../shared/protocol.js";
import {
  MANAGED_PLATFORMS,
  managedAllowedCommandsSchema,
  managedDescriptionSchema,
  managedFleetTargetSchema,
  managedRemoteRootSchema,
  managedRevisionSchema,
  managedSshKeyGenerationAlgorithmSchema,
  managedSshKeyIdSchema,
  managedSshKeyLabelSchema,
  managedSshKeyRevisionSchema,
  sshHostSchema,
  sshPathSchema,
  sshUsernameSchema,
  type ManagedSshFleetStatus,
  type ManagedSshFleetTarget,
} from "../test-ui/managed.js";
import type { AccessClientSessionSnapshot } from "../test-ui/accessclient-session.js";
import type { McpAdminPolicySnapshot } from "../service/mcp-admin-policy.js";
import { AdminApiError, type AdminClient } from "./admin-client.js";

const DEFAULT_TARGET_TIMEOUT_MS = 60_000;

const mcpEndpointInputSchema = z.strictObject({
  host: sshHostSchema,
  port: z.number().int().min(1).max(65_535).default(22),
  username: sshUsernameSchema,
  keyId: managedSshKeyIdSchema.optional(),
});

const mcpAccessClientInputSchema = z
  .strictObject({
    gatewayHost: sshHostSchema,
    gatewayPort: z.number().int().min(1).max(65_535).default(22),
    gatewayUsername: sshUsernameSchema,
    sharingHost: sshHostSchema.optional(),
    sharingPort: z.number().int().min(1).max(65_535).optional(),
    expectedHostname: z
      .string()
      .min(1)
      .max(255)
      .regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/u)
      .optional(),
  })
  .superRefine((connection, context) => {
    if (
      connection.sharingHost === undefined &&
      connection.sharingPort !== undefined
    ) {
      context.addIssue({
        code: "custom",
        path: ["sharingPort"],
        message: "sharingPort requires sharingHost",
      });
    }
  });

const mcpTargetInputSchema = z.strictObject({
  targetId: targetIdSchema.optional(),
  group: targetGroupSchema.optional(),
  previousAliases: z.array(targetAliasSchema).max(32).optional(),
  description: managedDescriptionSchema.optional(),
  enabled: z.boolean().default(true),
  connectionMode: z
    .enum(["openssh", "accessclient-share", "tailscale-ssh"])
    .default("openssh"),
  target: mcpEndpointInputSchema,
  bastion: mcpEndpointInputSchema.optional(),
  knownHostsFile: sshPathSchema.optional(),
  accessClient: mcpAccessClientInputSchema.optional(),
  platform: z.enum(MANAGED_PLATFORMS),
  policyMode: z.enum(["deny", "presets", "allow-list", "full-access"]),
  allowedCommands: managedAllowedCommandsSchema.optional(),
  permissionPresets: permissionPresetSelectionSchema.shape.presets.optional(),
  logPaths: permissionPresetSelectionSchema.shape.logPaths.optional(),
  logServices: permissionPresetSelectionSchema.shape.logServices.optional(),
  maxTimeoutMs: z
    .number()
    .int()
    .min(1)
    .max(MAX_TIMEOUT_MS)
    .default(DEFAULT_TARGET_TIMEOUT_MS),
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
});

const adminSaveTargetInputSchema = z.strictObject({
  alias: targetAliasSchema.optional(),
  previousAlias: targetAliasSchema.optional(),
  expectedRevision: managedRevisionSchema.optional(),
  target: mcpTargetInputSchema,
  fullAccessConfirmed: z.literal(true).optional(),
  transferAccessConfirmed: z.literal(true).optional(),
});

const adminSetTargetEnabledInputSchema = z.strictObject({
  alias: targetAliasSchema,
  enabled: z.boolean(),
  expectedRevision: managedRevisionSchema,
});

const adminRemoveTargetInputSchema = z.strictObject({
  alias: targetAliasSchema,
  expectedRevision: managedRevisionSchema,
  removeConfirmed: z.literal(true),
});

const adminManageGroupInputSchema = z
  .strictObject({
    action: z.enum(["create", "rename", "delete", "move", "reorder"]),
    name: targetGroupSchema.optional(),
    group: z.union([targetGroupSchema, z.literal("")]).optional(),
    aliases: z
      .array(targetAliasSchema)
      .min(1)
      .max(1_024)
      .refine(
        (aliases) => new Set(aliases).size === aliases.length,
        "aliases must be unique",
      )
      .optional(),
    groups: targetGroupCatalogSchema.optional(),
    expectedRevision: managedRevisionSchema.optional(),
  })
  .superRefine((request, context) => {
    switch (request.action) {
      case "create":
        if (request.name === undefined) {
          context.addIssue({
            code: "custom",
            path: ["name"],
            message: "create requires name",
          });
        }
        if (
          request.group !== undefined ||
          request.aliases !== undefined ||
          request.groups !== undefined
        ) {
          context.addIssue({
            code: "custom",
            message: "create only accepts name and optional expectedRevision",
          });
        }
        return;
      case "rename":
        if (request.group === undefined || request.group === "") {
          context.addIssue({
            code: "custom",
            path: ["group"],
            message: "rename requires a non-empty existing group name",
          });
        }
        if (request.name === undefined) {
          context.addIssue({
            code: "custom",
            path: ["name"],
            message: "rename requires name",
          });
        }
        if (request.aliases !== undefined || request.groups !== undefined) {
          context.addIssue({
            code: "custom",
            message: "rename only accepts group, name, and optional expectedRevision",
          });
        }
        return;
      case "delete":
        if (request.group === undefined || request.group === "") {
          context.addIssue({
            code: "custom",
            path: ["group"],
            message: "delete requires a non-empty existing group name",
          });
        }
        if (
          request.name !== undefined ||
          request.aliases !== undefined ||
          request.groups !== undefined
        ) {
          context.addIssue({
            code: "custom",
            message: "delete only accepts group and optional expectedRevision",
          });
        }
        return;
      case "move":
        if (request.aliases === undefined || request.aliases.length === 0) {
          context.addIssue({
            code: "custom",
            path: ["aliases"],
            message: "move requires at least one machine alias",
          });
        }
        if (request.name !== undefined || request.groups !== undefined) {
          context.addIssue({
            code: "custom",
            message: "move only accepts aliases, optional group, and optional expectedRevision",
          });
        }
        return;
      case "reorder":
        if (request.groups === undefined) {
          context.addIssue({
            code: "custom",
            path: ["groups"],
            message: "reorder requires groups containing every custom group once",
          });
        }
        if (
          request.name !== undefined ||
          request.group !== undefined ||
          request.aliases !== undefined
        ) {
          context.addIssue({
            code: "custom",
            message: "reorder only accepts groups and optional expectedRevision",
          });
        }
    }
  });

const adminGenerateKeyInputSchema = z.strictObject({
  label: managedSshKeyLabelSchema,
  algorithm: managedSshKeyGenerationAlgorithmSchema.default("ed25519"),
  expectedKeyRevision: managedSshKeyRevisionSchema,
});

const adminRenameKeyInputSchema = z.strictObject({
  keyId: managedSshKeyIdSchema,
  label: managedSshKeyLabelSchema,
  expectedKeyRevision: managedSshKeyRevisionSchema,
});

const adminRemoveKeyInputSchema = z.strictObject({
  keyId: managedSshKeyIdSchema,
  expectedKeyRevision: managedSshKeyRevisionSchema,
  removeConfirmed: z.literal(true),
});

const adminLaunchSshInstallInputSchema = z.strictObject({
  host: sshHostSchema,
  port: z.number().int().min(1).max(65_535).default(22),
  username: sshUsernameSchema,
  platform: z.enum(MANAGED_PLATFORMS),
  keyId: managedSshKeyIdSchema,
  knownHostsFile: sshPathSchema.optional(),
});

const adminSaveProviderSettingsInputSchema = z.strictObject({
  provider: z.enum(["tailscale", "accessclient"]),
  executable: sshPathSchema,
  expectedRevision: managedRevisionSchema.optional(),
});

const adminAccessClientSessionInputSchema = z.strictObject({
  action: z.enum(["prepare", "status", "cancel"]),
  alias: targetAliasSchema,
  expectedRevision: managedRevisionSchema,
});

interface AdminBootstrapPayload extends ManagedSshFleetStatus {
  readonly accessClientSession?: AccessClientSessionSnapshot;
  readonly mcpAdmin?: McpAdminPolicySnapshot;
}

function toolResult(value: object): {
  content: [{ type: "text"; text: string }];
  structuredContent: Record<string, unknown>;
} {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    structuredContent: value as Record<string, unknown>,
  };
}

export function deriveAliasFromHost(host: string): string | undefined {
  const family = isIP(host);
  if (family === 4) {
    return targetAliasSchema.safeParse(host).success ? host : undefined;
  }
  if (family === 6) {
    try {
      const canonical = new URL(`http://[${host}]/`).hostname.slice(1, -1);
      const candidate = `ip-${canonical.replaceAll(":", "-")}`;
      return targetAliasSchema.safeParse(candidate).success
        ? candidate
        : undefined;
    } catch {
      return undefined;
    }
  }
  return targetAliasSchema.safeParse(host).success ? host : undefined;
}

function formatZodIssues(error: z.ZodError): string {
  return error.issues
    .map((issue) => {
      const pathLabel = issue.path.length > 0 ? `${issue.path.join(".")}: ` : "";
      return `${pathLabel}${issue.message}`;
    })
    .join("; ");
}

function normalizeTargetForSave(
  input: z.infer<typeof mcpTargetInputSchema>,
  defaultKnownHostsFile: string | undefined,
): ManagedSshFleetTarget {
  const connectionMode = input.connectionMode;
  const knownHostsFile =
    connectionMode === "openssh"
      ? (input.knownHostsFile ?? defaultKnownHostsFile)
      : input.knownHostsFile;

  const common: Record<string, unknown> = {
    ...(input.targetId === undefined ? {} : { targetId: input.targetId }),
    ...(input.group === undefined ? {} : { group: input.group }),
    ...(input.previousAliases === undefined
      ? {}
      : { previousAliases: input.previousAliases }),
    ...(input.description === undefined
      ? {}
      : { description: input.description }),
    enabled: input.enabled,
    connectionMode,
    target: {
      host: input.target.host,
      port: input.target.port,
      username: input.target.username,
      ...(input.target.keyId === undefined ? {} : { keyId: input.target.keyId }),
    },
    ...(input.bastion === undefined
      ? {}
      : {
          bastion: {
            host: input.bastion.host,
            port: input.bastion.port,
            username: input.bastion.username,
            ...(input.bastion.keyId === undefined
              ? {}
              : { keyId: input.bastion.keyId }),
          },
        }),
    ...(knownHostsFile === undefined ? {} : { knownHostsFile }),
    ...(input.accessClient === undefined
      ? {}
      : { accessClient: input.accessClient }),
    platform: input.platform,
    maxTimeoutMs: input.maxTimeoutMs,
    ...(input.transferMode === undefined
      ? {}
      : { transferMode: input.transferMode }),
    ...(input.localRootPath === undefined
      ? {}
      : { localRootPath: input.localRootPath }),
    ...(input.remoteRoots === undefined
      ? {}
      : { remoteRoots: input.remoteRoots }),
    ...(input.maxTransferTimeoutMs === undefined
      ? {}
      : { maxTransferTimeoutMs: input.maxTransferTimeoutMs }),
  };

  let candidate: Record<string, unknown>;
  if (input.policyMode === "allow-list") {
    candidate = {
      ...common,
      policyMode: "allow-list",
      allowedCommands: input.allowedCommands ?? [],
    };
  } else if (input.policyMode === "presets") {
    candidate = {
      ...common,
      policyMode: "presets",
      allowedCommands: input.allowedCommands ?? [],
      permissionPresets: input.permissionPresets ?? [],
      logPaths: input.logPaths ?? [],
      logServices: input.logServices ?? [],
    };
  } else {
    candidate = {
      ...common,
      policyMode: input.policyMode,
      allowedCommands: input.allowedCommands ?? [],
    };
  }

  const parsed = managedFleetTargetSchema.safeParse(candidate);
  if (!parsed.success) {
    throw new AdminApiError(
      400,
      "INVALID_TARGET_CONFIG",
      formatZodIssues(parsed.error),
    );
  }
  const normalized = parsed.data;
  if (
    normalized.policyMode === "full-access" &&
    (normalized.transferMode ?? "deny") === "deny" &&
    (normalized.localRootPath !== undefined ||
      (normalized.remoteRoots ?? []).length !== 0 ||
      normalized.maxTransferTimeoutMs !== undefined)
  ) {
    throw new AdminApiError(
      400,
      "INVALID_TARGET_CONFIG",
      "full-access targets must omit restricted transfer fields (localRootPath, remoteRoots, maxTransferTimeoutMs)",
    );
  }
  if (
    normalized.policyMode === "full-access" &&
    (normalized.transferMode ?? "deny") !== "deny" &&
    (normalized.localRootPath === undefined ||
      (normalized.remoteRoots ?? []).length === 0)
  ) {
    throw new AdminApiError(
      400,
      "INVALID_TARGET_CONFIG",
      "legacy full-access transfer fields require both localRootPath and remoteRoots",
    );
  }
  return normalized;
}

export function registerAdminTools(
  server: McpServer,
  adminClient: AdminClient,
): void {
  server.registerTool(
    "ssh_admin_get_config",
    {
      description:
        "Inspect whether the local SSH management service is running and whether MCP configuration management is enabled. When enabled, returns the sanitized management state: current revision, keyRevision, defaultKnownHostsFile, custom groups, managed SSH keys (metadata and public keys only, never private keys), all configured machines, global Tailscale/Plink paths, AccessClient session status, command presets, and permission preset definitions. Call this first before onboarding or modifying machines so you can ask the user any undecided details and pass optimistic concurrency revisions.",
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    async (context) => {
      context.mcpReq.signal.throwIfAborted();
      const controlPlane = await adminClient.status(context.mcpReq.signal);
      if (!controlPlane.serviceRunning) {
        return toolResult({
          serviceRunning: false,
          mcpAdminEnabled: false,
          message:
            "SSH management service is not running. Ask the administrator to start agent-ssh-service.",
        });
      }
      if (!controlPlane.mcpAdminSupported) {
        return toolResult({
          serviceRunning: true,
          mcpAdminEnabled: false,
          message:
            "The running SSH management service does not support MCP administration. Restart agent-ssh-service to enable MCP management support.",
        });
      }
      if (!controlPlane.mcpAdminEnabled) {
        return toolResult({
          serviceRunning: true,
          mcpAdminEnabled: false,
          mcpAdminSource: controlPlane.policy.source,
          message:
            "MCP configuration management is currently disabled. Ask the administrator to enable '允许 MCP 管理机器与配置' in the local Web Management Center (Settings -> MCP 管理权限) or start agent-ssh-service with --allow-mcp-admin. You can call ssh_open_admin to open the management center.",
        });
      }

      const bootstrap = await adminClient.post<AdminBootstrapPayload>(
        "/api/admin/bootstrap",
        {},
        context.mcpReq.signal,
      );
      return toolResult({
        serviceRunning: true,
        mcpAdminEnabled: true,
        mcpAdminSource: bootstrap.mcpAdmin?.source ?? controlPlane.policy.source,
        state: bootstrap.state,
        configured: bootstrap.configured,
        revision: bootstrap.revision ?? null,
        keyRevision: bootstrap.keyRevision,
        defaultKnownHostsFile: bootstrap.defaultKnownHostsFile,
        defaultGroup: DEFAULT_TARGET_GROUP,
        groups: bootstrap.profile?.groups ?? [],
        keys: bootstrap.keys,
        targets: bootstrap.profile?.targets ?? {},
        ...(bootstrap.profile?.tailscale === undefined
          ? {}
          : { tailscale: bootstrap.profile.tailscale }),
        ...(bootstrap.profile?.accessClient === undefined
          ? {}
          : { accessClient: bootstrap.profile.accessClient }),
        ...(bootstrap.accessClientSession === undefined
          ? {}
          : { accessClientSession: bootstrap.accessClientSession }),
        commandPresets: bootstrap.commandPresets,
        permissionPresets: PERMISSION_PRESETS,
        ...(bootstrap.error === undefined ? {} : { error: bootstrap.error }),
        ...(bootstrap.keyError === undefined
          ? {}
          : { keyError: bootstrap.keyError }),
      });
    },
  );

  server.registerTool(
    "ssh_admin_save_target",
    {
      description:
        "Add a new machine or update/rename an existing machine in the SSH management center. Call ssh_admin_get_config first to obtain revision, keyIds, groups, and defaultKnownHostsFile. Ask the user for any undecided details before saving. To add a machine, omit previousAlias (alias is optional and defaults from target.host if omitted). To edit or rename an existing machine, set previousAlias to its current alias (alias defaults to previousAlias if omitted). Requires expectedRevision whenever a revision already exists. SAFETY CONFIRMATION REQUIRED: before setting policyMode='full-access', you MUST ask the user to explicitly confirm full-access (unrestricted commands and file transfer) and pass fullAccessConfirmed=true; before enabling file transfer (transferMode != 'deny') on an allow-list target, you MUST ask the user to explicitly confirm and pass transferAccessConfirmed=true. For OpenSSH targets, knownHostsFile defaults to defaultKnownHostsFile if omitted; host keys must already be present in knownHostsFile and the public key installed on the remote machine before saving.",
      inputSchema: adminSaveTargetInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
      },
    },
    async (args, context) => {
      context.mcpReq.signal.throwIfAborted();
      if (
        args.target.policyMode === "full-access" &&
        args.fullAccessConfirmed !== true
      ) {
        throw new AdminApiError(
          400,
          "CONFIRMATION_REQUIRED",
          "Configuring policyMode='full-access' requires explicit user confirmation. Confirm unrestricted command and file-transfer access with the user, then retry with fullAccessConfirmed: true.",
        );
      }
      if (
        args.target.policyMode !== "full-access" &&
        (args.target.transferMode ?? "deny") !== "deny" &&
        args.transferAccessConfirmed !== true
      ) {
        throw new AdminApiError(
          400,
          "CONFIRMATION_REQUIRED",
          "Enabling file transfer requires explicit user confirmation. Confirm transfer direction and allowed roots with the user, then retry with transferAccessConfirmed: true.",
        );
      }

      const resolvedAlias =
        args.alias ??
        args.previousAlias ??
        deriveAliasFromHost(args.target.target.host);
      if (resolvedAlias === undefined) {
        throw new AdminApiError(
          400,
          "INVALID_ALIAS",
          "Could not derive a valid target alias from target.host; provide an explicit alias.",
        );
      }

      let defaultKnownHostsFile: string | undefined;
      if (
        args.target.connectionMode === "openssh" &&
        args.target.knownHostsFile === undefined
      ) {
        const bootstrap = await adminClient.post<AdminBootstrapPayload>(
          "/api/admin/bootstrap",
          {},
          context.mcpReq.signal,
        );
        defaultKnownHostsFile = bootstrap.defaultKnownHostsFile;
      }

      const target = normalizeTargetForSave(args.target, defaultKnownHostsFile);
      const status = await adminClient.post<ManagedSshFleetStatus>(
        "/api/admin/target/save",
        {
          alias: resolvedAlias,
          ...(args.previousAlias === undefined
            ? {}
            : { previousAlias: args.previousAlias }),
          ...(args.expectedRevision === undefined
            ? {}
            : { expectedRevision: args.expectedRevision }),
          target,
          ...(args.fullAccessConfirmed === true
            ? { fullAccessConfirmed: true }
            : {}),
          ...(args.transferAccessConfirmed === true
            ? { transferAccessConfirmed: true }
            : {}),
        },
        context.mcpReq.signal,
      );
      const savedTarget = status.profile?.targets[resolvedAlias];
      return toolResult({
        alias: resolvedAlias,
        ...(savedTarget?.targetId === undefined
          ? {}
          : { targetId: savedTarget.targetId }),
        revision: status.revision ?? null,
        status,
      });
    },
  );

  server.registerTool(
    "ssh_admin_set_target_enabled",
    {
      description:
        "Enable or disable MCP access for an existing machine without changing its connection or permission settings. Requires expectedRevision from ssh_admin_get_config.",
      inputSchema: adminSetTargetEnabledInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
      },
    },
    async (args, context) => {
      context.mcpReq.signal.throwIfAborted();
      const status = await adminClient.post<ManagedSshFleetStatus>(
        "/api/admin/target/enabled",
        args,
        context.mcpReq.signal,
      );
      return toolResult({
        alias: args.alias,
        enabled: args.enabled,
        revision: status.revision ?? null,
        status,
      });
    },
  );

  server.registerTool(
    "ssh_admin_remove_target",
    {
      description:
        "Remove a machine from the SSH management center and revoke its access. DESTRUCTIVE: you MUST explicitly confirm with the user which machine will be deleted before setting removeConfirmed=true. Requires expectedRevision from ssh_admin_get_config.",
      inputSchema: adminRemoveTargetInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
      },
    },
    async (args, context) => {
      context.mcpReq.signal.throwIfAborted();
      const status = await adminClient.post<ManagedSshFleetStatus>(
        "/api/admin/target/remove",
        args,
        context.mcpReq.signal,
      );
      return toolResult({
        removedAlias: args.alias,
        revision: status.revision ?? null,
        status,
      });
    },
  );

  server.registerTool(
    "ssh_admin_check_target",
    {
      description:
        "Check connectivity to a saved machine through the management center. Unlike ssh_check_connection, this endpoint also automatically learns and saves expectedHostname on AccessClient targets on the first successful check.",
      inputSchema: targetCheckParamsSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async (args, context) => {
      context.mcpReq.signal.throwIfAborted();
      const result = await adminClient.post<Record<string, unknown>>(
        "/api/admin/target/check",
        args,
        context.mcpReq.signal,
      );
      return toolResult(result);
    },
  );

  server.registerTool(
    "ssh_admin_manage_group",
    {
      description:
        "Create, rename, delete, reorder machine groups, or move machines between groups. Group changes use the lightweight metadata overlay and do not disrupt active SSH sessions. Deleting a group moves its machines back to '默认分组' without deleting any machines. Pass expectedRevision from ssh_admin_get_config whenever a revision exists.",
      inputSchema: adminManageGroupInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
      },
    },
    async (args, context) => {
      context.mcpReq.signal.throwIfAborted();
      let body: Record<string, unknown>;
      switch (args.action) {
        case "create":
          body = { name: args.name };
          break;
        case "rename":
          body = { group: args.group, name: args.name };
          break;
        case "delete":
          body = { group: args.group };
          break;
        case "move":
          body = {
            aliases: args.aliases,
            ...(args.group === undefined ? {} : { group: args.group }),
          };
          break;
        case "reorder":
          body = { groups: args.groups };
          break;
      }
      if (args.expectedRevision !== undefined) {
        body.expectedRevision = args.expectedRevision;
      }
      const status = await adminClient.post<ManagedSshFleetStatus>(
        `/api/admin/group/${args.action}`,
        body,
        context.mcpReq.signal,
      );
      return toolResult({
        action: args.action,
        revision: status.revision ?? null,
        groups: status.profile?.groups ?? [],
        status,
      });
    },
  );

  server.registerTool(
    "ssh_admin_generate_key",
    {
      description:
        "Generate a new Ed25519 (default) or RSA-3072 SSH keypair in the local managed key vault. Returns the new keyId, fingerprint, and publicKey only; private key material is never returned to MCP. Requires expectedKeyRevision from ssh_admin_get_config. Note: importing arbitrary local private key files from disk is restricted to the local Web Management Center.",
      inputSchema: adminGenerateKeyInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
      },
    },
    async (args, context) => {
      context.mcpReq.signal.throwIfAborted();
      const status = await adminClient.post<ManagedSshFleetStatus>(
        "/api/admin/key/generate",
        args,
        context.mcpReq.signal,
      );
      const generatedKey = status.keys.find(
        (key) => key.label === args.label,
      );
      return toolResult({
        ...(generatedKey === undefined ? {} : { generatedKey }),
        keyRevision: status.keyRevision,
        keys: status.keys,
      });
    },
  );

  server.registerTool(
    "ssh_admin_rename_key",
    {
      description:
        "Rename the display label of a managed SSH key. Requires expectedKeyRevision from ssh_admin_get_config.",
      inputSchema: adminRenameKeyInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
      },
    },
    async (args, context) => {
      context.mcpReq.signal.throwIfAborted();
      const status = await adminClient.post<ManagedSshFleetStatus>(
        "/api/admin/key/rename",
        args,
        context.mcpReq.signal,
      );
      return toolResult({
        keyId: args.keyId,
        label: args.label,
        keyRevision: status.keyRevision,
        keys: status.keys,
      });
    },
  );

  server.registerTool(
    "ssh_admin_remove_key",
    {
      description:
        "Remove an unused managed SSH key from the key vault. Keys referenced by current or retained rollback revisions cannot be deleted (KEY_IN_USE). DESTRUCTIVE: you MUST explicitly confirm with the user before setting removeConfirmed=true. Requires expectedKeyRevision from ssh_admin_get_config.",
      inputSchema: adminRemoveKeyInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
      },
    },
    async (args, context) => {
      context.mcpReq.signal.throwIfAborted();
      const status = await adminClient.post<ManagedSshFleetStatus>(
        "/api/admin/key/remove",
        args,
        context.mcpReq.signal,
      );
      return toolResult({
        removedKeyId: args.keyId,
        keyRevision: status.keyRevision,
        keys: status.keys,
      });
    },
  );

  server.registerTool(
    "ssh_admin_launch_ssh_install",
    {
      description:
        "Open a local interactive terminal on the gateway host so the user can authenticate once to install a managed SSH public key into the remote account's authorized_keys (uses StrictHostKeyChecking=yes against knownHostsFile; the remote host key must already be trusted in knownHostsFile). Neither MCP nor the gateway ever sees or stores passwords. Ask the user to complete authentication in the opened terminal before saving the OpenSSH machine.",
      inputSchema: adminLaunchSshInstallInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async (args, context) => {
      context.mcpReq.signal.throwIfAborted();
      let knownHostsFile = args.knownHostsFile;
      if (knownHostsFile === undefined) {
        const bootstrap = await adminClient.post<AdminBootstrapPayload>(
          "/api/admin/bootstrap",
          {},
          context.mcpReq.signal,
        );
        knownHostsFile = bootstrap.defaultKnownHostsFile;
      }
      const result = await adminClient.post<{
        readonly started: boolean;
        readonly platform: string;
      }>(
        "/api/admin/ssh/install",
        {
          target: {
            enabled: false,
            connectionMode: "openssh",
            platform: args.platform,
            target: {
              host: args.host,
              port: args.port,
              username: args.username,
              keyId: args.keyId,
            },
            knownHostsFile,
            policyMode: "deny",
            allowedCommands: [],
            maxTimeoutMs: DEFAULT_TARGET_TIMEOUT_MS,
          },
        },
        context.mcpReq.signal,
      );
      return toolResult({
        ...result,
        knownHostsFile,
        note: "An interactive terminal was opened on the local host. Ask the user to complete remote password authentication in that terminal, then save the target with ssh_admin_save_target and verify with ssh_admin_check_target.",
      });
    },
  );

  server.registerTool(
    "ssh_admin_save_provider_settings",
    {
      description:
        "Save the global local executable path for Tailscale SSH ('tailscale', e.g. C:\\Program Files\\Tailscale\\tailscale.exe) or AccessClient/PuTTY ('accessclient', e.g. G:\\PuTTY\\plink.exe). Pass expectedRevision from ssh_admin_get_config whenever a revision exists.",
      inputSchema: adminSaveProviderSettingsInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
      },
    },
    async (args, context) => {
      context.mcpReq.signal.throwIfAborted();
      const route =
        args.provider === "tailscale"
          ? "/api/admin/tailscale/save"
          : "/api/admin/access-client/save";
      const body =
        args.provider === "tailscale"
          ? {
              executable: args.executable,
              ...(args.expectedRevision === undefined
                ? {}
                : { expectedRevision: args.expectedRevision }),
            }
          : {
              plinkExecutable: args.executable,
              ...(args.expectedRevision === undefined
                ? {}
                : { expectedRevision: args.expectedRevision }),
            };
      const status = await adminClient.post<ManagedSshFleetStatus>(
        route,
        body,
        context.mcpReq.signal,
      );
      return toolResult({
        provider: args.provider,
        revision: status.revision ?? null,
        ...(status.profile?.tailscale === undefined
          ? {}
          : { tailscale: status.profile.tailscale }),
        ...(status.profile?.accessClient === undefined
          ? {}
          : { accessClient: status.profile.accessClient }),
        status,
      });
    },
  );

  server.registerTool(
    "ssh_admin_accessclient_session",
    {
      description:
        "Prepare, poll status, or cancel an AccessClient PuTTY shared-session handshake for a saved AccessClient machine (Windows only). Call action='prepare' to arm PuTTY LogHost capture, ask the user to log into the target in AccessClient, then poll action='status' until ready (which also verifies and learns expectedHostname). Call action='cancel' to abort preparation.",
      inputSchema: adminAccessClientSessionInputSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async (args, context) => {
      context.mcpReq.signal.throwIfAborted();
      const result = await adminClient.post<Record<string, unknown>>(
        `/api/admin/access-client/session/${args.action}`,
        {
          alias: args.alias,
          expectedRevision: args.expectedRevision,
        },
        context.mcpReq.signal,
      );
      return toolResult(result);
    },
  );
}
