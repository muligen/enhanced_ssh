import { lstat, readFile } from "node:fs/promises";
import { isIP } from "node:net";
import path from "node:path";

import { parseDocument } from "yaml";
import { z } from "zod";

import { GATEWAY_ERROR_CODES, GatewayError } from "../shared/errors.js";
import {
  MAX_COMMAND_BYTES,
  MAX_RPC_FRAME_BYTES,
  MAX_TIMEOUT_MS,
  targetAliasSchema,
  targetIdSchema,
  targetPlatformSchema,
} from "../shared/protocol.js";

const MIN_INLINE_OUTPUT_BYTES = 1_024;
// Historical managed revisions used 64 KiB and must remain loadable. The
// output store applies the current 8 KiB hard ceiling before RPC exposure.
const MAX_INLINE_OUTPUT_BYTES = 65_536;
const MAX_STORED_OUTPUT_BYTES = 1_073_741_824;
const MAX_TOTAL_RETAINED_OUTPUT_BYTES = 10_737_418_240;
const MIN_AUDIT_BYTES = 1_048_576;
const MAX_AUDIT_BYTES = 10_737_418_240;
const MAX_CONFIG_BYTES = MAX_RPC_FRAME_BYTES * 4;
const MIN_OUTPUT_TTL_SECONDS = 60;
const MAX_OUTPUT_TTL_SECONDS = 86_400;
const MAX_CONCURRENT_EXECUTIONS = 32;
const MAX_RETAINED_OUTPUTS = 10_000;
const MAX_TARGETS = 1_024;
const MAX_ALLOWED_COMMANDS = 128;
const MAX_TRANSFER_ROOTS = 32;
const MAX_TRANSFER_FILES = 100_000;
const MAX_TRANSFER_BYTES = 1_099_511_627_776;

function isAbsolutePath(value: string): boolean {
  return (
    !/[\u0000-\u001f\u007f]/u.test(value) &&
    (path.isAbsolute(value) || path.win32.isAbsolute(value))
  );
}

function isFilesystemRoot(value: string): boolean {
  const nativeResolved = path.resolve(value);
  const windowsResolved = path.win32.resolve(value);
  return (
    nativeResolved === path.parse(nativeResolved).root ||
    windowsResolved === path.win32.parse(windowsResolved).root
  );
}

function isDirectFilesystemAbsolutePath(value: string): boolean {
  return (
    isAbsolutePath(value) &&
    !value.startsWith("\\\\") &&
    !value.startsWith("//") &&
    !value.startsWith("\\??\\")
  );
}

const absolutePathSchema = z
  .string()
  .min(1)
  .max(32_767)
  .refine(isAbsolutePath, "must be an absolute path without control characters");

const openSshConfigurationPathSchema = absolutePathSchema.refine(
  (value) => !value.includes("$"),
  "must not contain $ because OpenSSH expands environment variables in configuration paths",
);

const dataDirectorySchema = absolutePathSchema.refine(
  (value) => !isFilesystemRoot(value),
  "must not be a filesystem root",
);

const transferRootPathSchema = absolutePathSchema.refine(
  isDirectFilesystemAbsolutePath,
  "must not use UNC, network, or device path syntax",
);

const maxTimeoutSchema = z.number().int().min(1).max(MAX_TIMEOUT_MS);

const sshHostSchema = z
  .string()
  .min(1)
  .max(253)
  .refine(
    (value) =>
      isIP(value) !== 0 ||
      (/^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/u.test(value) &&
        !value.includes("..")),
    "must be an IPv4, IPv6, or DNS host name",
  );

const puttyUsernameSchema = z
  .string()
  .min(1)
  .max(128)
  .refine(
    (value) => !/[\u0000-\u001f\u007f]/u.test(value),
    "must not contain control characters",
  );

const expectedHostnameSchema = z
  .string()
  .min(1)
  .max(255)
  .regex(
    /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/u,
    "must be a stable remote hostname",
  );

export const accessClientShareConnectionSchema = z.strictObject({
  mode: z.literal("accessclient-share"),
  gatewayHost: sshHostSchema,
  gatewayPort: z.number().int().min(1).max(65_535),
  gatewayUsername: puttyUsernameSchema,
  sharingHost: sshHostSchema.optional(),
  sharingPort: z.number().int().min(1).max(65_535).optional(),
  expectedHostname: expectedHostnameSchema.optional(),
}).superRefine((connection, context) => {
  if (connection.sharingHost === undefined && connection.sharingPort !== undefined) {
    context.addIssue({
      code: "custom",
      path: ["sharingPort"],
      message: "requires sharingHost",
    });
  }
});

export const tailscaleSshConnectionSchema = z.strictObject({
  mode: z.literal("tailscale-ssh"),
  host: sshHostSchema,
  username: z.string().min(1).max(128).regex(/^[A-Za-z_][A-Za-z0-9._-]*[$]?$/u),
});

const allowedCommandSchema = z
  .string()
  .min(1)
  .max(MAX_COMMAND_BYTES)
  .refine((value) => value.trim().length > 0, "must not be blank")
  .refine(
    (value) => !/[\0\r\n]/u.test(value),
    "must not contain NUL bytes or newlines",
  )
  .refine(
    (value) => Buffer.byteLength(value, "utf8") <= MAX_COMMAND_BYTES,
    `must not exceed ${MAX_COMMAND_BYTES} UTF-8 bytes`,
  );

export const allowListPolicySchema = z.strictObject({
  mode: z.literal("allow-list"),
  allowedCommands: z
    .array(allowedCommandSchema)
    .min(1)
    .max(MAX_ALLOWED_COMMANDS)
    .superRefine((commands, context) => {
      if (new Set(commands).size !== commands.length) {
        context.addIssue({
          code: "custom",
          message: "must not contain duplicate commands",
        });
      }
    }),
  maxTimeoutMs: maxTimeoutSchema,
});

export const denyPolicySchema = z.strictObject({
  mode: z.literal("deny"),
  maxTimeoutMs: maxTimeoutSchema,
});

export const fullAccessPolicySchema = z.strictObject({
  mode: z.literal("full-access"),
  maxTimeoutMs: maxTimeoutSchema,
});

export const targetPolicySchema = z.discriminatedUnion("mode", [
  allowListPolicySchema,
  fullAccessPolicySchema,
  denyPolicySchema,
]);

export const transferPolicySchema = z.strictObject({
  mode: z.enum(["deny", "upload", "download", "bidirectional"]).default("deny"),
  localRoots: z
    .array(targetAliasSchema)
    .max(MAX_TRANSFER_ROOTS)
    .default([]),
  remoteRoots: z
    .array(
      z
        .string()
        .min(1)
        .max(8_192)
        .refine(
          (value) => !/[\u0000\r\n]/u.test(value),
          "must not contain NUL, CR, or LF characters",
        ),
    )
    .max(MAX_TRANSFER_ROOTS)
    .default([]),
  maxFileBytes: z
    .number()
    .int()
    .safe()
    .min(1)
    .max(MAX_TRANSFER_BYTES)
    .default(10_737_418_240),
  maxTotalBytes: z
    .number()
    .int()
    .safe()
    .min(1)
    .max(MAX_TRANSFER_BYTES)
    .default(107_374_182_400),
  maxFiles: z.number().int().min(1).max(MAX_TRANSFER_FILES).default(10_000),
  maxTimeoutMs: maxTimeoutSchema.default(MAX_TIMEOUT_MS),
});

export const targetConfigSchema = z.strictObject({
  targetId: targetIdSchema.optional(),
  previousAliases: z
    .array(targetAliasSchema)
    .max(32)
    .superRefine((aliases, context) => {
      const folded = new Set<string>();
      for (const [index, alias] of aliases.entries()) {
        const key = alias.toLowerCase();
        if (folded.has(key)) {
          context.addIssue({
            code: "custom",
            path: [index],
            message: "must not contain duplicate aliases",
          });
        }
        folded.add(key);
      }
    })
    .optional(),
  description: z
    .string()
    .min(1)
    .max(256)
    .refine(
      (value) => !/[\u0000-\u001f\u007f]/u.test(value),
      "must not contain control characters",
    )
    .optional(),
  sshAlias: targetAliasSchema,
  connection: z.union([accessClientShareConnectionSchema, tailscaleSshConnectionSchema]).optional(),
  platform: targetPlatformSchema.default("linux"),
  enabled: z.boolean(),
  policy: targetPolicySchema,
  transfer: transferPolicySchema.default({
    mode: "deny",
    localRoots: [],
    remoteRoots: [],
    maxFileBytes: 10_737_418_240,
    maxTotalBytes: 107_374_182_400,
    maxFiles: 10_000,
    maxTimeoutMs: MAX_TIMEOUT_MS,
  }),
});

const targetsSchema = z
  .record(targetAliasSchema, targetConfigSchema)
  .superRefine((targets, context) => {
    const count = Object.keys(targets).length;
    if (count > MAX_TARGETS) {
      context.addIssue({
        code: "custom",
        message: `must contain at most ${MAX_TARGETS} targets`,
      });
    }
    const references = new Map<string, string>();
    const sshAliases = new Map<string, string>();
    const puttyShares = new Map<string, string>();
    for (const [alias, target] of Object.entries(targets)) {
      const foldedSshAlias = target.sshAlias.toLowerCase();
      const sshAliasOwner = sshAliases.get(foldedSshAlias);
      if (sshAliasOwner !== undefined) {
        context.addIssue({
          code: "custom",
          path: [alias, "sshAlias"],
          message: `conflicts with the internal SSH alias owned by ${sshAliasOwner}`,
        });
      } else {
        sshAliases.set(foldedSshAlias, alias);
      }
      if (target.connection?.mode === "accessclient-share") {
        const connection = target.connection;
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
            path: [alias, "connection", "sharingHost"],
            message: `conflicts with the PuTTY shared identity owned by ${owner}`,
          });
        } else {
          puttyShares.set(sharingIdentity, alias);
        }
      }
      const identifiers = [
        alias,
        ...(target.targetId === undefined ? [] : [target.targetId]),
        ...(target.previousAliases ?? []),
      ];
      for (const [index, identifier] of identifiers.entries()) {
        const folded = identifier.toLowerCase();
        const owner = references.get(folded);
        if (owner !== undefined) {
          context.addIssue({
            code: "custom",
            path:
              index === 0
                ? [alias]
                : index === 1 && target.targetId !== undefined
                  ? [alias, "targetId"]
                  : [
                      alias,
                      "previousAliases",
                      index - (target.targetId === undefined ? 1 : 2),
                    ],
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

export const gatewayConfigSchema = z
  .strictObject({
    version: z.literal(1),
    runtime: z.strictObject({
      dataDirectory: dataDirectorySchema,
      inlineOutputBytes: z
        .number()
        .int()
        .min(MIN_INLINE_OUTPUT_BYTES)
        .max(MAX_INLINE_OUTPUT_BYTES),
      maxStoredOutputBytes: z
        .number()
        .int()
        .min(MIN_INLINE_OUTPUT_BYTES)
        .max(MAX_STORED_OUTPUT_BYTES),
      maxTotalRetainedOutputBytes: z
        .number()
        .int()
        .min(MIN_INLINE_OUTPUT_BYTES)
        .max(MAX_TOTAL_RETAINED_OUTPUT_BYTES),
      maxAuditBytes: z
        .number()
        .int()
        .min(MIN_AUDIT_BYTES)
        .max(MAX_AUDIT_BYTES),
      maxRetainedOutputs: z
        .number()
        .int()
        .min(1)
        .max(MAX_RETAINED_OUTPUTS),
      outputTtlSeconds: z
        .number()
        .int()
        .min(MIN_OUTPUT_TTL_SECONDS)
        .max(MAX_OUTPUT_TTL_SECONDS),
      maxConcurrentExecutions: z
        .number()
        .int()
        .min(1)
        .max(MAX_CONCURRENT_EXECUTIONS),
    }),
    ssh: z.strictObject({
      executable: absolutePathSchema,
      sftpExecutable: absolutePathSchema.optional(),
      configFile: openSshConfigurationPathSchema,
      knownHostsFile: openSshConfigurationPathSchema,
      connectTimeoutSeconds: z.number().int().min(1).max(120),
    }),
    tailscale: z.strictObject({ executable: absolutePathSchema }).optional(),
    putty: z
      .strictObject({
        executable: absolutePathSchema,
      })
      .optional(),
    transfer: z
      .strictObject({
        localRoots: z
          .record(targetAliasSchema, transferRootPathSchema)
          .refine(
            (roots) => Object.keys(roots).length <= MAX_TRANSFER_ROOTS,
            `must contain at most ${MAX_TRANSFER_ROOTS} local roots`,
          )
          .default({}),
      })
      .default({ localRoots: {} }),
    targets: targetsSchema,
  })
  .superRefine((config, context) => {
    if (config.runtime.inlineOutputBytes > config.runtime.maxStoredOutputBytes) {
      context.addIssue({
        code: "custom",
        path: ["runtime", "inlineOutputBytes"],
        message: "must not exceed runtime.maxStoredOutputBytes",
      });
    }
    if (
      config.runtime.maxStoredOutputBytes >
      config.runtime.maxTotalRetainedOutputBytes
    ) {
      context.addIssue({
        code: "custom",
        path: ["runtime", "maxStoredOutputBytes"],
        message: "must not exceed runtime.maxTotalRetainedOutputBytes",
      });
    }
    if (
      config.runtime.maxRetainedOutputs <
      config.runtime.maxConcurrentExecutions
    ) {
      context.addIssue({
        code: "custom",
        path: ["runtime", "maxRetainedOutputs"],
        message: "must be at least runtime.maxConcurrentExecutions",
      });
    }
    for (const [alias, target] of Object.entries(config.targets)) {
      if (target.connection?.mode === "tailscale-ssh") {
        if (config.tailscale === undefined || target.platform === "windows" || target.transfer.mode !== "deny") {
          context.addIssue({ code: "custom", path: ["targets", alias, "connection"], message: "Tailscale SSH requires tailscale.executable, a Linux/macOS target, and disabled file transfer" });
        }
      }
      if (target.connection?.mode === "accessclient-share" && config.putty === undefined) {
        context.addIssue({
          code: "custom",
          path: ["targets", alias, "connection"],
          message: "requires putty.executable",
        });
      }
      if (
        target.connection?.mode === "accessclient-share" &&
        target.transfer.mode !== "deny"
      ) {
        context.addIssue({
          code: "custom",
          path: ["targets", alias, "transfer", "mode"],
          message: "must be deny for AccessClient shared targets",
        });
      }
      if (target.transfer.maxFileBytes > target.transfer.maxTotalBytes) {
        context.addIssue({
          code: "custom",
          path: ["targets", alias, "transfer", "maxFileBytes"],
          message: "must not exceed maxTotalBytes",
        });
      }
      for (const root of target.transfer.localRoots) {
        if (!Object.hasOwn(config.transfer.localRoots, root)) {
          context.addIssue({
            code: "custom",
            path: ["targets", alias, "transfer", "localRoots"],
            message: `references unknown local root ${root}`,
          });
        }
      }
      if (
        target.transfer.mode !== "deny" &&
        (target.transfer.localRoots.length === 0 ||
          target.transfer.remoteRoots.length === 0)
      ) {
        context.addIssue({
          code: "custom",
          path: ["targets", alias, "transfer"],
          message: "enabled transfer policies require localRoots and remoteRoots",
        });
      }
    }
  });

type DeepReadonly<Value> = Value extends (...args: never[]) => unknown
  ? Value
  : Value extends readonly (infer Item)[]
    ? readonly DeepReadonly<Item>[]
    : Value extends object
      ? { readonly [Key in keyof Value]: DeepReadonly<Value[Key]> }
      : Value;

type ParsedGatewayConfig = z.infer<typeof gatewayConfigSchema>;
export type GatewayConfig = DeepReadonly<ParsedGatewayConfig>;
export type TargetConfig = DeepReadonly<z.infer<typeof targetConfigSchema>>;
export type TargetPolicyConfig = DeepReadonly<z.infer<typeof targetPolicySchema>>;
export type TransferPolicyConfig = DeepReadonly<
  z.infer<typeof transferPolicySchema>
>;

function deepFreeze<Value>(value: Value): DeepReadonly<Value> {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) {
      deepFreeze(child);
    }
    Object.freeze(value);
  }
  return value as DeepReadonly<Value>;
}

function configError(message: string, cause?: unknown): GatewayError {
  return new GatewayError(
    GATEWAY_ERROR_CODES.configInvalid,
    `Invalid gateway configuration: ${message}`,
    cause === undefined ? {} : { cause },
  );
}

function formatZodIssues(error: z.ZodError): string {
  return error.issues
    .slice(0, 8)
    .map((issue) => {
      const issuePath = issue.path.length === 0 ? "configuration" : issue.path.join(".");
      return `${issuePath}: ${issue.message}`;
    })
    .join("; ");
}

export function parseConfigText(source: string): GatewayConfig {
  if (Buffer.byteLength(source, "utf8") > MAX_CONFIG_BYTES) {
    throw configError("file is too large");
  }

  let rawConfig: unknown;
  try {
    const document = parseDocument(source, {
      schema: "core",
      strict: true,
      uniqueKeys: true,
      merge: false,
      prettyErrors: false,
    });

    if (document.errors.length > 0) {
      throw document.errors[0];
    }
    if (document.warnings.length > 0) {
      throw document.warnings[0];
    }

    // Configuration aliases add no value here and make size/accounting less
    // obvious, so fail closed on every alias reference.
    rawConfig = document.toJS({ maxAliasCount: 0 });
  } catch (error) {
    throw configError("YAML could not be parsed", error);
  }

  const result = gatewayConfigSchema.safeParse(rawConfig);
  if (!result.success) {
    throw configError(formatZodIssues(result.error), result.error);
  }

  return deepFreeze(result.data);
}

export async function loadConfig(configPath: string): Promise<GatewayConfig> {
  try {
    const fileStats = await lstat(configPath);
    if (!fileStats.isFile() || fileStats.isSymbolicLink()) {
      throw configError("path must refer directly to a regular file");
    }
    if (fileStats.size > MAX_CONFIG_BYTES) {
      throw configError("file is too large");
    }
    const source = await readFile(configPath, "utf8");
    return parseConfigText(source);
  } catch (error) {
    if (error instanceof GatewayError) {
      throw error;
    }
    throw configError("file could not be read", error);
  }
}
