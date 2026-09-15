import { z } from "zod";
import { operationRequestSchema } from "./operation-presets.js";

import type { GatewayErrorCode } from "./errors.js";

export const PROTOCOL_VERSION = 8 as const;
export const MAX_RPC_FRAME_BYTES = 1_048_576;
export const MAX_COMMAND_BYTES = 65_536;
export const MAX_TIMEOUT_MS = 3_600_000;
export const MAX_OUTPUT_READ_BYTES = 65_536;
export const MAX_INLINE_PREVIEW_BYTES = 8_192;
export const MAX_TARGET_CHECK_HOSTNAME_LENGTH = 255;
export const MAX_ENVIRONMENT_ENTRIES = 64;
export const MAX_TRANSFER_EXCLUDES = 128;
export const MAX_DOCKER_PREFLIGHT_PORTS = 64;
export const MAX_TASK_TAIL_BYTES = 65_536;

export const TARGET_ALIAS_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
export const TARGET_ID_PATTERN = /^t-[a-f0-9]{32}$/;

export const rpcIdSchema = z.union([
  z.string().min(1).max(128),
  z.number().int().safe(),
]);
export type RpcId = z.infer<typeof rpcIdSchema>;

export const targetAliasSchema = z
  .string()
  .regex(
    TARGET_ALIAS_PATTERN,
    "must start with an alphanumeric character and contain only alphanumerics, dot, underscore, or hyphen",
  );

export const targetIdSchema = z
  .string()
  .regex(TARGET_ID_PATTERN, "must be an opaque target ID");

export const targetGroupSchema = z
  .string()
  .refine(
    (value) => !/[\u0000-\u001f\u007f]/u.test(value),
    "must not contain control characters",
  )
  .trim()
  .min(1)
  .max(64);

export const targetPlatformSchema = z.enum(["windows", "linux", "macos"]);
export const DEFAULT_TARGET_GROUP = "默认分组";
export const targetGroupCatalogSchema = z.array(
  targetGroupSchema.refine((name) => name !== DEFAULT_TARGET_GROUP, "The default group is reserved"),
).max(1_024).refine((groups) => new Set(groups).size === groups.length, "Group names must be unique");
export type TargetPlatform = z.infer<typeof targetPlatformSchema>;
export const targetConnectionModeSchema = z.enum([
  "openssh",
  "accessclient-share",
  "tailscale-ssh",
]);
export type TargetConnectionMode = z.infer<
  typeof targetConnectionModeSchema
>;

const emptyParamsSchema = z.strictObject({});

export const sessionOpenParamsSchema = z.strictObject({
  token: z.base64url().min(32).max(256),
  protocolVersion: z.literal(PROTOCOL_VERSION),
  client: z.strictObject({
    name: z.string().min(1).max(64),
    version: z.string().min(1).max(64),
    pid: z.number().int().positive().optional(),
  }),
});
export type SessionOpenParams = z.infer<typeof sessionOpenParamsSchema>;

export const sessionOpenResultSchema = z.strictObject({
  protocolVersion: z.literal(PROTOCOL_VERSION),
  serverVersion: z.string().min(1).max(64),
  sessionId: z.base64url().min(32).max(256),
});
export type SessionOpenResult = z.infer<typeof sessionOpenResultSchema>;

export const pingResultSchema = z.strictObject({
  ok: z.literal(true),
  protocolVersion: z.literal(PROTOCOL_VERSION),
  serverTime: z.iso.datetime({ offset: true }),
});
export type PingResult = z.infer<typeof pingResultSchema>;

const publicDescriptionSchema = z
  .string()
  .min(1)
  .max(256)
  .refine(
    (value) => !/[\u0000-\u001f\u007f]/u.test(value),
    "must not contain control characters",
  );

export const targetSummarySchema = z.strictObject({
  targetId: targetIdSchema,
  alias: targetAliasSchema,
  group: targetGroupSchema.optional(),
  description: publicDescriptionSchema.optional(),
  enabled: z.boolean(),
  platform: targetPlatformSchema.default("linux"),
  connectionMode: targetConnectionModeSchema.default("openssh"),
  policyMode: z.enum(["allow-list", "full-access", "deny", "presets"]),
  transferMode: z
    .enum(["deny", "upload", "download", "bidirectional"])
    .default("deny"),
  transferScope: z.enum(["restricted", "all"]).default("restricted"),
  transferRoots: z.array(targetAliasSchema).max(32).default([]),
  maxTimeoutMs: z.number().int().min(1).max(MAX_TIMEOUT_MS),
  maxTransferTimeoutMs: z.number().int().min(1).max(MAX_TIMEOUT_MS),
});
export type TargetSummary = z.infer<typeof targetSummarySchema>;

export const targetListResultSchema = z.strictObject({
  targets: z.array(targetSummarySchema).max(1_024),
  groups: targetGroupCatalogSchema.optional(),
});
export type TargetListResult = z.infer<typeof targetListResultSchema>;

export const targetCheckParamsSchema = z.strictObject({
  target: targetAliasSchema,
});
export type TargetCheckParams = z.infer<typeof targetCheckParamsSchema>;

export const legacyExecRunParamsSchema = z.strictObject({
  target: targetAliasSchema,
  command: z
    .string()
    .refine((value) => value.trim().length > 0, "command must not be blank")
    .refine(
      (value) => !/[\0\r\n]/u.test(value),
      "command must not contain NUL bytes or newlines",
    )
    .refine(
      (value) => Buffer.byteLength(value, "utf8") <= MAX_COMMAND_BYTES,
      `command must not exceed ${MAX_COMMAND_BYTES} UTF-8 bytes`,
    ),
  timeoutMs: z.number().int().min(1).max(MAX_TIMEOUT_MS).optional(),
});

export const remoteShellSchema = z.enum(["powershell", "cmd", "bash"]);
export type RemoteShell = z.infer<typeof remoteShellSchema>;

const environmentNameSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(
    /^[A-Za-z_][A-Za-z0-9_]*$/u,
    "must be a portable environment variable name",
  );

const boundedPayloadStringSchema = z
  .string()
  .max(MAX_COMMAND_BYTES)
  .refine((value) => !value.includes("\0"), "must not contain NUL bytes")
  .refine(
    (value) => Buffer.byteLength(value, "utf8") <= MAX_COMMAND_BYTES,
    `must not exceed ${MAX_COMMAND_BYTES} UTF-8 bytes`,
  );

export const structuredExecRunParamsSchema = z
  .strictObject({
    target: targetAliasSchema,
    shell: remoteShellSchema,
    script: boundedPayloadStringSchema.refine(
      (value) => value.trim().length > 0,
      "script must not be blank",
    ),
    cwd: boundedPayloadStringSchema
      .refine((value) => value.length > 0, "cwd must not be empty")
      .refine(
        (value) => !/[\r\n]/u.test(value),
        "cwd must not contain CR or LF characters",
      )
      .optional(),
    env: z
      .record(environmentNameSchema, boundedPayloadStringSchema)
      .refine(
        (value) => Object.keys(value).length <= MAX_ENVIRONMENT_ENTRIES,
        `env must contain at most ${MAX_ENVIRONMENT_ENTRIES} entries`,
      )
      .optional(),
    encoding: z.literal("utf-8").default("utf-8"),
    timeoutMs: z.number().int().min(1).max(MAX_TIMEOUT_MS).optional(),
  })
  .superRefine((value, context) => {
    const entries = Object.entries(value.env ?? {});
    const aggregateBytes =
      Buffer.byteLength(value.script, "utf8") +
      Buffer.byteLength(value.cwd ?? "", "utf8") +
      entries.reduce(
        (total, [key, entryValue]) =>
          total +
          Buffer.byteLength(key, "utf8") +
          Buffer.byteLength(entryValue, "utf8"),
        0,
      );
    if (aggregateBytes > MAX_COMMAND_BYTES) {
      context.addIssue({
        code: "custom",
        message: `structured execution payload must not exceed ${MAX_COMMAND_BYTES} UTF-8 bytes`,
      });
    }

    if (
      value.shell !== "bash" &&
      entries.some(
        ([key], index) =>
          entries.findIndex(
            ([candidate]) => candidate.toLowerCase() === key.toLowerCase(),
          ) !== index,
      )
    ) {
      context.addIssue({
        code: "custom",
        path: ["env"],
        message: "Windows environment variable names must be unique ignoring case",
      });
    }
  });

export const execRunParamsSchema = z.union([
  legacyExecRunParamsSchema,
  structuredExecRunParamsSchema,
]);
export type ExecRunParams = z.infer<typeof execRunParamsSchema>;
export type LegacyExecRunParams = z.infer<typeof legacyExecRunParamsSchema>;
export type StructuredExecRunParams = z.infer<
  typeof structuredExecRunParamsSchema
>;

export const execCancelParamsSchema = z.strictObject({
  requestId: rpcIdSchema,
});
export type ExecCancelParams = z.infer<typeof execCancelParamsSchema>;

export const executionTerminationSchema = z.enum([
  "exit",
  "timeout",
  "cancel",
  "output_limit",
  "spawn_error",
]);
export type ExecutionTermination = z.infer<typeof executionTerminationSchema>;

const safeHostnameSchema = z
  .string()
  .min(1)
  .max(MAX_TARGET_CHECK_HOSTNAME_LENGTH)
  .regex(
    /^[A-Za-z0-9][A-Za-z0-9._-]*$/,
    "must be a bounded hostname without whitespace or control characters",
  );

export const targetCheckFailureReasonSchema = z.enum([
  "accessclient-session-unavailable",
  "accessclient-session-timeout",
  "accessclient-host-mismatch",
  "accessclient-session-ended",
  "tailscale-unavailable",
  "tailscale-peer-unavailable",
  "tailscale-host-key-unavailable",
]);
export type TargetCheckFailureReason = z.infer<
  typeof targetCheckFailureReasonSchema
>;

export const targetCheckResultSchema = z
  .strictObject({
    target: targetAliasSchema,
    connected: z.boolean(),
    termination: executionTerminationSchema,
    exitCode: z.number().int().min(0).max(4_294_967_295).nullable(),
    durationMs: z.number().int().safe().nonnegative(),
    hostname: safeHostnameSchema.optional(),
    failureReason: targetCheckFailureReasonSchema.optional(),
  })
  .superRefine((value, context) => {
    const connected = value.termination === "exit" && value.exitCode === 0;
    if (value.connected !== connected) {
      context.addIssue({
        code: "custom",
        path: ["connected"],
        message: "connected must exactly match a successful zero-code exit",
      });
    }
    if (!connected && value.hostname !== undefined) {
      context.addIssue({
        code: "custom",
        path: ["hostname"],
        message: "hostname is only allowed for a connected target",
      });
    }
    if (connected && value.failureReason !== undefined) {
      context.addIssue({
        code: "custom",
        path: ["failureReason"],
        message: "failureReason is only allowed for a failed target check",
      });
    }
    if (
      value.failureReason !== undefined &&
      (value.termination !== "exit" || value.exitCode !== 255)
    ) {
      context.addIssue({
        code: "custom",
        path: ["failureReason"],
        message: "Transport failure reasons require exit code 255",
      });
    }
  });
export type TargetCheckResult = z.infer<typeof targetCheckResultSchema>;

export const outputStreamSummarySchema = z.strictObject({
  text: z.string().max(MAX_RPC_FRAME_BYTES),
  bytes: z.number().int().safe().nonnegative(),
  inlineTruncated: z.boolean(),
});
export type OutputStreamSummary = z.infer<typeof outputStreamSummarySchema>;

const opaqueOutputReferenceSchema = z.base64url().min(32).max(256);

export const execResultSchema = z
  .strictObject({
    requestId: rpcIdSchema,
    termination: executionTerminationSchema,
    exitCode: z.number().int().min(0).max(4_294_967_295).nullable(),
    durationMs: z.number().int().safe().nonnegative(),
    stdout: outputStreamSummarySchema,
    stderr: outputStreamSummarySchema,
    outputRef: opaqueOutputReferenceSchema.optional(),
    outputExpiresAt: z.iso.datetime({ offset: true }).optional(),
  })
  .superRefine((value, context) => {
    if ((value.outputRef === undefined) !== (value.outputExpiresAt === undefined)) {
      context.addIssue({
        code: "custom",
        path: ["outputRef"],
        message: "outputRef and outputExpiresAt must either both be present or both be absent",
      });
    }
    if (
      (value.stdout.inlineTruncated || value.stderr.inlineTruncated) &&
      value.outputRef === undefined
    ) {
      context.addIssue({
        code: "custom",
        path: ["outputRef"],
        message: "outputRef is required when an inline output preview is truncated",
      });
    }
  });
export type ExecResult = z.infer<typeof execResultSchema>;

export const execCancelResultSchema = z.strictObject({
  accepted: z.boolean(),
});
export type ExecCancelResult = z.infer<typeof execCancelResultSchema>;

export const outputReadParamsSchema = z.strictObject({
  outputRef: opaqueOutputReferenceSchema,
  stream: z.enum(["stdout", "stderr"]),
  offset: z.number().int().safe().nonnegative(),
  limit: z.number().int().min(1).max(MAX_OUTPUT_READ_BYTES),
});
export type OutputReadParams = z.infer<typeof outputReadParamsSchema>;

export const outputChunkSchema = z
  .strictObject({
    dataBase64: z.base64(),
    nextOffset: z.number().int().safe().nonnegative().nullable(),
    eof: z.boolean(),
    totalBytes: z.number().int().safe().nonnegative(),
  })
  .superRefine((value, context) => {
    if (value.eof !== (value.nextOffset === null)) {
      context.addIssue({
        code: "custom",
        path: ["nextOffset"],
        message: "nextOffset must be null exactly when eof is true",
      });
    }
  });
export type OutputChunk = z.infer<typeof outputChunkSchema>;

const outputTextCursorSchema = z.base64url().min(8).max(256);

export const outputReadTextParamsSchema = z
  .strictObject({
    outputRef: opaqueOutputReferenceSchema,
    stream: z.enum(["stdout", "stderr"]),
    cursor: outputTextCursorSchema.optional(),
    // Explicit offsets remain available for older clients. New callers should
    // omit offset on the first page and continue with nextCursor.
    offset: z.number().int().safe().nonnegative().optional(),
    limit: z
      .number()
      .int()
      .min(1)
      .max(MAX_OUTPUT_READ_BYTES)
      .default(MAX_OUTPUT_READ_BYTES),
  })
  .refine(
    (value) => value.cursor === undefined || value.offset === undefined,
    {
      path: ["cursor"],
      message: "cursor and offset cannot be used together",
    },
  );
export type OutputReadTextParams = z.infer<typeof outputReadTextParamsSchema>;

export const outputTextChunkSchema = z
  .strictObject({
    text: z.string().max(MAX_RPC_FRAME_BYTES),
    bytesRead: z.number().int().safe().nonnegative(),
    nextCursor: outputTextCursorSchema.nullable().optional(),
    nextOffset: z.number().int().safe().nonnegative().nullable().optional(),
    eof: z.boolean(),
    totalBytes: z.number().int().safe().nonnegative(),
    hadDecodingErrors: z.boolean(),
  })
  .superRefine((value, context) => {
    const hasCursor = value.nextCursor !== undefined;
    const hasOffset = value.nextOffset !== undefined;
    if (hasCursor === hasOffset) {
      context.addIssue({
        code: "custom",
        path: ["nextCursor"],
        message: "exactly one of nextCursor or nextOffset must be present",
      });
      return;
    }
    const continuation = hasCursor ? value.nextCursor : value.nextOffset;
    if (value.eof !== (continuation === null)) {
      context.addIssue({
        code: "custom",
        path: [hasCursor ? "nextCursor" : "nextOffset"],
        message: "the continuation must be null exactly when eof is true",
      });
    }
  });
export type OutputTextChunk = z.infer<typeof outputTextChunkSchema>;

export const taskRunIdSchema = z.base64url().length(43);
export const taskCursorSchema = z.base64url().min(8).max(256);
export const taskKindSchema = z.enum([
  "exec",
  "upload",
  "download",
  "sync",
]);
export const taskStateSchema = z.enum([
  "running",
  "succeeded",
  "failed",
  "timed_out",
  "cancelled",
]);
export type TaskKind = z.infer<typeof taskKindSchema>;
export type TaskState = z.infer<typeof taskStateSchema>;

export const taskStartResultSchema = z.strictObject({
  runId: taskRunIdSchema,
  target: targetAliasSchema,
  kind: taskKindSchema,
  state: z.literal("running"),
  startedAt: z.iso.datetime({ offset: true }),
});
export type TaskStartResult = z.infer<typeof taskStartResultSchema>;

export const taskStatusParamsSchema = z.strictObject({
  runId: taskRunIdSchema,
});
export type TaskStatusParams = z.infer<typeof taskStatusParamsSchema>;

export const taskStatusResultSchema = z.strictObject({
  runId: taskRunIdSchema,
  target: targetAliasSchema,
  kind: taskKindSchema,
  state: taskStateSchema,
  startedAt: z.iso.datetime({ offset: true }),
  updatedAt: z.iso.datetime({ offset: true }),
  finishedAt: z.iso.datetime({ offset: true }).optional(),
  expiresAt: z.iso.datetime({ offset: true }).optional(),
  durationMs: z.number().int().safe().nonnegative(),
  stdoutBytes: z.number().int().safe().nonnegative(),
  stderrBytes: z.number().int().safe().nonnegative(),
  termination: executionTerminationSchema.optional(),
  exitCode: z.number().int().min(0).max(4_294_967_295).nullable().optional(),
  result: z.record(z.string(), z.unknown()).optional(),
  error: z
    .strictObject({
      gatewayCode: z.string().min(1).max(64),
      message: z.string().min(1).max(256),
    })
    .optional(),
});
export type TaskStatusResult = z.infer<typeof taskStatusResultSchema>;

export const taskTailParamsSchema = z.strictObject({
  runId: taskRunIdSchema,
  cursor: taskCursorSchema.optional(),
  limit: z.number().int().min(1).max(MAX_TASK_TAIL_BYTES).default(32_768),
});
export type TaskTailParams = z.infer<typeof taskTailParamsSchema>;

const taskTailStreamSchema = z.strictObject({
  text: z.string().max(MAX_RPC_FRAME_BYTES),
  bytesRead: z.number().int().safe().nonnegative(),
  totalBytes: z.number().int().safe().nonnegative(),
  droppedBytes: z.number().int().safe().nonnegative(),
  hadDecodingErrors: z.boolean(),
});

export const taskTailResultSchema = z.strictObject({
  runId: taskRunIdSchema,
  state: taskStateSchema,
  stdout: taskTailStreamSchema,
  stderr: taskTailStreamSchema,
  nextCursor: taskCursorSchema,
  eof: z.boolean(),
});
export type TaskTailResult = z.infer<typeof taskTailResultSchema>;

export const taskCancelParamsSchema = taskStatusParamsSchema;
export const taskCancelResultSchema = z.strictObject({
  runId: taskRunIdSchema,
  accepted: z.boolean(),
  state: taskStateSchema,
});
export type TaskCancelResult = z.infer<typeof taskCancelResultSchema>;

const transferPathTextSchema = z
  .string()
  .min(1)
  .max(4_096)
  .refine(
    (value) => !/[\0\r\n]/u.test(value),
    "must not contain NUL, CR, or LF characters",
  );
const relativeTransferPathSchema = transferPathTextSchema;
const remoteTransferPathSchema = z
  .string()
  .min(1)
  .max(8_192)
  .refine(
    (value) => !/[\0\r\n]/u.test(value),
    "must not contain NUL, CR, or LF characters",
  );
const transferCommonFields = {
  target: targetAliasSchema,
  localRoot: targetAliasSchema.optional(),
  localPath: transferPathTextSchema,
  remotePath: remoteTransferPathSchema,
  overwrite: z.boolean().default(false),
  resume: z.boolean().default(true),
  dryRun: z.boolean().default(false),
  timeoutMs: z.number().int().min(1).max(MAX_TIMEOUT_MS).optional(),
};

export const uploadParamsSchema = z.strictObject({
  ...transferCommonFields,
  expectedSha256: z
    .string()
    .regex(
      /^[A-Fa-f0-9]{64}$/u,
      "must be a 64-character hexadecimal SHA-256 digest; letter case is ignored",
    )
    .optional(),
  verify: z.enum(["transport", "sha256"]).default("sha256"),
});
export type UploadParams = z.infer<typeof uploadParamsSchema>;

export const downloadParamsSchema = z.strictObject({
  ...transferCommonFields,
  expectedSha256: z
    .string()
    .regex(
      /^[A-Fa-f0-9]{64}$/u,
      "must be a 64-character hexadecimal SHA-256 digest; letter case is ignored",
    )
    .optional(),
});
export type DownloadParams = z.infer<typeof downloadParamsSchema>;

export const syncParamsSchema = z.strictObject({
  ...transferCommonFields,
  exclude: z
    .array(
      z
        .string()
        .min(1)
        .max(512)
        .refine((value) => !/[\0\r\n]/u.test(value)),
    )
    .max(MAX_TRANSFER_EXCLUDES)
    .default([]),
  verifyExisting: z.boolean().default(false),
});
export type SyncParams = z.infer<typeof syncParamsSchema>;

export const targetInspectParamsSchema = targetCheckParamsSchema;
const safePublicTextSchema = z
  .string()
  .max(512)
  .refine((value) => !/[\u0000-\u001f\u007f]/u.test(value));
export const targetInspectResultSchema = z.strictObject({
  target: targetAliasSchema,
  connected: z.boolean(),
  observedAt: z.iso.datetime({ offset: true }),
  durationMs: z.number().int().safe().nonnegative(),
  sshHostKeyFingerprints: z.array(z.string().regex(/^SHA256:[A-Za-z0-9+/]+$/u)),
  machine: z
    .strictObject({
      machineId: z.string().regex(/^mid_[A-Za-z0-9_-]{43}$/u),
      hostname: safeHostnameSchema,
      configuredPlatform: targetPlatformSchema,
      reportedPlatform: targetPlatformSchema,
      platformMatch: z.boolean(),
      os: z.strictObject({
        name: safePublicTextSchema.optional(),
        version: safePublicTextSchema.optional(),
        build: safePublicTextSchema.optional(),
        kernel: safePublicTextSchema.optional(),
        architecture: safePublicTextSchema.optional(),
      }),
      disk: z
        .strictObject({
          totalBytes: z.number().int().safe().nonnegative(),
          availableBytes: z.number().int().safe().nonnegative(),
        })
        .optional(),
      docker: z.strictObject({
        installed: z.boolean(),
        daemonReachable: z.boolean(),
        clientVersion: safePublicTextSchema.optional(),
        serverVersion: safePublicTextSchema.optional(),
        composeVersion: safePublicTextSchema.optional(),
      }),
    })
    .optional(),
  warnings: z.array(z.string().min(1).max(64)).max(16),
});
export type TargetInspectResult = z.infer<typeof targetInspectResultSchema>;

const dockerProjectSchema = z.strictObject({
  directory: remoteTransferPathSchema,
  composeFiles: z.array(relativeTransferPathSchema).max(8).default([]),
  name: z
    .string()
    .regex(/^[a-z0-9][a-z0-9_-]{0,62}$/u)
    .optional(),
});
export const dockerPreflightParamsSchema = z
  .strictObject({
    target: targetAliasSchema,
    intent: z.enum(["create", "update", "inspect"]).default("create"),
    project: dockerProjectSchema.optional(),
    ports: z
      .array(
        z.strictObject({
          protocol: z.enum(["tcp", "udp"]),
          port: z.number().int().min(1).max(65_535),
        }),
      )
      .max(MAX_DOCKER_PREFLIGHT_PORTS)
      .default([]),
    requiredFreeBytes: z.number().int().safe().nonnegative().optional(),
  })
  .superRefine((value, context) => {
    const seenPorts = new Set<string>();
    for (const [index, entry] of value.ports.entries()) {
      const identity = `${entry.protocol}:${entry.port}`;
      if (seenPorts.has(identity)) {
        context.addIssue({
          code: "custom",
          path: ["ports", index],
          message: "must not contain duplicate protocol and port pairs",
        });
      }
      seenPorts.add(identity);
    }
  });
export type DockerPreflightParams = z.infer<typeof dockerPreflightParamsSchema>;

const checkStatusSchema = z.enum(["ok", "warning", "blocked", "unavailable"]);
export const dockerPreflightResultSchema = z.strictObject({
  target: targetAliasSchema,
  intent: z.enum(["create", "update", "inspect"]),
  checkedAt: z.iso.datetime({ offset: true }),
  durationMs: z.number().int().safe().nonnegative(),
  overall: z.enum(["ready", "degraded", "blocked"]),
  daemon: z.strictObject({
    status: checkStatusSchema,
    installed: z.boolean(),
    reachable: z.boolean(),
    clientVersion: safePublicTextSchema.optional(),
    serverVersion: safePublicTextSchema.optional(),
    context: z
      .strictObject({
        name: safePublicTextSchema,
        scope: z.enum(["local", "remote", "unknown"]),
      })
      .optional(),
  }),
  compose: z.strictObject({
    status: checkStatusSchema,
    installed: z.boolean(),
    version: safePublicTextSchema.optional(),
    config: z.enum(["valid", "invalid", "not-requested", "unavailable"]),
  }),
  ports: z.array(
    z.strictObject({
      protocol: z.enum(["tcp", "udp"]),
      port: z.number().int().min(1).max(65_535),
      observation: z.enum(["listener-observed", "not-observed", "unknown"]),
      ownership: z.enum([
        "requested-project",
        "other-container",
        "host-process",
        "unknown",
      ]),
    }),
  ),
  containers: z.strictObject({
    status: checkStatusSchema,
    filter: z.string().regex(
      /^label=com\.docker\.compose\.project=[a-z0-9][a-z0-9_-]{0,62}$/u,
    ).optional(),
    truncated: z.boolean(),
    total: z.number().int().safe().nonnegative(),
    running: z.number().int().safe().nonnegative(),
    healthy: z.number().int().safe().nonnegative(),
    unhealthy: z.number().int().safe().nonnegative(),
    starting: z.number().int().safe().nonnegative(),
    exited: z.number().int().safe().nonnegative(),
  }),
  disk: z
    .strictObject({
      status: checkStatusSchema,
      totalBytes: z.number().int().safe().nonnegative(),
      availableBytes: z.number().int().safe().nonnegative(),
      requiredBytes: z.number().int().safe().nonnegative().optional(),
    })
    .optional(),
  warnings: z.array(z.string().min(1).max(64)).max(16),
});
export type DockerPreflightResult = z.infer<
  typeof dockerPreflightResultSchema
>;

export const operationListParamsSchema = z.strictObject({ target: targetAliasSchema });
export const operationRunParamsSchema = operationRequestSchema.extend({
  target: targetAliasSchema,
  timeoutMs: z.number().int().min(1).max(15_000).optional(),
});
export const operationListResultSchema = z.strictObject({
  target: targetAliasSchema,
  presets: z.array(z.record(z.string(), z.unknown())),
  operations: z.array(z.record(z.string(), z.unknown())),
});

export const RPC_METHODS = [
  "session.open",
  "system.ping",
  "target.list",
  "target.check",
  "target.inspect",
  "operation.list",
  "operation.run",
  "docker.preflight",
  "exec.run",
  "exec.cancel",
  "task.start",
  "task.status",
  "task.tail",
  "task.cancel",
  "transfer.upload",
  "transfer.download",
  "transfer.sync",
  "output.read",
  "output.readText",
] as const;

export const rpcMethodSchema = z.enum(RPC_METHODS);
export type RpcMethod = (typeof RPC_METHODS)[number];

export const rpcParamsSchemas = {
  "session.open": sessionOpenParamsSchema,
  "system.ping": emptyParamsSchema,
  "target.list": emptyParamsSchema,
  "target.check": targetCheckParamsSchema,
  "target.inspect": targetInspectParamsSchema,
  "operation.list": operationListParamsSchema,
  "operation.run": operationRunParamsSchema,
  "docker.preflight": dockerPreflightParamsSchema,
  "exec.run": execRunParamsSchema,
  "exec.cancel": execCancelParamsSchema,
  "task.start": execRunParamsSchema,
  "task.status": taskStatusParamsSchema,
  "task.tail": taskTailParamsSchema,
  "task.cancel": taskCancelParamsSchema,
  "transfer.upload": uploadParamsSchema,
  "transfer.download": downloadParamsSchema,
  "transfer.sync": syncParamsSchema,
  "output.read": outputReadParamsSchema,
  "output.readText": outputReadTextParamsSchema,
} as const;

export const rpcResultSchemas = {
  "session.open": sessionOpenResultSchema,
  "system.ping": pingResultSchema,
  "target.list": targetListResultSchema,
  "target.check": targetCheckResultSchema,
  "target.inspect": targetInspectResultSchema,
  "operation.list": operationListResultSchema,
  "operation.run": execResultSchema,
  "docker.preflight": dockerPreflightResultSchema,
  "exec.run": execResultSchema,
  "exec.cancel": execCancelResultSchema,
  "task.start": taskStartResultSchema,
  "task.status": taskStatusResultSchema,
  "task.tail": taskTailResultSchema,
  "task.cancel": taskCancelResultSchema,
  "transfer.upload": taskStartResultSchema,
  "transfer.download": taskStartResultSchema,
  "transfer.sync": taskStartResultSchema,
  "output.read": outputChunkSchema,
  "output.readText": outputTextChunkSchema,
} as const;

export type RpcParamsByMethod = {
  [Method in RpcMethod]: z.infer<(typeof rpcParamsSchemas)[Method]>;
};

export type RpcResultByMethod = {
  [Method in RpcMethod]: z.infer<(typeof rpcResultSchemas)[Method]>;
};

export interface RpcRequestBase<Method extends string = string, Params = unknown> {
  readonly jsonrpc: "2.0";
  readonly id: RpcId;
  readonly method: Method;
  readonly params: Params;
}

export type RpcRequest = {
  [Method in RpcMethod]: Readonly<
    RpcRequestBase<Method, RpcParamsByMethod[Method]>
  >;
}[RpcMethod];

export const rpcRequestEnvelopeSchema = z.strictObject({
  jsonrpc: z.literal("2.0"),
  id: rpcIdSchema,
  method: rpcMethodSchema,
  params: z.unknown(),
});

export function parseRpcParams<Method extends RpcMethod>(
  method: Method,
  params: unknown,
): RpcParamsByMethod[Method] {
  return rpcParamsSchemas[method].parse(params) as RpcParamsByMethod[Method];
}

export function parseRpcRequest(input: unknown): RpcRequest {
  const envelope = rpcRequestEnvelopeSchema.parse(input);
  const params = parseRpcParams(envelope.method, envelope.params);

  // Both the envelope and method-specific params have been parsed above. The
  // assertion only teaches TypeScript the correlation represented by RpcRequest.
  return { ...envelope, params } as RpcRequest;
}

export interface RpcSuccessResponse<Result = unknown> {
  readonly jsonrpc: "2.0";
  readonly id: RpcId;
  readonly result: Result;
}

export interface RpcErrorResponse {
  readonly jsonrpc: "2.0";
  readonly id: RpcId | null;
  readonly error: Readonly<{
    code: number;
    message: string;
    data?: Readonly<{
      gatewayCode: GatewayErrorCode;
      details?: Readonly<Record<string, string | number | boolean | null>>;
    }>;
  }>;
}

export type RpcResponse<Result = unknown> =
  | RpcSuccessResponse<Result>
  | RpcErrorResponse;

export type RpcResponseFor<Method extends RpcMethod> = RpcResponse<
  RpcResultByMethod[Method]
>;

export function parseRpcResult<Method extends RpcMethod>(
  method: Method,
  result: unknown,
): RpcResultByMethod[Method] {
  return rpcResultSchemas[method].parse(result) as RpcResultByMethod[Method];
}
