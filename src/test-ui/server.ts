import { isUtf8 } from "node:buffer";
import { spawn } from "node:child_process";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { BrowserSession } from "../service/browser-session.js";

import { z } from "zod";

import { GATEWAY_ERROR_CODES } from "../shared/errors.js";
import {
  MAX_OUTPUT_READ_BYTES,
  DEFAULT_TARGET_GROUP,
  targetGroupSchema,
  targetGroupCatalogSchema,
  dockerPreflightParamsSchema,
  downloadParamsSchema,
  execRunParamsSchema,
  syncParamsSchema,
  targetAliasSchema,
  targetCheckParamsSchema,
  targetInspectParamsSchema,
  taskStatusParamsSchema,
  taskTailParamsSchema,
  uploadParamsSchema,
  type OutputChunk,
} from "../shared/protocol.js";
import { RpcRemoteError } from "../shared/rpc-client.js";
import { completeUtf8PrefixLength } from "../shared/utf8.js";
import {
  AccessClientSessionError,
  type AccessClientSessionPreparer,
  type AccessClientSessionSnapshot,
} from "./accessclient-session.js";
import type {
  TestUiGatewayFactory,
  TestUiGatewaySession,
} from "./gateway.js";
import {
  ManagedSshError,
  createManagedTargetId,
  currentManagedSshProfileSchema,
  managedAccessClientSettingsSchema,
  managedTailscaleSettingsSchema,
  managedFleetTargetSchema,
  managedSshKeyIdSchema,
  managedSshKeyGenerationAlgorithmSchema,
  managedSshKeyLabelSchema,
  managedSshKeyRevisionSchema,
  managedSshFleetProfileSchema,
  normalizeFleetGroups,
  type CurrentManagedSshProfile,
  type ManagedSshFleetProfile,
  type ManagedSshFleetStatus,
  type ManagedSshFleetTarget,
  type TestUiConfigurationService,
} from "./managed.js";

const LOOPBACK_HOST = "127.0.0.1";
const MAX_REQUEST_BODY_BYTES = 96 * 1_024;
const MAX_RESULT_REFERENCES = 32;
const UI_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

const emptyBodySchema = z.strictObject({});
const outputRequestSchema = z.strictObject({
  resultId: z.string().regex(UI_TOKEN_PATTERN),
  stream: z.enum(["stdout", "stderr"]),
  offset: z.number().int().safe().nonnegative(),
  limit: z.number().int().min(1).max(MAX_OUTPUT_READ_BYTES),
});
const fullAccessApplyRequestSchema = z
  .strictObject({
    profile: currentManagedSshProfileSchema,
    fullAccessConfirmed: z.literal(true),
  })
  .refine(
    (request) => request.profile.policyMode === "full-access",
    "fullAccessConfirmed is only valid for a full-access profile",
  );
const allowListApplyRequestSchema = z.strictObject({
  profile: currentManagedSshProfileSchema.refine(
    (profile) => profile.policyMode === "allow-list",
    "profile must use allow-list mode",
  ),
});
const setupApplyRequestSchema = z.union([
  allowListApplyRequestSchema,
  fullAccessApplyRequestSchema,
]);
const managedRevisionSchema = z
  .string()
  .regex(/^r-[a-z0-9]+-[a-f0-9]{32}$/u);
const adminTargetSaveFields = {
  alias: targetAliasSchema,
  previousAlias: targetAliasSchema.optional(),
  expectedRevision: managedRevisionSchema.optional(),
};
const adminTargetSaveRequestSchema = z.strictObject({
  ...adminTargetSaveFields,
  target: managedFleetTargetSchema,
  fullAccessConfirmed: z.literal(true).optional(),
  transferAccessConfirmed: z.literal(true).optional(),
}).superRefine((request, context) => {
  if (
    request.target.policyMode === "full-access" &&
    request.fullAccessConfirmed !== true
  ) {
    context.addIssue({
      code: "custom",
      path: ["fullAccessConfirmed"],
      message: "full-access changes require explicit confirmation",
    });
  }
  if (
    request.target.policyMode === "full-access" &&
    (request.target.transferMode ?? "deny") !== "deny" &&
    (request.target.localRootPath === undefined ||
      (request.target.remoteRoots ?? []).length === 0)
  ) {
    context.addIssue({
      code: "custom",
      path: ["target", "transferMode"],
      message: "legacy full-access transfer fields require complete roots",
    });
  }
  if (
    request.target.policyMode === "full-access" &&
    (request.target.transferMode ?? "deny") === "deny" &&
    (request.target.localRootPath !== undefined ||
      (request.target.remoteRoots ?? []).length !== 0 ||
      request.target.maxTransferTimeoutMs !== undefined)
  ) {
    context.addIssue({
      code: "custom",
      path: ["target", "transferMode"],
      message: "new full-access requests must omit restricted transfer fields",
    });
  }
  if (
    request.target.policyMode !== "full-access" &&
    (request.target.transferMode ?? "deny") !== "deny" &&
    request.transferAccessConfirmed !== true
  ) {
    context.addIssue({
      code: "custom",
      path: ["transferAccessConfirmed"],
      message: "file transfer changes require explicit confirmation",
    });
  }
});
const adminTargetRemoveRequestSchema = z.strictObject({
  alias: targetAliasSchema,
  expectedRevision: managedRevisionSchema.optional(),
});
const adminTargetEnabledRequestSchema = z.strictObject({
  alias: targetAliasSchema,
  enabled: z.boolean(),
  expectedRevision: managedRevisionSchema,
});
const adminGroupRequests = {
  "/api/admin/group/create": z.strictObject({ name: targetGroupSchema, expectedRevision: managedRevisionSchema.optional() }),
  "/api/admin/group/rename": z.strictObject({ group: targetGroupSchema, name: targetGroupSchema, expectedRevision: managedRevisionSchema.optional() }),
  "/api/admin/group/delete": z.strictObject({ group: targetGroupSchema, expectedRevision: managedRevisionSchema.optional() }),
  "/api/admin/group/move": z.strictObject({ aliases: z.array(targetAliasSchema).min(1).max(1_024).refine((aliases) => new Set(aliases).size === aliases.length, "Aliases must be unique"), group: z.union([targetGroupSchema, z.literal("")]).optional(), expectedRevision: managedRevisionSchema.optional() }),
  "/api/admin/group/reorder": z.strictObject({ groups: targetGroupCatalogSchema, expectedRevision: managedRevisionSchema.optional() }),
};
const adminTailscaleSaveRequestSchema = managedTailscaleSettingsSchema.extend({ expectedRevision: managedRevisionSchema.optional() });
const adminAccessClientSaveRequestSchema = z.strictObject({
  plinkExecutable: managedAccessClientSettingsSchema.shape.plinkExecutable,
  expectedRevision: managedRevisionSchema.optional(),
});
const adminAccessClientSessionRequestSchema = z.strictObject({
  alias: targetAliasSchema,
  expectedRevision: managedRevisionSchema,
});
const adminKeyGenerateRequestSchema = z.strictObject({
  label: managedSshKeyLabelSchema,
  expectedKeyRevision: managedSshKeyRevisionSchema,
  algorithm: managedSshKeyGenerationAlgorithmSchema.default("ed25519"),
});
const adminKeyImportRequestSchema = z.strictObject({
  label: managedSshKeyLabelSchema,
  sourcePath: z
    .string()
    .min(1)
    .max(4_096)
    .refine(
      isSafePrivateKeySourcePath,
      "must be a local absolute path without device, UNC, ADS, or expansion syntax",
    ),
  expectedKeyRevision: managedSshKeyRevisionSchema,
});
const adminKeyRenameRequestSchema = z.strictObject({
  keyId: managedSshKeyIdSchema,
  label: managedSshKeyLabelSchema,
  expectedKeyRevision: managedSshKeyRevisionSchema,
});
const adminKeyRemoveRequestSchema = z.strictObject({
  keyId: managedSshKeyIdSchema,
  expectedKeyRevision: managedSshKeyRevisionSchema,
});
const adminSshInstallRequestSchema = z
  .strictObject({ target: managedFleetTargetSchema })
  .superRefine((request, context) => {
    const target = request.target;
    if ((target.connectionMode ?? "openssh") !== "openssh") {
      context.addIssue({
        code: "custom",
        path: ["target", "connectionMode"],
        message: "automatic SSH key installation requires OpenSSH",
      });
    }
    if (target.target.keyId === undefined) {
      context.addIssue({
        code: "custom",
        path: ["target", "target", "keyId"],
        message: "an OpenSSH private key is required",
      });
    }
    if (target.knownHostsFile === undefined) {
      context.addIssue({
        code: "custom",
        path: ["target", "knownHostsFile"],
        message: "a known_hosts path is required",
      });
    }
  });

interface ResultReference {
  readonly outputRef: string;
  readonly expiresAtMs: number;
}

interface ActiveRun {
  readonly controller: AbortController;
}

interface StaticAsset {
  readonly contentType: string;
  readonly body: Buffer;
}

export interface TestUiServerOptions {
  readonly gatewayFactory: TestUiGatewayFactory;
  readonly mode: "demo" | "gateway" | "managed";
  readonly configurationService?: TestUiConfigurationService;
  readonly accessClientSessionPreparer?: AccessClientSessionPreparer;
  readonly legacySetupRoutes?: boolean;
  readonly port?: number;
  readonly sessionToken?: string;
  readonly browserSessionSecret?: string;
  readonly assetDirectory?: string;
  readonly onError?: (error: unknown) => void;
}

export interface RunningTestUiServer {
  readonly origin: string;
  readonly url: string;
  readonly sessionToken: string;
  readonly port: number;
  close(): Promise<void>;
}

class HttpProblem extends Error {
  public readonly status: number;
  public readonly code: string;

  public constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "HttpProblem";
    this.status = status;
    this.code = code;
  }
}

export async function startTestUiServer(
  options: TestUiServerOptions,
): Promise<RunningTestUiServer> {
  const port = validatePort(options.port ?? 0);
  const sessionToken = options.sessionToken ?? randomBytes(32).toString("base64url");
  const browserSession = new BrowserSession(options.browserSessionSecret ?? randomBytes(32).toString("base64url"));
  if (!UI_TOKEN_PATTERN.test(sessionToken)) {
    throw new TypeError("sessionToken must be a 256-bit base64url value");
  }

  const assetDirectory =
    options.assetDirectory ?? fileURLToPath(new URL("./public/", import.meta.url));
  const assets = await loadStaticAssets(assetDirectory);
  await options.accessClientSessionPreparer?.initialize();
  const resultReferences = new Map<string, ResultReference>();
  let activeRun: ActiveRun | undefined;
  let configurationMutationActive = false;
  let accessClientPreparationRequestActive = false;
  let accessClientVerificationActive = false;
  let expectedHost = "";
  let expectedOrigin = "";
  let closed = false;

  const server = createServer((request, response) => {
    void handleRequest(request, response).catch((error: unknown) => {
      if (!(error instanceof HttpProblem)) {
        options.onError?.(error);
      }
      writeProblem(response, toHttpProblem(error));
    });
  });
  configureHttpServer(server);

  const handleRequest = async (
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> => {
    applySecurityHeaders(response);
    if (request.headers.host !== expectedHost) {
      throw new HttpProblem(421, "INVALID_HOST", "Request host was rejected");
    }

    const route = request.url ?? "";
    const staticAsset = assets.get(route);
    if (staticAsset !== undefined) {
      if (request.method !== "GET") {
        throw new HttpProblem(405, "METHOD_NOT_ALLOWED", "Method is not allowed");
      }
      response.statusCode = 200;
      response.setHeader("Content-Type", staticAsset.contentType);
      response.setHeader("Content-Length", staticAsset.body.length);
      response.setHeader("Cache-Control", "no-store");
      response.end(staticAsset.body);
      return;
    }

    if (!route.startsWith("/api/")) {
      throw new HttpProblem(404, "NOT_FOUND", "Resource was not found");
    }
    if (request.method !== "POST") {
      throw new HttpProblem(405, "METHOD_NOT_ALLOWED", "Method is not allowed");
    }
    assertBrowserApiRequest(request, expectedOrigin, sessionToken, browserSession);
    response.setHeader("Set-Cookie", browserSession.issue(expectedOrigin));
    cleanupResultReferences(resultReferences);

    switch (route) {
      case "/api/ping": {
        emptyBodySchema.parse(await readJsonBody(request));
        const result = await withGateway(options.gatewayFactory, (gateway) =>
          gateway.ping(),
        );
        writeJson(response, 200, { mode: options.mode, gateway: result });
        return;
      }
      case "/api/targets": {
        emptyBodySchema.parse(await readJsonBody(request));
        const result = await withGateway(options.gatewayFactory, (gateway) =>
          gateway.listTargets(),
        );
        writeJson(response, 200, result);
        return;
      }
      case "/api/inspect": {
        const params = targetInspectParamsSchema.parse(await readJsonBody(request));
        assertForegroundOperationAvailable(activeRun, configurationMutationActive);
        const controller = new AbortController();
        const run = { controller };
        activeRun = run;
        const abortForDisconnect = (): void => {
          if (!response.writableEnded) controller.abort();
        };
        request.once("aborted", abortForDisconnect);
        response.once("close", abortForDisconnect);
        try {
          const result = await withGateway(options.gatewayFactory, (gateway) => {
            if (gateway.inspectTarget === undefined) throw capabilityUnavailable();
            return gateway.inspectTarget(params, controller.signal);
          });
          if (!response.destroyed) writeJson(response, 200, result);
        } finally {
          request.off("aborted", abortForDisconnect);
          response.off("close", abortForDisconnect);
          if (activeRun === run) activeRun = undefined;
        }
        return;
      }
      case "/api/docker/preflight": {
        const params = dockerPreflightParamsSchema.parse(await readJsonBody(request));
        assertForegroundOperationAvailable(activeRun, configurationMutationActive);
        const controller = new AbortController();
        const run = { controller };
        activeRun = run;
        const abortForDisconnect = (): void => {
          if (!response.writableEnded) controller.abort();
        };
        request.once("aborted", abortForDisconnect);
        response.once("close", abortForDisconnect);
        try {
          const result = await withGateway(options.gatewayFactory, (gateway) => {
            if (gateway.dockerPreflight === undefined) throw capabilityUnavailable();
            return gateway.dockerPreflight(params, controller.signal);
          });
          if (!response.destroyed) writeJson(response, 200, result);
        } finally {
          request.off("aborted", abortForDisconnect);
          response.off("close", abortForDisconnect);
          if (activeRun === run) activeRun = undefined;
        }
        return;
      }
      case "/api/run": {
        const params = execRunParamsSchema.parse(await readJsonBody(request));
        if (configurationMutationActive) {
          throw new HttpProblem(
            409,
            "CONFIG_BUSY",
            "SSH configuration is currently being changed",
          );
        }
        if (activeRun !== undefined) {
          throw new HttpProblem(
            409,
            "RUN_ACTIVE",
            "Another test command is already running",
          );
        }
        const controller = new AbortController();
        const run = { controller };
        activeRun = run;
        const abortForDisconnect = (): void => {
          if (!response.writableEnded) {
            controller.abort();
          }
        };
        request.once("aborted", abortForDisconnect);
        response.once("close", abortForDisconnect);
        try {
          const result = await withGateway(options.gatewayFactory, async (gateway) => {
            if (controller.signal.aborted) {
              throw new HttpProblem(499, "CLIENT_CLOSED", "Client disconnected");
            }
            return gateway.run(params, controller.signal);
          });
          if (response.destroyed) {
            return;
          }
          const reference = registerResultReference(resultReferences, result);
          writeJson(response, 200, {
            termination: result.termination,
            exitCode: result.exitCode,
            durationMs: result.durationMs,
            stdout: result.stdout,
            stderr: result.stderr,
            ...(reference === undefined ? {} : reference),
          });
        } finally {
          request.off("aborted", abortForDisconnect);
          response.off("close", abortForDisconnect);
          if (activeRun === run) {
            activeRun = undefined;
          }
        }
        return;
      }
      case "/api/task/start": {
        const params = execRunParamsSchema.parse(await readJsonBody(request));
        assertTaskStartAvailable(configurationMutationActive);
        const result = await withGateway(options.gatewayFactory, (gateway) => {
          if (gateway.startTask === undefined) throw capabilityUnavailable();
          return gateway.startTask(params);
        });
        writeJson(response, 202, result);
        return;
      }
      case "/api/task/status": {
        const params = taskStatusParamsSchema.parse(await readJsonBody(request));
        const result = await withGateway(options.gatewayFactory, (gateway) => {
          if (gateway.taskStatus === undefined) throw capabilityUnavailable();
          return gateway.taskStatus(params);
        });
        writeJson(
          response,
          200,
          publicTaskStatus(resultReferences, result),
        );
        return;
      }
      case "/api/task/tail": {
        const params = taskTailParamsSchema.parse(await readJsonBody(request));
        const result = await withGateway(options.gatewayFactory, (gateway) => {
          if (gateway.taskTail === undefined) throw capabilityUnavailable();
          return gateway.taskTail(params);
        });
        writeJson(response, 200, result);
        return;
      }
      case "/api/task/cancel": {
        const params = taskStatusParamsSchema.parse(await readJsonBody(request));
        const result = await withGateway(options.gatewayFactory, (gateway) => {
          if (gateway.cancelTask === undefined) throw capabilityUnavailable();
          return gateway.cancelTask(params);
        });
        writeJson(response, 200, result);
        return;
      }
      case "/api/transfer/upload": {
        const params = uploadParamsSchema.parse(await readJsonBody(request));
        assertTaskStartAvailable(configurationMutationActive);
        const result = await withGateway(options.gatewayFactory, (gateway) => {
          if (gateway.upload === undefined) throw capabilityUnavailable();
          return gateway.upload(params);
        });
        writeJson(response, 202, result);
        return;
      }
      case "/api/transfer/download": {
        const params = downloadParamsSchema.parse(await readJsonBody(request));
        assertTaskStartAvailable(configurationMutationActive);
        const result = await withGateway(options.gatewayFactory, (gateway) => {
          if (gateway.download === undefined) throw capabilityUnavailable();
          return gateway.download(params);
        });
        writeJson(response, 202, result);
        return;
      }
      case "/api/transfer/sync": {
        const params = syncParamsSchema.parse(await readJsonBody(request));
        assertTaskStartAvailable(configurationMutationActive);
        const result = await withGateway(options.gatewayFactory, (gateway) => {
          if (gateway.sync === undefined) throw capabilityUnavailable();
          return gateway.sync(params);
        });
        writeJson(response, 202, result);
        return;
      }
      case "/api/cancel": {
        emptyBodySchema.parse(await readJsonBody(request));
        const accepted = activeRun !== undefined;
        activeRun?.controller.abort();
        writeJson(response, 200, { accepted });
        return;
      }
      case "/api/output": {
        const params = outputRequestSchema.parse(await readJsonBody(request));
        const reference = resultReferences.get(params.resultId);
        if (reference === undefined || reference.expiresAtMs <= Date.now()) {
          resultReferences.delete(params.resultId);
          throw new HttpProblem(
            410,
            "OUTPUT_UNAVAILABLE",
            "Retained output is no longer available",
          );
        }
        const result = await withGateway(options.gatewayFactory, async (gateway) => {
          const first = await gateway.readOutput({
            outputRef: reference.outputRef,
            stream: params.stream,
            offset: params.offset,
            limit: params.limit,
          });
          return alignUtf8TextChunk(
            params.offset,
            first,
            (offset, limit) =>
              gateway.readOutput({
                outputRef: reference.outputRef,
                stream: params.stream,
                offset,
                limit,
              }),
          );
        });
        writeJson(response, 200, result);
        return;
      }
      case "/api/setup/status": {
        emptyBodySchema.parse(await readJsonBody(request));
        const configuration = requireLegacyConfigurationService(options);
        writeJson(response, 200, await configuration.status());
        return;
      }
      case "/api/setup/generate-key": {
        emptyBodySchema.parse(await readJsonBody(request));
        const configuration = requireLegacyConfigurationService(options);
        assertConfigurationMutationAvailable(
          activeRun,
          configurationMutationActive,
          accessClientPreparationRequestActive ||
            accessClientPreparationIsActive(options),
        );
        configurationMutationActive = true;
        try {
          writeJson(response, 200, await configuration.generateKey());
        } finally {
          configurationMutationActive = false;
        }
        return;
      }
      case "/api/setup/apply": {
        const applyRequest = setupApplyRequestSchema.parse(
          await readJsonBody(request),
        );
        const profile: CurrentManagedSshProfile = applyRequest.profile;
        const configuration = requireLegacyConfigurationService(options);
        assertConfigurationMutationAvailable(
          activeRun,
          configurationMutationActive,
          accessClientPreparationRequestActive ||
            accessClientPreparationIsActive(options),
        );
        configurationMutationActive = true;
        try {
          writeJson(response, 200, await configuration.apply(profile));
        } finally {
          configurationMutationActive = false;
        }
        return;
      }
      case "/api/admin/bootstrap": {
        emptyBodySchema.parse(await readJsonBody(request));
        const configuration = requireFleetConfigurationService(options);
        const status = publicFleetStatus(await configuration.fleetStatus());
        writeJson(
          response,
          200,
          options.accessClientSessionPreparer === undefined
            ? status
            : {
                ...status,
                accessClientSession:
                  options.accessClientSessionPreparer.status(),
              },
        );
        return;
      }
      case "/api/admin/key/generate": {
        const keyRequest = adminKeyGenerateRequestSchema.parse(
          await readJsonBody(request),
        );
        const configuration = requireFleetConfigurationService(options);
        assertConfigurationMutationAvailable(
          activeRun,
          configurationMutationActive,
          accessClientPreparationRequestActive ||
            accessClientPreparationIsActive(options),
        );
        configurationMutationActive = true;
        try {
          await configuration.generateManagedKey(
            keyRequest.label,
            keyRequest.expectedKeyRevision,
            keyRequest.algorithm,
          );
          writeJson(
            response,
            200,
            publicFleetStatus(await configuration.fleetStatus()),
          );
        } finally {
          configurationMutationActive = false;
        }
        return;
      }
      case "/api/admin/key/import": {
        const keyRequest = adminKeyImportRequestSchema.parse(
          await readJsonBody(request),
        );
        const configuration = requireFleetConfigurationService(options);
        assertConfigurationMutationAvailable(
          activeRun,
          configurationMutationActive,
          accessClientPreparationRequestActive ||
            accessClientPreparationIsActive(options),
        );
        configurationMutationActive = true;
        try {
          await configuration.importManagedKey(
            keyRequest.label,
            keyRequest.sourcePath,
            keyRequest.expectedKeyRevision,
          );
          writeJson(
            response,
            200,
            publicFleetStatus(await configuration.fleetStatus()),
          );
        } finally {
          configurationMutationActive = false;
        }
        return;
      }
      case "/api/admin/key/rename": {
        const keyRequest = adminKeyRenameRequestSchema.parse(
          await readJsonBody(request),
        );
        const configuration = requireFleetConfigurationService(options);
        assertConfigurationMutationAvailable(
          activeRun,
          configurationMutationActive,
          accessClientPreparationRequestActive ||
            accessClientPreparationIsActive(options),
        );
        configurationMutationActive = true;
        try {
          await configuration.renameManagedKey(
            keyRequest.keyId,
            keyRequest.label,
            keyRequest.expectedKeyRevision,
          );
          writeJson(
            response,
            200,
            publicFleetStatus(await configuration.fleetStatus()),
          );
        } finally {
          configurationMutationActive = false;
        }
        return;
      }
      case "/api/admin/key/remove": {
        const keyRequest = adminKeyRemoveRequestSchema.parse(
          await readJsonBody(request),
        );
        const configuration = requireFleetConfigurationService(options);
        assertConfigurationMutationAvailable(
          activeRun,
          configurationMutationActive,
          accessClientPreparationRequestActive ||
            accessClientPreparationIsActive(options),
        );
        configurationMutationActive = true;
        try {
          await configuration.removeManagedKey(
            keyRequest.keyId,
            keyRequest.expectedKeyRevision,
          );
          writeJson(
            response,
            200,
            publicFleetStatus(await configuration.fleetStatus()),
          );
        } finally {
          configurationMutationActive = false;
        }
        return;
      }
      case "/api/admin/ssh/install": {
        const installRequest = adminSshInstallRequestSchema.parse(
          await readJsonBody(request),
        );
        const configuration = requireFleetConfigurationService(options);
        const target = installRequest.target;
        const keyId = target.target.keyId!;
        const status = await configuration.fleetStatus();
        const key = status.keys.find((candidate) => candidate.keyId === keyId);
        if (key === undefined) {
          throw new HttpProblem(409, "KEY_NOT_FOUND", "The selected SSH key is unavailable");
        }
        launchInteractiveSshInstall({
          host: target.target.host,
          port: target.target.port,
          username: target.target.username,
          knownHostsFile: target.knownHostsFile!,
          platform: target.platform,
          publicKey: key.publicKey,
        });
        writeJson(response, 200, {
          started: true,
          platform: process.platform,
        });
        return;
      }
      case "/api/admin/tailscale/save": {
        const tailscaleRequest = adminTailscaleSaveRequestSchema.parse(
          await readJsonBody(request),
        );
        const configuration = requireFleetConfigurationService(options);
        assertConfigurationMutationAvailable(
          activeRun,
          configurationMutationActive,
          accessClientPreparationRequestActive ||
            accessClientPreparationIsActive(options),
        );
        configurationMutationActive = true;
        try {
          const current = await configuration.fleetStatus();
          assertExpectedRevision(
            current.revision,
            tailscaleRequest.expectedRevision,
          );
          const profile = managedSshFleetProfileSchema.parse({
            version: 3,
            ...(current.profile?.accessClient === undefined ? {} : { accessClient: current.profile.accessClient }),
            groups: normalizeFleetGroups(current.profile ?? { version: 3, targets: {} }).groups,
            tailscale: { executable: tailscaleRequest.executable },
            targets: current.profile?.targets ?? {},
          });
          writeJson(
            response,
            200,
            publicFleetStatus(
              await configuration.applyFleet(
                profile,
                tailscaleRequest.expectedRevision,
              ),
            ),
          );
        } finally {
          configurationMutationActive = false;
        }
        return;
      }
      case "/api/admin/access-client/save": {
        const accessClientRequest = adminAccessClientSaveRequestSchema.parse(
          await readJsonBody(request),
        );
        const configuration = requireFleetConfigurationService(options);
        assertConfigurationMutationAvailable(
          activeRun,
          configurationMutationActive,
          accessClientPreparationRequestActive ||
            accessClientPreparationIsActive(options),
        );
        configurationMutationActive = true;
        try {
          const current = await configuration.fleetStatus();
          assertExpectedRevision(
            current.revision,
            accessClientRequest.expectedRevision,
          );
          const profile = managedSshFleetProfileSchema.parse({
            version: 3,
            ...(current.profile?.tailscale === undefined ? {} : { tailscale: current.profile.tailscale }),
            accessClient: {
              plinkExecutable: accessClientRequest.plinkExecutable,
            },
            groups: normalizeFleetGroups(current.profile ?? { version: 3, targets: {} }).groups,
            targets: current.profile?.targets ?? {},
          });
          writeJson(
            response,
            200,
            publicFleetStatus(
              await configuration.applyFleet(
                profile,
                accessClientRequest.expectedRevision,
              ),
            ),
          );
        } finally {
          configurationMutationActive = false;
        }
        return;
      }
      case "/api/admin/access-client/session/prepare": {
        const sessionRequest = adminAccessClientSessionRequestSchema.parse(
          await readJsonBody(request),
        );
        assertForegroundOperationAvailable(activeRun, configurationMutationActive);
        if (accessClientPreparationRequestActive) {
          throw new HttpProblem(
            409,
            "ACCESSCLIENT_PREPARATION_BUSY",
            "Another AccessClient target is already being prepared",
          );
        }
        accessClientPreparationRequestActive = true;
        try {
          const target = await resolveSavedAccessClientTarget(
            options,
            sessionRequest.alias,
            sessionRequest.expectedRevision,
          );
          const preparer = requireAccessClientSessionPreparer(options);
          const sharingHost = target.accessClient.sharingHost;
          const sharingPort = target.accessClient.sharingPort;
          if (sharingHost === undefined || sharingPort === undefined) {
            throw new HttpProblem(
              409,
              "ACCESSCLIENT_SHARING_HOST_REQUIRED",
              "Save this target once to migrate its AccessClient sharing identity before preparing a session",
            );
          }
          writeJson(
            response,
            202,
            await preparer.prepare({
              alias: sessionRequest.alias,
              revision: sessionRequest.expectedRevision,
              sharingHost,
              sharingPort,
            }),
          );
        } finally {
          accessClientPreparationRequestActive = false;
        }
        return;
      }
      case "/api/admin/access-client/session/status": {
        const sessionRequest = adminAccessClientSessionRequestSchema.parse(
          await readJsonBody(request),
        );
        const preparer = requireAccessClientSessionPreparer(options);
        let snapshot: AccessClientSessionSnapshot = preparer.status();
        if (
          snapshot.state === "detected" &&
          snapshot.alias === sessionRequest.alias &&
          !accessClientVerificationActive &&
          activeRun === undefined &&
          !configurationMutationActive
        ) {
          accessClientVerificationActive = true;
          const controller = new AbortController();
          const run = { controller };
          activeRun = run;
          try {
            const result = await withGateway(
              options.gatewayFactory,
              (gateway) => gateway.checkTarget(
                { target: sessionRequest.alias },
                controller.signal,
              ),
            );
            let learnedStatus: ManagedSshFleetStatus | undefined;
            if (
              result.connected &&
              typeof result.hostname === "string" &&
              result.hostname.length > 0
            ) {
              learnedStatus = await learnAccessClientHostname(
                options,
                sessionRequest.alias,
                result.hostname,
              );
              snapshot = await preparer.verify(sessionRequest.alias, {
                hostname: result.hostname,
                durationMs: result.durationMs,
              });
            } else if (result.failureReason === "accessclient-host-mismatch") {
              snapshot = await preparer.reject(
                sessionRequest.alias,
                "The detected PuTTY session connected to a different machine",
              );
            } else {
              snapshot = preparer.status();
            }
            if (learnedStatus !== undefined) {
              writeJson(response, 200, {
                ...snapshot,
                status: publicFleetStatus(learnedStatus),
              });
              return;
            }
          } finally {
            accessClientVerificationActive = false;
            if (activeRun === run) activeRun = undefined;
          }
        }
        writeJson(response, 200, snapshot);
        return;
      }
      case "/api/admin/access-client/session/cancel": {
        const sessionRequest = adminAccessClientSessionRequestSchema.parse(
          await readJsonBody(request),
        );
        writeJson(
          response,
          200,
          await requireAccessClientSessionPreparer(options).cancel(
            sessionRequest.alias,
          ),
        );
        return;
      }
      case "/api/admin/group/create":
      case "/api/admin/group/rename":
      case "/api/admin/group/delete":
      case "/api/admin/group/move":
      case "/api/admin/group/reorder": {
        const groupRequest = adminGroupRequests[route].parse(await readJsonBody(request));
        const configuration = requireFleetConfigurationService(options);
        assertConfigurationMutationAvailable(activeRun, configurationMutationActive,
          accessClientPreparationRequestActive || accessClientPreparationIsActive(options));
        configurationMutationActive = true;
        try {
          const current = await configuration.fleetStatus();
          assertExpectedRevision(current.revision, groupRequest.expectedRevision);
          const profile = normalizeFleetGroups(current.profile ?? { version: 3, targets: {} });
          let groups = [...profile.groups!];
          const targets = { ...profile.targets };
          const requireCustomGroup = (name: string): void => {
            if (name === DEFAULT_TARGET_GROUP) throw new HttpProblem(409, "DEFAULT_GROUP_PROTECTED", "The default group cannot be renamed or deleted");
            if (!groups.includes(name)) throw new HttpProblem(404, "GROUP_NOT_FOUND", "The group no longer exists");
          };
          const requireNewName = (name: string): void => {
            if (name === DEFAULT_TARGET_GROUP) throw new HttpProblem(409, "DEFAULT_GROUP_PROTECTED", "The default group name is reserved");
            if (groups.includes(name)) throw new HttpProblem(409, "GROUP_EXISTS", "A group with this name already exists");
          };
          const moveTarget = (alias: string, destination: string | undefined): void => {
            if (!Object.hasOwn(targets, alias)) throw new HttpProblem(404, "TARGET_NOT_FOUND", "A selected target no longer exists");
            const { group: _oldGroup, ...target } = targets[alias]!;
            targets[alias] = { ...target, ...(destination === undefined ? {} : { group: destination }) };
          };
          if (route === "/api/admin/group/create" && "name" in groupRequest) {
            requireNewName(groupRequest.name);
            groups.push(groupRequest.name);
          } else if (route === "/api/admin/group/rename" && "group" in groupRequest && "name" in groupRequest && typeof groupRequest.name === "string") {
            const newName = groupRequest.name;
            requireCustomGroup(groupRequest.group!);
            if (newName !== groupRequest.group) requireNewName(newName);
            groups = groups.map((group) => group === groupRequest.group ? newName : group);
            for (const [alias, target] of Object.entries(targets)) if (target.group === groupRequest.group) moveTarget(alias, newName);
          } else if (route === "/api/admin/group/delete" && "group" in groupRequest) {
            requireCustomGroup(groupRequest.group!);
            groups = groups.filter((group) => group !== groupRequest.group);
            for (const [alias, target] of Object.entries(targets)) if (target.group === groupRequest.group) moveTarget(alias, undefined);
          } else if ("aliases" in groupRequest) {
            const destination = groupRequest.group === "" || groupRequest.group === DEFAULT_TARGET_GROUP ? undefined : groupRequest.group;
            if (destination !== undefined) requireCustomGroup(destination);
            for (const alias of groupRequest.aliases) moveTarget(alias, destination);
          } else if ("groups" in groupRequest) {
            if (groupRequest.groups.length !== groups.length || groupRequest.groups.some((group) => !groups.includes(group))) {
              throw new HttpProblem(409, "GROUP_ORDER_INVALID", "Group ordering must contain every custom group exactly once");
            }
            groups = groupRequest.groups;
          }
          writeJson(response, 200, publicFleetStatus(await configuration.applyFleet(
            managedSshFleetProfileSchema.parse({ ...profile, groups, targets }), groupRequest.expectedRevision,
          )));
        } finally { configurationMutationActive = false; }
        return;
      }
      case "/api/admin/target/save": {
        const saveRequest = adminTargetSaveRequestSchema.parse(
          await readJsonBody(request),
        );
        const configuration = requireFleetConfigurationService(options);
        assertConfigurationMutationAvailable(
          activeRun,
          configurationMutationActive,
          accessClientPreparationRequestActive ||
            accessClientPreparationIsActive(options),
        );
        configurationMutationActive = true;
        try {
          const current = await configuration.fleetStatus();
          assertExpectedRevision(current.revision, saveRequest.expectedRevision);
          const groups = normalizeFleetGroups(current.profile ?? { version: 3, targets: {} }).groups!;
          if (saveRequest.target.group === DEFAULT_TARGET_GROUP) delete saveRequest.target.group;
          if (saveRequest.target.group !== undefined && !groups.includes(saveRequest.target.group)) {
            throw new HttpProblem(404, "GROUP_NOT_FOUND", "Create the group before assigning a target to it");
          }
          const targets = { ...(current.profile?.targets ?? {}) };
          const previousAlias = saveRequest.previousAlias;
          let previousTarget: ManagedSshFleetTarget | undefined;
          if (previousAlias === undefined) {
            if (targetReferenceOwner(targets, saveRequest.alias) !== undefined) {
              throw new HttpProblem(
                409,
                "TARGET_EXISTS",
                "A target already owns this alias or identifier",
              );
            }
          } else {
            if (!Object.hasOwn(targets, previousAlias)) {
              throw new HttpProblem(
                404,
                "TARGET_NOT_FOUND",
                "The target being edited no longer exists",
              );
            }
            previousTarget = targets[previousAlias];
            const owner = targetReferenceOwner(
              targets,
              saveRequest.alias,
              previousAlias,
            );
            if (owner !== undefined) {
              throw new HttpProblem(
                409,
                "TARGET_EXISTS",
                "A target already owns this alias or identifier",
              );
            }
            delete targets[previousAlias];
          }
          const historicalAliases = new Map<string, string>();
          for (const historicalAlias of [
            ...(previousTarget?.previousAliases ?? []),
            ...(saveRequest.target.previousAliases ?? []),
            ...(previousAlias !== undefined && previousAlias !== saveRequest.alias
              ? [previousAlias]
              : []),
          ]) {
            if (historicalAlias.toLowerCase() !== saveRequest.alias.toLowerCase()) {
              historicalAliases.set(historicalAlias.toLowerCase(), historicalAlias);
            }
          }
          const accessClient = saveRequest.target.accessClient;
          const savedTarget: ManagedSshFleetTarget =
            saveRequest.target.connectionMode === "accessclient-share" &&
            accessClient !== undefined
              ? {
                  ...saveRequest.target,
                  accessClient: {
                    ...accessClient,
                    sharingHost:
                      accessClient.sharingHost ?? saveRequest.target.target.host,
                    sharingPort:
                      accessClient.sharingPort ??
                      (accessClient.sharingHost === undefined
                        ? saveRequest.target.target.port
                        : 22),
                  },
                }
              : { ...saveRequest.target };
          delete savedTarget.targetId;
          delete savedTarget.previousAliases;
          targets[saveRequest.alias] = {
            ...savedTarget,
            targetId: previousTarget?.targetId ?? createManagedTargetId(),
            ...(historicalAliases.size === 0
              ? {}
              : { previousAliases: [...historicalAliases.values()] }),
          };
          const profile = managedSshFleetProfileSchema.parse({
            version: 3,
            groups,
            ...(current.profile?.tailscale === undefined ? {} : { tailscale: current.profile.tailscale }),
            ...(current.profile?.accessClient === undefined
              ? {}
              : { accessClient: current.profile.accessClient }),
            targets,
          });
          writeJson(
            response,
            200,
            publicFleetStatus(
              await configuration.applyFleet(
                profile,
                saveRequest.expectedRevision,
              ),
            ),
          );
        } finally {
          configurationMutationActive = false;
        }
        return;
      }
      case "/api/admin/target/remove": {
        const removeRequest = adminTargetRemoveRequestSchema.parse(
          await readJsonBody(request),
        );
        const configuration = requireFleetConfigurationService(options);
        assertConfigurationMutationAvailable(
          activeRun,
          configurationMutationActive,
          accessClientPreparationRequestActive ||
            accessClientPreparationIsActive(options),
        );
        configurationMutationActive = true;
        try {
          const current = await configuration.fleetStatus();
          assertExpectedRevision(current.revision, removeRequest.expectedRevision);
          if (!Object.hasOwn(current.profile?.targets ?? {}, removeRequest.alias)) {
            throw new HttpProblem(
              404,
              "TARGET_NOT_FOUND",
              "The target being removed no longer exists",
            );
          }
          const targets = { ...(current.profile?.targets ?? {}) };
          delete targets[removeRequest.alias];
          const profile = managedSshFleetProfileSchema.parse({
            version: 3,
            groups: normalizeFleetGroups(current.profile!).groups,
            ...(current.profile?.tailscale === undefined ? {} : { tailscale: current.profile.tailscale }),
            ...(current.profile?.accessClient === undefined
              ? {}
              : { accessClient: current.profile.accessClient }),
            targets,
          });
          writeJson(
            response,
            200,
            publicFleetStatus(
              await configuration.applyFleet(
                profile,
                removeRequest.expectedRevision,
              ),
            ),
          );
        } finally {
          configurationMutationActive = false;
        }
        return;
      }
      case "/api/admin/target/enabled": {
        const enabledRequest = adminTargetEnabledRequestSchema.parse(
          await readJsonBody(request),
        );
        const configuration = requireFleetConfigurationService(options);
        assertConfigurationMutationAvailable(
          activeRun,
          configurationMutationActive,
          accessClientPreparationRequestActive ||
            accessClientPreparationIsActive(options),
        );
        configurationMutationActive = true;
        try {
          const current = await configuration.fleetStatus();
          assertExpectedRevision(current.revision, enabledRequest.expectedRevision);
          const savedTarget = current.profile?.targets[enabledRequest.alias];
          if (savedTarget === undefined) {
            throw new HttpProblem(
              404,
              "TARGET_NOT_FOUND",
              "The target being toggled no longer exists",
            );
          }
          if (savedTarget.enabled === enabledRequest.enabled) {
            writeJson(response, 200, publicFleetStatus(current));
            return;
          }
          const targets = {
            ...current.profile!.targets,
            [enabledRequest.alias]: {
              ...savedTarget,
              enabled: enabledRequest.enabled,
            },
          };
          const profile = managedSshFleetProfileSchema.parse({
            version: 3,
            groups: normalizeFleetGroups(current.profile!).groups,
            ...(current.profile?.tailscale === undefined ? {} : { tailscale: current.profile.tailscale }),
            ...(current.profile?.accessClient === undefined
              ? {}
              : { accessClient: current.profile.accessClient }),
            targets,
          });
          writeJson(
            response,
            200,
            publicFleetStatus(
              await configuration.applyFleet(
                profile,
                enabledRequest.expectedRevision,
              ),
            ),
          );
        } finally {
          configurationMutationActive = false;
        }
        return;
      }
      case "/api/admin/target/check": {
        requireFleetConfigurationService(options);
        const params = targetCheckParamsSchema.parse(await readJsonBody(request));
        if (configurationMutationActive) {
          throw new HttpProblem(
            409,
            "CONFIG_BUSY",
            "SSH configuration is currently being changed",
          );
        }
        if (activeRun !== undefined) {
          throw new HttpProblem(
            409,
            "RUN_ACTIVE",
            "Another SSH operation is already running",
          );
        }
        const controller = new AbortController();
        const run = { controller };
        activeRun = run;
        const abortForDisconnect = (): void => {
          if (!response.writableEnded) {
            controller.abort();
          }
        };
        request.once("aborted", abortForDisconnect);
        response.once("close", abortForDisconnect);
        try {
          const result = await withGateway(
            options.gatewayFactory,
            async (gateway) => {
              if (controller.signal.aborted) {
                throw new HttpProblem(499, "CLIENT_CLOSED", "Client disconnected");
              }
              return gateway.checkTarget(params, controller.signal);
            },
          );
          let learnedStatus: ManagedSshFleetStatus | undefined;
          if (
            result.connected &&
            typeof result.hostname === "string" &&
            result.hostname.length > 0
          ) {
            learnedStatus = await learnAccessClientHostname(
              options,
              params.target,
              result.hostname,
            );
          }
          if (!response.destroyed) {
            writeJson(response, 200, {
              ...result,
              ...(learnedStatus === undefined
                ? {}
                : { status: publicFleetStatus(learnedStatus) }),
            });
          }
        } finally {
          request.off("aborted", abortForDisconnect);
          response.off("close", abortForDisconnect);
          if (activeRun === run) {
            activeRun = undefined;
          }
        }
        return;
      }
      default:
        throw new HttpProblem(404, "NOT_FOUND", "Resource was not found");
    }
  };

  await new Promise<void>((resolveListen, rejectListen) => {
    const onError = (error: Error): void => rejectListen(error);
    server.once("error", onError);
    server.listen({ host: LOOPBACK_HOST, port, exclusive: true }, () => {
      server.off("error", onError);
      const address = server.address();
      if (address === null || typeof address === "string") {
        rejectListen(new Error("Test UI server did not receive a TCP port"));
        return;
      }
      expectedHost = `${LOOPBACK_HOST}:${address.port}`;
      expectedOrigin = `http://${expectedHost}`;
      resolveListen();
    });
  });

  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("Test UI server is not listening on TCP");
  }
  const origin = `http://${LOOPBACK_HOST}:${address.port}`;

  return {
    origin,
    url: `${origin}/#token=${sessionToken}`,
    sessionToken,
    port: address.port,
    async close(): Promise<void> {
      if (closed) {
        return;
      }
      closed = true;
      activeRun?.controller.abort();
      resultReferences.clear();
      const closeErrors: unknown[] = [];
      try {
        await options.accessClientSessionPreparer?.close();
      } catch (error) {
        closeErrors.push(error);
      }
      try {
        await new Promise<void>((resolveClose) => {
          server.close(() => resolveClose());
          server.closeAllConnections();
        });
      } catch (error) {
        closeErrors.push(error);
      }
      try {
        await options.configurationService?.close();
      } catch (error) {
        closeErrors.push(error);
      }
      if (closeErrors.length > 0) {
        throw new AggregateError(closeErrors, "Test UI server could not close safely");
      }
    },
  };
}

function configureHttpServer(server: Server): void {
  server.maxConnections = 16;
  server.maxHeadersCount = 32;
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;
  server.keepAliveTimeout = 2_000;
}

async function loadStaticAssets(directory: string): Promise<Map<string, StaticAsset>> {
  const [html, css, script] = await Promise.all([
    readFile(`${directory}/index.html`),
    readFile(`${directory}/styles.css`),
    readFile(`${directory}/app.js`),
  ]);
  return new Map([
    ["/", { contentType: "text/html; charset=utf-8", body: html }],
    ["/index.html", { contentType: "text/html; charset=utf-8", body: html }],
    ["/styles.css", { contentType: "text/css; charset=utf-8", body: css }],
    ["/app.js", { contentType: "text/javascript; charset=utf-8", body: script }],
  ]);
}

function applySecurityHeaders(response: ServerResponse): void {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
  );
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
}

function assertBrowserApiRequest(
  request: IncomingMessage,
  expectedOrigin: string,
  sessionToken: string,
  browserSession: BrowserSession,
): void {
  if (request.headers.origin !== expectedOrigin) {
    throw new HttpProblem(403, "INVALID_ORIGIN", "Request origin was rejected");
  }
  const fetchSite = request.headers["sec-fetch-site"];
  if (fetchSite !== undefined && fetchSite !== "same-origin") {
    throw new HttpProblem(403, "CROSS_SITE_REQUEST", "Cross-site request was rejected");
  }
  const providedToken = request.headers["x-agent-ssh-ui-token"];
  if (
    !(typeof providedToken === "string" && constantTimeTextEquals(providedToken, sessionToken)) &&
    !browserSession.accepts(request.headers.cookie, expectedOrigin)
  ) {
    throw new HttpProblem(403, "INVALID_SESSION", "Test UI session was rejected");
  }
  const contentType = request.headers["content-type"]?.split(";", 1)[0]?.trim();
  if (contentType !== "application/json") {
    throw new HttpProblem(415, "JSON_REQUIRED", "Content-Type must be application/json");
  }
}

function constantTimeTextEquals(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  if (leftBytes.length !== rightBytes.length) {
    timingSafeEqual(rightBytes, rightBytes);
    return false;
  }
  return timingSafeEqual(leftBytes, rightBytes);
}

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const declaredLength = Number(request.headers["content-length"] ?? 0);
  if (
    Number.isFinite(declaredLength) &&
    declaredLength > MAX_REQUEST_BODY_BYTES
  ) {
    request.resume();
    throw new HttpProblem(413, "BODY_TOO_LARGE", "Request body is too large");
  }
  const chunks: Buffer[] = [];
  let totalBytes = 0;
  for await (const rawChunk of request) {
    const chunk = Buffer.isBuffer(rawChunk)
      ? rawChunk
      : Buffer.from(rawChunk as Uint8Array);
    totalBytes += chunk.length;
    if (totalBytes > MAX_REQUEST_BODY_BYTES) {
      request.resume();
      throw new HttpProblem(413, "BODY_TOO_LARGE", "Request body is too large");
    }
    chunks.push(Buffer.from(chunk));
  }
  const body = Buffer.concat(chunks, totalBytes);
  if (!isUtf8(body)) {
    throw new HttpProblem(400, "INVALID_JSON", "Request body is not valid UTF-8");
  }
  try {
    return JSON.parse(body.toString("utf8")) as unknown;
  } catch {
    throw new HttpProblem(400, "INVALID_JSON", "Request body is not valid JSON");
  }
}

async function withGateway<Result>(
  factory: TestUiGatewayFactory,
  operation: (gateway: TestUiGatewaySession) => Promise<Result>,
): Promise<Result> {
  let gateway: TestUiGatewaySession;
  try {
    gateway = await factory();
  } catch {
    throw new HttpProblem(
      503,
      "GATEWAY_UNAVAILABLE",
      "SSH gateway is not available",
    );
  }
  try {
    return await operation(gateway);
  } finally {
    gateway.close();
  }
}

function registerResultReference(
  references: Map<string, ResultReference>,
  result: {
    readonly outputRef?: unknown;
    readonly outputExpiresAt?: unknown;
  },
): { readonly resultId: string; readonly outputExpiresAt: string } | undefined {
  if (
    typeof result.outputRef !== "string" ||
    typeof result.outputExpiresAt !== "string"
  ) {
    return undefined;
  }
  const expiresAtMs = Date.parse(result.outputExpiresAt);
  if (!Number.isFinite(expiresAtMs)) return undefined;
  cleanupResultReferences(references);
  while (references.size >= MAX_RESULT_REFERENCES) {
    const oldest = references.keys().next().value as string | undefined;
    if (oldest === undefined) {
      break;
    }
    references.delete(oldest);
  }
  const resultId = randomBytes(32).toString("base64url");
  references.set(resultId, {
    outputRef: result.outputRef,
    expiresAtMs,
  });
  return { resultId, outputExpiresAt: result.outputExpiresAt };
}

function publicTaskStatus(
  references: Map<string, ResultReference>,
  status: Awaited<ReturnType<NonNullable<TestUiGatewaySession["taskStatus"]>>>,
): Readonly<Record<string, unknown>> {
  if (status.result === undefined) return status;

  const publicResult: Record<string, unknown> = { ...status.result };
  delete publicResult["outputRef"];
  delete publicResult["outputExpiresAt"];
  const reference =
    status.state === "running"
      ? undefined
      : registerResultReference(references, status.result);
  return {
    ...status,
    result: publicResult,
    ...(reference === undefined ? {} : reference),
  };
}

async function alignUtf8TextChunk(
  offset: number,
  chunk: OutputChunk,
  readMore: (offset: number, limit: number) => Promise<OutputChunk>,
): Promise<OutputChunk> {
  if (chunk.eof || chunk.dataBase64.length === 0) {
    return chunk;
  }
  const bytes = Buffer.from(chunk.dataBase64, "base64");
  const completeBytes = completeUtf8PrefixLength(bytes);
  if (completeBytes === bytes.length) {
    return chunk;
  }
  if (completeBytes === 0) {
    const missingBytes = utf8SequenceLength(bytes[0]!) - bytes.byteLength;
    if (missingBytes > 0) {
      const extra = await readMore(offset + bytes.byteLength, missingBytes);
      const combined = Buffer.concat([
        bytes,
        Buffer.from(extra.dataBase64, "base64"),
      ]);
      if (completeUtf8PrefixLength(combined) > 0 && isUtf8(combined)) {
        const nextOffset = offset + combined.byteLength;
        const eof = nextOffset >= chunk.totalBytes;
        return {
          dataBase64: combined.toString("base64"),
          nextOffset: eof ? null : nextOffset,
          eof,
          totalBytes: chunk.totalBytes,
        };
      }
    }
    // Invalid or truncated UTF-8 still advances by the gateway's byte page.
    return chunk;
  }
  return {
    ...chunk,
    dataBase64: bytes.subarray(0, completeBytes).toString("base64"),
    nextOffset: offset + completeBytes,
  };
}

function utf8SequenceLength(lead: number): number {
  if (lead >= 0xc2 && lead <= 0xdf) return 2;
  if (lead >= 0xe0 && lead <= 0xef) return 3;
  if (lead >= 0xf0 && lead <= 0xf4) return 4;
  return 1;
}

function cleanupResultReferences(references: Map<string, ResultReference>): void {
  const now = Date.now();
  for (const [resultId, reference] of references) {
    if (reference.expiresAtMs <= now) {
      references.delete(resultId);
    }
  }
}

function toHttpProblem(error: unknown): HttpProblem {
  if (error instanceof HttpProblem) {
    return error;
  }
  if (error instanceof z.ZodError) {
    return new HttpProblem(400, "INVALID_REQUEST", "Request parameters are invalid");
  }
  if (error instanceof RpcRemoteError) {
    const gatewayCode = extractGatewayCode(error.data);
    return new HttpProblem(
      statusForGatewayCode(gatewayCode),
      gatewayCode ?? "GATEWAY_REJECTED",
      error.message,
    );
  }
  if (error instanceof ManagedSshError) {
    return new HttpProblem(error.status, error.code, error.message);
  }
  if (error instanceof AccessClientSessionError) {
    return new HttpProblem(error.status, error.code, error.message);
  }
  return new HttpProblem(500, "INTERNAL_ERROR", "Test UI request failed");
}

function publicFleetStatus(
  status: ManagedSshFleetStatus,
): ManagedSshFleetStatus {
  return {
    state: status.state,
    configured: status.configured,
    defaultKnownHostsFile: status.defaultKnownHostsFile,
    commandPresets: status.commandPresets,
    keyRevision: status.keyRevision,
    keys: status.keys.map((key) => ({
      keyId: key.keyId,
      label: key.label,
      algorithm: key.algorithm,
      fingerprint: key.fingerprint,
      publicKey: key.publicKey,
      createdAt: key.createdAt,
      origin: key.origin,
      inUseBy: key.inUseBy.map((reference) => ({
        alias: reference.alias,
        ...(reference.targetId === undefined
          ? {}
          : { targetId: reference.targetId }),
        role: reference.role,
      })),
    })),
    ...(status.revision === undefined ? {} : { revision: status.revision }),
    ...(status.profile === undefined
      ? {}
      : { profile: normalizeFleetGroups(managedSshFleetProfileSchema.parse(status.profile)) }),
    ...(status.error === undefined
      ? {}
      : {
          error: {
            code: status.error.code,
            message: status.error.message,
          },
        }),
    ...(status.keyError === undefined
      ? {}
      : {
          keyError: {
            code: status.keyError.code,
            message: status.keyError.message,
          },
        }),
  };
}

function isSafePrivateKeySourcePath(value: string): boolean {
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
  return (
    /^[A-Za-z]:\\/u.test(windowsValue) &&
    !windowsValue.slice(3).includes(":")
  );
}

function requireConfigurationService(
  options: TestUiServerOptions,
): TestUiConfigurationService {
  if (options.mode !== "managed" || options.configurationService === undefined) {
    throw new HttpProblem(404, "NOT_FOUND", "Resource was not found");
  }
  return options.configurationService;
}

function requireLegacyConfigurationService(
  options: TestUiServerOptions,
): TestUiConfigurationService {
  if (options.legacySetupRoutes !== true) {
    throw new HttpProblem(404, "NOT_FOUND", "Resource was not found");
  }
  return requireConfigurationService(options);
}

type FleetConfigurationService = TestUiConfigurationService & {
  fleetStatus(): Promise<ManagedSshFleetStatus>;
  applyFleet(
    profile: ManagedSshFleetProfile,
    expectedRevision?: string,
  ): Promise<ManagedSshFleetStatus>;
};

function requireFleetConfigurationService(
  options: TestUiServerOptions,
): FleetConfigurationService {
  const configuration = requireConfigurationService(options);
  if (
    typeof configuration.fleetStatus !== "function" ||
    typeof configuration.applyFleet !== "function" ||
    typeof configuration.keyStatus !== "function" ||
    typeof configuration.generateManagedKey !== "function" ||
    typeof configuration.importManagedKey !== "function" ||
    typeof configuration.renameManagedKey !== "function" ||
    typeof configuration.removeManagedKey !== "function"
  ) {
    throw new HttpProblem(404, "NOT_FOUND", "Resource was not found");
  }
  return configuration as FleetConfigurationService;
}

function requireAccessClientSessionPreparer(
  options: TestUiServerOptions,
): AccessClientSessionPreparer {
  requireFleetConfigurationService(options);
  if (options.accessClientSessionPreparer === undefined) {
    throw new HttpProblem(
      501,
      "ACCESSCLIENT_PREPARATION_UNSUPPORTED",
      "AccessClient session preparation is available only on Windows",
    );
  }
  return options.accessClientSessionPreparer;
}

function accessClientPreparationIsActive(options: TestUiServerOptions): boolean {
  const state = options.accessClientSessionPreparer?.status().state;
  return state === "armed" || state === "detected";
}

async function resolveSavedAccessClientTarget(
  options: TestUiServerOptions,
  alias: string,
  expectedRevision: string,
): Promise<ManagedSshFleetTarget & {
  readonly connectionMode: "accessclient-share";
  readonly accessClient: NonNullable<ManagedSshFleetTarget["accessClient"]>;
}> {
  const configuration = requireFleetConfigurationService(options);
  const current = await configuration.fleetStatus();
  assertExpectedRevision(current.revision, expectedRevision);
  const target = current.profile?.targets[alias];
  if (target === undefined) {
    throw new HttpProblem(404, "TARGET_NOT_FOUND", "The saved target was not found");
  }
  if (
    target.connectionMode !== "accessclient-share" ||
    target.accessClient === undefined
  ) {
    throw new HttpProblem(
      422,
      "TARGET_NOT_ACCESSCLIENT",
      "The saved target does not use AccessClient shared sessions",
    );
  }
  if (!target.enabled) {
    throw new HttpProblem(403, "TARGET_DISABLED", "The saved target is disabled");
  }
  return {
    ...target,
    connectionMode: "accessclient-share",
    accessClient: target.accessClient,
  };
}

async function learnAccessClientHostname(
  options: TestUiServerOptions,
  reference: string,
  hostname: string,
): Promise<ManagedSshFleetStatus | undefined> {
  const configuration = requireFleetConfigurationService(options);
  const current = await configuration.fleetStatus();
  const owner = targetReferenceOwner(current.profile?.targets ?? {}, reference);
  if (owner === undefined) return undefined;
  const target = current.profile?.targets[owner];
  if (
    target?.connectionMode !== "accessclient-share" ||
    target.accessClient === undefined ||
    target.accessClient.expectedHostname !== undefined
  ) {
    return undefined;
  }
  const profile = managedSshFleetProfileSchema.parse({
    version: 3,
    groups: normalizeFleetGroups(current.profile!).groups,
    ...(current.profile?.tailscale === undefined ? {} : { tailscale: current.profile.tailscale }),
    ...(current.profile?.accessClient === undefined
      ? {}
      : { accessClient: current.profile.accessClient }),
    targets: {
      ...current.profile?.targets,
      [owner]: {
        ...target,
        accessClient: {
          ...target.accessClient,
          expectedHostname: hostname,
        },
      },
    },
  });
  return configuration.applyFleet(profile, current.revision);
}

function targetReferenceOwner(
  targets: Readonly<Record<string, ManagedSshFleetTarget>>,
  reference: string,
  ignoredAlias?: string,
): string | undefined {
  const folded = reference.toLowerCase();
  for (const [alias, target] of Object.entries(targets)) {
    if (alias === ignoredAlias) {
      continue;
    }
    if (
      alias.toLowerCase() === folded ||
      target.targetId?.toLowerCase() === folded ||
      (target.previousAliases ?? []).some(
        (historicalAlias) => historicalAlias.toLowerCase() === folded,
      )
    ) {
      return alias;
    }
  }
  return undefined;
}

function assertExpectedRevision(
  actual: string | undefined,
  expected: string | undefined,
): void {
  if (actual !== expected) {
    throw new HttpProblem(
      409,
      "CONFIG_CONFLICT",
      "The SSH configuration changed after this page loaded",
    );
  }
}

function assertConfigurationMutationAvailable(
  activeRun: ActiveRun | undefined,
  configurationMutationActive: boolean,
  accessClientPreparationActive = false,
): void {
  if (activeRun !== undefined) {
    throw new HttpProblem(
      409,
      "RUN_ACTIVE",
      "The SSH configuration cannot change while a command is running",
    );
  }
  if (configurationMutationActive) {
    throw new HttpProblem(
      409,
      "CONFIG_BUSY",
      "Another SSH configuration operation is still running",
    );
  }
  if (accessClientPreparationActive) {
    throw new HttpProblem(
      409,
      "ACCESSCLIENT_PREPARATION_BUSY",
      "SSH configuration cannot change while an AccessClient target is being prepared",
    );
  }
}

function assertForegroundOperationAvailable(
  activeRun: ActiveRun | undefined,
  configurationMutationActive: boolean,
): void {
  if (configurationMutationActive) {
    throw new HttpProblem(
      409,
      "CONFIG_BUSY",
      "SSH configuration is currently being changed",
    );
  }
  if (activeRun !== undefined) {
    throw new HttpProblem(
      409,
      "RUN_ACTIVE",
      "Another SSH operation is already running",
    );
  }
}

function assertTaskStartAvailable(configurationMutationActive: boolean): void {
  if (configurationMutationActive) {
    throw new HttpProblem(
      409,
      "CONFIG_BUSY",
      "SSH configuration is currently being changed",
    );
  }
}

function capabilityUnavailable(): HttpProblem {
  return new HttpProblem(
    501,
    "CAPABILITY_UNAVAILABLE",
    "This gateway does not provide the requested operation",
  );
}

function extractGatewayCode(data: unknown): string | undefined {
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    return undefined;
  }
  const gatewayCode = (data as Record<string, unknown>).gatewayCode;
  return typeof gatewayCode === "string" && /^[A-Z_]{3,64}$/u.test(gatewayCode)
    ? gatewayCode
    : undefined;
}

function statusForGatewayCode(code: string | undefined): number {
  switch (code) {
    case GATEWAY_ERROR_CODES.invalidParams:
      return 400;
    case GATEWAY_ERROR_CODES.targetNotFound:
    case GATEWAY_ERROR_CODES.executionNotFound:
    case GATEWAY_ERROR_CODES.outputNotFound:
      return 404;
    case GATEWAY_ERROR_CODES.targetDisabled:
    case GATEWAY_ERROR_CODES.commandDenied:
    case GATEWAY_ERROR_CODES.transferDenied:
      return 403;
    case GATEWAY_ERROR_CODES.executionLimitReached:
      return 409;
    case GATEWAY_ERROR_CODES.checksumMismatch:
      return 422;
    case GATEWAY_ERROR_CODES.transferFailed:
      return 424;
    case GATEWAY_ERROR_CODES.outputExpired:
      return 410;
    case GATEWAY_ERROR_CODES.auditUnavailable:
    case GATEWAY_ERROR_CODES.daemonNotActive:
    case GATEWAY_ERROR_CODES.sftpUnavailable:
      return 503;
    default:
      return 500;
  }
}

interface InteractiveSshInstallOptions {
  readonly host: string;
  readonly port: number;
  readonly username: string;
  readonly knownHostsFile: string;
  readonly platform: "windows" | "linux" | "macos";
  readonly publicKey: string;
}

function launchInteractiveSshInstall(
  options: InteractiveSshInstallOptions,
): void {
  const remoteCommand = buildSshInstallRemoteCommand(
    options.platform,
    options.publicKey,
  );
  const sshArguments = [
    "/usr/bin/ssh",
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "PubkeyAuthentication=no",
    "-o",
    "PreferredAuthentications=password,keyboard-interactive",
    "-o",
    `UserKnownHostsFile=${options.knownHostsFile}`,
    "-o",
    "StrictHostKeyChecking=yes",
    "-p",
    String(options.port),
    `${options.username}@${options.host}`,
    remoteCommand,
  ];

  if (process.platform === "darwin") {
    const command = sshArguments.map(shellQuotePosix).join(" ");
    const appleScript = [
      "tell application \"Terminal\"",
      "activate",
      `do script ${appleScriptQuote(command)}`,
      "end tell",
    ].join("\n");
    const child = spawn("/usr/bin/osascript", ["-e", appleScript], {
      detached: true,
      stdio: "ignore",
    });
    child.once("error", () => undefined);
    child.unref();
    return;
  }

  if (process.platform === "win32") {
    const command = [
      "ssh.exe",
      "-o",
      "IdentitiesOnly=yes",
      "-o",
      "PubkeyAuthentication=no",
      "-o",
      "PreferredAuthentications=password,keyboard-interactive",
      "-o",
      `UserKnownHostsFile=${options.knownHostsFile}`,
      "-o",
      "StrictHostKeyChecking=yes",
      "-p",
      String(options.port),
      `${options.username}@${options.host}`,
      remoteCommand,
    ].map(shellQuotePowerShell).join(" ");
    const child = spawn(
      process.env.ComSpec ?? "cmd.exe",
      ["/d", "/c", "start", "\"SSH 公钥安装\"", "powershell.exe", "-NoLogo", "-NoExit", "-Command", command],
      { detached: true, stdio: "ignore", windowsHide: false },
    );
    child.once("error", () => undefined);
    child.unref();
    return;
  }

  const command = sshArguments.map(shellQuotePosix).join(" ");
  const child = spawn(
    "x-terminal-emulator",
    ["-e", "sh", "-lc", `${command}; printf '\\nSSH 公钥安装命令已结束，按回车关闭。'; read -r`],
    { detached: true, stdio: "ignore" },
  );
  child.once("error", () => undefined);
  child.unref();
}

function buildSshInstallRemoteCommand(
  platform: InteractiveSshInstallOptions["platform"],
  publicKey: string,
): string {
  if (platform === "windows") {
    const script = `$k='${publicKey}';$utf8=[Text.UTF8Encoding]::new($false);$id=[Security.Principal.WindowsIdentity]::GetCurrent();$p=[Security.Principal.WindowsPrincipal]::new($id);if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){$d=Join-Path $env:ProgramData 'ssh';$f=Join-Path $d 'administrators_authorized_keys'}else{$d=Join-Path $env:USERPROFILE '.ssh';$f=Join-Path $d 'authorized_keys'};[IO.Directory]::CreateDirectory($d)|Out-Null;if(!(Test-Path -LiteralPath $f)){[IO.File]::WriteAllText($f,'',$utf8)};$parts=$k -split ' ';$exists=[IO.File]::ReadAllLines($f)|Where-Object{$line=$_ -split '\\s+';for($i=0;$i-lt $line.Count-1;$i++){if($line[$i] -ceq $parts[0] -and $line[$i+1] -ceq $parts[1]){return $true}}return $false}|Select-Object -First 1;if(!$exists){[IO.File]::AppendAllText($f,[Environment]::NewLine+$k+[Environment]::NewLine,$utf8)};if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){& icacls.exe $d /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F'|Out-Null;& icacls.exe $f /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F'|Out-Null}else{$sid=$id.User.Value;& icacls.exe $d /inheritance:r /grant:r \"*$($sid):(OI)(CI)F\" '*S-1-5-18:(OI)(CI)F'|Out-Null;& icacls.exe $f /inheritance:r /grant:r \"*$($sid):F\" '*S-1-5-18:F'|Out-Null};Write-Output 'SSH public key installed.'`;
    return `powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ${Buffer.from(script, "utf16le").toString("base64")}`;
  }
  const quotedKey = shellQuotePosix(publicKey);
  return `umask 077; k=${quotedKey}; d="$HOME/.ssh"; f="$d/authorized_keys"; mkdir -p "$d" && chmod 700 "$d" && touch "$f" && chmod 600 "$f" && { awk -v k="$k" 'BEGIN { split(k,p," ") } { for (i=1; i<NF; i++) if ($i==p[1] && $(i+1)==p[2]) found=1 } END { exit found ? 0 : 1 }' "$f" || printf '\\n%s\\n' "$k" >> "$f"; }; printf 'SSH public key installed.\\n'`;
}

function shellQuotePosix(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function shellQuotePowerShell(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

function appleScriptQuote(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("\n", "\\n")}"`;
}

function writeProblem(response: ServerResponse, problem: HttpProblem): void {
  if (response.destroyed || response.writableEnded) {
    return;
  }
  writeJson(response, problem.status, {
    error: { code: problem.code, message: problem.message },
  });
}

function writeJson(response: ServerResponse, status: number, value: unknown): void {
  if (response.destroyed || response.writableEnded) {
    return;
  }
  const body = Buffer.from(JSON.stringify(value), "utf8");
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Content-Length", body.length);
  response.end(body);
}

function validatePort(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 65_535) {
    throw new RangeError("port must be an integer from 0 through 65535");
  }
  return value;
}
