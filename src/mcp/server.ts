import { spawn } from "node:child_process";
import path from "node:path";

import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";

import { readAdminDescriptor } from "../service/control-plane.js";
import {
  dockerPreflightParamsSchema,
  dockerPreflightResultSchema,
  downloadParamsSchema,
  execResultSchema,
  execRunParamsSchema,
  outputChunkSchema,
  outputReadParamsSchema,
  outputReadTextParamsSchema,
  outputTextChunkSchema,
  pingResultSchema,
  targetCheckParamsSchema,
  targetCheckResultSchema,
  targetInspectParamsSchema,
  targetInspectResultSchema,
  targetListResultSchema,
  targetSummarySchema,
  taskCancelParamsSchema,
  taskCancelResultSchema,
  taskStartResultSchema,
  taskStatusParamsSchema,
  taskStatusResultSchema,
  taskTailParamsSchema,
  taskTailResultSchema,
  uploadParamsSchema,
  syncParamsSchema,
} from "../shared/protocol.js";
import { GatewayRpcClient } from "../shared/rpc-client.js";
import { GATEWAY_VERSION } from "../shared/version.js";

export type GatewayRpcClientFactory = () => Promise<GatewayRpcClient>;

export interface McpServerOptions {
  readonly dataDirectory?: string;
  readonly openAdmin?: (url: string) => Promise<void>;
}

const gatewayStatusResultSchema = z.strictObject({
  serviceRunning: z.boolean(),
  gatewayReady: z.boolean(),
  adminAvailable: z.boolean(),
  protocolVersion: z.number().int().positive().optional(),
  targets: z.array(targetSummarySchema),
});

const openAdminResultSchema = z.discriminatedUnion("opened", [
  z.strictObject({
    opened: z.literal(true),
  }),
  z.strictObject({
    opened: z.literal(false),
    message: z.string(),
  }),
]);

export function createGatewayRpcClientFactory(
  dataDirectory: string,
): GatewayRpcClientFactory {
  return () =>
    GatewayRpcClient.connect(dataDirectory, {
      name: "agent-ssh-mcp",
      version: GATEWAY_VERSION,
    });
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

async function withGatewayClient<Result>(
  factory: GatewayRpcClientFactory,
  operation: (client: GatewayRpcClient) => Promise<Result>,
): Promise<Result> {
  const client = await factory();
  try {
    return await operation(client);
  } finally {
    client.close();
  }
}

export function createMcpServer(
  clientFactory: GatewayRpcClientFactory,
  options: McpServerOptions = {},
): McpServer {
  const server = new McpServer(
    { name: "agent-ssh-mcp", version: GATEWAY_VERSION },
    { capabilities: { tools: {} } },
  );

  server.registerTool(
    "ssh_gateway_status",
    {
      description:
        "Report whether the local SSH management service and Gateway are ready, plus the configured target summaries.",
      outputSchema: gatewayStatusResultSchema,
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    async () => {
      const adminAvailable = await adminIsAvailable(options.dataDirectory);
      try {
        const { ping, targets } = await withGatewayClient(
          clientFactory,
          async (client) => {
            const [ping, targets] = await Promise.all([
              client.request("system.ping", {}),
              client.request("target.list", {}),
            ]);
            return { ping, targets };
          },
        );
        return toolResult({
          serviceRunning: adminAvailable,
          gatewayReady: ping.ok,
          adminAvailable,
          protocolVersion: ping.protocolVersion,
          targets: targets.targets,
        });
      } catch {
        return toolResult({
          serviceRunning: adminAvailable,
          gatewayReady: false,
          adminAvailable,
          targets: [],
        });
      }
    },
  );

  server.registerTool(
    "ssh_open_admin",
    {
      description:
        "Open the local SSH management center in the Windows default browser without exposing its administrator token to the MCP caller.",
      outputSchema: openAdminResultSchema,
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    async () => {
      const descriptor = await getAdminDescriptor(options.dataDirectory);
      if (descriptor === undefined) {
        return toolResult({
          opened: false,
          message: "SSH management service is not running.",
        });
      }
      try {
        await (options.openAdmin ?? openAdminInDefaultBrowser)(descriptor.url);
        return toolResult({ opened: true });
      } catch {
        return toolResult({
          opened: false,
          message: "SSH management center could not be opened.",
        });
      }
    },
  );

  server.registerTool(
    "ssh_ping",
    {
      description: "Check whether the local Agent SSH Gateway daemon is ready.",
      outputSchema: pingResultSchema,
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    async () =>
      toolResult(
        await withGatewayClient(clientFactory, (client) =>
          client.request("system.ping", {}),
        ),
      ),
  );

  server.registerTool(
    "ssh_list_targets",
    {
      description:
        "List immutable SSH target IDs, current display aliases, remote platforms, and effective command and file-transfer policy status. Tools accept either the targetId or a current/retained alias.",
      outputSchema: targetListResultSchema,
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    async () =>
      toolResult(
        await withGatewayClient(clientFactory, (client) =>
          client.request("target.list", {}),
        ),
      ),
  );

  server.registerTool(
    "ssh_check_connection",
    {
      description:
        "Check one configured SSH target with the Gateway's fixed hostname probe. Known AccessClient failures are returned as a closed, non-sensitive failureReason; remote stderr is never returned. No command or timeout can be supplied by the caller.",
      inputSchema: targetCheckParamsSchema,
      outputSchema: targetCheckResultSchema,
      annotations: {
        readOnlyHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async (args, context) => {
      context.mcpReq.signal.throwIfAborted();
      return toolResult(
        await withGatewayClient(clientFactory, (client) =>
          client.check(args, context.mcpReq.signal),
        ),
      );
    },
  );

  server.registerTool(
    "ssh_exec",
    {
      description:
        "Run a command synchronously on an SSH target. Accepts the compatible single command form or a full-access structured shell/script/cwd/env form. Prefer ssh_start for builds, downloads, and other long work.",
      inputSchema: execRunParamsSchema,
      outputSchema: execResultSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async (args, context) => {
      context.mcpReq.signal.throwIfAborted();
      return toolResult(
        await withGatewayClient(clientFactory, (client) =>
          client.run(args, context.mcpReq.signal),
        ),
      );
    },
  );

  server.registerTool(
    "ssh_start",
    {
      description:
        "Start a daemon-owned SSH execution and return a runId immediately. The task continues across MCP client disconnects; use ssh_status and ssh_tail to follow it.",
      inputSchema: execRunParamsSchema,
      outputSchema: taskStartResultSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async (args, context) => {
      context.mcpReq.signal.throwIfAborted();
      return toolResult(
        await withGatewayClient(clientFactory, (client) =>
          client.request("task.start", args),
        ),
      );
    },
  );

  server.registerTool(
    "ssh_status",
    {
      description: "Read the current state and progress counters of a daemon-owned SSH task.",
      inputSchema: taskStatusParamsSchema,
      outputSchema: taskStatusResultSchema,
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    async (args) =>
      toolResult(
        await withGatewayClient(clientFactory, (client) =>
          client.request("task.status", args),
        ),
      ),
  );

  server.registerTool(
    "ssh_tail",
    {
      description:
        "Read new UTF-8 stdout and stderr from a daemon-owned task using an opaque cursor. No Base64 decoding or byte-offset bookkeeping is required.",
      inputSchema: taskTailParamsSchema,
      outputSchema: taskTailResultSchema,
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    async (args) =>
      toolResult(
        await withGatewayClient(clientFactory, (client) =>
          client.request("task.tail", args),
        ),
      ),
  );

  server.registerTool(
    "ssh_cancel",
    {
      description: "Cancel a running daemon-owned SSH execution or transfer by runId.",
      inputSchema: taskCancelParamsSchema,
      outputSchema: taskCancelResultSchema,
      annotations: { readOnlyHint: false, idempotentHint: true },
    },
    async (args) =>
      toolResult(
        await withGatewayClient(clientFactory, (client) =>
          client.request("task.cancel", args),
        ),
      ),
  );

  server.registerTool(
    "ssh_upload",
    {
      description:
        "Start an SFTP upload. Restricted targets require an approved localRoot and a relative localPath. Full-access targets may omit localRoot and use a gateway-local absolute localPath; remotePath must be a legal target-native absolute path. expectedSha256 accepts uppercase or lowercase hexadecimal.",
      inputSchema: uploadParamsSchema,
      outputSchema: taskStartResultSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async (args) =>
      toolResult(
        await withGatewayClient(clientFactory, (client) =>
          client.request("transfer.upload", args),
        ),
      ),
  );

  server.registerTool(
    "ssh_download",
    {
      description:
        "Start an SFTP download. Restricted targets require an approved localRoot and a relative localPath. Full-access targets may omit localRoot and use a gateway-local absolute localPath; remotePath must be a legal target-native absolute path. expectedSha256 accepts uppercase or lowercase hexadecimal.",
      inputSchema: downloadParamsSchema,
      outputSchema: taskStartResultSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async (args) =>
      toolResult(
        await withGatewayClient(clientFactory, (client) =>
          client.request("transfer.download", args),
        ),
      ),
  );

  server.registerTool(
    "ssh_sync",
    {
      description:
        "Start a non-destructive one-way local-to-remote directory sync. Restricted targets require an approved localRoot and a relative localPath. Full-access targets may omit localRoot and use a gateway-local absolute localPath. Supports exclusions and dryRun.",
      inputSchema: syncParamsSchema,
      outputSchema: taskStartResultSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async (args) =>
      toolResult(
        await withGatewayClient(clientFactory, (client) =>
          client.request("transfer.sync", args),
        ),
      ),
  );

  server.registerTool(
    "ssh_target_info",
    {
      description:
        "Inspect one target with a fixed read-only probe and return machine identity, OS, disk, Docker/Compose status, and trusted SSH host-key fingerprints.",
      inputSchema: targetInspectParamsSchema,
      outputSchema: targetInspectResultSchema,
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    },
    async (args) =>
      toolResult(
        await withGatewayClient(clientFactory, (client) =>
          client.request("target.inspect", args),
        ),
      ),
  );

  server.registerTool(
    "ssh_docker_preflight",
    {
      description:
        "Run a fixed read-only Docker deployment preflight for create, update, or inspect intent: daemon/context, Compose configuration, port ownership, project-label-filtered containers, health, and free disk. requiredFreeBytes may be checked without a project.",
      inputSchema: dockerPreflightParamsSchema,
      outputSchema: dockerPreflightResultSchema,
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    },
    async (args) =>
      toolResult(
        await withGatewayClient(clientFactory, (client) =>
          client.request("docker.preflight", args),
        ),
      ),
  );

  server.registerTool(
    "ssh_read_output",
    {
      description:
        "Read a bounded page of retained stdout or stderr by opaque reference.",
      inputSchema: outputReadParamsSchema,
      outputSchema: outputChunkSchema,
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    async (args) =>
      toolResult(
        await withGatewayClient(clientFactory, (client) =>
          client.request("output.read", args),
        ),
      ),
  );

  server.registerTool(
    "ssh_read_output_text",
    {
      description:
        "Read retained stdout or stderr directly as UTF-8 text. Omit cursor and offset for the first page, then pass nextCursor; explicit byte offsets remain supported for older clients and are aligned away from the middle of valid UTF-8 characters. Long-running work should normally use ssh_tail.",
      inputSchema: outputReadTextParamsSchema,
      outputSchema: outputTextChunkSchema,
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    async (args) =>
      toolResult(
        await withGatewayClient(clientFactory, (client) =>
          client.request("output.readText", args),
        ),
      ),
  );

  return server;
}

async function adminIsAvailable(dataDirectory: string | undefined): Promise<boolean> {
  return (await getAdminDescriptor(dataDirectory)) !== undefined;
}

async function getAdminDescriptor(dataDirectory: string | undefined) {
  if (dataDirectory === undefined) {
    return undefined;
  }
  try {
    return await readAdminDescriptor(dataDirectory);
  } catch {
    return undefined;
  }
}

function openAdminInDefaultBrowser(url: string): Promise<void> {
  if (process.platform !== "win32") {
    return Promise.reject(
      new Error("Opening the SSH management center requires Windows"),
    );
  }
  const executable = path.join(
    process.env.SystemRoot ?? String.raw`C:\Windows`,
    "System32",
    "rundll32.exe",
  );
  return new Promise((resolve, reject) => {
    const child = spawn(
      executable,
      ["url.dll,FileProtocolHandler", url],
      {
        detached: true,
        stdio: "ignore",
        windowsHide: true,
      },
    );
    child.once("error", reject);
    child.once("spawn", () => {
      child.unref();
      resolve();
    });
  });
}
