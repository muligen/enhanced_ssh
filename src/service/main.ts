#!/usr/bin/env node

import path from "node:path";
import process from "node:process";
import { loadBrowserSessionSecret } from "./browser-session.js";
import { loadMcpAdminPolicy } from "./mcp-admin-policy.js";

import { GATEWAY_VERSION } from "../shared/version.js";
import {
  createWindowsAccessClientSessionPreparer,
  type AccessClientSessionPreparer,
} from "../test-ui/accessclient-session.js";
import {
  createManagedSshService,
  defaultManagedSshDirectory,
} from "../test-ui/managed.js";
import {
  startTestUiServer,
  type RunningTestUiServer,
} from "../test-ui/server.js";
import {
  publishAdminDescriptor,
  removeAdminDescriptor,
  type AdminDescriptor,
} from "./control-plane.js";

interface ServiceArguments {
  readonly action: "run" | "help" | "version";
  readonly managedDirectory: string;
  readonly port: number;
  readonly allowMcpAdmin: boolean;
}

function usage(): string {
  return [
    "Usage:",
    "  agent-ssh-service [--managed-directory PATH] [--port PORT] [--allow-mcp-admin]",
  ].join("\n");
}

function parseArguments(argv: readonly string[]): ServiceArguments {
  if (argv.length === 1 && argv[0] === "--help") {
    return {
      action: "help",
      managedDirectory: defaultManagedSshDirectory(),
      port: 0,
      allowMcpAdmin: false,
    };
  }
  if (argv.length === 1 && argv[0] === "--version") {
    return {
      action: "version",
      managedDirectory: defaultManagedSshDirectory(),
      port: 0,
      allowMcpAdmin: false,
    };
  }

  let managedDirectory = defaultManagedSshDirectory();
  let managedDirectorySpecified = false;
  let port = 52075;
  let allowMcpAdmin = false;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--managed-directory") {
      if (managedDirectorySpecified) {
        throw new Error("--managed-directory may only be specified once");
      }
      managedDirectorySpecified = true;
      managedDirectory = path.resolve(requireValue(argument, argv[++index]));
      continue;
    }
    if (argument === "--port") {
      const rawPort = requireValue(argument, argv[++index]);
      if (!/^(?:0|[1-9][0-9]*)$/u.test(rawPort)) {
        throw new Error("--port must be an integer from 0 through 65535");
      }
      port = Number(rawPort);
      if (!Number.isSafeInteger(port) || port > 65_535) {
        throw new Error("--port must be an integer from 0 through 65535");
      }
      continue;
    }
    if (argument === "--allow-mcp-admin") {
      if (allowMcpAdmin) {
        throw new Error("--allow-mcp-admin may only be specified once");
      }
      allowMcpAdmin = true;
      continue;
    }
    throw new Error(`Unknown argument: ${argument ?? "<missing>"}\n${usage()}`);
  }
  return { action: "run", managedDirectory, port, allowMcpAdmin };
}

function requireValue(option: string, value: string | undefined): string {
  if (value === undefined || value.length === 0) {
    throw new Error(`${option} requires a value`);
  }
  return value;
}

async function run(args: ServiceArguments): Promise<void> {
  if (args.action === "help") {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  if (args.action === "version") {
    process.stdout.write(`${GATEWAY_VERSION}\n`);
    return;
  }

  const runtimeDirectory = path.join(args.managedDirectory, "runtime");
  const configurationService = await createManagedSshService(
    args.managedDirectory,
  );
  const accessClientSessionPreparer: AccessClientSessionPreparer | undefined =
    process.platform === "win32"
      ? createWindowsAccessClientSessionPreparer(
          path.join(runtimeDirectory, "accessclient-loghost-recovery.json"),
        )
      : undefined;
  let server: RunningTestUiServer | undefined;
  let descriptor: AdminDescriptor | undefined;
  let runError: unknown;
  try {
    const mcpAdminPolicy = await loadMcpAdminPolicy(args.managedDirectory, {
      forceEnabledByCli: args.allowMcpAdmin,
    });
    server = await startTestUiServer({
      browserSessionSecret: await loadBrowserSessionSecret(args.managedDirectory),
      gatewayFactory: configurationService.gatewayFactory,
      configurationService,
      mcpAdminPolicy,
      ...(accessClientSessionPreparer === undefined
        ? {}
        : { accessClientSessionPreparer }),
      mode: "managed",
      legacySetupRoutes: false,
      port: args.port,
      onAdminAction: (event) => {
        if (event.caller === "mcp" && event.route !== "/api/admin/mcp-admin/status") {
          const suffix = event.code === undefined ? "" : ` (${event.code})`;
          process.stderr.write(
            `agent-ssh-service mcp-admin: ${event.route} -> ${event.status}${suffix}\n`,
          );
        }
      },
      onError: (error) => {
        const name = error instanceof Error ? error.name : "UnknownError";
        process.stderr.write(`agent-ssh-service warning: ${name}\n`);
      },
    });
    descriptor = {
      version: 1,
      pid: process.pid,
      origin: server.origin,
      url: server.url,
      startedAt: new Date().toISOString(),
      mcpAdminToken: server.mcpAdminToken,
    };
    await publishAdminDescriptor(runtimeDirectory, descriptor);

    const policySnapshot = mcpAdminPolicy.get();
    const mcpAdminSummary = policySnapshot.enabled
      ? policySnapshot.source === "cli"
        ? "enabled (--allow-mcp-admin)"
        : "enabled (saved setting)"
      : "disabled (enable in Web Management Center -> Settings)";
    process.stdout.write(`Agent SSH management center: ${server.url}\n`);
    process.stdout.write(`Gateway runtime: ${runtimeDirectory}\n`);
    process.stdout.write(`MCP configuration management: ${mcpAdminSummary}\n`);
    process.stdout.write("Press Ctrl+C to stop.\n");
    await waitForStopSignal();
  } catch (error) {
    runError = error;
    throw error;
  } finally {
    let cleanupError: unknown;
    if (descriptor !== undefined) {
      await removeAdminDescriptor(runtimeDirectory, descriptor).catch(
        (error: unknown) => {
          cleanupError = error;
        },
      );
    }
    try {
      if (server === undefined) {
        await accessClientSessionPreparer?.close();
        await configurationService.close();
      } else {
        await server.close();
      }
    } catch (closeError) {
      cleanupError ??= closeError;
    }
    if (runError === undefined && cleanupError !== undefined) {
      throw cleanupError;
    }
  }
}

function waitForStopSignal(): Promise<void> {
  return new Promise((resolve) => {
    const stop = (): void => {
      process.off("SIGINT", stop);
      process.off("SIGTERM", stop);
      resolve();
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
}

try {
  await run(parseArguments(process.argv.slice(2)));
} catch (error) {
  const message = error instanceof Error ? error.message : "Unknown error";
  process.stderr.write(`agent-ssh-service: ${message}\n`);
  process.exitCode = 1;
}
