#!/usr/bin/env node

import path from "node:path";
import process from "node:process";

import { CONFIG_PATH_ENV } from "../shared/paths.js";
import { GATEWAY_VERSION } from "../shared/version.js";
import { startGatewayDaemon } from "./service.js";

interface DaemonArguments {
  readonly action: "run" | "help" | "version";
  readonly configPath?: string;
}

function usage(): string {
  return [
    "Usage: agent-ssh-gateway --config PATH",
    `       ${CONFIG_PATH_ENV}=PATH agent-ssh-gateway`,
  ].join("\n");
}

function parseArguments(argv: readonly string[]): DaemonArguments {
  if (argv.length === 1 && argv[0] === "--help") {
    return { action: "help" };
  }
  if (argv.length === 1 && argv[0] === "--version") {
    return { action: "version" };
  }
  if (argv.length === 2 && argv[0] === "--config" && argv[1]!.length > 0) {
    return { action: "run", configPath: path.resolve(argv[1]!) };
  }
  if (argv.length === 0 && process.env[CONFIG_PATH_ENV]) {
    return {
      action: "run",
      configPath: path.resolve(process.env[CONFIG_PATH_ENV]),
    };
  }
  throw new Error(usage());
}

async function startDaemon(configPath: string): Promise<void> {
  const daemon = await startGatewayDaemon(configPath);
  await new Promise<void>((resolve) => {
    let stopping = false;
    const stop = (): void => {
      if (stopping) {
        return;
      }
      stopping = true;
      void daemon.stop().finally(resolve);
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
}

try {
  const args = parseArguments(process.argv.slice(2));
  if (args.action === "help") {
    process.stdout.write(`${usage()}\n`);
  } else if (args.action === "version") {
    process.stdout.write(`${GATEWAY_VERSION}\n`);
  } else {
    await startDaemon(args.configPath!);
  }
} catch (error) {
  const message = error instanceof Error ? error.message : "Unknown error";
  process.stderr.write(`agent-ssh-gateway: ${message}\n`);
  process.exitCode = 1;
}
