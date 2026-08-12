#!/usr/bin/env node

import process from "node:process";

import { serveStdio } from "@modelcontextprotocol/server/stdio";

import { resolveDataDirectory } from "../shared/paths.js";
import {
  createGatewayRpcClientFactory,
  createMcpServer,
} from "./server.js";

function parseDataDirectory(argv: readonly string[]): string {
  if (argv.length === 0) {
    return resolveDataDirectory();
  }
  if (argv.length === 2 && argv[0] === "--data-directory") {
    return resolveDataDirectory(argv[1]);
  }
  throw new Error("Usage: agent-ssh-mcp [--data-directory PATH]");
}

try {
  const dataDirectory = parseDataDirectory(process.argv.slice(2));
  const clientFactory = createGatewayRpcClientFactory(dataDirectory);
  const handle = serveStdio(
    () => createMcpServer(clientFactory, { dataDirectory }),
    {
    onerror: (error) => process.stderr.write(`MCP transport error: ${error.message}\n`),
    },
  );

  let closing: Promise<void> | undefined;
  const close = async (): Promise<void> => {
    closing ??= handle.close();
    await closing;
  };
  process.once("SIGINT", () => void close());
  process.once("SIGTERM", () => void close());
  process.stdin.once("end", () => void close());
} catch (error) {
  const message = error instanceof Error ? error.message : "Unknown error";
  process.stderr.write(`agent-ssh-mcp: ${message}\n`);
  process.exitCode = 1;
}
