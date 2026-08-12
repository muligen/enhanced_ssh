#!/usr/bin/env node

import process from "node:process";

import { resolveDataDirectory } from "../shared/paths.js";
import { GatewayRpcClient } from "../shared/rpc-client.js";
import { MAX_OUTPUT_READ_BYTES } from "../shared/protocol.js";
import { GATEWAY_VERSION } from "../shared/version.js";

interface ParsedCommand {
  readonly dataDirectory: string;
  readonly action: string;
  readonly args: readonly string[];
}

function usage(): string {
  return [
    "Usage:",
    "  agent-ssh [--data-directory PATH] ping",
    "  agent-ssh [--data-directory PATH] targets",
    "  agent-ssh [--data-directory PATH] run TARGET --command COMMAND [--timeout-ms MS]",
    "  agent-ssh [--data-directory PATH] output OUTPUT_REF STREAM [--offset N] [--limit N]",
  ].join("\n");
}

function parseGlobalArguments(argv: readonly string[]): ParsedCommand {
  const remaining = [...argv];
  let explicitDataDirectory: string | undefined;
  while (remaining[0]?.startsWith("--")) {
    const option = remaining.shift();
    if (option === "--data-directory") {
      explicitDataDirectory = requireValue(option, remaining.shift());
      continue;
    }
    if (option === "--help") {
      return { dataDirectory: resolveDataDirectory(explicitDataDirectory), action: "help", args: [] };
    }
    if (option === "--version") {
      return { dataDirectory: resolveDataDirectory(explicitDataDirectory), action: "version", args: [] };
    }
    throw new Error(`Unknown option: ${option}`);
  }

  return {
    dataDirectory: resolveDataDirectory(explicitDataDirectory),
    action: remaining.shift() ?? "help",
    args: remaining,
  };
}

function requireValue(option: string, value: string | undefined): string {
  if (value === undefined || value.length === 0) {
    throw new Error(`${option} requires a value`);
  }
  return value;
}

function parseInteger(option: string, value: string | undefined, maximum?: number): number {
  const raw = requireValue(option, value);
  if (!/^(?:0|[1-9][0-9]*)$/u.test(raw)) {
    throw new Error(`${option} must be a non-negative integer`);
  }
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || (maximum !== undefined && parsed > maximum)) {
    throw new Error(`${option} is outside the supported range`);
  }
  return parsed;
}

function optionValues(args: readonly string[]): ReadonlyMap<string, string> {
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const option = args[index];
    if (option === undefined || !option.startsWith("--")) {
      throw new Error(`Expected an option, received: ${option ?? "<missing>"}`);
    }
    if (values.has(option)) {
      throw new Error(`Duplicate option: ${option}`);
    }
    values.set(option, requireValue(option, args[index + 1]));
  }
  return values;
}

async function execute(command: ParsedCommand): Promise<unknown> {
  if (command.action === "help") {
    return { usage: usage() };
  }
  if (command.action === "version") {
    return { version: GATEWAY_VERSION };
  }

  const client = await GatewayRpcClient.connect(command.dataDirectory, {
    name: "agent-ssh-cli",
    version: GATEWAY_VERSION,
  });
  try {
    switch (command.action) {
      case "ping":
        assertNoArguments(command.args);
        return await client.request("system.ping", {});
      case "targets":
        assertNoArguments(command.args);
        return await client.request("target.list", {});
      case "run":
        return await runCommand(client, command.args);
      case "output":
        return await readOutput(client, command.args);
      default:
        throw new Error(`Unknown command: ${command.action}\n${usage()}`);
    }
  } finally {
    client.close();
  }
}

async function runCommand(
  client: GatewayRpcClient,
  args: readonly string[],
): Promise<unknown> {
  const target = requireValue("TARGET", args[0]);
  const options = optionValues(args.slice(1));
  for (const option of options.keys()) {
    if (option !== "--command" && option !== "--timeout-ms") {
      throw new Error(`Unknown run option: ${option}`);
    }
  }
  const command = requireValue("--command", options.get("--command"));
  const timeoutValue = options.get("--timeout-ms");
  if (timeoutValue !== undefined && parseInteger("--timeout-ms", timeoutValue) < 1) {
    throw new Error("--timeout-ms must be at least 1");
  }
  const params = timeoutValue === undefined
    ? { target, command }
    : { target, command, timeoutMs: parseInteger("--timeout-ms", timeoutValue) };

  const cancellation = new AbortController();
  const onSignal = (): void => cancellation.abort();
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);
  try {
    return await client.run(params, cancellation.signal);
  } finally {
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
  }
}

async function readOutput(
  client: GatewayRpcClient,
  args: readonly string[],
): Promise<unknown> {
  const outputRef = requireValue("OUTPUT_REF", args[0]);
  const stream = requireValue("STREAM", args[1]);
  if (stream !== "stdout" && stream !== "stderr") {
    throw new Error("STREAM must be stdout or stderr");
  }
  const options = optionValues(args.slice(2));
  for (const option of options.keys()) {
    if (option !== "--offset" && option !== "--limit") {
      throw new Error(`Unknown output option: ${option}`);
    }
  }
  const offset = options.has("--offset")
    ? parseInteger("--offset", options.get("--offset"))
    : 0;
  const limit = options.has("--limit")
    ? parseInteger("--limit", options.get("--limit"), MAX_OUTPUT_READ_BYTES)
    : MAX_OUTPUT_READ_BYTES;
  if (limit < 1) {
    throw new Error("--limit must be at least 1");
  }
  return await client.request("output.read", { outputRef, stream, offset, limit });
}

function assertNoArguments(args: readonly string[]): void {
  if (args.length !== 0) {
    throw new Error("This command does not accept arguments");
  }
}

try {
  const result = await execute(parseGlobalArguments(process.argv.slice(2)));
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} catch (error) {
  const message = error instanceof Error ? error.message : "Unknown error";
  process.stderr.write(`${JSON.stringify({ error: message })}\n`);
  process.exitCode = 1;
}
