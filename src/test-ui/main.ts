#!/usr/bin/env node

import process from "node:process";
import path from "node:path";

import { resolveDataDirectory } from "../shared/paths.js";
import { GATEWAY_VERSION } from "../shared/version.js";
import {
  createDemoGatewayFactory,
  createRpcGatewayFactory,
} from "./gateway.js";
import {
  createWindowsAccessClientSessionPreparer,
  type AccessClientSessionPreparer,
} from "./accessclient-session.js";
import {
  createManagedSshService,
  defaultManagedSshDirectory,
} from "./managed.js";
import {
  startTestUiServer,
  type RunningTestUiServer,
} from "./server.js";

interface TestUiArguments {
  readonly action: "run" | "help" | "version";
  readonly demo: boolean;
  readonly setup: boolean;
  readonly dataDirectory?: string;
  readonly port: number;
}

function usage(): string {
  return [
    "Usage:",
    "  agent-ssh-test-ui --demo [--port PORT]",
    "  agent-ssh-test-ui --setup [--port PORT]",
    "  agent-ssh-test-ui --data-directory PATH [--port PORT]",
  ].join("\n");
}

function parseArguments(argv: readonly string[]): TestUiArguments {
  if (argv.length === 1 && argv[0] === "--help") {
    return { action: "help", demo: false, setup: false, port: 0 };
  }
  if (argv.length === 1 && argv[0] === "--version") {
    return { action: "version", demo: false, setup: false, port: 0 };
  }

  let demo = false;
  let setup = false;
  let dataDirectory: string | undefined;
  let port = 0;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--demo") {
      if (demo) {
        throw new Error("--demo may only be specified once");
      }
      demo = true;
      continue;
    }
    if (argument === "--setup") {
      if (setup) {
        throw new Error("--setup may only be specified once");
      }
      setup = true;
      continue;
    }
    if (argument === "--data-directory") {
      if (dataDirectory !== undefined) {
        throw new Error("--data-directory may only be specified once");
      }
      dataDirectory = requireValue(argument, argv[++index]);
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
    throw new Error(`Unknown argument: ${argument ?? "<missing>"}\n${usage()}`);
  }
  const selectedModes = Number(demo) + Number(setup) + Number(dataDirectory !== undefined);
  if (selectedModes !== 1) {
    throw new Error(
      `Choose exactly one of --demo, --setup, or --data-directory\n${usage()}`,
    );
  }
  return {
    action: "run",
    demo,
    setup,
    ...(dataDirectory === undefined ? {} : { dataDirectory }),
    port,
  };
}

function requireValue(option: string, value: string | undefined): string {
  if (value === undefined || value.length === 0) {
    throw new Error(`${option} requires a value`);
  }
  return value;
}

async function run(args: TestUiArguments): Promise<void> {
  if (args.action === "help") {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  if (args.action === "version") {
    process.stdout.write(`${GATEWAY_VERSION}\n`);
    return;
  }

  const mode = args.demo
    ? "demo"
    : args.setup
      ? "managed"
      : "gateway";
  const managedDirectory = defaultManagedSshDirectory();
  const configurationService =
    mode === "managed"
      ? await createManagedSshService(managedDirectory)
      : undefined;
  const accessClientSessionPreparer: AccessClientSessionPreparer | undefined =
    mode === "managed" && process.platform === "win32"
      ? createWindowsAccessClientSessionPreparer(
          path.join(managedDirectory, "runtime", "accessclient-loghost-recovery.json"),
        )
      : undefined;
  let server: RunningTestUiServer | undefined;
  let runError: unknown;
  try {
    const gatewayFactory =
      mode === "demo"
        ? createDemoGatewayFactory()
        : mode === "managed"
          ? configurationService!.gatewayFactory
          : createRpcGatewayFactory(resolveDataDirectory(args.dataDirectory));
    server = await startTestUiServer({
      gatewayFactory,
      mode,
      ...(configurationService === undefined ? {} : { configurationService }),
      ...(accessClientSessionPreparer === undefined
        ? {}
        : { accessClientSessionPreparer }),
      legacySetupRoutes: mode === "managed",
      port: args.port,
      onError: (error) => {
        const name = error instanceof Error ? error.name : "UnknownError";
        process.stderr.write(`agent-ssh-test-ui warning: ${name}\n`);
      },
    });

    process.stdout.write(`Agent SSH test UI (${mode}): ${server.url}\n`);
    process.stdout.write("Press Ctrl+C to stop.\n");

    await new Promise<void>((resolve) => {
      const stop = (): void => {
        process.off("SIGINT", stop);
        process.off("SIGTERM", stop);
        resolve();
      };
      process.once("SIGINT", stop);
      process.once("SIGTERM", stop);
    });
  } catch (error) {
    runError = error;
    throw error;
  } finally {
    try {
      if (server === undefined) {
        await accessClientSessionPreparer?.close();
        await configurationService?.close();
      } else {
        await server.close();
      }
    } catch (closeError) {
      if (runError === undefined) {
        throw closeError;
      }
      const message =
        runError instanceof Error ? runError.message : "Unknown error";
      throw new AggregateError([runError, closeError], message);
    }
  }
}

try {
  await run(parseArguments(process.argv.slice(2)));
} catch (error) {
  const message = error instanceof Error ? error.message : "Unknown error";
  process.stderr.write(`agent-ssh-test-ui: ${message}\n`);
  process.exitCode = 1;
}
