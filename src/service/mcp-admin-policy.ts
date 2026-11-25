import { randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import path from "node:path";

import { z } from "zod";

import { hardenPrivatePath } from "../daemon/runtime-state.js";

export const MCP_ADMIN_POLICY_FILENAME = "mcp-admin-policy.json";

const MAX_POLICY_FILE_BYTES = 4_096;

const storedMcpAdminPolicySchema = z.strictObject({
  version: z.literal(1),
  enabled: z.boolean(),
});

export const mcpAdminPolicySnapshotSchema = z.strictObject({
  enabled: z.boolean(),
  persistedEnabled: z.boolean(),
  source: z.enum(["settings", "cli"]),
});

export type McpAdminPolicySource = "settings" | "cli";
export type McpAdminPolicySnapshot = z.infer<typeof mcpAdminPolicySnapshotSchema>;

export interface McpAdminPolicyOptions {
  readonly forceEnabledByCli?: boolean;
}

export interface McpAdminPolicyStore {
  get(): McpAdminPolicySnapshot;
  setEnabled(enabled: boolean): Promise<McpAdminPolicySnapshot>;
}

export class McpAdminPolicyError extends Error {
  public readonly status: number;
  public readonly code: string;

  public constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "McpAdminPolicyError";
    this.status = status;
    this.code = code;
  }
}

export function mcpAdminPolicyPath(directory: string): string {
  return path.join(path.resolve(directory), MCP_ADMIN_POLICY_FILENAME);
}

export function createInMemoryMcpAdminPolicy(
  initialEnabled = false,
  options: McpAdminPolicyOptions = {},
): McpAdminPolicyStore {
  let persistedEnabled = initialEnabled;
  const forceEnabledByCli = options.forceEnabledByCli === true;

  const snapshot = (): McpAdminPolicySnapshot => ({
    enabled: forceEnabledByCli || persistedEnabled,
    persistedEnabled,
    source: forceEnabledByCli ? "cli" : "settings",
  });

  return {
    get: snapshot,
    setEnabled(enabled: boolean): Promise<McpAdminPolicySnapshot> {
      if (forceEnabledByCli) {
        return Promise.reject(
          new McpAdminPolicyError(
            409,
            "MCP_ADMIN_CLI_OVERRIDE",
            "MCP administration is forced on by --allow-mcp-admin; restart without that flag to change this setting",
          ),
        );
      }
      persistedEnabled = enabled;
      return Promise.resolve(snapshot());
    },
  };
}

export async function loadMcpAdminPolicy(
  directory: string,
  options: McpAdminPolicyOptions = {},
): Promise<McpAdminPolicyStore> {
  const resolvedDirectory = path.resolve(directory);
  const policyPath = mcpAdminPolicyPath(resolvedDirectory);
  const forceEnabledByCli = options.forceEnabledByCli === true;
  let persistedEnabled = false;

  let entry;
  try {
    entry = await lstat(policyPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  }

  if (entry !== undefined) {
    if (!entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1) {
      throw new Error("Unsafe MCP admin policy file");
    }
    if (entry.size > MAX_POLICY_FILE_BYTES) {
      throw new Error("MCP admin policy file is too large");
    }
    await hardenPrivatePath(policyPath, false);
    const parsed = storedMcpAdminPolicySchema.parse(
      JSON.parse(await readFile(policyPath, "utf8")) as unknown,
    );
    persistedEnabled = parsed.enabled;
  }

  let writeChain = Promise.resolve();

  const snapshot = (): McpAdminPolicySnapshot => ({
    enabled: forceEnabledByCli || persistedEnabled,
    persistedEnabled,
    source: forceEnabledByCli ? "cli" : "settings",
  });

  return {
    get: snapshot,
    setEnabled(enabled: boolean): Promise<McpAdminPolicySnapshot> {
      if (forceEnabledByCli) {
        return Promise.reject(
          new McpAdminPolicyError(
            409,
            "MCP_ADMIN_CLI_OVERRIDE",
            "MCP administration is forced on by --allow-mcp-admin; restart without that flag to change this setting",
          ),
        );
      }
      const run = writeChain.then(async () => {
        await writePolicyFile(resolvedDirectory, policyPath, enabled);
        persistedEnabled = enabled;
        return snapshot();
      });
      writeChain = run.then(
        () => undefined,
        () => undefined,
      );
      return run;
    },
  };
}

async function writePolicyFile(
  directory: string,
  policyPath: string,
  enabled: boolean,
): Promise<void> {
  const payload = storedMcpAdminPolicySchema.parse({ version: 1, enabled });
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await hardenPrivatePath(directory, true);

  let existing;
  try {
    existing = await lstat(policyPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  }
  if (
    existing !== undefined &&
    (!existing.isFile() || existing.isSymbolicLink() || existing.nlink !== 1)
  ) {
    throw new Error("Refusing to replace an unsafe MCP admin policy file");
  }

  const pendingPath = `${policyPath}.pending-${process.pid}-${randomBytes(12).toString("hex")}`;
  const handle = await open(
    pendingPath,
    fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY,
    0o600,
  );
  try {
    await handle.writeFile(`${JSON.stringify(payload)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }

  try {
    await hardenPrivatePath(pendingPath, false);
    await rename(pendingPath, policyPath);
    await hardenPrivatePath(policyPath, false);
  } catch (error) {
    await unlink(pendingPath).catch(() => undefined);
    throw error;
  }
}
