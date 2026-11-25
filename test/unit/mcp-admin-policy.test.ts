import assert from "node:assert/strict";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  McpAdminPolicyError,
  createInMemoryMcpAdminPolicy,
  loadMcpAdminPolicy,
  mcpAdminPolicyPath,
} from "../../src/service/mcp-admin-policy.js";

test("MCP admin policy defaults to disabled and persists toggles across reloads", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agent-ssh-mcp-policy-"));
  try {
    const initial = await loadMcpAdminPolicy(root);
    assert.deepEqual(initial.get(), {
      enabled: false,
      persistedEnabled: false,
      source: "settings",
    });

    const enabled = await initial.setEnabled(true);
    assert.deepEqual(enabled, {
      enabled: true,
      persistedEnabled: true,
      source: "settings",
    });

    const reloadedEnabled = await loadMcpAdminPolicy(root);
    assert.deepEqual(reloadedEnabled.get(), {
      enabled: true,
      persistedEnabled: true,
      source: "settings",
    });

    const disabled = await reloadedEnabled.setEnabled(false);
    assert.deepEqual(disabled, {
      enabled: false,
      persistedEnabled: false,
      source: "settings",
    });

    const reloadedDisabled = await loadMcpAdminPolicy(root);
    assert.deepEqual(reloadedDisabled.get(), {
      enabled: false,
      persistedEnabled: false,
      source: "settings",
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("CLI --allow-mcp-admin override enables MCP admin without mutating persisted state", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agent-ssh-mcp-policy-cli-"));
  try {
    const forced = await loadMcpAdminPolicy(root, { forceEnabledByCli: true });
    assert.deepEqual(forced.get(), {
      enabled: true,
      persistedEnabled: false,
      source: "cli",
    });

    await assert.rejects(
      forced.setEnabled(false),
      (error: unknown) =>
        error instanceof McpAdminPolicyError &&
        error.status === 409 &&
        error.code === "MCP_ADMIN_CLI_OVERRIDE",
    );

    const normal = await loadMcpAdminPolicy(root);
    assert.deepEqual(normal.get(), {
      enabled: false,
      persistedEnabled: false,
      source: "settings",
    });

    const inMemoryForced = createInMemoryMcpAdminPolicy(false, {
      forceEnabledByCli: true,
    });
    assert.equal(inMemoryForced.get().enabled, true);
    assert.equal(inMemoryForced.get().source, "cli");
    await assert.rejects(inMemoryForced.setEnabled(false), McpAdminPolicyError);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("MCP admin policy fails closed on corrupt, oversized, or symlinked policy files", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agent-ssh-mcp-policy-unsafe-"));
  try {
    const file = mcpAdminPolicyPath(root);

    await writeFile(file, "{not-json", "utf8");
    await assert.rejects(loadMcpAdminPolicy(root));

    await writeFile(file, JSON.stringify({ version: 1, enabled: true, extra: 1 }), "utf8");
    await assert.rejects(loadMcpAdminPolicy(root));

    await writeFile(file, " ".repeat(5_000), "utf8");
    await assert.rejects(loadMcpAdminPolicy(root));

    await rm(file, { force: true });
    if (process.platform !== "win32") {
      const target = path.join(root, "real-policy.json");
      await writeFile(target, JSON.stringify({ version: 1, enabled: true }), "utf8");
      await symlink(target, file);
      await assert.rejects(loadMcpAdminPolicy(root), /Unsafe MCP admin policy file/u);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("concurrent setEnabled calls serialize cleanly and persist the final value", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agent-ssh-mcp-policy-race-"));
  try {
    const policy = await loadMcpAdminPolicy(root);
    const [first, second, third] = await Promise.all([
      policy.setEnabled(true),
      policy.setEnabled(false),
      policy.setEnabled(true),
    ]);
    assert.equal(first.enabled, true);
    assert.equal(second.enabled, false);
    assert.equal(third.enabled, true);

    const reloaded = await loadMcpAdminPolicy(root);
    assert.equal(reloaded.get().enabled, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
