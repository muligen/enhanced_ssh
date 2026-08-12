import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { stringify } from "yaml";

import {
  startGatewayDaemon,
  type RunningGatewayDaemon,
} from "../../src/daemon/service.js";
import { GatewayRpcClient } from "../../src/shared/rpc-client.js";

test(
  "daemon routes an AccessClient target through the configured Plink executable",
  { skip: process.platform !== "win32", timeout: 60_000 },
  async (t) => {
    const sandbox = await mkdtemp(
      path.join(os.tmpdir(), "agent-ssh-accessclient-route-"),
    );
    const dataDirectory = path.join(sandbox, "runtime");
    const knownHosts = path.join(sandbox, "known_hosts");
    const sshConfig = path.join(sandbox, "ssh_config");
    const gatewayConfig = path.join(sandbox, "gateway.yaml");
    let daemon: RunningGatewayDaemon | undefined;
    let client: GatewayRpcClient | undefined;
    t.after(async () => {
      client?.close();
      await daemon?.stop().catch(() => undefined);
      await rm(sandbox, { recursive: true, force: true });
    });

    await Promise.all([
      writeFile(knownHosts, "", { encoding: "utf8", mode: 0o600 }),
      writeFile(sshConfig, "", { encoding: "utf8", mode: 0o600 }),
      writeFile(
        gatewayConfig,
        stringify(accessClientConfiguration(dataDirectory, sshConfig, knownHosts)),
        "utf8",
      ),
    ]);

    daemon = await startGatewayDaemon(gatewayConfig);
    client = await GatewayRpcClient.connect(dataDirectory, {
      name: "accessclient-route-test",
      version: "1.0.0",
    });

    const targets = await client.request("target.list", {});
    assert.equal(targets.targets[0]?.alias, "accessclient");
    assert.equal(targets.targets[0]?.transferMode, "deny");

    // node.exe is deliberately used as the Plink executable. It rejects the
    // Plink-only -batch option without touching the network, proving that the
    // daemon selected this route instead of its OpenSSH fallback.
    const execution = await client.run({
      target: "accessclient",
      command: "hostname",
      timeoutMs: 5_000,
    });
    assert.equal(execution.termination, "exit");
    assert.equal(execution.exitCode, 255);
    assert.equal(execution.stdout.text, "");
    assert.match(
      execution.stderr.text,
      /AccessClient shared session is not available/iu,
    );
  },
);

function accessClientConfiguration(
  dataDirectory: string,
  sshConfig: string,
  knownHosts: string,
) {
  const systemRoot = process.env.SystemRoot ?? String.raw`C:\Windows`;
  return {
    version: 1,
    runtime: {
      dataDirectory,
      inlineOutputBytes: 8_192,
      maxStoredOutputBytes: 10_485_760,
      maxTotalRetainedOutputBytes: 104_857_600,
      maxAuditBytes: 104_857_600,
      maxRetainedOutputs: 1_024,
      outputTtlSeconds: 900,
      maxConcurrentExecutions: 2,
    },
    ssh: {
      executable: path.join(systemRoot, "System32", "OpenSSH", "ssh.exe"),
      sftpExecutable: path.join(systemRoot, "System32", "OpenSSH", "sftp.exe"),
      configFile: sshConfig,
      knownHostsFile: knownHosts,
      connectTimeoutSeconds: 15,
    },
    putty: {
      executable: process.execPath,
    },
    targets: {
      accessclient: {
        description: "AccessClient routed target",
        sshAlias: "internal-accessclient",
        connection: {
          mode: "accessclient-share",
          gatewayHost: "192.0.2.1",
          gatewayPort: 22,
          gatewayUsername: "portal/172.24.251.37/kxjdev",
          expectedHostname: "test-ai-agent",
        },
        platform: "linux",
        enabled: true,
        policy: {
          mode: "allow-list",
          allowedCommands: ["hostname"],
          maxTimeoutMs: 30_000,
        },
      },
    },
  };
}
