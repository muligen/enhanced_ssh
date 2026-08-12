import assert from "node:assert/strict";
import test from "node:test";

import { ExecService } from "../../src/core/exec-service.js";
import { FIXED_PROBE_OUTPUT_PROTOCOL } from "../../src/core/fixed-probe.js";
import type { MachineIdentityKeyStore } from "../../src/core/machine-identity.js";
import type { OutputStore } from "../../src/core/output-store.js";
import { TargetRegistry } from "../../src/core/target-registry.js";
import { GATEWAY_ERROR_CODES, GatewayError } from "../../src/shared/errors.js";
import type { AuditWriter } from "../../src/infra/audit-writer.js";
import type { SshExecutor } from "../../src/infra/openssh-executor.js";
import {
  FakeAuditWriter,
  FakeSshExecutor,
  MemoryOutputStore,
  sshOutcome,
} from "../helpers/fakes.js";

const caller = { sessionId: "probe-test-session" };

function frame(
  kind: "target-info" | "docker-preflight",
  fields: Readonly<Record<string, string>>,
): string {
  return [
    `${FIXED_PROBE_OUTPUT_PROTOCOL}\t${kind}`,
    ...Object.entries(fields).map(
      ([key, value]) => `${key}:${Buffer.from(value, "utf8").toString("base64")}`,
    ),
    "AGENT_SSH_PROBE_END",
    "",
  ].join("\n");
}

function healthyDockerFields(): Record<string, string> {
  return {
    "docker.installed": "true",
    "docker.daemonReachable": "true",
    "docker.clientVersion": "27.1.1",
    "docker.serverVersion": "27.1.1",
    "docker.contextName": "default",
    "docker.contextScope": "local",
    "compose.installed": "true",
    "compose.provider": "plugin",
    "compose.version": "v2.29.1",
  };
}

function registry(): TargetRegistry {
  return new TargetRegistry({
    managed: {
      sshAlias: "managed-internal",
      platform: "linux",
      enabled: true,
      policy: { mode: "full-access", maxTimeoutMs: 120_000 },
    },
  });
}

test("returns HMAC identity, trusted fingerprint, and structured Docker facts", async () => {
  const targetOutput = frame("target-info", {
    platform: "linux",
    "machine.nativeId": "00112233445566778899aabbccddeeff",
    "machine.hostname": "build-01",
    "os.name": "Ubuntu",
    "os.version": "24.04",
    "os.kernel": "Linux 6.8.0",
    "os.architecture": "x86_64",
    "disk.path": "/",
    "disk.totalBytes": "1000000000",
    "disk.availableBytes": "750000000",
    ...healthyDockerFields(),
  });
  const preflightOutput = frame("docker-preflight", {
    platform: "linux",
    ...healthyDockerFields(),
    "preflight.intent": "update",
    "compose.requested": "true",
    "compose.config": "valid",
    "ports.count": "1",
    "port.0.protocol": "tcp",
    "port.0.port": "18080",
    "port.0.observation": "listener-observed",
    "port.0.ownership": "requested-project",
    "containers.status": "ok",
    "containers.filter": "label=com.docker.compose.project=app",
    "containers.count": "2",
    "containers.truncated": "false",
    "container.0.record": "/web-1|running|healthy|web",
    "container.1.record": "/worker-1|running|none|worker",
    "disk.status": "available",
    "disk.path": "/srv/app",
    "disk.totalBytes": "1000000",
    "disk.availableBytes": "500000",
  });
  const outputs = [targetOutput, preflightOutput];
  const executor = new FakeSshExecutor(async (input) => {
    const stdout = outputs.shift();
    assert.ok(stdout !== undefined);
    const bytes = Buffer.from(stdout, "utf8");
    await input.outputSink?.append("stdout", bytes);
    return sshOutcome({
      stdout,
      stdoutBytes: bytes.byteLength,
      durationMs: 9,
    });
  });
  const audit = new FakeAuditWriter();
  const outputStore = new MemoryOutputStore();
  const machineIdentity = {
    derive(platform: string, nativeId: string): string {
      assert.equal(platform, "linux");
      assert.equal(nativeId, "00112233445566778899aabbccddeeff");
      return `mid_${"A".repeat(43)}`;
    },
  } as unknown as MachineIdentityKeyStore;
  const service = new ExecService({
    registry: registry(),
    executor: executor as unknown as SshExecutor,
    outputStore: outputStore as unknown as OutputStore,
    audit: audit as unknown as AuditWriter,
    maxConcurrentExecutions: 2,
    machineIdentity,
    hostKeyInspector: {
      inspect: async (sshAlias) => {
        assert.equal(sshAlias, "managed-internal");
        return ["SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"];
      },
    },
  });

  const identity = await service.inspect(caller, "inspect-1", {
    target: "managed",
  });
  assert.equal(identity.connected, true);
  assert.equal(identity.machine?.machineId, `mid_${"A".repeat(43)}`);
  assert.equal(identity.machine?.hostname, "build-01");
  assert.deepEqual(identity.sshHostKeyFingerprints, [
    "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  ]);
  assert.equal(identity.machine?.docker.daemonReachable, true);

  const preflight = await service.dockerPreflight(caller, "preflight-1", {
    target: "managed",
    intent: "update",
    project: { directory: "/srv/app", composeFiles: [], name: "app" },
    ports: [{ protocol: "tcp", port: 18_080 }],
  });
  assert.equal(preflight.overall, "ready");
  assert.equal(preflight.intent, "update");
  assert.equal(preflight.daemon.status, "ok");
  assert.deepEqual(preflight.daemon.context, { name: "default", scope: "local" });
  assert.equal(preflight.compose.config, "valid");
  assert.equal(preflight.ports[0]?.ownership, "requested-project");
  assert.equal(preflight.containers.filter, "label=com.docker.compose.project=app");
  assert.equal(preflight.containers.total, 2);
  assert.equal(preflight.containers.running, 2);
  assert.equal(preflight.containers.healthy, 1);
  assert.equal(outputStore.sinks.length, 0);

  const probeEvents = audit.events.filter(
    (event) => event.event === "probe.completed",
  );
  assert.deepEqual(probeEvents, [
    {
      event: "probe.completed",
      target: "managed",
      probeKind: "target-info",
      durationMs: 9,
      resultCode: "success",
    },
    {
      event: "probe.completed",
      target: "managed",
      probeKind: "docker-preflight",
      durationMs: 9,
      resultCode: "success",
    },
  ]);
  const auditText = JSON.stringify(audit.events);
  assert.equal(auditText.includes("00112233445566778899aabbccddeeff"), false);
  assert.equal(auditText.includes("build-01"), false);
  assert.equal(auditText.includes("Ubuntu"), false);
});

test("audits a fixed invalid-response code without retaining probe output", async () => {
  const invalidOutput = "not-a-probe\nsecret-native-machine-id\n";
  const executor = new FakeSshExecutor(async (input) => {
    const bytes = Buffer.from(invalidOutput, "utf8");
    await input.outputSink?.append("stdout", bytes);
    return sshOutcome({ stdout: invalidOutput, stdoutBytes: bytes.byteLength });
  });
  const audit = new FakeAuditWriter();
  const service = new ExecService({
    registry: registry(),
    executor: executor as unknown as SshExecutor,
    outputStore: new MemoryOutputStore() as unknown as OutputStore,
    audit: audit as unknown as AuditWriter,
    maxConcurrentExecutions: 1,
  });

  await assert.rejects(
    service.inspect(caller, "inspect-invalid", { target: "managed" }),
    (error: unknown) =>
      error instanceof GatewayError &&
      error.code === GATEWAY_ERROR_CODES.probeFailed,
  );
  assert.deepEqual(audit.events.at(-1), {
    event: "probe.completed",
    target: "managed",
    probeKind: "target-info",
    durationMs: 1,
    resultCode: "invalid-response",
  });
  assert.equal(JSON.stringify(audit.events).includes("secret-native-machine-id"), false);
});

test("maps platform-specific Docker probe validation to INVALID_PARAMS", async () => {
  const executor = new FakeSshExecutor(async () => sshOutcome());
  const service = new ExecService({
    registry: registry(),
    executor: executor as unknown as SshExecutor,
    outputStore: new MemoryOutputStore() as unknown as OutputStore,
    audit: new FakeAuditWriter() as unknown as AuditWriter,
    maxConcurrentExecutions: 1,
  });

  await assert.rejects(
    service.dockerPreflight(caller, "preflight-invalid-path", {
      target: "managed",
      intent: "create",
      project: {
        directory: String.raw`C:\services\project`,
        composeFiles: [],
      },
      ports: [],
    }),
    (error: unknown) =>
      error instanceof GatewayError &&
      error.code === GATEWAY_ERROR_CODES.invalidParams,
  );
  assert.equal(executor.calls.length, 0);
});
