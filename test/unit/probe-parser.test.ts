import assert from "node:assert/strict";
import test from "node:test";

import {
  FIXED_PROBE_OUTPUT_PROTOCOL,
  MAX_FIXED_PROBE_OUTPUT_BYTES,
  type FixedProbeKind,
} from "../../src/core/fixed-probe.js";
import {
  FixedProbeParseError,
  parseFixedProbeOutput,
} from "../../src/core/probe-parser.js";

function frame(
  kind: FixedProbeKind,
  fields: Readonly<Record<string, string>>,
  newline = "\n",
): string {
  return [
    `${FIXED_PROBE_OUTPUT_PROTOCOL}\t${kind}`,
    ...Object.entries(fields).map(
      ([key, value]) => `${key}:${Buffer.from(value, "utf8").toString("base64")}`,
    ),
    "AGENT_SSH_PROBE_END",
    "",
  ].join(newline);
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

test("parses a complete Windows target identity frame", () => {
  const result = parseFixedProbeOutput(
    "target-info",
    frame(
      "target-info",
      {
        platform: "windows",
        "machine.nativeId": "00112233-4455-6677-8899-AABBCCDDEEFF",
        "machine.hostname": "WIN-BUILD-01",
        "os.name": "Microsoft Windows Server 2022 Datacenter",
        "os.version": "10.0.20348",
        "os.build": "20348",
        "os.kernel": "Microsoft Windows NT 10.0.20348.0",
        "os.architecture": "64-bit",
        "disk.path": "C:\\",
        "disk.totalBytes": "107374182400",
        "disk.availableBytes": "53687091200",
        ...healthyDockerFields(),
      },
      "\r\n",
    ),
  );
  assert.equal(result.reportedPlatform, "windows");
  assert.equal(result.nativeMachineId, "00112233-4455-6677-8899-aabbccddeeff");
  assert.equal(result.hostname, "WIN-BUILD-01");
  assert.equal(result.disk?.availableBytes, 53_687_091_200);
  assert.equal(result.docker.daemonReachable, true);
  assert.deepEqual(result.warnings, []);
});

test("returns bounded warnings without inventing missing target facts", () => {
  const result = parseFixedProbeOutput(
    "target-info",
    frame("target-info", {
      platform: "linux",
      "os.kernel": "Linux 6.8.0",
      "docker.installed": "false",
      "docker.daemonReachable": "false",
      "compose.installed": "false",
    }),
  );
  assert.equal("nativeMachineId" in result, false);
  assert.equal("hostname" in result, false);
  assert.equal("disk" in result, false);
  assert.deepEqual(result.warnings, [
    "machine-id-unavailable",
    "hostname-unavailable",
    "os-info-partial",
    "disk-info-unavailable",
    "docker-not-installed",
    "compose-not-installed",
  ]);
});

test("parses a ready Docker deployment preflight", () => {
  const result = parseFixedProbeOutput(
    "docker-preflight",
    frame("docker-preflight", {
      platform: "linux",
      ...healthyDockerFields(),
      "preflight.intent": "create",
      "compose.requested": "true",
      "compose.config": "valid",
      "ports.count": "2",
      "port.0.protocol": "tcp",
      "port.0.port": "18080",
      "port.0.observation": "not-observed",
      "port.0.ownership": "unknown",
      "port.1.protocol": "udp",
      "port.1.port": "53",
      "port.1.observation": "not-observed",
      "port.1.ownership": "unknown",
      "containers.status": "ok",
      "containers.filter": "label=com.docker.compose.project=app",
      "containers.count": "2",
      "containers.truncated": "false",
      "container.0.record": "/web-1|running|healthy|web",
      "container.1.record": "worker-1|running|none|worker",
      "disk.status": "available",
      "disk.path": "/srv/app",
      "disk.totalBytes": "1000000000",
      "disk.availableBytes": "800000000",
      "disk.requiredBytes": "500000000",
    }),
  );
  assert.equal(result.overall, "ready");
  assert.equal(result.compose.config, "valid");
  assert.equal(result.ports[0]?.port, 18_080);
  assert.equal(result.containers.items[0]?.name, "web-1");
  assert.equal(result.containers.items[0]?.health, "healthy");
  assert.deepEqual(result.warnings, []);
});

test("derives a blocked preflight from listeners, health, and disk", () => {
  const result = parseFixedProbeOutput(
    "docker-preflight",
    frame("docker-preflight", {
      platform: "macos",
      ...healthyDockerFields(),
      "docker.contextScope": "remote",
      "preflight.intent": "create",
      "compose.requested": "true",
      "compose.config": "valid",
      "ports.count": "1",
      "port.0.protocol": "tcp",
      "port.0.port": "8080",
      "port.0.observation": "listener-observed",
      "port.0.ownership": "other-container",
      "containers.status": "ok",
      "containers.filter": "label=com.docker.compose.project=app",
      "containers.count": "1",
      "containers.truncated": "true",
      "container.0.record": "api-1|running|unhealthy|api",
      "disk.status": "available",
      "disk.path": "/Users/build/app",
      "disk.totalBytes": "1000",
      "disk.availableBytes": "100",
      "disk.requiredBytes": "200",
    }),
  );
  assert.equal(result.overall, "blocked");
  assert.deepEqual(result.warnings, [
    "docker-context-remote",
    "port-listener-observed",
    "container-unhealthy",
    "container-list-truncated",
    "required-disk-space-insufficient",
  ]);
});

test("does not treat a requested-project listener as a conflict for update or inspect", () => {
  for (const intent of ["update", "inspect"] as const) {
    const result = parseFixedProbeOutput(
      "docker-preflight",
      frame("docker-preflight", {
        platform: "linux",
        ...healthyDockerFields(),
        "preflight.intent": intent,
        "compose.requested": "true",
        "compose.config": "valid",
        "ports.count": "1",
        "port.0.protocol": "tcp",
        "port.0.port": "18080",
        "port.0.observation": "listener-observed",
        "port.0.ownership": "requested-project",
        "containers.status": "ok",
        "containers.filter": "label=com.docker.compose.project=three3d-mac-stack",
        "containers.count": "1",
        "containers.truncated": "false",
        "container.0.record": "web-1|running|healthy|web",
        "disk.status": "available",
        "disk.path": "/srv/app",
        "disk.totalBytes": "1000",
        "disk.availableBytes": "800",
      }),
    );
    assert.equal(result.intent, intent);
    assert.equal(result.overall, "ready");
    assert.equal(result.ports[0]?.ownership, "requested-project");
    assert.equal(result.containers.filter, "label=com.docker.compose.project=three3d-mac-stack");
    assert.deepEqual(result.warnings, []);
  }
});

test("fails closed on malformed, injected, inconsistent, or oversized output", () => {
  const validFields = {
    platform: "linux",
    "docker.installed": "false",
    "docker.daemonReachable": "false",
    "compose.installed": "false",
  };
  const valid = frame("target-info", validFields);
  const cases: Array<string | Buffer> = [
    valid.slice(0, -1),
    valid.replace("AGENT_SSH_PROBE_END", "unexpected:dmFsdWU=\nAGENT_SSH_PROBE_END"),
    valid.replace("platform:bGludXg=", "platform:***"),
    valid.replace(
      "platform:bGludXg=",
      "platform:bGludXg=\nplatform:bGludXg=",
    ),
    valid.replace(
      "docker.daemonReachable:ZmFsc2U=",
      "docker.daemonReachable:dHJ1ZQ==",
    ),
    frame("target-info", {
      ...validFields,
      "machine.nativeId": "0000000000000000000000000000000Z",
    }),
    Buffer.concat([
      Buffer.from(valid, "utf8"),
      Buffer.alloc(MAX_FIXED_PROBE_OUTPUT_BYTES, 0x41),
    ]),
  ];
  for (const value of cases) {
    assert.throws(
      () => parseFixedProbeOutput("target-info", value),
      FixedProbeParseError,
    );
  }
});

test("rejects non-contiguous array indexes and free-form container data", () => {
  const base = {
    platform: "linux",
    ...healthyDockerFields(),
    "preflight.intent": "inspect",
    "compose.requested": "true",
    "compose.config": "valid",
    "ports.count": "0",
    "containers.status": "ok",
    "containers.filter": "label=com.docker.compose.project=app",
    "containers.count": "1",
    "containers.truncated": "false",
    "disk.status": "not-requested",
  };
  assert.throws(() =>
    parseFixedProbeOutput(
      "docker-preflight",
      frame("docker-preflight", {
        ...base,
        "container.1.record": "api|running|healthy|api",
      }),
    ),
  );
  assert.throws(() =>
    parseFixedProbeOutput(
      "docker-preflight",
      frame("docker-preflight", {
        ...base,
        "container.0.record": "api|running|healthy|api|secret",
      }),
    ),
  );
});
