import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  FIXED_PROBE_OUTPUT_PROTOCOL,
  MAX_FIXED_PROBE_OUTPUT_BYTES,
  MAX_FIXED_PROBE_STDIN_BYTES,
  prepareFixedProbe,
  type DockerPreflightProbePayload,
  type FixedProbePlatform,
} from "../../src/core/fixed-probe.js";
import { parseFixedProbeOutput } from "../../src/core/probe-parser.js";

const PLATFORMS = ["windows", "linux", "macos"] as const;

test("builds bounded ASCII target-info scripts for every remote platform", () => {
  for (const platform of PLATFORMS) {
    const prepared = prepareFixedProbe(platform, "target-info");
    assert.equal(prepared.platform, platform);
    assert.equal(prepared.kind, "target-info");
    assert.equal(prepared.outputProtocol, FIXED_PROBE_OUTPUT_PROTOCOL);
    assert.equal(prepared.maxOutputBytes, MAX_FIXED_PROBE_OUTPUT_BYTES);
    assert.ok(prepared.stdin.byteLength > 0);
    assert.ok(prepared.stdin.byteLength <= MAX_FIXED_PROBE_STDIN_BYTES);
    assert.equal(Buffer.from(prepared.stdin).every((byte) => byte <= 0x7f), true);
    assert.equal(
      prepared.command,
      platform === "windows"
        ? "powershell.exe -NoLogo -NoProfile -NonInteractive -Command -"
        : "/bin/sh -s",
    );
  }
});

test("keeps untrusted project data out of argv and script source", () => {
  const cases: Array<{
    readonly platform: FixedProbePlatform;
    readonly directory: string;
  }> = [
    {
      platform: "windows",
      directory: String.raw`C:\services\';$(Start-Process calc);中文`,
    },
    {
      platform: "linux",
      directory: "/srv/';$(touch injected);中文",
    },
    {
      platform: "macos",
      directory: "/Users/build/';`touch injected`;中文",
    },
  ];
  for (const { platform, directory } of cases) {
    const prepared = prepareFixedProbe(platform, "docker-preflight", {
      project: {
        directory,
        composeFiles: ["deploy/compose.prod.yaml"],
        name: "agent_test",
      },
      ports: [
        { protocol: "tcp", port: 18_080 },
        { protocol: "udp", port: 53 },
      ],
      requiredFreeBytes: 1_048_576,
    });
    const stdin = Buffer.from(prepared.stdin).toString("ascii");
    assert.equal(prepared.command.includes(directory), false);
    assert.equal(stdin.includes(directory), false);
    assert.equal(stdin.includes("中文"), false);
    assert.ok(prepared.stdin.byteLength <= MAX_FIXED_PROBE_STDIN_BYTES);
    assert.equal(Buffer.from(prepared.stdin).every((byte) => byte <= 0x7f), true);
  }
});

test("uses JSON inspection for Windows Compose container labels", () => {
  const prepared = prepareFixedProbe("windows", "docker-preflight", {
    intent: "update",
    project: {
      directory: String.raw`D:\deploy\app`,
      composeFiles: ["compose.yaml"],
      name: "app",
    },
    ports: [{ protocol: "tcp", port: 18_080 }],
  });
  const wrapper = Buffer.from(prepared.stdin).toString("ascii");
  const encodedScript = /FromBase64String\('([A-Za-z0-9+/=]+)'\)/u.exec(wrapper)?.[1];
  assert.ok(encodedScript !== undefined);
  const script = Buffer.from(encodedScript, "base64").toString("ascii");
  assert.match(script, /inspect --format '\{\{json \.\}\}'/u);
  assert.equal(
    script.includes(
      "inspect --format '{{.Name}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{index .Config.Labels",
    ),
    false,
  );
  assert.match(script, /publish=/u);
  assert.match(script, /containers\.filter/u);
});

test("rejects ambiguous or unsafe Docker preflight payloads", () => {
  const invalid: Array<{
    readonly platform: FixedProbePlatform;
    readonly payload: DockerPreflightProbePayload | Record<string, unknown>;
  }> = [
    { platform: "linux", payload: { project: { directory: "relative" } } },
    {
      platform: "windows",
      payload: { project: { directory: String.raw`\\server\share\project` } },
    },
    {
      platform: "linux",
      payload: {
        project: { directory: "/srv/app", composeFiles: ["../secret.yaml"] },
      },
    },
    {
      platform: "linux",
      payload: {
        ports: [
          { protocol: "tcp", port: 80 },
          { protocol: "tcp", port: 80 },
        ],
      },
    },
    { platform: "linux", payload: { project: { directory: "/srv/app" }, shell: "bash" } },
  ];
  for (const { platform, payload } of invalid) {
    assert.throws(() =>
      prepareFixedProbe(
        platform,
        "docker-preflight",
        payload as DockerPreflightProbePayload,
      ),
    );
  }
});

test("rejects payloads for target-info and missing Docker payloads", () => {
  const invoke = prepareFixedProbe as unknown as (
    platform: FixedProbePlatform,
    kind: string,
    payload?: DockerPreflightProbePayload,
  ) => unknown;
  assert.throws(() => invoke("linux", "target-info", {}));
  assert.throws(() => invoke("linux", "docker-preflight"));
  assert.throws(() => invoke("linux", "unknown"));
});

test(
  "executes and parses the generated Windows fixed probes",
  { skip: process.platform !== "win32", timeout: 120_000 },
  () => {
    const cases = [
      prepareFixedProbe("windows", "target-info"),
      prepareFixedProbe("windows", "docker-preflight", {
        ports: [],
        requiredFreeBytes: 1,
      }),
    ] as const;
    for (const prepared of cases) {
      const executed = spawnSync(
        "powershell.exe",
        ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"],
        {
          input: prepared.stdin,
          encoding: "buffer",
          timeout: 60_000,
          windowsHide: true,
        },
      );
      assert.equal(executed.error, undefined);
      assert.equal(executed.status, 0, executed.stderr.toString("utf8"));
      const parsed =
        prepared.kind === "target-info"
          ? parseFixedProbeOutput("target-info", executed.stdout)
          : parseFixedProbeOutput("docker-preflight", executed.stdout);
      assert.equal(parsed.reportedPlatform, "windows");
      if (parsed.kind === "docker-preflight") {
        assert.equal(parsed.disk.status, "available");
        assert.equal(parsed.disk.requiredBytes, 1);
      }
    }
  },
);

test(
  "keeps generated Unix scripts syntactically valid",
  { skip: process.platform === "win32" },
  () => {
    for (const platform of ["linux", "macos"] as const) {
      for (const prepared of [
        prepareFixedProbe(platform, "target-info"),
        prepareFixedProbe(platform, "docker-preflight", {
          project: {
            directory: "/srv/app",
            composeFiles: ["compose.yaml"],
            name: "app",
          },
          ports: [{ protocol: "tcp", port: 8080 }],
        }),
        prepareFixedProbe(platform, "docker-preflight", {
          requiredFreeBytes: 1,
        }),
      ]) {
        const checked = spawnSync("/bin/sh", ["-n"], {
          input: prepared.stdin,
          encoding: "buffer",
        });
        assert.equal(checked.status, 0, checked.stderr.toString("utf8"));
      }
    }
  },
);
