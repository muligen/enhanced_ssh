import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { buildPresetOperation, listPresetOperations, permissionPresetSelectionSchema } from "../../src/shared/operation-presets.js";
import { GatewayError } from "../../src/shared/errors.js";

const all = permissionPresetSelectionSchema.parse({
  presets: ["basic-inspection", "log-inspection", "docker-readonly", "docker-protection"],
  logPaths: ["/var/log/app.log", "/var/log/app '$(touch forbidden)'.log", "C:\\Logs\\app's $(Remove-Item x).log"],
  logServices: ["app.service", "System"],
});
function fails(code: string) { return (error: unknown) => error instanceof GatewayError && error.code === code; }

test("permission presets grant only selected operations; protection grants none", () => {
  for (const platform of ["linux", "windows", "macos"] as const) {
    const protection = permissionPresetSelectionSchema.parse({ presets: ["docker-protection"] });
    assert.deepEqual(listPresetOperations(protection, platform), []);
    assert.throws(() => buildPresetOperation(protection, platform, { operation: "system.cpu" }), fails("COMMAND_DENIED"));
    const basic = permissionPresetSelectionSchema.parse({ presets: ["basic-inspection", "docker-protection"] });
    assert.equal(listPresetOperations(basic, platform).length, 6);
    assert.throws(() => buildPresetOperation(basic, platform, { operation: "docker.containers" }), fails("COMMAND_DENIED"));
    assert.match(buildPresetOperation(basic, platform, { operation: "system.cpu" }).script, /AGENT_SSH_CPU/u);
  }
});

test("log resources are explicit exact choices and platform appropriate", () => {
  const defaults = permissionPresetSelectionSchema.parse({ presets: ["log-inspection"] });
  assert.equal(listPresetOperations(defaults, "linux").length, 0);
  for (const path of ["/etc/shadow", "/var/log/../etc/shadow", "C:\\Logs\\app.log", "/var/log/app.log\nwhoami"]) {
    assert.throws(() => buildPresetOperation(all, "linux", { operation: "logs.file", parameters: { path } }));
  }
  assert.throws(() => buildPresetOperation(all, "linux", { operation: "logs.service", parameters: { service: "ssh.service" } }), fails("COMMAND_DENIED"));
  const fileOperation = listPresetOperations(all, "linux").find(op => op.id === "logs.file")!;
  assert.deepEqual((fileOperation.parameters.properties as Record<string, { enum: unknown }>).path!.enum, all.logPaths.slice(0, 2));
  assert.throws(() => permissionPresetSelectionSchema.parse({ logPaths: ["relative.log"] }));
  assert.throws(() => permissionPresetSelectionSchema.parse({ logPaths: ["\\\\host\\share\\log"] }));
  assert.throws(() => permissionPresetSelectionSchema.parse({ presets: ["basic-inspection", "basic-inspection"] }));
});

test("preset parameters reject shell, environment, options and unbounded requests", () => {
  const attempts = [
    { operation: "system.identity", script: "whoami" },
    { operation: "system.identity", parameters: { env: { BASH_ENV: "attack" } } },
    { operation: "system.identity", parameters: { command: "whoami" } },
    { operation: "system.processes", parameters: { limit: 101 } },
    { operation: "system.processes", parameters: { limit: "1; touch bad" } },
    { operation: "docker.logs", parameters: { container: "--follow", lines: 20 } },
    { operation: "docker.health", parameters: { container: "foo;reboot" } },
    { operation: "docker.logs", parameters: { container: "foo", lines: 201 } },
    { operation: "logs.service", parameters: { service: "app.service\nreboot" } },
    { operation: "logs.file", parameters: { path: "/var/log/app.log", follow: true } },
  ];
  for (const input of attempts) assert.throws(() => buildPresetOperation(all, "linux", input), fails("INVALID_PARAMS"));
});

test("all supported operations build bounded commands on each platform", () => {
  for (const platform of ["linux", "windows", "macos"] as const) {
    for (const operation of listPresetOperations(all, platform)) {
      const parameters = operation.id === "logs.file" ? { path: platform === "windows" ? all.logPaths[2] : all.logPaths[0] }
        : operation.id === "logs.service" ? { service: "System" }
        : ["docker.logs", "docker.health"].includes(operation.id) ? { container: "web-1" } : {};
      const built = buildPresetOperation(all, platform, { operation: operation.id, parameters });
      assert.equal(built.shell, platform === "windows" ? "powershell" : "bash");
      assert.equal(built.encoding, "utf-8");
      assert.ok(built.script.length < 2048);
      if (operation.id === "docker.health") {
        assert.doesNotMatch(built.script, /\.Config|\.State\.Health\.Log|\.Env/u);
        assert.match(built.script, /--type container --format/u);
      }
      if (operation.id === "system.processes") assert.doesNotMatch(built.script, /CommandLine|args|command=/iu);
      if (platform !== "windows") assert.match(built.script, /^set -o pipefail/u);
    }
  }
});

test("administrator-authorized paths are quoted literally in each shell", () => {
  const unix = buildPresetOperation(all, "linux", { operation: "logs.file", parameters: { path: all.logPaths[1] } });
  assert.ok(unix.script.includes("'/var/log/app '\\''$(touch forbidden)'\\''.log'"));
  const windows = buildPresetOperation(all, "windows", { operation: "logs.file", parameters: { path: all.logPaths[2] } });
  assert.ok(windows.script.includes("'C:\\Logs\\app''s $(Remove-Item x).log'"));
});

test("Windows native Docker format survives PowerShell 5 argument marshalling", { skip: process.platform !== "win32" }, () => {
  // PowerShell executes this test process itself as a native argument recorder;
  // no Docker daemon or remote machine is touched.
  for (const operation of ["docker.containers", "docker.stats", "docker.health"] as const) {
    const built = buildPresetOperation(all, "windows", { operation, parameters: operation === "docker.health" ? { container: "web-1" } : {} });
    // A sentinel prevents the Docker verb "inspect" from being interpreted as
    // Node's own interactive debugger command.
    const native = `& '${process.execPath.replaceAll("'", "''")}' -p 'JSON.stringify(process.argv.slice(2))' -- record`;
    const script = built.script.replace(/^docker /mu, native + " ");
    const environment: NodeJS.ProcessEnv = { ...process.env, PSModulePath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules" };
    // The recorder is a normal native child, not a node:test worker.
    delete environment.NODE_TEST_CONTEXT;
    const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { encoding: "utf8", timeout: 30_000,
      env: environment });
    assert.equal(result.status, 0, result.stderr);
    const args = JSON.parse(result.stdout.trim()) as string[];
    const format = args[args.indexOf("--format") + 1];
    assert.ok(format?.startsWith("[{{json ."), result.stdout);
    assert.ok(format?.endsWith("]"), result.stdout);
    assert.doesNotMatch(format!, /"/u);
    if (operation === "docker.health") assert.equal(args.at(-1), "web-1");
  }
});
