import path from "node:path";

import { z } from "zod";

import { prepareRemoteCommand } from "./remote-command.js";

export const FIXED_PROBE_OUTPUT_PROTOCOL = "agent-ssh-probe-v1" as const;
export const MAX_FIXED_PROBE_OUTPUT_BYTES = 128 * 1024;
export const MAX_FIXED_PROBE_STDIN_BYTES = 256 * 1024;

export const FIXED_PROBE_PLATFORMS = ["windows", "linux", "macos"] as const;
export type FixedProbePlatform = (typeof FIXED_PROBE_PLATFORMS)[number];

export const FIXED_PROBE_KINDS = ["target-info", "docker-preflight"] as const;
export type FixedProbeKind = (typeof FIXED_PROBE_KINDS)[number];

export interface DockerPreflightPortInput {
  readonly protocol: "tcp" | "udp";
  readonly port: number;
}

export interface DockerPreflightProjectInput {
  readonly directory: string;
  readonly composeFiles?: readonly string[];
  readonly name?: string;
}

export type DockerPreflightIntent = "create" | "update" | "inspect";

export interface DockerPreflightProbePayload {
  readonly intent?: DockerPreflightIntent;
  readonly project?: DockerPreflightProjectInput;
  readonly ports?: readonly DockerPreflightPortInput[];
  readonly requiredFreeBytes?: number;
}

export interface PreparedFixedProbe {
  readonly platform: FixedProbePlatform;
  readonly kind: FixedProbeKind;
  readonly command: string;
  readonly stdin: Uint8Array;
  readonly outputProtocol: typeof FIXED_PROBE_OUTPUT_PROTOCOL;
  readonly maxOutputBytes: number;
}

interface NormalizedDockerPayload {
  readonly intent: DockerPreflightIntent;
  readonly project?: {
    readonly directory: string;
    readonly composeFiles: readonly string[];
    readonly name?: string;
  };
  readonly ports: readonly DockerPreflightPortInput[];
  readonly requiredFreeBytes?: number;
}

const SAFE_PROJECT_NAME_PATTERN = /^[a-z0-9][a-z0-9_-]{0,62}$/;
const SAFE_COMPOSE_SEGMENT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

const portSchema = z.strictObject({
  protocol: z.enum(["tcp", "udp"]),
  port: z.number().int().min(1).max(65_535),
});

const projectSchema = z.strictObject({
  directory: z
    .string()
    .min(1)
    .max(4_096)
    .refine((value) => !/[\u0000-\u001f\u007f]/u.test(value), "contains control characters"),
  composeFiles: z.array(z.string().min(1).max(512)).max(8).optional(),
  name: z.string().regex(SAFE_PROJECT_NAME_PATTERN).optional(),
});

const dockerPayloadSchema = z
  .strictObject({
    intent: z.enum(["create", "update", "inspect"]).default("create"),
    project: projectSchema.optional(),
    ports: z.array(portSchema).max(64).optional(),
    requiredFreeBytes: z.number().int().safe().nonnegative().optional(),
  })
  .superRefine((value, context) => {
    const ports = value.ports ?? [];
    const identities = ports.map((entry) => `${entry.protocol}:${entry.port}`);
    if (new Set(identities).size !== identities.length) {
      context.addIssue({
        code: "custom",
        path: ["ports"],
        message: "must not contain duplicate protocol and port pairs",
      });
    }
  });

export function prepareFixedProbe(
  platform: FixedProbePlatform,
  kind: "target-info",
): PreparedFixedProbe;
export function prepareFixedProbe(
  platform: FixedProbePlatform,
  kind: "docker-preflight",
  payload: DockerPreflightProbePayload,
): PreparedFixedProbe;
export function prepareFixedProbe(
  platform: FixedProbePlatform,
  kind: FixedProbeKind,
  payload?: DockerPreflightProbePayload,
): PreparedFixedProbe {
  assertPlatform(platform);
  if (kind === "target-info") {
    if (payload !== undefined) {
      throw new TypeError("target-info does not accept a payload");
    }
    return finishProbe(platform, kind, buildTargetInfoScript(platform));
  }
  if (kind !== "docker-preflight") {
    throw new TypeError("Unsupported fixed probe kind");
  }
  if (payload === undefined) {
    throw new TypeError("docker-preflight requires a payload");
  }
  const normalized = normalizeDockerPayload(platform, payload);
  return finishProbe(platform, kind, buildDockerPreflightScript(platform, normalized));
}

function finishProbe(
  platform: FixedProbePlatform,
  kind: FixedProbeKind,
  script: string,
): PreparedFixedProbe {
  if (!isAscii(script)) {
    throw new Error("Fixed probe scripts must remain ASCII");
  }
  const prepared =
    platform === "windows"
      ? prepareRemoteCommand("windows", script)
      : { command: "/bin/sh -s", stdin: Buffer.from(`${script}\n`, "ascii") };
  if (prepared.stdin === undefined) {
    throw new Error("Fixed probes must be delivered through managed stdin");
  }
  if (prepared.stdin.byteLength > MAX_FIXED_PROBE_STDIN_BYTES) {
    throw new RangeError("Fixed probe script exceeds the managed stdin limit");
  }
  return Object.freeze({
    platform,
    kind,
    command: prepared.command,
    stdin: Buffer.from(prepared.stdin),
    outputProtocol: FIXED_PROBE_OUTPUT_PROTOCOL,
    maxOutputBytes: MAX_FIXED_PROBE_OUTPUT_BYTES,
  });
}

function normalizeDockerPayload(
  platform: FixedProbePlatform,
  input: DockerPreflightProbePayload,
): NormalizedDockerPayload {
  const parsed = dockerPayloadSchema.parse(input);
  const project = parsed.project;
  if (project !== undefined) {
    assertRemoteAbsolutePath(platform, project.directory);
    for (const file of project.composeFiles ?? []) {
      assertSafeComposeRelativePath(file);
    }
  }
  return Object.freeze({
    intent: parsed.intent,
    ...(project === undefined
      ? {}
      : {
          project: Object.freeze({
            directory: project.directory,
            composeFiles: Object.freeze([...(project.composeFiles ?? [])]),
            ...(project.name === undefined ? {} : { name: project.name }),
          }),
        }),
    ports: Object.freeze((parsed.ports ?? []).map((entry) => Object.freeze({ ...entry }))),
    ...(parsed.requiredFreeBytes === undefined
      ? {}
      : { requiredFreeBytes: parsed.requiredFreeBytes }),
  });
}

function assertPlatform(platform: string): asserts platform is FixedProbePlatform {
  if (!(FIXED_PROBE_PLATFORMS as readonly string[]).includes(platform)) {
    throw new TypeError("Unsupported fixed probe platform");
  }
}

function assertRemoteAbsolutePath(platform: FixedProbePlatform, value: string): void {
  if (platform === "windows") {
    if (
      !/^[A-Za-z]:[\\/]/u.test(value) ||
      /^(?:\\\\|\/\/|\\[?.]\\)/u.test(value) ||
      /[:*?<>|"]/u.test(value.slice(2)) ||
      !path.win32.isAbsolute(value)
    ) {
      throw new TypeError("Windows project directory must be a local drive absolute path");
    }
    return;
  }
  if (!value.startsWith("/") || !path.posix.isAbsolute(value)) {
    throw new TypeError("Unix project directory must be an absolute path");
  }
}

function assertSafeComposeRelativePath(value: string): void {
  if (value.includes("\\") || value.startsWith("/") || value.includes("//")) {
    throw new TypeError("Compose files must be relative paths inside the project directory");
  }
  const segments = value.split("/");
  if (
    segments.length === 0 ||
    segments.some(
      (segment) =>
        segment === "." ||
        segment === ".." ||
        !SAFE_COMPOSE_SEGMENT_PATTERN.test(segment),
    )
  ) {
    throw new TypeError("Compose file path contains an unsafe segment");
  }
}

function buildTargetInfoScript(platform: FixedProbePlatform): string {
  return platform === "windows"
    ? windowsTargetInfoScript()
    : unixTargetInfoScript(platform);
}

function buildDockerPreflightScript(
  platform: FixedProbePlatform,
  payload: NormalizedDockerPayload,
): string {
  return platform === "windows"
    ? windowsDockerPreflightScript(payload)
    : unixDockerPreflightScript(platform, payload);
}

function windowsPrelude(kind: FixedProbeKind): string[] {
  return [
    "$ErrorActionPreference='SilentlyContinue'",
    "$agentUtf8=New-Object System.Text.UTF8Encoding($false)",
    "[Console]::InputEncoding=$agentUtf8",
    "[Console]::OutputEncoding=$agentUtf8",
    "$OutputEncoding=$agentUtf8",
    "function AgentEmit([string]$Key,[object]$Value){if($null -eq $Value){return};$Text=[Convert]::ToString($Value,[Globalization.CultureInfo]::InvariantCulture);$Bytes=[Text.Encoding]::UTF8.GetBytes($Text);[Console]::Out.WriteLine($Key+':'+[Convert]::ToBase64String($Bytes))}",
    "function AgentFirstLine($Value){if($null -eq $Value){return $null};$Line=[string]($Value|Select-Object -First 1);return $Line.Trim()}",
    `[Console]::Out.WriteLine('${FIXED_PROBE_OUTPUT_PROTOCOL}\t${kind}')`,
    "AgentEmit 'platform' 'windows'",
  ];
}

function windowsDockerFacts(): string[] {
  return [
    "$agentDockerCommand=Get-Command docker.exe -CommandType Application -ErrorAction SilentlyContinue|Select-Object -First 1",
    "$agentDockerPath=if($null -eq $agentDockerCommand){$null}else{$agentDockerCommand.Source}",
    "AgentEmit 'docker.installed' $(if($null -eq $agentDockerPath){'false'}else{'true'})",
    "$agentDockerReachable=$false",
    "$agentComposeProvider=$null",
    "$agentComposePath=$null",
    "if($null -ne $agentDockerPath){$agentClient=AgentFirstLine (& $agentDockerPath version --format '{{.Client.Version}}' 2>$null);if($LASTEXITCODE -eq 0 -and $agentClient){AgentEmit 'docker.clientVersion' $agentClient};$agentServer=AgentFirstLine (& $agentDockerPath version --format '{{.Server.Version}}' 2>$null);if($LASTEXITCODE -eq 0 -and $agentServer){$agentDockerReachable=$true;AgentEmit 'docker.serverVersion' $agentServer};$agentComposeVersion=AgentFirstLine (& $agentDockerPath compose version --short 2>$null);if($LASTEXITCODE -eq 0 -and $agentComposeVersion){$agentComposeProvider='plugin';AgentEmit 'compose.version' $agentComposeVersion}}",
    "if($null -eq $agentComposeProvider){$agentStandalone=Get-Command docker-compose.exe -CommandType Application -ErrorAction SilentlyContinue|Select-Object -First 1;if($null -ne $agentStandalone){$agentStandaloneVersion=AgentFirstLine (& $agentStandalone.Source version --short 2>$null);if($LASTEXITCODE -eq 0 -and $agentStandaloneVersion){$agentComposeProvider='standalone';$agentComposePath=$agentStandalone.Source;AgentEmit 'compose.version' $agentStandaloneVersion}}}",
    "AgentEmit 'docker.daemonReachable' $(if($agentDockerReachable){'true'}else{'false'})",
    "AgentEmit 'compose.installed' $(if($null -eq $agentComposeProvider){'false'}else{'true'})",
    "if($null -ne $agentComposeProvider){AgentEmit 'compose.provider' $agentComposeProvider}",
    "if($agentDockerReachable){$agentContext=AgentFirstLine (& $agentDockerPath context show 2>$null);if($LASTEXITCODE -eq 0 -and $agentContext -match '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$'){AgentEmit 'docker.contextName' $agentContext;$agentContextJson=(& $agentDockerPath context inspect $agentContext 2>$null|Out-String);$agentEndpoint=$null;try{$agentContextObject=$agentContextJson|ConvertFrom-Json -ErrorAction Stop;$agentEndpoint=[string]$agentContextObject[0].Endpoints.docker.Host}catch{};if($agentEndpoint -match '^(npipe|unix)://'){AgentEmit 'docker.contextScope' 'local'}elseif($agentEndpoint -match '^(tcp|ssh)://'){AgentEmit 'docker.contextScope' 'remote'}else{AgentEmit 'docker.contextScope' 'unknown'}}}",
  ];
}

function windowsTargetInfoScript(): string {
  return [
    ...windowsPrelude("target-info"),
    "$agentMachineId=(Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography' -Name MachineGuid -ErrorAction SilentlyContinue).MachineGuid",
    "if($agentMachineId -match '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'){AgentEmit 'machine.nativeId' $agentMachineId.ToLowerInvariant()}",
    "$agentHostname=[Environment]::MachineName",
    "if($agentHostname){AgentEmit 'machine.hostname' $agentHostname}",
    "$agentOs=Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue",
    "if($null -ne $agentOs){AgentEmit 'os.name' $agentOs.Caption;AgentEmit 'os.version' $agentOs.Version;AgentEmit 'os.build' $agentOs.BuildNumber;AgentEmit 'os.architecture' $agentOs.OSArchitecture}",
    "AgentEmit 'os.kernel' ([Environment]::OSVersion.VersionString)",
    "$agentDriveRoot=[IO.Path]::GetPathRoot([Environment]::SystemDirectory)",
    "try{$agentDrive=New-Object IO.DriveInfo($agentDriveRoot);if($agentDrive.IsReady){AgentEmit 'disk.path' $agentDrive.Name;AgentEmit 'disk.totalBytes' $agentDrive.TotalSize;AgentEmit 'disk.availableBytes' $agentDrive.AvailableFreeSpace}}catch{}",
    ...windowsDockerFacts(),
    `[Console]::Out.WriteLine('AGENT_SSH_PROBE_END')`,
  ].join("\n");
}

function windowsDockerPreflightScript(payload: NormalizedDockerPayload): string {
  const payloadBase64 = Buffer.from(canonicalDockerPayload(payload), "utf8").toString("base64");
  return [
    ...windowsPrelude("docker-preflight"),
    `$agentInput=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${payloadBase64}')))`,
    "AgentEmit 'preflight.intent' ([string]$agentInput.intent)",
    ...windowsDockerFacts(),
    "function AgentPortOwnership([string]$Protocol,[int]$Port,[string]$Observation,[string]$ProjectName){if(-not $agentDockerReachable){return 'unknown'};$agentPublishFilter='publish='+$Port+'/'+$Protocol;$agentAllRaw=@(& $agentDockerPath ps -q --filter $agentPublishFilter 2>$null);if($LASTEXITCODE -ne 0){return 'unknown'};$agentAll=@($agentAllRaw|ForEach-Object{([string]$_).Trim()}|Where-Object{$_});if(@($agentAll|Where-Object{$_ -notmatch '^[0-9a-f]{12,64}$'}).Count -gt 0){return 'unknown'};if($agentAll.Count -gt 0){if($ProjectName){$agentProjectFilter='label=com.docker.compose.project='+$ProjectName;$agentRequestedRaw=@(& $agentDockerPath ps -q --filter $agentPublishFilter --filter $agentProjectFilter 2>$null);if($LASTEXITCODE -ne 0){return 'unknown'};$agentRequested=@($agentRequestedRaw|ForEach-Object{([string]$_).Trim()}|Where-Object{$_});if(@($agentRequested|Where-Object{$_ -notmatch '^[0-9a-f]{12,64}$'}).Count -gt 0){return 'unknown'};if($agentRequested.Count -gt 0){if(@($agentAll|Where-Object{$agentRequested -notcontains $_}).Count -gt 0){return 'other-container'};return 'requested-project'}};return 'other-container'};if($Observation -eq 'listener-observed'){return 'host-process'};return 'unknown'}",
    "$agentProjectRequested=$null -ne $agentInput.project",
    "$agentRequestedProjectName=if($agentProjectRequested -and $null -ne $agentInput.project.name){[string]$agentInput.project.name}else{''}",
    "AgentEmit 'compose.requested' $(if($agentProjectRequested){'true'}else{'false'})",
    "$agentConfigStatus='not-requested'",
    "if($agentProjectRequested){if(-not $agentDockerReachable -or $null -eq $agentComposeProvider){$agentConfigStatus='unavailable'}else{$agentPushed=$false;try{Push-Location -LiteralPath ([string]$agentInput.project.directory) -ErrorAction Stop;$agentPushed=$true;$agentArgs=New-Object Collections.Generic.List[string];if($agentComposeProvider -eq 'plugin'){$agentArgs.Add('compose')};if($null -ne $agentInput.project.name){$agentArgs.Add('-p');$agentArgs.Add([string]$agentInput.project.name)};foreach($agentFile in @($agentInput.project.composeFiles)){$agentArgs.Add('-f');$agentArgs.Add([string]$agentFile)};$agentArgs.Add('config');$agentArgs.Add('--quiet');$agentArgumentArray=$agentArgs.ToArray();$agentComposeExecutable=if($agentComposeProvider -eq 'plugin'){$agentDockerPath}else{$agentComposePath};& $agentComposeExecutable @agentArgumentArray >$null 2>&1;$agentConfigStatus=if($LASTEXITCODE -eq 0){'valid'}else{'invalid'}}catch{$agentConfigStatus='unavailable'}finally{if($agentPushed){Pop-Location -ErrorAction SilentlyContinue}}}}",
    "AgentEmit 'compose.config' $agentConfigStatus",
    `AgentEmit 'ports.count' '${payload.ports.length}'`,
    ...payload.ports.flatMap((entry, index) => [
      `AgentEmit 'port.${index}.protocol' '${entry.protocol}'`,
      `AgentEmit 'port.${index}.port' '${entry.port}'`,
      `$agentPortObservation='unknown';try{if('${entry.protocol}' -eq 'tcp'){$agentListeners=@(Get-NetTCPConnection -State Listen -LocalPort ${entry.port} -ErrorAction Stop)}else{$agentListeners=@(Get-NetUDPEndpoint -LocalPort ${entry.port} -ErrorAction Stop)};$agentPortObservation=if($agentListeners.Count -gt 0){'listener-observed'}else{'not-observed'}}catch{};AgentEmit 'port.${index}.observation' $agentPortObservation;$agentPortOwnership=AgentPortOwnership '${entry.protocol}' '${entry.port}' $agentPortObservation $agentRequestedProjectName;AgentEmit 'port.${index}.ownership' $agentPortOwnership`,
    ]),
    "$agentContainerStatus='not-requested'",
    "$agentContainerCount=0",
    "$agentContainersTruncated=$false",
    "if($null -ne $agentInput.project -and $null -ne $agentInput.project.name){$agentFilter='label=com.docker.compose.project='+[string]$agentInput.project.name;AgentEmit 'containers.filter' $agentFilter;if($agentDockerReachable){$agentContainerStatus='ok';$agentIds=@(& $agentDockerPath ps -aq --filter $agentFilter 2>$null);if($LASTEXITCODE -ne 0){$agentContainerStatus='unavailable'}else{foreach($agentIdValue in $agentIds){$agentId=([string]$agentIdValue).Trim();if($agentId -notmatch '^[0-9a-f]{12,64}$'){$agentContainerStatus='unavailable';break};if($agentContainerCount -ge 100){$agentContainersTruncated=$true;break};$agentInspect=AgentFirstLine (& $agentDockerPath inspect --format '{{json .}}' $agentId 2>$null);if($LASTEXITCODE -ne 0 -or -not $agentInspect){$agentContainerStatus='unavailable';break};try{$agentObject=$agentInspect|ConvertFrom-Json -ErrorAction Stop;$agentName=[string]$agentObject.Name;$agentState=[string]$agentObject.State.Status;$agentHealth=if($null -ne $agentObject.State.Health){[string]$agentObject.State.Health.Status}else{'none'};$agentService='';$agentServiceProperty=$agentObject.Config.Labels.PSObject.Properties['com.docker.compose.service'];if($null -ne $agentServiceProperty){$agentService=[string]$agentServiceProperty.Value};$agentRecord=$agentName+'|'+$agentState+'|'+$agentHealth+'|'+$agentService;AgentEmit ('container.'+$agentContainerCount+'.record') $agentRecord;$agentContainerCount++}catch{$agentContainerStatus='unavailable';break}}}}else{$agentContainerStatus='unavailable'}}",
    "AgentEmit 'containers.status' $agentContainerStatus",
    "AgentEmit 'containers.count' $agentContainerCount",
    "AgentEmit 'containers.truncated' $(if($agentContainersTruncated){'true'}else{'false'})",
    "$agentDiskRequested=$agentProjectRequested -or $null -ne $agentInput.requiredFreeBytes",
    "$agentDiskStatus='not-requested'",
    "if($agentDiskRequested){$agentDiskStatus='unavailable';try{$agentCandidate=if($agentProjectRequested){[string]$agentInput.project.directory}else{[Environment]::SystemDirectory};while(-not (Test-Path -LiteralPath $agentCandidate)){[string]$agentParent=[IO.Path]::GetDirectoryName($agentCandidate);if(-not $agentParent -or $agentParent -eq $agentCandidate){break};$agentCandidate=$agentParent};$agentRoot=[IO.Path]::GetPathRoot($agentCandidate);$agentDrive=New-Object IO.DriveInfo($agentRoot);if($agentDrive.IsReady){$agentDiskStatus='available';AgentEmit 'disk.path' $agentDrive.Name;AgentEmit 'disk.totalBytes' $agentDrive.TotalSize;AgentEmit 'disk.availableBytes' $agentDrive.AvailableFreeSpace}}catch{}}",
    "AgentEmit 'disk.status' $agentDiskStatus",
    "if($null -ne $agentInput.requiredFreeBytes){AgentEmit 'disk.requiredBytes' ([Int64]$agentInput.requiredFreeBytes)}",
    `[Console]::Out.WriteLine('AGENT_SSH_PROBE_END')`,
  ].join("\n");
}

function unixPrelude(platform: "linux" | "macos", kind: FixedProbeKind): string[] {
  const decodeFlag = platform === "macos" ? "-D" : "-d";
  const base64Command = platform === "macos" ? "/usr/bin/base64" : "base64";
  return [
    "set -u",
    "umask 077",
    `AGENT_BASE64='${base64Command}'`,
    `agent_decode(){ printf '%s' \"$1\" | \"$AGENT_BASE64\" ${decodeFlag}; }`,
    "agent_emit(){ agent_emit_key=$1;agent_emit_value=$2;printf '%s:' \"$agent_emit_key\";printf '%s' \"$agent_emit_value\" | \"$AGENT_BASE64\" | tr -d '\\r\\n';printf '\\n'; }",
    "agent_first_line(){ sed -n '1{s/\\r$//;p;}'; }",
    `printf '${FIXED_PROBE_OUTPUT_PROTOCOL}\\t${kind}\\n'`,
    `agent_emit platform '${platform}'`,
  ];
}

function unixDockerFacts(): string[] {
  return [
    "agent_docker_path=$(command -v docker 2>/dev/null || :) ",
    "case $agent_docker_path in /*) if [ -x \"$agent_docker_path\" ];then agent_docker_installed=true;else agent_docker_installed=false;fi;; *) agent_docker_installed=false;; esac",
    "agent_emit docker.installed \"$agent_docker_installed\"",
    "agent_docker_reachable=false",
    "agent_compose_installed=false",
    "agent_compose_provider=''",
    "agent_compose_path=''",
    "if [ \"$agent_docker_installed\" = true ];then agent_client=$(\"$agent_docker_path\" version --format '{{.Client.Version}}' 2>/dev/null | agent_first_line || :);if [ -n \"$agent_client\" ];then agent_emit docker.clientVersion \"$agent_client\";fi;agent_server=$(\"$agent_docker_path\" version --format '{{.Server.Version}}' 2>/dev/null | agent_first_line || :);if [ -n \"$agent_server\" ];then agent_docker_reachable=true;agent_emit docker.serverVersion \"$agent_server\";fi;agent_compose_version=$(\"$agent_docker_path\" compose version --short 2>/dev/null | agent_first_line || :);if [ -n \"$agent_compose_version\" ];then agent_compose_installed=true;agent_compose_provider=plugin;agent_emit compose.version \"$agent_compose_version\";fi;fi",
    "if [ \"$agent_compose_installed\" = false ];then agent_compose_path=$(command -v docker-compose 2>/dev/null || :);case $agent_compose_path in /*) if [ -x \"$agent_compose_path\" ];then agent_compose_version=$(\"$agent_compose_path\" version --short 2>/dev/null | agent_first_line || :);if [ -n \"$agent_compose_version\" ];then agent_compose_installed=true;agent_compose_provider=standalone;agent_emit compose.version \"$agent_compose_version\";fi;fi;; esac;fi",
    "agent_emit docker.daemonReachable \"$agent_docker_reachable\"",
    "agent_emit compose.installed \"$agent_compose_installed\"",
    "if [ -n \"$agent_compose_provider\" ];then agent_emit compose.provider \"$agent_compose_provider\";fi",
    "if [ \"$agent_docker_reachable\" = true ];then agent_context=$(\"$agent_docker_path\" context show 2>/dev/null | agent_first_line || :);if printf '%s' \"$agent_context\" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$';then agent_emit docker.contextName \"$agent_context\";agent_endpoint=$(\"$agent_docker_path\" context inspect --format '{{(index .Endpoints \"docker\").Host}}' \"$agent_context\" 2>/dev/null | agent_first_line || :);case $agent_endpoint in unix://*|npipe://*) agent_emit docker.contextScope local;;tcp://*|ssh://*) agent_emit docker.contextScope remote;;*) agent_emit docker.contextScope unknown;;esac;fi;fi",
  ];
}

function unixTargetInfoScript(platform: "linux" | "macos"): string {
  const platformFacts =
    platform === "linux"
      ? [
          "agent_machine_id=''",
          "if [ -r /etc/machine-id ];then agent_machine_id=$(tr -d '[:space:]' </etc/machine-id);elif [ -r /var/lib/dbus/machine-id ];then agent_machine_id=$(tr -d '[:space:]' </var/lib/dbus/machine-id);fi",
          "if printf '%s' \"$agent_machine_id\" | grep -Eq '^[0-9A-Fa-f]{32}$';then agent_emit machine.nativeId \"$(printf '%s' \"$agent_machine_id\" | tr 'A-F' 'a-f')\";fi",
          "if [ -r /etc/os-release ];then agent_os_name=$(awk -F= '$1==\"PRETTY_NAME\"{sub(/^[^=]*=/,\"\");sub(/^\"/,\"\");sub(/\"$/,\"\");print;exit}' /etc/os-release);agent_os_version=$(awk -F= '$1==\"VERSION_ID\"{sub(/^[^=]*=/,\"\");sub(/^\"/,\"\");sub(/\"$/,\"\");print;exit}' /etc/os-release);if [ -n \"$agent_os_name\" ];then agent_emit os.name \"$agent_os_name\";fi;if [ -n \"$agent_os_version\" ];then agent_emit os.version \"$agent_os_version\";fi;fi",
        ]
      : [
          "agent_machine_id=$(/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'\"' '/\"IOPlatformUUID\"/{print $(NF-1);exit}')",
          "if printf '%s' \"$agent_machine_id\" | grep -Eq '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$';then agent_emit machine.nativeId \"$(printf '%s' \"$agent_machine_id\" | tr 'A-F' 'a-f')\";fi",
          "agent_os_name=$(sw_vers -productName 2>/dev/null | agent_first_line || :);agent_os_version=$(sw_vers -productVersion 2>/dev/null | agent_first_line || :);agent_os_build=$(sw_vers -buildVersion 2>/dev/null | agent_first_line || :);if [ -n \"$agent_os_name\" ];then agent_emit os.name \"$agent_os_name\";fi;if [ -n \"$agent_os_version\" ];then agent_emit os.version \"$agent_os_version\";fi;if [ -n \"$agent_os_build\" ];then agent_emit os.build \"$agent_os_build\";fi",
        ];
  return [
    ...unixPrelude(platform, "target-info"),
    ...platformFacts,
    "agent_hostname=$(hostname 2>/dev/null | agent_first_line || :);if [ -n \"$agent_hostname\" ];then agent_emit machine.hostname \"$agent_hostname\";fi",
    "agent_kernel=$(uname -sr 2>/dev/null | agent_first_line || :);agent_arch=$(uname -m 2>/dev/null | agent_first_line || :);if [ -n \"$agent_kernel\" ];then agent_emit os.kernel \"$agent_kernel\";fi;if [ -n \"$agent_arch\" ];then agent_emit os.architecture \"$agent_arch\";fi",
    "agent_disk_total=$(df -Pk / 2>/dev/null | awk 'END{print $2}');agent_disk_available=$(df -Pk / 2>/dev/null | awk 'END{print $4}');case $agent_disk_total:$agent_disk_available in *[!0-9:]*|'':);;*) agent_emit disk.path /;agent_emit disk.totalBytes \"$((agent_disk_total*1024))\";agent_emit disk.availableBytes \"$((agent_disk_available*1024))\";;esac",
    ...unixDockerFacts(),
    "printf 'AGENT_SSH_PROBE_END\\n'",
  ].join("\n");
}

function unixDockerPreflightScript(
  platform: "linux" | "macos",
  payload: NormalizedDockerPayload,
): string {
  const project = payload.project;
  const projectValue = project === undefined ? "" : encodeText(project.directory);
  const projectName = project?.name === undefined ? "" : encodeText(project.name);
  const composeArgumentLines = (project?.composeFiles ?? []).map(
    (file) => `set -- \"$@\" -f \"$(agent_decode '${encodeText(file)}')\"`,
  );
  const portLines = payload.ports.flatMap((entry, index) => [
    `agent_emit port.${index}.protocol '${entry.protocol}'`,
    `agent_emit port.${index}.port '${entry.port}'`,
    `agent_check_port '${entry.protocol}' '${entry.port}' '${index}'`,
    `agent_port_ownership_result=$(agent_port_ownership '${entry.protocol}' '${entry.port}' "$agent_observation" "$agent_project_name");agent_emit port.${index}.ownership "$agent_port_ownership_result"`,
  ]);
  const portFunction =
    platform === "linux"
      ? "agent_check_port(){ agent_protocol=$1;agent_port=$2;agent_index=$3;agent_hex=$(printf '%04X' \"$agent_port\");agent_seen_file=false;agent_found=false;if [ \"$agent_protocol\" = tcp ];then agent_files='/proc/net/tcp /proc/net/tcp6';agent_state=0A;else agent_files='/proc/net/udp /proc/net/udp6';agent_state='';fi;for agent_file in $agent_files;do if [ -r \"$agent_file\" ];then agent_seen_file=true;if awk -v suffix=\":$agent_hex\" -v state=\"$agent_state\" '$2 ~ (suffix \"$\") && (state==\"\" || $4==state){found=1}END{exit found?0:1}' \"$agent_file\";then agent_found=true;break;fi;fi;done;if [ \"$agent_found\" = true ];then agent_observation=listener-observed;elif [ \"$agent_seen_file\" = true ];then agent_observation=not-observed;else agent_observation=unknown;fi;agent_emit \"port.$agent_index.observation\" \"$agent_observation\"; }"
      : "agent_check_port(){ agent_protocol=$1;agent_port=$2;agent_index=$3;if [ \"$agent_protocol\" = tcp ];then /usr/sbin/lsof -nP \"-iTCP:$agent_port\" -sTCP:LISTEN >/dev/null 2>&1;else /usr/sbin/lsof -nP \"-iUDP:$agent_port\" >/dev/null 2>&1;fi;agent_code=$?;if [ $agent_code -eq 0 ];then agent_observation=listener-observed;elif [ $agent_code -eq 1 ];then agent_observation=not-observed;else agent_observation=unknown;fi;agent_emit \"port.$agent_index.observation\" \"$agent_observation\"; }";
  const portOwnershipFunction =
    "agent_port_ownership(){ agent_owner_protocol=$1;agent_owner_port=$2;agent_owner_observation=$3;agent_owner_project=$4;if [ \"$agent_docker_reachable\" != true ];then printf unknown;return;fi;agent_owner_publish=publish=$agent_owner_port/$agent_owner_protocol;agent_owner_all=$(\"$agent_docker_path\" ps -q --filter \"$agent_owner_publish\" 2>/dev/null);agent_owner_code=$?;if [ $agent_owner_code -ne 0 ];then printf unknown;return;fi;agent_owner_found=false;for agent_owner_id in $agent_owner_all;do if ! printf '%s' \"$agent_owner_id\" | grep -Eq '^[0-9a-f]{12,64}$';then printf unknown;return;fi;agent_owner_found=true;done;if [ \"$agent_owner_found\" = true ];then if [ -n \"$agent_owner_project\" ];then agent_owner_project_filter=label=com.docker.compose.project=$agent_owner_project;agent_owner_requested=$(\"$agent_docker_path\" ps -q --filter \"$agent_owner_publish\" --filter \"$agent_owner_project_filter\" 2>/dev/null);agent_owner_code=$?;if [ $agent_owner_code -ne 0 ];then printf unknown;return;fi;agent_owner_requested_found=false;for agent_owner_id in $agent_owner_requested;do if ! printf '%s' \"$agent_owner_id\" | grep -Eq '^[0-9a-f]{12,64}$';then printf unknown;return;fi;agent_owner_requested_found=true;done;if [ \"$agent_owner_requested_found\" = true ];then printf requested-project;return;fi;fi;printf other-container;return;fi;if [ \"$agent_owner_observation\" = listener-observed ];then printf host-process;else printf unknown;fi; }";
  return [
    ...unixPrelude(platform, "docker-preflight"),
    portFunction,
    portOwnershipFunction,
    `agent_project_set='${project === undefined ? "false" : "true"}'`,
    `agent_project=$(agent_decode '${projectValue}')`,
    `agent_project_name=$(agent_decode '${projectName}')`,
    `agent_emit preflight.intent '${payload.intent}'`,
    ...unixDockerFacts(),
    "agent_emit compose.requested \"$agent_project_set\"",
    "agent_config_status=not-requested",
    "if [ \"$agent_project_set\" = true ];then if [ \"$agent_docker_reachable\" != true ] || [ \"$agent_compose_installed\" != true ] || [ ! -d \"$agent_project\" ];then agent_config_status=unavailable;else if [ \"$agent_compose_provider\" = plugin ];then set -- \"$agent_docker_path\" compose;else set -- \"$agent_compose_path\";fi",
    ...(project?.name === undefined
      ? []
      : ["set -- \"$@\" -p \"$agent_project_name\""]),
    ...composeArgumentLines,
    "set -- \"$@\" config --quiet;if (cd \"$agent_project\" && \"$@\" >/dev/null 2>&1);then agent_config_status=valid;else agent_config_status=invalid;fi;fi;fi",
    "agent_emit compose.config \"$agent_config_status\"",
    `agent_emit ports.count '${payload.ports.length}'`,
    ...portLines,
    "agent_container_status=not-requested;agent_container_count=0;agent_containers_truncated=false",
    "if [ -n \"$agent_project_name\" ];then agent_container_filter=label=com.docker.compose.project=$agent_project_name;agent_emit containers.filter \"$agent_container_filter\";if [ \"$agent_docker_reachable\" = true ];then agent_container_status=ok;agent_ids=$(\"$agent_docker_path\" ps -aq --filter \"$agent_container_filter\" 2>/dev/null);agent_ids_code=$?;if [ $agent_ids_code -ne 0 ];then agent_container_status=unavailable;else for agent_id in $agent_ids;do if ! printf '%s' \"$agent_id\" | grep -Eq '^[0-9a-f]{12,64}$';then agent_container_status=unavailable;break;fi;if [ $agent_container_count -ge 100 ];then agent_containers_truncated=true;break;fi;agent_record=$(\"$agent_docker_path\" inspect --format '{{.Name}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{index .Config.Labels \"com.docker.compose.service\"}}' \"$agent_id\" 2>/dev/null);agent_inspect_code=$?;agent_record=$(printf '%s\n' \"$agent_record\" | agent_first_line);if [ $agent_inspect_code -ne 0 ] || [ -z \"$agent_record\" ];then agent_container_status=unavailable;break;fi;agent_emit \"container.$agent_container_count.record\" \"$agent_record\";agent_container_count=$((agent_container_count+1));done;fi;else agent_container_status=unavailable;fi;fi",
    "agent_emit containers.status \"$agent_container_status\";agent_emit containers.count \"$agent_container_count\";agent_emit containers.truncated \"$agent_containers_truncated\"",
    `agent_disk_requested='${project !== undefined || payload.requiredFreeBytes !== undefined ? "true" : "false"}'`,
    "agent_disk_status=not-requested",
    "if [ \"$agent_disk_requested\" = true ];then agent_disk_status=unavailable;agent_disk_path=$agent_project;if [ \"$agent_project_set\" != true ];then agent_disk_path=/;fi;while [ ! -e \"$agent_disk_path\" ] && [ \"$agent_disk_path\" != / ];do agent_disk_path=${agent_disk_path%/*};if [ -z \"$agent_disk_path\" ];then agent_disk_path=/;fi;done;agent_disk_total=$(df -Pk \"$agent_disk_path\" 2>/dev/null | awk 'END{print $2}');agent_disk_available=$(df -Pk \"$agent_disk_path\" 2>/dev/null | awk 'END{print $4}');case $agent_disk_total:$agent_disk_available in *[!0-9:]*|'':);;*) agent_disk_status=available;agent_emit disk.path \"$agent_disk_path\";agent_emit disk.totalBytes \"$((agent_disk_total*1024))\";agent_emit disk.availableBytes \"$((agent_disk_available*1024))\";;esac;fi",
    "agent_emit disk.status \"$agent_disk_status\"",
    ...(payload.requiredFreeBytes === undefined
      ? []
      : [`agent_emit disk.requiredBytes '${payload.requiredFreeBytes}'`]),
    "printf 'AGENT_SSH_PROBE_END\\n'",
  ].join("\n");
}

function canonicalDockerPayload(payload: NormalizedDockerPayload): string {
  return JSON.stringify({
    intent: payload.intent,
    ...(payload.project === undefined
      ? {}
      : {
          project: {
            directory: payload.project.directory,
            composeFiles: [...payload.project.composeFiles],
            ...(payload.project.name === undefined ? {} : { name: payload.project.name }),
          },
        }),
    ports: payload.ports.map((entry) => ({
      protocol: entry.protocol,
      port: entry.port,
    })),
    ...(payload.requiredFreeBytes === undefined
      ? {}
      : { requiredFreeBytes: payload.requiredFreeBytes }),
  });
}

function encodeText(value: string): string {
  return Buffer.from(value, "utf8").toString("base64");
}

function isAscii(value: string): boolean {
  return Buffer.from(value, "utf8").every((byte) => byte <= 0x7f);
}
