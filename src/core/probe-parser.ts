import { isUtf8 } from "node:buffer";

import {
  FIXED_PROBE_OUTPUT_PROTOCOL,
  MAX_FIXED_PROBE_OUTPUT_BYTES,
  type FixedProbeKind,
  type FixedProbePlatform,
} from "./fixed-probe.js";

export type ProbeWarningCode =
  | "machine-id-unavailable"
  | "hostname-unavailable"
  | "os-info-partial"
  | "disk-info-unavailable"
  | "docker-not-installed"
  | "docker-daemon-unreachable"
  | "docker-context-remote"
  | "compose-not-installed"
  | "compose-config-invalid"
  | "compose-config-unavailable"
  | "port-state-unknown"
  | "port-listener-observed"
  | "container-state-unavailable"
  | "container-unhealthy"
  | "container-starting"
  | "container-list-truncated"
  | "required-disk-space-unavailable"
  | "required-disk-space-insufficient";

export interface ProbeOperatingSystemInfo {
  readonly name?: string;
  readonly version?: string;
  readonly build?: string;
  readonly kernel?: string;
  readonly architecture?: string;
}

export interface ProbeDiskInfo {
  readonly path: string;
  readonly totalBytes: number;
  readonly availableBytes: number;
}

export interface ProbeDockerFacts {
  readonly installed: boolean;
  readonly daemonReachable: boolean;
  readonly clientVersion?: string;
  readonly serverVersion?: string;
  readonly contextName?: string;
  readonly contextScope?: "local" | "remote" | "unknown";
  readonly compose: {
    readonly installed: boolean;
    readonly provider?: "plugin" | "standalone";
    readonly version?: string;
  };
}

export interface TargetInfoProbeResult {
  readonly kind: "target-info";
  readonly reportedPlatform: FixedProbePlatform;
  /** Internal input to machine-identity derivation. Never expose or persist it. */
  readonly nativeMachineId?: string;
  readonly hostname?: string;
  readonly os: ProbeOperatingSystemInfo;
  readonly disk?: ProbeDiskInfo;
  readonly docker: ProbeDockerFacts;
  readonly warnings: readonly ProbeWarningCode[];
}

export interface DockerPortProbeResult {
  readonly protocol: "tcp" | "udp";
  readonly port: number;
  readonly observation: "listener-observed" | "not-observed" | "unknown";
  readonly ownership:
    | "requested-project"
    | "other-container"
    | "host-process"
    | "unknown";
}

export interface DockerContainerProbeResult {
  readonly name: string;
  readonly service?: string;
  readonly state:
    | "created"
    | "restarting"
    | "running"
    | "removing"
    | "paused"
    | "exited"
    | "dead";
  readonly health: "healthy" | "unhealthy" | "starting" | "none";
}

export interface DockerPreflightDiskResult {
  readonly status: "available" | "unavailable" | "not-requested";
  readonly path?: string;
  readonly totalBytes?: number;
  readonly availableBytes?: number;
  readonly requiredBytes?: number;
}

export interface DockerPreflightProbeResult {
  readonly kind: "docker-preflight";
  readonly intent: "create" | "update" | "inspect";
  readonly reportedPlatform: FixedProbePlatform;
  readonly overall: "ready" | "degraded" | "blocked";
  readonly daemon: Omit<ProbeDockerFacts, "compose">;
  readonly compose: ProbeDockerFacts["compose"] & {
    readonly requested: boolean;
    readonly config: "valid" | "invalid" | "unavailable" | "not-requested";
  };
  readonly ports: readonly DockerPortProbeResult[];
  readonly containers: {
    readonly status: "ok" | "unavailable" | "not-requested";
    readonly filter?: string;
    readonly items: readonly DockerContainerProbeResult[];
    readonly truncated: boolean;
  };
  readonly disk: DockerPreflightDiskResult;
  readonly warnings: readonly ProbeWarningCode[];
}

export type FixedProbeResult = TargetInfoProbeResult | DockerPreflightProbeResult;

export class FixedProbeParseError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "FixedProbeParseError";
  }
}

const MAX_PROBE_FIELDS = 512;
const MAX_ENCODED_FIELD_BYTES = 24 * 1024;
const KEY_PATTERN = /^[a-z][A-Za-z0-9]*(?:\.[a-zA-Z0-9]+)*$/;
const CANONICAL_BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const HOSTNAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/;
const SAFE_CONTAINER_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const SAFE_SERVICE_NAME_PATTERN = /^[a-z0-9][a-z0-9_-]{0,127}$/;
const SAFE_DOCKER_CONTEXT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const COMPOSE_PROJECT_FILTER_PATTERN =
  /^label=com\.docker\.compose\.project=[a-z0-9][a-z0-9_-]{0,62}$/;

const TARGET_INFO_KEYS = new Set([
  "platform",
  "machine.nativeId",
  "machine.hostname",
  "os.name",
  "os.version",
  "os.build",
  "os.kernel",
  "os.architecture",
  "disk.path",
  "disk.totalBytes",
  "disk.availableBytes",
  "docker.installed",
  "docker.daemonReachable",
  "docker.clientVersion",
  "docker.serverVersion",
  "docker.contextName",
  "docker.contextScope",
  "compose.installed",
  "compose.provider",
  "compose.version",
]);

const PREFLIGHT_KEYS = new Set([
  "platform",
  "docker.installed",
  "docker.daemonReachable",
  "docker.clientVersion",
  "docker.serverVersion",
  "docker.contextName",
  "docker.contextScope",
  "compose.installed",
  "compose.provider",
  "compose.version",
  "preflight.intent",
  "compose.requested",
  "compose.config",
  "ports.count",
  "containers.status",
  "containers.count",
  "containers.truncated",
  "containers.filter",
  "disk.status",
  "disk.path",
  "disk.totalBytes",
  "disk.availableBytes",
  "disk.requiredBytes",
]);

export function parseFixedProbeOutput(
  kind: "target-info",
  output: Uint8Array | string,
): TargetInfoProbeResult;
export function parseFixedProbeOutput(
  kind: "docker-preflight",
  output: Uint8Array | string,
): DockerPreflightProbeResult;
export function parseFixedProbeOutput(
  kind: FixedProbeKind,
  output: Uint8Array | string,
): FixedProbeResult {
  const fields = parseFrame(kind, output);
  return kind === "target-info"
    ? parseTargetInfo(fields)
    : parseDockerPreflight(fields);
}

function parseFrame(
  expectedKind: FixedProbeKind,
  output: Uint8Array | string,
): ReadonlyMap<string, string> {
  const bytes = typeof output === "string" ? Buffer.from(output, "utf8") : Buffer.from(output);
  if (bytes.length === 0 || bytes.length > MAX_FIXED_PROBE_OUTPUT_BYTES) {
    throw new FixedProbeParseError("Probe output is empty or exceeds its byte limit");
  }
  if (!isUtf8(bytes)) {
    throw new FixedProbeParseError("Probe output is not valid UTF-8");
  }
  const raw = bytes.toString("utf8");
  if (/\r(?!\n)/u.test(raw)) {
    throw new FixedProbeParseError("Probe output contains a bare carriage return");
  }
  const normalized = raw.replaceAll("\r\n", "\n");
  if (!normalized.endsWith("\n")) {
    throw new FixedProbeParseError("Probe output is incomplete");
  }
  const lines = normalized.slice(0, -1).split("\n");
  const expectedHeader = `${FIXED_PROBE_OUTPUT_PROTOCOL}\t${expectedKind}`;
  if (lines[0] !== expectedHeader || lines.at(-1) !== "AGENT_SSH_PROBE_END") {
    throw new FixedProbeParseError("Probe output has an invalid frame boundary");
  }
  const fieldLines = lines.slice(1, -1);
  if (fieldLines.length === 0 || fieldLines.length > MAX_PROBE_FIELDS) {
    throw new FixedProbeParseError("Probe output has an invalid field count");
  }
  const fields = new Map<string, string>();
  for (const line of fieldLines) {
    if (Buffer.byteLength(line, "utf8") > MAX_ENCODED_FIELD_BYTES) {
      throw new FixedProbeParseError("Probe output contains an oversized field");
    }
    const separator = line.indexOf(":");
    if (separator <= 0) {
      throw new FixedProbeParseError("Probe output contains a malformed field");
    }
    const key = line.slice(0, separator);
    const encoded = line.slice(separator + 1);
    if (!KEY_PATTERN.test(key) || fields.has(key)) {
      throw new FixedProbeParseError("Probe output contains an invalid or duplicate key");
    }
    fields.set(key, decodeCanonicalBase64(encoded));
  }
  assertKnownKeys(expectedKind, fields.keys());
  return fields;
}

function decodeCanonicalBase64(encoded: string): string {
  if (
    encoded.length === 0 ||
    encoded.length > MAX_ENCODED_FIELD_BYTES ||
    !CANONICAL_BASE64_PATTERN.test(encoded)
  ) {
    throw new FixedProbeParseError("Probe output contains invalid Base64");
  }
  const decoded = Buffer.from(encoded, "base64");
  if (decoded.toString("base64") !== encoded || !isUtf8(decoded)) {
    throw new FixedProbeParseError("Probe output contains non-canonical or non-UTF-8 data");
  }
  const text = decoded.toString("utf8");
  if (/[\u0000-\u001f\u007f]/u.test(text)) {
    throw new FixedProbeParseError("Probe output contains control characters");
  }
  return text;
}

function assertKnownKeys(kind: FixedProbeKind, keys: Iterable<string>): void {
  for (const key of keys) {
    const known =
      kind === "target-info"
        ? TARGET_INFO_KEYS.has(key)
        : PREFLIGHT_KEYS.has(key) ||
          /^port\.(?:0|[1-9][0-9]*)\.(?:protocol|port|observation|ownership)$/u.test(key) ||
          /^container\.(?:0|[1-9][0-9]*)\.record$/u.test(key);
    if (!known) {
      throw new FixedProbeParseError("Probe output contains an unknown field");
    }
  }
}

function parseTargetInfo(fields: ReadonlyMap<string, string>): TargetInfoProbeResult {
  const reportedPlatform = readPlatform(fields);
  const nativeMachineId = optionalText(fields, "machine.nativeId", 128);
  if (nativeMachineId !== undefined && !isNativeMachineId(reportedPlatform, nativeMachineId)) {
    throw new FixedProbeParseError("Probe returned an invalid native machine ID");
  }
  const hostname = optionalText(fields, "machine.hostname", 255, HOSTNAME_PATTERN);
  const os = readOperatingSystem(fields);
  const disk = readCompleteDisk(fields);
  const docker = readDockerFacts(fields);
  const warnings: ProbeWarningCode[] = [];
  if (nativeMachineId === undefined) warnings.push("machine-id-unavailable");
  if (hostname === undefined) warnings.push("hostname-unavailable");
  if (os.name === undefined || os.version === undefined) warnings.push("os-info-partial");
  if (disk === undefined) warnings.push("disk-info-unavailable");
  appendDockerWarnings(docker, warnings);
  return Object.freeze({
    kind: "target-info",
    reportedPlatform,
    ...(nativeMachineId === undefined ? {} : { nativeMachineId: normalizeNativeId(nativeMachineId) }),
    ...(hostname === undefined ? {} : { hostname }),
    os: Object.freeze(os),
    ...(disk === undefined ? {} : { disk: Object.freeze(disk) }),
    docker: freezeDockerFacts(docker),
    warnings: Object.freeze(warnings),
  });
}

function parseDockerPreflight(
  fields: ReadonlyMap<string, string>,
): DockerPreflightProbeResult {
  const reportedPlatform = readPlatform(fields);
  const docker = readDockerFacts(fields);
  const intent = requiredEnum(fields, "preflight.intent", [
    "create",
    "update",
    "inspect",
  ] as const);
  const requested = requiredBoolean(fields, "compose.requested");
  const config = requiredEnum(fields, "compose.config", [
    "valid",
    "invalid",
    "unavailable",
    "not-requested",
  ] as const);
  if (requested === (config === "not-requested")) {
    throw new FixedProbeParseError("Compose request and config status disagree");
  }
  const ports = readPorts(fields);
  const containers = readContainers(fields);
  if (
    ports.some((entry) =>
      entry.ownership === "requested-project" || entry.ownership === "other-container"
    ) &&
    !docker.daemonReachable
  ) {
    throw new FixedProbeParseError("Container port ownership requires a reachable daemon");
  }
  if (
    ports.some((entry) => entry.ownership === "requested-project") &&
    containers.filter === undefined
  ) {
    throw new FixedProbeParseError("Requested-project port ownership requires a project filter");
  }
  const disk = readPreflightDisk(fields);
  const warnings: ProbeWarningCode[] = [];
  appendDockerWarnings(docker, warnings);
  if (config === "invalid") warnings.push("compose-config-invalid");
  if (config === "unavailable") warnings.push("compose-config-unavailable");
  if (ports.some((entry) => entry.observation === "unknown")) {
    warnings.push("port-state-unknown");
  }
  if (ports.some((entry) => isPortConflict(entry, intent))) {
    warnings.push("port-listener-observed");
  }
  if (containers.status === "unavailable") warnings.push("container-state-unavailable");
  if (containers.items.some((entry) => entry.health === "unhealthy")) {
    warnings.push("container-unhealthy");
  }
  if (containers.items.some((entry) => entry.health === "starting")) {
    warnings.push("container-starting");
  }
  if (containers.truncated) warnings.push("container-list-truncated");
  if (disk.requiredBytes !== undefined && disk.status !== "available") {
    warnings.push("required-disk-space-unavailable");
  } else if (
    disk.requiredBytes !== undefined &&
    disk.availableBytes !== undefined &&
    disk.availableBytes < disk.requiredBytes
  ) {
    warnings.push("required-disk-space-insufficient");
  }
  const overall = deriveOverall(docker, config, intent, ports, containers, disk);
  const daemon = Object.freeze({
    installed: docker.installed,
    daemonReachable: docker.daemonReachable,
    ...(docker.clientVersion === undefined ? {} : { clientVersion: docker.clientVersion }),
    ...(docker.serverVersion === undefined ? {} : { serverVersion: docker.serverVersion }),
    ...(docker.contextName === undefined ? {} : { contextName: docker.contextName }),
    ...(docker.contextScope === undefined ? {} : { contextScope: docker.contextScope }),
  });
  return Object.freeze({
    kind: "docker-preflight",
    intent,
    reportedPlatform,
    overall,
    daemon,
    compose: Object.freeze({ ...docker.compose, requested, config }),
    ports: Object.freeze(ports.map((entry) => Object.freeze(entry))),
    containers: Object.freeze({
      status: containers.status,
      ...optionalProperty("filter", containers.filter),
      items: Object.freeze(containers.items.map((entry) => Object.freeze(entry))),
      truncated: containers.truncated,
    }),
    disk: Object.freeze(disk),
    warnings: Object.freeze(warnings),
  });
}

function readPlatform(fields: ReadonlyMap<string, string>): FixedProbePlatform {
  return requiredEnum(fields, "platform", ["windows", "linux", "macos"] as const);
}

function readOperatingSystem(fields: ReadonlyMap<string, string>): ProbeOperatingSystemInfo {
  return {
    ...optionalProperty("name", optionalText(fields, "os.name", 256)),
    ...optionalProperty("version", optionalText(fields, "os.version", 128)),
    ...optionalProperty("build", optionalText(fields, "os.build", 128)),
    ...optionalProperty("kernel", optionalText(fields, "os.kernel", 256)),
    ...optionalProperty("architecture", optionalText(fields, "os.architecture", 128)),
  };
}

function readCompleteDisk(fields: ReadonlyMap<string, string>): ProbeDiskInfo | undefined {
  const path = optionalText(fields, "disk.path", 4_096);
  const totalBytes = optionalSafeInteger(fields, "disk.totalBytes");
  const availableBytes = optionalSafeInteger(fields, "disk.availableBytes");
  if (path === undefined && totalBytes === undefined && availableBytes === undefined) {
    return undefined;
  }
  if (path === undefined || totalBytes === undefined || availableBytes === undefined) {
    throw new FixedProbeParseError("Probe returned incomplete disk information");
  }
  if (availableBytes > totalBytes) {
    throw new FixedProbeParseError("Probe returned impossible disk information");
  }
  return { path, totalBytes, availableBytes };
}

function readDockerFacts(fields: ReadonlyMap<string, string>): ProbeDockerFacts {
  const installed = requiredBoolean(fields, "docker.installed");
  const daemonReachable = requiredBoolean(fields, "docker.daemonReachable");
  const clientVersion = optionalText(fields, "docker.clientVersion", 128);
  const serverVersion = optionalText(fields, "docker.serverVersion", 128);
  const contextName = optionalText(
    fields,
    "docker.contextName",
    128,
    SAFE_DOCKER_CONTEXT_PATTERN,
  );
  const contextScope = optionalEnum(fields, "docker.contextScope", [
    "local",
    "remote",
    "unknown",
  ] as const);
  const composeInstalled = requiredBoolean(fields, "compose.installed");
  const provider = optionalEnum(fields, "compose.provider", ["plugin", "standalone"] as const);
  const composeVersion = optionalText(fields, "compose.version", 128);
  if (
    (!installed && (daemonReachable || clientVersion !== undefined || serverVersion !== undefined)) ||
    (daemonReachable && serverVersion === undefined) ||
    (!daemonReachable && (contextName !== undefined || contextScope !== undefined)) ||
    ((contextName === undefined) !== (contextScope === undefined)) ||
    (composeInstalled !== (provider !== undefined)) ||
    (!composeInstalled && composeVersion !== undefined)
  ) {
    throw new FixedProbeParseError("Probe returned inconsistent Docker information");
  }
  return {
    installed,
    daemonReachable,
    ...optionalProperty("clientVersion", clientVersion),
    ...optionalProperty("serverVersion", serverVersion),
    ...optionalProperty("contextName", contextName),
    ...optionalProperty("contextScope", contextScope),
    compose: {
      installed: composeInstalled,
      ...optionalProperty("provider", provider),
      ...optionalProperty("version", composeVersion),
    },
  };
}

function readPorts(fields: ReadonlyMap<string, string>): DockerPortProbeResult[] {
  const count = requiredSafeInteger(fields, "ports.count", 64);
  assertDynamicIndexes(fields, /^port\.(\d+)\./u, count, "port");
  const ports: DockerPortProbeResult[] = [];
  const seen = new Set<string>();
  for (let index = 0; index < count; index += 1) {
    const protocol = requiredEnum(fields, `port.${index}.protocol`, ["tcp", "udp"] as const);
    const port = requiredSafeInteger(fields, `port.${index}.port`, 65_535, 1);
    const observation = requiredEnum(fields, `port.${index}.observation`, [
      "listener-observed",
      "not-observed",
      "unknown",
    ] as const);
    const ownership = requiredEnum(fields, `port.${index}.ownership`, [
      "requested-project",
      "other-container",
      "host-process",
      "unknown",
    ] as const);
    if (ownership === "host-process" && observation !== "listener-observed") {
      throw new FixedProbeParseError("Host-process port ownership requires a listener");
    }
    const identity = `${protocol}:${port}`;
    if (seen.has(identity)) {
      throw new FixedProbeParseError("Probe returned duplicate ports");
    }
    seen.add(identity);
    ports.push({ protocol, port, observation, ownership });
  }
  return ports;
}

function readContainers(fields: ReadonlyMap<string, string>): {
  readonly status: "ok" | "unavailable" | "not-requested";
  readonly filter?: string;
  readonly items: DockerContainerProbeResult[];
  readonly truncated: boolean;
} {
  const status = requiredEnum(fields, "containers.status", [
    "ok",
    "unavailable",
    "not-requested",
  ] as const);
  const count = requiredSafeInteger(fields, "containers.count", 100);
  const truncated = requiredBoolean(fields, "containers.truncated");
  const filter = optionalText(
    fields,
    "containers.filter",
    128,
    COMPOSE_PROJECT_FILTER_PATTERN,
  );
  assertDynamicIndexes(fields, /^container\.(\d+)\./u, count, "container");
  if (status !== "ok" && (count !== 0 || truncated)) {
    throw new FixedProbeParseError("Unavailable container results must be empty");
  }
  if ((status === "not-requested") !== (filter === undefined)) {
    throw new FixedProbeParseError("Container status and project filter disagree");
  }
  const items: DockerContainerProbeResult[] = [];
  for (let index = 0; index < count; index += 1) {
    const record = requiredText(fields, `container.${index}.record`, 1_024);
    const parts = record.split("|");
    if (parts.length !== 4) {
      throw new FixedProbeParseError("Probe returned a malformed container record");
    }
    const rawName = parts[0]!;
    const name = rawName.startsWith("/") ? rawName.slice(1) : rawName;
    if (!SAFE_CONTAINER_NAME_PATTERN.test(name)) {
      throw new FixedProbeParseError("Probe returned an invalid container name");
    }
    const state = enumValue(parts[1]!, [
      "created",
      "restarting",
      "running",
      "removing",
      "paused",
      "exited",
      "dead",
    ] as const);
    const health = enumValue(parts[2]!, ["healthy", "unhealthy", "starting", "none"] as const);
    const service = parts[3]!;
    if (service.length > 0 && !SAFE_SERVICE_NAME_PATTERN.test(service)) {
      throw new FixedProbeParseError("Probe returned an invalid Compose service name");
    }
    items.push({
      name,
      state,
      health,
      ...(service.length === 0 ? {} : { service }),
    });
  }
  return { status, ...optionalProperty("filter", filter), items, truncated };
}

function readPreflightDisk(fields: ReadonlyMap<string, string>): DockerPreflightDiskResult {
  const status = requiredEnum(fields, "disk.status", [
    "available",
    "unavailable",
    "not-requested",
  ] as const);
  const path = optionalText(fields, "disk.path", 4_096);
  const totalBytes = optionalSafeInteger(fields, "disk.totalBytes");
  const availableBytes = optionalSafeInteger(fields, "disk.availableBytes");
  const requiredBytes = optionalSafeInteger(fields, "disk.requiredBytes");
  if (status === "available") {
    if (path === undefined || totalBytes === undefined || availableBytes === undefined) {
      throw new FixedProbeParseError("Available disk results must include size information");
    }
    if (availableBytes > totalBytes) {
      throw new FixedProbeParseError("Probe returned impossible disk information");
    }
  } else if (path !== undefined || totalBytes !== undefined || availableBytes !== undefined) {
    throw new FixedProbeParseError("Unavailable disk results must not include size information");
  }
  return {
    status,
    ...optionalProperty("path", path),
    ...optionalProperty("totalBytes", totalBytes),
    ...optionalProperty("availableBytes", availableBytes),
    ...optionalProperty("requiredBytes", requiredBytes),
  };
}

function appendDockerWarnings(docker: ProbeDockerFacts, warnings: ProbeWarningCode[]): void {
  if (!docker.installed) warnings.push("docker-not-installed");
  else if (!docker.daemonReachable) warnings.push("docker-daemon-unreachable");
  if (docker.contextScope === "remote") warnings.push("docker-context-remote");
  if (!docker.compose.installed) warnings.push("compose-not-installed");
}

function deriveOverall(
  docker: ProbeDockerFacts,
  config: DockerPreflightProbeResult["compose"]["config"],
  intent: DockerPreflightProbeResult["intent"],
  ports: readonly DockerPortProbeResult[],
  containers: ReturnType<typeof readContainers>,
  disk: DockerPreflightDiskResult,
): DockerPreflightProbeResult["overall"] {
  const blocked =
    !docker.installed ||
    !docker.daemonReachable ||
    !docker.compose.installed ||
    config === "invalid" ||
    config === "unavailable" ||
    ports.some((entry) => isPortConflict(entry, intent)) ||
    containers.items.some((entry) => entry.health === "unhealthy") ||
    (disk.requiredBytes !== undefined &&
      (disk.availableBytes === undefined || disk.availableBytes < disk.requiredBytes));
  if (blocked) return "blocked";
  const degraded =
    docker.contextScope === "remote" ||
    ports.some((entry) => entry.observation === "unknown") ||
    containers.status === "unavailable" ||
    containers.truncated ||
    containers.items.some((entry) => entry.health === "starting") ||
    disk.status === "unavailable";
  return degraded ? "degraded" : "ready";
}

function isPortConflict(
  entry: DockerPortProbeResult,
  intent: DockerPreflightProbeResult["intent"],
): boolean {
  if (entry.ownership === "requested-project" && intent !== "create") {
    return false;
  }
  return (
    entry.ownership !== "unknown" ||
    entry.observation === "listener-observed"
  );
}

function freezeDockerFacts(docker: ProbeDockerFacts): ProbeDockerFacts {
  return Object.freeze({ ...docker, compose: Object.freeze({ ...docker.compose }) });
}

function assertDynamicIndexes(
  fields: ReadonlyMap<string, string>,
  pattern: RegExp,
  count: number,
  label: string,
): void {
  for (const key of fields.keys()) {
    const match = pattern.exec(key);
    if (match === null) continue;
    const index = Number(match[1]);
    if (!Number.isSafeInteger(index) || index < 0 || index >= count) {
      throw new FixedProbeParseError(`Probe returned an out-of-range ${label} index`);
    }
  }
}

function isNativeMachineId(platform: FixedProbePlatform, value: string): boolean {
  const valid = platform === "linux"
    ? /^[0-9A-Fa-f]{32}$/u.test(value)
    : /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/u.test(
        value,
      );
  return valid && !/^0+(?:-0+)*$/u.test(value);
}

function normalizeNativeId(value: string): string {
  return value.toLowerCase();
}

function requiredBoolean(fields: ReadonlyMap<string, string>, key: string): boolean {
  const value = requiredText(fields, key, 5);
  if (value === "true") return true;
  if (value === "false") return false;
  throw new FixedProbeParseError(`Probe returned an invalid boolean for ${key}`);
}

function requiredSafeInteger(
  fields: ReadonlyMap<string, string>,
  key: string,
  maximum = Number.MAX_SAFE_INTEGER,
  minimum = 0,
): number {
  const value = requiredText(fields, key, 32);
  if (!/^(?:0|[1-9][0-9]*)$/u.test(value)) {
    throw new FixedProbeParseError(`Probe returned an invalid integer for ${key}`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new FixedProbeParseError(`Probe returned an out-of-range integer for ${key}`);
  }
  return parsed;
}

function optionalSafeInteger(fields: ReadonlyMap<string, string>, key: string): number | undefined {
  return fields.has(key) ? requiredSafeInteger(fields, key) : undefined;
}

function requiredText(
  fields: ReadonlyMap<string, string>,
  key: string,
  maximumLength: number,
  pattern?: RegExp,
): string {
  const value = fields.get(key);
  if (value === undefined) {
    throw new FixedProbeParseError(`Probe output is missing ${key}`);
  }
  assertText(value, key, maximumLength, pattern);
  return value;
}

function optionalText(
  fields: ReadonlyMap<string, string>,
  key: string,
  maximumLength: number,
  pattern?: RegExp,
): string | undefined {
  const value = fields.get(key);
  if (value === undefined) return undefined;
  assertText(value, key, maximumLength, pattern);
  return value;
}

function assertText(value: string, key: string, maximumLength: number, pattern?: RegExp): void {
  if (value.length === 0 || value.length > maximumLength || (pattern !== undefined && !pattern.test(value))) {
    throw new FixedProbeParseError(`Probe returned an invalid value for ${key}`);
  }
}

function requiredEnum<const Values extends readonly string[]>(
  fields: ReadonlyMap<string, string>,
  key: string,
  values: Values,
): Values[number] {
  return enumValue(requiredText(fields, key, 128), values);
}

function optionalEnum<const Values extends readonly string[]>(
  fields: ReadonlyMap<string, string>,
  key: string,
  values: Values,
): Values[number] | undefined {
  const value = fields.get(key);
  return value === undefined ? undefined : enumValue(value, values);
}

function enumValue<const Values extends readonly string[]>(
  value: string,
  values: Values,
): Values[number] {
  if (!(values as readonly string[]).includes(value)) {
    throw new FixedProbeParseError("Probe returned an unknown enum value");
  }
  return value as Values[number];
}

function optionalProperty<Key extends string, Value>(
  key: Key,
  value: Value | undefined,
): {} | Readonly<Record<Key, Value>> {
  return value === undefined ? {} : ({ [key]: value } as Readonly<Record<Key, Value>>);
}
