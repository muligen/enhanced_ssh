import { z } from "zod";

import { GATEWAY_ERROR_CODES, GatewayError } from "./errors.js";

export const permissionPresetIdSchema = z.enum([
  "basic-inspection", "log-inspection", "docker-readonly", "docker-protection",
]);
export type PermissionPresetId = z.infer<typeof permissionPresetIdSchema>;
const resourceNameSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$/);
const logPathSchema = z.string().min(1).max(1024)
  .refine(value => !/[\x00-\x1f\x7f]/u.test(value), "Log paths must not contain control characters")
  .refine(value => /^(?:[A-Za-z]:[\\/]|\/(?!\/))/u.test(value), "Log paths must be absolute local file paths");
export const permissionPresetSelectionSchema = z.strictObject({
  presets: z.array(permissionPresetIdSchema).max(4).default([])
    .refine(value => new Set(value).size === value.length, "Preset selections must be unique"),
  logPaths: z.array(logPathSchema).max(32).default([])
    .refine(value => new Set(value).size === value.length, "Log paths must be unique"),
  logServices: z.array(resourceNameSchema).max(32).default([])
    .refine(value => new Set(value).size === value.length, "Log services must be unique"),
});
export type PermissionPresetSelection = z.infer<typeof permissionPresetSelectionSchema>;

export const operationIdSchema = z.enum([
  "system.identity", "system.cpu", "system.memory", "system.disk", "system.processes", "system.ports",
  "logs.file", "logs.service", "docker.containers", "docker.stats", "docker.health", "docker.logs",
]);
export const operationRequestSchema = z.strictObject({
  operation: operationIdSchema,
  parameters: z.record(z.string(), z.unknown()).default({}),
});
export type OperationRequest = z.infer<typeof operationRequestSchema>;
type Platform = "windows" | "linux" | "macos";
type OperationId = z.infer<typeof operationIdSchema>;

export const PERMISSION_PRESETS = [
  { id: "basic-inspection", name: "基础巡检", description: "查看主机、CPU、内存、磁盘、进程和监听端口；不修改系统。", operations: ["system.identity", "system.cpu", "system.memory", "system.disk", "system.processes", "system.ports"] },
  { id: "log-inspection", name: "日志排查", description: "限量读取明确授权的日志文件和服务日志；日志可能含敏感信息。", operations: ["logs.file", "logs.service"] },
  { id: "docker-readonly", name: "Docker 只读巡检", description: "查看容器、资源和健康状态、最近日志；不允许容器 exec 或完整 inspect。", operations: ["docker.containers", "docker.stats", "docker.health", "docker.logs"] },
  { id: "docker-protection", name: "Docker 保护", description: "仅允许已选巡检操作；禁止任意命令、脚本和文件传输，阻断 Docker 修改入口。本组不额外授予操作。", operations: [] },
] as const;

const emptyParametersSchema = z.strictObject({});
const linesSchema = z.number().int().min(1).max(200).default(100);
const limitSchema = z.number().int().min(1).max(100).default(30);
const containerSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/);
const parameterSchemas = {
  "system.identity": emptyParametersSchema,
  "system.cpu": emptyParametersSchema,
  "system.memory": emptyParametersSchema,
  "system.disk": emptyParametersSchema,
  "system.processes": z.strictObject({ limit: limitSchema }),
  "system.ports": z.strictObject({ limit: limitSchema }),
  "logs.file": z.strictObject({ path: logPathSchema, lines: linesSchema }),
  "logs.service": z.strictObject({ service: resourceNameSchema, lines: linesSchema }),
  "docker.containers": emptyParametersSchema,
  "docker.stats": emptyParametersSchema,
  "docker.health": z.strictObject({ container: containerSchema }),
  "docker.logs": z.strictObject({ container: containerSchema, lines: linesSchema }),
} as const;

export interface PresetOperationDescriptor {
  readonly id: OperationId;
  readonly name: string;
  readonly description: string;
  readonly parameters: Record<string, unknown>;
}
const operationLabels: Record<OperationId, readonly [string, string]> = {
  "system.identity": ["主机信息", "主机名、系统版本和当前账号。"],
  "system.cpu": ["CPU 使用率", "采样约一秒，返回总使用率和逻辑核心数。"],
  "system.memory": ["内存信息", "查看物理内存和当前内存使用情况。"],
  "system.disk": ["磁盘容量", "查看本地磁盘容量和可用空间。"],
  "system.processes": ["进程概况", "限量返回进程 ID、名称和资源；不返回完整命令行。"],
  "system.ports": ["监听端口", "限量返回本机监听端口。"],
  "logs.file": ["授权文件日志", "只可选择配置中授权的绝对文件路径；最多 200 行、约 64 KiB。"],
  "logs.service": ["授权服务日志", "Linux：systemd 单元；Windows：事件日志名（如 System）；macOS：进程名。最近一小时，最多 200 条。"],
  "docker.containers": ["容器列表", "最多 100 行 JSON 数组，列顺序：ID、名称、镜像、状态、端口。"],
  "docker.stats": ["容器资源", "单次采样，最多 100 行 JSON 数组，列顺序：ID、名称、CPU、内存、网络、磁盘 I/O。"],
  "docker.health": ["容器健康", "JSON 数组，列顺序：ID、名称、状态、健康状态（无检查时 null）、重启次数；不返回环境变量或健康检查日志。"],
  "docker.logs": ["容器日志", "指定容器最近一小时的日志，最多 200 行；日志可能含敏感信息。"],
};

export function listPresetOperations(selection: PermissionPresetSelection, platform: Platform): PresetOperationDescriptor[] {
  const allowed = new Set<string>(PERMISSION_PRESETS.filter(preset => selection.presets.includes(preset.id)).flatMap(preset => [...preset.operations]));
  return operationIdSchema.options.filter(id => allowed.has(id))
    .filter(id => id !== "logs.file" || selection.logPaths.some(path => validPathForPlatform(path, platform)))
    .filter(id => id !== "logs.service" || selection.logServices.length > 0)
    .map(id => {
      const parameters = z.toJSONSchema(parameterSchemas[id]) as Record<string, unknown>;
      const properties = parameters.properties as Record<string, Record<string, unknown>>;
      if (id === "logs.file") properties.path = { type: "string", enum: selection.logPaths.filter(path => validPathForPlatform(path, platform)) };
      if (id === "logs.service") properties.service = { type: "string", enum: selection.logServices };
      return { id, name: operationLabels[id][0], description: operationLabels[id][1], parameters };
    });
}

function validPathForPlatform(path: string, platform: Platform): boolean {
  return platform === "windows" ? /^[A-Za-z]:[\\/]/u.test(path) : path.startsWith("/");
}
function sh(value: string): string { return `'${value.replaceAll("'", "'\\''")}'`; }
function ps(value: string): string { return `'${value.replaceAll("'", "''")}'`; }
function denied(): never { throw new GatewayError(GATEWAY_ERROR_CODES.commandDenied, "Operation or resource is not allowed by this target's permission presets"); }
function invalid(): never { throw new GatewayError(GATEWAY_ERROR_CODES.invalidParams, "Invalid preset operation parameters; use operation.list to inspect allowed parameters and resources"); }

const CPU_SCRIPTS = {
  linux: `read -r _ u n s i w q sq st _ < /proc/stat
t1=$((u+n+s+i+w+q+sq+st)); i1=$((i+w))
sleep 1
read -r _ u n s i w q sq st _ < /proc/stat
t2=$((u+n+s+i+w+q+sq+st)); i2=$((i+w))
cores=$(getconf _NPROCESSORS_ONLN)
awk -v t="$((t2-t1))" -v idle="$((i2-i1))" -v c="$cores" 'BEGIN { if(t<=0) exit 1; printf "AGENT_SSH_CPU %.4f %d\\n", 100*(t-idle)/t,c }'`,
  windows: `Start-Sleep -Seconds 1
$cpu=Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'"
$cores=(Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
if ($null -eq $cpu -or $null -eq $cpu.PercentProcessorTime -or $null -eq $cores -or $cores -lt 1) { throw 'CPU counters unavailable' }
[Console]::WriteLine(('AGENT_SSH_CPU {0} {1}' -f ([double]$cpu.PercentProcessorTime).ToString([Globalization.CultureInfo]::InvariantCulture),$cores))`,
  macos: `idle=$(LC_ALL=C top -l 2 -s 1 -n 0 | awk '/CPU usage:/ {for(i=1;i<=NF;i++) if($i=="idle") {v=$(i-1);gsub(/%/,"",v)}} END {print v}')
cores=$(sysctl -n hw.logicalcpu)
awk -v idle="$idle" -v c="$cores" 'BEGIN {if(idle=="" || c<1) exit 1; printf "AGENT_SSH_CPU %.4f %d\\n",100-idle,c}'`,
} as const;

/** Only server-generated templates reach the execution engine. No caller shell,
 * environment, command fragment, formatting expression, or redirection is accepted. */
export function buildPresetOperation(selection: PermissionPresetSelection, platform: Platform, input: unknown): {
  script: string; shell: "bash" | "powershell"; encoding: "utf-8";
} {
  const parsed = operationRequestSchema.safeParse(input);
  if (!parsed.success) return invalid();
  const request = parsed.data;
  if (!listPresetOperations(selection, platform).some(operation => operation.id === request.operation)) return denied();
  const checked = parameterSchemas[request.operation].safeParse(request.parameters);
  if (!checked.success) return invalid();
  const parameters = checked.data as { limit?: number; lines?: number; path?: string; service?: string; container?: string };
  if (request.operation === "logs.file" && (!selection.logPaths.includes(parameters.path!) || !validPathForPlatform(parameters.path!, platform))) return denied();
  if (request.operation === "logs.service" && !selection.logServices.includes(parameters.service!)) return denied();
  const windows = platform === "windows";
  const quote = windows ? ps : sh;
  const limit = parameters.limit ?? 30;
  const lines = parameters.lines ?? 100;
  // Bound long single lines as well as line counts. The execution engine also
  // retains only bounded output; these limits prevent unnecessary log traffic.
  const bounded = windows
    ? " | ForEach-Object { $s=[string]$_; $s.Substring(0,[Math]::Min(1024,$s.Length)) } | Select-Object -First 200"
    : " | head -c 65536";
  let script: string;
  switch (request.operation) {
    case "system.identity": script = windows
      ? "$o=Get-CimInstance Win32_OperatingSystem; [pscustomobject]@{hostname=[Environment]::MachineName; user=[Environment]::UserName; caption=$o.Caption; version=$o.Version; architecture=$o.OSArchitecture} | ConvertTo-Json -Compress"
      : platform === "macos" ? "hostname; id -un; sw_vers; uname -m" : "hostname; id -un; uname -srmo"; break;
    case "system.cpu": script = CPU_SCRIPTS[platform]; break;
    case "system.memory": script = windows
      ? "Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory,TotalVirtualMemorySize,FreeVirtualMemory | ConvertTo-Json -Compress"
      : platform === "macos" ? "sysctl -n hw.memsize; vm_stat | head -n 30" : "head -n 30 /proc/meminfo"; break;
    case "system.disk": script = windows
      ? "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object -First 100 DeviceID,FileSystem,Size,FreeSpace | ConvertTo-Json -Compress"
      : "df -k -l -P | head -n 101"; break;
    case "system.processes": script = windows
      ? `Get-Process | Sort-Object CPU -Descending | Select-Object -First ${limit} Id,ProcessName,CPU,WorkingSet64 | ConvertTo-Json -Compress`
      : platform === "macos" ? `ps -axo pid,pcpu,pmem,comm -r | head -n ${limit + 1}` : `ps -eo pid,pcpu,pmem,comm --sort=-pcpu | head -n ${limit + 1}`; break;
    case "system.ports": script = windows
      ? `Get-NetTCPConnection -State Listen | Select-Object -First ${limit} LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress`
      : platform === "macos" ? `lsof -nP -iTCP -sTCP:LISTEN | head -n ${limit + 1}` : `ss -lntu | head -n ${limit + 1}`; break;
    case "logs.file": script = windows
      ? `$f=Get-Item -LiteralPath ${quote(parameters.path!)}; if ($f -isnot [IO.FileInfo]) { throw 'Authorized log resource is not a regular file' }; Get-Content -LiteralPath ${quote(parameters.path!)} -Tail ${lines} -Encoding UTF8${bounded}`
      : `if [ ! -f ${quote(parameters.path!)} ]; then printf '%s\\n' 'Authorized log resource is not a regular file' >&2; exit 1; fi\ntail -n ${lines} ${quote(parameters.path!)}${bounded}`; break;
    case "logs.service": script = windows
      ? `Get-WinEvent -FilterHashtable @{LogName=${quote(parameters.service!)};StartTime=(Get-Date).AddHours(-1)} -MaxEvents ${lines} | Select-Object TimeCreated,Id,LevelDisplayName,@{Name='Message';Expression={$s=[string]$_.Message;$s.Substring(0,[Math]::Min(1024,$s.Length))}} | ConvertTo-Json -Compress`
      : platform === "macos" ? `/usr/bin/log show --last 1h --style compact --predicate ${quote(`process == "${parameters.service!}"`)} | tail -n ${lines}${bounded}`
      : `journalctl --no-pager -u ${quote(parameters.service!)} --since '1 hour ago' -n ${lines} -o short-iso${bounded}`; break;
    case "docker.containers": script = `docker ps -a --no-trunc --format ${quote('[{{json .ID}},{{json .Names}},{{json .Image}},{{json .Status}},{{json .Ports}}]')}` + (windows ? " | Select-Object -First 100" : " | head -n 100"); break;
    case "docker.stats": script = `docker stats --no-stream --format ${quote('[{{json .ID}},{{json .Name}},{{json .CPUPerc}},{{json .MemUsage}},{{json .NetIO}},{{json .BlockIO}}]')}` + (windows ? " | Select-Object -First 100" : " | head -n 100"); break;
    case "docker.health": script = `docker inspect --type container --format ${quote('[{{json .Id}},{{json .Name}},{{json .State.Status}},{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}},{{.RestartCount}}]')} ${quote(parameters.container!)}`; break;
    case "docker.logs": script = `docker logs --timestamps --since 1h --tail ${lines} ${quote(parameters.container!)} 2>&1${bounded}`; break;
  }
  // Native stderr contains ordinary Docker log data on PowerShell 5.1. The
  // process exit code, rather than NativeCommandError, determines success.
  const psNative = request.operation.startsWith("docker.");
  // head intentionally closes a large pipeline early (SIGPIPE = 141). Preserve
  // genuine command failures, including a missing Docker daemon.
  return { script: windows ? `$ErrorActionPreference='${psNative ? "Continue" : "Stop"}'\n[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n` + script + (psNative ? "\nif ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }" : "")
    : "set -o pipefail\n" + script + "\n_agent_preset_status=$?\nif [ \"$_agent_preset_status\" -eq 141 ]; then exit 0; else exit \"$_agent_preset_status\"; fi",
    shell: windows ? "powershell" : "bash", encoding: "utf-8" };
}
