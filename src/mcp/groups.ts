import { randomUUID } from "node:crypto";
import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { GATEWAY_ERROR_CODES } from "../shared/errors.js";
import { DEFAULT_TARGET_GROUP, execRunParamsSchema, legacyExecRunParamsSchema, structuredExecRunParamsSchema, targetGroupSchema,
  type ExecRunParams, type TargetSummary, type TaskState } from "../shared/protocol.js";
import { RpcRemoteError, type GatewayRpcClient } from "../shared/rpc-client.js";

type Client = Pick<GatewayRpcClient, "request" | "run" | "close">;
type ClientFactory = () => Promise<Client>;
const groupNameSchema = targetGroupSchema;
const parallelSchema = z.number().int().min(1).max(8).default(4);
const commandSchema = z.strictObject({
  command: legacyExecRunParamsSchema.shape.command.optional(),
  shell: structuredExecRunParamsSchema.shape.shell.optional(),
  script: structuredExecRunParamsSchema.shape.script.optional(),
  cwd: structuredExecRunParamsSchema.shape.cwd,
  env: structuredExecRunParamsSchema.shape.env,
  encoding: z.literal("utf-8").optional(),
  timeoutMs: legacyExecRunParamsSchema.shape.timeoutMs,
}).superRefine((value, context) => {
  if (!execRunParamsSchema.safeParse({ ...value, target: "validation" }).success) {
    context.addIssue({ code: "custom", message: "Use either command, or shell/script with optional cwd/env/encoding; the normal ssh_exec constraints apply." });
  }
});
export const groupStartSchema = z.strictObject({
  group: groupNameSchema,
  common: commandSchema.optional(),
  platforms: z.strictObject({ linux: commandSchema.optional(), windows: commandSchema.optional(), macos: commandSchema.optional() }).optional(),
  concurrency: z.number().int().min(1).max(4).default(2),
}).superRefine((value, context) => {
  if ((value.common === undefined) === (value.platforms === undefined)) {
    context.addIssue({ code: "custom", message: "Supply exactly one of common (explicitly shared across platforms) or platforms." });
  }
});
const groupCpuSchema = z.strictObject({ group: groupNameSchema, concurrency: parallelSchema });
const groupHandleSchema = z.strictObject({ groupRunId: z.string().uuid() });
type GroupStart = z.infer<typeof groupStartSchema>;
type GroupMember = { targetId: string; alias: string; platform: TargetSummary["platform"]; state: TaskState | "queued" | "skipped" | "unknown";
  runId?: string; errorCode?: string; cancelAccepted?: boolean };
type Batch = { groupRunId: string; group: string; createdAt: string; expiresAt: string; members: GroupMember[];
  concurrency: number; cancelling: boolean; commands: (ExecRunParams | undefined)[]; completedAt?: string; work?: Promise<void>; timer?: NodeJS.Timeout };
const TERMINAL = new Set<string>(["succeeded", "failed", "timed_out", "cancelled", "skipped"]);
const RETENTION_MS = 24 * 60 * 60 * 1000;
const MAX_BATCHES = 128;

async function parallelMap<T, R>(items: readonly T[], concurrency: number, operation: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await operation(items[index]!);
    }
  }));
  return results;
}
function safeError(error: unknown): string {
  if (error instanceof RpcRemoteError && error.data !== null && typeof error.data === "object") {
    const code = (error.data as Record<string, unknown>)["gatewayCode"];
    if (typeof code === "string" && (Object.values(GATEWAY_ERROR_CODES) as string[]).includes(code)) return code;
  }
  return "GATEWAY_REQUEST_FAILED";
}
function memberOf(target: TargetSummary): GroupMember {
  return { targetId: target.targetId, alias: target.alias, platform: target.platform,
    state: target.enabled ? "running" : "skipped", ...(!target.enabled ? { errorCode: "TARGET_DISABLED" } : {}) };
}
function report(batch: Batch) {
  const counts: Record<string, number> = {};
  for (const member of batch.members) counts[member.state] = (counts[member.state] ?? 0) + 1;
  return { groupRunId: batch.groupRunId, group: batch.group, createdAt: batch.createdAt, expiresAt: batch.completedAt ? batch.expiresAt : null,
    concurrency: batch.concurrency, members: batch.members.map(member => ({ ...member })), counts,
    complete: batch.members.every(member => TERMINAL.has(member.state)),
    handleScope: "mcp-process" as const };
}

// Legacy targets use normal structured execution authorization. Preset targets
// use the daemon's vetted system.cpu operation and its selected capability check.
export const CPU_SCRIPTS = {
  linux: `read -r _ u n s i w q sq st _ < /proc/stat
t1=$((u+n+s+i+w+q+sq+st)); i1=$((i+w))
sleep 1
read -r _ u n s i w q sq st _ < /proc/stat
t2=$((u+n+s+i+w+q+sq+st)); i2=$((i+w))
cores=$(getconf _NPROCESSORS_ONLN)
awk -v t="$((t2-t1))" -v idle="$((i2-i1))" -v c="$cores" 'BEGIN { if(t<=0) exit 1; printf "AGENT_SSH_CPU %.4f %d\\n", 100*(t-idle)/t,c }'`,
  windows: `$ErrorActionPreference='Stop'
Start-Sleep -Seconds 1
$cpu=Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'"
$cores=(Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
if ($null -eq $cpu -or $null -eq $cpu.PercentProcessorTime -or $null -eq $cores -or $cores -lt 1) { throw 'CPU counters unavailable' }
[Console]::WriteLine(('AGENT_SSH_CPU {0} {1}' -f ([double]$cpu.PercentProcessorTime).ToString([Globalization.CultureInfo]::InvariantCulture),$cores))`,
  macos: `idle=$(LC_ALL=C top -l 2 -s 1 -n 0 | awk '/CPU usage:/ {for(i=1;i<=NF;i++) if($i=="idle") {v=$(i-1);gsub(/%/,"",v)}} END {print v}')
cores=$(sysctl -n hw.logicalcpu)
awk -v idle="$idle" -v c="$cores" 'BEGIN {if(idle=="" || c<1) exit 1; printf "AGENT_SSH_CPU %.4f %d\\n",100-idle,c}'`,
} as const;
export function parseCpuOutput(text: string): { cpuPercent: number; logicalCpus: number } | undefined {
  const match = /^AGENT_SSH_CPU ([0-9]+(?:\.[0-9]+)?) ([0-9]+)\r?$/mu.exec(text);
  if (!match) return undefined;
  const cpuPercent = Number(match[1]);
  const logicalCpus = Number(match[2]);
  if (!Number.isFinite(cpuPercent) || cpuPercent < 0 || cpuPercent > 100 || !Number.isSafeInteger(logicalCpus) || logicalCpus < 1) return undefined;
  return { cpuPercent, logicalCpus };
}

export class GroupController {
  readonly #factory: ClientFactory;
  readonly #batches = new Map<string, Batch>();
  readonly #now: () => number;
  constructor(factory: ClientFactory, now: () => number = Date.now) { this.#factory = factory; this.#now = now; }
  #snapshot(batch: Batch) {
    if (!batch.completedAt && batch.members.every(member => TERMINAL.has(member.state))) {
      batch.completedAt = new Date(this.#now()).toISOString();
      batch.expiresAt = new Date(this.#now() + RETENTION_MS).toISOString();
    }
    return report(batch);
  }
  async #withClient<T>(operation: (client: Client) => Promise<T>): Promise<T> {
    const client = await this.#factory();
    try { return await operation(client); } finally { client.close(); }
  }
  async #targets(group?: string): Promise<TargetSummary[]> {
    const result = await this.#withClient(client => client.request("target.list", {}));
    if (group === undefined) return result.targets;
    const members = result.targets.filter(target => (target.group ?? DEFAULT_TARGET_GROUP) === group);
    const exists = group === DEFAULT_TARGET_GROUP || result.groups?.includes(group) || members.length > 0;
    if (!exists) throw new Error("GROUP_NOT_FOUND: no such named group. Use ssh_list_groups.");
    return members;
  }
  async list() {
    const { targets, groups } = await this.#withClient(client => client.request("target.list", {}));
    const names = [...new Set([DEFAULT_TARGET_GROUP, ...(groups ?? []), ...targets.flatMap(target => target.group ? [target.group] : [])])];
    return { groups: names.map(group => {
      const members = targets.filter(target => (target.group ?? DEFAULT_TARGET_GROUP) === group);
      return { group, isDefault: group === DEFAULT_TARGET_GROUP, total: members.length, enabled: members.filter(target => target.enabled).length,
        targets: members.map(target => ({ targetId: target.targetId, alias: target.alias, platform: target.platform, enabled: target.enabled })) };
    }), ungroupedCount: targets.filter(target => !target.group).length };
  }
  async cpu(input: z.input<typeof groupCpuSchema>, signal?: AbortSignal) {
    const args = groupCpuSchema.parse(input);
    const targets = await this.#targets(args.group);
    const members = await parallelMap(targets, args.concurrency, async target => {
      const base = memberOf(target);
      if (!target.enabled) return { ...base, sample: null };
      if (signal?.aborted) return { ...base, state: "skipped", errorCode: "REQUEST_CANCELLED", sample: null };
      try {
        const result = await this.#withClient(client => target.policyMode === "presets"
          ? client.request("operation.run", { target: target.targetId, operation: "system.cpu", parameters: {},
            timeoutMs: Math.min(15_000, target.maxTimeoutMs) })
          : client.run({ target: target.targetId,
          shell: target.platform === "windows" ? "powershell" : "bash", script: CPU_SCRIPTS[target.platform],
          encoding: "utf-8", timeoutMs: Math.min(15_000, target.maxTimeoutMs) }, signal));
        const sample = result.exitCode === 0 && result.termination === "exit" ? parseCpuOutput(result.stdout.text) : undefined;
        return sample ? { ...base, state: "succeeded", sample } : { ...base, state: "failed", errorCode: "CPU_SAMPLE_FAILED", sample: null };
      } catch (error) { return { ...base, state: "failed", errorCode: safeError(error), sample: null }; }
    });
    const samples = members.flatMap(member => member.sample ? [member.sample] : []);
    const cores = samples.reduce((sum, sample) => sum + sample.logicalCpus, 0);
    return { group: args.group, sampledAt: new Date(this.#now()).toISOString(), total: targets.length,
      sampled: samples.length, failed: members.filter(member => member.state === "failed").length,
      skipped: members.filter(member => member.state === "skipped").length,
      averageCpuPercent: samples.length ? samples.reduce((sum, sample) => sum + sample.cpuPercent, 0) / samples.length : null,
      coreWeightedCpuPercent: cores ? samples.reduce((sum, sample) => sum + sample.cpuPercent * sample.logicalCpus, 0) / cores : null,
      aggregation: "Successful samples only; sampled at slightly different times. Core weighting does not normalize CPU model or speed.", members };
  }
  async start(input: z.input<typeof groupStartSchema>, signal?: AbortSignal) {
    const args: GroupStart = groupStartSchema.parse(input);
    const targets = await this.#targets(args.group);
    // Validate the entire plan before any remote start. Missing OS variants must
    // not result in half a mixed-platform deployment being launched.
    const commands = targets.map(target => {
      if (!target.enabled) return undefined;
      const command = args.common ?? args.platforms?.[target.platform];
      if (command === undefined) throw new Error(`PLATFORM_COMMAND_REQUIRED: supply a ${target.platform} command or an explicit common command.`);
      return execRunParamsSchema.parse({ ...command, target: target.targetId });
    });
    const now = this.#now();
    for (const [id, batch] of this.#batches) if (batch.completedAt && Date.parse(batch.expiresAt) <= now) this.#batches.delete(id);
    if (this.#batches.size >= MAX_BATCHES) throw new Error("GROUP_HANDLE_LIMIT: at most 128 group handles are retained; completed handles expire after 24 hours and active handles are never evicted.");
    signal?.throwIfAborted();
    const batch: Batch = { groupRunId: randomUUID(), group: args.group, createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + RETENTION_MS).toISOString(), members: targets.map(target => ({ ...memberOf(target), state: target.enabled ? "queued" : "skipped" })),
      concurrency: args.concurrency, cancelling: false, commands };
    this.#batches.set(batch.groupRunId, batch);
    // Scheduling belongs to this MCP process; each dispatched child belongs to
    // the daemon. Return before remote submissions, which may themselves be slow.
    this.#schedule(batch, 0);
    return this.#snapshot(batch);
  }
  #schedule(batch: Batch, delay = 1000): void {
    if (batch.timer || batch.members.every(member => TERMINAL.has(member.state))) return;
    batch.timer = setTimeout(() => {
      delete batch.timer;
      void this.#cycle(batch).then(() => { this.#snapshot(batch); this.#schedule(batch); }).catch(() => {
        // Never leave an unhandled rejection in a background coordinator.
        for (const member of batch.members) if (!TERMINAL.has(member.state)) {
          member.state = member.runId ? "unknown" : "failed";
          member.errorCode = "GROUP_COORDINATOR_FAILED";
        }
      });
    }, delay);
    batch.timer.unref();
  }
  async #refresh(batch: Batch): Promise<void> {
    await parallelMap(batch.members, 4, async member => {
      if (!member.runId || TERMINAL.has(member.state)) return;
      try {
        const status = await this.#withClient(client => client.request("task.status", { runId: member.runId! }));
        member.state = status.state;
        delete member.errorCode;
        if (status.error) member.errorCode = (Object.values(GATEWAY_ERROR_CODES) as string[]).includes(status.error.gatewayCode) ? status.error.gatewayCode : "TASK_FAILED";
      } catch (error) { member.state = "unknown"; member.errorCode = safeError(error); }
    });
  }
  async #cycle(batch: Batch): Promise<void> {
    if (batch.work) return batch.work;
    const work = (async () => {
      await this.#refresh(batch);
      const active = batch.members.filter(member => !TERMINAL.has(member.state) && (member.runId || member.state === "unknown")).length;
      const next = batch.members.map((member, index) => ({ member, index }))
        .filter(({ member }) => member.state === "queued").slice(0, Math.max(0, batch.concurrency - active));
      if (batch.cancelling) return;
      await parallelMap(next, batch.concurrency, async ({ member, index }) => {
        if (batch.cancelling) { member.state = "cancelled"; return; }
        try {
          const result = await this.#withClient(client => client.request("task.start", batch.commands[index]!));
          member.runId = result.runId;
          member.state = result.state;
        } catch (error) {
          // Transport failure can lose a response after the daemon accepted the
          // command. Keep its slot reserved and never retry an ambiguous start.
          member.state = error instanceof RpcRemoteError ? "failed" : "unknown";
          member.errorCode = error instanceof RpcRemoteError ? safeError(error) : "TASK_START_OUTCOME_UNKNOWN";
        }
        // Scripts are no longer needed after dispatch; do not retain payloads.
        batch.commands[index] = undefined;
      });
    })();
    batch.work = work;
    try { await work; } finally { delete batch.work; }
  }
  #batch(groupRunId: string): Batch {
    groupHandleSchema.parse({ groupRunId });
    const batch = this.#batches.get(groupRunId);
    if (batch && (!batch.completedAt || Date.parse(batch.expiresAt) > this.#now())) return batch;
    this.#batches.delete(groupRunId);
    throw new Error("GROUP_RUN_NOT_FOUND: handle expired or MCP restarted. Use the returned per-machine runIds with ssh_status/ssh_cancel; daemon tasks may still be running.");
  }
  async status(groupRunId: string) {
    const batch = this.#batch(groupRunId);
    await this.#cycle(batch);
    this.#schedule(batch);
    return this.#snapshot(batch);
  }
  async cancel(groupRunId: string) {
    const batch = this.#batch(groupRunId);
    batch.cancelling = true;
    if (batch.timer) { clearTimeout(batch.timer); delete batch.timer; }
    for (const member of batch.members) if (member.state === "queued") member.state = "cancelled";
    // An in-flight start can still return a child runId. Wait and cancel it too.
    if (batch.work) await batch.work;
    batch.commands.fill(undefined);
    await parallelMap(batch.members, 4, async member => {
      if (!member.runId || TERMINAL.has(member.state)) return;
      try {
        const result = await this.#withClient(client => client.request("task.cancel", { runId: member.runId! }));
        member.cancelAccepted = result.accepted;
        member.state = result.state;
        delete member.errorCode;
      } catch (error) { member.state = "unknown"; member.errorCode = safeError(error); }
    });
    this.#schedule(batch);
    return this.#snapshot(batch);
  }
}

export function registerGroupTools(server: McpServer, factory: ClientFactory): void {
  const controller = new GroupController(factory);
  const result = (value: object) => ({ content: [{ type: "text" as const, text: JSON.stringify(value) }], structuredContent: value as Record<string, unknown> });
  server.registerTool("ssh_list_groups", { description: "List exact machine group names and immutable target IDs, including disabled members. Configure membership in the SSH management center.",
    annotations: { readOnlyHint: true, idempotentHint: true } }, async () => result(await controller.list()));
  server.registerTool("ssh_group_cpu", { description: "Read CPU utilization on enabled members of one exact group using Windows/Linux/macOS read-only probes. Returns each machine, failures/skips, arithmetic and logical-core-weighted averages over successful samples. Preset targets require basic-inspection; other targets require full-access structured execution. concurrency bounds simultaneous probes.",
    inputSchema: groupCpuSchema, annotations: { readOnlyHint: true, openWorldHint: true } }, async (args, context) => result(await controller.cpu(args, context.mcpReq.signal)));
  server.registerTool("ssh_group_start", { description: "Queue per-machine daemon tasks on an exact group snapshot and return groupRunId immediately. Supply common to explicitly use the same command on all platforms, or platforms.linux/windows/macos variants; no implicit OS fallback. Uses normal ssh_exec validation, permissions, timeout and gateway execution limits; disabled targets are skipped and failures isolated. concurrency bounds active child jobs in this group (default 2, max 4); remaining members stay queued until slots free. External gateway capacity conflicts return per-machine EXECUTION_LIMIT_REACHED failures. Poll ssh_group_status for child runIds and use ssh_tail for logs. Group queue/handles live only in this MCP process (max 128, retained 24 hours after completion, active handles never evicted); MCP restart loses undispatched work, but already dispatched daemon tasks survive and are accessible by their runIds. Installations require an appropriate user-authorized script, not an automatic installer.",
    inputSchema: groupStartSchema, annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true } },
    async (args, context) => result(await controller.start(args, context.mcpReq.signal)));
  server.registerTool("ssh_group_status", { description: "Poll the saved group task snapshot, including individual runIds and terminal counts. Unreachable status is unknown, never success. After MCP restart or 24-hour expiry use ssh_status per runId.",
    inputSchema: groupHandleSchema, annotations: { readOnlyHint: true, idempotentHint: true } }, async args => result(await controller.status(args.groupRunId)));
  server.registerTool("ssh_group_cancel", { description: "Request cancellation of nonterminal tasks in a saved group snapshot. cancelAccepted means the request was accepted; poll ssh_group_status for final cancelled states. Does not undo completed commands.",
    inputSchema: groupHandleSchema, annotations: { readOnlyHint: false, idempotentHint: true } }, async args => result(await controller.cancel(args.groupRunId)));
}
