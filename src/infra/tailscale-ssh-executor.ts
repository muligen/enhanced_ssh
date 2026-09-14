import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import path from "node:path";
import { z } from "zod";

import { hardenPrivatePath } from "../daemon/runtime-state.js";
import { tailscaleSshConnectionSchema } from "../config/load-config.js";
import { executeManagedCommand } from "./managed-command.js";
import { buildOpenSshArguments, type SshExecutorOptions } from "./openssh-executor.js";
import { SshExecutionError, type SshFailureReason, type SshOutcome, type SshRunInput, type SshRunner } from "./ssh-runner.js";

const MAX_STATUS_BYTES = 4 * 1024 * 1024;
const peerSchema = z.object({
  DNSName: z.string(),
  TailscaleIPs: z.array(z.string()).nullish().transform((value) => value ?? []),
  SSH_HostKeys: z.array(z.string()).nullish().transform((value) => value ?? []),
});
const statusSchema = z.object({
  BackendState: z.string(),
  Peer: z.record(z.string(), peerSchema).nullable().optional(),
});

export interface TailscalePeer {
  readonly address: string;
  readonly hostKeys: readonly string[];
}

/** Accept only an unambiguous peer advertised by the authenticated local daemon. */
export function resolveTailscalePeer(json: string, host: string): TailscalePeer {
  const status = statusSchema.parse(JSON.parse(json) as unknown);
  if (status.BackendState !== "Running") throw new TailscaleFailure("tailscale-unavailable");
  const name = host.toLowerCase().replace(/\.$/u, "");
  const peers = Object.values(status.Peer ?? {}).filter((peer) => {
    const dns = peer.DNSName.toLowerCase().replace(/\.$/u, "");
    return peer.TailscaleIPs.some((address) => canonicalAddress(address) === canonicalAddress(host)) || dns === name || (!name.includes(".") && dns.split(".")[0] === name);
  });
  if (peers.length !== 1) throw new TailscaleFailure("tailscale-peer-unavailable");
  const peer = peers[0]!;
  const address = peer.TailscaleIPs.find(isTailscaleAddress);
  if (address === undefined) throw new TailscaleFailure("tailscale-peer-unavailable");
  const hostKeys = peer.SSH_HostKeys.map((key) => key.trim()).filter((key) =>
    /^(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/]+={0,2}$/u.test(key),
  );
  if (hostKeys.length === 0 || hostKeys.length !== peer.SSH_HostKeys.length) {
    throw new TailscaleFailure("tailscale-host-key-unavailable");
  }
  return Object.freeze({ address, hostKeys: Object.freeze(hostKeys) });
}

function canonicalAddress(value: string): string {
  return isIP(value) === 6 ? new URL(`http://[${value}]/`).hostname : value;
}

function isTailscaleAddress(value: string): boolean {
  if (isIP(value) === 4) {
    const parts = value.split(".").map(Number);
    return parts[0] === 100 && parts[1]! >= 64 && parts[1]! <= 127;
  }
  return isIP(value) === 6 && value.toLowerCase().startsWith("fd7a:115c:a1e0:");
}

class TailscaleFailure extends Error {
  public constructor(readonly reason: SshFailureReason) { super(reason); }
}

export interface TailscaleSshExecutorOptions extends SshExecutorOptions {
  readonly tailscaleExecutable: string;
  readonly runtimeDirectory: string;
  readonly targetAlias: string;
  readonly host: string;
  readonly username: string;
}

export interface TailscaleSshExecutorDependencies {
  readonly execute?: typeof executeManagedCommand;
}

/** Uses normal Tailscale networking and the pinned system OpenSSH binary.
 * Credentials and host keys come from the local Tailscale daemon, never ssh-keyscan.
 * Each invocation gets an isolated configuration so user ssh_config cannot add
 * credentials, proxies, forwarding, or local commands.
 */
export class TailscaleSshExecutor implements SshRunner {
  readonly #options: TailscaleSshExecutorOptions;
  readonly #execute: typeof executeManagedCommand;
  readonly #stop = new AbortController();
  readonly #active = new Set<Promise<SshOutcome>>();
  #fingerprints: readonly string[] = [];

  public constructor(options: TailscaleSshExecutorOptions, dependencies: TailscaleSshExecutorDependencies = {}) {
    tailscaleSshConnectionSchema.parse({ mode: "tailscale-ssh", host: options.host, username: options.username });
    for (const value of [options.executable, options.tailscaleExecutable, options.runtimeDirectory]) {
      if (!path.isAbsolute(value) || /[\u0000-\u001f\u007f"$%]/u.test(value)) throw new TypeError("Tailscale executable and runtime paths must be safe absolute paths");
    }
    this.#options = options;
    this.#execute = dependencies.execute ?? executeManagedCommand;
  }

  public get fingerprints(): readonly string[] { return this.#fingerprints; }

  public run(input: SshRunInput): Promise<SshOutcome> {
    if (this.#stop.signal.aborted) return Promise.reject(new SshExecutionError("Tailscale SSH executor is closed"));
    if (input.sshAlias !== this.#options.targetAlias) return Promise.reject(new SshExecutionError("Tailscale SSH target does not match"));
    // Validate command/alias/stdin before launching any local process.
    buildOpenSshArguments({}, input);
    const operation = this.#run(input);
    this.#active.add(operation);
    void operation.finally(() => this.#active.delete(operation)).catch(() => undefined);
    return operation;
  }

  async #run(input: SshRunInput): Promise<SshOutcome> {
    const startedAt = performance.now();
    const signal = AbortSignal.any([this.#stop.signal, ...(input.signal === undefined ? [] : [input.signal])]);
    const options = this.#options;
    this.#fingerprints = [];
    let peer: TailscalePeer;
    try {
      const status = await this.#execute({ ...options, executable: options.tailscaleExecutable }, {
        arguments: ["status", "--json"],
        signal: AbortSignal.any([signal, AbortSignal.timeout(10_000)]),
        maxCapturedOutputBytes: MAX_STATUS_BYTES,
      });
      if (status.aborted || status.exitCode !== 0 || status.stdoutTruncated) throw new TailscaleFailure("tailscale-unavailable");
      peer = resolveTailscalePeer(status.stdout, options.host);
    } catch (error) {
      // Status includes tailnet identities and addresses: never expose raw JSON/stderr.
      return {
        exitCode: signal.aborted ? null : 255, signal: null, stdout: "", stderr: "",
        stdoutBytes: 0, stderrBytes: 0, stdoutTruncated: false, stderrTruncated: false,
        aborted: signal.aborted, durationMs: Math.round(performance.now() - startedAt), terminationMode: null,
        ...(signal.aborted ? {} : { failureReason: error instanceof TailscaleFailure ? error.reason : "tailscale-unavailable" as const }),
      };
    }
    const directory = await mkdtemp(path.join(options.runtimeDirectory, ".tailscale-ssh-"));
    try {
      await hardenPrivatePath(directory, true);
      const configFile = path.join(directory, "ssh_config");
      const knownHostsFile = path.join(directory, "known_hosts");
      const config = [
        `Host ${options.targetAlias}`, `  HostName ${peer.address}`, `  User ${options.username}`, "  Port 22",
        "  ProxyCommand none", "  ProxyJump none", "  IdentityFile none", "  CertificateFile none",
        "  IdentityAgent none", "  PubkeyAuthentication no", "  PasswordAuthentication no",
        "  KbdInteractiveAuthentication no", "  GSSAPIAuthentication no", "  HostbasedAuthentication no",
        "  PreferredAuthentications none", "  CanonicalizeHostname no", "",
      ].join("\n");
      await writeFile(configFile, config, { mode: 0o600, flag: "wx" });
      await writeFile(knownHostsFile, peer.hostKeys.map((key) => `${peer.address} ${key}\n`).join(""), { mode: 0o600, flag: "wx" });
      await hardenPrivatePath(configFile, false);
      await hardenPrivatePath(knownHostsFile, false);
      this.#fingerprints = Object.freeze(peer.hostKeys.map((key) =>
        `SHA256:${createHash("sha256").update(Buffer.from(key.split(" ")[1]!, "base64")).digest("base64").replace(/=+$/u, "")}`,
      ));
      return await this.#execute(options, {
        arguments: buildOpenSshArguments({ ...options, configFile, knownHostsFile }, input),
        signal,
        ...(input.stdin === undefined ? {} : { stdin: input.stdin }),
        ...(input.outputSink === undefined ? {} : { outputSink: input.outputSink }),
        ...(input.maxCapturedOutputBytes === undefined ? {} : { maxCapturedOutputBytes: input.maxCapturedOutputBytes }),
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }

  public async close(): Promise<void> {
    this.#stop.abort();
    await Promise.allSettled([...this.#active]);
  }
}
