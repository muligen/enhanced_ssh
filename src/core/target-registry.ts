import { createHash } from "node:crypto";

import type { GatewayConfig, TargetConfig } from "../config/load-config.js";
import { GATEWAY_ERROR_CODES, GatewayError } from "../shared/errors.js";
import {
  MAX_COMMAND_BYTES,
  TARGET_ALIAS_PATTERN,
  type TargetConnectionMode,
  type TargetSummary,
} from "../shared/protocol.js";

export interface RegisteredTarget {
  readonly targetId: string;
  readonly alias: string;
  readonly sshAlias: string;
  readonly description?: string;
  readonly enabled: boolean;
  readonly platform: TargetSummary["platform"];
  readonly connectionMode: TargetConnectionMode;
  readonly policyMode: TargetSummary["policyMode"];
  readonly transferMode: TargetSummary["transferMode"];
  readonly transferScope: TargetSummary["transferScope"];
  readonly transferRoots: readonly string[];
  readonly maxTimeoutMs: number;
}

export interface TargetAuthorization {
  readonly target: RegisteredTarget;
  readonly timeoutMs: number;
}

export interface TransferAuthorization extends TargetAuthorization {
  readonly scope: TargetSummary["transferScope"];
  readonly localRootPath?: string;
  readonly remoteRoots: readonly string[];
  readonly maxFileBytes: number;
  readonly maxTotalBytes: number;
  readonly maxFiles: number;
}

type RegistryTargetConfig = Omit<TargetConfig, "transfer"> & {
  readonly transfer?: TargetConfig["transfer"];
};

const TARGET_CHECK_TIMEOUT_MS = 15_000;
const ACCESSCLIENT_CHECK_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_TRANSFER_FILE_BYTES = 10_737_418_240;
const DEFAULT_MAX_TRANSFER_TOTAL_BYTES = 107_374_182_400;
const DEFAULT_MAX_TRANSFER_FILES = 10_000;

interface RegistryEntry {
  readonly target: RegisteredTarget;
  readonly allowedCommands: ReadonlySet<string>;
  readonly transfer: TargetConfig["transfer"] | undefined;
}

const MAX_ERROR_CANDIDATES = 8;

function compareAliases(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function createEntry(alias: string, config: RegistryTargetConfig): RegistryEntry {
  const unrestrictedTransfer =
    config.policy.mode === "full-access" && config.connection === undefined;
  const target: RegisteredTarget = Object.freeze({
    targetId: config.targetId ?? legacyTargetId(alias, config.sshAlias),
    alias,
    sshAlias: config.sshAlias,
    ...(config.description === undefined
      ? {}
      : { description: config.description }),
    enabled: config.enabled,
    platform: config.platform,
    connectionMode:
      config.connection?.mode === "accessclient-share"
        ? "accessclient-share"
        : "openssh",
    policyMode: config.policy.mode,
    transferMode: config.connection !== undefined
      ? "deny"
      : unrestrictedTransfer
      ? "bidirectional"
      : (config.transfer?.mode ?? "deny"),
    transferScope: unrestrictedTransfer ? "all" : "restricted",
    transferRoots: Object.freeze(
      unrestrictedTransfer ? [] : [...(config.transfer?.localRoots ?? [])],
    ),
    maxTimeoutMs: config.policy.maxTimeoutMs,
  });

  const allowedCommands =
    config.policy.mode === "allow-list"
      ? new Set(config.policy.allowedCommands)
      : new Set<string>();

  return Object.freeze({
    target,
    allowedCommands,
    transfer: config.transfer,
  });
}

function toSummary(target: RegisteredTarget): TargetSummary {
  return Object.freeze({
    targetId: target.targetId,
    alias: target.alias,
    ...(target.description === undefined
      ? {}
      : { description: target.description }),
    enabled: target.enabled,
    platform: target.platform,
    connectionMode: target.connectionMode,
    policyMode: target.policyMode,
    transferMode: target.transferMode,
    transferScope: target.transferScope,
    transferRoots: [...target.transferRoots],
    maxTimeoutMs: target.maxTimeoutMs,
  });
}

export class TargetRegistry {
  readonly #entries: ReadonlyMap<string, RegistryEntry>;
  readonly #references: ReadonlyMap<string, RegistryEntry>;
  readonly #summaries: readonly TargetSummary[];
  readonly #localRoots: Readonly<Record<string, string>>;

  public constructor(
    configs: Readonly<Record<string, RegistryTargetConfig>>,
    localRoots: Readonly<Record<string, string>> = {},
  ) {
    const entries = new Map<string, RegistryEntry>();
    const references = new Map<string, RegistryEntry>();
    for (const [alias, config] of Object.entries(configs)) {
      const entry = createEntry(alias, config);
      entries.set(alias, entry);
      for (const reference of [
        alias,
        entry.target.targetId,
        ...(config.previousAliases ?? []),
      ]) {
        const folded = reference.toLowerCase();
        if (references.has(folded)) {
          throw new GatewayError(
            GATEWAY_ERROR_CODES.configInvalid,
            "Target references are not unique",
          );
        }
        references.set(folded, entry);
      }
    }
    this.#entries = entries;
    this.#references = references;
    this.#localRoots = Object.freeze({ ...localRoots });
    this.#summaries = Object.freeze(
      [...entries.values()]
        .map((entry) => toSummary(entry.target))
        .sort((left, right) => compareAliases(left.alias, right.alias)),
    );
  }

  public static fromConfig(config: GatewayConfig): TargetRegistry {
    return new TargetRegistry(config.targets, config.transfer.localRoots);
  }

  /** Returns immutable public metadata and never exposes sshAlias or patterns. */
  public list(): readonly TargetSummary[] {
    return this.#summaries;
  }

  /** Resolves a target for execution, rejecting unknown and disabled aliases. */
  public require(alias: string): RegisteredTarget {
    if (!TARGET_ALIAS_PATTERN.test(alias)) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.invalidParams,
        "Target alias is invalid",
      );
    }

    const entry = this.#references.get(alias.toLowerCase());
    if (entry === undefined) {
      const candidates = this.#summaries
        .slice(0, MAX_ERROR_CANDIDATES)
        .map((target) => target.alias)
        .join(", ");
      throw new GatewayError(
        GATEWAY_ERROR_CODES.targetNotFound,
        "Target was not found",
        {
          details: {
            target: alias,
            ...(candidates.length === 0 ? {} : { candidates }),
          },
        },
      );
    }
    if (!entry.target.enabled) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.targetDisabled,
        "Target is disabled",
        { details: { target: alias } },
      );
    }
    return entry.target;
  }

  /**
   * Applies command and timeout policy before any SSH process is started.
   * A client may lower a target timeout but cannot silently raise it.
   */
  public authorize(
    alias: string,
    command: string,
    requestedTimeoutMs?: number,
  ): TargetAuthorization {
    const target = this.require(alias);
    const entry = this.#entries.get(target.alias);
    if (entry === undefined) {
      // `require` already proves this invariant; retain a safe failure if the
      // implementation changes later.
      throw new GatewayError(
        GATEWAY_ERROR_CODES.internalError,
        "Internal gateway error",
      );
    }

    if (
      command.trim().length === 0 ||
      /[\0\r\n]/u.test(command) ||
      Buffer.byteLength(command, "utf8") > MAX_COMMAND_BYTES
    ) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.invalidParams,
        "Command is invalid",
      );
    }

    const commandAllowed =
      target.policyMode === "full-access" ||
      (target.policyMode === "allow-list" && entry.allowedCommands.has(command));
    if (!commandAllowed) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.commandDenied,
        "Command is not allowed for this target",
        { details: { target: alias } },
      );
    }

    return Object.freeze({
      target,
      timeoutMs: authorizeTimeout(target, requestedTimeoutMs),
    });
  }

  /**
   * Authorizes a structured shell execution. Structured cwd/environment
   * context cannot be represented by the existing exact command allow-list,
   * so this capability is deliberately restricted to full-access targets.
   */
  public authorizeStructured(
    alias: string,
    requestedTimeoutMs?: number,
  ): TargetAuthorization {
    const target = this.require(alias);
    if (target.policyMode !== "full-access") {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.commandDenied,
        "Structured execution is not allowed for this target",
        { details: { target: alias } },
      );
    }

    return Object.freeze({
      target,
      timeoutMs: authorizeTimeout(target, requestedTimeoutMs),
    });
  }

  /**
   * Resolves a target for the gateway-owned connectivity probe. The probe is
   * independent of user command policy, but disabled targets remain closed.
   */
  public authorizeCheck(alias: string): TargetAuthorization {
    const target = this.require(alias);
    const probeTimeoutMs =
      target.connectionMode === "accessclient-share"
        ? ACCESSCLIENT_CHECK_TIMEOUT_MS
        : TARGET_CHECK_TIMEOUT_MS;
    return Object.freeze({
      target,
      timeoutMs: Math.min(target.maxTimeoutMs, probeTimeoutMs),
    });
  }

  public authorizeTransfer(
    alias: string,
    direction: "upload" | "download" | "sync",
    localRoot: string | undefined,
    requestedTimeoutMs?: number,
  ): TransferAuthorization {
    const target = this.require(alias);
    const entry = this.#entries.get(target.alias);
    const transfer = entry?.transfer;
    const unrestricted = target.transferScope === "all";
    const directionAllowed =
      unrestricted ||
      transfer?.mode === "bidirectional" ||
      ((direction === "upload" || direction === "sync") &&
        transfer?.mode === "upload") ||
      (direction === "download" && transfer?.mode === "download");
    if (!directionAllowed) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.transferDenied,
        "File transfer is not allowed for this target",
        { details: { target: alias } },
      );
    }
    if (
      !unrestricted &&
      (localRoot === undefined || !transfer?.localRoots.includes(localRoot))
    ) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.transferDenied,
        "Local transfer root is not allowed for this target",
        {
          details: {
            target: alias,
            ...(localRoot === undefined ? {} : { localRoot }),
          },
        },
      );
    }
    const localRootAllowed =
      localRoot !== undefined &&
      (unrestricted || transfer?.localRoots.includes(localRoot) === true);
    const localRootPath =
      localRootAllowed && localRoot !== undefined
        ? this.#localRoots[localRoot]
        : undefined;
    if (localRoot !== undefined && localRootPath === undefined) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.configInvalid,
        "Configured local transfer root is unavailable",
      );
    }
    const maximumTimeoutMs = transfer?.maxTimeoutMs ?? target.maxTimeoutMs;
    if (
      requestedTimeoutMs !== undefined &&
      (!Number.isSafeInteger(requestedTimeoutMs) ||
        requestedTimeoutMs < 1 ||
        requestedTimeoutMs > maximumTimeoutMs)
    ) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.invalidParams,
        "Requested transfer timeout exceeds the target policy",
        { details: { maxTimeoutMs: maximumTimeoutMs } },
      );
    }
    return Object.freeze({
      target,
      timeoutMs: requestedTimeoutMs ?? maximumTimeoutMs,
      scope: unrestricted ? "all" : "restricted",
      ...(localRootPath === undefined ? {} : { localRootPath }),
      remoteRoots: unrestricted ? [] : [...(transfer?.remoteRoots ?? [])],
      maxFileBytes: transfer?.maxFileBytes ?? DEFAULT_MAX_TRANSFER_FILE_BYTES,
      maxTotalBytes:
        transfer?.maxTotalBytes ?? DEFAULT_MAX_TRANSFER_TOTAL_BYTES,
      maxFiles: transfer?.maxFiles ?? DEFAULT_MAX_TRANSFER_FILES,
    });
  }

  public authorizeInspect(alias: string): TargetAuthorization {
    return this.authorizeCheck(alias);
  }

  public authorizeDockerPreflight(alias: string): TargetAuthorization {
    const target = this.require(alias);
    if (target.policyMode !== "full-access") {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.commandDenied,
        "Docker preflight is only enabled for full-access targets",
        { details: { target: alias } },
      );
    }
    return Object.freeze({
      target,
      timeoutMs: Math.min(target.maxTimeoutMs, 120_000),
    });
  }
}

function authorizeTimeout(
  target: RegisteredTarget,
  requestedTimeoutMs: number | undefined,
): number {
  if (
    requestedTimeoutMs !== undefined &&
    (!Number.isSafeInteger(requestedTimeoutMs) ||
      requestedTimeoutMs < 1 ||
      requestedTimeoutMs > target.maxTimeoutMs)
  ) {
    throw new GatewayError(
      GATEWAY_ERROR_CODES.invalidParams,
      "Requested timeout exceeds the target policy",
      { details: { maxTimeoutMs: target.maxTimeoutMs } },
    );
  }
  return requestedTimeoutMs ?? target.maxTimeoutMs;
}

function legacyTargetId(alias: string, sshAlias: string): string {
  const digest = createHash("sha256")
    .update("agent-ssh-legacy-target\0", "utf8")
    .update(sshAlias, "utf8")
    .update("\0", "utf8")
    .update(alias, "utf8")
    .digest("hex")
    .slice(0, 32);
  return `t-${digest}`;
}
