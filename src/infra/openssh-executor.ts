import {
  MAX_MANAGED_STDIN_BYTES,
  type ManagedProcess,
} from "./process-tree.js";
import {
  executeManagedCommand,
  executePrestartedCommand,
  spawnPrestartedProcess,
  type ManagedCommandDependencies,
  type ManagedCommandInput,
  type ManagedCommandOptions,
} from "./managed-command.js";
import {
  type SshOutcome,
  type SshRunInput,
  type SshRunner,
} from "./ssh-runner.js";
import {
  MAX_COMMAND_BYTES,
  TARGET_ALIAS_PATTERN,
} from "../shared/protocol.js";

export { SshExecutionError } from "./ssh-runner.js";
export type {
  OutputSink,
  OutputStream,
  SshOutcome,
  SshRunInput,
  SshRunner,
} from "./ssh-runner.js";

export interface SshExecutorOptions {
  readonly executable: string;
  readonly configFile?: string;
  readonly knownHostsFile?: string;
  readonly connectTimeoutSeconds?: number;
  readonly maxCapturedOutputBytes?: number;
  readonly cwd?: string;
  readonly environment?: NodeJS.ProcessEnv;
  readonly windowsSupervisorPath?: string;
  readonly allowUnsafeProcessTermination?: boolean;
  /** Optional per-generation pool of shared connections to reuse. */
  readonly controlMasters?: SshControlPathProvider;
}

export interface SshControlPathProvider {
  /** Resolves a live control socket, or undefined to connect directly. */
  acquire(sshAlias: string, signal?: AbortSignal): Promise<string | undefined>;
}

export interface SshExecutorDependencies extends ManagedCommandDependencies {}

const DEFAULT_CONNECT_TIMEOUT_SECONDS = 15;

export class SshExecutor implements SshRunner {
  readonly #options: SshExecutorOptions;
  readonly #dependencies: SshExecutorDependencies;

  public constructor(
    options: SshExecutorOptions,
    dependencies: SshExecutorDependencies = {},
  ) {
    validateExecutorOptions(options);
    this.#options = options;
    this.#dependencies = dependencies;
  }

  public async run(input: SshRunInput): Promise<SshOutcome> {
    validateRunInput(input);
    const controlPath = await this.#options.controlMasters?.acquire(
      input.sshAlias,
      input.signal,
    );
    const sshArguments = buildOpenSshArguments(this.#options, input, controlPath);
    return executeManagedCommand(
      this.#commandOptions(),
      { arguments: sshArguments, ...commandInput(input) },
      this.#dependencies,
    );
  }

  /**
   * Starts `command` over a shared connection and leaves its standard input
   * open for {@link runPrestarted}. Resolves undefined when no shared
   * connection is available, so a waiting process never holds a dedicated one.
   */
  public async prestart(
    sshAlias: string,
    command: string,
  ): Promise<ManagedProcess | undefined> {
    const input = { sshAlias, command, stdin: new Uint8Array() };
    validateRunInput(input);
    const controlPath = await this.#options.controlMasters?.acquire(sshAlias);
    if (controlPath === undefined) return undefined;
    return spawnPrestartedProcess(
      this.#commandOptions(),
      buildOpenSshArguments(this.#options, input, controlPath),
      this.#dependencies,
    );
  }

  /** Runs `input` on a process that {@link prestart} started for the same alias and command. */
  public async runPrestarted(
    prestarted: ManagedProcess,
    input: SshRunInput,
  ): Promise<SshOutcome> {
    validateRunInput(input);
    return executePrestartedCommand(
      prestarted,
      this.#commandOptions(),
      commandInput(input),
    );
  }

  public async close(): Promise<void> {}

  #commandOptions(): ManagedCommandOptions {
    return {
      executable: this.#options.executable,
      ...(this.#options.maxCapturedOutputBytes === undefined
        ? {}
        : { maxCapturedOutputBytes: this.#options.maxCapturedOutputBytes }),
      ...(this.#options.cwd === undefined ? {} : { cwd: this.#options.cwd }),
      ...(this.#options.environment === undefined
        ? {}
        : { environment: this.#options.environment }),
      ...(this.#options.windowsSupervisorPath === undefined
        ? {}
        : { windowsSupervisorPath: this.#options.windowsSupervisorPath }),
      ...(this.#options.allowUnsafeProcessTermination === undefined
        ? {}
        : {
            allowUnsafeProcessTermination:
              this.#options.allowUnsafeProcessTermination,
          }),
    };
  }
}

function commandInput(
  input: SshRunInput,
): Omit<ManagedCommandInput, "arguments"> {
  return {
    ...(input.stdin === undefined ? {} : { stdin: input.stdin }),
    ...(input.signal === undefined ? {} : { signal: input.signal }),
    ...(input.outputSink === undefined ? {} : { outputSink: input.outputSink }),
    ...(input.maxCapturedOutputBytes === undefined
      ? {}
      : { maxCapturedOutputBytes: input.maxCapturedOutputBytes }),
  };
}

export function buildOpenSshArguments(
  options: Pick<
    SshExecutorOptions,
    "configFile" | "knownHostsFile" | "connectTimeoutSeconds"
  >,
  input: Pick<SshRunInput, "sshAlias" | "command" | "stdin">,
  controlPath?: string,
): string[] {
  validateRunInput(input);
  if (controlPath !== undefined) validateControlPath(controlPath);

  // A control path only makes this process a multiplexing client of a master
  // started by SshControlMasterPool. ControlMaster=no means a missing or dead
  // master falls back to an ordinary, fully authenticated connection.
  const arguments_: string[] = [
    "-T",
    ...(input.stdin === undefined
      ? ["-n"]
      : ["-o", "StdinNull=no"]),
    "-S",
    controlPath ?? "none",
    ...hardenedSessionOptions(options, "command"),
  ];
  arguments_.push("--", input.sshAlias, input.command);
  return arguments_;
}

/**
 * Arguments for a dedicated, daemonized control master. It authenticates with
 * the same hardened options as a command, runs no remote session, and exits on
 * its own after `persistSeconds` without multiplexed clients.
 */
export function buildOpenSshControlMasterArguments(
  options: Pick<
    SshExecutorOptions,
    "configFile" | "knownHostsFile" | "connectTimeoutSeconds"
  >,
  sshAlias: string,
  controlPath: string,
  persistSeconds: number,
): string[] {
  validateAlias(sshAlias);
  validateControlPath(controlPath);
  if (!Number.isSafeInteger(persistSeconds) || persistSeconds < 1) {
    throw new RangeError("persistSeconds must be a positive integer");
  }
  return [
    "-M",
    "-N",
    "-f",
    "-n",
    "-T",
    "-S",
    controlPath,
    "-o",
    `ControlPersist=${persistSeconds}`,
    "-o",
    "ServerAliveInterval=15",
    "-o",
    "ServerAliveCountMax=3",
    ...hardenedSessionOptions(options, "master"),
    "--",
    sshAlias,
  ];
}

/** Arguments that send a multiplexing control command (`stop`, `exit`, `check`). */
export function buildOpenSshControlCommandArguments(
  sshAlias: string,
  controlPath: string,
  command: "check" | "exit" | "stop",
): string[] {
  validateAlias(sshAlias);
  validateControlPath(controlPath);
  return ["-F", "none", "-S", controlPath, "-O", command, "--", sshAlias];
}

function hardenedSessionOptions(
  options: Pick<
    SshExecutorOptions,
    "configFile" | "knownHostsFile" | "connectTimeoutSeconds"
  >,
  role: "command" | "master",
): string[] {
  const connectTimeout =
    options.connectTimeoutSeconds ?? DEFAULT_CONNECT_TIMEOUT_SECONDS;
  validateConnectTimeout(connectTimeout);

  const arguments_: string[] = [
    "-o",
    "BatchMode=yes",
    "-o",
    "NumberOfPasswordPrompts=0",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "KnownHostsCommand=none",
    "-o",
    "VerifyHostKeyDNS=no",
    "-o",
    "ConnectionAttempts=1",
    "-o",
    `ConnectTimeout=${connectTimeout}`,
    "-o",
    "ClearAllForwardings=yes",
    "-o",
    "PermitLocalCommand=no",
    "-o",
    "ForwardAgent=no",
    "-o",
    "ForwardX11=no",
    // The master's -f, -N, -M, and ControlPersist flags must not be contradicted.
    ...(role === "command"
      ? [
          "-o",
          "ForkAfterAuthentication=no",
          "-o",
          "SessionType=default",
        ]
      : []),
    "-o",
    "RemoteCommand=none",
    "-o",
    "AddKeysToAgent=no",
    ...(role === "command"
      ? ["-o", "ControlMaster=no", "-o", "ControlPersist=no"]
      : []),
    "-o",
    "EscapeChar=none",
    "-o",
    "EnableEscapeCommandline=no",
    "-o",
    "UpdateHostKeys=no",
  ];

  if (options.configFile !== undefined) {
    validatePathArgument(options.configFile, "configFile");
    arguments_.push("-F", options.configFile);
  }

  if (options.knownHostsFile !== undefined) {
    validateKnownHostsPath(options.knownHostsFile);
    arguments_.push(
      "-o",
      `UserKnownHostsFile=${quoteSshConfigValue(options.knownHostsFile)}`,
      "-o",
      "GlobalKnownHostsFile=none",
    );
  }
  return arguments_;
}

function validateExecutorOptions(options: SshExecutorOptions): void {
  validatePathArgument(options.executable, "executable");
  if (options.connectTimeoutSeconds !== undefined) {
    validateConnectTimeout(options.connectTimeoutSeconds);
  }
  if (options.maxCapturedOutputBytes !== undefined) {
    validateByteLimit(options.maxCapturedOutputBytes, "maxCapturedOutputBytes");
  }
  if (options.configFile !== undefined) {
    validatePathArgument(options.configFile, "configFile");
  }
  if (options.knownHostsFile !== undefined) {
    validateKnownHostsPath(options.knownHostsFile);
  }
}

function validateAlias(sshAlias: string): void {
  if (!TARGET_ALIAS_PATTERN.test(sshAlias)) {
    throw new TypeError(
      "sshAlias must be an approved OpenSSH alias containing only letters, digits, dots, underscores, and hyphens",
    );
  }
}

function validateControlPath(value: string): void {
  validatePathArgument(value, "controlPath");
  // OpenSSH expands % and ~ in ControlPath; managed paths must be literal.
  if (value === "none" || /[%~$\s]/u.test(value)) {
    throw new TypeError("controlPath must be a literal path without OpenSSH expansions or whitespace");
  }
}

function validateRunInput(
  input: Pick<SshRunInput, "sshAlias" | "command" | "stdin">,
): void {
  validateAlias(input.sshAlias);
  if (input.command.trim().length === 0 || /[\0\r\n]/u.test(input.command)) {
    throw new TypeError(
      "command must be non-empty and must not contain NUL, CR, or LF characters",
    );
  }
  if (Buffer.byteLength(input.command, "utf8") > MAX_COMMAND_BYTES) {
    throw new RangeError(`command must not exceed ${MAX_COMMAND_BYTES} UTF-8 bytes`);
  }
  if (
    input.stdin !== undefined &&
    input.stdin.byteLength > MAX_MANAGED_STDIN_BYTES
  ) {
    throw new RangeError(
      `stdin must not exceed ${MAX_MANAGED_STDIN_BYTES} bytes`,
    );
  }
}

function validatePathArgument(value: string, name: string): void {
  if (value.length === 0 || /[\0\r\n]/u.test(value)) {
    throw new TypeError(`${name} must be non-empty and must not contain control characters`);
  }
}

function validateKnownHostsPath(value: string): void {
  validatePathArgument(value, "knownHostsFile");
  if (value.includes("$")) {
    throw new TypeError(
      "knownHostsFile must not contain OpenSSH environment expansions",
    );
  }
}

function validateConnectTimeout(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > 300) {
    throw new RangeError("connectTimeoutSeconds must be an integer from 1 through 300");
  }
}

function validateByteLimit(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative safe integer`);
  }
}

function quoteSshConfigValue(value: string): string {
  return `"${value
    .replaceAll("\\", "\\\\")
    .replaceAll('"', '\\"')
    .replaceAll("%", "%%")}"`;
}
