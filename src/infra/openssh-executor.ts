import { MAX_MANAGED_STDIN_BYTES } from "./process-tree.js";
import {
  executeManagedCommand,
  type ManagedCommandDependencies,
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
    const sshArguments = buildOpenSshArguments(this.#options, input);
    return executeManagedCommand(
      {
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
      },
      {
        arguments: sshArguments,
        ...(input.stdin === undefined ? {} : { stdin: input.stdin }),
        ...(input.signal === undefined ? {} : { signal: input.signal }),
        ...(input.outputSink === undefined
          ? {}
          : { outputSink: input.outputSink }),
        ...(input.maxCapturedOutputBytes === undefined
          ? {}
          : { maxCapturedOutputBytes: input.maxCapturedOutputBytes }),
      },
      this.#dependencies,
    );
  }

  public async close(): Promise<void> {}
}

export function buildOpenSshArguments(
  options: Pick<
    SshExecutorOptions,
    "configFile" | "knownHostsFile" | "connectTimeoutSeconds"
  >,
  input: Pick<SshRunInput, "sshAlias" | "command" | "stdin">,
): string[] {
  const connectTimeout =
    options.connectTimeoutSeconds ?? DEFAULT_CONNECT_TIMEOUT_SECONDS;
  validateConnectTimeout(connectTimeout);
  validateRunInput(input);

  const arguments_: string[] = [
    "-T",
    ...(input.stdin === undefined
      ? ["-n"]
      : ["-o", "StdinNull=no"]),
    "-S",
    "none",
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
    "-o",
    "ForkAfterAuthentication=no",
    "-o",
    "SessionType=default",
    "-o",
    "RemoteCommand=none",
    "-o",
    "AddKeysToAgent=no",
    "-o",
    "ControlMaster=no",
    "-o",
    "ControlPersist=no",
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

  arguments_.push("--", input.sshAlias, input.command);
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

function validateRunInput(
  input: Pick<SshRunInput, "sshAlias" | "command" | "stdin">,
): void {
  if (!TARGET_ALIAS_PATTERN.test(input.sshAlias)) {
    throw new TypeError(
      "sshAlias must be an approved OpenSSH alias containing only letters, digits, dots, underscores, and hyphens",
    );
  }
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
