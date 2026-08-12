import {
  MAX_COMMAND_BYTES,
  type TargetPlatform,
} from "../shared/protocol.js";
import { GATEWAY_ERROR_CODES, GatewayError } from "../shared/errors.js";

export const WINDOWS_POWERSHELL_REMOTE_COMMAND =
  "powershell.exe -NoLogo -NoProfile -NonInteractive -Command -";
export const POSIX_BASH_REMOTE_COMMAND = "bash --noprofile --norc -s";

export type StructuredRemoteShell = "powershell" | "cmd" | "bash";

export interface StructuredRemoteCommandInput {
  readonly shell: StructuredRemoteShell;
  readonly script: string;
  readonly cwd?: string | undefined;
  readonly env?: Readonly<Record<string, string>> | undefined;
  readonly encoding?: "utf-8" | undefined;
}

export interface PreparedRemoteCommand {
  readonly command: string;
  readonly stdin?: Uint8Array;
}

const MAX_ENVIRONMENT_ENTRIES = 64;
const ENVIRONMENT_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

const WINDOWS_COMPLETION = [
  "$agentSshCommandSucceeded=$?",
  "$agentSshNativeExitVariable=Microsoft.PowerShell.Utility\\Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue",
  "$agentSshNativeExitCode=if($null -eq $agentSshNativeExitVariable){$null}else{$agentSshNativeExitVariable.Value}",
  "if($agentSshCommandSucceeded){exit 0}",
  "if($agentSshNativeExitCode -is [int] -and $agentSshNativeExitCode -ne 0){exit $agentSshNativeExitCode}",
  "exit 1",
].join(";");

const WINDOWS_UTF8_SETUP = [
  "$agentSshUtf8=[System.Text.UTF8Encoding]::new($false)",
  "[Console]::InputEncoding=$agentSshUtf8",
  "[Console]::OutputEncoding=$agentSshUtf8",
  "$OutputEncoding=$agentSshUtf8",
];

/**
 * Produces the legacy remote command and, for Windows, an ASCII PowerShell
 * wrapper delivered over standard input. The user's UTF-8 command never
 * enters argv on Windows. Linux and macOS behavior intentionally remains a
 * byte-for-byte pass-through for compatibility.
 */
export function prepareRemoteCommand(
  platform: TargetPlatform,
  command: string,
): PreparedRemoteCommand {
  if (platform !== "windows") {
    return { command };
  }

  const commandBytes = Buffer.byteLength(command, "utf8");
  if (commandBytes > MAX_COMMAND_BYTES) {
    throw new GatewayError(
      GATEWAY_ERROR_CODES.invalidParams,
      "Command is too long for a Windows target",
      { details: { maximumCommandBytes: MAX_COMMAND_BYTES } },
    );
  }

  return prepareWindowsPowerShellScript(command);
}

/**
 * Renders a structured execution without placing user-controlled script,
 * working-directory, or environment text in the local ssh.exe argv. Shell
 * names map to fixed platform-owned entry points and cannot select arbitrary
 * executables or arguments.
 */
export function prepareStructuredRemoteCommand(
  platform: TargetPlatform,
  input: StructuredRemoteCommandInput,
): PreparedRemoteCommand {
  const environment = validateStructuredInput(platform, input);

  switch (input.shell) {
    case "powershell":
      return prepareWindowsPowerShellScript(
        input.script,
        prepareWindowsContext(input.cwd, environment),
      );
    case "cmd":
      return prepareWindowsCmdScript(input, environment);
    case "bash":
      return preparePosixBashScript(input, environment);
  }
}

function prepareWindowsPowerShellScript(
  script: string,
  context: readonly string[] = [],
): PreparedRemoteCommand {
  const commandText = `${script}\n\n${WINDOWS_COMPLETION}`;
  const wrapper = [
    ...WINDOWS_UTF8_SETUP,
    ...context,
    `$agentSshCommandText=${powershellUtf8Expression(commandText)}`,
    "try{$agentSshScript=[ScriptBlock]::Create($agentSshCommandText)}catch{[Console]::Error.WriteLine('PowerShell command parsing failed.');exit 1}",
    "try{& $agentSshScript 2>&1|ForEach-Object{if($_ -is [System.Management.Automation.ErrorRecord]){[Console]::Error.WriteLine($_.Exception.Message)}else{$_}}}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 1}",
  ].join(";");

  return {
    command: WINDOWS_POWERSHELL_REMOTE_COMMAND,
    stdin: Buffer.from(`${wrapper}\n`, "ascii"),
  };
}

function prepareWindowsCmdScript(
  input: StructuredRemoteCommandInput,
  environment: readonly (readonly [string, string])[],
): PreparedRemoteCommand {
  const batchText = [
    "@echo off",
    "chcp 65001 >nul",
    input.script,
  ].join("\r\n");
  const wrapper = [
    ...WINDOWS_UTF8_SETUP,
    "$agentSshCmdExecutable=[System.IO.Path]::Combine($env:SystemRoot,'System32','cmd.exe')",
    "$agentSshTempDirectory=[System.IO.Path]::GetTempPath()",
    ...prepareWindowsContext(input.cwd, environment),
    `$agentSshBatchText=${powershellUtf8Expression(batchText)}`,
    "$agentSshBatchPath=[System.IO.Path]::Combine($agentSshTempDirectory,('agent-ssh-'+[System.Guid]::NewGuid().ToString('N')+'.cmd'))",
    "$agentSshBatchExitCode=1",
    "try{$agentSshBatchBytes=$agentSshUtf8.GetBytes($agentSshBatchText);$agentSshBatchStream=[System.IO.File]::Open($agentSshBatchPath,[System.IO.FileMode]::CreateNew,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None);try{$agentSshBatchStream.Write($agentSshBatchBytes,0,$agentSshBatchBytes.Length)}finally{$agentSshBatchStream.Dispose()};& $agentSshCmdExecutable '/d' '/q' '/s' '/c' ('call \"'+$agentSshBatchPath+'\"');if($global:LASTEXITCODE -is [int]){$agentSshBatchExitCode=$global:LASTEXITCODE}}catch{[Console]::Error.WriteLine('Command Prompt execution failed.');$agentSshBatchExitCode=1}finally{try{[System.IO.File]::Delete($agentSshBatchPath)}catch{}}",
    "exit $agentSshBatchExitCode",
  ].join(";");

  return {
    command: WINDOWS_POWERSHELL_REMOTE_COMMAND,
    stdin: Buffer.from(`${wrapper}\n`, "ascii"),
  };
}

function prepareWindowsContext(
  cwd: string | undefined,
  environment: readonly (readonly [string, string])[],
): string[] {
  const statements: string[] = [];
  for (const [name, value] of environment) {
    statements.push(
      `try{[System.Environment]::SetEnvironmentVariable(${powershellUtf8Expression(name)},${powershellUtf8Expression(value)},[System.EnvironmentVariableTarget]::Process)}catch{[Console]::Error.WriteLine('Remote environment setup failed.');exit 1}`,
    );
  }
  if (cwd !== undefined) {
    statements.push(
      `try{Set-Location -LiteralPath (${powershellUtf8Expression(cwd)}) -ErrorAction Stop}catch{[Console]::Error.WriteLine('Remote working directory is unavailable.');exit 1}`,
    );
  }
  return statements;
}

function preparePosixBashScript(
  input: StructuredRemoteCommandInput,
  environment: readonly (readonly [string, string])[],
): PreparedRemoteCommand {
  const prelude: string[] = [];
  for (const [name, value] of environment) {
    prelude.push(
      `if ! export ${name}=${quotePosixLiteral(value)} 2>/dev/null; then printf '%s\\n' 'Remote environment setup failed.' >&2; exit 1; fi`,
    );
  }
  if (input.cwd !== undefined) {
    prelude.push(
      `if ! cd -- ${quotePosixLiteral(input.cwd)} 2>/dev/null; then printf '%s\\n' 'Remote working directory is unavailable.' >&2; exit 1; fi`,
    );
  }

  return {
    command: POSIX_BASH_REMOTE_COMMAND,
    stdin: Buffer.from([...prelude, input.script, ""].join("\n"), "utf8"),
  };
}

function validateStructuredInput(
  platform: TargetPlatform,
  input: StructuredRemoteCommandInput,
): readonly (readonly [string, string])[] {
  const supported =
    (platform === "windows" &&
      (input.shell === "powershell" || input.shell === "cmd")) ||
    ((platform === "linux" || platform === "macos") && input.shell === "bash");
  if (!supported) {
    throw invalidStructuredCommand("Shell is not supported for the target platform", {
      platform,
      shell: input.shell,
    });
  }
  if (
    typeof input.script !== "string" ||
    input.script.trim().length === 0 ||
    input.script.includes("\0")
  ) {
    throw invalidStructuredCommand("Structured script is invalid");
  }
  if (
    input.cwd !== undefined &&
    (typeof input.cwd !== "string" ||
      input.cwd.trim().length === 0 ||
      /[\0\r\n]/u.test(input.cwd))
  ) {
    throw invalidStructuredCommand("Remote working directory is invalid");
  }
  if (input.encoding !== undefined && input.encoding !== "utf-8") {
    throw invalidStructuredCommand("Structured command encoding is not supported");
  }

  const environment = validateEnvironment(input.env, input.shell !== "bash");
  let payloadBytes = Buffer.byteLength(input.script, "utf8");
  if (input.cwd !== undefined) {
    payloadBytes += Buffer.byteLength(input.cwd, "utf8");
  }
  for (const [name, value] of environment) {
    payloadBytes += Buffer.byteLength(name, "utf8");
    payloadBytes += Buffer.byteLength(value, "utf8");
  }
  if (payloadBytes > MAX_COMMAND_BYTES) {
    throw invalidStructuredCommand("Structured command payload is too large", {
      maximumPayloadBytes: MAX_COMMAND_BYTES,
    });
  }
  return environment;
}

function validateEnvironment(
  value: Readonly<Record<string, string>> | undefined,
  environmentNamesIgnoreCase: boolean,
): readonly (readonly [string, string])[] {
  if (value === undefined) {
    return [];
  }
  if (
    value === null ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null)
  ) {
    throw invalidStructuredCommand("Remote environment is invalid");
  }

  const entries = Object.entries(value);
  if (entries.length > MAX_ENVIRONMENT_ENTRIES) {
    throw invalidStructuredCommand("Remote environment has too many entries", {
      maximumEnvironmentEntries: MAX_ENVIRONMENT_ENTRIES,
    });
  }
  const normalizedNames = new Set<string>();
  for (const [name, environmentValue] of entries) {
    const normalizedName = environmentNamesIgnoreCase ? name.toLowerCase() : name;
    if (
      !ENVIRONMENT_NAME_PATTERN.test(name) ||
      normalizedNames.has(normalizedName) ||
      typeof environmentValue !== "string" ||
      environmentValue.includes("\0")
    ) {
      throw invalidStructuredCommand("Remote environment is invalid");
    }
    normalizedNames.add(normalizedName);
  }
  return entries.sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
}

function powershellUtf8Expression(value: string): string {
  const encoded = Buffer.from(value, "utf8").toString("base64");
  return `[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'))`;
}

function quotePosixLiteral(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function invalidStructuredCommand(
  message: string,
  details?: Readonly<Record<string, string | number | boolean | null>>,
): GatewayError {
  return new GatewayError(GATEWAY_ERROR_CODES.invalidParams, message, {
    ...(details === undefined ? {} : { details }),
  });
}
