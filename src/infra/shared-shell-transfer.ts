import type { TargetPlatform } from "../shared/protocol.js";
import { prepareStructuredRemoteCommand } from "../core/remote-command.js";
import type { SshOutcome, SshRunner } from "./ssh-runner.js";

export const SHARED_SHELL_TRANSFER_CHUNK_BYTES = 96 * 1024;

export interface SharedShellTransferTarget {
  readonly sshAlias: string;
  readonly platform: TargetPlatform;
}

export interface SharedShellWriteInput {
  readonly target: SharedShellTransferTarget;
  readonly remotePath: string;
  readonly bytes: Uint8Array;
  readonly truncate: boolean;
  readonly signal: AbortSignal;
}

export interface SharedShellReadInput {
  readonly target: SharedShellTransferTarget;
  readonly remotePath: string;
  readonly offset: number;
  readonly length: number;
  readonly signal: AbortSignal;
}

export class SharedShellTransferError extends Error {
  public override readonly cause: unknown;

  public constructor(message: string, options?: { readonly cause?: unknown }) {
    super(message);
    this.name = "SharedShellTransferError";
    this.cause = options?.cause;
  }
}

/**
 * Moves bounded file chunks through the already-authenticated persistent
 * shell. No second SSH authentication or SFTP subsystem is opened.
 */
export class SharedShellTransferExecutor {
  readonly #ssh: SshRunner;

  public constructor(ssh: SshRunner) {
    this.#ssh = ssh;
  }

  public async write(input: SharedShellWriteInput): Promise<void> {
    validateTarget(input.target);
    validateRemotePath(input.remotePath);
    if (input.bytes.byteLength > SHARED_SHELL_TRANSFER_CHUNK_BYTES) {
      throw new RangeError("shared-shell transfer chunk is too large");
    }
    const command = buildWriteCommand(
      input.target.platform,
      input.remotePath,
      input.truncate,
    );
    const outcome = await this.#ssh.run({
      sshAlias: input.target.sshAlias,
      command,
      stdin: input.bytes,
      signal: input.signal,
      maxCapturedOutputBytes: 1_024,
    });
    requireSuccessfulOutcome(outcome, "write remote file chunk");
  }

  public async read(input: SharedShellReadInput): Promise<Buffer> {
    validateTarget(input.target);
    validateRemotePath(input.remotePath);
    if (
      !Number.isSafeInteger(input.offset) ||
      input.offset < 0 ||
      !Number.isSafeInteger(input.length) ||
      input.length < 1 ||
      input.length > SHARED_SHELL_TRANSFER_CHUNK_BYTES
    ) {
      throw new RangeError("shared-shell transfer range is invalid");
    }
    const prepared = prepareStructuredRemoteCommand(input.target.platform, {
      shell: input.target.platform === "windows" ? "powershell" : "bash",
      env: {
        AGENT_SSH_TRANSFER_PATH: input.remotePath,
        AGENT_SSH_TRANSFER_OFFSET: String(input.offset),
        AGENT_SSH_TRANSFER_LENGTH: String(input.length),
      },
      encoding: "utf-8",
      script: readChunkScript(input.target.platform),
    });
    const maximumEncodedBytes = Math.ceil(input.length / 3) * 4;
    const outcome = await this.#ssh.run({
      sshAlias: input.target.sshAlias,
      ...prepared,
      signal: input.signal,
      maxCapturedOutputBytes: maximumEncodedBytes + 1_024,
    });
    requireSuccessfulOutcome(outcome, "read remote file chunk");
    const decoded = decodeCanonicalBase64(outcome.stdout);
    if (decoded.byteLength !== input.length) {
      throw new SharedShellTransferError(
        "the remote file chunk length did not match the requested range",
      );
    }
    return decoded;
  }

  public async ensureDirectory(
    target: SharedShellTransferTarget,
    remotePath: string,
    signal: AbortSignal,
  ): Promise<void> {
    await this.#runStructured(
      target,
      remotePath,
      target.platform === "windows"
        ? "[void][System.IO.Directory]::CreateDirectory($env:AGENT_SSH_TRANSFER_PATH)"
        : "umask 077; mkdir -p -- \"$AGENT_SSH_TRANSFER_PATH\"",
      signal,
      "create remote transfer directory",
    );
  }

  public async removeFile(
    target: SharedShellTransferTarget,
    remotePath: string,
    signal: AbortSignal,
  ): Promise<void> {
    const script = target.platform === "windows"
      ? [
          "$agentSshPath=$env:AGENT_SSH_TRANSFER_PATH",
          "if(Test-Path -LiteralPath $agentSshPath){",
          "  $agentSshItem=Microsoft.PowerShell.Management\\Get-Item -LiteralPath $agentSshPath -Force -ErrorAction Stop",
          "  if($agentSshItem.PSIsContainer){exit 12}",
          "  Microsoft.PowerShell.Management\\Remove-Item -LiteralPath $agentSshPath -Force -ErrorAction Stop",
          "}",
        ].join("\n")
      : [
          "if [ -d \"$AGENT_SSH_TRANSFER_PATH\" ] && [ ! -L \"$AGENT_SSH_TRANSFER_PATH\" ]; then exit 12; fi",
          "rm -f -- \"$AGENT_SSH_TRANSFER_PATH\"",
        ].join("\n");
    await this.#runStructured(
      target,
      remotePath,
      script,
      signal,
      "remove remote partial file",
    );
  }

  public async replaceFile(
    target: SharedShellTransferTarget,
    sourcePath: string,
    destinationPath: string,
    signal: AbortSignal,
  ): Promise<void> {
    validateTarget(target);
    validateRemotePath(sourcePath);
    validateRemotePath(destinationPath);
    const prepared = prepareStructuredRemoteCommand(target.platform, {
      shell: target.platform === "windows" ? "powershell" : "bash",
      env: {
        AGENT_SSH_TRANSFER_PART: sourcePath,
        AGENT_SSH_TRANSFER_DESTINATION: destinationPath,
      },
      encoding: "utf-8",
      script: target.platform === "windows"
        ? [
            "$agentSshPart=$env:AGENT_SSH_TRANSFER_PART",
            "$agentSshDestination=$env:AGENT_SSH_TRANSFER_DESTINATION",
            "if(Test-Path -LiteralPath $agentSshDestination){",
            "  [System.IO.File]::Replace($agentSshPart,$agentSshDestination,$null,$true)",
            "}else{",
            "  [System.IO.File]::Move($agentSshPart,$agentSshDestination)",
            "}",
          ].join("\n")
        : "mv -f -- \"$AGENT_SSH_TRANSFER_PART\" \"$AGENT_SSH_TRANSFER_DESTINATION\"",
    });
    const outcome = await this.#ssh.run({
      sshAlias: target.sshAlias,
      ...prepared,
      signal,
      maxCapturedOutputBytes: 1_024,
    });
    requireSuccessfulOutcome(outcome, "publish remote file");
  }

  async #runStructured(
    target: SharedShellTransferTarget,
    remotePath: string,
    script: string,
    signal: AbortSignal,
    operation: string,
  ): Promise<void> {
    validateTarget(target);
    validateRemotePath(remotePath);
    const prepared = prepareStructuredRemoteCommand(target.platform, {
      shell: target.platform === "windows" ? "powershell" : "bash",
      env: { AGENT_SSH_TRANSFER_PATH: remotePath },
      encoding: "utf-8",
      script,
    });
    const outcome = await this.#ssh.run({
      sshAlias: target.sshAlias,
      ...prepared,
      signal,
      maxCapturedOutputBytes: 1_024,
    });
    requireSuccessfulOutcome(outcome, operation);
  }
}

function buildWriteCommand(
  platform: TargetPlatform,
  remotePath: string,
  truncate: boolean,
): string {
  if (platform === "windows") {
    const pathExpression = powershellUtf8Expression(remotePath);
    const mode = truncate ? "Create" : "Append";
    const script = [
      "$ErrorActionPreference='Stop'",
      `$agentSshPath=${pathExpression}`,
      "$agentSshExists=Test-Path -LiteralPath $agentSshPath",
      "if($agentSshExists){",
      "  $agentSshItem=Microsoft.PowerShell.Management\\Get-Item -LiteralPath $agentSshPath -Force -ErrorAction Stop",
      "  if($agentSshItem.PSIsContainer -or (($agentSshItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)){exit 12}",
      "}",
      ...(truncate ? [] : ["if(-not $agentSshExists){exit 12}"]),
      `$agentSshMode=[System.IO.FileMode]::${mode}`,
      "$agentSshStream=[System.IO.File]::Open($agentSshPath,$agentSshMode,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None)",
      "try{[Console]::OpenStandardInput().CopyTo($agentSshStream);$agentSshStream.Flush($true)}finally{$agentSshStream.Dispose()}",
    ].join(";");
    return `powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ${Buffer.from(script, "utf16le").toString("base64")}`;
  }
  const pathLiteral = quotePosixLiteral(remotePath);
  const redirect = truncate ? ">" : ">>";
  const requireExisting = truncate
    ? ""
    : "[ -f \"$agentSshPath\" ] || exit 12; ";
  return [
    "set -eu",
    "umask 077",
    `agentSshPath=${pathLiteral}`,
    "[ ! -L \"$agentSshPath\" ] || exit 11",
    `${requireExisting}/bin/cat ${redirect} \"$agentSshPath\"`,
    "/bin/chmod 600 \"$agentSshPath\"",
  ].join("; ");
}

function readChunkScript(platform: TargetPlatform): string {
  if (platform === "windows") {
    return [
      "$agentSshOffset=[Int64]::Parse($env:AGENT_SSH_TRANSFER_OFFSET,[Globalization.CultureInfo]::InvariantCulture)",
      "$agentSshLength=[Int32]::Parse($env:AGENT_SSH_TRANSFER_LENGTH,[Globalization.CultureInfo]::InvariantCulture)",
      "$agentSshStream=[System.IO.File]::Open($env:AGENT_SSH_TRANSFER_PATH,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::Read)",
      "try{",
      "  [void]$agentSshStream.Seek($agentSshOffset,[System.IO.SeekOrigin]::Begin)",
      "  $agentSshBytes=[byte[]]::new($agentSshLength)",
      "  $agentSshRead=0",
      "  while($agentSshRead -lt $agentSshLength){$agentSshCount=$agentSshStream.Read($agentSshBytes,$agentSshRead,$agentSshLength-$agentSshRead);if($agentSshCount -eq 0){break};$agentSshRead+=$agentSshCount}",
      "  if($agentSshRead -ne $agentSshLength){exit 13}",
      "  [Console]::Out.Write([Convert]::ToBase64String($agentSshBytes))",
      "}finally{$agentSshStream.Dispose()}",
    ].join("\n");
  }
  return [
    "set -euo pipefail",
    "[[ $AGENT_SSH_TRANSFER_OFFSET =~ ^(0|[1-9][0-9]*)$ ]] || exit 12",
    "[[ $AGENT_SSH_TRANSFER_LENGTH =~ ^[1-9][0-9]*$ ]] || exit 12",
    "[ -f \"$AGENT_SSH_TRANSFER_PATH\" ] && [ ! -L \"$AGENT_SSH_TRANSFER_PATH\" ] || exit 12",
    "dd if=\"$AGENT_SSH_TRANSFER_PATH\" bs=1 skip=\"$AGENT_SSH_TRANSFER_OFFSET\" count=\"$AGENT_SSH_TRANSFER_LENGTH\" 2>/dev/null | base64 | tr -d '\\r\\n'",
  ].join("\n");
}

function requireSuccessfulOutcome(outcome: SshOutcome, operation: string): void {
  if (outcome.aborted) {
    throw new SharedShellTransferError(`shared-shell transfer was stopped while trying to ${operation}`);
  }
  if (
    outcome.exitCode !== 0 ||
    outcome.stdoutTruncated ||
    outcome.stderrTruncated ||
    outcome.stderr.length !== 0
  ) {
    throw new SharedShellTransferError(`shared-shell transfer could not ${operation}`);
  }
}

function decodeCanonicalBase64(value: string): Buffer {
  if (
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
  ) {
    throw new SharedShellTransferError("the remote file chunk was not valid Base64");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) {
    throw new SharedShellTransferError("the remote file chunk was not canonical Base64");
  }
  return decoded;
}

function powershellUtf8Expression(value: string): string {
  const encoded = Buffer.from(value, "utf8").toString("base64");
  return `[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'))`;
}

function quotePosixLiteral(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function validateTarget(target: SharedShellTransferTarget): void {
  if (target.sshAlias.length === 0) {
    throw new TypeError("shared-shell transfer target alias is required");
  }
}

function validateRemotePath(remotePath: string): void {
  if (remotePath.length === 0 || /[\0\r\n]/u.test(remotePath)) {
    throw new TypeError("shared-shell transfer remote path is invalid");
  }
}
