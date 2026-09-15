import {
  constants as fsConstants,
  type Stats,
} from "node:fs";
import {
  chmod,
  copyFile,
  link,
  lstat,
  open,
  opendir,
  readFile,
  readdir,
  rename,
  unlink,
  writeFile,
} from "node:fs/promises";
import { createHash, randomBytes } from "node:crypto";
import path from "node:path";

import type { SshRunner } from "../infra/ssh-runner.js";
import type { AuditWriter } from "../infra/audit-writer.js";
import {
  SftpExecutionError,
  type SftpExecutor,
  type SftpOutcome,
} from "../infra/sftp-executor.js";
import {
  SHARED_SHELL_TRANSFER_CHUNK_BYTES,
  SharedShellTransferError,
  SharedShellTransferExecutor,
} from "../infra/shared-shell-transfer.js";
import { GATEWAY_ERROR_CODES, GatewayError } from "../shared/errors.js";
import type {
  DownloadParams,
  SyncParams,
  TaskStartResult,
  UploadParams,
} from "../shared/protocol.js";
import { prepareStructuredRemoteCommand } from "./remote-command.js";
import {
  TaskStore,
  type TaskCompletion,
  type TaskWorkerContext,
} from "./task-store.js";
import {
  TransferPathError,
  MAX_TRANSFER_PATH_BYTES,
  buildSftpBatch,
  normalizeLocalTransferRelativePath,
  normalizeRemoteTransferPath,
  quoteSftpBatchPath,
  resolveLocalTransferDestination,
  resolveLocalTransferSource,
  splitUnrestrictedLocalTransferPath,
} from "./transfer-paths.js";
import {
  type TargetRegistry,
  type TransferAuthorization,
} from "./target-registry.js";

export interface TransferServiceGeneration {
  readonly registry: TargetRegistry;
  readonly sftp: SftpExecutor;
  readonly ssh: SshRunner;
}

export interface TransferServiceOptions extends TransferServiceGeneration {
  readonly taskStore: TaskStore;
  readonly spoolDirectory: string;
  readonly audit: Pick<AuditWriter, "write">;
  readonly partialTtlMs?: number;
}

interface PreparedTransfer {
  readonly authorization: TransferAuthorization;
  readonly localRootPath: string;
  readonly localPath: string;
  readonly remotePath: string;
  readonly remoteRoot: string;
  readonly generation: TransferServiceGeneration;
}

interface SyncFile {
  readonly relativePath: string;
  readonly absolutePath: string;
  readonly size: number;
}

interface RemoteFingerprint {
  readonly size: number;
  readonly sha256: string;
}

interface EnumerationLimits {
  readonly maxFiles: number;
  readonly maxFileBytes: number;
  readonly maxTotalBytes: number;
}

interface ExcludeMatcher {
  readonly tokenCount: number;
  matches(relativePath: string): boolean;
}

interface DownloadBinding {
  readonly target: string;
  readonly localRoot: string;
  readonly localPath: string;
  readonly remotePath: string;
  readonly remoteSize: number;
  readonly remoteSha256: string;
}

interface DownloadSpoolLease {
  readonly partPath: string;
  readonly resumed: boolean;
  restart(): Promise<void>;
  release(retainPartial: boolean): Promise<void>;
}

const DEFAULT_PARTIAL_TTL_MS = 24 * 60 * 60 * 1_000;
const DOWNLOAD_METADATA_VERSION = 2;
const DOWNLOAD_PART_PATTERN = /^([a-f0-9]{64})\.download\.part$/u;
const DOWNLOAD_METADATA_PATTERN = /^([a-f0-9]{64})\.download\.json$/u;
const MAX_TOTAL_EXCLUDE_TOKENS = 1_024;
const REMOTE_PATH_MISSING_EXIT_CODE = 10;
const REMOTE_PATH_UNSAFE_EXIT_CODE = 11;
const REMOTE_PATH_ERROR_EXIT_CODE = 12;
const REMOTE_PATH_SAFE_TOKEN = "SAFE";
const REMOTE_PATH_MISSING_TOKEN = "MISSING";
const REMOTE_PATH_UNSAFE_TOKEN = "UNSAFE";
const REMOTE_PATH_ERROR_TOKEN = "ERROR";

const POSIX_REMOTE_ANCESTOR_PROBE = [
  "set -uf",
  "set -o pipefail",
  "unset BASH_ENV ENV CDPATH",
  "export LC_ALL=C",
  "export PATH=/usr/bin:/bin",
  "exec 2>/dev/null",
  "agentSshModeOf() {",
  '  if [ "$AGENT_SSH_TRANSFER_PLATFORM" = macos ]; then',
  '    command stat -f \'%p\' "$1"',
  "  else",
  '    command stat -c \'%f\' -- "$1"',
  "  fi",
  "}",
  "agentSshCheckEntry() {",
  '  local agentSshProbeEntry="$1"',
  '  local agentSshProbeParent="$2"',
  '  local agentSshProbeNeedDirectory="$3"',
  '  local agentSshProbeIsRoot="$4"',
  "  local agentSshProbeMode",
  "  local agentSshProbeType",
  '  if agentSshProbeMode=$(agentSshModeOf "$agentSshProbeEntry"); then',
  '    if [ "$AGENT_SSH_TRANSFER_PLATFORM" = macos ]; then',
  '      [[ $agentSshProbeMode =~ ^[0-7]{1,8}$ ]] || return 12',
  "      agentSshProbeType=$((8#$agentSshProbeMode & 0170000))",
  "      if [ \"$agentSshProbeType\" -eq 40960 ]; then return 11; fi",
  '      if [ "$agentSshProbeNeedDirectory" -eq 1 ] && [ "$agentSshProbeType" -ne 16384 ]; then return 12; fi',
  "    else",
  '      [[ $agentSshProbeMode =~ ^[0-9A-Fa-f]{1,8}$ ]] || return 12',
  "      agentSshProbeType=$((16#$agentSshProbeMode & 0xf000))",
  "      if [ \"$agentSshProbeType\" -eq 40960 ]; then return 11; fi",
  '      if [ "$agentSshProbeNeedDirectory" -eq 1 ] && [ "$agentSshProbeType" -ne 16384 ]; then return 12; fi',
  "    fi",
  '    if [ "$agentSshProbeNeedDirectory" -eq 0 ] && [ "$agentSshProbeType" -ne 32768 ]; then return 12; fi',
  '    if [ "$agentSshProbeNeedDirectory" -eq 1 ] && [ ! -x "$agentSshProbeEntry" ]; then return 12; fi',
  "    return 0",
  "  fi",
  '  if [ -L "$agentSshProbeEntry" ] || [ -e "$agentSshProbeEntry" ]; then return 12; fi',
  '  if [ "$agentSshProbeIsRoot" -eq 1 ]; then return 12; fi',
  '  if [ ! -d "$agentSshProbeParent" ] || [ -L "$agentSshProbeParent" ] || [ ! -x "$agentSshProbeParent" ]; then return 12; fi',
  "  return 10",
  "}",
  "agentSshCheckPath() {",
  '  local agentSshProbePath="$1"',
  "  local agentSshProbeRemainder",
  "  local agentSshProbeSegment",
  "  local agentSshProbeCurrent=",
  "  local agentSshProbeParent=/",
  "  local agentSshProbeNeedDirectory",
  "  local agentSshProbeStatus",
  '  case "$agentSshProbePath" in /) ;; /*) case "$agentSshProbePath" in */|*//*) return 12 ;; esac ;; *) return 12 ;; esac',
  '  agentSshProbeRemainder=${agentSshProbePath#/}',
  '  if [ -n "$agentSshProbeRemainder" ]; then agentSshProbeNeedDirectory=1; else agentSshProbeNeedDirectory=0; fi',
  '  agentSshCheckEntry / / "$agentSshProbeNeedDirectory" 1',
  "  agentSshProbeStatus=$?",
  '  if [ "$agentSshProbeStatus" -ne 0 ]; then return "$agentSshProbeStatus"; fi',
  '  while [ -n "$agentSshProbeRemainder" ]; do',
  '    case "$agentSshProbeRemainder" in',
  '      */*) agentSshProbeSegment=${agentSshProbeRemainder%%/*}; agentSshProbeRemainder=${agentSshProbeRemainder#*/}; agentSshProbeNeedDirectory=1 ;;',
  '      *) agentSshProbeSegment=$agentSshProbeRemainder; agentSshProbeRemainder=; agentSshProbeNeedDirectory=0 ;;',
  "    esac",
  '    if [ -z "$agentSshProbeSegment" ] || [ "$agentSshProbeSegment" = . ] || [ "$agentSshProbeSegment" = .. ]; then return 12; fi',
  '    if [ "$agentSshProbeParent" = / ]; then',
  '      agentSshProbeCurrent=/$agentSshProbeSegment',
  "    else",
  '      agentSshProbeCurrent=$agentSshProbeParent/$agentSshProbeSegment',
  "    fi",
  '    agentSshCheckEntry "$agentSshProbeCurrent" "$agentSshProbeParent" "$agentSshProbeNeedDirectory" 0',
  "    agentSshProbeStatus=$?",
  '    if [ "$agentSshProbeStatus" -ne 0 ]; then return "$agentSshProbeStatus"; fi',
  "    agentSshProbeParent=$agentSshProbeCurrent",
  "  done",
  "  return 0",
  "}",
].join("\n");

const WINDOWS_REMOTE_ANCESTOR_PROBE = [
  "Set-StrictMode -Version 3.0",
  "$ErrorActionPreference='Stop'",
  "$ProgressPreference='SilentlyContinue'",
  "function Get-AgentSshPathProbeStatus {",
  "  param([string]$agentSshProbePath)",
  "  if([string]::IsNullOrWhiteSpace($agentSshProbePath)){return 12}",
  "  try{",
  "    $agentSshProbeMatch=[regex]::Match($agentSshProbePath,'\\A([A-Za-z]):/(.*)\\z')",
  "    if(-not $agentSshProbeMatch.Success){return 12}",
  "    $agentSshProbeRemainder=$agentSshProbeMatch.Groups[2].Value",
  "    $agentSshProbeSegments=if($agentSshProbeRemainder.Length -eq 0){@()}else{@($agentSshProbeRemainder.Split([char[]]@('/'),[System.StringSplitOptions]::None))}",
  "    foreach($agentSshProbeSegment in $agentSshProbeSegments){",
  "      if($agentSshProbeSegment.Length -eq 0 -or $agentSshProbeSegment -eq '.' -or $agentSshProbeSegment -eq '..' -or $agentSshProbeSegment -match '[\\\\/:*?\"<>|\\x00-\\x1f]' -or $agentSshProbeSegment.EndsWith('.') -or $agentSshProbeSegment.EndsWith(' ')){return 12}",
  "    }",
  "    $agentSshProbeCurrent=$agentSshProbeMatch.Groups[1].Value.ToUpperInvariant()+':\\'",
  "    try{$agentSshProbeItem=Microsoft.PowerShell.Management\\Get-Item -LiteralPath $agentSshProbeCurrent -Force -ErrorAction Stop}",
  "    catch{return 12}",
  "    if($agentSshProbeItem -isnot [System.IO.FileSystemInfo]){return 12}",
  "    if(($agentSshProbeItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0){return 11}",
  "    if($agentSshProbeSegments.Count -gt 0 -and -not $agentSshProbeItem.PSIsContainer){return 12}",
  "    for($agentSshProbeIndex=0;$agentSshProbeIndex -lt $agentSshProbeSegments.Count;$agentSshProbeIndex++){",
  "      $agentSshProbeSegment=$agentSshProbeSegments[$agentSshProbeIndex]",
  "      if(-not $agentSshProbeItem.PSIsContainer){return 12}",
  "      $agentSshProbeCurrent=[System.IO.Path]::Combine($agentSshProbeCurrent,$agentSshProbeSegment)",
  "      try{$agentSshProbeItem=Microsoft.PowerShell.Management\\Get-Item -LiteralPath $agentSshProbeCurrent -Force -ErrorAction Stop}",
  "      catch [System.Management.Automation.ItemNotFoundException]{return 10}",
  "      catch [System.IO.FileNotFoundException]{return 10}",
  "      catch [System.IO.DirectoryNotFoundException]{return 10}",
  "      catch{return 12}",
  "      if($agentSshProbeItem -isnot [System.IO.FileSystemInfo]){return 12}",
  "      if(($agentSshProbeItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0){return 11}",
  "      if($agentSshProbeIndex -lt ($agentSshProbeSegments.Count-1) -and -not $agentSshProbeItem.PSIsContainer){return 12}",
  "    }",
  "    if($agentSshProbeItem -isnot [System.IO.FileInfo]){return 12}",
  "    return 0",
  "  }catch{return 12}",
  "}",
].join("\n");

export class TransferService {
  #generation: TransferServiceGeneration;
  readonly #tasks: TaskStore;
  readonly #spoolDirectory: string;
  readonly #audit: Pick<AuditWriter, "write">;
  readonly #spoolReady: Promise<void>;
  #spoolInitializationError: unknown;

  public constructor(options: TransferServiceOptions) {
    this.#generation = freezeGeneration(options);
    this.#tasks = options.taskStore;
    this.#spoolDirectory = options.spoolDirectory;
    this.#audit = options.audit;
    this.#spoolReady = prepareTransferSpool(
      options.spoolDirectory,
      options.partialTtlMs ?? DEFAULT_PARTIAL_TTL_MS,
    ).catch((error: unknown) => {
      this.#spoolInitializationError = error;
    });
  }

  public replaceGeneration(generation: TransferServiceGeneration): void {
    this.#generation = freezeGeneration(generation);
  }

  public replaceMetadataRegistry(registry: TargetRegistry): void {
    this.#generation = freezeGeneration({ ...this.#generation, registry });
  }

  public startUpload(params: UploadParams): TaskStartResult {
    const prepared = this.#prepare(
      params.target,
      "upload",
      params.localRoot,
      params.localPath,
      params.remotePath,
      params.timeoutMs,
    );
    return this.#tasks.start({
      kind: "upload",
      target: params.target,
      timeoutMs: prepared.authorization.timeoutMs,
      worker: (context) =>
        this.#runAuditedTransfer(context, "upload", params.dryRun, () =>
          this.#upload(context, params, prepared),
        ),
    });
  }

  public startDownload(params: DownloadParams): TaskStartResult {
    const prepared = this.#prepare(
      params.target,
      "download",
      params.localRoot,
      params.localPath,
      params.remotePath,
      params.timeoutMs,
    );
    return this.#tasks.start({
      kind: "download",
      target: params.target,
      timeoutMs: prepared.authorization.timeoutMs,
      worker: (context) =>
        this.#runAuditedTransfer(context, "download", params.dryRun, () =>
          this.#download(context, params, prepared),
        ),
    });
  }

  public startSync(params: SyncParams): TaskStartResult {
    const prepared = this.#prepare(
      params.target,
      "sync",
      params.localRoot,
      params.localPath,
      params.remotePath,
      params.timeoutMs,
    );
    return this.#tasks.start({
      kind: "sync",
      target: params.target,
      timeoutMs: prepared.authorization.timeoutMs,
      worker: (context) =>
        this.#runAuditedTransfer(context, "sync", params.dryRun, () =>
          this.#sync(context, params, prepared),
        ),
    });
  }

  #prepare(
    target: string,
    direction: "upload" | "download" | "sync",
    localRoot: string | undefined,
    localInput: string,
    remoteInput: string,
    timeoutMs: number | undefined,
  ): PreparedTransfer {
    const generation = this.#generation;
    const authorization = generation.registry.authorizeTransfer(
      target,
      direction,
      localRoot,
      timeoutMs,
    );
    let localRootPath: string;
    let localPath: string;
    let remotePath: string;
    let allowedRoots: string[];
    try {
      if (
        authorization.scope === "all" &&
        authorization.localRootPath === undefined
      ) {
        const unrestricted = splitUnrestrictedLocalTransferPath(localInput);
        localRootPath = unrestricted.rootPath;
        localPath = unrestricted.relativePath;
      } else {
        if (authorization.localRootPath === undefined) {
          throw new TransferPathError(
            "INVALID_PATH",
            "A configured local root is required for restricted transfer",
          );
        }
        localRootPath = authorization.localRootPath;
        localPath = normalizeLocalTransferRelativePath(localInput);
      }
      remotePath = normalizeRemoteTransferPath(
        authorization.target.platform,
        remoteInput,
      );
      allowedRoots =
        authorization.scope === "all"
          ? [remoteFilesystemRoot(authorization.target.platform, remotePath)]
          : authorization.remoteRoots.map((root) =>
              normalizeRemoteTransferPath(authorization.target.platform, root),
            );
    } catch (error) {
      throw publicTransferPathError(error);
    }
    const remoteRoot = allowedRoots
      .filter((root) =>
        remotePathIsContained(authorization.target.platform, root, remotePath),
      )
      .sort((left, right) => right.length - left.length)[0];
    if (remoteRoot === undefined) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.transferDenied,
        "Remote transfer path is outside the target's approved roots",
        { details: { target } },
      );
    }
    return {
      authorization,
      localRootPath,
      localPath,
      remotePath,
      remoteRoot,
      generation,
    };
  }

  async #runAuditedTransfer(
    context: TaskWorkerContext,
    direction: "upload" | "download" | "sync",
    dryRun: boolean,
    worker: () => Promise<TaskCompletion>,
  ): Promise<TaskCompletion> {
    await this.#audit.write({
      event: "transfer.started",
      runId: context.runId,
      target: this.#tasks.status(context.runId).target,
      direction,
      dryRun,
    });
    try {
      const completion = await worker();
      await this.#audit.write({
        event: "transfer.completed",
        runId: context.runId,
        target: this.#tasks.status(context.runId).target,
        direction,
        files: resultMetric(completion.result, "files"),
        bytes: resultMetric(completion.result, "bytes"),
      });
      return completion;
    } catch (error) {
      await this.#audit.write({
        event: "transfer.failed",
        runId: context.runId,
        target: this.#tasks.status(context.runId).target,
        direction,
        reasonCode: transferAuditReason(error, context.signal),
      });
      throw error;
    }
  }

  async #requireSpool(): Promise<void> {
    await this.#spoolReady;
    if (this.#spoolInitializationError !== undefined) {
      throw this.#spoolInitializationError;
    }
  }

  async #upload(
    context: TaskWorkerContext,
    params: UploadParams,
    prepared: PreparedTransfer,
  ) {
    await this.#requireSpool();
    context.append("stdout", "Validating local source and checksum...\n");
    const source = await resolveLocalTransferSource(
      prepared.localRootPath,
      prepared.localPath,
      "file",
    ).catch(rethrowTransferPath);
    enforceFileQuota(prepared.authorization, source.size ?? 0);
    if (params.dryRun) {
      const fingerprint = await fingerprintLocalSource(
        source.absolutePath,
        context.signal,
      );
      enforceFileQuota(prepared.authorization, fingerprint.size);
      if (
        params.expectedSha256 !== undefined &&
        params.expectedSha256.toLowerCase() !== fingerprint.sha256
      ) {
        throw checksumError("Local source checksum does not match expectedSha256");
      }
      context.append("stdout", "Dry run complete; no remote data was changed.\n");
      return {
        result: {
          dryRun: true,
          files: 1,
          bytes: fingerprint.size,
          sha256: fingerprint.sha256,
        },
      };
    }
    const staged = await stageLocalSource(
      source.absolutePath,
      this.#spoolDirectory,
      context.signal,
    );
    try {
      enforceFileQuota(prepared.authorization, staged.size);
      if (
        params.expectedSha256 !== undefined &&
        params.expectedSha256.toLowerCase() !== staged.sha256
      ) {
        throw checksumError("Local source checksum does not match expectedSha256");
      }
      await this.#uploadFile(
        context,
        prepared,
        staged.path,
        prepared.remotePath,
        staged.size,
        staged.sha256,
        params.overwrite,
        params.resume,
      );
      context.append("stdout", "Upload verified and published.\n");
      return {
        result: {
          dryRun: false,
          files: 1,
          bytes: staged.size,
          sha256: staged.sha256,
        },
      };
    } finally {
      await unlink(staged.path).catch(() => undefined);
    }
  }

  async #download(
    context: TaskWorkerContext,
    params: DownloadParams,
    prepared: PreparedTransfer,
  ) {
    await this.#requireSpool();
    context.append("stdout", "Resolving remote fingerprint...\n");
    const remoteFingerprint = await readRemoteFingerprint(
      prepared.generation.ssh,
      prepared.authorization,
      prepared.remotePath,
      context.signal,
    );
    if (remoteFingerprint === undefined) {
      throw transferFailure("Remote source was not found or could not be read");
    }
    enforceFileQuota(prepared.authorization, remoteFingerprint.size);
    if (
      params.expectedSha256 !== undefined &&
      params.expectedSha256.toLowerCase() !== remoteFingerprint.sha256
    ) {
      throw checksumError("Remote source checksum does not match expectedSha256");
    }

    const relativePath = prepared.localPath;
    const parentRelative = path.posix.dirname(relativePath);
    await resolveLocalTransferSource(
      prepared.localRootPath,
      parentRelative,
      "directory",
    ).catch(rethrowTransferPath);
    const destination = await resolveLocalTransferDestination(
      prepared.localRootPath,
      relativePath,
      "file",
    ).catch(rethrowTransferPath);
    if (destination.exists && !params.overwrite) {
      throw transferFailure("Local destination already exists");
    }
    if (params.dryRun) {
      context.append("stdout", "Dry run complete; no local data was changed.\n");
      return {
        result: {
          dryRun: true,
          files: 1,
          bytes: remoteFingerprint.size,
          sha256: remoteFingerprint.sha256,
        },
      };
    }

    const spool = await acquireDownloadSpool({
      spoolDirectory: this.#spoolDirectory,
      binding: {
        target: params.target,
        localRoot: params.localRoot ?? prepared.localRootPath,
        localPath: relativePath,
        remotePath: prepared.remotePath,
        remoteSize: remoteFingerprint.size,
        remoteSha256: remoteFingerprint.sha256,
      },
      resume: params.resume,
      maximumBytes: Math.min(
        prepared.authorization.maxFileBytes,
        prepared.authorization.maxTotalBytes,
      ),
    });
    let preservePartial = params.resume;
    try {
      if (usesSharedShellTransfer(prepared)) {
        await downloadThroughSharedShell(
          prepared,
          prepared.remotePath,
          spool.partPath,
          remoteFingerprint.size,
          spool.resumed,
          context.signal,
        );
      } else {
        await runSftp(
          prepared,
          buildSftpBatch([
            {
              operation: spool.resumed ? "reget" : "get",
              remotePath: prepared.remotePath,
              localPath: spool.partPath,
            },
          ]),
          context.signal,
        );
      }
      await chmod(spool.partPath, 0o600).catch(() => undefined);
      let localFingerprint = await fingerprintLocalSource(
        spool.partPath,
        context.signal,
      );
      if (!fingerprintsMatch(localFingerprint, remoteFingerprint) && spool.resumed) {
        await spool.restart();
        if (usesSharedShellTransfer(prepared)) {
          await downloadThroughSharedShell(
            prepared,
            prepared.remotePath,
            spool.partPath,
            remoteFingerprint.size,
            false,
            context.signal,
          );
        } else {
          await runSftp(
            prepared,
            buildSftpBatch([
              {
                operation: "get",
                remotePath: prepared.remotePath,
                localPath: spool.partPath,
              },
            ]),
            context.signal,
          );
        }
        await chmod(spool.partPath, 0o600).catch(() => undefined);
        localFingerprint = await fingerprintLocalSource(
          spool.partPath,
          context.signal,
        );
      }
      if (!fingerprintsMatch(localFingerprint, remoteFingerprint)) {
        preservePartial = false;
        throw checksumError("Downloaded file failed fingerprint verification");
      }
      await publishDownloadedFile(
        spool.partPath,
        destination.absolutePath,
        params.overwrite,
        context.signal,
      );
      preservePartial = false;
      context.append("stdout", "Download verified and published.\n");
      return {
        result: {
          dryRun: false,
          files: 1,
          bytes: localFingerprint.size,
          sha256: localFingerprint.sha256,
        },
      };
    } finally {
      await spool.release(preservePartial);
    }
  }

  async #sync(
    context: TaskWorkerContext,
    params: SyncParams,
    prepared: PreparedTransfer,
  ) {
    await this.#requireSpool();
    context.append("stdout", "Scanning local directory...\n");
    const source = await resolveLocalTransferSource(
      prepared.localRootPath,
      prepared.localPath,
      "directory",
    ).catch(rethrowTransferPath);
    const excludeMatchers = compileExcludePatterns(params.exclude);
    const { files, totalBytes } = await enumerateFiles(
      source.absolutePath,
      excludeMatchers,
      {
        maxFiles: prepared.authorization.maxFiles,
        maxFileBytes: prepared.authorization.maxFileBytes,
        maxTotalBytes: prepared.authorization.maxTotalBytes,
      },
      context.signal,
    );
    if (params.dryRun) {
      context.append("stdout", "Dry run complete; no remote data was changed.\n");
      return {
        result: {
          dryRun: true,
          files: files.length,
          bytes: totalBytes,
          uploaded: 0,
          skipped: 0,
        },
      };
    }

    let uploaded = 0;
    let skipped = 0;
    let stagedBytes = 0;
    for (const [index, file] of files.entries()) {
      context.signal.throwIfAborted();
      context.append(
        "stdout",
        `Checking file ${index + 1}/${files.length}...\n`,
      );
      const remotePath = joinRemotePath(prepared.remotePath, file.relativePath);
      const staged = await stageLocalSource(
        file.absolutePath,
        this.#spoolDirectory,
        context.signal,
      );
      try {
        enforceFileQuota(prepared.authorization, staged.size);
        if (
          !Number.isSafeInteger(stagedBytes) ||
          stagedBytes > prepared.authorization.maxTotalBytes - staged.size
        ) {
          throw transferFailure("Directory sync exceeds the configured transfer quota");
        }
        stagedBytes += staged.size;
        if (params.verifyExisting) {
          const existingFingerprint = await readRemoteFingerprint(
            prepared.generation.ssh,
            prepared.authorization,
            remotePath,
            context.signal,
          );
          if (
            existingFingerprint !== undefined &&
            existingFingerprint.size === staged.size &&
            existingFingerprint.sha256 === staged.sha256
          ) {
            skipped += 1;
            continue;
          }
        }
        await this.#uploadFile(
          context,
          prepared,
          staged.path,
          remotePath,
          staged.size,
          staged.sha256,
          params.overwrite,
          params.resume,
        );
        uploaded += 1;
      } finally {
        await unlink(staged.path).catch(() => undefined);
      }
    }
    context.append("stdout", "Directory sync completed.\n");
    return {
      result: {
        dryRun: false,
        files: files.length,
        bytes: totalBytes,
        uploaded,
        skipped,
      },
    };
  }

  async #uploadFile(
    context: TaskWorkerContext,
    prepared: PreparedTransfer,
    localPath: string,
    remotePath: string,
    size: number,
    sha256: string,
    overwrite: boolean,
    resume: boolean,
  ): Promise<void> {
    const partPath = `${remotePath}.agent-ssh-${sha256.slice(0, 16)}.part`;
    if (
      !remotePathIsContained(
        prepared.authorization.target.platform,
        prepared.remoteRoot,
        partPath,
      )
    ) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.transferDenied,
        "Remote transfer staging path is outside the target's approved roots",
      );
    }
    if (usesSharedShellTransfer(prepared)) {
      await this.#uploadFileThroughSharedShell(
        context,
        prepared,
        localPath,
        remotePath,
        partPath,
        size,
        sha256,
        overwrite,
        resume,
      );
      return;
    }
    await assertRemoteUploadPathsSafe(
      prepared,
      remotePath,
      partPath,
      context.signal,
    );
    if (!overwrite && (await remoteExists(prepared, remotePath, context.signal))) {
      throw transferFailure("Remote destination already exists");
    }
    await ensureRemoteParents(prepared, remotePath, context.signal);
    const resumed = resume && (await remoteExists(prepared, partPath, context.signal));
    try {
      await runSftp(
        prepared,
        buildSftpBatch([
          {
            operation: resumed ? "reput" : "put",
            localPath,
            remotePath: partPath,
          },
        ]),
        context.signal,
      );
      let transferredFingerprint = await readRemoteFingerprint(
        prepared.generation.ssh,
        prepared.authorization,
        partPath,
        context.signal,
      );
      if (
        !fingerprintsMatch(
          transferredFingerprint,
          { size, sha256 },
        ) &&
        resumed
      ) {
        await removeRemotePartial(prepared, partPath, context.signal);
        await runSftp(
          prepared,
          buildSftpBatch([{ operation: "put", localPath, remotePath: partPath }]),
          context.signal,
        );
        transferredFingerprint = await readRemoteFingerprint(
          prepared.generation.ssh,
          prepared.authorization,
          partPath,
          context.signal,
        );
      }
      if (!fingerprintsMatch(transferredFingerprint, { size, sha256 })) {
        await removeRemotePartial(prepared, partPath, context.signal);
        throw checksumError("Uploaded file failed fingerprint verification");
      }
      if (overwrite) {
        await runSftp(
          prepared,
          buildSftpBatch([
            { operation: "rm", remotePath, ignoreFailure: true },
            {
              operation: "rename",
              sourceRemotePath: partPath,
              destinationRemotePath: remotePath,
            },
          ]),
          context.signal,
        );
      } else {
        await publishRemoteExclusive(
          prepared,
          partPath,
          remotePath,
          context.signal,
        );
      }
    } catch (error) {
      if (!resume && !context.signal.aborted) {
        await removeRemotePartial(prepared, partPath, context.signal).catch(
          () => undefined,
        );
      }
      throw error;
    }
  }

  async #uploadFileThroughSharedShell(
    context: TaskWorkerContext,
    prepared: PreparedTransfer,
    localPath: string,
    remotePath: string,
    partPath: string,
    size: number,
    sha256: string,
    overwrite: boolean,
    resume: boolean,
  ): Promise<void> {
    const executor = new SharedShellTransferExecutor(prepared.generation.ssh);
    const target = sharedShellTarget(prepared);
    await assertRemoteUploadPathsSafe(
      prepared,
      remotePath,
      partPath,
      context.signal,
    );
    if (
      !overwrite &&
      (await readRemoteFingerprint(
        prepared.generation.ssh,
        prepared.authorization,
        remotePath,
        context.signal,
      )) !== undefined
    ) {
      throw transferFailure("Remote destination already exists");
    }
    await ensureRemoteParents(prepared, remotePath, context.signal);

    let resumeOffset = 0;
    let resumed = false;
    if (resume) {
      const partialFingerprint = await readRemoteFingerprint(
        prepared.generation.ssh,
        prepared.authorization,
        partPath,
        context.signal,
      );
      if (partialFingerprint !== undefined && partialFingerprint.size <= size) {
        resumeOffset = partialFingerprint.size;
        resumed = true;
      } else if (partialFingerprint !== undefined) {
        await runSharedShellOperation("remove oversized remote partial file", () =>
          executor.removeFile(target, partPath, context.signal),
        );
      }
    }

    try {
      await uploadThroughSharedShell(
        executor,
        target,
        localPath,
        partPath,
        size,
        resumeOffset,
        context.signal,
      );
      let transferredFingerprint = await readRemoteFingerprint(
        prepared.generation.ssh,
        prepared.authorization,
        partPath,
        context.signal,
      );
      if (!fingerprintsMatch(transferredFingerprint, { size, sha256 }) && resumed) {
        await runSharedShellOperation("remove invalid remote partial file", () =>
          executor.removeFile(target, partPath, context.signal),
        );
        await uploadThroughSharedShell(
          executor,
          target,
          localPath,
          partPath,
          size,
          0,
          context.signal,
        );
        transferredFingerprint = await readRemoteFingerprint(
          prepared.generation.ssh,
          prepared.authorization,
          partPath,
          context.signal,
        );
      }
      if (!fingerprintsMatch(transferredFingerprint, { size, sha256 })) {
        await runSharedShellOperation("remove invalid remote partial file", () =>
          executor.removeFile(target, partPath, context.signal),
        );
        throw checksumError("Uploaded file failed fingerprint verification");
      }
      if (overwrite) {
        await runSharedShellOperation("publish remote file", () =>
          executor.replaceFile(target, partPath, remotePath, context.signal),
        );
      } else {
        await publishRemoteExclusive(
          prepared,
          partPath,
          remotePath,
          context.signal,
        );
      }
    } catch (error) {
      if (!resume && !context.signal.aborted) {
        await runSharedShellOperation("remove remote partial file", () =>
          executor.removeFile(target, partPath, context.signal),
        ).catch(() => undefined);
      }
      throw error;
    }
  }
}

function freezeGeneration(
  generation: TransferServiceGeneration,
): TransferServiceGeneration {
  return Object.freeze({
    registry: generation.registry,
    sftp: generation.sftp,
    ssh: generation.ssh,
  });
}

function usesSharedShellTransfer(prepared: PreparedTransfer): boolean {
  return prepared.authorization.target.connectionMode === "accessclient-share";
}

function sharedShellTarget(prepared: PreparedTransfer) {
  return Object.freeze({
    sshAlias: prepared.authorization.target.sshAlias,
    platform: prepared.authorization.target.platform,
  });
}

async function runSharedShellOperation<Result>(
  operation: string,
  worker: () => Promise<Result>,
): Promise<Result> {
  try {
    return await worker();
  } catch (error) {
    if (error instanceof SharedShellTransferError) {
      throw transferFailure(`Shared AccessClient session could not ${operation}`, error);
    }
    throw error;
  }
}

async function uploadThroughSharedShell(
  executor: SharedShellTransferExecutor,
  target: ReturnType<typeof sharedShellTarget>,
  localPath: string,
  remotePath: string,
  size: number,
  offset: number,
  signal: AbortSignal,
): Promise<void> {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > size) {
    throw transferFailure("Remote partial file has an invalid size");
  }
  const source = await open(localPath, "r");
  try {
    if (size === 0) {
      await runSharedShellOperation("write empty remote file", () =>
        executor.write({
          target,
          remotePath,
          bytes: Buffer.alloc(0),
          truncate: true,
          signal,
        }),
      );
      return;
    }
    let position = offset;
    const buffer = Buffer.allocUnsafe(SHARED_SHELL_TRANSFER_CHUNK_BYTES);
    while (position < size) {
      signal.throwIfAborted();
      const requested = Math.min(buffer.length, size - position);
      const { bytesRead } = await source.read(buffer, 0, requested, position);
      if (bytesRead === 0) {
        throw transferFailure("Local transfer staging file ended unexpectedly");
      }
      await runSharedShellOperation("write remote file chunk", () =>
        executor.write({
          target,
          remotePath,
          bytes: buffer.subarray(0, bytesRead),
          truncate: position === 0,
          signal,
        }),
      );
      position += bytesRead;
    }
  } finally {
    await source.close().catch(() => undefined);
  }
}

async function downloadThroughSharedShell(
  prepared: PreparedTransfer,
  remotePath: string,
  localPath: string,
  size: number,
  resume: boolean,
  signal: AbortSignal,
): Promise<void> {
  const executor = new SharedShellTransferExecutor(prepared.generation.ssh);
  const target = sharedShellTarget(prepared);
  let offset = 0;
  let partialExists = false;
  if (resume) {
    const partial = await optionalSafeSpoolFile(localPath);
    if (partial !== undefined && partial.size <= size) {
      offset = partial.size;
      partialExists = true;
    } else if (partial !== undefined) {
      await removeSafeSpoolFile(localPath);
    }
  }
  const destination = await open(localPath, partialExists ? "r+" : "wx");
  try {
    while (offset < size) {
      signal.throwIfAborted();
      const length = Math.min(SHARED_SHELL_TRANSFER_CHUNK_BYTES, size - offset);
      const bytes = await runSharedShellOperation("read remote file chunk", () =>
        executor.read({ target, remotePath, offset, length, signal }),
      );
      let written = 0;
      while (written < bytes.length) {
        const result = await destination.write(
          bytes,
          written,
          bytes.length - written,
          offset + written,
        );
        written += result.bytesWritten;
      }
      offset += bytes.length;
    }
    await destination.sync();
  } finally {
    await destination.close().catch(() => undefined);
  }
}

async function runSftp(
  prepared: PreparedTransfer,
  batch: Uint8Array,
  signal: AbortSignal,
): Promise<SftpOutcome> {
  let outcome: SftpOutcome;
  try {
    outcome = await prepared.generation.sftp.run({
      sshAlias: prepared.authorization.target.sshAlias,
      batch,
      signal,
      maxCapturedOutputBytes: 8_192,
    });
  } catch (error) {
    if (error instanceof SftpExecutionError) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.sftpUnavailable,
        "SFTP could not be started for this target",
        { cause: error },
      );
    }
    throw error;
  }
  if (outcome.aborted) {
    throw transferFailure("SFTP transfer was stopped");
  }
  if (outcome.exitCode !== 0) {
    throw transferFailure("SFTP operation failed");
  }
  return outcome;
}

async function remoteExists(
  prepared: PreparedTransfer,
  remotePath: string,
  signal: AbortSignal,
): Promise<boolean> {
  const batch = Buffer.from(
    `@ls ${quoteSftpBatchPath(remotePath)}\n@quit\n`,
    "utf8",
  );
  try {
    const outcome = await prepared.generation.sftp.run({
      sshAlias: prepared.authorization.target.sshAlias,
      batch,
      signal,
      maxCapturedOutputBytes: 4_096,
    });
    if (outcome.aborted) throw transferFailure("SFTP transfer was stopped");
    return outcome.exitCode === 0;
  } catch (error) {
    if (error instanceof SftpExecutionError) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.sftpUnavailable,
        "SFTP could not be started for this target",
        { cause: error },
      );
    }
    throw error;
  }
}

function remoteUploadPathProbeScript(
  platform: TransferAuthorization["target"]["platform"],
): string {
  if (platform === "windows") {
    return [
      WINDOWS_REMOTE_ANCESTOR_PROBE,
      "foreach($agentSshProbePath in @($env:AGENT_SSH_TRANSFER_DESTINATION,$env:AGENT_SSH_TRANSFER_PART)){",
      "  $agentSshProbeStatus=Get-AgentSshPathProbeStatus $agentSshProbePath",
      "  if($agentSshProbeStatus -eq 10){continue}",
      `  if($agentSshProbeStatus -eq ${REMOTE_PATH_UNSAFE_EXIT_CODE}){[Console]::Out.Write('${REMOTE_PATH_UNSAFE_TOKEN}');exit ${REMOTE_PATH_UNSAFE_EXIT_CODE}}`,
      `  if($agentSshProbeStatus -ne 0){[Console]::Out.Write('${REMOTE_PATH_ERROR_TOKEN}');exit ${REMOTE_PATH_ERROR_EXIT_CODE}}`,
      "}",
      `[Console]::Out.Write('${REMOTE_PATH_SAFE_TOKEN}')`,
    ].join("\n");
  }
  return [
    `AGENT_SSH_TRANSFER_PLATFORM=${platform}`,
    POSIX_REMOTE_ANCESTOR_PROBE,
    'for agentSshProbePath in "$AGENT_SSH_TRANSFER_DESTINATION" "$AGENT_SSH_TRANSFER_PART"; do',
    '  agentSshCheckPath "$agentSshProbePath"',
    "  agentSshProbeStatus=$?",
    '  case "$agentSshProbeStatus" in',
    "    0|10) ;;",
    `    ${REMOTE_PATH_UNSAFE_EXIT_CODE}) printf '%s' '${REMOTE_PATH_UNSAFE_TOKEN}'; exit ${REMOTE_PATH_UNSAFE_EXIT_CODE} ;;`,
    `    *) printf '%s' '${REMOTE_PATH_ERROR_TOKEN}'; exit ${REMOTE_PATH_ERROR_EXIT_CODE} ;;`,
    "  esac",
    "done",
    `printf '%s' '${REMOTE_PATH_SAFE_TOKEN}'`,
  ].join("\n");
}

function remoteFingerprintScript(
  platform: TransferAuthorization["target"]["platform"],
): string {
  if (platform === "windows") {
    return [
      WINDOWS_REMOTE_ANCESTOR_PROBE,
      "$agentSshProbeStatus=Get-AgentSshPathProbeStatus $env:AGENT_SSH_TRANSFER_PATH",
      `if($agentSshProbeStatus -eq ${REMOTE_PATH_MISSING_EXIT_CODE}){[Console]::Out.Write('${REMOTE_PATH_MISSING_TOKEN}');exit ${REMOTE_PATH_MISSING_EXIT_CODE}}`,
      `if($agentSshProbeStatus -eq ${REMOTE_PATH_UNSAFE_EXIT_CODE}){[Console]::Out.Write('${REMOTE_PATH_UNSAFE_TOKEN}');exit ${REMOTE_PATH_UNSAFE_EXIT_CODE}}`,
      `if($agentSshProbeStatus -ne 0){[Console]::Out.Write('${REMOTE_PATH_ERROR_TOKEN}');exit ${REMOTE_PATH_ERROR_EXIT_CODE}}`,
      "try{",
      "  $agentSshItem=Microsoft.PowerShell.Management\\Get-Item -LiteralPath $env:AGENT_SSH_TRANSFER_PATH -Force -ErrorAction Stop",
      `}catch [System.Management.Automation.ItemNotFoundException]{[Console]::Out.Write('${REMOTE_PATH_MISSING_TOKEN}');exit ${REMOTE_PATH_MISSING_EXIT_CODE}}`,
      `catch [System.IO.FileNotFoundException]{[Console]::Out.Write('${REMOTE_PATH_MISSING_TOKEN}');exit ${REMOTE_PATH_MISSING_EXIT_CODE}}`,
      `catch [System.IO.DirectoryNotFoundException]{[Console]::Out.Write('${REMOTE_PATH_MISSING_TOKEN}');exit ${REMOTE_PATH_MISSING_EXIT_CODE}}`,
      `catch{[Console]::Out.Write('${REMOTE_PATH_ERROR_TOKEN}');exit ${REMOTE_PATH_ERROR_EXIT_CODE}}`,
      `if($agentSshItem -isnot [System.IO.FileSystemInfo]){[Console]::Out.Write('${REMOTE_PATH_ERROR_TOKEN}');exit ${REMOTE_PATH_ERROR_EXIT_CODE}}`,
      `if(($agentSshItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0){[Console]::Out.Write('${REMOTE_PATH_UNSAFE_TOKEN}');exit ${REMOTE_PATH_UNSAFE_EXIT_CODE}}`,
      `if($agentSshItem.PSIsContainer){[Console]::Out.Write('${REMOTE_PATH_ERROR_TOKEN}');exit ${REMOTE_PATH_ERROR_EXIT_CODE}}`,
      "try{",
      "  $agentSshSize=([UInt64]$agentSshItem.Length).ToString([System.Globalization.CultureInfo]::InvariantCulture)",
      "  $agentSshHash=(Microsoft.PowerShell.Utility\\Get-FileHash -LiteralPath $env:AGENT_SSH_TRANSFER_PATH -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()",
      "  [Console]::Out.Write($agentSshSize+':'+$agentSshHash)",
      `}catch{[Console]::Out.Write('${REMOTE_PATH_ERROR_TOKEN}');exit ${REMOTE_PATH_ERROR_EXIT_CODE}}`,
    ].join("\n");
  }
  const sizeCommand =
    platform === "macos"
      ? "command stat -f '%z' \"$AGENT_SSH_TRANSFER_PATH\""
      : "command stat -c '%s' -- \"$AGENT_SSH_TRANSFER_PATH\"";
  const hashCommand =
    platform === "macos"
      ? 'command shasum -a 256 "$AGENT_SSH_TRANSFER_PATH"'
      : 'command sha256sum -- "$AGENT_SSH_TRANSFER_PATH"';
  return [
    `AGENT_SSH_TRANSFER_PLATFORM=${platform}`,
    POSIX_REMOTE_ANCESTOR_PROBE,
    'agentSshCheckPath "$AGENT_SSH_TRANSFER_PATH"',
    "agentSshProbeStatus=$?",
    'case "$agentSshProbeStatus" in',
    "  0) ;;",
    `  ${REMOTE_PATH_MISSING_EXIT_CODE}) printf '%s' '${REMOTE_PATH_MISSING_TOKEN}'; exit ${REMOTE_PATH_MISSING_EXIT_CODE} ;;`,
    `  ${REMOTE_PATH_UNSAFE_EXIT_CODE}) printf '%s' '${REMOTE_PATH_UNSAFE_TOKEN}'; exit ${REMOTE_PATH_UNSAFE_EXIT_CODE} ;;`,
    `  *) printf '%s' '${REMOTE_PATH_ERROR_TOKEN}'; exit ${REMOTE_PATH_ERROR_EXIT_CODE} ;;`,
    "esac",
    `if [ -L "$AGENT_SSH_TRANSFER_PATH" ]; then printf '%s' '${REMOTE_PATH_UNSAFE_TOKEN}'; exit ${REMOTE_PATH_UNSAFE_EXIT_CODE}; fi`,
    `if [ ! -f "$AGENT_SSH_TRANSFER_PATH" ]; then printf '%s' '${REMOTE_PATH_ERROR_TOKEN}'; exit ${REMOTE_PATH_ERROR_EXIT_CODE}; fi`,
    `if ! agentSshSize=$(${sizeCommand}); then printf '%s' '${REMOTE_PATH_ERROR_TOKEN}'; exit ${REMOTE_PATH_ERROR_EXIT_CODE}; fi`,
    `if ! agentSshHash=$(${hashCommand}); then printf '%s' '${REMOTE_PATH_ERROR_TOKEN}'; exit ${REMOTE_PATH_ERROR_EXIT_CODE}; fi`,
    "agentSshHash=${agentSshHash%% *}",
    "printf '%s:%s' \"$agentSshSize\" \"$agentSshHash\"",
  ].join("\n");
}

async function readRemoteFingerprint(
  ssh: SshRunner,
  authorization: TransferAuthorization,
  remotePath: string,
  signal: AbortSignal,
): Promise<RemoteFingerprint | undefined> {
  const platform = authorization.target.platform;
  const prepared = prepareStructuredRemoteCommand(platform, {
    shell: platform === "windows" ? "powershell" : "bash",
    env: { AGENT_SSH_TRANSFER_PATH: remotePath },
    encoding: "utf-8",
    script: remoteFingerprintScript(platform),
  });
  const outcome = await ssh.run({
    sshAlias: authorization.target.sshAlias,
    ...prepared,
    signal,
    maxCapturedOutputBytes: 256,
  });
  if (outcome.aborted) throw transferFailure("Transfer verification was stopped");
  if (
    outcome.stdoutTruncated ||
    outcome.stderrTruncated ||
    outcome.stderr.length !== 0
  ) {
    throw transferFailure("Remote fingerprint response was invalid");
  }
  if (
    outcome.exitCode === REMOTE_PATH_MISSING_EXIT_CODE &&
    outcome.stdout === REMOTE_PATH_MISSING_TOKEN
  ) {
    return undefined;
  }
  if (
    outcome.exitCode === REMOTE_PATH_UNSAFE_EXIT_CODE &&
    outcome.stdout === REMOTE_PATH_UNSAFE_TOKEN
  ) {
    throw unsafeRemotePathError();
  }
  if (outcome.exitCode !== 0) {
    throw transferFailure("Remote path inspection failed");
  }
  const match = /^(0|[1-9][0-9]{0,19}):([a-f0-9]{64})$/u.exec(
    outcome.stdout,
  );
  if (match?.[1] === undefined || match[2] === undefined) {
    throw transferFailure("Remote fingerprint response was invalid");
  }
  const size = Number(match[1]);
  if (!Number.isSafeInteger(size) || size < 0) {
    throw transferFailure("Remote fingerprint response was invalid");
  }
  return Object.freeze({ size, sha256: match[2] });
}

async function assertRemoteUploadPathsSafe(
  prepared: PreparedTransfer,
  remotePath: string,
  partPath: string,
  signal: AbortSignal,
): Promise<void> {
  const platform = prepared.authorization.target.platform;
  const command = prepareStructuredRemoteCommand(platform, {
    shell: platform === "windows" ? "powershell" : "bash",
    env: {
      AGENT_SSH_TRANSFER_DESTINATION: remotePath,
      AGENT_SSH_TRANSFER_PART: partPath,
    },
    encoding: "utf-8",
    script: remoteUploadPathProbeScript(platform),
  });
  const outcome = await prepared.generation.ssh.run({
    sshAlias: prepared.authorization.target.sshAlias,
    ...command,
    signal,
    maxCapturedOutputBytes: 64,
  });
  if (outcome.aborted) {
    throw transferFailure("Remote path inspection was stopped");
  }
  if (
    outcome.stdoutTruncated ||
    outcome.stderrTruncated ||
    outcome.stderr.length !== 0
  ) {
    throw transferFailure("Remote path inspection failed");
  }
  if (outcome.exitCode === 0 && outcome.stdout === REMOTE_PATH_SAFE_TOKEN) {
    return;
  }
  if (
    outcome.exitCode === REMOTE_PATH_UNSAFE_EXIT_CODE &&
    outcome.stdout === REMOTE_PATH_UNSAFE_TOKEN
  ) {
    throw unsafeRemotePathError();
  }
  throw transferFailure("Remote path inspection failed");
}

function fingerprintsMatch(
  left: RemoteFingerprint | undefined,
  right: RemoteFingerprint,
): boolean {
  return (
    left !== undefined &&
    left.size === right.size &&
    left.sha256 === right.sha256
  );
}

async function ensureRemoteParents(
  prepared: PreparedTransfer,
  remotePath: string,
  signal: AbortSignal,
): Promise<void> {
  if (remotePath === prepared.remoteRoot) return;
  const parent = remotePath.slice(0, remotePath.lastIndexOf("/"));
  if (
    parent === "" ||
    !remotePathIsContained(
      prepared.authorization.target.platform,
      prepared.remoteRoot,
      parent,
    )
  ) {
    return;
  }
  const rootIsFilesystemRoot =
    prepared.remoteRoot === "/" || /^[A-Za-z]:\/$/u.test(prepared.remoteRoot);
  let current = prepared.remoteRoot.replace(/\/$/u, "");
  const commands: Array<{
    readonly operation: "mkdir";
    readonly remotePath: string;
    readonly ignoreFailure: true;
  }> = [];
  if (!rootIsFilesystemRoot) {
    commands.push({
      operation: "mkdir",
      remotePath: prepared.remoteRoot,
      ignoreFailure: true,
    });
  }
  const remainder =
    parent === prepared.remoteRoot
      ? ""
      : parent.slice(
          prepared.remoteRoot.length +
            (prepared.remoteRoot.endsWith("/") ? 0 : 1),
        );
  for (const segment of remainder.split("/").filter(Boolean)) {
    current = current === "" ? `/${segment}` : `${current}/${segment}`;
    commands.push({ operation: "mkdir", remotePath: current, ignoreFailure: true });
  }
  if (commands.length > 0) {
    if (usesSharedShellTransfer(prepared)) {
      const executor = new SharedShellTransferExecutor(prepared.generation.ssh);
      const target = sharedShellTarget(prepared);
      for (const command of commands) {
        await runSharedShellOperation("create remote directory", () =>
          executor.ensureDirectory(target, command.remotePath, signal),
        );
      }
    } else {
      await runSftp(prepared, buildSftpBatch(commands), signal);
    }
  }
}

async function publishRemoteExclusive(
  prepared: PreparedTransfer,
  partPath: string,
  destinationPath: string,
  signal: AbortSignal,
): Promise<void> {
  const platform = prepared.authorization.target.platform;
  const command = prepareStructuredRemoteCommand(platform, {
    shell: platform === "windows" ? "powershell" : "bash",
    env: {
      AGENT_SSH_TRANSFER_PART: partPath,
      AGENT_SSH_TRANSFER_DESTINATION: destinationPath,
    },
    encoding: "utf-8",
    script:
      platform === "windows"
        ? "try{[System.IO.File]::Move($env:AGENT_SSH_TRANSFER_PART,$env:AGENT_SSH_TRANSFER_DESTINATION)}catch{exit 17}"
        : "if ln \"$AGENT_SSH_TRANSFER_PART\" \"$AGENT_SSH_TRANSFER_DESTINATION\"; then rm -f \"$AGENT_SSH_TRANSFER_PART\"; else exit 17; fi",
  });
  const outcome = await prepared.generation.ssh.run({
    sshAlias: prepared.authorization.target.sshAlias,
    ...command,
    signal,
    maxCapturedOutputBytes: 1_024,
  });
  if (outcome.aborted) {
    throw transferFailure("Remote publish was stopped");
  }
  if (outcome.exitCode !== 0) {
    await removeRemotePartial(prepared, partPath, signal).catch(() => undefined);
    throw transferFailure(
      "Remote destination could not be published without overwriting",
    );
  }
}

async function removeRemotePartial(
  prepared: PreparedTransfer,
  partPath: string,
  signal: AbortSignal,
): Promise<void> {
  if (usesSharedShellTransfer(prepared)) {
    const executor = new SharedShellTransferExecutor(prepared.generation.ssh);
    await runSharedShellOperation("remove remote partial file", () =>
      executor.removeFile(sharedShellTarget(prepared), partPath, signal),
    );
    return;
  }
  await runSftp(
    prepared,
    buildSftpBatch([
      { operation: "rm", remotePath: partPath, ignoreFailure: true },
    ]),
    signal,
  );
}

async function fingerprintLocalSource(
  sourcePath: string,
  signal: AbortSignal,
): Promise<{ readonly size: number; readonly sha256: string }> {
  const sourceEntry = await lstat(sourcePath).catch((error: unknown) => {
    throw transferFailure("Local source could not be inspected", error);
  });
  if (!sourceEntry.isFile() || sourceEntry.isSymbolicLink()) {
    throw transferFailure("Local source is no longer a safe regular file");
  }
  const noFollow = "O_NOFOLLOW" in fsConstants ? fsConstants.O_NOFOLLOW : 0;
  const source = await open(sourcePath, fsConstants.O_RDONLY | noFollow).catch(
    (error: unknown) => {
      throw transferFailure("Local source could not be opened safely", error);
    },
  );
  try {
    const openedEntry = await source.stat();
    if (
      !openedEntry.isFile() ||
      openedEntry.dev !== sourceEntry.dev ||
      openedEntry.ino !== sourceEntry.ino
    ) {
      throw transferFailure("Local source changed during validation");
    }
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(256 * 1_024);
    let position = 0;
    while (true) {
      signal.throwIfAborted();
      const { bytesRead } = await source.read(buffer, 0, buffer.length, position);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    const finalEntry = await source.stat();
    if (
      finalEntry.size !== openedEntry.size ||
      finalEntry.mtimeMs !== openedEntry.mtimeMs ||
      position !== openedEntry.size
    ) {
      throw transferFailure("Local source changed while it was being checked");
    }
    return { size: position, sha256: hash.digest("hex") };
  } catch (error) {
    if (signal.aborted) throw transferFailure("Local source check was stopped");
    throw error;
  } finally {
    await source.close().catch(() => undefined);
  }
}

async function stageLocalSource(
  sourcePath: string,
  spoolDirectory: string,
  signal: AbortSignal,
): Promise<{ readonly path: string; readonly size: number; readonly sha256: string }> {
  const sourceEntry = await lstat(sourcePath).catch((error: unknown) => {
    throw transferFailure("Local source could not be inspected", error);
  });
  if (!sourceEntry.isFile() || sourceEntry.isSymbolicLink()) {
    throw transferFailure("Local source is no longer a safe regular file");
  }
  const stagedPath = path.join(
    spoolDirectory,
    `${randomBytes(32).toString("base64url")}.upload`,
  );
  const noFollow = "O_NOFOLLOW" in fsConstants ? fsConstants.O_NOFOLLOW : 0;
  const source = await open(sourcePath, fsConstants.O_RDONLY | noFollow).catch(
    (error: unknown) => {
      throw transferFailure("Local source could not be opened safely", error);
    },
  );
  let destination: Awaited<ReturnType<typeof open>> | undefined;
  try {
    const openedEntry = await source.stat();
    if (
      !openedEntry.isFile() ||
      openedEntry.dev !== sourceEntry.dev ||
      openedEntry.ino !== sourceEntry.ino
    ) {
      throw transferFailure("Local source changed during validation");
    }
    destination = await open(stagedPath, "wx", 0o600);
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(256 * 1_024);
    let position = 0;
    while (true) {
      signal.throwIfAborted();
      const { bytesRead } = await source.read(buffer, 0, buffer.length, position);
      if (bytesRead === 0) break;
      const chunk = buffer.subarray(0, bytesRead);
      hash.update(chunk);
      let written = 0;
      while (written < bytesRead) {
        const result = await destination.write(
          chunk,
          written,
          bytesRead - written,
          position + written,
        );
        written += result.bytesWritten;
      }
      position += bytesRead;
    }
    const finalEntry = await source.stat();
    if (
      finalEntry.size !== openedEntry.size ||
      finalEntry.mtimeMs !== openedEntry.mtimeMs ||
      position !== openedEntry.size
    ) {
      throw transferFailure("Local source changed while it was being staged");
    }
    await destination.sync();
    return { path: stagedPath, size: position, sha256: hash.digest("hex") };
  } catch (error) {
    await unlink(stagedPath).catch(() => undefined);
    if (signal.aborted) throw transferFailure("Local source staging was stopped");
    throw error;
  } finally {
    await destination?.close().catch(() => undefined);
    await source.close().catch(() => undefined);
  }
}

async function prepareTransferSpool(
  spoolDirectory: string,
  partialTtlMs: number,
): Promise<void> {
  if (!Number.isSafeInteger(partialTtlMs) || partialTtlMs < 1) {
    throw new RangeError("partialTtlMs must be a positive safe integer");
  }
  const directory = await lstat(spoolDirectory).catch((error: unknown) => {
    throw transferFailure("Transfer staging storage is unavailable", error);
  });
  if (!directory.isDirectory() || directory.isSymbolicLink()) {
    throw transferFailure("Transfer staging storage is unsafe");
  }

  const parts = new Map<string, { readonly path: string; readonly mtimeMs: number }>();
  const metadata = new Map<
    string,
    { readonly path: string; readonly mtimeMs: number }
  >();
  for (const entry of await readdir(spoolDirectory, { withFileTypes: true })) {
    const entryPath = path.join(spoolDirectory, entry.name);
    const stats = await optionalSafeSpoolFile(entryPath);
    if (stats === undefined) continue;
    if (entry.name.endsWith(".upload") || entry.name.endsWith(".download.lock")) {
      await removeSafeSpoolFile(entryPath);
      continue;
    }
    const partId = DOWNLOAD_PART_PATTERN.exec(entry.name)?.[1];
    if (partId !== undefined) {
      parts.set(partId, { path: entryPath, mtimeMs: stats.mtimeMs });
      continue;
    }
    const metadataId = DOWNLOAD_METADATA_PATTERN.exec(entry.name)?.[1];
    if (metadataId !== undefined) {
      metadata.set(metadataId, { path: entryPath, mtimeMs: stats.mtimeMs });
    }
  }

  const now = Date.now();
  for (const id of new Set([...parts.keys(), ...metadata.keys()])) {
    const part = parts.get(id);
    const manifest = metadata.get(id);
    const validManifest =
      manifest === undefined
        ? false
        : await downloadMetadataMatches(manifest.path, id);
    const expired =
      part !== undefined &&
      manifest !== undefined &&
      now - Math.max(part.mtimeMs, manifest.mtimeMs) > partialTtlMs;
    if (part === undefined || manifest === undefined || !validManifest || expired) {
      await Promise.all([
        part === undefined ? Promise.resolve() : unlink(part.path),
        manifest === undefined ? Promise.resolve() : unlink(manifest.path),
      ]);
    }
  }
}

async function acquireDownloadSpool(options: {
  readonly spoolDirectory: string;
  readonly binding: DownloadBinding;
  readonly resume: boolean;
  readonly maximumBytes: number;
}): Promise<DownloadSpoolLease> {
  const bindingSha256 = hashDownloadBinding(options.binding);
  const partPath = path.join(
    options.spoolDirectory,
    `${bindingSha256}.download.part`,
  );
  const metadataPath = path.join(
    options.spoolDirectory,
    `${bindingSha256}.download.json`,
  );
  const lockPath = path.join(
    options.spoolDirectory,
    `${bindingSha256}.download.lock`,
  );
  const lock = await open(lockPath, "wx", 0o600).catch((error: unknown) => {
    throw transferFailure("An identical download is already active", error);
  });
  await lock.close();

  try {
    const existingPart = await optionalSafeSpoolFile(partPath);
    const metadataMatches = await downloadMetadataMatches(
      metadataPath,
      bindingSha256,
      options.binding.remoteSize,
      options.binding.remoteSha256,
    );
    const resumed =
      options.resume &&
      existingPart !== undefined &&
      existingPart.size <= options.maximumBytes &&
      metadataMatches;
    if (!resumed) {
      await Promise.all([
        removeSafeSpoolFile(partPath),
        removeSafeSpoolFile(metadataPath),
      ]);
      await writeFile(
        metadataPath,
        `${JSON.stringify({
          version: DOWNLOAD_METADATA_VERSION,
          bindingSha256,
          remoteSize: options.binding.remoteSize,
          remoteSha256: options.binding.remoteSha256,
        })}\n`,
        { encoding: "utf8", flag: "wx", mode: 0o600 },
      );
      await chmod(metadataPath, 0o600).catch(() => undefined);
    }

    let released = false;
    return {
      partPath,
      resumed,
      restart: async (): Promise<void> => {
        if (released) throw transferFailure("Download staging is no longer active");
        await removeSafeSpoolFile(partPath);
      },
      release: async (retainPartial: boolean): Promise<void> => {
        if (released) return;
        released = true;
        try {
          const retainedPart = retainPartial
            ? await optionalSafeSpoolFile(partPath)
            : undefined;
          const retainedMetadata =
            retainPartial &&
            (await downloadMetadataMatches(
              metadataPath,
              bindingSha256,
              options.binding.remoteSize,
              options.binding.remoteSha256,
            ));
          if (retainedPart === undefined || !retainedMetadata) {
            await Promise.all([
              removeSafeSpoolFile(partPath),
              removeSafeSpoolFile(metadataPath),
            ]);
          }
        } finally {
          await removeSafeSpoolFile(lockPath);
        }
      },
    };
  } catch (error) {
    await removeSafeSpoolFile(lockPath).catch(() => undefined);
    throw error;
  }
}

function hashDownloadBinding(binding: DownloadBinding): string {
  return createHash("sha256")
    .update(
      JSON.stringify([
        "agent-ssh-download-v1",
        binding.target,
        binding.localRoot,
        binding.localPath,
        binding.remotePath,
        binding.remoteSize,
        binding.remoteSha256,
      ]),
      "utf8",
    )
    .digest("hex");
}

async function downloadMetadataMatches(
  metadataPath: string,
  bindingSha256: string,
  remoteSize?: number,
  remoteSha256?: string,
): Promise<boolean> {
  const stats = await optionalSafeSpoolFile(metadataPath);
  if (stats === undefined || stats.size > 1_024) return false;
  try {
    const parsed = JSON.parse(await readFile(metadataPath, "utf8")) as unknown;
    return (
      typeof parsed === "object" &&
      parsed !== null &&
      !Array.isArray(parsed) &&
      (parsed as Record<string, unknown>).version === DOWNLOAD_METADATA_VERSION &&
      (parsed as Record<string, unknown>).bindingSha256 === bindingSha256 &&
      Number.isSafeInteger((parsed as Record<string, unknown>).remoteSize) &&
      ((parsed as Record<string, unknown>).remoteSize as number) >= 0 &&
      (remoteSize === undefined ||
        (parsed as Record<string, unknown>).remoteSize === remoteSize) &&
      typeof (parsed as Record<string, unknown>).remoteSha256 === "string" &&
      /^[a-f0-9]{64}$/u.test(
        (parsed as Record<string, unknown>).remoteSha256 as string,
      ) &&
      (remoteSha256 === undefined ||
        (parsed as Record<string, unknown>).remoteSha256 === remoteSha256) &&
      Object.keys(parsed).length === 4
    );
  } catch {
    return false;
  }
}

async function requireSafeSpoolFile(
  filePath: string,
): Promise<Stats> {
  const stats = await lstat(filePath).catch((error: unknown) => {
    throw transferFailure("Transfer staging file is unavailable", error);
  });
  if (!stats.isFile() || stats.isSymbolicLink()) {
    throw transferFailure("Transfer staging contains an unsafe file");
  }
  return stats;
}

async function optionalSafeSpoolFile(
  filePath: string,
): Promise<Stats | undefined> {
  try {
    return await requireSafeSpoolFile(filePath);
  } catch (error) {
    if (isNodeErrorCause(error, "ENOENT")) return undefined;
    throw error;
  }
}

async function removeSafeSpoolFile(filePath: string): Promise<void> {
  const stats = await optionalSafeSpoolFile(filePath);
  if (stats !== undefined) {
    await unlink(filePath).catch((error: unknown) => {
      if (!isNodeErrorCause(error, "ENOENT")) throw error;
    });
  }
}

async function publishDownloadedFile(
  sourcePath: string,
  destinationPath: string,
  overwrite: boolean,
  signal: AbortSignal,
): Promise<void> {
  const publishPath = path.join(
    path.dirname(destinationPath),
    `.agent-ssh-${randomBytes(32).toString("base64url")}.publish`,
  );
  try {
    signal.throwIfAborted();
    await copyFile(sourcePath, publishPath, fsConstants.COPYFILE_EXCL);
    signal.throwIfAborted();
    await chmod(publishPath, 0o600).catch(() => undefined);
    const handle = await open(publishPath, "r+");
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
    signal.throwIfAborted();
    if (overwrite) {
      await rename(publishPath, destinationPath);
    } else {
      await link(publishPath, destinationPath);
    }
  } catch (error) {
    throw transferFailure("Local destination could not be published", error);
  } finally {
    await unlink(publishPath).catch(() => undefined);
  }
}

async function enumerateFiles(
  root: string,
  excludes: readonly ExcludeMatcher[],
  limits: EnumerationLimits,
  signal: AbortSignal,
): Promise<{ readonly files: SyncFile[]; readonly totalBytes: number }> {
  requireEnumerationLimit(limits.maxFiles, "maxFiles");
  requireEnumerationLimit(limits.maxFileBytes, "maxFileBytes");
  requireEnumerationLimit(limits.maxTotalBytes, "maxTotalBytes");
  const files: SyncFile[] = [];
  let totalBytes = 0;
  const visit = async (directory: string, relativeDirectory: string): Promise<void> => {
    signal.throwIfAborted();
    const entries = await opendir(directory);
    try {
      while (true) {
        signal.throwIfAborted();
        const entry = await entries.read();
        signal.throwIfAborted();
        if (entry === null) break;
        const relativePath = relativeDirectory
          ? `${relativeDirectory}/${entry.name}`
          : entry.name;
        if (Buffer.byteLength(relativePath, "utf8") > MAX_TRANSFER_PATH_BYTES) {
          throw transferFailure("Directory sync path exceeds the safe transfer limit");
        }
        signal.throwIfAborted();
        const excluded = excludes.some((matcher) => matcher.matches(relativePath));
        signal.throwIfAborted();
        if (excluded) continue;
        const absolutePath = path.join(directory, entry.name);
        const stats = await lstat(absolutePath);
        signal.throwIfAborted();
        if (stats.isSymbolicLink()) {
          throw transferFailure("Directory sync does not follow links or reparse points");
        }
        if (stats.isDirectory()) {
          await visit(absolutePath, relativePath);
        } else if (stats.isFile()) {
          if (!Number.isSafeInteger(stats.size) || stats.size < 0) {
            throw transferFailure("Directory sync encountered an invalid file size");
          }
          if (
            stats.size > limits.maxFileBytes ||
            stats.size > limits.maxTotalBytes ||
            files.length >= limits.maxFiles ||
            totalBytes > limits.maxTotalBytes - stats.size
          ) {
            throw transferFailure("Directory sync exceeds the configured transfer quota");
          }
          files.push({ relativePath, absolutePath, size: stats.size });
          totalBytes += stats.size;
        } else {
          throw transferFailure("Directory sync encountered an unsupported file type");
        }
      }
    } finally {
      await entries.close().catch(() => undefined);
    }
  };
  await visit(root, "");
  signal.throwIfAborted();
  return { files, totalBytes };
}

type GlobToken =
  | Readonly<{ readonly kind: "literal"; readonly value: string }>
  | Readonly<{ readonly kind: "single" | "star" | "globstar" }>;

function compileExcludePattern(pattern: string): ExcludeMatcher {
  const normalized = pattern.replaceAll("\\", "/");
  if (
    normalized.length === 0 ||
    Buffer.byteLength(normalized, "utf8") > 512 ||
    /[\u0000-\u001f\u007f]/u.test(normalized) ||
    normalized.startsWith("/") ||
    /^[A-Za-z]:/u.test(normalized) ||
    normalized.split("/").includes("..")
  ) {
    throw new GatewayError(
      GATEWAY_ERROR_CODES.invalidParams,
      "Sync exclusion pattern is invalid",
    );
  }
  const characters = Array.from(normalized);
  const tokens: GlobToken[] = [];
  for (let index = 0; index < characters.length; index += 1) {
    const character = characters[index]!;
    if (character === "*") {
      let runLength = 1;
      while (characters[index + runLength] === "*") runLength += 1;
      tokens.push({ kind: runLength >= 2 ? "globstar" : "star" });
      index += runLength - 1;
    } else if (character === "?") {
      tokens.push({ kind: "single" });
    } else {
      tokens.push({ kind: "literal", value: character });
    }
  }
  const frozenTokens = Object.freeze(tokens);
  return Object.freeze({
    tokenCount: frozenTokens.length,
    matches: (relativePath: string): boolean =>
      globMatchesPathOrDescendant(frozenTokens, relativePath),
  });
}

function compileExcludePatterns(patterns: readonly string[]): ExcludeMatcher[] {
  const matchers: ExcludeMatcher[] = [];
  let totalTokens = 0;
  for (const pattern of patterns) {
    const matcher = compileExcludePattern(pattern);
    if (matcher.tokenCount > MAX_TOTAL_EXCLUDE_TOKENS - totalTokens) {
      throw new GatewayError(
        GATEWAY_ERROR_CODES.invalidParams,
        "Sync exclusion patterns are too complex",
      );
    }
    totalTokens += matcher.tokenCount;
    matchers.push(matcher);
  }
  return matchers;
}

function globMatchesPathOrDescendant(
  tokens: readonly GlobToken[],
  relativePath: string,
): boolean {
  let states = new Uint8Array(tokens.length + 1);
  let next = new Uint8Array(tokens.length + 1);
  states[0] = 1;
  expandGlobEpsilon(states, tokens);
  for (const character of relativePath) {
    if (states[tokens.length] === 1 && character === "/") return true;
    next.fill(0);
    let hasActiveState = false;
    for (let index = 0; index < tokens.length; index += 1) {
      if (states[index] !== 1) continue;
      const token = tokens[index]!;
      if (token.kind === "literal") {
        if (token.value === character) {
          next[index + 1] = 1;
          hasActiveState = true;
        }
      } else if (token.kind === "single") {
        if (character !== "/") {
          next[index + 1] = 1;
          hasActiveState = true;
        }
      } else if (token.kind === "star") {
        if (character !== "/") {
          next[index] = 1;
          hasActiveState = true;
        }
      } else {
        next[index] = 1;
        hasActiveState = true;
      }
    }
    if (!hasActiveState) return false;
    const previous = states;
    states = next;
    next = previous;
    expandGlobEpsilon(states, tokens);
  }
  return states[tokens.length] === 1;
}

function expandGlobEpsilon(
  states: Uint8Array,
  tokens: readonly GlobToken[],
): void {
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (
      states[index] === 1 &&
      (token.kind === "star" || token.kind === "globstar")
    ) {
      states[index + 1] = 1;
    }
  }
}

function requireEnumerationLimit(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${name} must be a positive safe integer`);
  }
}

function joinRemotePath(root: string, relativePath: string): string {
  return `${root.replace(/\/$/u, "")}/${relativePath}`;
}

function remoteFilesystemRoot(
  platform: TransferAuthorization["target"]["platform"],
  remotePath: string,
): string {
  if (platform !== "windows") return "/";
  const match = /^([A-Z]):\//u.exec(remotePath);
  if (match?.[1] === undefined) {
    throw transferFailure("Remote Windows path has no filesystem root");
  }
  return `${match[1]}:/`;
}

function remotePathIsContained(
  platform: TransferAuthorization["target"]["platform"],
  root: string,
  candidate: string,
): boolean {
  const normalize = (value: string): string =>
    platform === "windows" ? value.toLowerCase() : value;
  const normalizedRoot = normalize(root).replace(/\/$/u, "");
  const normalizedCandidate = normalize(candidate);
  return (
    normalizedCandidate === normalizedRoot ||
    normalizedRoot === "" ||
    normalizedCandidate.startsWith(`${normalizedRoot}/`)
  );
}

function enforceFileQuota(
  authorization: TransferAuthorization,
  size: number,
): void {
  if (
    !Number.isSafeInteger(size) ||
    size < 0 ||
    size > authorization.maxFileBytes ||
    size > authorization.maxTotalBytes
  ) {
    throw transferFailure("File exceeds the configured transfer quota");
  }
}

function checksumError(message: string): GatewayError {
  return new GatewayError(GATEWAY_ERROR_CODES.checksumMismatch, message);
}

function unsafeRemotePathError(): GatewayError {
  return transferFailure(
    "Remote transfer path contains a link or reparse point",
  );
}

function transferFailure(message: string, cause?: unknown): GatewayError {
  return new GatewayError(GATEWAY_ERROR_CODES.transferFailed, message, {
    ...(cause === undefined ? {} : { cause }),
  });
}

function publicTransferPathError(error: unknown): GatewayError {
  return error instanceof TransferPathError
    ? new GatewayError(GATEWAY_ERROR_CODES.invalidParams, error.message)
    : transferFailure("Transfer path could not be validated", error);
}

function rethrowTransferPath(error: unknown): never {
  throw publicTransferPathError(error);
}

function resultMetric(
  result: Readonly<Record<string, unknown>> | undefined,
  key: "files" | "bytes",
): number {
  const value = result?.[key];
  return Number.isSafeInteger(value) && (value as number) >= 0
    ? (value as number)
    : 0;
}

function transferAuditReason(error: unknown, signal: AbortSignal): string {
  if (signal.aborted) return "transfer.stopped";
  if (error instanceof GatewayError) {
    return error.code.toLowerCase().replaceAll("_", ".");
  }
  return "internal.error";
}

function isNodeErrorCause(error: unknown, code: string): boolean {
  let current = error;
  for (let depth = 0; depth < 8 && current !== undefined; depth += 1) {
    if (
      current instanceof Error &&
      "code" in current &&
      (current as NodeJS.ErrnoException).code === code
    ) {
      return true;
    }
    current =
      current instanceof Error && "cause" in current
        ? (current as Error & { readonly cause?: unknown }).cause
        : undefined;
  }
  return false;
}
