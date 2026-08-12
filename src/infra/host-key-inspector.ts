import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import path from "node:path";
import { isUtf8 } from "node:buffer";

export const HOST_KEY_INSPECTION_TIMEOUT_MS = 10_000;
export const MAX_HOST_KEY_INSPECTION_OUTPUT_BYTES = 256 * 1024;

export interface HostKeyInspectorOptions {
  readonly sshExecutable: string;
  readonly configFile: string;
  readonly knownHostsFile: string;
}

export interface TrustedHostKeyFingerprint {
  readonly keyType: string;
  readonly fingerprintSha256: string;
  readonly trust: "host-key" | "host-ca";
}

export type HostKeyInspectionErrorCode =
  | "INVALID_INSPECTION_CONFIGURATION"
  | "SSH_CONFIG_REJECTED"
  | "HOST_KEY_LOOKUP_FAILED"
  | "HOST_KEY_NOT_FOUND"
  | "HOST_KEY_INVALID";

export class HostKeyInspectionError extends Error {
  public readonly code: HostKeyInspectionErrorCode;

  public constructor(code: HostKeyInspectionErrorCode, message: string) {
    super(message);
    this.name = "HostKeyInspectionError";
    this.code = code;
  }
}

export interface HostKeyCommandResult {
  readonly exitCode: number;
  readonly stdout: Uint8Array;
}

export interface HostKeyCommandRunnerInput {
  readonly executable: string;
  readonly arguments: readonly string[];
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
}

export type HostKeyCommandRunner = (
  input: HostKeyCommandRunnerInput,
) => Promise<HostKeyCommandResult>;

export interface HostKeyInspectorDependencies {
  readonly runCommand?: HostKeyCommandRunner;
}

interface ResolvedHostIdentity {
  readonly hostname: string;
  readonly port: number;
  readonly hostKeyAlias?: string;
}

const SSH_ALIAS_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const LOOKUP_NAME_PATTERN = /^[A-Za-z0-9:][A-Za-z0-9._:%-]{0,254}$/;
const KEY_TYPE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}$/;
const CANONICAL_BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const MAX_KEY_BLOB_BYTES = 16 * 1024;

export class HostKeyInspector {
  readonly #options: HostKeyInspectorOptions;
  readonly #sshKeygenExecutable: string;
  readonly #runCommand: HostKeyCommandRunner;
  readonly #cache = new Map<string, Promise<readonly TrustedHostKeyFingerprint[]>>();

  public constructor(
    options: HostKeyInspectorOptions,
    dependencies: HostKeyInspectorDependencies = {},
  ) {
    validateOptions(options);
    this.#options = Object.freeze({ ...options });
    this.#sshKeygenExecutable = siblingSshKeygen(options.sshExecutable);
    this.#runCommand = dependencies.runCommand ?? runCommand;
  }

  public inspect(sshAlias: string): Promise<readonly TrustedHostKeyFingerprint[]> {
    if (!SSH_ALIAS_PATTERN.test(sshAlias)) {
      return Promise.reject(
        new HostKeyInspectionError(
          "INVALID_INSPECTION_CONFIGURATION",
          "SSH target alias is invalid",
        ),
      );
    }
    let inspection = this.#cache.get(sshAlias);
    if (inspection === undefined) {
      const candidate = this.#inspect(sshAlias);
      const cached = candidate.catch((error: unknown) => {
        if (this.#cache.get(sshAlias) === cached) {
          this.#cache.delete(sshAlias);
        }
        throw error;
      });
      inspection = cached;
      this.#cache.set(sshAlias, inspection);
    }
    return inspection;
  }

  async #inspect(sshAlias: string): Promise<readonly TrustedHostKeyFingerprint[]> {
    const resolvedResult = await this.#execute(
      this.#options.sshExecutable,
      ["-G", "-F", this.#options.configFile, "--", sshAlias],
      "SSH_CONFIG_REJECTED",
      "OpenSSH could not resolve the target configuration",
    );
    if (resolvedResult.exitCode !== 0) {
      throw new HostKeyInspectionError(
        "SSH_CONFIG_REJECTED",
        "OpenSSH could not resolve the target configuration",
      );
    }
    const resolved = parseResolvedHostIdentity(resolvedResult.stdout);
    const candidates = lookupCandidates(resolved);
    const fingerprints = new Map<string, TrustedHostKeyFingerprint>();
    const revoked = new Set<string>();
    for (const candidate of candidates) {
      const lookup = await this.#execute(
        this.#sshKeygenExecutable,
        ["-F", candidate, "-f", this.#options.knownHostsFile],
        "HOST_KEY_LOOKUP_FAILED",
        "Trusted host-key lookup failed",
      );
      if (lookup.exitCode !== 0 && lookup.exitCode !== 1) {
        throw new HostKeyInspectionError(
          "HOST_KEY_LOOKUP_FAILED",
          "Trusted host-key lookup failed",
        );
      }
      if (lookup.exitCode === 1 && lookup.stdout.byteLength === 0) {
        continue;
      }
      const matches = parseKnownHostMatches(lookup.stdout);
      for (const identity of matches.revoked) {
        revoked.add(identity);
      }
      for (const fingerprint of matches.trusted) {
        fingerprints.set(
          `${fingerprint.trust}\0${fingerprint.keyType}\0${fingerprint.fingerprintSha256}`,
          fingerprint,
        );
      }
    }
    for (const [identity, fingerprint] of fingerprints) {
      if (revoked.has(`${fingerprint.keyType}\0${fingerprint.fingerprintSha256}`)) {
        fingerprints.delete(identity);
      }
    }
    if (fingerprints.size === 0) {
      throw new HostKeyInspectionError(
        "HOST_KEY_NOT_FOUND",
        "No trusted host key is configured for the target",
      );
    }
    return Object.freeze(
      [...fingerprints.values()]
        .sort(compareFingerprints)
        .map((entry) => Object.freeze(entry)),
    );
  }

  async #execute(
    executable: string,
    arguments_: readonly string[],
    code: HostKeyInspectionErrorCode,
    message: string,
  ): Promise<HostKeyCommandResult> {
    let result: HostKeyCommandResult;
    try {
      result = await this.#runCommand({
        executable,
        arguments: Object.freeze([...arguments_]),
        timeoutMs: HOST_KEY_INSPECTION_TIMEOUT_MS,
        maxOutputBytes: MAX_HOST_KEY_INSPECTION_OUTPUT_BYTES,
      });
    } catch {
      throw new HostKeyInspectionError(code, message);
    }
    if (
      !Number.isSafeInteger(result.exitCode) ||
      result.exitCode < 0 ||
      result.exitCode > 4_294_967_295 ||
      result.stdout.byteLength > MAX_HOST_KEY_INSPECTION_OUTPUT_BYTES
    ) {
      throw new HostKeyInspectionError(code, message);
    }
    return { exitCode: result.exitCode, stdout: Buffer.from(result.stdout) };
  }
}

function validateOptions(options: HostKeyInspectorOptions): void {
  for (const value of [
    options.sshExecutable,
    options.configFile,
    options.knownHostsFile,
  ]) {
    if (
      (!path.isAbsolute(value) && !path.win32.isAbsolute(value)) ||
      /[\u0000-\u001f\u007f]/u.test(value)
    ) {
      throw new HostKeyInspectionError(
        "INVALID_INSPECTION_CONFIGURATION",
        "Host-key inspection paths are invalid",
      );
    }
  }
}

function siblingSshKeygen(sshExecutable: string): string {
  const extension = path.extname(sshExecutable).toLowerCase();
  return path.join(
    path.dirname(sshExecutable),
    extension === ".exe" ? "ssh-keygen.exe" : "ssh-keygen",
  );
}

function parseResolvedHostIdentity(output: Uint8Array): ResolvedHostIdentity {
  const text = decodeBoundedUtf8(output, "SSH_CONFIG_REJECTED");
  const selected = new Map<string, string>();
  for (const line of text.split(/\r?\n/u)) {
    const separator = line.indexOf(" ");
    if (separator <= 0) continue;
    const key = line.slice(0, separator).toLowerCase();
    if (key !== "hostname" && key !== "port" && key !== "hostkeyalias") continue;
    const value = line.slice(separator + 1).trim();
    if (selected.has(key) || value.length === 0) {
      throw new HostKeyInspectionError(
        "SSH_CONFIG_REJECTED",
        "OpenSSH returned an invalid target configuration",
      );
    }
    selected.set(key, value);
  }
  const hostname = selected.get("hostname");
  const portText = selected.get("port");
  const hostKeyAliasValue = selected.get("hostkeyalias");
  const hostKeyAlias =
    hostKeyAliasValue === undefined || hostKeyAliasValue.toLowerCase() === "none"
      ? undefined
      : hostKeyAliasValue;
  const port = portText === undefined ? Number.NaN : Number(portText);
  if (
    hostname === undefined ||
    !LOOKUP_NAME_PATTERN.test(hostname) ||
    !Number.isSafeInteger(port) ||
    port < 1 ||
    port > 65_535 ||
    (hostKeyAlias !== undefined && !LOOKUP_NAME_PATTERN.test(hostKeyAlias))
  ) {
    throw new HostKeyInspectionError(
      "SSH_CONFIG_REJECTED",
      "OpenSSH returned an invalid target configuration",
    );
  }
  return {
    hostname,
    port,
    ...(hostKeyAlias === undefined ? {} : { hostKeyAlias }),
  };
}

function lookupCandidates(resolved: ResolvedHostIdentity): readonly string[] {
  if (resolved.hostKeyAlias !== undefined) {
    return Object.freeze([resolved.hostKeyAlias]);
  }
  return Object.freeze(
    resolved.port === 22
      ? [resolved.hostname, `[${resolved.hostname}]:22`]
      : [`[${resolved.hostname}]:${resolved.port}`],
  );
}

function parseKnownHostMatches(output: Uint8Array): {
  readonly trusted: TrustedHostKeyFingerprint[];
  readonly revoked: ReadonlySet<string>;
} {
  const text = decodeBoundedUtf8(output, "HOST_KEY_INVALID");
  const trusted: TrustedHostKeyFingerprint[] = [];
  const revoked = new Set<string>();
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#")) continue;
    const fields = line.split(/\s+/u);
    let offset = 0;
    let trust: TrustedHostKeyFingerprint["trust"] = "host-key";
    let isRevoked = false;
    if (fields[0]?.startsWith("@")) {
      const marker = fields[0];
      if (marker === "@revoked") isRevoked = true;
      else if (marker === "@cert-authority") trust = "host-ca";
      else continue;
      offset = 1;
    }
    const hosts = fields[offset];
    const keyType = fields[offset + 1];
    const encodedKey = fields[offset + 2];
    if (
      hosts === undefined ||
      hosts.length === 0 ||
      hosts.length > 4_096 ||
      /[\u0000-\u0020\u007f]/u.test(hosts) ||
      keyType === undefined ||
      !KEY_TYPE_PATTERN.test(keyType) ||
      encodedKey === undefined
    ) {
      throw new HostKeyInspectionError(
        "HOST_KEY_INVALID",
        "Trusted host-key data is invalid",
      );
    }
    const blob = decodeKeyBlob(encodedKey, keyType);
    const digest = createHash("sha256").update(blob).digest("base64").replace(/=+$/u, "");
    const fingerprintSha256 = `SHA256:${digest}`;
    if (isRevoked) {
      revoked.add(`${keyType}\0${fingerprintSha256}`);
      continue;
    }
    trusted.push({
      keyType,
      fingerprintSha256,
      trust,
    });
  }
  return { trusted, revoked };
}

function decodeKeyBlob(encoded: string, keyType: string): Buffer {
  if (
    encoded.length === 0 ||
    encoded.length > Math.ceil((MAX_KEY_BLOB_BYTES * 4) / 3) + 4 ||
    !CANONICAL_BASE64_PATTERN.test(encoded)
  ) {
    throw new HostKeyInspectionError(
      "HOST_KEY_INVALID",
      "Trusted host-key data is invalid",
    );
  }
  const blob = Buffer.from(encoded, "base64");
  if (
    blob.length < 8 ||
    blob.length > MAX_KEY_BLOB_BYTES ||
    blob.toString("base64") !== encoded
  ) {
    throw new HostKeyInspectionError(
      "HOST_KEY_INVALID",
      "Trusted host-key data is invalid",
    );
  }
  const algorithmLength = blob.readUInt32BE(0);
  if (algorithmLength < 1 || algorithmLength > 128 || 4 + algorithmLength > blob.length) {
    throw new HostKeyInspectionError(
      "HOST_KEY_INVALID",
      "Trusted host-key data is invalid",
    );
  }
  const algorithm = blob.subarray(4, 4 + algorithmLength);
  if (!isUtf8(algorithm) || algorithm.toString("utf8") !== keyType) {
    throw new HostKeyInspectionError(
      "HOST_KEY_INVALID",
      "Trusted host-key data is invalid",
    );
  }
  return blob;
}

function decodeBoundedUtf8(
  output: Uint8Array,
  code: Extract<HostKeyInspectionErrorCode, "SSH_CONFIG_REJECTED" | "HOST_KEY_INVALID">,
): string {
  const bytes = Buffer.from(output);
  if (
    bytes.length > MAX_HOST_KEY_INSPECTION_OUTPUT_BYTES ||
    !isUtf8(bytes) ||
    bytes.includes(0) ||
    /[\u0001-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(bytes.toString("utf8"))
  ) {
    throw new HostKeyInspectionError(
      code,
      code === "SSH_CONFIG_REJECTED"
        ? "OpenSSH returned an invalid target configuration"
        : "Trusted host-key data is invalid",
    );
  }
  return bytes.toString("utf8");
}

function compareFingerprints(
  left: TrustedHostKeyFingerprint,
  right: TrustedHostKeyFingerprint,
): number {
  const leftKey = `${left.trust}\0${left.keyType}\0${left.fingerprintSha256}`;
  const rightKey = `${right.trust}\0${right.keyType}\0${right.fingerprintSha256}`;
  return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
}

function runCommand(input: HostKeyCommandRunnerInput): Promise<HostKeyCommandResult> {
  return new Promise((resolve, reject) => {
    execFile(
      input.executable,
      [...input.arguments],
      {
        encoding: "buffer",
        maxBuffer: input.maxOutputBytes,
        timeout: input.timeoutMs,
        windowsHide: true,
      },
      (error, stdout) => {
        if (error === null) {
          resolve({ exitCode: 0, stdout: Buffer.from(stdout) });
          return;
        }
        if (typeof error.code === "number") {
          resolve({ exitCode: error.code < 0 ? error.code >>> 0 : error.code, stdout: Buffer.from(stdout) });
          return;
        }
        reject(new Error("Local host-key inspection command failed"));
      },
    );
  });
}
