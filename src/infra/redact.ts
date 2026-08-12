export const REDACTED = "[REDACTED]";
export const REDACTED_BINARY = "[REDACTED BINARY]";
export const REDACTED_CIRCULAR = "[CIRCULAR]";
export const REDACTED_TRUNCATED = "[TRUNCATED]";

export interface RedactionOptions {
  readonly maxDepth?: number;
  readonly maxEntries?: number;
}

const DEFAULT_MAX_DEPTH = 12;
const DEFAULT_MAX_ENTRIES = 10_000;

const SAFE_DERIVED_KEYS = new Set([
  "commandbytes",
  "commandsha256",
  "stderrbytes",
  "stdoutbytes",
]);

const SENSITIVE_KEYS = new Set([
  "apikey",
  "argv",
  "authorization",
  "cmd",
  "command",
  "configfile",
  "cookie",
  "credential",
  "credentials",
  "cwd",
  "directory",
  "error",
  "errormessage",
  "executable",
  "filepath",
  "knownhostsfile",
  "mfa",
  "otp",
  "output",
  "outputexpiresat",
  "outputref",
  "passphrase",
  "passwd",
  "password",
  "path",
  "privatekey",
  "pwd",
  "ref",
  "reference",
  "secret",
  "sessionid",
  "stderr",
  "stdout",
  "token",
]);

const SENSITIVE_SUFFIXES = [
  "apikey",
  "authorization",
  "cookie",
  "credential",
  "error",
  "message",
  "passphrase",
  "password",
  "path",
  "privatekey",
  "ref",
  "secret",
  "stderr",
  "stdout",
  "token",
] as const;

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

export function isSensitiveKey(key: string): boolean {
  const normalized = normalizeKey(key);
  if (SAFE_DERIVED_KEYS.has(normalized)) {
    return false;
  }

  return (
    SENSITIVE_KEYS.has(normalized) ||
    SENSITIVE_SUFFIXES.some((suffix) => normalized.endsWith(suffix)) ||
    normalized.endsWith("command")
  );
}

/**
 * Redacts common credential forms that can be embedded in otherwise allowed
 * string fields. Structured callers should still remove sensitive fields
 * before invoking this function.
 */
export function redactText(value: string): string {
  return value
    .replace(
      /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/gi,
      REDACTED,
    )
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, `$1 ${REDACTED}`)
    .replace(
      /\b(password|passwd|pwd|passphrase|secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key|authorization|cookie|otp)\b(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi,
      (_match, name: string, separator: string) =>
        `${name}${separator}${REDACTED}`,
    )
    .replace(/\b[A-Za-z]:[\\/](?:[^\\/\r\n\t "']+[\\/]?)+/g, REDACTED)
    .replace(/\\\\[^\\\s]+\\[^\s"']+/g, REDACTED)
    .replace(/\bfile:\/\/\/[^\s"']+/gi, REDACTED)
    .replace(
      /(^|[\s(])\/(?:etc|home|mnt|opt|root|run|srv|tmp|users|var)(?:\/[^\s"',;)]+)+/gi,
      (_match, prefix: string) => `${prefix}${REDACTED}`,
    )
    .replace(/\b[A-Za-z0-9_-]{43}\b/g, REDACTED);
}

/**
 * Recursively creates a JSON-safe, non-mutating redacted copy. Accessor
 * properties are never invoked, and binary/error objects are not inspected.
 */
export function redact(
  value: unknown,
  options: RedactionOptions = {},
): unknown {
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  const maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
  if (!Number.isSafeInteger(maxDepth) || maxDepth < 0) {
    throw new RangeError("maxDepth must be a non-negative safe integer");
  }
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
    throw new RangeError("maxEntries must be a positive safe integer");
  }

  const seen = new WeakSet<object>();
  let entries = 0;

  const visit = (current: unknown, depth: number): unknown => {
    entries += 1;
    if (entries > maxEntries || depth > maxDepth) {
      return REDACTED_TRUNCATED;
    }

    if (typeof current === "string") {
      return redactText(current);
    }
    if (
      current === null ||
      typeof current === "boolean" ||
      typeof current === "number"
    ) {
      return current;
    }
    if (typeof current === "bigint") {
      return current.toString();
    }
    if (typeof current === "undefined") {
      return null;
    }
    if (typeof current === "function" || typeof current === "symbol") {
      return REDACTED;
    }
    if (current instanceof Date) {
      return Number.isNaN(current.getTime()) ? REDACTED : current.toISOString();
    }
    if (current instanceof Uint8Array || current instanceof ArrayBuffer) {
      return REDACTED_BINARY;
    }
    if (current instanceof Error) {
      return REDACTED;
    }
    if (seen.has(current)) {
      return REDACTED_CIRCULAR;
    }

    seen.add(current);
    if (Array.isArray(current)) {
      return current.map((item) => visit(item, depth + 1));
    }

    const prototype = Object.getPrototypeOf(current) as object | null;
    if (prototype !== Object.prototype && prototype !== null) {
      return REDACTED;
    }

    const result: Record<string, unknown> = {};
    const descriptors = Object.getOwnPropertyDescriptors(current);
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (!descriptor.enumerable) {
        continue;
      }
      if (isSensitiveKey(key) || !("value" in descriptor)) {
        result[key] = REDACTED;
      } else {
        result[key] = visit(descriptor.value, depth + 1);
      }
    }
    return result;
  };

  return visit(value, 0);
}
