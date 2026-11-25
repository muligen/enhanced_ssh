import { readAdminDescriptor, type AdminDescriptor } from "../service/control-plane.js";
import {
  mcpAdminPolicySnapshotSchema,
  type McpAdminPolicySnapshot,
} from "../service/mcp-admin-policy.js";

const DEFAULT_ADMIN_TIMEOUT_MS = 60_000;
const SAFE_ERROR_CODE_PATTERN = /^[A-Z][A-Z0-9_]{1,63}$/u;

export class AdminApiError extends Error {
  public readonly status: number;
  public readonly code: string;

  public constructor(status: number, code: string, message: string) {
    super(`[${code}] ${message}`);
    this.name = "AdminApiError";
    this.status = status;
    this.code = code;
  }
}

export type AdminControlPlaneStatus =
  | Readonly<{
      serviceRunning: false;
      mcpAdminSupported: false;
      mcpAdminEnabled: false;
    }>
  | Readonly<{
      serviceRunning: true;
      mcpAdminSupported: false;
      mcpAdminEnabled: false;
    }>
  | Readonly<{
      serviceRunning: true;
      mcpAdminSupported: true;
      mcpAdminEnabled: boolean;
      policy: McpAdminPolicySnapshot;
    }>;

export interface AdminClient {
  status(signal?: AbortSignal): Promise<AdminControlPlaneStatus>;
  post<Result>(
    route: string,
    body: object,
    signal?: AbortSignal,
  ): Promise<Result>;
}

export interface AdminHttpClientOptions {
  readonly timeoutMs?: number;
  readonly fetchImpl?: typeof fetch;
  readonly readDescriptor?: () => Promise<AdminDescriptor | undefined>;
}

export function createAdminHttpClient(
  dataDirectory: string | undefined,
  options: AdminHttpClientOptions = {},
): AdminClient {
  const timeoutMs = options.timeoutMs ?? DEFAULT_ADMIN_TIMEOUT_MS;
  const fetchImpl = options.fetchImpl ?? fetch;
  const loadDescriptor =
    options.readDescriptor ??
    (async (): Promise<AdminDescriptor | undefined> => {
      if (dataDirectory === undefined) {
        return undefined;
      }
      try {
        return await readAdminDescriptor(dataDirectory);
      } catch {
        return undefined;
      }
    });

  const postWithDescriptor = async <Result>(
    descriptor: AdminDescriptor,
    route: string,
    body: object,
    signal?: AbortSignal,
  ): Promise<Result> => {
    const token = descriptor.mcpAdminToken;
    if (token === undefined) {
      throw new AdminApiError(
        501,
        "MCP_ADMIN_UNSUPPORTED",
        "The running SSH management service does not support MCP administration. Restart agent-ssh-service to enable MCP management support.",
      );
    }

    const timeoutSignal = AbortSignal.timeout(timeoutMs);
    const requestSignal =
      signal === undefined ? timeoutSignal : AbortSignal.any([signal, timeoutSignal]);

    let response: Response;
    try {
      response = await fetchImpl(`${descriptor.origin}${route}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Agent-SSH-MCP-Token": token,
        },
        body: JSON.stringify(body),
        redirect: "error",
        signal: requestSignal,
      });
    } catch (error) {
      if (signal?.aborted) {
        throw error;
      }
      if (timeoutSignal.aborted) {
        throw new AdminApiError(
          504,
          "ADMIN_REQUEST_TIMEOUT",
          "The local SSH management service did not respond in time.",
        );
      }
      throw new AdminApiError(
        503,
        "SERVICE_UNAVAILABLE",
        "Could not reach the local SSH management service. Ensure agent-ssh-service is running.",
      );
    }

    let payload: unknown;
    try {
      payload = (await response.json()) as unknown;
    } catch {
      if (!response.ok) {
        throw new AdminApiError(
          response.status,
          "ADMIN_REQUEST_FAILED",
          "The local SSH management service returned an invalid error response.",
        );
      }
      throw new AdminApiError(
        502,
        "ADMIN_INVALID_RESPONSE",
        "The local SSH management service returned a malformed response.",
      );
    }

    if (!response.ok) {
      throw problemToAdminError(response.status, payload);
    }

    return payload as Result;
  };

  return {
    async status(signal?: AbortSignal): Promise<AdminControlPlaneStatus> {
      const descriptor = await loadDescriptor();
      if (descriptor === undefined) {
        return {
          serviceRunning: false,
          mcpAdminSupported: false,
          mcpAdminEnabled: false,
        };
      }
      if (descriptor.mcpAdminToken === undefined) {
        return {
          serviceRunning: true,
          mcpAdminSupported: false,
          mcpAdminEnabled: false,
        };
      }
      try {
        const raw = await postWithDescriptor<unknown>(
          descriptor,
          "/api/admin/mcp-admin/status",
          {},
          signal,
        );
        const policy = mcpAdminPolicySnapshotSchema.parse(raw);
        return {
          serviceRunning: true,
          mcpAdminSupported: true,
          mcpAdminEnabled: policy.enabled,
          policy,
        };
      } catch (error) {
        if (
          error instanceof AdminApiError &&
          error.code === "SERVICE_UNAVAILABLE"
        ) {
          return {
            serviceRunning: false,
            mcpAdminSupported: false,
            mcpAdminEnabled: false,
          };
        }
        throw error;
      }
    },

    async post<Result>(
      route: string,
      body: object,
      signal?: AbortSignal,
    ): Promise<Result> {
      const descriptor = await loadDescriptor();
      if (descriptor === undefined) {
        throw new AdminApiError(
          503,
          "SERVICE_UNAVAILABLE",
          "SSH management service is not running. Start agent-ssh-service first.",
        );
      }
      return postWithDescriptor<Result>(descriptor, route, body, signal);
    },
  };
}

function problemToAdminError(status: number, payload: unknown): AdminApiError {
  if (typeof payload === "object" && payload !== null && !Array.isArray(payload)) {
    const errorValue = (payload as Record<string, unknown>).error;
    if (
      typeof errorValue === "object" &&
      errorValue !== null &&
      !Array.isArray(errorValue)
    ) {
      const record = errorValue as Record<string, unknown>;
      const rawCode = record.code;
      const rawMessage = record.message;
      const code =
        typeof rawCode === "string" && SAFE_ERROR_CODE_PATTERN.test(rawCode)
          ? rawCode
          : "ADMIN_REQUEST_FAILED";
      const message =
        typeof rawMessage === "string" && rawMessage.trim().length > 0
          ? rawMessage.slice(0, 512)
          : "The local SSH management service rejected the request.";
      return new AdminApiError(status, code, message);
    }
  }
  return new AdminApiError(
    status,
    "ADMIN_REQUEST_FAILED",
    "The local SSH management service rejected the request.",
  );
}
