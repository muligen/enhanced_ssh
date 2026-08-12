export const JSON_RPC_ERROR_CODES = {
  parseError: -32700,
  invalidRequest: -32600,
  methodNotFound: -32601,
  invalidParams: -32602,
  internalError: -32603,
} as const;

export const GATEWAY_ERROR_CODES = {
  invalidParams: "INVALID_PARAMS",
  unauthorized: "UNAUTHORIZED",
  protocolVersionMismatch: "PROTOCOL_VERSION_MISMATCH",
  configInvalid: "CONFIG_INVALID",
  daemonNotActive: "DAEMON_NOT_ACTIVE",
  targetNotFound: "TARGET_NOT_FOUND",
  targetDisabled: "TARGET_DISABLED",
  commandDenied: "COMMAND_DENIED",
  executionNotFound: "EXECUTION_NOT_FOUND",
  executionLimitReached: "EXECUTION_LIMIT_REACHED",
  transferDenied: "TRANSFER_DENIED",
  transferFailed: "TRANSFER_FAILED",
  checksumMismatch: "CHECKSUM_MISMATCH",
  sftpUnavailable: "SFTP_UNAVAILABLE",
  probeFailed: "PROBE_FAILED",
  outputNotFound: "OUTPUT_NOT_FOUND",
  outputExpired: "OUTPUT_EXPIRED",
  auditUnavailable: "AUDIT_UNAVAILABLE",
  internalError: "INTERNAL_ERROR",
} as const;

export type GatewayErrorCode =
  (typeof GATEWAY_ERROR_CODES)[keyof typeof GATEWAY_ERROR_CODES];

const RPC_CODE_BY_GATEWAY_CODE: Readonly<Record<GatewayErrorCode, number>> = {
  INVALID_PARAMS: JSON_RPC_ERROR_CODES.invalidParams,
  UNAUTHORIZED: -32001,
  PROTOCOL_VERSION_MISMATCH: -32002,
  CONFIG_INVALID: -32010,
  DAEMON_NOT_ACTIVE: -32011,
  TARGET_NOT_FOUND: -32020,
  TARGET_DISABLED: -32021,
  COMMAND_DENIED: -32022,
  EXECUTION_NOT_FOUND: -32030,
  EXECUTION_LIMIT_REACHED: -32031,
  TRANSFER_DENIED: -32032,
  TRANSFER_FAILED: -32033,
  CHECKSUM_MISMATCH: -32034,
  SFTP_UNAVAILABLE: -32035,
  PROBE_FAILED: -32036,
  OUTPUT_NOT_FOUND: -32040,
  OUTPUT_EXPIRED: -32041,
  AUDIT_UNAVAILABLE: -32050,
  INTERNAL_ERROR: JSON_RPC_ERROR_CODES.internalError,
};

export interface GatewayErrorOptions extends ErrorOptions {
  readonly rpcCode?: number;
  readonly details?: Readonly<Record<string, string | number | boolean | null>>;
}

/**
 * An expected gateway failure with a stable, non-sensitive public message.
 * Callers must not put commands, output, credentials, or filesystem paths in
 * message/details because these values may cross the IPC boundary.
 */
export class GatewayError extends Error {
  public readonly code: GatewayErrorCode;
  public readonly rpcCode: number;
  public readonly details?: Readonly<
    Record<string, string | number | boolean | null>
  >;

  public constructor(
    code: GatewayErrorCode,
    message: string,
    options: GatewayErrorOptions = {},
  ) {
    super(message, options);
    this.name = "GatewayError";
    this.code = code;
    this.rpcCode = options.rpcCode ?? RPC_CODE_BY_GATEWAY_CODE[code];
    if (options.details !== undefined) {
      this.details = Object.freeze({ ...options.details });
    }
  }
}

export interface PublicErrorDescriptor {
  readonly code: number;
  readonly message: string;
  readonly data: Readonly<{
    gatewayCode: GatewayErrorCode;
    details?: Readonly<Record<string, string | number | boolean | null>>;
  }>;
}

export function toPublicError(error: unknown): PublicErrorDescriptor {
  if (error instanceof GatewayError) {
    return {
      code: error.rpcCode,
      message: error.message,
      data:
        error.details === undefined
          ? { gatewayCode: error.code }
          : { gatewayCode: error.code, details: error.details },
    };
  }

  return {
    code: JSON_RPC_ERROR_CODES.internalError,
    message: "Internal gateway error",
    data: { gatewayCode: GATEWAY_ERROR_CODES.internalError },
  };
}
