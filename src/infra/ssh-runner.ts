import type { ProcessTerminationMode } from "./process-tree.js";
import type { TargetCheckFailureReason } from "../shared/protocol.js";

export type OutputStream = "stdout" | "stderr";
export type SshFailureReason = TargetCheckFailureReason;

export interface OutputSink {
  append(stream: OutputStream, chunk: Uint8Array): void | Promise<void>;
}

export interface SshRunInput {
  readonly sshAlias: string;
  readonly command: string;
  readonly stdin?: Uint8Array;
  readonly signal?: AbortSignal;
  readonly outputSink?: OutputSink;
  readonly maxCapturedOutputBytes?: number;
}

export interface SshOutcome {
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
  readonly stdoutTruncated: boolean;
  readonly stderrTruncated: boolean;
  readonly aborted: boolean;
  readonly durationMs: number;
  readonly terminationMode: ProcessTerminationMode | null;
  /** A closed, non-sensitive transport reason. Never place remote output here. */
  readonly failureReason?: SshFailureReason;
}

export interface SshRunner {
  run(input: SshRunInput): Promise<SshOutcome>;
  close(): Promise<void>;
}

export class SshExecutionError extends Error {
  public override readonly cause: unknown;

  public constructor(message: string, options?: { readonly cause?: unknown }) {
    super(message);
    this.name = "SshExecutionError";
    this.cause = options?.cause;
  }
}
