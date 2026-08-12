import type {
  SshOutcome,
  SshRunner,
  SshRunInput,
} from "./ssh-runner.js";
import { SshExecutionError } from "./ssh-runner.js";

export class RoutingSshExecutor implements SshRunner {
  readonly #fallback: SshRunner;
  readonly #routes: ReadonlyMap<string, SshRunner>;
  #closed = false;
  #closeOperation: Promise<void> | undefined;

  public constructor(
    fallback: SshRunner,
    routes: ReadonlyMap<string, SshRunner>,
  ) {
    this.#fallback = fallback;
    this.#routes = new Map(routes);
  }

  public run(input: SshRunInput): Promise<SshOutcome> {
    if (this.#closed) {
      return Promise.reject(new SshExecutionError("the SSH executor is closed"));
    }
    return (this.#routes.get(input.sshAlias) ?? this.#fallback).run(input);
  }

  public close(): Promise<void> {
    this.#closed = true;
    if (this.#closeOperation !== undefined) return this.#closeOperation;

    const operation = closeRunners(
      new Set([this.#fallback, ...this.#routes.values()]),
    );
    this.#closeOperation = operation;
    void operation.catch(() => {
      if (this.#closeOperation === operation) {
        this.#closeOperation = undefined;
      }
    });
    return operation;
  }
}

async function closeRunners(runners: ReadonlySet<SshRunner>): Promise<void> {
  const results = await Promise.allSettled(
    [...runners].map(async (runner) => runner.close()),
  );
  const failures = results.flatMap((result) =>
    result.status === "rejected" ? [result.reason] : [],
  );
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) {
    throw new AggregateError(failures, "multiple SSH executors failed to close");
  }
}
