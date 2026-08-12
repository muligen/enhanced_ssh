import assert from "node:assert/strict";
import test from "node:test";

import { RoutingSshExecutor } from "../../src/infra/routing-ssh-executor.js";
import type {
  SshOutcome,
  SshRunner,
  SshRunInput,
} from "../../src/infra/ssh-runner.js";

class RecordingRunner implements SshRunner {
  public readonly calls: SshRunInput[] = [];
  public closeCalls = 0;
  readonly #outcome: SshOutcome;
  readonly #closeErrors: Error[];

  public constructor(
    outcome: SshOutcome,
    closeErrors: Error | readonly Error[] = [],
  ) {
    this.#outcome = outcome;
    this.#closeErrors = Array.isArray(closeErrors)
      ? [...closeErrors]
      : [closeErrors];
  }

  public run(input: SshRunInput): Promise<SshOutcome> {
    this.calls.push(input);
    return Promise.resolve(this.#outcome);
  }

  public async close(): Promise<void> {
    this.closeCalls += 1;
    const error = this.#closeErrors.shift();
    if (error !== undefined) throw error;
  }
}

test("routes configured AccessClient aliases and keeps OpenSSH as the fallback", async () => {
  const openSsh = new RecordingRunner(outcome(0, "openssh"));
  const accessClient = new RecordingRunner(outcome(23, "accessclient"));
  const router = new RoutingSshExecutor(
    openSsh,
    new Map([["internal-accessclient", accessClient]]),
  );

  const routed = await router.run({
    sshAlias: "internal-accessclient",
    command: "hostname",
  });
  const fallback = await router.run({
    sshAlias: "internal-openssh",
    command: "hostname",
  });

  assert.equal(routed.exitCode, 23);
  assert.equal(routed.stdout, "accessclient");
  assert.equal(fallback.exitCode, 0);
  assert.equal(fallback.stdout, "openssh");
  assert.equal(accessClient.calls.length, 1);
  assert.equal(openSsh.calls.length, 1);
});

test("never falls back after a routed AccessClient execution fails", async () => {
  const openSsh = new RecordingRunner(outcome(0, "must-not-run"));
  const accessClient = new RecordingRunner(
    outcome(255, "", "AccessClient shared session is not available.\n"),
  );
  const router = new RoutingSshExecutor(
    openSsh,
    new Map([["internal-accessclient", accessClient]]),
  );

  const result = await router.run({
    sshAlias: "internal-accessclient",
    command: "hostname",
  });

  assert.equal(result.exitCode, 255);
  assert.match(result.stderr, /shared session is not available/iu);
  assert.equal(accessClient.calls.length, 1);
  assert.equal(openSsh.calls.length, 0);
});

test("closes each distinct routed executor once and rejects later runs", async () => {
  const shared = new RecordingRunner(outcome(0, "shared"));
  const dedicated = new RecordingRunner(outcome(0, "dedicated"));
  const router = new RoutingSshExecutor(
    shared,
    new Map([
      ["same-as-fallback", shared],
      ["first-alias", dedicated],
      ["second-alias", dedicated],
    ]),
  );

  await Promise.all([router.close(), router.close()]);

  assert.equal(shared.closeCalls, 1);
  assert.equal(dedicated.closeCalls, 1);
  await assert.rejects(
    router.run({ sshAlias: "first-alias", command: "hostname" }),
    /executor is closed/iu,
  );
});

test("retries every distinct close after a transient child failure", async () => {
  const failing = new RecordingRunner(
    outcome(0, "failing"),
    new Error("close failed"),
  );
  const healthy = new RecordingRunner(outcome(0, "healthy"));
  const router = new RoutingSshExecutor(
    failing,
    new Map([["healthy", healthy]]),
  );

  const firstClose = router.close();
  assert.equal(router.close(), firstClose);
  await assert.rejects(
    router.run({ sshAlias: "healthy", command: "during-close" }),
    /executor is closed/iu,
  );
  await assert.rejects(firstClose, /close failed/iu);

  assert.equal(failing.closeCalls, 1);
  assert.equal(healthy.closeCalls, 1);
  await assert.rejects(
    router.run({ sshAlias: "healthy", command: "between-closes" }),
    /executor is closed/iu,
  );

  const successfulClose = router.close();
  assert.equal(router.close(), successfulClose);
  await successfulClose;

  assert.equal(failing.closeCalls, 2);
  assert.equal(healthy.closeCalls, 2);
  assert.equal(router.close(), successfulClose);
  await assert.rejects(
    router.run({ sshAlias: "healthy", command: "after-close" }),
    /executor is closed/iu,
  );
});

function outcome(
  exitCode: number,
  stdout: string,
  stderr = "",
): SshOutcome {
  return {
    exitCode,
    signal: null,
    stdout,
    stderr,
    stdoutBytes: Buffer.byteLength(stdout),
    stderrBytes: Buffer.byteLength(stderr),
    stdoutTruncated: false,
    stderrTruncated: false,
    aborted: false,
    durationMs: 1,
    terminationMode: null,
  };
}
