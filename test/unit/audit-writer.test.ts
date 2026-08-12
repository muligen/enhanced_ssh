import assert from "node:assert/strict";
import {
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  AuditSchemaError,
  type AuditEvent,
  type ExecStartedAuditEvent,
  AuditWriteError,
  AuditWriter,
} from "../../src/infra/audit-writer.js";

async function temporaryDirectory(): Promise<string> {
  return mkdtemp(join(tmpdir(), "agent-ssh-audit-"));
}

function executionId(sequence: number): string {
  return `00000000-0000-4000-8000-${sequence.toString(16).padStart(12, "0")}`;
}

function startedEvent(sequence: number): ExecStartedAuditEvent {
  return {
    event: "exec.started",
    executionId: executionId(sequence),
    target: "dev-linux",
    commandSha256: "a".repeat(64),
    commandBytes: 12,
  };
}

test("writes strict JSONL records serially under concurrent calls", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = join(directory, "audit", "events.jsonl");
  let eventSequence = 0;
  const writer = new AuditWriter({
    filePath,
    now: () => Date.UTC(2026, 7, 5, 1, 2, 3),
    createEventId: () => `event-${++eventSequence}`,
  });

  await Promise.all(
    Array.from({ length: 20 }, (_, sequence) =>
      writer.write(startedEvent(sequence)),
    ),
  );
  await writer.close();

  const lines = (await readFile(filePath, "utf8")).trim().split("\n");
  assert.equal(lines.length, 20);
  const records = lines.map((line) => JSON.parse(line) as Record<string, unknown>);
  assert.deepEqual(
    records.map((record) => record.executionId),
    Array.from({ length: 20 }, (_, index) => executionId(index)),
  );
  assert.equal(new Set(records.map((record) => record.eventId)).size, 20);
  assert.deepEqual(Object.keys(records[0]!), [
    "schemaVersion",
    "eventId",
    "timestamp",
    "event",
    "executionId",
    "target",
    "commandSha256",
    "commandBytes",
  ]);
});

test("rejects every field outside the event allowlist", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = join(directory, "events.jsonl");
  const writer = new AuditWriter({ filePath });
  const forbiddenFields = [
    "command",
    "stdout",
    "stderr",
    "output",
    "token",
    "outputRef",
    "path",
    "error",
    "requestId",
    "client",
  ];

  for (const field of forbiddenFields) {
    const malicious = {
      ...startedEvent(1),
      [field]: `secret-${field}`,
    } as unknown as AuditEvent;
    await assert.rejects(writer.write(malicious), AuditSchemaError);
  }

  await writer.write(startedEvent(2));
  await writer.close();
  const serialized = await readFile(filePath, "utf8");
  for (const field of forbiddenFields) {
    assert.equal(serialized.includes(`secret-${field}`), false);
  }
});

test("rejects client-controlled values outside audit identifier grammars", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = join(directory, "events.jsonl");
  const writer = new AuditWriter({ filePath });

  await assert.rejects(
    writer.write({
      ...startedEvent(1),
      executionId: "MY_CUSTOM_SECRET_123",
    }),
    AuditSchemaError,
  );
  await assert.rejects(
    writer.write({
      ...startedEvent(1),
      target: "password=hunter2",
    }),
    AuditSchemaError,
  );
  await writer.write(startedEvent(2));
  await writer.close();

  const serialized = await readFile(filePath, "utf8");
  assert.equal(serialized.includes("MY_CUSTOM_SECRET_123"), false);
  assert.equal(serialized.includes("hunter2"), false);
  assert.match(serialized, /"commandSha256":"a{64}"/);
  assert.match(serialized, /"commandBytes":12/);
});

test("exec.started is fail-closed when the audit destination cannot be opened", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const blockingFile = join(directory, "not-a-directory");
  await writeFile(blockingFile, "block", "utf8");
  const writer = new AuditWriter({
    filePath: join(blockingFile, "events.jsonl"),
  });
  let processStarted = false;

  await assert.rejects(
    (async () => {
      await writer.write(startedEvent(1));
      processStarted = true;
    })(),
    AuditWriteError,
  );
  assert.equal(processStarted, false);
});

test("completed records contain metrics but no output or references", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = join(directory, "events.jsonl");
  const writer = new AuditWriter({ filePath });

  await writer.write({
    event: "exec.completed",
    executionId: executionId(1),
    target: "dev-linux",
    termination: "exit",
    exitCode: 0,
    durationMs: 50,
    stdoutBytes: 1_024,
    stderrBytes: 4,
    truncated: true,
  });
  await writer.close();

  const record = JSON.parse(
    (await readFile(filePath, "utf8")).trim(),
  ) as Record<string, unknown>;
  assert.equal(record.stdoutBytes, 1_024);
  assert.equal(record.stderrBytes, 4);
  assert.equal(record.truncated, true);
  assert.equal("stdout" in record, false);
  assert.equal("stderr" in record, false);
  assert.equal("outputRef" in record, false);
});

test("transfer audit records expose metrics and codes but reject filesystem paths", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = join(directory, "events.jsonl");
  const writer = new AuditWriter({ filePath });
  const runId = "a".repeat(43);

  await writer.write({
    event: "transfer.started",
    runId,
    target: "dev-linux",
    direction: "upload",
    dryRun: false,
  });
  await writer.write({
    event: "transfer.completed",
    runId,
    target: "dev-linux",
    direction: "upload",
    files: 2,
    bytes: 4_096,
  });
  await writer.write({
    event: "transfer.failed",
    runId,
    target: "dev-linux",
    direction: "download",
    reasonCode: "checksum.mismatch",
  });
  await assert.rejects(
    writer.write({
      event: "transfer.started",
      runId,
      target: "dev-linux",
      direction: "sync",
      dryRun: false,
      remotePath: "/srv/private/project",
    } as unknown as AuditEvent),
    AuditSchemaError,
  );
  await writer.close();

  const serialized = await readFile(filePath, "utf8");
  assert.equal(serialized.includes("/srv/private/project"), false);
  assert.equal(serialized.includes("remotePath"), false);
  const records = serialized
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>);
  assert.deepEqual(
    records.map((record) => record.event),
    ["transfer.started", "transfer.completed", "transfer.failed"],
  );
  assert.equal(records[1]?.files, 2);
  assert.equal(records[1]?.bytes, 4_096);
});

test("reserves audit capacity for execution completion before admitting starts", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = join(directory, "events.jsonl");
  await writeFile(filePath, Buffer.alloc(49_000, 0x20));
  const writer = new AuditWriter({
    filePath,
    maxBytes: 65_536,
    maxConcurrentExecutions: 1,
  });

  await assert.rejects(writer.write(startedEvent(1)), AuditWriteError);
  await writer.write({
    event: "exec.completed",
    executionId: executionId(1),
    target: "dev-linux",
    termination: "spawn_error",
    exitCode: null,
    durationMs: 0,
    stdoutBytes: 0,
    stderrBytes: 0,
    truncated: false,
  });
  await writer.close();

  assert.ok((await stat(filePath)).size <= 65_536);
});
