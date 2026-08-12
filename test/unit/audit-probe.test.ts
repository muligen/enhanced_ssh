import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  AuditSchemaError,
  AuditWriter,
  type AuditEvent,
} from "../../src/infra/audit-writer.js";

test("probe audit records contain only bounded public result metadata", async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), "agent-ssh-probe-audit-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, "events.jsonl");
  const writer = new AuditWriter({
    filePath,
    now: () => Date.UTC(2026, 7, 7, 8, 9, 10),
    createEventId: () => "probe-event-1",
  });

  await writer.write({
    event: "probe.completed",
    target: "managed-ssh",
    probeKind: "target-info",
    durationMs: 17,
    resultCode: "success",
  });
  await assert.rejects(
    writer.write({
      event: "probe.completed",
      target: "managed-ssh",
      probeKind: "target-info",
      durationMs: 17,
      resultCode: "success",
      nativeMachineId: "00112233445566778899aabbccddeeff",
    } as unknown as AuditEvent),
    AuditSchemaError,
  );
  await writer.close();

  const record = JSON.parse(
    (await readFile(filePath, "utf8")).trim(),
  ) as Record<string, unknown>;
  assert.deepEqual(Object.keys(record), [
    "schemaVersion",
    "eventId",
    "timestamp",
    "event",
    "target",
    "probeKind",
    "durationMs",
    "resultCode",
  ]);
  assert.equal(JSON.stringify(record).includes("nativeMachineId"), false);
});
