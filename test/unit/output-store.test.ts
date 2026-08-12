import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  OutputExpiredError,
  OutputLimitExceededError,
  OutputNotFoundError,
  OutputStore,
  OutputStoreIoError,
} from "../../src/core/output-store.js";

async function temporaryDirectory(): Promise<string> {
  return mkdtemp(join(tmpdir(), "agent-ssh-output-store-"));
}

interface TestOutputMetadata {
  readonly version: 1;
  readonly expiresAtMs: number;
  readonly stdoutBytes: number;
  readonly stderrBytes: number;
}

async function writeRetainedEntry(
  directory: string,
  reference: string,
  metadata: TestOutputMetadata,
  payloads: {
    readonly stdout?: string;
    readonly stderr?: string;
  } = {},
): Promise<string> {
  const entryDirectory = join(directory, reference);
  await mkdir(entryDirectory);
  await writeFile(
    join(entryDirectory, "metadata.json"),
    `${JSON.stringify(metadata)}\n`,
  );
  if (payloads.stdout !== undefined) {
    await writeFile(join(entryDirectory, "stdout.bin"), payloads.stdout);
  }
  if (payloads.stderr !== undefined) {
    await writeFile(join(entryDirectory, "stderr.bin"), payloads.stderr);
  }
  return entryDirectory;
}

test("spools from the first byte and enforces an inline cap per stream", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = await OutputStore.open({
    directory,
    inlineBytesPerStream: 3,
    maxStoredBytes: 100,
    maxTotalRetainedBytes: 100,
    maxRetainedEntries: 100,
    ttlMs: 60_000,
    maxReadBytes: 4,
  });
  const sink = await store.create("request-visible-name");

  await sink.append("stdout", Buffer.from("abcdef"));
  const reservedEntries = await readdir(directory);
  assert.equal(reservedEntries.length, 1);
  assert.equal(
    await readFile(join(directory, reservedEntries[0]!, "stdout.bin"), "utf8"),
    "abcdef",
  );

  await sink.append("stderr", Buffer.from("WXYZ"));
  const result = await sink.finalize();
  assert.deepEqual(result.stdout, {
    text: "abc",
    bytes: 6,
    inlineTruncated: true,
  });
  assert.deepEqual(result.stderr, {
    text: "WXY",
    bytes: 4,
    inlineTruncated: true,
  });
  assert.ok(result.outputRef);
  assert.match(result.outputRef, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(result.outputRef.includes("request-visible-name"), false);
  assert.equal(result.outputRef.includes("/"), false);

  const first = await store.read(result.outputRef, "stdout", 0, 2);
  assert.deepEqual(first, {
    dataBase64: Buffer.from("ab").toString("base64"),
    nextOffset: 2,
    eof: false,
    totalBytes: 6,
  });
  const second = await store.read(result.outputRef, "stdout", 2, 4);
  assert.deepEqual(second, {
    dataBase64: Buffer.from("cdef").toString("base64"),
    nextOffset: null,
    eof: true,
    totalBytes: 6,
  });
});

test("does not expose a partial UTF-8 code point in truncated inline text", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = await OutputStore.open({
    directory,
    inlineBytesPerStream: 2,
    maxStoredBytes: 100,
    maxTotalRetainedBytes: 100,
    maxRetainedEntries: 100,
    ttlMs: 60_000,
    maxReadBytes: 4,
  });
  const sink = await store.create("utf8-inline-boundary");
  await sink.append("stdout", Buffer.from("中x", "utf8"));

  const result = await sink.finalize();
  assert.deepEqual(result.stdout, {
    text: "",
    bytes: 4,
    inlineTruncated: true,
  });
  assert.equal(result.stdout.text.includes("\ufffd"), false);
  assert.ok(result.outputRef);

  const full = await store.read(result.outputRef, "stdout", 0, 4);
  assert.equal(
    new TextDecoder("utf-8", { fatal: true }).decode(
      Buffer.from(full.dataBase64, "base64"),
    ),
    "中x",
  );
});

test("hard-caps legacy inline settings at 8 KiB and retains the full output", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = await OutputStore.open({
    directory,
    inlineBytesPerStream: 65_536,
    maxStoredBytes: 20_000,
    maxTotalRetainedBytes: 20_000,
    maxRetainedEntries: 10,
    ttlMs: 60_000,
  });
  const sink = await store.create("legacy-large-inline-setting");
  const payload = Buffer.alloc(8_193, 0x61);
  await sink.append("stdout", payload);
  const result = await sink.finalize();

  assert.equal(Buffer.byteLength(result.stdout.text, "utf8"), 8_192);
  assert.equal(result.stdout.inlineTruncated, true);
  assert.ok(result.outputRef);
  const retained = await store.read(result.outputRef, "stdout", 0, payload.length);
  assert.deepEqual(Buffer.from(retained.dataBase64, "base64"), payload);
});

test("keeps output.read byte-exact across UTF-8 boundaries", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = await OutputStore.open({
    directory,
    inlineBytesPerStream: 1,
    maxStoredBytes: 100,
    maxTotalRetainedBytes: 100,
    maxRetainedEntries: 100,
    ttlMs: 60_000,
    maxReadBytes: 4,
  });
  const sink = await store.create("utf8-page-boundary");
  await sink.append("stdout", Buffer.from("ab中😀z", "utf8"));
  const result = await sink.finalize();
  assert.ok(result.outputRef);

  const payload = Buffer.from("ab中😀z", "utf8");
  const expectedPages = [
    { offset: 0, bytes: payload.subarray(0, 4), nextOffset: 4 },
    { offset: 4, bytes: payload.subarray(4, 8), nextOffset: 8 },
    { offset: 8, bytes: payload.subarray(8, 10), nextOffset: null },
  ] as const;
  for (const expected of expectedPages) {
    const page = await store.read(
      result.outputRef,
      "stdout",
      expected.offset,
      4,
    );
    assert.deepEqual(Buffer.from(page.dataBase64, "base64"), expected.bytes);
    assert.equal(page.nextOffset, expected.nextOffset);
  }

  const arbitraryByte = await store.read(result.outputRef, "stdout", 3, 1);
  assert.deepEqual(
    Buffer.from(arbitraryByte.dataBase64, "base64"),
    payload.subarray(3, 4),
  );
  assert.equal(arbitraryByte.nextOffset, 4);
});

test("removes the spool when both streams fit inline", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = await OutputStore.open({
    directory,
    inlineBytesPerStream: 16,
    maxStoredBytes: 100,
    maxTotalRetainedBytes: 100,
    maxRetainedEntries: 100,
    ttlMs: 60_000,
  });
  const sink = await store.create(7);
  await sink.append("stdout", Buffer.from("small"));

  const result = await sink.finalize();
  assert.deepEqual(result, {
    stdout: { text: "small", bytes: 5, inlineTruncated: false },
    stderr: { text: "", bytes: 0, inlineTruncated: false },
  });
  assert.deepEqual(await readdir(directory), []);
});

test("throws a typed error before exceeding the aggregate hard limit", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = await OutputStore.open({
    directory,
    inlineBytesPerStream: 2,
    maxStoredBytes: 5,
    maxTotalRetainedBytes: 100,
    maxRetainedEntries: 100,
    ttlMs: 60_000,
  });
  const sink = await store.create("limit-request");
  await sink.append("stdout", Buffer.from("abc"));

  await assert.rejects(
    sink.append("stderr", Buffer.from("def")),
    (error: unknown) => {
      assert.ok(error instanceof OutputLimitExceededError);
      assert.equal(error.maxBytes, 5);
      assert.equal(error.currentBytes, 3);
      assert.equal(error.attemptedBytes, 3);
      return true;
    },
  );

  const result = await sink.finalize();
  assert.equal(result.stdout.bytes, 3);
  assert.equal(result.stderr.bytes, 2);
  assert.equal(result.stderr.text, "de");
  assert.ok(result.outputRef);
  const page = await store.read(result.outputRef, "stdout", 0, 5);
  assert.equal(Buffer.from(page.dataBase64, "base64").toString("utf8"), "abc");
  const stderrPage = await store.read(result.outputRef, "stderr", 0, 5);
  assert.equal(
    Buffer.from(stderrPage.dataBase64, "base64").toString("utf8"),
    "de",
  );
});

test("rejects forged and expired references without exposing storage paths", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  let now = 1_000;
  const store = await OutputStore.open({
    directory,
    inlineBytesPerStream: 0,
    maxStoredBytes: 100,
    maxTotalRetainedBytes: 100,
    maxRetainedEntries: 100,
    ttlMs: 10,
    now: () => now,
  });
  const sink = await store.create("ttl-request");
  await sink.append("stdout", Buffer.from("x"));
  const result = await sink.finalize();
  assert.ok(result.outputRef);

  await assert.rejects(
    store.read("A".repeat(43), "stdout", 0, 1),
    OutputNotFoundError,
  );
  await assert.rejects(
    store.read("../metadata.json", "stdout", 0, 1),
    OutputNotFoundError,
  );

  now = 1_011;
  await assert.rejects(
    store.read(result.outputRef, "stdout", 0, 1),
    (error: unknown) => {
      assert.ok(error instanceof OutputExpiredError);
      assert.equal(error.message.includes(directory), false);
      assert.equal(error.message.includes(result.outputRef!), false);
      return true;
    },
  );
  assert.deepEqual(await readdir(directory), []);
});

test("startup cleanup removes expired and incomplete entries", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  let now = 5_000;
  const firstStore = await OutputStore.open({
    directory,
    inlineBytesPerStream: 0,
    maxStoredBytes: 100,
    maxTotalRetainedBytes: 100,
    maxRetainedEntries: 100,
    ttlMs: 10,
    now: () => now,
  });
  const retained = await firstStore.create("retained");
  await retained.append("stdout", Buffer.from("retained"));
  const retainedResult = await retained.finalize();
  assert.ok(retainedResult.outputRef);

  await firstStore.create("incomplete");
  assert.equal((await readdir(directory)).length, 2);
  now = 5_011;

  const restartedStore = await OutputStore.open({
    directory,
    inlineBytesPerStream: 0,
    maxStoredBytes: 100,
    maxTotalRetainedBytes: 100,
    maxRetainedEntries: 100,
    ttlMs: 10,
    now: () => now,
  });
  assert.deepEqual(await readdir(directory), []);
  await assert.rejects(
    restartedStore.read(retainedResult.outputRef, "stdout", 0, 1),
    OutputNotFoundError,
  );
});

test("cleanup skips output entries that are still being written", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = await OutputStore.open({
    directory,
    inlineBytesPerStream: 16,
    maxStoredBytes: 100,
    maxTotalRetainedBytes: 100,
    maxRetainedEntries: 100,
    ttlMs: 60_000,
  });
  const sink = await store.create("active");
  await sink.append("stdout", Buffer.from("in progress"));

  assert.equal(await store.cleanupExpired(), 0);
  const result = await sink.finalize();
  assert.equal(result.stdout.text, "in progress");
});

test("enforces the total retained byte quota atomically across concurrent sinks", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = await OutputStore.open({
    directory,
    inlineBytesPerStream: 0,
    maxStoredBytes: 10,
    maxTotalRetainedBytes: 5,
    maxRetainedEntries: 10,
    ttlMs: 60_000,
  });
  const first = await store.create("concurrent-first");
  const second = await store.create("concurrent-second");

  const writes = await Promise.allSettled([
    first.append("stdout", Buffer.from("aaaa")),
    second.append("stderr", Buffer.from("bbbb")),
  ]);

  assert.equal(writes[0]!.status, "fulfilled");
  assert.equal(writes[1]!.status, "rejected");
  if (writes[1]!.status === "rejected") {
    const error = writes[1]!.reason as unknown;
    assert.ok(error instanceof OutputLimitExceededError);
    assert.equal(error.maxBytes, 5);
    assert.equal(error.currentBytes, 4);
    assert.equal(error.attemptedBytes, 4);
  }

  const summaries = await Promise.all([first.finalize(), second.finalize()]);
  assert.equal(
    summaries.reduce(
      (bytes, summary) =>
        bytes + summary.stdout.bytes + summary.stderr.bytes,
      0,
    ),
    5,
  );
  assert.ok(summaries.every((summary) => summary.outputRef !== undefined));

  const blocked = await store.create("concurrent-blocked");
  await assert.rejects(
    blocked.append("stdout", Buffer.from("x")),
    (error: unknown) => {
      assert.ok(error instanceof OutputLimitExceededError);
      assert.equal(error.maxBytes, 5);
      assert.equal(error.currentBytes, 5);
      assert.equal(error.attemptedBytes, 1);
      return true;
    },
  );
  await blocked.abort();
});

test("enforces the retained entry quota atomically across concurrent sinks", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = await OutputStore.open({
    directory,
    inlineBytesPerStream: 0,
    maxStoredBytes: 10,
    maxTotalRetainedBytes: 100,
    maxRetainedEntries: 1,
    ttlMs: 60_000,
  });
  const first = await store.create("entry-first");
  const second = await store.create("entry-second");

  const writes = await Promise.allSettled([
    first.append("stdout", Buffer.from("a")),
    second.append("stderr", Buffer.from("b")),
  ]);
  assert.equal(
    writes.filter((result) => result.status === "fulfilled").length,
    1,
  );
  const rejectedWrite = writes.find((result) => result.status === "rejected");
  assert.ok(rejectedWrite);
  assert.equal(rejectedWrite.status, "rejected");
  const error = rejectedWrite.reason as unknown;
  assert.ok(error instanceof OutputLimitExceededError);
  assert.equal(error.limitKind, "entries");
  assert.equal(error.maxBytes, 1);
  assert.equal(error.currentBytes, 1);
  assert.equal(error.attemptedBytes, 1);

  const summaries = await Promise.all([first.finalize(), second.finalize()]);
  assert.equal(
    summaries.filter((summary) => summary.outputRef !== undefined).length,
    1,
  );

  const blocked = await store.create("entry-still-retained");
  await assert.rejects(
    blocked.append("stdout", Buffer.from("x")),
    (blockedError: unknown) => {
      assert.ok(blockedError instanceof OutputLimitExceededError);
      assert.equal(blockedError.limitKind, "entries");
      return true;
    },
  );
  await blocked.abort();
});

test("returns total quota after inline finalize, abort, and storage failure", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = await OutputStore.open({
    directory,
    inlineBytesPerStream: 3,
    maxStoredBytes: 10,
    maxTotalRetainedBytes: 3,
    maxRetainedEntries: 1,
    ttlMs: 60_000,
  });

  const inline = await store.create("inline-release");
  await inline.append("stdout", Buffer.from("abc"));
  const inlineSummary = await inline.finalize();
  assert.equal(inlineSummary.outputRef, undefined);

  const aborted = await store.create("abort-release");
  await aborted.append("stdout", Buffer.from("def"));
  await aborted.abort();

  const failed = await store.create("failure-release");
  const [failedDirectory] = await readdir(directory);
  assert.ok(failedDirectory);
  await rm(join(directory, failedDirectory), { recursive: true, force: true });
  await assert.rejects(
    failed.append("stdout", Buffer.from("ghi")),
    OutputStoreIoError,
  );
  await failed.abort();

  const afterFailure = await store.create("after-failure");
  await afterFailure.append("stdout", Buffer.from("jkl"));
  const finalSummary = await afterFailure.finalize();
  assert.equal(finalSummary.stdout.text, "jkl");
  assert.equal(finalSummary.outputRef, undefined);
});

test("cancel quarantines a file sink until abort cleans it up", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = await OutputStore.open({
    directory,
    inlineBytesPerStream: 0,
    maxStoredBytes: 3,
    maxTotalRetainedBytes: 3,
    maxRetainedEntries: 1,
    ttlMs: 60_000,
  });
  const cancelled = await store.create("cancelled");
  await cancelled.append("stdout", Buffer.from("abc"));

  cancelled.cancel();
  await assert.rejects(
    cancelled.append("stdout", Buffer.from("x")),
    /closed/iu,
  );
  await assert.rejects(cancelled.finalize(), /closed/iu);
  await cancelled.abort();

  const replacement = await store.create("replacement");
  await replacement.append("stdout", Buffer.from("xyz"));
  const summary = await replacement.finalize();
  assert.equal(summary.stdout.bytes, 3);
});

test("retains each entry slot until expired output is removed by read or cleanup", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  let now = 100;
  const store = await OutputStore.open({
    directory,
    inlineBytesPerStream: 0,
    maxStoredBytes: 10,
    maxTotalRetainedBytes: 3,
    maxRetainedEntries: 1,
    ttlMs: 10,
    now: () => now,
  });

  const readExpired = await store.create("read-expired");
  await readExpired.append("stdout", Buffer.from("abc"));
  const readExpiredSummary = await readExpired.finalize();
  assert.ok(readExpiredSummary.outputRef);

  const blockedBeforeRead = await store.create("blocked-before-read");
  await assert.rejects(
    blockedBeforeRead.append("stdout", Buffer.from("x")),
    (error: unknown) => {
      assert.ok(error instanceof OutputLimitExceededError);
      assert.equal(error.limitKind, "entries");
      return true;
    },
  );
  await blockedBeforeRead.abort();

  now = 111;
  await assert.rejects(
    store.read(readExpiredSummary.outputRef, "stdout", 0, 3),
    OutputExpiredError,
  );

  const cleanupExpired = await store.create("cleanup-expired");
  await cleanupExpired.append("stdout", Buffer.from("def"));
  const cleanupExpiredSummary = await cleanupExpired.finalize();
  assert.ok(cleanupExpiredSummary.outputRef);

  const blockedBeforeCleanup = await store.create("blocked-before-cleanup");
  await assert.rejects(
    blockedBeforeCleanup.append("stdout", Buffer.from("x")),
    (error: unknown) => {
      assert.ok(error instanceof OutputLimitExceededError);
      assert.equal(error.limitKind, "entries");
      return true;
    },
  );
  await blockedBeforeCleanup.abort();

  now = 122;
  assert.equal(await store.cleanupExpired(), 1);
  const afterCleanup = await store.create("after-cleanup");
  await afterCleanup.append("stdout", Buffer.from("ghi"));
  await afterCleanup.abort();
});

test("restart scans retained bytes and evicts the earliest expiry after a quota reduction", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  let now = 1_000;
  const original = await OutputStore.open({
    directory,
    inlineBytesPerStream: 0,
    maxStoredBytes: 10,
    maxTotalRetainedBytes: 20,
    maxRetainedEntries: 10,
    ttlMs: 100,
    now: () => now,
  });

  const first = await original.create("restart-first");
  await first.append("stdout", Buffer.from("aaaa"));
  const firstSummary = await first.finalize();
  assert.ok(firstSummary.outputRef);

  now = 1_010;
  const second = await original.create("restart-second");
  await second.append("stdout", Buffer.from("bbbb"));
  const secondSummary = await second.finalize();
  assert.ok(secondSummary.outputRef);

  now = 1_020;
  const third = await original.create("restart-third");
  await third.append("stdout", Buffer.from("cccc"));
  const thirdSummary = await third.finalize();
  assert.ok(thirdSummary.outputRef);
  await original.create("restart-incomplete");

  now = 1_030;
  const restarted = await OutputStore.open({
    directory,
    inlineBytesPerStream: 0,
    maxStoredBytes: 10,
    maxTotalRetainedBytes: 8,
    maxRetainedEntries: 10,
    ttlMs: 100,
    now: () => now,
  });

  await assert.rejects(
    restarted.read(firstSummary.outputRef, "stdout", 0, 4),
    OutputNotFoundError,
  );
  assert.equal(
    Buffer.from(
      (await restarted.read(secondSummary.outputRef, "stdout", 0, 4))
        .dataBase64,
      "base64",
    ).toString("utf8"),
    "bbbb",
  );
  assert.equal(
    Buffer.from(
      (await restarted.read(thirdSummary.outputRef, "stdout", 0, 4))
        .dataBase64,
      "base64",
    ).toString("utf8"),
    "cccc",
  );
  assert.deepEqual(
    (await readdir(directory)).sort(),
    [secondSummary.outputRef, thirdSummary.outputRef].sort(),
  );

  const blocked = await restarted.create("restart-blocked");
  await assert.rejects(
    blocked.append("stdout", Buffer.from("x")),
    (error: unknown) => {
      assert.ok(error instanceof OutputLimitExceededError);
      assert.equal(error.maxBytes, 8);
      assert.equal(error.currentBytes, 8);
      return true;
    },
  );
  await blocked.abort();
});

test("read releases quota only after confirming the reference directory is absent", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = await OutputStore.open({
    directory,
    inlineBytesPerStream: 0,
    maxStoredBytes: 10,
    maxTotalRetainedBytes: 100,
    maxRetainedEntries: 1,
    ttlMs: 60_000,
  });

  const deleted = await store.create("deleted-reference");
  await deleted.append("stdout", Buffer.from("a"));
  const deletedSummary = await deleted.finalize();
  assert.ok(deletedSummary.outputRef);
  await rm(join(directory, deletedSummary.outputRef), {
    recursive: true,
    force: true,
  });
  await assert.rejects(
    store.read(deletedSummary.outputRef, "stdout", 0, 1),
    OutputNotFoundError,
  );

  const incomplete = await store.create("missing-payload");
  await incomplete.append("stdout", Buffer.from("b"));
  const incompleteSummary = await incomplete.finalize();
  assert.ok(incompleteSummary.outputRef);
  await rm(join(directory, incompleteSummary.outputRef, "stdout.bin"));
  await assert.rejects(
    store.read(incompleteSummary.outputRef, "stdout", 0, 1),
    OutputNotFoundError,
  );

  const blocked = await store.create("blocked-by-incomplete-reference");
  await assert.rejects(
    blocked.append("stdout", Buffer.from("c")),
    (error: unknown) => {
      assert.ok(error instanceof OutputLimitExceededError);
      assert.equal(error.limitKind, "entries");
      return true;
    },
  );
  await blocked.abort();

  assert.equal(await store.cleanupExpired(), 1);
  const afterCleanup = await store.create("after-incomplete-cleanup");
  await afterCleanup.append("stdout", Buffer.from("d"));
  await afterCleanup.abort();
});

test("restart evicts the earliest expiry when the retained entry cap is reduced", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  let now = 2_000;
  const original = await OutputStore.open({
    directory,
    inlineBytesPerStream: 0,
    maxStoredBytes: 10,
    maxTotalRetainedBytes: 100,
    maxRetainedEntries: 3,
    ttlMs: 1_000,
    now: () => now,
  });

  const first = await original.create("entry-restart-first");
  await first.append("stdout", Buffer.from("a"));
  const firstSummary = await first.finalize();
  assert.ok(firstSummary.outputRef);

  now = 2_010;
  const second = await original.create("entry-restart-second");
  await second.append("stdout", Buffer.from("b"));
  const secondSummary = await second.finalize();
  assert.ok(secondSummary.outputRef);

  now = 2_020;
  const third = await original.create("entry-restart-third");
  await third.append("stdout", Buffer.from("c"));
  const thirdSummary = await third.finalize();
  assert.ok(thirdSummary.outputRef);

  now = 2_030;
  const restarted = await OutputStore.open({
    directory,
    inlineBytesPerStream: 0,
    maxStoredBytes: 10,
    maxTotalRetainedBytes: 100,
    maxRetainedEntries: 2,
    ttlMs: 1_000,
    now: () => now,
  });

  await assert.rejects(
    restarted.read(firstSummary.outputRef, "stdout", 0, 1),
    OutputNotFoundError,
  );
  assert.equal(
    Buffer.from(
      (await restarted.read(secondSummary.outputRef, "stdout", 0, 1))
        .dataBase64,
      "base64",
    ).toString("utf8"),
    "b",
  );
  assert.equal(
    Buffer.from(
      (await restarted.read(thirdSummary.outputRef, "stdout", 0, 1))
        .dataBase64,
      "base64",
    ).toString("utf8"),
    "c",
  );
  assert.deepEqual(
    (await readdir(directory)).sort(),
    [secondSummary.outputRef, thirdSummary.outputRef].sort(),
  );

  const blocked = await restarted.create("entry-restart-blocked");
  await assert.rejects(
    blocked.append("stdout", Buffer.from("d")),
    (error: unknown) => {
      assert.ok(error instanceof OutputLimitExceededError);
      assert.equal(error.limitKind, "entries");
      return true;
    },
  );
  await blocked.abort();
});

test("startup removes malformed retained entries and unexpected root files", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const validReference = "V".repeat(43);
  const underReportedReference = "U".repeat(43);
  const overReportedReference = "O".repeat(43);
  const nonRegularReference = "N".repeat(43);
  const extraFileReference = "E".repeat(43);
  const expiresAtMs = 10_000;

  await writeRetainedEntry(
    directory,
    validReference,
    { version: 1, expiresAtMs, stdoutBytes: 5, stderrBytes: 0 },
    { stdout: "valid" },
  );
  await writeRetainedEntry(
    directory,
    underReportedReference,
    { version: 1, expiresAtMs, stdoutBytes: 2, stderrBytes: 0 },
    { stdout: "abc" },
  );
  await writeRetainedEntry(
    directory,
    overReportedReference,
    { version: 1, expiresAtMs, stdoutBytes: 4, stderrBytes: 0 },
    { stdout: "abc" },
  );
  const nonRegularDirectory = await writeRetainedEntry(
    directory,
    nonRegularReference,
    { version: 1, expiresAtMs, stdoutBytes: 1, stderrBytes: 0 },
  );
  await mkdir(join(nonRegularDirectory, "stdout.bin"));
  const extraFileDirectory = await writeRetainedEntry(
    directory,
    extraFileReference,
    { version: 1, expiresAtMs, stdoutBytes: 1, stderrBytes: 0 },
    { stdout: "x" },
  );
  await writeFile(join(extraFileDirectory, "unexpected.tmp"), "unexpected");
  await writeFile(join(directory, "unexpected-root.tmp"), "unexpected");

  const store = await OutputStore.open({
    directory,
    inlineBytesPerStream: 0,
    maxStoredBytes: 10,
    maxTotalRetainedBytes: 100,
    maxRetainedEntries: 10,
    ttlMs: 1_000,
    now: () => 1_000,
  });

  assert.deepEqual(await readdir(directory), [validReference]);
  assert.equal(
    Buffer.from(
      (await store.read(validReference, "stdout", 0, 5)).dataBase64,
      "base64",
    ).toString("utf8"),
    "valid",
  );
});

test("fixed random collisions do not untrack or delete an active sink", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  let referenceCalls = 0;
  const store = await OutputStore.open({
    directory,
    inlineBytesPerStream: 0,
    maxStoredBytes: 10,
    maxTotalRetainedBytes: 100,
    maxRetainedEntries: 10,
    ttlMs: 60_000,
    randomBytes: (size) => {
      if (size === 32) {
        referenceCalls += 1;
      }
      return Buffer.alloc(size, 0x5a);
    },
  });

  const first = await store.create("fixed-first");
  await first.append("stdout", Buffer.from("active"));
  await assert.rejects(store.create("fixed-second"), OutputStoreIoError);
  assert.equal(referenceCalls, 9);
  assert.equal(await store.cleanupExpired(), 0);
  assert.equal((await readdir(directory)).length, 1);

  const summary = await first.finalize();
  assert.ok(summary.outputRef);
  assert.equal(
    Buffer.from(
      (await store.read(summary.outputRef, "stdout", 0, 6)).dataBase64,
      "base64",
    ).toString("utf8"),
    "active",
  );
});

test("does not reuse a retained reference whose directory disappeared externally", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = await OutputStore.open({
    directory,
    inlineBytesPerStream: 0,
    maxStoredBytes: 10,
    maxTotalRetainedBytes: 100,
    maxRetainedEntries: 10,
    ttlMs: 60_000,
    randomBytes: (size) => Buffer.alloc(size, 0x6b),
  });

  const retained = await store.create("retained-before-external-delete");
  await retained.append("stdout", Buffer.from("retained"));
  const summary = await retained.finalize();
  assert.ok(summary.outputRef);
  await rm(join(directory, summary.outputRef), {
    recursive: true,
    force: true,
  });

  await assert.rejects(
    store.create("must-not-reuse-retained-reference"),
    OutputStoreIoError,
  );
});
