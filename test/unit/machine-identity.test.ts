import assert from "node:assert/strict";
import { link, lstat, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  MACHINE_IDENTITY_KEY_BYTES,
  MACHINE_ID_PATTERN,
  deriveMachineId,
  loadOrCreateMachineIdentityKey,
  normalizeNativeMachineId,
  openMachineIdentityKey,
} from "../../src/core/machine-identity.js";

const WINDOWS_ID = "00112233-4455-6677-8899-aabbccddeeff";
const LINUX_ID = "0123456789abcdef0123456789abcdef";

test("derives stable scoped machine IDs without exposing the native ID", () => {
  const key = Buffer.alloc(MACHINE_IDENTITY_KEY_BYTES, 0x5a);
  const first = deriveMachineId(key, "windows", WINDOWS_ID);
  const second = deriveMachineId(key, "windows", WINDOWS_ID.toUpperCase());
  assert.equal(first, second);
  assert.match(first, MACHINE_ID_PATTERN);
  assert.equal(first.includes("00112233"), false);
  assert.notEqual(first, deriveMachineId(key, "macos", WINDOWS_ID));
  assert.notEqual(first, deriveMachineId(Buffer.alloc(32, 0x6b), "windows", WINDOWS_ID));
});

test("validates and canonicalizes native machine identifiers", () => {
  assert.equal(normalizeNativeMachineId("linux", LINUX_ID.toUpperCase()), LINUX_ID);
  assert.equal(
    normalizeNativeMachineId("macos", WINDOWS_ID.toUpperCase()),
    WINDOWS_ID,
  );
  for (const invalid of ["", "not-an-id", "0".repeat(32), "../machine-id"]) {
    assert.throws(() => normalizeNativeMachineId("linux", invalid));
  }
  assert.throws(() => deriveMachineId(Buffer.alloc(31), "linux", LINUX_ID));
});

test(
  "creates, hardens, and reopens one installation key",
  { timeout: 120_000 },
  async (t) => {
    const root = await mkdtemp(path.join(tmpdir(), "agent-ssh-machine-id-"));
    t.after(() => rm(root, { recursive: true, force: true }));
    const runtime = path.join(root, "runtime");
    const keyPath = path.join(runtime, "machine-identity.key");
    await mkdir(runtime, { mode: 0o700 });

    const first = await loadOrCreateMachineIdentityKey(keyPath);
    const second = await loadOrCreateMachineIdentityKey(keyPath);
    assert.equal(first.length, MACHINE_IDENTITY_KEY_BYTES);
    assert.deepEqual(first, second);
    assert.equal((await lstat(keyPath)).size, MACHINE_IDENTITY_KEY_BYTES);
    if (process.platform !== "win32") {
      assert.equal((await lstat(keyPath)).mode & 0o777, 0o600);
    }

    const store = await openMachineIdentityKey(keyPath);
    assert.equal(store.derive("linux", LINUX_ID), deriveMachineId(first, "linux", LINUX_ID));
    store.close();
    assert.throws(() => store.derive("linux", LINUX_ID), /closed/u);
    first.fill(0);
    second.fill(0);
  },
);

test(
  "rejects malformed and hard-linked installation keys",
  { timeout: 120_000 },
  async (t) => {
    const root = await mkdtemp(path.join(tmpdir(), "agent-ssh-machine-id-invalid-"));
    t.after(() => rm(root, { recursive: true, force: true }));
    const shortPath = path.join(root, "short.key");
    await writeFile(shortPath, Buffer.alloc(31));
    await assert.rejects(loadOrCreateMachineIdentityKey(shortPath), /32-byte/u);

    const source = path.join(root, "source.key");
    const linked = path.join(root, "linked.key");
    await writeFile(source, Buffer.alloc(32, 1));
    await link(source, linked);
    await assert.rejects(loadOrCreateMachineIdentityKey(linked), /single-link/u);
  },
);
