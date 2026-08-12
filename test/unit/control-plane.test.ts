import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  publishAdminDescriptor,
  readAdminDescriptor,
  removeAdminDescriptor,
  type AdminDescriptor,
} from "../../src/service/control-plane.js";

const TEST_TOKEN = "A".repeat(43);

test("admin descriptor round-trips only while its service process is alive", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agent-ssh-admin-"));
  const dataDirectory = path.join(root, "runtime");
  await mkdir(dataDirectory);
  const descriptor: AdminDescriptor = {
    version: 1,
    pid: process.pid,
    origin: "http://127.0.0.1:43123",
    url: `http://127.0.0.1:43123/#token=${TEST_TOKEN}`,
    startedAt: new Date().toISOString(),
  };
  try {
    await publishAdminDescriptor(dataDirectory, descriptor);
    assert.deepEqual(await readAdminDescriptor(dataDirectory), descriptor);
    await removeAdminDescriptor(dataDirectory, descriptor);
    assert.equal(await readAdminDescriptor(dataDirectory), undefined);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("admin descriptor rejects non-loopback and untokenized URLs", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agent-ssh-admin-"));
  const dataDirectory = path.join(root, "runtime");
  try {
    await assert.rejects(
      publishAdminDescriptor(dataDirectory, {
        version: 1,
        pid: process.pid,
        origin: "http://0.0.0.0:43123",
        url: `http://0.0.0.0:43123/#token=${TEST_TOKEN}`,
        startedAt: new Date().toISOString(),
      }),
    );
    await assert.rejects(
      publishAdminDescriptor(dataDirectory, {
        version: 1,
        pid: process.pid,
        origin: "http://127.0.0.1:43123",
        url: "http://127.0.0.1:43123/",
        startedAt: new Date().toISOString(),
      }),
    );
    await assert.rejects(
      publishAdminDescriptor(dataDirectory, {
        version: 1,
        pid: process.pid,
        origin: "http://127.0.0.1:43123",
        url: `http://operator:secret@127.0.0.1:43123/#token=${TEST_TOKEN}`,
        startedAt: new Date().toISOString(),
      }),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("stale admin descriptor is not reported as an active service", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agent-ssh-admin-"));
  const dataDirectory = path.join(root, "runtime");
  await mkdir(dataDirectory);
  const descriptor: AdminDescriptor = {
    version: 1,
    pid: 2_147_483_647,
    origin: "http://127.0.0.1:43123",
    url: `http://127.0.0.1:43123/#token=${TEST_TOKEN}`,
    startedAt: new Date().toISOString(),
  };
  try {
    await publishAdminDescriptor(dataDirectory, descriptor);
    assert.equal(await readAdminDescriptor(dataDirectory), undefined);
    await removeAdminDescriptor(dataDirectory, descriptor);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
