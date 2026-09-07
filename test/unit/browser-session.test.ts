import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { BrowserSession, loadBrowserSessionSecret } from "../../src/service/browser-session.js";

test("browser authorization survives secret reload but rejects expiry, tampering and other origins", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "ssh-browser-session-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const secret = await loadBrowserSessionSecret(directory);
  const session = new BrowserSession(secret);
  const origin = "http://127.0.0.1:52075";
  const now = 1_800_000_000_000;
  const cookie = session.issue(origin, now).split(";", 1)[0]!;
  const restarted = new BrowserSession(await loadBrowserSessionSecret(directory));
  assert.equal(restarted.accepts(cookie, origin, now + 1000), true);
  assert.equal(restarted.accepts(cookie, origin, now + 31 * 86400_000), false);
  assert.equal(restarted.accepts(cookie + "x", origin, now), false);
  assert.equal(restarted.accepts(cookie, "http://127.0.0.1:52076", now), false);
  assert.equal(restarted.accepts(`${cookie}; ${cookie}`, origin, now), false);
  assert.equal(new BrowserSession("revoked").accepts(cookie, origin, now), false);
});
