import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { lstat, open, readFile, unlink } from "node:fs/promises";
import path from "node:path";
import { hardenPrivatePath } from "../daemon/runtime-state.js";

const MAX_AGE = 30 * 24 * 60 * 60;
const SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/u;

// Kept outside runtime descriptors: stopping/restarting the service must not revoke browsers.
export async function loadBrowserSessionSecret(directory: string): Promise<string> {
  const filename = path.join(directory, "browser-session.key");
  let created = false;
  try {
    const handle = await open(filename, "wx", 0o600);
    created = true;
    try {
      await handle.writeFile(randomBytes(32).toString("base64url"));
      await handle.sync();
    } finally {
      await handle.close();
    }
    await hardenPrivatePath(filename, false);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
      if (created) await unlink(filename).catch(() => undefined);
      throw error;
    }
  }
  const entry = await lstat(filename);
  if (entry.isFile() && !entry.isSymbolicLink() && entry.nlink === 1 && entry.size === 0) {
    // Recover an interrupted first creation before any browser could be authorized.
    await unlink(filename);
    return loadBrowserSessionSecret(directory);
  }
  if (!entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1 || entry.size !== 43) {
    throw new Error("Unsafe browser session key file");
  }
  await hardenPrivatePath(filename, false);
  const secret = await readFile(filename, "utf8");
  if (!SECRET_PATTERN.test(secret)) throw new Error("Invalid browser session key");
  return secret;
}

export class BrowserSession {
  constructor(private readonly secret: string) {}

  private signature(value: string, origin: string): string {
    return createHmac("sha256", this.secret).update(`${origin}\n${value}`).digest("base64url");
  }

  private name(origin: string): string {
    return `agent_ssh_session_${new URL(origin).port}`;
  }

  issue(origin: string, now = Date.now()): string {
    const value = `${Math.floor(now / 1000) + MAX_AGE}.${randomBytes(16).toString("base64url")}`;
    return `${this.name(origin)}=${value}.${this.signature(value, origin)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${MAX_AGE}`;
  }

  accepts(cookie: string | undefined, origin: string, now = Date.now()): boolean {
    const prefix = `${this.name(origin)}=`;
    const matches = (cookie ?? "").split(";").map((part) => part.trim()).filter((part) => part.startsWith(prefix));
    if (matches.length !== 1) return false;
    const match = /^(\d{10})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/u.exec(matches[0]!.slice(prefix.length));
    if (!match) return false;
    const expires = Number(match[1]);
    const seconds = Math.floor(now / 1000);
    if (expires <= seconds || expires > seconds + MAX_AGE) return false;
    const expected = this.signature(`${match[1]}.${match[2]}`, origin);
    return timingSafeEqual(Buffer.from(match[3]!), Buffer.from(expected));
  }
}
