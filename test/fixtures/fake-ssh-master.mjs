#!/usr/bin/env node
// Stands in for OpenSSH in control-master tests. Records each invocation and
// emulates `-M -f` (socket-holding daemon), `-O stop`, auth failure, and a
// remote command that echoes its standard input once it ends.
import { spawn } from "node:child_process";
import { appendFileSync, unlinkSync } from "node:fs";
import { createServer } from "node:net";

const startedAt = Date.now();
const args = process.argv.slice(2);
const log = process.env.FAKE_SSH_LOG;
const socketPath = args[args.indexOf("-S") + 1];
const alias = args.at(-1);

if (args[0] === "--serve") {
  const server = createServer((socket) => socket.end());
  server.listen(args[1]);
  setTimeout(() => server.close(), 10_000).unref();
  process.on("SIGTERM", () => server.close(() => process.exit(0)));
} else {
  if (log !== undefined) appendFileSync(log, JSON.stringify(args) + "\n");
  if (args.includes("-M")) {
    if (alias === "unreachable") process.exit(255);
    const daemon = spawn(process.execPath, [process.argv[1], "--serve", socketPath], {
      detached: true,
      stdio: "ignore",
    });
    daemon.unref();
    // Emulate -f: exit once the master is listening.
    const wait = setInterval(async () => {
      const { lstat } = await import("node:fs/promises");
      try {
        if ((await lstat(socketPath)).isSocket()) {
          clearInterval(wait);
          process.exit(0);
        }
      } catch {}
    }, 10);
  } else if (args.includes("-O")) {
    try { unlinkSync(socketPath); } catch {}
    process.exit(0);
  } else {
    runSession();
  }
}

function runSession() {
  const sessions = process.env.FAKE_SSH_SESSIONS;
  const record = (entry) => {
    if (sessions !== undefined) {
      appendFileSync(sessions, JSON.stringify({ pid: process.pid, ...entry }) + "\n");
    }
  };
  record({ event: "start", startedAt });
  if (process.env.FAKE_SSH_BANNER !== undefined) {
    process.stderr.write(process.env.FAKE_SSH_BANNER);
  }
  const chunks = [];
  const finish = () => {
    const stdin = Buffer.concat(chunks).toString("utf8");
    record({ event: "exit", stdin });
    process.stdout.write(JSON.stringify({ pid: process.pid, startedAt, stdin }) + "\n", () => {
      process.exit(Number(/^exit (\d+)$/u.exec(stdin)?.[1] ?? 0));
    });
  };
  if (args.includes("-n")) {
    finish();
  } else {
    process.stdin.on("data", (chunk) => chunks.push(chunk));
    process.stdin.on("end", finish);
  }
}
