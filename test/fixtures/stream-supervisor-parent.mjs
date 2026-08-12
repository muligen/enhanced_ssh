import process from "node:process";

import { spawnManagedProcess } from "../../dist/src/infra/process-tree.js";

const [supervisorPath, childFixturePath] = process.argv.slice(2);
if (!supervisorPath || !childFixturePath) {
  throw new Error("supervisor and child fixture paths are required");
}

const managed = await spawnManagedProcess({
  executable: process.execPath,
  arguments: [childFixturePath, "stdin-stream-blocked-tree"],
  streamStdin: true,
  windowsSupervisorPath: supervisorPath,
});
managed.child.stdout.pipe(process.stdout);
managed.child.stderr.pipe(process.stderr);
managed.child.stdin.on("error", () => undefined);

await new Promise((resolve, reject) => {
  managed.child.stdin.write(Buffer.alloc(2 * 1024 * 1024, 0x63), (error) => {
    if (error) reject(error);
    else resolve();
  });
});
process.stdout.write(`supervisor:${managed.child.pid}\n`);
setInterval(() => undefined, 1_000);
