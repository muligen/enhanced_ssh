import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const fixturePath = fileURLToPath(import.meta.url);
const scenario = process.argv[2];
const scenarioArguments = process.argv.slice(3);

switch (scenario) {
  case "argv":
    process.stdout.write(JSON.stringify(scenarioArguments));
    break;

  case "io-exit":
    process.stdout.write("stdout-data");
    process.stderr.write("stderr-data");
    process.exitCode = 23;
    break;

  case "stdin": {
    const chunks = [];
    for await (const chunk of process.stdin) {
      chunks.push(Buffer.from(chunk));
    }
    process.stdout.write(Buffer.concat(chunks));
    break;
  }

  case "stdin-stream": {
    let pending = "";
    for await (const chunk of process.stdin) {
      pending += Buffer.from(chunk).toString("utf8");
      for (;;) {
        const newline = pending.indexOf("\n");
        if (newline < 0) break;
        const line = pending.slice(0, newline);
        pending = pending.slice(newline + 1);
        process.stdout.write(`received:${line}\n`);
      }
    }
    break;
  }

  case "stdin-stream-tree": {
    process.stdout.write(`root:${process.pid}\n`);
    spawnFixture("tree-child");
    for await (const _chunk of process.stdin) {
      // Keep the root alive while the supervisor forwards parent input.
    }
    keepAlive();
    break;
  }

  case "stdin-stream-blocked-tree":
    process.stdout.write(`root:${process.pid}\n`);
    spawnFixture("tree-child");
    // Deliberately never read stdin, exercising supervisor backpressure handling.
    keepAlive();
    break;

  case "stdin-tree": {
    for await (const _chunk of process.stdin) {
      // Drain the forwarded payload before starting the long-lived tree.
    }
    process.stdout.write(`root:${process.pid}\n`);
    spawnFixture("tree-child");
    keepAlive();
    break;
  }

  case "flood":
    await writeAll(process.stdout, Buffer.alloc(128 * 1024, 0x61));
    await writeAll(process.stderr, Buffer.alloc(96 * 1024, 0x62));
    break;

  case "hang":
    process.stdout.write("ready\n");
    keepAlive();
    break;

  case "tree":
    process.stdout.write(`root:${process.pid}\n`);
    spawnFixture("tree-child");
    keepAlive();
    break;

  case "orphan-tree": {
    process.stdout.write(`root:${process.pid}\n`);
    const child = spawnFixture("tree-child");
    child.unref();
    break;
  }

  case "tree-child":
    process.stdout.write(`child:${process.pid}\n`);
    spawnFixture("tree-grandchild");
    keepAlive();
    break;

  case "tree-grandchild":
    process.stdout.write(`grandchild:${process.pid}\n`);
    keepAlive();
    break;

  default:
    process.stderr.write(`unknown fake SSH scenario: ${String(scenario)}\n`);
    process.exitCode = 64;
}

function spawnFixture(childScenario) {
  const child = spawn(process.execPath, [fixturePath, childScenario], {
    shell: false,
    windowsHide: true,
    stdio: ["ignore", "inherit", "inherit"],
  });
  child.once("error", (error) => {
    process.stderr.write(`fixture spawn failed: ${error.message}\n`);
    process.exitCode = 70;
  });
  return child;
}

function keepAlive() {
  setInterval(() => undefined, 1_000);
}

function writeAll(stream, chunk) {
  return new Promise((resolve, reject) => {
    stream.once("error", reject);
    stream.write(chunk, (error) => {
      stream.off("error", reject);
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}
