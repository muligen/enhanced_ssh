import assert from "node:assert/strict";
import { mkdtemp, rename, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  ManagedSshKeyVault,
  ManagedSshKeyVaultError,
} from "../../src/test-ui/managed-keys.js";

const SSH_KEYGEN =
  process.platform === "win32"
    ? path.join(
        process.env.SystemRoot ?? String.raw`C:\Windows`,
        "System32",
        "OpenSSH",
        "ssh-keygen.exe",
      )
    : "ssh-keygen";

test(
  "managed key vault persists public metadata and enforces optimistic revisions",
  { timeout: 120_000 },
  async (t) => {
    const sandbox = await mkdtemp(path.join(os.tmpdir(), "agent-ssh-key-vault-"));
    const root = path.join(sandbox, "keys");
    t.after(() => rm(sandbox, { recursive: true, force: true }));

    const vault = new ManagedSshKeyVault(root, SSH_KEYGEN);
    await vault.initialize();
    const empty = vault.snapshot();
    assert.deepEqual(empty.keys, []);

    const generated = await vault.generate("部署密钥", empty.keyRevision);
    assert.equal(generated.keys.length, 1);
    const key = generated.keys[0]!;
    assert.match(key.keyId, /^k-[a-f0-9]{32}$/u);
    assert.match(key.fingerprint, /^SHA256:/u);
    assert.match(key.publicKey, /^ssh-/u);
    assert.equal(JSON.stringify(generated).includes("privateKey"), false);
    assert.equal(JSON.stringify(generated).includes(root), false);

    await assert.rejects(
      vault.renameKey(key.keyId, "stale", empty.keyRevision),
      (error: unknown) =>
        error instanceof ManagedSshKeyVaultError &&
        error.code === "KEY_REVISION_CONFLICT" &&
        error.status === 409,
    );

    const renamed = await vault.renameKey(
      key.keyId,
      "部署密钥 2026",
      generated.keyRevision,
    );
    assert.equal(renamed.keys[0]?.label, "部署密钥 2026");
    assert.equal(renamed.keys[0]?.keyId, key.keyId);

    const reopened = new ManagedSshKeyVault(root, SSH_KEYGEN);
    await reopened.initialize();
    assert.deepEqual(reopened.snapshot(), renamed);
    const removed = await reopened.removeKey(
      key.keyId,
      reopened.snapshot().keyRevision,
    );
    assert.deepEqual(removed.keys, []);
  },
);

test(
  "managed key vault restores a deletion interrupted before manifest commit",
  { timeout: 120_000 },
  async (t) => {
    const sandbox = await mkdtemp(
      path.join(os.tmpdir(), "agent-ssh-key-vault-recovery-"),
    );
    const root = path.join(sandbox, "keys");
    t.after(() => rm(sandbox, { recursive: true, force: true }));

    const vault = new ManagedSshKeyVault(root, SSH_KEYGEN);
    await vault.initialize();
    const generated = await vault.generate("recovery", vault.snapshot().keyRevision);
    const keyId = generated.keys[0]!.keyId;
    await rename(path.join(root, keyId), path.join(root, `.deleting-${keyId}`));

    const reopened = new ManagedSshKeyVault(root, SSH_KEYGEN);
    await reopened.initialize();
    assert.equal(reopened.snapshot().keys[0]?.keyId, keyId);
  },
);

test(
  "managed key vault generates Ed25519 by default and explicit RSA-3072 keys",
  { timeout: 120_000 },
  async (t) => {
    const sandbox = await mkdtemp(
      path.join(os.tmpdir(), "agent-ssh-key-vault-algorithms-"),
    );
    const root = path.join(sandbox, "keys");
    t.after(() => rm(sandbox, { recursive: true, force: true }));

    const vault = new ManagedSshKeyVault(root, SSH_KEYGEN);
    await vault.initialize();
    const ed25519 = await vault.generate(
      "default algorithm",
      vault.snapshot().keyRevision,
    );
    const ed25519Key = ed25519.keys.find(
      (candidate) => candidate.label === "default algorithm",
    );
    assert.equal(ed25519Key?.algorithm, "ssh-ed25519");
    assert.match(ed25519Key?.publicKey ?? "", /^ssh-ed25519 /u);

    const rsa = await vault.generate(
      "RSA 3072",
      ed25519.keyRevision,
      "rsa-3072",
    );
    const rsaKey = rsa.keys.find((candidate) => candidate.label === "RSA 3072");
    assert.equal(rsaKey?.algorithm, "ssh-rsa");
    assert.match(rsaKey?.publicKey ?? "", /^ssh-rsa /u);
    assert.equal(rsaPublicKeyBits(rsaKey?.publicKey ?? ""), 3_072);
  },
);

function rsaPublicKeyBits(publicKey: string): number {
  const encoded = publicKey.split(" ")[1];
  assert.notEqual(encoded, undefined);
  const blob = Buffer.from(encoded!, "base64");
  let offset = 0;
  const readField = (): Buffer => {
    assert.ok(offset + 4 <= blob.length);
    const length = blob.readUInt32BE(offset);
    offset += 4;
    assert.ok(offset + length <= blob.length);
    const field = blob.subarray(offset, offset + length);
    offset += length;
    return field;
  };
  assert.equal(readField().toString("ascii"), "ssh-rsa");
  readField();
  let modulus = readField();
  while (modulus[0] === 0) modulus = modulus.subarray(1);
  assert.ok(modulus.length > 0);
  return (modulus.length - 1) * 8 + (32 - Math.clz32(modulus[0]!));
}
