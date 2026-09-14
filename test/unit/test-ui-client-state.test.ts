import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const APP_SCRIPT = new URL("../../src/test-ui/public/app.js", import.meta.url);
const SESSION_TOKEN = "T".repeat(43);
const KEY_ID = `k-${"a".repeat(32)}`;
const SECOND_KEY_ID = `k-${"b".repeat(32)}`;

class MemoryStorage {
  readonly #values = new Map<string, string>();

  public getItem(key: string): string | null {
    return this.#values.get(key) ?? null;
  }

  public setItem(key: string, value: string): void {
    this.#values.set(key, value);
  }

  public removeItem(key: string): void {
    this.#values.delete(key);
  }
}

class FakeClassList {
  readonly #values = new Set<string>();

  public add(...values: string[]): void {
    for (const value of values) this.#values.add(value);
  }

  public toggle(value: string, force?: boolean): boolean {
    const enabled = force ?? !this.#values.has(value);
    if (enabled) this.#values.add(value);
    else this.#values.delete(value);
    return enabled;
  }
}

type FakeListener = (event: FakeEvent) => void;

interface FakeEvent {
  readonly target: FakeElement;
  readonly key?: string;
  preventDefault(): void;
}

class FakeElement {
  public textContent = "";
  public className = "";
  public title = "";
  public hidden = false;
  public disabled = false;
  public checked = false;
  public value = "";
  public max = "";
  public placeholder = "";
  public tabIndex = 0;
  public parentNode: FakeElement | null = null;
  public readonly dataset: Record<string, string> = {};
  public readonly classList = new FakeClassList();
  readonly #listeners = new Map<string, FakeListener[]>();
  readonly #children: FakeElement[] = [];

  public get children(): readonly FakeElement[] {
    return this.#children;
  }

  public addEventListener(type: string, listener: FakeListener): void {
    const listeners = this.#listeners.get(type) ?? [];
    listeners.push(listener);
    this.#listeners.set(type, listeners);
  }

  public dispatch(type: string, target: FakeElement = this): void {
    const event: FakeEvent = {
      target,
      preventDefault(): void {},
    };
    for (const listener of this.#listeners.get(type) ?? []) listener(event);
  }

  public setAttribute(): void {}
  public removeAttribute(): void {}
  public focus(): void {}
  public select(): void {}
  public setCustomValidity(): void {}
  public reportValidity(): boolean { return true; }
  public matches(): boolean { return false; }
  public querySelectorAll(): FakeElement[] { return []; }

  public append(...children: FakeElement[]): void {
    for (const child of children) {
      child.parentNode = this;
      this.#children.push(child);
    }
  }

  public replaceChildren(...children: FakeElement[]): void {
    for (const child of this.#children) child.parentNode = null;
    this.#children.length = 0;
    this.append(...children);
  }

  public remove(): void {
    this.parentNode = null;
  }
}

type NetworkMode = "success" | "invalid-session" | "offline" | "config-error" | "config-error-with-keys" | "key-storage-error" | "key-file-unsafe" | "keys-error" | "orphan-key" | "pending" | "check-unavailable" | "check-host-mismatch" | "prepare-active";
type ClientProfileKind = "tailscale" | "openssh" | "accessclient" | "accessclient-unconfigured";

interface ClientRequest {
  readonly url: string;
  readonly body: unknown;
}

interface ClientHarness {
  readonly elements: ReadonlyMap<string, FakeElement>;
  readonly inputGroups: ReadonlyMap<string, FakeElement[]>;
  readonly clipboardWrites: readonly string[];
  readonly requests: readonly ClientRequest[];
  readonly requestTokens: string[];
  readonly storage: MemoryStorage;
  releasePending(mode?: Exclude<NetworkMode, "pending">): void;
  setNetworkMode(mode: NetworkMode): void;
  settle(): Promise<void>;
}

test("management UI exchanges its fragment token and attempts cookie authentication on a new page", async () => {
  const storage = new MemoryStorage();
  storage.setItem("agent-ssh-ui-token", "O".repeat(43));
  const first = await startClient({ hash: `#token=${SESSION_TOKEN}`, storage });

  assert.equal(storage.getItem("agent-ssh-ui-token"), null);
  assert.deepEqual(new Set(first.requestTokens), new Set([SESSION_TOKEN]));
  assert.equal(requireElement(first, "machine-count").textContent, "1");

  const reloaded = await startClient({ hash: "", storage: new MemoryStorage() });
  assert.deepEqual(new Set(reloaded.requestTokens), new Set([""]));
  assert.equal(requireElement(reloaded, "machine-count").textContent, "1");
  assert.equal(requireElement(reloaded, "inventory-empty").hidden, true);
});

test("the first unresolved bootstrap stays pending until inventory arrives", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    mode: "pending",
    storage: new MemoryStorage(),
  });

  assert.equal(requireElement(harness, "machine-count").textContent, "--");
  assert.equal(requireElement(harness, "inventory-empty").hidden, true);
  assert.equal(requireElement(harness, "machine-list").hidden, true);
  assert.equal(requireElement(harness, "revision-label").textContent, "正在加载");
  assert.equal(requireElement(harness, "workspace-title").textContent, "正在加载机器配置");
  assert.equal(requireElement(harness, "machine-form").hidden, true);
  assert.equal(requireElement(harness, "new-machine-button").disabled, true);

  harness.releasePending();
  await harness.settle();

  assert.equal(requireElement(harness, "machine-count").textContent, "1");
  assert.equal(requireElement(harness, "machine-list").hidden, false);
  assert.equal(requireElement(harness, "workspace-title").textContent, "alpha");
  assert.equal(requireElement(harness, "machine-form").hidden, false);
  assert.equal(requireElement(harness, "new-machine-button").disabled, false);
});

test("machine inventory displays a saved description without creating markup", async () => {
  const description = "<b>GPU 部署节点 & 主机</b>";
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    storage: new MemoryStorage(),
    description,
  });

  const machineItem = requireElement(harness, "machine-list").children[0];
  assert.notEqual(machineItem, undefined);
  const selectButton = machineItem!.children[0];
  const descriptionElement = selectButton?.children.find(
    (child) => child.className === "machine-description",
  );
  assert.equal(descriptionElement?.textContent, description);
  assert.equal(descriptionElement?.title, description);
  assert.equal(descriptionElement?.children.length, 0);
});

test("the machine list MCP switch applies immediately without overwriting a dirty form", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    storage: new MemoryStorage(),
  });
  const description = requireElement(harness, "target-description");
  description.value = "尚未保存的新说明";
  requireElement(harness, "machine-form").dispatch("input", description);

  const machineItem = requireElement(harness, "machine-list").children[0]!;
  const toggle = machineItem.children.find((child) => child.className === "machine-mcp-toggle");
  assert.notEqual(toggle, undefined);
  assert.equal(toggle!.dataset.enabled, "true");
  toggle!.dispatch("click");
  await harness.settle();

  const toggleRequest = harness.requests.find((candidate) =>
    candidate.url.endsWith("/api/admin/target/enabled")
  );
  assert.deepEqual(toggleRequest?.body, {
    alias: "alpha",
    enabled: false,
    expectedRevision: `r-test-${"a".repeat(32)}`,
  });
  assert.equal(description.value, "尚未保存的新说明");
  assert.match(requireElement(harness, "saved-indicator").textContent, /未保存修改/u);
  assert.equal(requireElement(harness, "selected-state-badge").textContent, "已停用");

  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();
  const saveRequest = harness.requests.findLast((candidate) =>
    candidate.url.endsWith("/api/admin/target/save")
  );
  assert.equal(
    (saveRequest?.body as { readonly target?: { readonly enabled?: unknown } })?.target?.enabled,
    false,
  );
});

test("a temporary refresh failure keeps the last loaded inventory read-only", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    storage: new MemoryStorage(),
  });
  assert.equal(requireElement(harness, "machine-count").textContent, "1");

  harness.setNetworkMode("offline");
  requireElement(harness, "refresh-button").dispatch("click");
  await harness.settle();

  assert.equal(requireElement(harness, "machine-count").textContent, "1");
  assert.equal(requireElement(harness, "machine-list").hidden, false);
  assert.equal(requireElement(harness, "workspace-title").textContent, "alpha");
  assert.equal(requireElement(harness, "new-machine-button").disabled, true);
  assert.match(requireElement(harness, "gateway-detail").textContent, /1 台机器保留上次加载结果/u);
});

test("an invalid session clears the stored token without erasing loaded machines", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    storage: new MemoryStorage(),
  });
  assert.equal(requireElement(harness, "machine-count").textContent, "1");

  harness.setNetworkMode("invalid-session");
  requireElement(harness, "refresh-button").dispatch("click");
  await harness.settle();

  assert.equal(harness.storage.getItem("agent-ssh-ui-token"), null);
  assert.equal(requireElement(harness, "machine-count").textContent, "1");
  assert.equal(requireElement(harness, "machine-list").hidden, false);
  assert.match(requireElement(harness, "inventory-error").textContent, /授权已过期/u);
  assert.equal(requireElement(harness, "gateway-label").textContent, "需要授权此浏览器");
  assert.equal(requireElement(harness, "new-machine-button").disabled, true);
});

test("global key generation preserves an unsaved machine and sends only the key contract", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    storage: new MemoryStorage(),
  });

  assert.equal(requireElement(harness, "target-key-id").value, KEY_ID);
  assert.equal(harness.elements.has("target-identity-file"), false);
  requireElement(harness, "target-description").value = "尚未保存的说明";
  requireElement(harness, "machine-form").dispatch("input");
  assert.match(requireElement(harness, "saved-indicator").textContent, /有未保存修改/u);
  requireElement(harness, "settings-tab").dispatch("click");
  assert.match(requireElement(harness, "saved-indicator").textContent, /机器配置有未保存修改/u);
  requireElement(harness, "generate-key-button").dispatch("click");
  requireElement(harness, "key-label").value = "第二把密钥";
  requireElement(harness, "key-editor-form").dispatch("submit");
  await harness.settle();

  const request = harness.requests.find((candidate) => candidate.url.endsWith("/api/admin/key/generate"));
  assert.deepEqual(request?.body, {
    label: "第二把密钥",
    expectedKeyRevision: "kr-test-1",
    algorithm: "ed25519",
  });
  assert.equal(requireElement(harness, "target-description").value, "尚未保存的说明");
  assert.equal(requireElement(harness, "target-key-id").value, KEY_ID);
  assert.equal(requireElement(harness, "key-count").textContent, "2");
  assert.match(requireElement(harness, "saved-indicator").textContent, /机器配置有未保存修改/u);
});

test("the OpenSSH first connection guide follows the selected key and platform", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    storage: new MemoryStorage(),
  });
  const expectedPublicKey = `ssh-ed25519 ${Buffer.from(KEY_ID).toString("base64")}`;
  const guide = requireElement(harness, "ssh-install-guide");
  const command = requireElement(harness, "ssh-install-command");
  const launchButton = requireElement(harness, "launch-ssh-install-button");
  const copyButton = requireElement(harness, "copy-ssh-install-command-button");

  assert.equal(guide.hidden, false);
  assert.match(command.textContent, /authorized_keys/u);
  assert.match(command.textContent, /umask 077/u);
  assert.match(command.textContent, /for \(i=1; i<NF; i\+\+\)/u);
  assert.ok(command.textContent.includes(expectedPublicKey));
  assert.ok(!command.textContent.includes(`${expectedPublicKey} test`));
  assert.equal(launchButton.disabled, false);
  assert.equal(copyButton.disabled, false);

  launchButton.dispatch("click");
  await harness.settle();
  const installRequest = harness.requests.find((candidate) =>
    candidate.url.endsWith("/api/admin/ssh/install"),
  );
  assert.equal(
    (installRequest?.body as { readonly target?: { readonly target?: { readonly keyId?: unknown } } })
      ?.target?.target?.keyId,
    KEY_ID,
  );

  const platforms = harness.inputGroups.get('input[name="platform"]')!;
  platforms[1]!.checked = false;
  platforms[0]!.checked = true;
  requireElement(harness, "machine-form").dispatch("change", platforms[0]);

  assert.match(command.textContent, /Join-Path \$env:ProgramData/u);
  assert.match(command.textContent, /administrators_authorized_keys/u);
  assert.doesNotMatch(command.textContent, /umask 077/u);
  assert.ok(command.textContent.includes(expectedPublicKey));

  copyButton.dispatch("click");
  await harness.settle();
  assert.deepEqual(harness.clipboardWrites, [command.textContent]);
});

test("the first connection guide updates its key and hides outside usable OpenSSH", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    storage: new MemoryStorage(),
  });

  requireElement(harness, "generate-key-button").dispatch("click");
  requireElement(harness, "key-label").value = "第二把密钥";
  requireElement(harness, "key-algorithm").value = "rsa-3072";
  requireElement(harness, "key-editor-form").dispatch("submit");
  await harness.settle();

  const targetKey = requireElement(harness, "target-key-id");
  targetKey.value = SECOND_KEY_ID;
  requireElement(harness, "machine-form").dispatch("change", targetKey);
  const expectedPublicKey = `ssh-rsa ${Buffer.from(SECOND_KEY_ID).toString("base64")}`;
  assert.ok(requireElement(harness, "ssh-install-command").textContent.includes(expectedPublicKey));

  const connectionModes = harness.inputGroups.get('input[name="connection-mode"]')!;
  connectionModes[0]!.checked = false;
  connectionModes[1]!.checked = true;
  requireElement(harness, "machine-form").dispatch("change", connectionModes[1]);
  assert.equal(requireElement(harness, "ssh-install-guide").hidden, true);
  assert.equal(requireElement(harness, "ssh-install-command").textContent, "");
  assert.equal(requireElement(harness, "launch-ssh-install-button").disabled, true);
  assert.equal(requireElement(harness, "copy-ssh-install-command-button").disabled, true);
});

test("the first connection guide stays unavailable for an orphaned key", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    mode: "orphan-key",
    storage: new MemoryStorage(),
  });

  assert.equal(requireElement(harness, "ssh-install-guide").hidden, true);
  assert.equal(requireElement(harness, "ssh-install-command").textContent, "");
  assert.equal(requireElement(harness, "launch-ssh-install-button").disabled, true);
  assert.equal(requireElement(harness, "copy-ssh-install-command-button").disabled, true);
});

test("RSA key generation sends the selected algorithm", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    storage: new MemoryStorage(),
  });

  requireElement(harness, "generate-key-button").dispatch("click");
  requireElement(harness, "key-label").value = "企业堡垒机";
  requireElement(harness, "key-algorithm").value = "rsa-3072";
  requireElement(harness, "key-editor-form").dispatch("submit");
  await harness.settle();

  const request = harness.requests.find((candidate) => candidate.url.endsWith("/api/admin/key/generate"));
  assert.deepEqual(request?.body, {
    label: "企业堡垒机",
    expectedKeyRevision: "kr-test-1",
    algorithm: "rsa-3072",
  });
  assert.match(requireElement(harness, "key-public-meta").textContent, /ssh-rsa/u);
});

test("a strict passthrough username reaches the target save contract unchanged", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    storage: new MemoryStorage(),
  });

  requireElement(harness, "target-username").value = "portal.user/172.24.251.37/system-user";
  requireElement(harness, "machine-form").dispatch("input");
  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();

  const request = harness.requests.find((candidate) => candidate.url.endsWith("/api/admin/target/save"));
  assert.equal(
    (request?.body as { readonly target?: { readonly target?: { readonly username?: unknown } } })
      ?.target?.target?.username,
    "portal.user/172.24.251.37/system-user",
  );
});

test("an orphaned key reference keeps the machine visible and blocks saving", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    mode: "orphan-key",
    storage: new MemoryStorage(),
  });

  assert.equal(requireElement(harness, "machine-count").textContent, "1");
  assert.equal(requireElement(harness, "machine-list").hidden, false);
  assert.equal(requireElement(harness, "target-key-id").value, SECOND_KEY_ID);
  assert.match(requireElement(harness, "target-key-note").textContent, /当前私钥不可用/u);
  assert.equal(requireElement(harness, "save-button").disabled, true);
});

test("a malformed key snapshot does not clear the machine inventory", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    mode: "keys-error",
    storage: new MemoryStorage(),
  });

  assert.equal(requireElement(harness, "machine-count").textContent, "1");
  assert.equal(requireElement(harness, "machine-list").hidden, false);
  assert.equal(requireElement(harness, "key-count").textContent, "--");
  assert.equal(requireElement(harness, "key-error").hidden, false);
  assert.equal(requireElement(harness, "save-button").disabled, true);
});

test("a key storage error preserves the last key list and machine inventory read-only", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    storage: new MemoryStorage(),
  });
  assert.equal(requireElement(harness, "key-count").textContent, "1");

  harness.setNetworkMode("key-storage-error");
  requireElement(harness, "refresh-button").dispatch("click");
  await harness.settle();

  assert.equal(requireElement(harness, "machine-count").textContent, "1");
  assert.equal(requireElement(harness, "key-count").textContent, "1");
  assert.equal(requireElement(harness, "key-list").hidden, false);
  assert.equal(requireElement(harness, "key-empty").hidden, true);
  assert.match(requireElement(harness, "key-error").textContent, /私钥存储已损坏/u);
  assert.equal(requireElement(harness, "generate-key-button").disabled, true);
});

test("any dedicated key error preserves the last key snapshot", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    storage: new MemoryStorage(),
  });

  harness.setNetworkMode("key-file-unsafe");
  requireElement(harness, "refresh-button").dispatch("click");
  await harness.settle();

  assert.equal(requireElement(harness, "machine-count").textContent, "1");
  assert.equal(requireElement(harness, "key-count").textContent, "1");
  assert.equal(requireElement(harness, "generate-key-button").disabled, true);
});

test("a fleet configuration error does not disable a valid key snapshot", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    mode: "config-error-with-keys",
    storage: new MemoryStorage(),
  });

  assert.equal(requireElement(harness, "machine-count").textContent, "1");
  assert.equal(requireElement(harness, "machine-list").hidden, false);
  assert.equal(requireElement(harness, "workspace-title").textContent, "alpha");
  assert.equal(requireElement(harness, "new-machine-button").disabled, true);
  assert.equal(requireElement(harness, "key-count").textContent, "1");
  assert.equal(requireElement(harness, "generate-key-button").disabled, false);
  assert.equal(requireElement(harness, "import-key-button").disabled, false);
});

test("an AccessClient target hydrates without OpenSSH fields", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    profile: "accessclient",
    storage: new MemoryStorage(),
  });

  const connectionModes = harness.inputGroups.get('input[name="connection-mode"]')!;
  assert.equal(connectionModes[0]?.checked, false);
  assert.equal(connectionModes[1]?.checked, true);
  assert.equal(requireElement(harness, "openssh-connection-fields").hidden, true);
  assert.equal(requireElement(harness, "accessclient-connection-fields").hidden, false);
  assert.equal(requireElement(harness, "accessclient-target-port").value, "22");
  assert.equal(requireElement(harness, "accessclient-gateway-username").value, "portal-user");
  assert.equal(requireElement(harness, "target-key-id").value, "");
  assert.equal(requireElement(harness, "transfer-deny-note").hidden, true);
  assert.equal(requireElement(harness, "accessclient-transfer-note").hidden, false);
});

test("AccessClient save omits OpenSSH credentials and forces transfer denial", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    profile: "accessclient",
    storage: new MemoryStorage(),
  });

  const connectionModes = harness.inputGroups.get('input[name="connection-mode"]')!;
  connectionModes[0]!.checked = true;
  connectionModes[1]!.checked = false;
  requireElement(harness, "machine-form").dispatch("change", connectionModes[0]);
  assert.equal(requireElement(harness, "openssh-connection-fields").hidden, false);
  assert.equal(requireElement(harness, "accessclient-connection-fields").hidden, true);

  const transferModes = harness.inputGroups.get('input[name="transfer-mode"]')!;
  transferModes[0]!.checked = false;
  transferModes[3]!.checked = true;
  connectionModes[0]!.checked = false;
  connectionModes[1]!.checked = true;
  requireElement(harness, "machine-form").dispatch("change", connectionModes[1]);
  assert.equal(requireElement(harness, "openssh-connection-fields").hidden, true);
  assert.equal(requireElement(harness, "accessclient-connection-fields").hidden, false);

  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();

  const request = harness.requests.find((candidate) => candidate.url.endsWith("/api/admin/target/save"));
  assert.ok(request);
  const body = request.body as {
    readonly target?: {
      readonly connectionMode?: unknown;
      readonly target?: Record<string, unknown>;
      readonly accessClient?: unknown;
      readonly transferMode?: unknown;
      readonly knownHostsFile?: unknown;
      readonly bastion?: unknown;
    };
  };
  assert.equal(body.target?.connectionMode, "accessclient-share");
  assert.deepEqual(body.target?.target, {
    host: "192.0.2.20",
    port: 22,
    username: "portal-user",
  });
  assert.deepEqual(body.target?.accessClient, {
    gatewayHost: "192.0.2.20",
    gatewayPort: 22,
    gatewayUsername: "portal-user",
    sharingHost: "192.0.2.20",
    sharingPort: 22,
    expectedHostname: "access-target",
  });
  assert.equal(body.target?.transferMode, "deny");
  assert.equal(Object.hasOwn(body.target ?? {}, "knownHostsFile"), false);
  assert.equal(Object.hasOwn(body.target ?? {}, "bastion"), false);
  assert.equal(Object.hasOwn(body.target?.target ?? {}, "keyId"), false);
});

test("a new AccessClient target saves with only the simplified connection fields", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    profile: "accessclient",
    storage: new MemoryStorage(),
  });

  requireElement(harness, "new-machine-button").dispatch("click");
  const connectionModes = harness.inputGroups.get('input[name="connection-mode"]')!;
  connectionModes[0]!.checked = false;
  connectionModes[1]!.checked = true;
  requireElement(harness, "target-alias").value = "new-accessclient";
  requireElement(harness, "target-host").value = "192.0.2.30";
  assert.equal(
    requireElement(harness, "accessclient-gateway-username").value,
    "chenzilve",
  );
  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();

  const request = [...harness.requests]
    .reverse()
    .find((candidate) => candidate.url.endsWith("/api/admin/target/save"));
  assert.ok(request);
  const body = request.body as {
    readonly target?: {
      readonly target?: Record<string, unknown>;
      readonly accessClient?: Record<string, unknown>;
    };
  };
  assert.deepEqual(body.target?.target, {
    host: "192.0.2.30",
    port: 22,
    username: "chenzilve",
  });
  assert.deepEqual(body.target?.accessClient, {
    gatewayHost: "192.0.2.30",
    gatewayPort: 22,
    gatewayUsername: "chenzilve",
    sharingHost: "192.0.2.30",
    sharingPort: 22,
  });
});

test("AccessClient can save when the global key snapshot is unavailable", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    mode: "keys-error",
    profile: "accessclient",
    storage: new MemoryStorage(),
  });

  assert.equal(requireElement(harness, "save-button").disabled, false);
  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();
  assert.equal(
    harness.requests.filter((candidate) => candidate.url.endsWith("/api/admin/target/save")).length,
    1,
  );
});

test("selecting AccessClient without a saved Plink path stops target save", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    profile: "accessclient-unconfigured",
    storage: new MemoryStorage(),
  });

  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();
  assert.equal(
    harness.requests.filter((candidate) => candidate.url.endsWith("/api/admin/target/save")).length,
    0,
  );
  assert.match(requireElement(harness, "form-error").textContent, /全局设置保存 Plink/u);
});

test("saving Plink keeps a dirty machine form intact", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    storage: new MemoryStorage(),
  });

  requireElement(harness, "target-description").value = "尚未保存的机器说明";
  requireElement(harness, "machine-form").dispatch("input");
  requireElement(harness, "plink-executable").value = "C:\\Tools\\plink.exe";
  requireElement(harness, "accessclient-settings-form").dispatch("input");
  requireElement(harness, "accessclient-settings-form").dispatch("submit");
  await harness.settle();

  const request = harness.requests.find((candidate) => candidate.url.endsWith("/api/admin/access-client/save"));
  assert.deepEqual(request?.body, {
    plinkExecutable: "C:\\Tools\\plink.exe",
    expectedRevision: `r-test-${"a".repeat(32)}`,
  });
  assert.equal(requireElement(harness, "target-description").value, "尚未保存的机器说明");
  assert.match(requireElement(harness, "saved-indicator").textContent, /有未保存修改/u);
});

test("saving a machine preserves an unsaved Plink path draft", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    storage: new MemoryStorage(),
  });

  requireElement(harness, "plink-executable").value = "C:\\Draft\\plink.exe";
  requireElement(harness, "accessclient-settings-form").dispatch("input");
  requireElement(harness, "target-description").value = "更新机器说明";
  requireElement(harness, "machine-form").dispatch("input");
  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();

  assert.equal(
    harness.requests.filter((candidate) => candidate.url.endsWith("/api/admin/target/save")).length,
    1,
  );
  assert.equal(requireElement(harness, "plink-executable").value, "C:\\Draft\\plink.exe");
  assert.match(requireElement(harness, "saved-indicator").textContent, /全局设置有未保存修改/u);
});

test("a pending Plink save blocks a concurrent machine mutation", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    storage: new MemoryStorage(),
  });

  requireElement(harness, "plink-executable").value = "C:\\Tools\\plink.exe";
  requireElement(harness, "accessclient-settings-form").dispatch("input");
  harness.setNetworkMode("pending");
  requireElement(harness, "accessclient-settings-form").dispatch("submit");
  requireElement(harness, "target-description").value = "应该被保留的修改";
  requireElement(harness, "machine-form").dispatch("input");
  requireElement(harness, "machine-form").dispatch("submit");

  assert.equal(
    harness.requests.filter((candidate) => candidate.url.endsWith("/api/admin/access-client/save")).length,
    1,
  );
  assert.equal(
    harness.requests.filter((candidate) => candidate.url.endsWith("/api/admin/target/save")).length,
    0,
  );
  harness.releasePending();
  await harness.settle();
});

for (const mode of ["offline", "config-error"] as const) {
  test(`a first ${mode} load is unavailable instead of an empty editable fleet`, async () => {
    const harness = await startClient({
      hash: `#token=${SESSION_TOKEN}`,
      mode,
      storage: new MemoryStorage(),
    });

    assert.equal(requireElement(harness, "machine-count").textContent, "--");
    assert.equal(requireElement(harness, "inventory-empty").hidden, true);
    assert.equal(requireElement(harness, "machine-list").hidden, true);
    assert.equal(requireElement(harness, "workspace-title").textContent, "机器配置未加载");
    assert.equal(requireElement(harness, "machine-form").hidden, true);
    assert.equal(requireElement(harness, "new-machine-button").disabled, true);
    assert.equal(requireElement(harness, "inventory-error").hidden, false);
  });
}

test("an unavailable AccessClient check automatically starts PuTTY discovery", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    mode: "check-unavailable",
    profile: "accessclient",
    storage: new MemoryStorage(),
  });

  requireElement(harness, "check-button").dispatch("click");
  await harness.settle();

  assert.equal(requireElement(harness, "form-error").hidden, true);
  assert.equal(
    harness.requests.filter((request) =>
      request.url.endsWith("/api/admin/access-client/session/prepare")
    ).length,
    1,
  );
  assert.equal(
    requireElement(harness, "accessclient-prepare-label").textContent,
    "等待 AccessClient 打开这台机器",
  );
  assert.match(
    requireElement(harness, "form-status").textContent,
    /请现在从 AccessClient 打开这台机器/u,
  );
});

test("an AccessClient host mismatch remains a final identity error", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    mode: "check-host-mismatch",
    profile: "accessclient",
    storage: new MemoryStorage(),
  });

  requireElement(harness, "check-button").dispatch("click");
  await harness.settle();

  const message = requireElement(harness, "form-error").textContent;
  assert.match(message, /AccessClient 当前共享会话连接到了另一台机器/u);
  assert.doesNotMatch(message, /探测命令退出码/u);
  assert.equal(
    harness.requests.some((request) =>
      request.url.endsWith("/api/admin/access-client/session/prepare")
    ),
    false,
  );
});

test("the hidden AccessClient preparation action still sends only alias and revision", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    profile: "accessclient",
    storage: new MemoryStorage(),
  });

  requireElement(harness, "prepare-accessclient-button").dispatch("click");
  await harness.settle();
  const prepareRequest = harness.requests.find((request) =>
    request.url.endsWith("/api/admin/access-client/session/prepare")
  );
  assert.deepEqual(prepareRequest?.body, {
    alias: "alpha",
    expectedRevision: `r-test-${"a".repeat(32)}`,
  });
  assert.equal(
    requireElement(harness, "accessclient-prepare-label").textContent,
    "等待 AccessClient 打开这台机器",
  );
  assert.equal(requireElement(harness, "prepare-accessclient-button").hidden, true);
  assert.equal(
    requireElement(harness, "cancel-accessclient-prepare-button").hidden,
    false,
  );

  requireElement(harness, "cancel-accessclient-prepare-button").dispatch("click");
  await harness.settle();
  assert.equal(
    requireElement(harness, "accessclient-prepare-label").textContent,
    "准备已取消",
  );
});

test("an armed AccessClient preparation is restored from bootstrap", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    mode: "prepare-active",
    profile: "accessclient",
    storage: new MemoryStorage(),
  });

  assert.equal(
    requireElement(harness, "accessclient-prepare-label").textContent,
    "等待 AccessClient 打开这台机器",
  );
  assert.equal(requireElement(harness, "prepare-accessclient-button").disabled, true);
  assert.equal(
    requireElement(harness, "cancel-accessclient-prepare-button").disabled,
    false,
  );
});

async function startClient(options: {
  readonly hash: string;
  readonly storage: MemoryStorage;
  readonly mode?: NetworkMode;
  readonly profile?: ClientProfileKind;
  readonly description?: string;
}): Promise<ClientHarness> {
  const source = await readFile(APP_SCRIPT, "utf8");
  const elements = new Map<string, FakeElement>();
  const groups = createInputGroups();
  const body = new FakeElement();
  const document = {
    title: "SSH Management Center",
    body,
    querySelector(selector: string): FakeElement {
      const id = selector.startsWith("#") ? selector.slice(1) : selector;
      let element = elements.get(id);
      if (element === undefined) {
        element = new FakeElement();
        elements.set(id, element);
      }
      return element;
    },
    querySelectorAll(selector: string): FakeElement[] {
      return groups.get(selector) ?? [];
    },
    createElement(): FakeElement {
      return new FakeElement();
    },
    execCommand(): boolean {
      return true;
    },
  };

  const location = { hash: options.hash, pathname: "/", search: "" };
  let networkMode: NetworkMode = options.mode ?? "success";
  let resolvePendingGate!: () => void;
  const pending = new Promise<void>((resolve) => {
    resolvePendingGate = resolve;
  });
  const requestTokens: string[] = [];
  const requests: ClientRequest[] = [];
  const clipboardWrites: string[] = [];
  let keyRevision = "kr-test-1";
  let keys = [keySummary(KEY_ID, "默认部署密钥")];
  const profileKind = options.profile ?? "openssh";
  let plinkExecutable = profileKind === "accessclient" ? "C:\\Tools\\plink.exe" : "";
  const initialKeyId = options.mode === "orphan-key" ? SECOND_KEY_ID : KEY_ID;
  let currentProfile: unknown = fleetProfile(
    initialKeyId,
    profileKind,
    plinkExecutable,
    options.description,
  );
  let accessClientPreparation: Record<string, unknown> = networkMode === "prepare-active"
    ? {
        state: "armed",
        alias: "alpha",
        sharingHost: "192.0.2.20",
        startedAt: "2026-08-11T00:00:00.000Z",
        deadlineAt: "2026-08-11T00:01:00.000Z",
      }
    : { state: "idle" };
  const window = {
    location,
    sessionStorage: options.storage,
    history: {
      replaceState(): void {
        location.hash = "";
      },
    },
    confirm(): boolean { return true; },
    setTimeout(): number { return 0; },
    clearTimeout(): void {},
    atob(value: string): string { return Buffer.from(value, "base64").toString("binary"); },
  };

  const fetch = async (_url: string, init: { readonly body?: string; readonly headers?: Record<string, string> }): Promise<unknown> => {
    requestTokens.push(init.headers?.["X-Agent-SSH-UI-Token"] ?? "");
    const body = typeof init.body === "string" ? JSON.parse(init.body) as unknown : undefined;
    requests.push({ url: _url, body });
    if (networkMode === "pending") await pending;
    if (networkMode === "offline") throw new Error("offline");
    if (networkMode === "invalid-session") {
      return response(403, {
        error: { code: "INVALID_SESSION", message: "Test UI session was rejected" },
      });
    }
    if ((networkMode === "config-error" || networkMode === "config-error-with-keys") && _url.endsWith("/api/admin/bootstrap")) {
      return response(200, {
        state: "error",
        configured: networkMode === "config-error-with-keys",
        ...(networkMode === "config-error-with-keys"
          ? {
              revision: `r-test-${"a".repeat(32)}`,
              keyRevision,
              keys,
              profile: currentProfile,
            }
          : {}),
        defaultKnownHostsFile: "C:\\Users\\test\\.ssh\\known_hosts",
        commandPresets: commandPresets(),
        error: { code: "CONFIG_INVALID", message: "Saved configuration could not be read" },
      });
    }
    if (_url.endsWith("/api/admin/bootstrap")) {
      const status = fleetStatus({
        keyId: networkMode === "orphan-key" ? SECOND_KEY_ID : KEY_ID,
        keyRevision,
        keys: networkMode === "keys-error"
          ? undefined
          : networkMode === "key-storage-error" || networkMode === "key-file-unsafe"
            ? []
            : keys,
        ...(networkMode === "key-file-unsafe"
          ? { keyError: { code: "FILE_UNSAFE", message: "Stored private key is unsafe" } }
          : {}),
        error: networkMode === "key-storage-error"
          ? { code: "KEY_STORAGE_INVALID", message: "Stored key metadata is invalid" }
          : undefined,
        profile: currentProfile,
      }) as Record<string, unknown>;
      return response(200, {
        ...status,
        accessClientSession: accessClientPreparation,
      });
    }
    if (_url.endsWith("/api/admin/key/generate")) {
      const label = typeof (body as { readonly label?: unknown })?.label === "string"
        ? (body as { readonly label: string }).label
        : "新密钥";
      const requestedAlgorithm = (body as { readonly algorithm?: unknown })?.algorithm;
      keys = [
        ...keys,
        keySummary(
          SECOND_KEY_ID,
          label,
          requestedAlgorithm === "rsa-3072" ? "ssh-rsa" : "ssh-ed25519",
        ),
      ];
      keyRevision = "kr-test-2";
      return response(200, fleetStatus({
        keyId: KEY_ID,
        keyRevision,
        keys,
        error: undefined,
        profile: currentProfile,
      }));
    }
    if (_url.endsWith("/api/admin/target/enabled")) {
      const request = body && typeof body === "object"
        ? body as { readonly alias?: unknown; readonly enabled?: unknown }
        : {};
      if (typeof request.alias === "string" && typeof request.enabled === "boolean") {
        const profile = currentProfile && typeof currentProfile === "object"
          ? currentProfile as { readonly accessClient?: unknown; readonly targets?: Record<string, unknown> }
          : {};
        const target = profile.targets?.[request.alias];
        if (target && typeof target === "object") {
          currentProfile = {
            version: 3,
            ...(profile.accessClient === undefined ? {} : { accessClient: profile.accessClient }),
            targets: {
              ...(profile.targets ?? {}),
              [request.alias]: { ...target, enabled: request.enabled },
            },
          };
        }
      }
      return response(200, fleetStatus({
        keyId: KEY_ID,
        keyRevision,
        keys,
        error: undefined,
        profile: currentProfile,
      }));
    }
    if (_url.endsWith("/api/admin/target/save")) {
      const request = body && typeof body === "object"
        ? body as { readonly alias?: unknown; readonly target?: unknown }
        : {};
      if (typeof request.alias === "string" && request.target && typeof request.target === "object") {
        const profile = currentProfile && typeof currentProfile === "object"
          ? currentProfile as { readonly accessClient?: unknown; readonly targets?: Record<string, unknown> }
          : {};
        currentProfile = {
          version: 3,
          ...(profile.accessClient === undefined ? {} : { accessClient: profile.accessClient }),
          targets: {
            ...(profile.targets ?? {}),
            [request.alias]: request.target,
          },
        };
      }
      return response(200, fleetStatus({
        keyId: KEY_ID,
        keyRevision,
        keys,
        error: undefined,
        profile: currentProfile,
      }));
    }
    if (_url.endsWith("/api/admin/access-client/save")) {
      const request = body && typeof body === "object"
        ? body as { readonly plinkExecutable?: unknown }
        : {};
      if (typeof request.plinkExecutable === "string") {
        plinkExecutable = request.plinkExecutable;
        const profile = currentProfile && typeof currentProfile === "object"
          ? currentProfile as { readonly targets?: Record<string, unknown> }
          : {};
        currentProfile = {
          version: 3,
          accessClient: { plinkExecutable },
          targets: profile.targets ?? {},
        };
      }
      return response(200, fleetStatus({
        keyId: KEY_ID,
        keyRevision,
        keys,
        error: undefined,
        profile: currentProfile,
      }));
    }
    if (_url.endsWith("/api/admin/access-client/session/prepare")) {
      accessClientPreparation = {
        state: "armed",
        alias: "alpha",
        sharingHost: "192.0.2.20",
        startedAt: "2026-08-11T00:00:00.000Z",
        deadlineAt: "2026-08-11T00:01:00.000Z",
      };
      return response(202, accessClientPreparation);
    }
    if (_url.endsWith("/api/admin/access-client/session/status")) {
      return response(200, accessClientPreparation);
    }
    if (_url.endsWith("/api/admin/access-client/session/cancel")) {
      accessClientPreparation = {
        state: "cancelled",
        alias: "alpha",
        completedAt: "2026-08-11T00:00:01.000Z",
      };
      return response(200, accessClientPreparation);
    }
    if (_url.endsWith("/api/admin/target/check")) {
      return response(200, {
        target: "alpha",
        connected: false,
        termination: "exit",
        exitCode: 255,
        durationMs: 4,
        failureReason: networkMode === "check-host-mismatch"
          ? "accessclient-host-mismatch"
          : "accessclient-session-unavailable",
      });
    }
    if (_url.endsWith("/api/targets")) {
      return response(200, { targets: [{ alias: "alpha", enabled: true }] });
    }
    return response(200, { mode: "managed", gateway: { ok: true } });
  };

  vm.runInNewContext(source, {
    AbortController,
    Blob,
    Date,
    Math,
    Map,
    Number,
    Object,
    Promise,
    Set,
    String,
    TextDecoder,
    URL,
    URLSearchParams,
    console,
    document,
    fetch,
    navigator: { clipboard: { writeText: async (value: string): Promise<void> => { clipboardWrites.push(value); } } },
    window,
  }, { filename: APP_SCRIPT.pathname });

  const settle = async (): Promise<void> => {
    for (let index = 0; index < 4; index += 1) {
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
  };
  await settle();
  return {
    elements,
    inputGroups: groups,
    clipboardWrites,
    requests,
    requestTokens,
    storage: options.storage,
    releasePending(mode = "success"): void {
      networkMode = mode;
      resolvePendingGate();
    },
    setNetworkMode(mode: NetworkMode): void { networkMode = mode; },
    settle,
  };
}

function createInputGroups(): Map<string, FakeElement[]> {
  const input = (value: string, checked = false): FakeElement => {
    const element = new FakeElement();
    element.value = value;
    element.checked = checked;
    return element;
  };
  const operation = (value: string): FakeElement => {
    const element = new FakeElement();
    element.dataset.operation = value;
    return element;
  };
  return new Map([
    ['input[name="platform"]', [input("windows"), input("linux", true), input("macos")]],
    ['input[name="connection-mode"]', [input("openssh", true), input("accessclient-share"), input("tailscale-ssh")]],
    ['input[name="policy-mode"]', [input("allow-list", true), input("full-access"), input("deny")]],
    ['input[name="transfer-mode"]', [input("deny", true), input("upload"), input("download"), input("bidirectional")]],
    [".operation-tab", [operation("exec"), operation("transfer"), operation("inspect")]],
    ['input[name="execution-format"]', [input("single", true), input("structured")]],
    ['input[name="remote-shell"]', [input("powershell"), input("cmd"), input("bash", true)]],
    ['input[name="transfer-kind"]', [input("upload", true), input("download"), input("sync")]],
    ['input[name="docker-intent"]', [input("inspect", true), input("create"), input("update")]],
  ]);
}

function response(status: number, body: unknown): unknown {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json(): Promise<unknown> { return body; },
  };
}

function commandPresets(): Record<string, string[]> {
  return {
    windows: ["hostname"],
    linux: ["hostname"],
    macos: ["hostname"],
  };
}

function keySummary(
  keyId: string,
  label: string,
  algorithm = "ssh-ed25519",
): unknown {
  return {
    keyId,
    label,
    algorithm,
    fingerprint: `SHA256:${keyId.slice(2, 18)}`,
    publicKey: `${algorithm} ${Buffer.from(keyId).toString("base64")} test`,
    createdAt: "2026-08-10T00:00:00.000Z",
    origin: "generated",
    inUseBy: keyId === KEY_ID ? [{ alias: "alpha", role: "target" }] : [],
  };
}

function fleetStatus(options: {
  readonly keyId: string;
  readonly keyRevision: string;
  readonly keys: readonly unknown[] | undefined;
  readonly keyError?: Readonly<{ readonly code: string; readonly message: string }>;
  readonly error: Readonly<{ readonly code: string; readonly message: string }> | undefined;
  readonly profile?: unknown;
}): unknown {
  return {
    state: "ready",
    configured: true,
    revision: `r-test-${"a".repeat(32)}`,
    keyRevision: options.keyRevision,
    keys: options.keys,
    ...(options.keyError === undefined ? {} : { keyError: options.keyError }),
    ...(options.error === undefined ? {} : { error: options.error }),
    defaultKnownHostsFile: "C:\\Users\\test\\.ssh\\known_hosts",
    commandPresets: commandPresets(),
    profile: options.profile ?? fleetProfile(options.keyId),
  };
}

function fleetProfile(
  keyId: string,
  kind: ClientProfileKind = "openssh",
  plinkExecutable = "",
  description?: string,
): unknown {
  if (kind === "tailscale") {
    return { version: 3, tailscale: { executable: "C:\\Program Files\\Tailscale\\tailscale.exe" }, targets: { alpha: {
      enabled: true, connectionMode: "tailscale-ssh", target: { host: "build", port: 22, username: "ubuntu" }, platform: "linux", policyMode: "allow-list", allowedCommands: ["hostname"], maxTimeoutMs: 30000, transferMode: "deny",
    } } };
  }
  if (kind !== "openssh") {
    return {
      version: 3,
      ...(plinkExecutable ? { accessClient: { plinkExecutable } } : {}),
      targets: {
        alpha: {
          enabled: true,
          connectionMode: "accessclient-share",
          target: {
            host: "192.0.2.20",
            port: 22,
            username: "target-user",
          },
          accessClient: {
            gatewayHost: "gateway.example.test",
            gatewayPort: 2222,
            gatewayUsername: "portal-user",
            expectedHostname: "access-target",
          },
          platform: "windows",
          policyMode: "allow-list",
          allowedCommands: ["hostname"],
          maxTimeoutMs: 30_000,
          transferMode: "deny",
        },
      },
    };
  }
  return {
    version: 3,
    targets: {
      alpha: {
        ...(description === undefined ? {} : { description }),
        enabled: true,
        connectionMode: "openssh",
        target: {
          host: "192.0.2.10",
          port: 22,
          username: "tester",
          keyId,
        },
        knownHostsFile: "C:\\keys\\known_hosts",
        platform: "linux",
        policyMode: "allow-list",
        allowedCommands: ["hostname"],
        maxTimeoutMs: 30_000,
      },
    },
  };
}

function requireElement(harness: ClientHarness, id: string): FakeElement {
  const element = harness.elements.get(id);
  assert.notEqual(element, undefined, `missing fake element #${id}`);
  return element!;
}


test("Tailscale UI needs no private key and submits a credential-free command-only target", async () => {
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, profile: "tailscale", mode: "keys-error", storage: new MemoryStorage() });
  assert.equal(requireElement(harness, "tailscale-connection-note").hidden, false);
  assert.equal(requireElement(harness, "target-key-field").hidden, true);
  assert.equal(requireElement(harness, "known-hosts-field").hidden, true);
  assert.equal(requireElement(harness, "target-port-field").hidden, true);
  assert.equal(requireElement(harness, "save-button").disabled, false);
  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();
  const request = harness.requests.find((candidate) => candidate.url.endsWith("/api/admin/target/save"));
  assert.ok(request);
  const body = request.body as { target: { connectionMode: string; target: Record<string, unknown>; knownHostsFile?: string; accessClient?: unknown; transferMode: string } };
  assert.equal(body.target.connectionMode, "tailscale-ssh");
  assert.equal(body.target.target.port, 22);
  assert.equal(body.target.target.keyId, undefined);
  assert.equal(body.target.knownHostsFile, undefined);
  assert.equal(body.target.accessClient, undefined);
  assert.equal(body.target.transferMode, "deny");
});
