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
  public constructor(public readonly tagName = "DIV") {}
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
  public focusCount = 0;
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
  public focus(): void { this.focusCount += 1; }
  public select(): void {}
  public setCustomValidity(): void {}
  public reportValidity(): boolean { return true; }
  public matches(): boolean { return false; }
  public querySelectorAll(selector: string): FakeElement[] {
    const matches = (item: FakeElement) => selector.split(",").some((entry) => {
      const candidate = entry.trim();
      return candidate.startsWith(".") ? item.className.split(" ").includes(candidate.slice(1)) : item.tagName.toLowerCase() === candidate;
    });
    return this.#children.flatMap((child) => [...(matches(child) ? [child] : []), ...child.querySelectorAll(selector)]);
  }
  public querySelector(selector: string): FakeElement | null { return this.querySelectorAll(selector)[0] ?? null; }

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

type NetworkMode = "success" | "invalid-session" | "offline" | "config-error" | "config-error-with-keys" | "key-storage-error" | "key-file-unsafe" | "keys-error" | "orphan-key" | "pending" | "check-unavailable" | "check-host-mismatch" | "prepare-active" | "group-conflict";
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

  const machineItem = requireElement(harness, "machine-list").children.find((item) => item.dataset.alias);
  assert.notEqual(machineItem, undefined);
  const selectButton = machineItem!.children[0];
  const descriptionElement = selectButton?.querySelector(".machine-description");
  assert.equal(descriptionElement?.textContent, description);
  assert.equal(descriptionElement?.title, description);
  assert.equal(descriptionElement?.children.length, 0);
});

test("machine groups render safely, filter membership and survive save or removal", async () => {
  const group = "A组 <b>生产</b>";
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, storage: new MemoryStorage(), targetGroups: { alpha: group, beta: "B组", gamma: undefined } });
  const list = requireElement(harness, "machine-list");
  const groupLabels = () => list.children.filter((item) => item.className === "machine-group-heading").map((item) => item.querySelector(".machine-group-name")?.textContent);
  assert.deepEqual(groupLabels(), ["默认分组", group, "B组"]);
  const groupName = list.children.find((item) => item.dataset.group === group)?.querySelector(".machine-group-name");
  assert.equal(groupName?.children.length, 0);
  assert.equal(requireElement(harness, "target-group").value, group);
  const filter = requireElement(harness, "machine-group-filter");
  filter.value = "group:B组";
  filter.dispatch("change");
  assert.equal(list.children.length, 2);
  assert.deepEqual(groupLabels(), ["B组"]);
  filter.value = "ungrouped";
  filter.dispatch("change");
  assert.deepEqual(groupLabels(), ["默认分组"]);
  filter.value = "";
  filter.dispatch("change");
  const search = requireElement(harness, "machine-search");
  search.value = "B组";
  search.dispatch("input");
  assert.deepEqual(groupLabels(), ["B组"]);
  search.value = "";
  search.dispatch("input");
  const field = requireElement(harness, "target-group");
  field.value = " B组 ";
  requireElement(harness, "machine-form").dispatch("input", field);
  assert.match(requireElement(harness, "saved-indicator").textContent, /未保存/u);
  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();
  const saved = harness.requests.findLast((request) => request.url.endsWith("/api/admin/target/save"))?.body as { target: { group?: string } };
  assert.equal(saved.target.group, "B组");
  assert.equal(list.children.find((item) => item.dataset.group === "B组")?.querySelector(".group-count")?.textContent, "2");
  field.value = "";
  requireElement(harness, "machine-form").dispatch("input", field);
  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();
  const cleared = harness.requests.findLast((request) => request.url.endsWith("/api/admin/target/save"))?.body as { target: { group?: string } };
  assert.equal(Object.hasOwn(cleared.target, "group"), false);
  assert.equal(requireElement(harness, "machine-count").textContent, "3");
});

test("group directory preserves collapsed choices during search and exposes only existing group options", async () => {
  const storage = new MemoryStorage();
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, storage, targetGroups: { alpha: "A组" }, customGroups: ["A组", "空组"] });
  const list = requireElement(harness, "machine-list");
  const defaultHeading = list.children.find((item) => item.dataset.group === "");
  assert.equal(defaultHeading?.children[1]?.className, "group-protected");
  assert.equal(defaultHeading?.querySelector(".group-count")?.textContent, "0");
  assert.deepEqual(requireElement(harness, "target-group").children.map((option) => option.value), ["", "A组", "空组"]);
  const toggle = list.children.find((item) => item.dataset.group === "A组")?.children[0];
  toggle?.dispatch("click");
  assert.equal(list.children.find((item) => item.dataset.alias === "alpha")?.hidden, true);
  const search = requireElement(harness, "machine-search");
  search.value = "alpha";
  search.dispatch("input");
  assert.equal(list.children.find((item) => item.dataset.alias === "alpha")?.hidden, false);
  search.value = "";
  search.dispatch("input");
  assert.equal(list.children.find((item) => item.dataset.alias === "alpha")?.hidden, true);
  assert.ok(list.children.some((item) => item.dataset.group === "空组"));
  const reloaded = await startClient({ hash: "", storage, targetGroups: { alpha: "A组" } });
  assert.equal(requireElement(reloaded, "machine-list").children.find((item) => item.dataset.alias === "alpha")?.hidden, true);
});

test("group create, move, reorder, rename and delete update inventory without deleting machines", async () => {
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, storage: new MemoryStorage(), targetGroups: { alpha: undefined }, customGroups: ["A组"] });
  const list = requireElement(harness, "machine-list");
  const submit = async () => { requireElement(harness, "group-dialog-form").dispatch("submit"); await harness.settle(); };
  requireElement(harness, "new-group-button").dispatch("click");
  requireElement(harness, "group-name").value = "B组";
  await submit();
  assert.ok(list.children.some((item) => item.dataset.group === "B组"));
  assert.equal(list.children.find((item) => item.dataset.group === "B组")?.children[0]?.focusCount, 1);
  const create = harness.requests.find((request) => request.url.endsWith("/admin/group/create"));
  assert.deepEqual(create?.body, { name: "B组", expectedRevision: `r-test-${"a".repeat(32)}` });
  list.children.find((item) => item.dataset.alias === "alpha")?.children.find((item) => item.className === "machine-move-button")?.dispatch("click");
  requireElement(harness, "group-destination").value = "B组";
  await submit();
  assert.equal(requireElement(harness, "target-group").value, "B组");
  list.children.find((item) => item.dataset.group === "B组")?.children[1]?.dispatch("click");
  requireElement(harness, "group-up-button").dispatch("click");
  await harness.settle();
  assert.deepEqual(list.children.filter((item) => item.className === "machine-group-heading").map((item) => item.dataset.group), ["", "B组", "A组"]);
  list.children.find((item) => item.dataset.group === "B组")?.children[1]?.dispatch("click");
  requireElement(harness, "group-name").value = "生产组";
  await submit();
  assert.equal(requireElement(harness, "target-group").value, "生产组");
  list.children.find((item) => item.dataset.group === "生产组")?.children[1]?.dispatch("click");
  requireElement(harness, "group-delete-button").dispatch("click");
  assert.match(requireElement(harness, "group-dialog-description").textContent, /1 台机器将移到默认分组/u);
  assert.equal(harness.requests.filter((request) => request.url.endsWith("/admin/group/delete")).length, 0);
  await submit();
  assert.equal(requireElement(harness, "target-group").value, "");
  assert.equal(requireElement(harness, "machine-count").textContent, "1");
  assert.ok(list.children.some((item) => item.dataset.alias === "alpha"));
  assert.ok(!list.children.some((item) => item.dataset.group === "生产组"));
  assert.equal(list.children.find((item) => item.dataset.group === "")?.children[0]?.focusCount, 1);
});

test("group dialogs preserve unsaved machine forms and reject reserved or duplicate group names", async () => {
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, storage: new MemoryStorage(), targetGroups: { alpha: "A组" } });
  const description = requireElement(harness, "target-description");
  description.value = "未保存说明";
  requireElement(harness, "machine-form").dispatch("input", description);
  requireElement(harness, "new-group-button").dispatch("click");
  for (const name of ["默认分组", "A组"]) {
    requireElement(harness, "group-name").value = name;
    requireElement(harness, "group-dialog-form").dispatch("submit");
    await harness.settle();
    assert.equal(harness.requests.filter((request) => request.url.includes("/admin/group/")).length, 0);
  }
  requireElement(harness, "group-name").value = "新组";
  requireElement(harness, "group-dialog-form").dispatch("submit");
  await harness.settle();
  assert.equal(description.value, "未保存说明");
  const list = requireElement(harness, "machine-list");
  list.children.find((item) => item.dataset.alias === "alpha")?.children.find((item) => item.className === "machine-move-button")?.dispatch("click");
  requireElement(harness, "group-destination").value = "新组";
  requireElement(harness, "group-dialog-form").dispatch("submit");
  await harness.settle();
  assert.match(requireElement(harness, "group-dialog-error").textContent, /未保存/u);
  assert.equal(harness.requests.filter((request) => request.url.endsWith("/admin/group/move")).length, 0);
  assert.equal(description.value, "未保存说明");
});

test("an unconfigured inventory can create its first empty group without a revision", async () => {
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, storage: new MemoryStorage(), unconfigured: true });
  assert.equal(requireElement(harness, "new-group-button").disabled, false);
  requireElement(harness, "new-group-button").dispatch("click");
  requireElement(harness, "group-name").value = "新组";
  requireElement(harness, "group-dialog-form").dispatch("submit");
  await harness.settle();
  assert.deepEqual(harness.requests.find((request) => request.url.endsWith("/admin/group/create"))?.body, { name: "新组" });
  assert.ok(requireElement(harness, "machine-list").children.some((item) => item.dataset.group === "新组"));
});

test("group conflicts keep inventory intact and failed refresh allows only directory navigation", async () => {
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, storage: new MemoryStorage(), mode: "group-conflict", targetGroups: { alpha: "A组" } });
  const list = requireElement(harness, "machine-list");
  list.children.find((item) => item.dataset.group === "A组")?.children[1]?.dispatch("click");
  requireElement(harness, "group-name").value = "新组";
  requireElement(harness, "group-dialog-form").dispatch("submit");
  await harness.settle();
  assert.match(requireElement(harness, "group-dialog-error").textContent, /配置版本已变化/u);
  assert.equal(requireElement(harness, "group-submit-button").textContent, "保存名称");
  assert.equal(requireElement(harness, "group-dialog-status").hidden, true);
  assert.equal(requireElement(harness, "target-group").value, "A组");
  assert.equal(requireElement(harness, "machine-count").textContent, "1");
  requireElement(harness, "group-cancel-button").dispatch("click");
  harness.setNetworkMode("offline");
  requireElement(harness, "refresh-button").dispatch("click");
  await harness.settle();
  assert.equal(requireElement(harness, "new-group-button").disabled, true);
  const heading = list.children.find((item) => item.dataset.group === "A组");
  assert.equal(heading?.children[1]?.disabled, true);
  assert.equal(heading?.children[0]?.disabled, false);
  heading?.children[0]?.dispatch("click");
  assert.equal(list.children.find((item) => item.dataset.alias === "alpha")?.hidden, true);
});

test("a slow group save displays progress and rejects duplicate submissions", async () => {
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, storage: new MemoryStorage() });
  requireElement(harness, "new-group-button").dispatch("click");
  requireElement(harness, "group-name").value = "A组";
  harness.setNetworkMode("pending");
  requireElement(harness, "group-dialog-form").dispatch("submit");
  await harness.settle();
  assert.equal(requireElement(harness, "group-submit-button").textContent, "保存中…");
  assert.equal(requireElement(harness, "group-submit-button").disabled, true);
  assert.equal(requireElement(harness, "group-dialog-status").hidden, false);
  requireElement(harness, "group-dialog-form").dispatch("submit");
  assert.equal(harness.requests.filter((request) => request.url.endsWith("/admin/group/create")).length, 1);
  harness.releasePending();
  await harness.settle();
  assert.equal(requireElement(harness, "group-dialog-status").hidden, true);
});

test("the machine list MCP switch applies immediately without overwriting a dirty form", async () => {
  const harness = await startClient({
    hash: `#token=${SESSION_TOKEN}`,
    storage: new MemoryStorage(),
  });
  const description = requireElement(harness, "target-description");
  description.value = "尚未保存的新说明";
  requireElement(harness, "machine-form").dispatch("input", description);

  const machineItem = requireElement(harness, "machine-list").children.find((item) => item.dataset.alias)!;
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
  assert.match(requireElement(harness, "saved-indicator").textContent, /未保存/u);
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
  assert.match(requireElement(harness, "saved-indicator").textContent, /未保存/u);
  requireElement(harness, "settings-tab").dispatch("click");
  assert.match(requireElement(harness, "saved-indicator").textContent, /机器配置未保存/u);
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
  assert.match(requireElement(harness, "saved-indicator").textContent, /机器配置未保存/u);
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

test("AccessClient no-op and metadata saves preserve hidden legacy transport fields", async () => {
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, profile: "accessclient", storage: new MemoryStorage() });
  const savedTarget = (fleetProfile(KEY_ID, "accessclient", "C:\\Tools\\plink.exe") as { targets: { alpha: object } }).targets.alpha;
  const save = async () => {
    requireElement(harness, "machine-form").dispatch("submit");
    await harness.settle();
    return (harness.requests.findLast((request) => request.url.endsWith("/api/admin/target/save"))?.body as { target: object }).target;
  };
  assert.deepEqual(await save(), savedTarget);
  requireElement(harness, "target-host").value = "temporary.example.test";
  requireElement(harness, "machine-form").dispatch("input");
  requireElement(harness, "target-host").value = "192.0.2.20";
  requireElement(harness, "machine-form").dispatch("input");
  assert.deepEqual(await save(), savedTarget);
  requireElement(harness, "target-description").value = "更新说明";
  requireElement(harness, "machine-form").dispatch("input");
  assert.deepEqual(await save(), { ...savedTarget, description: "更新说明" });
  requireElement(harness, "target-host").value = "192.0.2.99";
  requireElement(harness, "machine-form").dispatch("input");
  const changed = await save() as { target: { host: string; username: string }; accessClient: { gatewayHost: string } };
  assert.equal(changed.target.host, "192.0.2.99");
  assert.equal(changed.target.username, "portal-user");
  assert.equal(changed.accessClient.gatewayHost, "192.0.2.99");
});

test("OpenSSH metadata saves preserve unrendered bastion and optional operational fields", async () => {
  const hidden = { bastion: { host: "jump.example.test", port: 2222, username: "jump", keyId: SECOND_KEY_ID }, maxTransferTimeoutMs: 600000, targetId: `t-${"c".repeat(32)}`, previousAliases: ["legacy"] };
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, storage: new MemoryStorage(), targetPatch: hidden });
  requireElement(harness, "target-description").value = "Only metadata";
  requireElement(harness, "machine-form").dispatch("input");
  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();
  const body = harness.requests.findLast((request) => request.url.endsWith("/api/admin/target/save"))?.body as { target: Record<string, unknown> };
  const original = (fleetProfile(KEY_ID) as { targets: { alpha: object } }).targets.alpha;
  assert.deepEqual(body.target, { ...original, ...hidden, description: "Only metadata" });
});

test("preset controls persist operational changes and block raw command execution", async () => {
  const patch = { policyMode: "presets", allowedCommands: [], permissionPresets: ["basic-inspection", "docker-protection"], logPaths: [], logServices: [], transferMode: "deny" };
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, storage: new MemoryStorage(), targetPatch: patch });
  assert.equal(requireElement(harness, "preset-fields").hidden, false);
  assert.equal(requireElement(harness, "run-button").disabled, true);
  assert.match(requireElement(harness, "command-note").textContent, /ssh_run_operation/u);
  assert.match(requireElement(harness, "preset-effective").textContent, /Docker 服务与容器变更/u);
  const presets = harness.inputGroups.get('input[name="permission-preset"]')!;
  presets.find((input) => input.value === "log-inspection")!.checked = true;
  requireElement(harness, "preset-log-paths").value = "/var/log/myapp.log";
  requireElement(harness, "machine-form").dispatch("input");
  assert.equal(requireElement(harness, "preset-log-fields").hidden, false);
  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();
  const saved = harness.requests.findLast((request) => request.url.endsWith("/api/admin/target/save"))?.body as { target: Record<string, unknown> };
  assert.deepEqual(saved.target.permissionPresets, ["basic-inspection", "log-inspection", "docker-protection"]);
  assert.deepEqual(saved.target.logPaths, ["/var/log/myapp.log"]);
  assert.equal(saved.target.transferMode, "deny");
  assert.deepEqual(saved.target.allowedCommands, []);
});

test("preset metadata saves preserve exact stored permissions and legacy optional fields", async () => {
  const patch = { policyMode: "presets", allowedCommands: [], permissionPresets: ["docker-protection"], logPaths: [], logServices: [], transferMode: "deny", previousAliases: ["old-alpha"] };
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, storage: new MemoryStorage(), targetPatch: patch });
  assert.match(requireElement(harness, "preset-effective").textContent, /尚未授予任何操作/u);
  requireElement(harness, "target-description").value = "巡检机器";
  requireElement(harness, "machine-form").dispatch("input");
  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();
  const saved = harness.requests.findLast((request) => request.url.endsWith("/api/admin/target/save"))?.body as { target: Record<string, unknown> };
  const original = (fleetProfile(KEY_ID) as { targets: { alpha: object } }).targets.alpha;
  assert.deepEqual(saved.target, { ...original, ...patch, description: "巡检机器" });
});

test("a new OpenSSH machine uses its single IP field as the endpoint and generated alias", async () => {
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, storage: new MemoryStorage() });
  requireElement(harness, "new-machine-button").dispatch("click");
  assert.equal(harness.elements.has("target-alias"), false);
  assert.equal(requireElement(harness, "target-host").focusCount, 1);
  requireElement(harness, "target-host").value = "192.0.2.30";
  requireElement(harness, "target-username").value = "ubuntu";
  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();
  const body = harness.requests.findLast((request) => request.url.endsWith("/api/admin/target/save"))?.body as {
    alias: string; previousAlias?: string; target: { target: { host: string } };
  };
  assert.ok(body);
  assert.equal(body.alias, "192.0.2.30");
  assert.equal(body.target.target.host, "192.0.2.30");
  assert.equal(body.previousAlias, undefined);
});

test("a new IPv6 machine generates an SSH-safe alias from its canonical IP", async () => {
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, storage: new MemoryStorage() });
  requireElement(harness, "new-machine-button").dispatch("click");
  requireElement(harness, "target-host").value = "2001:0DB8:0:0:0:0:0:30";
  requireElement(harness, "target-username").value = "ubuntu";
  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();
  const body = harness.requests.findLast((request) => request.url.endsWith("/api/admin/target/save"))?.body as {
    alias: string; target: { target: { host: string } };
  };
  assert.ok(body);
  assert.equal(body.alias, "ip-2001-db8--30");
  assert.equal(body.target.target.host, "2001:db8::30");
});

test("invalid machine IPs are rejected before save without accepting hostnames, URLs or ports", async () => {
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, storage: new MemoryStorage() });
  requireElement(harness, "new-machine-button").dispatch("click");
  requireElement(harness, "target-username").value = "ubuntu";
  for (const host of ["", "256.1.2.3", "192.0.2", "192.00.2.30", "server.example.test", "https://192.0.2.30", "192.0.2.30:22", "[2001:db8::30]:22", "2001:::30"]) {
    requireElement(harness, "target-host").value = host;
    requireElement(harness, "machine-form").dispatch("submit");
    await harness.settle();
    assert.equal(harness.requests.filter((request) => request.url.endsWith("/api/admin/target/save")).length, 0, host);
    assert.match(requireElement(harness, "form-error").textContent, /IP/u, host);
  }
});

test("editing a saved machine IP preserves its existing MCP alias and identity", async () => {
  const targetId = `t-${"c".repeat(32)}`;
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, storage: new MemoryStorage(), targetPatch: { targetId, previousAliases: ["legacy-alpha"] } });
  requireElement(harness, "target-host").value = "192.0.2.99";
  requireElement(harness, "machine-form").dispatch("input");
  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();
  const body = harness.requests.findLast((request) => request.url.endsWith("/api/admin/target/save"))?.body as {
    alias: string; previousAlias: string; target: { target: { host: string }; targetId?: string; previousAliases?: string[] };
  };
  assert.ok(body);
  assert.equal(body.alias, "alpha");
  assert.equal(body.previousAlias, "alpha");
  assert.equal(body.target.target.host, "192.0.2.99");
  // Identity is preserved by the server's previousAlias lookup, not a newly generated IP alias.
});

test("unchanged legacy hostnames can still save metadata but edited hostnames must be IPs", async () => {
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, storage: new MemoryStorage(), profile: "tailscale" });
  requireElement(harness, "target-description").value = "Build worker";
  requireElement(harness, "machine-form").dispatch("input");
  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();
  const saved = harness.requests.findLast((request) => request.url.endsWith("/api/admin/target/save"))?.body as { alias: string; target: { target: { host: string } } };
  assert.ok(saved);
  assert.equal(saved.alias, "alpha");
  assert.equal(saved.target.target.host, "build");
  requireElement(harness, "target-host").value = "other-build";
  requireElement(harness, "machine-form").dispatch("input");
  requireElement(harness, "machine-form").dispatch("submit");
  await harness.settle();
  assert.equal(harness.requests.filter((request) => request.url.endsWith("/api/admin/target/save")).length, 1);
  assert.match(requireElement(harness, "form-error").textContent, /IP/u);
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
    readonly alias?: string;
    readonly target?: {
      readonly target?: Record<string, unknown>;
      readonly accessClient?: Record<string, unknown>;
    };
  };
  assert.equal(body.alias, "192.0.2.30");
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
  assert.match(requireElement(harness, "saved-indicator").textContent, /未保存/u);
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
  assert.match(requireElement(harness, "saved-indicator").textContent, /全局设置未保存/u);
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
  readonly targetGroups?: Readonly<Record<string, string | undefined>>;
  readonly customGroups?: readonly string[];
  readonly unconfigured?: boolean;
  readonly targetPatch?: Readonly<Record<string, unknown>>;
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
    createElement(tagName: string): FakeElement {
      return new FakeElement(tagName.toUpperCase());
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
  if (options.targetPatch) {
    const profile = currentProfile as { targets: Record<string, object> };
    currentProfile = { ...profile, targets: { ...profile.targets, alpha: { ...profile.targets.alpha, ...options.targetPatch } } };
  }
  if (options.targetGroups) {
    const profile = currentProfile as { targets: Record<string, Record<string, unknown>> };
    currentProfile = { ...profile, targets: Object.fromEntries(Object.entries(options.targetGroups).map(([alias, group]) => [alias, { ...profile.targets["alpha"], ...(group ? { group } : {}) }])) };
  }
  if (options.customGroups) currentProfile = { ...(currentProfile as object), groups: [...options.customGroups] };
  if (options.unconfigured) currentProfile = { version: 3, targets: {} };
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
        ...(options.unconfigured ? { revision: undefined } : {}),
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
    if (_url.includes("/api/admin/group/")) {
      if (networkMode === "group-conflict") return response(409, { error: { code: "REVISION_CONFLICT", message: "The configuration has changed" } });
      const action = _url.split("/").at(-1);
      const request = body as { name?: string; group?: string; aliases?: string[]; groups?: string[] };
      const profile = currentProfile as { groups?: string[]; targets: Record<string, Record<string, unknown>> };
      let customGroups = [...new Set([...(profile.groups ?? []), ...Object.values(profile.targets).map((target) => target["group"]).filter((group): group is string => typeof group === "string")])];
      const targets = Object.fromEntries(Object.entries(profile.targets).map(([alias, target]) => [alias, { ...target }]));
      if (action === "create") customGroups.push(request.name!);
      if (action === "rename" || action === "delete") {
        customGroups = customGroups.flatMap((group) => group !== request.group ? [group] : action === "rename" ? [request.name!] : []);
        for (const target of Object.values(targets)) {
          if (target["group"] !== request.group) continue;
          if (action === "delete") delete target["group"];
          else target["group"] = request.name;
        }
      }
      if (action === "move") {
        for (const alias of request.aliases ?? []) {
          if (request.group) targets[alias]!["group"] = request.group;
          else delete targets[alias]!["group"];
        }
      }
      if (action === "reorder") customGroups = request.groups!;
      currentProfile = { ...profile, groups: customGroups, targets };
      return response(200, fleetStatus({ keyId: KEY_ID, keyRevision, keys, error: undefined, profile: currentProfile }));
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
    ['input[name="policy-mode"]', [input("allow-list", true), input("full-access"), input("deny"), input("presets")]],
    ['input[name="permission-preset"]', [input("basic-inspection"), input("log-inspection"), input("docker-readonly"), input("docker-protection")]],
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


test("opening a stored public key immediately enables its copy action", async () => {
  const harness = await startClient({ hash: `#token=${SESSION_TOKEN}`, storage: new MemoryStorage() });
  assert.equal(requireElement(harness, "copy-public-key-button").disabled, true);
  const firstKey = requireElement(harness, "key-list").children[0];
  assert.ok(firstKey);
  const publicAction = firstKey.children[1]?.children[0];
  assert.ok(publicAction);
  publicAction.dispatch("click");
  assert.equal(requireElement(harness, "key-public-panel").hidden, false);
  assert.match(requireElement(harness, "public-key-output").textContent, /^ssh-/u);
  assert.equal(requireElement(harness, "copy-public-key-button").disabled, false);
});
