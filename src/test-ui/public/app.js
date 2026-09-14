"use strict";

const OUTPUT_PAGE_BYTES = 65_536;
const TASK_TAIL_BYTES = 65_536;
const TASK_POLL_INTERVAL_MS = 600;
const MAX_COMMAND_BYTES = 65_536;
const MAX_ENVIRONMENT_ENTRIES = 64;
const MAX_TIMEOUT_MS = 3_600_000;
const ALIAS_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const STANDARD_USERNAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const PASSTHROUGH_ACCOUNT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const KEY_GENERATION_ALGORITHMS = new Set(["ed25519", "rsa-3072"]);
const KEY_ID_PATTERN = /^k-[a-f0-9]{32}$/;
const ENVIRONMENT_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const DOCKER_PROJECT_PATTERN = /^[a-z0-9][a-z0-9_-]{0,62}$/;
const ABSOLUTE_LOCAL_PATH_PATTERN = /^(?:[A-Za-z]:[\\/]|\/)/u;
const WINDOWS_ABSOLUTE_FILE_PATTERN = /^[A-Za-z]:[\\/]/u;
const SSH_PUBLIC_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9@._+-]* [A-Za-z0-9+/]+={0,3}$/u;
const SESSION_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const SESSION_TOKEN_STORAGE_KEY = "agent-ssh-ui-token";
const DEFAULT_ACCESSCLIENT_USERNAME = "chenzilve";

const FALLBACK_COMMAND_PRESETS = Object.freeze({
  windows: Object.freeze([
    "hostname",
    "whoami",
    "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture | Format-List",
    "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime",
    "Get-Culture | Format-List Name, DisplayName",
  ]),
  linux: Object.freeze(["hostname", "whoami", "uname -a", "uptime"]),
  macos: Object.freeze(["hostname", "whoami", "sw_vers", "uptime"]),
});

const PLATFORM_LABELS = Object.freeze({ windows: "Windows", linux: "Linux", macos: "macOS" });
const POLICY_LABELS = Object.freeze({
  "allow-list": "白名单",
  "full-access": "Full access",
  deny: "禁止访问",
});
const TRANSFER_LABELS = Object.freeze({
  deny: "未授权",
  upload: "仅上传",
  download: "仅下载",
  bidirectional: "双向",
});
const CONNECTION_MODE_LABELS = Object.freeze({
  openssh: "OpenSSH",
  "accessclient-share": "AccessClient",
  "tailscale-ssh": "Tailscale SSH",
});

const fragment = new URLSearchParams(window.location.hash.slice(1));
const fragmentToken = fragment.get("token") ?? "";
let sessionToken = SESSION_TOKEN_PATTERN.test(fragmentToken)
  ? fragmentToken
  : readStoredSessionToken();
if (fragmentToken.length > 0 && !SESSION_TOKEN_PATTERN.test(fragmentToken)) {
  clearSessionToken();
}
if (window.location.hash.length > 0) {
  window.history.replaceState(null, document.title, `${window.location.pathname}${window.location.search}`);
}

function readStoredSessionToken() {
  try {
    const value = window.sessionStorage.getItem(SESSION_TOKEN_STORAGE_KEY) ?? "";
    return SESSION_TOKEN_PATTERN.test(value) ? value : "";
  } catch {
    return "";
  }
}

function clearSessionToken() {
  sessionToken = "";
  try {
    window.sessionStorage.removeItem(SESSION_TOKEN_STORAGE_KEY);
  } catch {
    // There is nothing else to clear when browser storage is unavailable.
  }
}

const elements = {
  gatewayDot: document.querySelector("#gateway-dot"),
  gatewayLabel: document.querySelector("#gateway-label"),
  gatewayDetail: document.querySelector("#gateway-detail"),
  refreshButton: document.querySelector("#refresh-button"),
  machineCount: document.querySelector("#machine-count"),
  machineSearch: document.querySelector("#machine-search"),
  inventoryNoResults: document.querySelector("#inventory-no-results"),
  actionHint: document.querySelector("#action-hint"),
  breadcrumbCurrent: document.querySelector("#breadcrumb-current"),
  machineList: document.querySelector("#machine-list"),
  inventoryEmpty: document.querySelector("#inventory-empty"),
  inventoryError: document.querySelector("#inventory-error"),
  revisionLabel: document.querySelector("#revision-label"),
  newMachineButton: document.querySelector("#new-machine-button"),
  workspaceTitle: document.querySelector("#workspace-title"),
  workspaceSubtitle: document.querySelector("#workspace-subtitle"),
  selectedStateBadge: document.querySelector("#selected-state-badge"),
  savedIndicator: document.querySelector("#saved-indicator"),
  configTab: document.querySelector("#config-tab"),
  commandTab: document.querySelector("#command-tab"),
  settingsTab: document.querySelector("#settings-tab"),
  configPanel: document.querySelector("#config-panel"),
  commandPanel: document.querySelector("#command-panel"),
  settingsPanel: document.querySelector("#settings-panel"),
  machineForm: document.querySelector("#machine-form"),
  targetAlias: document.querySelector("#target-alias"),
  targetDescription: document.querySelector("#target-description"),
  targetPortField: document.querySelector("#target-port-field"),
  targetKeyField: document.querySelector("#target-key-field"),
  knownHostsField: document.querySelector("#known-hosts-field"),
  tailscaleConnectionNote: document.querySelector("#tailscale-connection-note"),
  platformInputs: [...document.querySelectorAll('input[name="platform"]')],
  connectionModeInputs: [...document.querySelectorAll('input[name="connection-mode"]')],
  targetHost: document.querySelector("#target-host"),
  targetPort: document.querySelector("#target-port"),
  accessClientTargetPort: document.querySelector("#accessclient-target-port"),
  targetUsername: document.querySelector("#target-username"),
  targetKeyId: document.querySelector("#target-key-id"),
  targetKeyNote: document.querySelector("#target-key-note"),
  targetManageKeysButton: document.querySelector("#target-manage-keys-button"),
  sshInstallGuide: document.querySelector("#ssh-install-guide"),
  sshInstallCommand: document.querySelector("#ssh-install-command"),
  launchSshInstallButton: document.querySelector("#launch-ssh-install-button"),
  copySshInstallCommandButton: document.querySelector("#copy-ssh-install-command-button"),
  knownHostsFile: document.querySelector("#known-hosts-file"),
  knownHostsNote: document.querySelector("#known-hosts-note"),
  openSshConnectionFields: document.querySelector("#openssh-connection-fields"),
  accessClientConnectionFields: document.querySelector("#accessclient-connection-fields"),
  accessClientGatewayUsername: document.querySelector("#accessclient-gateway-username"),
  accessClientPreparePanel: document.querySelector("#accessclient-prepare-panel"),
  accessClientPrepareDot: document.querySelector("#accessclient-prepare-dot"),
  accessClientPrepareLabel: document.querySelector("#accessclient-prepare-label"),
  accessClientPrepareDetail: document.querySelector("#accessclient-prepare-detail"),
  prepareAccessClientButton: document.querySelector("#prepare-accessclient-button"),
  cancelAccessClientPrepareButton: document.querySelector("#cancel-accessclient-prepare-button"),
  policyInputs: [...document.querySelectorAll('input[name="policy-mode"]')],
  policySummary: document.querySelector("#policy-summary"),
  allowListFields: document.querySelector("#allow-list-fields"),
  allowedCommands: document.querySelector("#allowed-commands"),
  fullAccessWarning: document.querySelector("#full-access-warning"),
  fullAccessConfirm: document.querySelector("#full-access-confirm"),
  denyNote: document.querySelector("#deny-note"),
  permissionLimits: document.querySelector("#permission-limits"),
  maxTimeoutMs: document.querySelector("#max-timeout-ms"),
  transferInputs: [...document.querySelectorAll('input[name="transfer-mode"]')],
  restrictedTransferSummary: document.querySelector("#restricted-transfer-summary"),
  transferFields: document.querySelector("#transfer-fields"),
  transferDenyNote: document.querySelector("#transfer-deny-note"),
  localRootPath: document.querySelector("#local-root-path"),
  remoteRoots: document.querySelector("#remote-roots"),
  transferTimeoutField: document.querySelector("#transfer-timeout-field"),
  maxTransferTimeoutMs: document.querySelector("#max-transfer-timeout-ms"),
  transferAccessConfirm: document.querySelector("#transfer-access-confirm"),
  accessClientTransferNote: document.querySelector("#accessclient-transfer-note"),
  fullAccessHeading: document.querySelector("#full-access-heading"),
  fullAccessDescription: document.querySelector("#full-access-description"),
  fullAccessConfirmText: document.querySelector("#full-access-confirm-text"),
  formError: document.querySelector("#form-error"),
  formStatus: document.querySelector("#form-status"),
  deleteButton: document.querySelector("#delete-button"),
  checkButton: document.querySelector("#check-button"),
  saveButton: document.querySelector("#save-button"),
  keyCount: document.querySelector("#key-count"),
  keyList: document.querySelector("#key-list"),
  keyEmpty: document.querySelector("#key-empty"),
  keyError: document.querySelector("#key-error"),
  keyStatus: document.querySelector("#key-status"),
  importKeyButton: document.querySelector("#import-key-button"),
  generateKeyButton: document.querySelector("#generate-key-button"),
  keyEditorForm: document.querySelector("#key-editor-form"),
  keyEditorTitle: document.querySelector("#key-editor-title"),
  keyLabel: document.querySelector("#key-label"),
  keyAlgorithmField: document.querySelector("#key-algorithm-field"),
  keyAlgorithm: document.querySelector("#key-algorithm"),
  keySourceField: document.querySelector("#key-source-field"),
  keySourcePath: document.querySelector("#key-source-path"),
  keyEditorSubmitButton: document.querySelector("#key-editor-submit-button"),
  cancelKeyEditorButton: document.querySelector("#cancel-key-editor-button"),
  keyPublicPanel: document.querySelector("#key-public-panel"),
  keyPublicHeading: document.querySelector("#key-public-heading"),
  keyPublicMeta: document.querySelector("#key-public-meta"),
  publicKeyOutput: document.querySelector("#public-key-output"),
  copyPublicKeyButton: document.querySelector("#copy-public-key-button"),
  accessClientSettingsForm: document.querySelector("#accessclient-settings-form"),
  plinkExecutable: document.querySelector("#plink-executable"),
  saveAccessClientSettingsButton: document.querySelector("#save-accessclient-settings-button"),
  accessClientSettingsBadge: document.querySelector("#accessclient-settings-badge"),
  accessClientSettingsDot: document.querySelector("#accessclient-settings-dot"),
  accessClientSettingsLabel: document.querySelector("#accessclient-settings-label"),
  accessClientSettingsDetail: document.querySelector("#accessclient-settings-detail"),
  accessClientSettingsError: document.querySelector("#accessclient-settings-error"),
  accessClientSettingsStatus: document.querySelector("#accessclient-settings-status"),
  tailscaleSettingsForm: document.querySelector("#tailscale-settings-form"),
  tailscaleExecutable: document.querySelector("#tailscale-executable"),
  saveTailscaleSettingsButton: document.querySelector("#save-tailscale-settings-button"),
  tailscaleSettingsBadge: document.querySelector("#tailscale-settings-badge"),
  tailscaleSettingsDot: document.querySelector("#tailscale-settings-dot"),
  tailscaleSettingsLabel: document.querySelector("#tailscale-settings-label"),
  tailscaleSettingsDetail: document.querySelector("#tailscale-settings-detail"),
  tailscaleSettingsError: document.querySelector("#tailscale-settings-error"),
  tailscaleSettingsStatus: document.querySelector("#tailscale-settings-status"),
  commandTargetName: document.querySelector("#command-target-name"),
  commandPolicyBadge: document.querySelector("#command-policy-badge"),
  operationTabs: [...document.querySelectorAll(".operation-tab")],
  execOperationPanel: document.querySelector("#exec-operation-panel"),
  transferOperationPanel: document.querySelector("#transfer-operation-panel"),
  inspectOperationPanel: document.querySelector("#inspect-operation-panel"),
  commandForm: document.querySelector("#command-form"),
  executionFormatInputs: [...document.querySelectorAll('input[name="execution-format"]')],
  singleCommandFields: document.querySelector("#single-command-fields"),
  structuredCommandFields: document.querySelector("#structured-command-fields"),
  remoteShellInputs: [...document.querySelectorAll('input[name="remote-shell"]')],
  commandInput: document.querySelector("#command-input"),
  scriptInput: document.querySelector("#script-input"),
  workingDirectory: document.querySelector("#working-directory"),
  environmentInput: document.querySelector("#environment-input"),
  backgroundTask: document.querySelector("#background-task"),
  commandNote: document.querySelector("#command-note"),
  runTimeoutMs: document.querySelector("#run-timeout-ms"),
  runButton: document.querySelector("#run-button"),
  cancelButton: document.querySelector("#cancel-button"),
  transferForm: document.querySelector("#transfer-form"),
  transferKindInputs: [...document.querySelectorAll('input[name="transfer-kind"]')],
  transferLocalRootField: document.querySelector("#transfer-local-root-field"),
  transferLocalRoot: document.querySelector("#transfer-local-root"),
  transferLocalPathLabel: document.querySelector("#transfer-local-path-label"),
  transferLocalPath: document.querySelector("#transfer-local-path"),
  transferRemotePath: document.querySelector("#transfer-remote-path"),
  transferChecksumField: document.querySelector("#transfer-checksum-field"),
  transferChecksum: document.querySelector("#transfer-checksum"),
  syncOptions: document.querySelector("#sync-options"),
  transferExcludes: document.querySelector("#transfer-excludes"),
  verifyExisting: document.querySelector("#verify-existing"),
  transferOverwrite: document.querySelector("#transfer-overwrite"),
  transferResume: document.querySelector("#transfer-resume"),
  transferDryRun: document.querySelector("#transfer-dry-run"),
  transferTimeoutMs: document.querySelector("#transfer-timeout-ms"),
  transferRunButton: document.querySelector("#transfer-run-button"),
  transferCancelButton: document.querySelector("#transfer-cancel-button"),
  inspectTargetButton: document.querySelector("#inspect-target-button"),
  targetInfoStatus: document.querySelector("#target-info-status"),
  targetInfoGrid: document.querySelector("#target-info-grid"),
  dockerPreflightButton: document.querySelector("#docker-preflight-button"),
  dockerIntentInputs: [...document.querySelectorAll('input[name="docker-intent"]')],
  dockerProjectDirectory: document.querySelector("#docker-project-directory"),
  dockerComposeFiles: document.querySelector("#docker-compose-files"),
  dockerProjectName: document.querySelector("#docker-project-name"),
  dockerRequiredFreeMb: document.querySelector("#docker-required-free-mb"),
  dockerPorts: document.querySelector("#docker-ports"),
  dockerPreflightStatus: document.querySelector("#docker-preflight-status"),
  dockerPreflightGrid: document.querySelector("#docker-preflight-grid"),
  commandError: document.querySelector("#command-error"),
  resultSummary: document.querySelector("#result-summary"),
  resultSummaryText: document.querySelector("#result-summary-text"),
  stdoutTab: document.querySelector("#stdout-tab"),
  stderrTab: document.querySelector("#stderr-tab"),
  stdoutCount: document.querySelector("#stdout-count"),
  stderrCount: document.querySelector("#stderr-count"),
  outputView: document.querySelector("#output-view"),
  wrapButton: document.querySelector("#wrap-button"),
  copyOutputButton: document.querySelector("#copy-output-button"),
  retentionNote: document.querySelector("#retention-note"),
  fullOutputButton: document.querySelector("#full-output-button"),
  pagination: document.querySelector("#pagination"),
  previousPage: document.querySelector("#previous-page"),
  nextPage: document.querySelector("#next-page"),
  pageLabel: document.querySelector("#page-label"),
  toastRegion: document.querySelector("#toast-region"),
};

const state = {
  fleetStatus: null,
  commandPresets: { ...FALLBACK_COMMAND_PRESETS },
  targets: new Map(),
  keys: new Map(),
  keyRevision: null,
  tailscaleSettings: { executable: "" },
  tailscaleSettingsBaseline: "",
  tailscaleSettingsDirty: false,
  tailscaleMutationBusy: false,
  accessClientSettings: { plinkExecutable: "" },
  accessClientSettingsBaseline: "",
  accessClientSettingsDirty: false,
  accessClientMutationBusy: false,
  accessClientPreparation: { state: "idle" },
  accessClientPreparationBusy: false,
  accessClientPreparationTimer: null,
  gatewayTargets: new Map(),
  probes: new Map(),
  selectedAlias: null,
  originalAlias: null,
  operationTargetAlias: null,
  activeView: "config",
  activeOperation: "exec",
  baseline: "",
  dirty: false,
  hydrating: false,
  refreshing: false,
  inventoryLoaded: false,
  inventoryAvailable: false,
  keysLoaded: false,
  keysAvailable: false,
  keyLoadError: null,
  mutationBusy: false,
  keyMutationBusy: false,
  keyEditorMode: null,
  editingKeyId: null,
  publicKeyId: null,
  checking: false,
  running: false,
  cancelling: false,
  inspecting: false,
  task: null,
  activeStream: "stdout",
  wrapped: true,
  result: null,
  outputPages: createOutputPageState(),
};

class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

function createOutputPageState() {
  return {
    stdout: { mode: "inline", offsets: [0], index: 0, chunk: null, text: "", loading: false },
    stderr: { mode: "inline", offsets: [0], index: 0, chunk: null, text: "", loading: false },
  };
}

async function postApi(route, body) {
  const response = await fetch(`/api/${route}`, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(sessionToken ? { "X-Agent-SSH-UI-Token": sessionToken } : {}),
    },
    body: JSON.stringify(body),
  });
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new ApiError(response.status, "INVALID_RESPONSE", "管理服务返回了无法识别的响应。");
  }
  if (!response.ok) {
    const problem = payload && typeof payload === "object" ? payload.error : null;
    const error = new ApiError(
      response.status,
      typeof problem?.code === "string" ? problem.code : "REQUEST_FAILED",
      typeof problem?.message === "string" ? problem.message : "请求失败",
    );
    if (error.code === "INVALID_SESSION") {
      clearSessionToken();
    }
    throw error;
  }
  clearSessionToken(); // Subsequent requests use the server-issued HttpOnly cookie.
  return payload;
}

function setGatewayState(kind, label, detail) {
  elements.gatewayDot.className = `status-dot is-${kind}`;
  elements.gatewayLabel.textContent = label;
  elements.gatewayDetail.textContent = detail;
}

async function refreshApplication(options = {}) {
  if (
    state.refreshing ||
    state.mutationBusy ||
    state.keyMutationBusy ||
    state.tailscaleMutationBusy || state.accessClientMutationBusy ||
    state.running
  ) {
    return;
  }
  state.refreshing = true;
  if (!state.inventoryLoaded) {
    renderPendingInventory();
    renderPendingWorkspace();
  }
  updateControls();
  clearAlert(elements.inventoryError);
  clearAlert(elements.keyError);
  clearAlert(elements.tailscaleSettingsError);
  clearAlert(elements.accessClientSettingsError);
  state.keyLoadError = null;
  setGatewayState("checking", "正在读取配置", "本机管理服务");
  const preferredAlias = options.preferredAlias ?? state.selectedAlias;
  const preferredView = state.activeView;
  let bootstrapLoaded = false;
  try {
    const [bootstrapResult, pingResult, targetsResult] = await Promise.allSettled([
      postApi("admin/bootstrap", {}),
      postApi("ping", {}),
      postApi("targets", {}),
    ]);
    if (bootstrapResult.status === "rejected") {
      throw bootstrapResult.reason;
    }
    bootstrapLoaded = true;
    const inventoryApplied = applyFleetStatus(bootstrapResult.value);
    if (!inventoryApplied) {
      const status = state.fleetStatus;
      throw new ApiError(
        503,
        typeof status?.error?.code === "string" ? status.error.code : "CONFIG_LOAD_FAILED",
        typeof status?.error?.message === "string" ? status.error.message : "机器配置加载失败",
      );
    }
    if (targetsResult.status === "fulfilled") {
      applyGatewayTargets(targetsResult.value);
    } else {
      state.gatewayTargets.clear();
    }
    renderInventory();

    if (preferredAlias && state.targets.has(preferredAlias)) {
      selectMachine(preferredAlias, { force: true, view: preferredView });
    } else if (state.targets.size > 0) {
      selectMachine(sortedTargets()[0][0], { force: true, view: preferredView });
    } else {
      startNewMachine({ force: true, view: preferredView });
    }

    renderGatewayState(pingResult);
  } catch (error) {
    const retainedInventory = state.inventoryLoaded;
    state.inventoryAvailable = false;
    state.gatewayTargets.clear();
    if (retainedInventory) {
      renderInventory();
      if (bootstrapLoaded && state.targets.size > 0) {
        const selectedAlias = preferredAlias && state.targets.has(preferredAlias)
          ? preferredAlias
          : sortedTargets()[0][0];
        selectMachine(selectedAlias, { force: true, view: preferredView });
      }
    } else {
      renderUnavailableInventory();
      renderUnavailableWorkspace();
    }
    const invalidSession = error instanceof ApiError && error.code === "INVALID_SESSION";
    if (invalidSession && !retainedInventory) {
      elements.workspaceTitle.textContent = "首次使用，请授权此浏览器";
      elements.workspaceSubtitle.textContent = "通过本机管理入口打开一次后，即可直接访问固定地址；授权保留 30 天并随使用续期。";
      elements.selectedStateBadge.textContent = "待授权";
      elements.revisionLabel.textContent = "授权后读取";
    }
    setGatewayState(
      "offline",
       invalidSession ? "需要授权此浏览器" : "机器配置加载失败",
      retainedInventory ? `${state.targets.size} 台机器保留上次加载结果` : "未能读取机器配置",
    );
    showAlert(elements.inventoryError, messageForError(error), "error");
    if (!bootstrapLoaded) {
      state.keysAvailable = false;
      renderKeyManagement();
      showAlert(elements.keyError, messageForError(error), "error");
    }
  } finally {
    state.refreshing = false;
    updateControls();
  }
}

function applyFleetStatus(rawStatus, options = {}) {
  const status = rawStatus?.status && typeof rawStatus.status === "object" ? rawStatus.status : rawStatus;
  state.fleetStatus = status && typeof status === "object" ? status : null;
  if (status?.accessClientSession && typeof status.accessClientSession === "object") {
    applyAccessClientPreparationSnapshot(status.accessClientSession);
  }
  applyAccessClientSettingsSnapshot(status, options.preserveAccessClientDraft === true);
  applyTailscaleSettingsSnapshot(status, options.preserveAccessClientDraft === true);
  if (!applyKeySnapshot(status)) {
    showAlert(
      elements.keyError,
      state.keyLoadError
        ? messageForError(new ApiError(503, state.keyLoadError.code, state.keyLoadError.message))
        : state.keysLoaded ? "未能刷新私钥，已保留上次加载结果。" : "未能读取全局私钥。",
      "error",
    );
  }
  const rawTargets = status?.profile?.targets;
  const hasInventorySnapshot = rawTargets && typeof rawTargets === "object" && !Array.isArray(rawTargets);
  if (status?.state === "error" && !hasInventorySnapshot) {
    state.inventoryAvailable = false;
    return false;
  }
  state.targets.clear();
  if (hasInventorySnapshot) {
    for (const [alias, target] of Object.entries(rawTargets)) {
      const normalised = normaliseFleetTarget(target);
      if (ALIAS_PATTERN.test(alias) && normalised) {
        state.targets.set(alias, normalised);
      }
    }
  }
  state.inventoryLoaded = true;
  state.inventoryAvailable = status?.state !== "error";
  const presets = status?.commandPresets;
  for (const platform of Object.keys(PLATFORM_LABELS)) {
    if (Array.isArray(presets?.[platform]) && presets[platform].every((item) => typeof item === "string")) {
      state.commandPresets[platform] = [...presets[platform]];
    }
  }
  elements.revisionLabel.textContent = typeof status?.revision === "string" ? status.revision : "未配置";
  elements.revisionLabel.title = elements.revisionLabel.textContent;
  if (typeof status?.defaultKnownHostsFile === "string") {
    elements.knownHostsNote.textContent = `默认路径：${status.defaultKnownHostsFile}。网关会严格校验主机指纹。`;
  }
  return state.inventoryAvailable;
}

function applyAccessClientSettingsSnapshot(rawStatus, preserveDraft = false) {
  const status = rawStatus?.status && typeof rawStatus.status === "object" ? rawStatus.status : rawStatus;
  const draft = elements.plinkExecutable.value;
  const wasDirty = state.accessClientSettingsDirty;
  const plinkExecutable = typeof status?.profile?.accessClient?.plinkExecutable === "string"
    ? status.profile.accessClient.plinkExecutable
    : "";
  state.accessClientSettings = { plinkExecutable };
  state.accessClientSettingsBaseline = plinkExecutable;
  elements.plinkExecutable.value = preserveDraft && wasDirty ? draft : plinkExecutable;
  state.accessClientSettingsDirty = elements.plinkExecutable.value.trim() !== plinkExecutable;
  renderAccessClientSettings();
}

function applyTailscaleSettingsSnapshot(rawStatus, preserveDraft = false) {
  const status = rawStatus?.status && typeof rawStatus.status === "object" ? rawStatus.status : rawStatus;
  const draft = elements.tailscaleExecutable.value;
  const wasDirty = state.tailscaleSettingsDirty;
  const executable = typeof status?.profile?.tailscale?.executable === "string"
    ? status.profile.tailscale.executable
    : "";
  state.tailscaleSettings = { executable };
  state.tailscaleSettingsBaseline = executable;
  elements.tailscaleExecutable.value = preserveDraft && wasDirty ? draft : executable;
  state.tailscaleSettingsDirty = elements.tailscaleExecutable.value.trim() !== executable;
  renderTailscaleSettings();
}

function normaliseFleetTarget(value) {
  if (!value || typeof value !== "object") {
    return null;
  }
  const connectionMode = Object.hasOwn(CONNECTION_MODE_LABELS, value.connectionMode) ? value.connectionMode : "openssh";
  const targetEndpoint = normaliseEndpoint(value.target);
  if (!targetEndpoint) return null;
  const bastionEndpoint = connectionMode === "openssh" ? normaliseEndpoint(value.bastion) : null;
  const accessClient = connectionMode === "accessclient-share"
    ? normaliseAccessClientConnection(value.accessClient, targetEndpoint)
    : null;
  if (connectionMode === "accessclient-share" && !accessClient) return null;
  const platform = Object.hasOwn(PLATFORM_LABELS, value.platform) ? value.platform : "linux";
  const policyMode = Object.hasOwn(POLICY_LABELS, value.policyMode) ? value.policyMode : "deny";
  const configuredTransferMode = Object.hasOwn(TRANSFER_LABELS, value.transferMode) ? value.transferMode : "deny";
  return {
    ...(typeof value.description === "string" ? { description: value.description } : {}),
    enabled: value.enabled === true,
    connectionMode,
    target: targetEndpoint,
    ...(connectionMode === "openssh"
      ? { knownHostsFile: typeof value.knownHostsFile === "string" ? value.knownHostsFile : "" }
      : connectionMode === "accessclient-share" ? { accessClient } : {}),
    ...(bastionEndpoint ? { bastion: bastionEndpoint } : {}),
    platform,
    policyMode,
    allowedCommands: Array.isArray(value.allowedCommands)
      ? value.allowedCommands.filter((command) => typeof command === "string")
      : [],
    maxTimeoutMs: validInteger(value.maxTimeoutMs, 1, MAX_TIMEOUT_MS) ? value.maxTimeoutMs : 30_000,
    transferMode: connectionMode === "tailscale-ssh" ? "deny" : policyMode === "full-access"
        ? "bidirectional"
      : policyMode === "deny"
        ? "deny"
        : configuredTransferMode,
    ...(typeof value.localRootPath === "string" ? { localRootPath: value.localRootPath } : {}),
    remoteRoots: Array.isArray(value.remoteRoots)
      ? value.remoteRoots.filter((root) => typeof root === "string")
      : [],
    maxTransferTimeoutMs: policyMode === "allow-list"
      && validInteger(value.maxTransferTimeoutMs, 1, MAX_TIMEOUT_MS)
      ? value.maxTransferTimeoutMs
      : MAX_TIMEOUT_MS,
  };
}

function normaliseAccessClientConnection(value, targetEndpoint) {
  if (
    !value ||
    typeof value !== "object" ||
    typeof value.gatewayHost !== "string" ||
    !validInteger(value.gatewayPort, 1, 65_535) ||
    typeof value.gatewayUsername !== "string"
  ) {
    return null;
  }
  return {
    gatewayHost: value.gatewayHost,
    gatewayPort: value.gatewayPort,
    gatewayUsername: value.gatewayUsername,
    sharingHost: typeof value.sharingHost === "string"
      ? value.sharingHost
      : targetEndpoint.host,
    sharingPort: validInteger(value.sharingPort, 1, 65_535)
      ? value.sharingPort
      : typeof value.sharingHost === "string"
        ? 22
        : targetEndpoint.port,
    ...(typeof value.expectedHostname === "string"
      ? { expectedHostname: value.expectedHostname }
      : {}),
  };
}

function normaliseEndpoint(value) {
  if (!value || typeof value !== "object") {
    return null;
  }
  if (
    typeof value.host !== "string" ||
    typeof value.username !== "string" ||
    !validInteger(value.port, 1, 65_535)
  ) {
    return null;
  }
  const keyId = typeof value.keyId === "string" && KEY_ID_PATTERN.test(value.keyId) ? value.keyId : "";
  return { host: value.host, port: value.port, username: value.username, keyId, keyUnavailable: keyId === "" };
}

function applyKeySnapshot(rawStatus) {
  const status = rawStatus?.status && typeof rawStatus.status === "object" ? rawStatus.status : rawStatus;
  const storageError = keyStorageError(status);
  if (storageError) return rejectKeySnapshot(storageError);
  if (!Array.isArray(status?.keys) || typeof status.keyRevision !== "string" || status.keyRevision.length === 0) {
    return rejectKeySnapshot(null);
  }
  const nextKeys = new Map();
  for (const value of status.keys) {
    const key = normaliseKey(value);
    if (!key || nextKeys.has(key.keyId)) {
      return rejectKeySnapshot(null);
    }
    nextKeys.set(key.keyId, key);
  }
  state.keys.clear();
  for (const [keyId, key] of nextKeys) state.keys.set(keyId, key);
  state.keyRevision = status.keyRevision;
  state.keysLoaded = true;
  state.keysAvailable = true;
  state.keyLoadError = null;
  if (state.publicKeyId && !state.keys.has(state.publicKeyId)) state.publicKeyId = null;
  clearAlert(elements.keyError);
  renderKeyManagement();
  renderKeyOptions();
  return true;
}

function keyStorageError(status) {
  for (const candidate of [status?.keyStatus?.error, status?.keyError]) {
    const error = normaliseKeyStorageError(candidate);
    if (error) return error;
  }
  const legacyError = normaliseKeyStorageError(status?.error);
  return legacyError?.code.startsWith("KEY_STORAGE_") ? legacyError : null;
}

function normaliseKeyStorageError(value) {
  if (!value || typeof value !== "object" || typeof value.code !== "string") return null;
  return {
    code: value.code,
    message: typeof value.message === "string" ? value.message : "SSH key storage is unavailable",
  };
}

function rejectKeySnapshot(error) {
  state.keysAvailable = false;
  state.keyLoadError = error;
  renderKeyManagement();
  renderKeyOptions();
  return false;
}

function keySnapshotApiError() {
  return state.keyLoadError
    ? new ApiError(503, state.keyLoadError.code, state.keyLoadError.message)
    : new ApiError(500, "INVALID_RESPONSE", "管理服务没有返回私钥列表。");
}

function normaliseKey(value) {
  if (
    !value ||
    typeof value !== "object" ||
    typeof value.keyId !== "string" ||
    !KEY_ID_PATTERN.test(value.keyId) ||
    typeof value.label !== "string" ||
    value.label.trim().length === 0 ||
    value.label.trim().length > 128
  ) return null;
  const inUseBy = Array.isArray(value.inUseBy)
    ? value.inUseBy.flatMap((reference) => {
        if (
          !reference ||
          typeof reference !== "object" ||
          typeof reference.alias !== "string" ||
          !["target", "bastion"].includes(reference.role)
        ) return [];
        return [{ alias: reference.alias, role: reference.role }];
      })
    : [];
  return {
    keyId: value.keyId,
    label: value.label.trim(),
    algorithm: typeof value.algorithm === "string" ? value.algorithm : "SSH",
    fingerprint: typeof value.fingerprint === "string" ? value.fingerprint : "",
    publicKey: typeof value.publicKey === "string" ? value.publicKey : "",
    createdAt: typeof value.createdAt === "string" ? value.createdAt : "",
    origin: typeof value.origin === "string" ? value.origin : "",
    inUseBy,
  };
}

function applyGatewayTargets(value) {
  state.gatewayTargets.clear();
  const list = Array.isArray(value?.targets) ? value.targets : [];
  for (const target of list) {
    if (typeof target?.alias === "string") {
      state.gatewayTargets.set(target.alias, target);
    }
  }
}

function renderGatewayState(pingResult) {
  const status = state.fleetStatus;
  if (status?.state === "error") {
    setGatewayState("offline", "配置加载失败", status.error?.code ?? "需要检查配置");
    return;
  }
  if (status?.state === "starting") {
    setGatewayState("checking", "网关启动中", `${state.targets.size} 台机器`);
    return;
  }
  if (status?.state === "unconfigured" || state.targets.size === 0) {
    setGatewayState("idle", "等待配置", "尚未添加机器");
    return;
  }
  if (pingResult.status === "fulfilled") {
    setGatewayState("online", "网关已连接", `${state.targets.size} 台机器`);
  } else {
    setGatewayState("offline", "网关未连接", "管理服务仍可配置");
  }
}

function sortedTargets() {
  return [...state.targets.entries()].sort(([left], [right]) => left.localeCompare(right, "zh-CN", { sensitivity: "base" }));
}

function sortedKeys() {
  return [...state.keys.entries()].sort(([, left], [, right]) =>
    left.label.localeCompare(right.label, "zh-CN", { sensitivity: "base" }));
}

function renderKeyOptions(targetSelection = elements.targetKeyId.value) {
  fillKeySelect(elements.targetKeyId, targetSelection);
  renderKeyNotes();
  renderSshInstallGuide();
}

function fillKeySelect(select, selectedKeyId) {
  select.replaceChildren();
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = state.keysLoaded
    ? state.keys.size === 0 ? "没有可用私钥" : "请选择私钥"
    : "私钥列表未加载";
  select.append(placeholder);

  if (selectedKeyId && !state.keys.has(selectedKeyId)) {
    const unavailable = document.createElement("option");
    unavailable.value = selectedKeyId;
    unavailable.textContent = "当前私钥不可用";
    unavailable.disabled = true;
    select.append(unavailable);
  }
  for (const [keyId, key] of sortedKeys()) {
    const option = document.createElement("option");
    option.value = keyId;
    option.textContent = `${key.label} · ${key.algorithm}`;
    option.title = key.fingerprint ? `${key.label} · ${key.fingerprint}` : key.label;
    select.append(option);
  }
  select.value = selectedKeyId && (state.keys.has(selectedKeyId) || selectedKeyId !== "") ? selectedKeyId : "";
}

function renderKeyNotes() {
  renderKeyNote(elements.targetKeyNote, elements.targetKeyId.value, "从全局私钥中选择。");
}

function renderKeyNote(element, keyId, fallback) {
  const key = state.keys.get(keyId);
  if (key) {
    element.textContent = [key.algorithm, key.fingerprint].filter(Boolean).join(" · ");
  } else if (keyId) {
    element.textContent = "当前私钥不可用，请重新选择。";
  } else if (state.keysLoaded && state.keys.size === 0) {
    element.textContent = "请先在全局设置中添加私钥。";
  } else {
    element.textContent = fallback;
  }
}

function normaliseSshPublicKey(value) {
  if (typeof value !== "string") return "";
  const fields = value.trim().split(/\s+/u);
  if (fields.length < 2) return "";
  const publicKey = `${fields[0]} ${fields[1]}`;
  return SSH_PUBLIC_KEY_PATTERN.test(publicKey) ? publicKey : "";
}

function buildSshInstallCommand(platform, publicKey) {
  if (platform === "windows") {
    return `$k='${publicKey}';$utf8=[Text.UTF8Encoding]::new($false);$id=[Security.Principal.WindowsIdentity]::GetCurrent();$p=[Security.Principal.WindowsPrincipal]::new($id);if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){$d=Join-Path $env:ProgramData 'ssh';$f=Join-Path $d 'administrators_authorized_keys'}else{$d=Join-Path $env:USERPROFILE '.ssh';$f=Join-Path $d 'authorized_keys'};[IO.Directory]::CreateDirectory($d)|Out-Null;if(!(Test-Path -LiteralPath $f)){[IO.File]::WriteAllText($f,'',$utf8)};$parts=$k -split ' ';$exists=[IO.File]::ReadAllLines($f)|Where-Object{$line=$_ -split '\\s+';for($i=0;$i-lt $line.Count-1;$i++){if($line[$i] -ceq $parts[0] -and $line[$i+1] -ceq $parts[1]){return $true}}return $false}|Select-Object -First 1;if(!$exists){[IO.File]::AppendAllText($f,[Environment]::NewLine+$k+[Environment]::NewLine,$utf8)};if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){& icacls.exe $d /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F'|Out-Null;& icacls.exe $f /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F'|Out-Null}else{$sid=$id.User.Value;& icacls.exe $d /inheritance:r /grant:r "*$($sid):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F'|Out-Null;& icacls.exe $f /inheritance:r /grant:r "*$($sid):F" '*S-1-5-18:F'|Out-Null}`;
  }
  return `umask 077; k='${publicKey}'; d="$HOME/.ssh"; f="$d/authorized_keys"; mkdir -p "$d" && chmod 700 "$d" && touch "$f" && chmod 600 "$f" && { awk -v k="$k" 'BEGIN { split(k,p," ") } { for (i=1; i<NF; i++) if ($i==p[1] && $(i+1)==p[2]) found=1 } END { exit found ? 0 : 1 }' "$f" || printf '\\n%s\\n' "$k" >> "$f"; }`;
}

function renderSshInstallGuide() {
  const openSsh = selectedRadio(elements.connectionModeInputs) === "openssh";
  const key = state.keys.get(elements.targetKeyId.value);
  const publicKey = normaliseSshPublicKey(key?.publicKey);
  const visible = openSsh && publicKey.length > 0;
  elements.sshInstallGuide.hidden = !visible;
  elements.sshInstallCommand.textContent = visible
    ? buildSshInstallCommand(selectedRadio(elements.platformInputs) ?? "linux", publicKey)
    : "";
  elements.launchSshInstallButton.disabled = !visible;
  elements.copySshInstallCommandButton.disabled = !visible;
}

function renderInventory() {
  elements.machineList.replaceChildren();
  const targets = sortedTargets();
  elements.machineCount.textContent = String(targets.length);
  elements.inventoryEmpty.hidden = targets.length > 0;
  elements.machineList.hidden = targets.length === 0;
  const query = elements.machineSearch.value.trim().toLocaleLowerCase();
  const matches = targets.filter(([alias, target]) =>
    [alias, target.description, target.target.host, target.target.username]
      .some((value) => String(value ?? "").toLocaleLowerCase().includes(query)),
  );
  elements.inventoryNoResults.hidden = targets.length === 0 || matches.length > 0;
  for (const [alias, target] of matches) {
    elements.machineList.append(createMachineItem(alias, target));
  }
}

function renderUnavailableInventory() {
  elements.inventoryNoResults.hidden = true;
  elements.machineCount.textContent = "--";
  elements.inventoryEmpty.hidden = true;
  elements.machineList.hidden = true;
  elements.revisionLabel.textContent = "读取失败";
  elements.revisionLabel.title = elements.revisionLabel.textContent;
}

function renderPendingInventory() {
  elements.inventoryNoResults.hidden = true;
  elements.machineCount.textContent = "--";
  elements.inventoryEmpty.hidden = true;
  elements.machineList.hidden = true;
  elements.revisionLabel.textContent = "正在加载";
  elements.revisionLabel.title = elements.revisionLabel.textContent;
}

function renderUnavailableWorkspace() {
  state.selectedAlias = null;
  state.originalAlias = null;
  elements.machineForm.hidden = true;
  setActiveView("config");
  elements.workspaceTitle.textContent = "机器配置未加载";
  elements.workspaceSubtitle.textContent = "恢复管理会话或服务后刷新重试。";
  elements.selectedStateBadge.textContent = "不可用";
  elements.selectedStateBadge.className = "state-badge is-disabled";
}

function renderPendingWorkspace() {
  state.selectedAlias = null;
  state.originalAlias = null;
  elements.machineForm.hidden = true;
  setActiveView("config");
  elements.workspaceTitle.textContent = "正在加载机器配置";
  elements.workspaceSubtitle.textContent = "正在读取本机管理服务。";
  elements.selectedStateBadge.textContent = "加载中";
  elements.selectedStateBadge.className = "state-badge is-draft";
}

function createMachineItem(alias, target) {
  const item = document.createElement("article");
  item.className = "machine-item";
  item.dataset.alias = alias;
  item.setAttribute("role", "listitem");
  if (state.selectedAlias === alias) item.classList.add("is-selected");

  const button = document.createElement("button");
  button.type = "button";
  button.className = "machine-item-select";
  button.setAttribute("aria-current", state.selectedAlias === alias ? "true" : "false");
  button.setAttribute("aria-label", `编辑机器 ${alias}`);

  const top = document.createElement("span");
  top.className = "machine-item-top";
  const name = document.createElement("strong");
  name.textContent = alias;
  const stateWrap = document.createElement("span");
  stateWrap.className = "machine-health";
  const dot = document.createElement("span");
  const health = machineHealth(alias, target);
  dot.className = `machine-health-dot is-${health.kind}`;
  dot.setAttribute("aria-hidden", "true");
  const healthText = document.createElement("span");
  healthText.textContent = health.label;
  stateWrap.append(dot, healthText);
  top.append(name, stateWrap);

  const descriptionText = target.description?.trim();
  const description = descriptionText
    ? document.createElement("span")
    : null;
  if (description) {
    description.className = "machine-description";
    description.textContent = descriptionText;
    description.title = descriptionText;
  }

  const endpoint = document.createElement("span");
  endpoint.className = "machine-endpoint";
  endpoint.textContent = target.connectionMode === "accessclient-share"
    ? `AccessClient · ${target.target.username}@${target.target.host}:${target.target.port}`
    : `${target.target.username}@${target.target.host}:${target.target.port}`;

  const meta = document.createElement("span");
  meta.className = "machine-meta";
  const platform = document.createElement("span");
  platform.textContent = `${PLATFORM_LABELS[target.platform]} · ${CONNECTION_MODE_LABELS[target.connectionMode]}`;
  const policy = document.createElement("span");
  policy.className = `mini-policy ${policyClass(target.policyMode)}`;
  policy.textContent = POLICY_LABELS[target.policyMode];
  meta.append(platform, policy);
  button.append(top);
  if (description) button.append(description);
  button.append(endpoint, meta);
  button.addEventListener("click", () => selectMachine(alias));

  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.className = "machine-mcp-toggle";
  toggle.dataset.alias = alias;
  toggle.dataset.enabled = String(target.enabled);
  toggle.setAttribute("role", "switch");
  toggle.setAttribute("aria-checked", String(target.enabled));
  toggle.setAttribute("aria-label", `${target.enabled ? "停用" : "启用"} ${alias} 的 MCP 访问`);
  toggle.title = target.enabled ? "停用 MCP 访问" : "启用 MCP 访问";
  const toggleLabel = document.createElement("span");
  toggleLabel.className = "machine-mcp-label";
  toggleLabel.textContent = "MCP";
  const toggleTrack = document.createElement("span");
  toggleTrack.className = "machine-mcp-track";
  toggleTrack.setAttribute("aria-hidden", "true");
  toggle.append(toggleLabel, toggleTrack);
  toggle.addEventListener("click", () => void setMachineEnabled(alias, !target.enabled));

  item.append(button, toggle);
  return item;
}

async function setMachineEnabled(alias, enabled) {
  if (
    state.mutationBusy ||
    state.keyMutationBusy ||
    state.tailscaleMutationBusy || state.accessClientMutationBusy ||
    state.checking ||
    state.inspecting ||
    state.running ||
    !state.inventoryAvailable ||
    !state.targets.has(alias) ||
    typeof state.fleetStatus?.revision !== "string"
  ) return;
  state.mutationBusy = true;
  updateControls();
  try {
    const result = await postApi("admin/target/enabled", {
      alias,
      enabled,
      expectedRevision: state.fleetStatus.revision,
    });
    applyFleetStatus(result, { preserveAccessClientDraft: true });
    state.probes.delete(alias);
    renderInventory();
    renderWorkspaceHeading();
    renderCommandTarget();
    renderDirtyState();
    showToast(`${alias} 已${enabled ? "启用" : "停用"} MCP 访问`);
    void refreshGatewayTargets();
  } catch (error) {
    showToast(messageForError(error), "error");
  } finally {
    state.mutationBusy = false;
    updateControls();
  }
}

function machineHealth(alias, target) {
  const probe = state.probes.get(alias);
  if (probe?.connected === true) {
    return { kind: "online", label: "可连接" };
  }
  if (probe?.connected === false) {
    return { kind: "offline", label: "检测失败" };
  }
  if (!target.enabled) {
    return { kind: "idle", label: "已停用" };
  }
  if (target.policyMode === "deny") {
    return { kind: "warning", label: "禁止访问" };
  }
  if (
    target.connectionMode === "openssh" &&
    state.keysLoaded &&
    (!state.keys.has(target.target.keyId) || (target.bastion && !state.keys.has(target.bastion.keyId)))
  ) {
    return { kind: "warning", label: "私钥不可用" };
  }
  if (target.connectionMode === "accessclient-share") {
    return { kind: "idle", label: "等待会话" };
  }
  return { kind: "ready", label: "已启用" };
}

function selectMachine(alias, options = {}) {
  if (!state.targets.has(alias)) {
    return;
  }
  if (!options.force && state.running) {
    showToast("当前任务结束或取消后才能切换机器。", "error");
    return;
  }
  if (!options.force && state.dirty && !confirmDiscardChanges()) {
    return;
  }
  state.selectedAlias = alias;
  state.originalAlias = alias;
  state.task = null;
  state.result = null;
  state.outputPages = createOutputPageState();
  elements.machineForm.hidden = false;
  clearInspectionResults();
  fillForm(alias, state.targets.get(alias));
  const nextView = options.view ?? (state.activeView === "command" ? "command" : "config");
  setActiveView(nextView);
  renderInventory();
  renderWorkspaceHeading();
  renderCommandTarget();
  renderOutput();
  updateControls();
}

function startNewMachine(options = {}) {
  if (!options.force && state.running) {
    showToast("当前任务结束或取消后才能新增机器。", "error");
    return;
  }
  if (!options.force && state.dirty && !confirmDiscardChanges()) {
    return;
  }
  state.selectedAlias = null;
  state.originalAlias = null;
  state.task = null;
  state.result = null;
  state.outputPages = createOutputPageState();
  elements.machineForm.hidden = false;
  clearInspectionResults();
  fillForm("", createDefaultTarget());
  setActiveView(options.view === "settings" ? "settings" : "config");
  renderInventory();
  renderWorkspaceHeading();
  renderCommandTarget();
  renderOutput();
  updateControls();
  if (state.activeView === "config") elements.targetAlias.focus();
}

function createDefaultTarget() {
  const platform = "linux";
  const defaultKeyId = sortedKeys()[0]?.[0] ?? "";
  return {
    enabled: true,
    connectionMode: "openssh",
    target: { host: "", port: 22, username: "", keyId: defaultKeyId },
    knownHostsFile: typeof state.fleetStatus?.defaultKnownHostsFile === "string"
      ? state.fleetStatus.defaultKnownHostsFile
      : "",
    platform,
    policyMode: "allow-list",
    allowedCommands: [...state.commandPresets[platform]],
    maxTimeoutMs: 30_000,
    transferMode: "deny",
    remoteRoots: [],
    maxTransferTimeoutMs: MAX_TIMEOUT_MS,
  };
}

function fillForm(alias, target) {
  state.hydrating = true;
  clearFormMessages();
  clearInvalidFields();
  elements.targetAlias.value = alias;
  elements.targetDescription.value = target.description ?? "";
  selectRadio(elements.platformInputs, target.platform);
  selectRadio(elements.connectionModeInputs, target.connectionMode ?? "openssh");
  elements.targetHost.value = target.target.host;
  elements.targetPort.value = String(target.target.port);
  elements.accessClientTargetPort.value = String(target.target.port);
  elements.targetUsername.value = target.target.username;
  elements.knownHostsFile.value = target.knownHostsFile ?? "";
  elements.accessClientGatewayUsername.value =
    target.accessClient?.gatewayUsername ?? DEFAULT_ACCESSCLIENT_USERNAME;
  renderKeyOptions(target.target.keyId);
  selectRadio(elements.policyInputs, target.policyMode);
  elements.allowedCommands.value = target.allowedCommands.join("\n");
  elements.fullAccessConfirm.checked = false;
  elements.maxTimeoutMs.value = String(target.maxTimeoutMs);
  selectRadio(
    elements.transferInputs,
    target.policyMode === "allow-list" ? target.transferMode ?? "deny" : "deny",
  );
  elements.localRootPath.value = target.localRootPath ?? "";
  elements.remoteRoots.value = (target.remoteRoots ?? []).join("\n");
  elements.maxTransferTimeoutMs.value = String(target.maxTransferTimeoutMs ?? MAX_TIMEOUT_MS);
  elements.transferAccessConfirm.checked = false;
  renderConnectionFields();
  renderKeyNotes();
  renderPermissionFields();
  state.hydrating = false;
  state.baseline = rawFormSnapshot();
  state.dirty = false;
  renderDirtyState();
}

function selectRadio(inputs, value) {
  for (const input of inputs) {
    input.checked = input.value === value;
  }
}

function rawFormSnapshot() {
  return JSON.stringify({
    alias: elements.targetAlias.value,
    description: elements.targetDescription.value,
    platform: selectedRadio(elements.platformInputs),
    connectionMode: selectedRadio(elements.connectionModeInputs),
    host: elements.targetHost.value,
    port: elements.targetPort.value,
    accessClientTargetPort: elements.accessClientTargetPort.value,
    username: elements.targetUsername.value,
    keyId: elements.targetKeyId.value,
    knownHostsFile: elements.knownHostsFile.value,
    accessClientGatewayUsername: elements.accessClientGatewayUsername.value,
    policyMode: selectedRadio(elements.policyInputs),
    allowedCommands: elements.allowedCommands.value,
    maxTimeoutMs: elements.maxTimeoutMs.value,
    transferMode: selectedRadio(elements.transferInputs),
    localRootPath: elements.localRootPath.value,
    remoteRoots: elements.remoteRoots.value,
    maxTransferTimeoutMs: elements.maxTransferTimeoutMs.value,
  });
}

function handleFormChange(event) {
  if (state.hydrating) {
    return;
  }
  if (event.target === elements.targetPort) {
    elements.accessClientTargetPort.value = elements.targetPort.value;
  }
  if (event.target === elements.accessClientTargetPort) {
    elements.targetPort.value = elements.accessClientTargetPort.value;
  }
  if (event.target.matches('input[name="platform"]')) {
    updatePresetForPlatform(event.target.value);
  }
  if (event.target.matches('input[name="connection-mode"]')) {
    elements.fullAccessConfirm.checked = false;
    elements.transferAccessConfirm.checked = false;
  }
  if (event.target.matches('input[name="policy-mode"]')) {
    elements.fullAccessConfirm.checked = false;
    elements.transferAccessConfirm.checked = false;
    renderPermissionFields();
  }
  if (event.target.matches('input[name="transfer-mode"]')) {
    elements.transferAccessConfirm.checked = false;
    renderPermissionFields();
  }
  if (event.target === elements.targetKeyId) renderKeyNotes();
  if (event.target.matches('input[name="connection-mode"]') && selectedRadio(elements.connectionModeInputs) === "tailscale-ssh" && selectedRadio(elements.platformInputs) === "windows") {
    selectRadio(elements.platformInputs, "linux");
    updatePresetForPlatform("linux");
  }
  renderConnectionFields();
  renderPermissionFields();
  state.dirty = rawFormSnapshot() !== state.baseline;
  clearFormMessages();
  renderDirtyState();
  updateControls();
}

function renderConnectionFields() {
  const accessClient = selectedRadio(elements.connectionModeInputs) === "accessclient-share";
  const tailscale = selectedRadio(elements.connectionModeInputs) === "tailscale-ssh";
  elements.tailscaleConnectionNote.hidden = !tailscale;
  elements.targetPortField.hidden = tailscale;
  elements.targetKeyField.hidden = tailscale;
  elements.knownHostsField.hidden = tailscale;
  elements.openSshConnectionFields.classList.toggle("tailscale-endpoint", tailscale);
  elements.targetHost.placeholder = tailscale ? "例如 build-server 或 100.101.102.103" : "IP 地址或域名";
  elements.targetUsername.placeholder = tailscale ? "远端系统账号，例如 ubuntu" : "user 或 portal/10.0.0.1/root";
  elements.openSshConnectionFields.hidden = accessClient;
  elements.accessClientConnectionFields.hidden = !accessClient;
  renderSshInstallGuide();
  renderAccessClientPreparation();
}

function updatePresetForPlatform(platform) {
  if (state.originalAlias !== null) {
    return;
  }
  const current = elements.allowedCommands.value.trim();
  const allPresets = Object.values(state.commandPresets).map((commands) => commands.join("\n"));
  if (current.length === 0 || allPresets.includes(current)) {
    elements.allowedCommands.value = state.commandPresets[platform].join("\n");
  }
}

function renderPermissionFields() {
  const policyMode = selectedRadio(elements.policyInputs) ?? "allow-list";
  const selectedTransferMode = selectedRadio(elements.transferInputs) ?? "deny";
  const accessClient = selectedRadio(elements.connectionModeInputs) === "accessclient-share";
  const tailscale = selectedRadio(elements.connectionModeInputs) === "tailscale-ssh";
  const transferMode = tailscale ? "deny" : policyMode === "full-access"
      ? "bidirectional"
    : policyMode === "deny"
      ? "deny"
      : selectedTransferMode;
  const restrictedTransferEnabled = !accessClient && !tailscale && policyMode === "allow-list" && transferMode !== "deny";
  elements.allowListFields.hidden = policyMode !== "allow-list";
  elements.fullAccessWarning.hidden = policyMode !== "full-access";
  elements.denyNote.hidden = policyMode !== "deny";
  elements.permissionLimits.hidden = policyMode === "deny";
  elements.transferFields.hidden = !restrictedTransferEnabled;
  elements.transferDenyNote.hidden = accessClient || tailscale || policyMode !== "allow-list" || restrictedTransferEnabled;
  elements.accessClientTransferNote.hidden = !accessClient || policyMode === "deny";
  elements.transferTimeoutField.hidden = !restrictedTransferEnabled;
  elements.restrictedTransferSummary.textContent = TRANSFER_LABELS[transferMode];
  elements.policySummary.className = `policy-chip ${policyClass(policyMode)}`;
  elements.policySummary.textContent = POLICY_LABELS[policyMode];
  elements.fullAccessHeading.textContent = "Full access 将开放完整命令与文件权限";
  elements.fullAccessDescription.textContent = accessClient
    ? "Codex 可以执行任意命令，并通过持久化 Plink 通道使用任意本机或远端绝对路径双向传输文件。每次保存都必须重新确认。"
    : "Codex 可以执行任意命令，并可使用任意本机或远端绝对路径双向传输文件，包括读取本机私钥、凭证等敏感文件，以及修改配置、停止服务或删除数据。每次保存都必须重新确认。";
  elements.fullAccessConfirmText.textContent = "我已核对目标机器，并确认授予 Codex 完整命令权限和全部本机、远端文件权限。";
  if (tailscale) {
    elements.fullAccessHeading.textContent = "Full access 将开放完整命令权限";
    elements.fullAccessDescription.textContent = "Agent 可在远端账号权限范围内执行任意命令，包括修改配置、停止服务或删除数据。Tailscale SSH 暂不提供文件传输。";
    elements.fullAccessConfirmText.textContent = "我已核对目标机器，并确认授予 Agent 完整远端命令权限。";
  }
}

function setActiveOperation(operation, moveFocus = false) {
  if (!new Set(["exec", "transfer", "inspect"]).has(operation)) {
    return;
  }
  const requestedTab = elements.operationTabs.find((tab) => tab.dataset.operation === operation);
  if (!requestedTab || requestedTab.disabled) return;
  state.activeOperation = operation;
  const panels = {
    exec: elements.execOperationPanel,
    transfer: elements.transferOperationPanel,
    inspect: elements.inspectOperationPanel,
  };
  for (const tab of elements.operationTabs) {
    const selected = tab.dataset.operation === operation;
    tab.classList.toggle("is-active", selected);
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
    if (selected && moveFocus) {
      tab.focus();
    }
  }
  for (const [name, panel] of Object.entries(panels)) {
    panel.hidden = name !== operation;
  }
  clearAlert(elements.commandError);
}

function handleOperationTabKeydown(event) {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
    return;
  }
  event.preventDefault();
  const operations = elements.operationTabs.filter((tab) => !tab.disabled).map((tab) => tab.dataset.operation);
  if (operations.length === 0) return;
  let index = operations.indexOf(state.activeOperation);
  if (event.key === "Home") index = 0;
  else if (event.key === "End") index = operations.length - 1;
  else if (event.key === "ArrowLeft") index = (index - 1 + operations.length) % operations.length;
  else index = (index + 1) % operations.length;
  setActiveOperation(operations[index], true);
}

function renderExecutionFormat() {
  const target = state.selectedAlias ? state.targets.get(state.selectedAlias) : null;
  const structuredInput = elements.executionFormatInputs.find((input) => input.value === "structured");
  const structuredAllowed = target?.policyMode === "full-access";
  structuredInput.disabled = !structuredAllowed || state.running;
  if (!structuredAllowed && selectedRadio(elements.executionFormatInputs) === "structured") {
    selectRadio(elements.executionFormatInputs, "single");
  }
  const structured = selectedRadio(elements.executionFormatInputs) === "structured";
  elements.singleCommandFields.hidden = structured;
  elements.structuredCommandFields.hidden = !structured;

  const compatibleShells = target?.platform === "windows"
    ? new Set(["powershell", "cmd"])
    : new Set(["bash"]);
  for (const input of elements.remoteShellInputs) {
    input.disabled = !compatibleShells.has(input.value) || state.running;
  }
  if (!compatibleShells.has(selectedRadio(elements.remoteShellInputs))) {
    selectRadio(elements.remoteShellInputs, target?.platform === "windows" ? "powershell" : "bash");
  }
}

function renderTransferOperation() {
  const alias = state.selectedAlias;
  const target = alias ? state.targets.get(alias) : null;
  const mode = target?.transferMode ?? "deny";
  const fullAccess = target?.policyMode === "full-access";
  const allowedKinds = new Set(
    mode === "bidirectional"
      ? ["upload", "download", "sync"]
      : mode === "upload"
        ? ["upload", "sync"]
        : mode === "download"
          ? ["download"]
          : [],
  );
  for (const input of elements.transferKindInputs) {
    input.disabled = !allowedKinds.has(input.value) || state.running;
  }
  if (!allowedKinds.has(selectedRadio(elements.transferKindInputs))) {
    selectRadio(elements.transferKindInputs, [...allowedKinds][0] ?? "upload");
  }
  const kind = selectedRadio(elements.transferKindInputs) ?? "upload";
  elements.syncOptions.hidden = kind !== "sync";
  elements.transferChecksumField.hidden = kind === "sync";
  elements.transferOverwrite.disabled = kind === "sync" || state.running;

  const targetChanged = state.operationTargetAlias !== alias;
  const previousRoot = elements.transferLocalRoot.value;
  elements.transferLocalRoot.replaceChildren();
  elements.transferLocalRootField.hidden = fullAccess;
  elements.transferLocalPathLabel.textContent = fullAccess ? "本机绝对路径" : "本机相对路径";
  elements.transferLocalPath.placeholder = fullAccess
    ? "例如 E:\\projects\\release.zip"
    : "相对于授权目录";
  if (fullAccess) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "Full access";
    elements.transferLocalRoot.append(option);
  } else if (alias && target?.localRootPath && mode !== "deny") {
    const option = document.createElement("option");
    option.value = alias;
    option.textContent = `${alias} (${target.localRootPath})`;
    elements.transferLocalRoot.append(option);
    elements.transferLocalRoot.value = previousRoot === alias ? previousRoot : alias;
  } else {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "未授权本机目录";
    elements.transferLocalRoot.append(option);
  }
  if (targetChanged) {
    elements.transferLocalPath.value = "";
    elements.transferRemotePath.value = fullAccess ? "" : target?.remoteRoots?.[0] ?? "";
    state.operationTargetAlias = alias;
  }
  elements.transferTimeoutMs.max = String(target?.maxTransferTimeoutMs ?? MAX_TIMEOUT_MS);
  if (Number(elements.transferTimeoutMs.value) > Number(elements.transferTimeoutMs.max)) {
    elements.transferTimeoutMs.value = elements.transferTimeoutMs.max;
  }
  if (!fullAccess && !elements.transferRemotePath.value && target?.remoteRoots?.[0]) {
    elements.transferRemotePath.value = target.remoteRoots[0];
  }
}

function clearInspectionResults() {
  for (const status of [elements.targetInfoStatus, elements.dockerPreflightStatus]) {
    clearAlert(status);
  }
  for (const grid of [elements.targetInfoGrid, elements.dockerPreflightGrid]) {
    grid.replaceChildren();
    grid.hidden = true;
  }
}

function renderDirtyState() {
  if (state.dirty) {
    elements.savedIndicator.textContent = state.activeView === "settings" ? "机器配置有未保存修改" : "有未保存修改";
    elements.savedIndicator.className = "saved-indicator is-dirty";
  } else if (state.accessClientSettingsDirty || state.tailscaleSettingsDirty) {
    elements.savedIndicator.textContent = "全局设置有未保存修改";
    elements.savedIndicator.className = "saved-indicator is-dirty";
  } else if (state.activeView === "settings") {
    elements.savedIndicator.textContent = "";
    elements.savedIndicator.className = "saved-indicator";
  } else if (state.originalAlias) {
    elements.savedIndicator.textContent = "配置已保存";
    elements.savedIndicator.className = "saved-indicator is-saved";
  } else {
    elements.savedIndicator.textContent = "";
    elements.savedIndicator.className = "saved-indicator";
  }
}

function renderWorkspaceHeading() {
  elements.breadcrumbCurrent.textContent = state.activeView === "settings" ? "全局设置" : "机器管理";
  if (state.activeView === "settings") {
    elements.workspaceTitle.textContent = "全局设置";
    const accessClientConfigured = state.accessClientSettings.plinkExecutable.length > 0;
    const tailscaleSummary = ` · Tailscale ${state.tailscaleSettings.executable ? "已配置" : "未配置"}`;
    elements.workspaceSubtitle.textContent = state.keysLoaded
      ? `${state.keys.size} 把 SSH 私钥 · AccessClient ${accessClientConfigured ? "已配置" : "未配置"}${tailscaleSummary}`
      : `正在读取全局私钥 · AccessClient ${accessClientConfigured ? "已配置" : "未配置"}${tailscaleSummary}`;
    elements.selectedStateBadge.textContent = state.keysAvailable ? "可管理" : state.keysLoaded ? "只读" : "加载中";
    elements.selectedStateBadge.className = `state-badge ${state.keysAvailable ? "is-enabled" : "is-draft"}`;
    return;
  }
  const alias = state.selectedAlias;
  const target = alias ? state.targets.get(alias) : null;
  if (!target) {
    elements.workspaceTitle.textContent = "新增机器";
    elements.workspaceSubtitle.textContent = "配置服务器连接与 Agent 访问权限，保存后即可检测连接。";
    elements.selectedStateBadge.textContent = "未保存";
    elements.selectedStateBadge.className = "state-badge is-draft";
    return;
  }
  elements.workspaceTitle.textContent = alias;
  elements.workspaceSubtitle.textContent = target.description || `${target.target.username}@${target.target.host}:${target.target.port}`;
  elements.selectedStateBadge.textContent = target.enabled ? "已启用" : "已停用";
  elements.selectedStateBadge.className = `state-badge ${target.enabled ? "is-enabled" : "is-disabled"}`;
}

function setActiveView(view, moveFocus = false) {
  if (!["config", "command", "settings"].includes(view)) view = "config";
  if (view === "command" && !state.selectedAlias) {
    view = "config";
  }
  const viewChanged = state.activeView !== view;
  state.activeView = view;
  const views = [
    { name: "config", tab: elements.configTab, panel: elements.configPanel },
    { name: "command", tab: elements.commandTab, panel: elements.commandPanel },
    { name: "settings", tab: elements.settingsTab, panel: elements.settingsPanel },
  ];
  for (const item of views) {
    const selected = item.name === view;
    item.tab.classList.toggle("is-active", selected);
    item.tab.setAttribute("aria-selected", String(selected));
    item.tab.tabIndex = selected ? 0 : -1;
    item.panel.hidden = !selected;
    if (selected && moveFocus) item.tab.focus();
  }
  renderWorkspaceHeading();
  renderDirtyState();
  if (viewChanged) window.scrollTo?.({ top: 0, behavior: "instant" });
}

function handleWorkspaceTabKeydown(event) {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
    return;
  }
  event.preventDefault();
  const enabled = [
    { name: "config", tab: elements.configTab },
    { name: "command", tab: elements.commandTab },
    { name: "settings", tab: elements.settingsTab },
  ].filter((item) => !item.tab.disabled);
  const currentIndex = Math.max(0, enabled.findIndex((item) => item.tab === event.target));
  const nextIndex = event.key === "Home"
    ? 0
    : event.key === "End"
      ? enabled.length - 1
      : (currentIndex + (event.key === "ArrowLeft" ? -1 : 1) + enabled.length) % enabled.length;
  setActiveView(enabled[nextIndex].name, true);
}

function collectForm(options = {}) {
  clearInvalidFields();
  const alias = elements.targetAlias.value.trim();
  if (!ALIAS_PATTERN.test(alias)) {
    return invalid(elements.targetAlias, "机器别名格式不正确。");
  }
  const duplicate = [...state.targets.keys()].find(
    (candidate) => candidate.toLowerCase() === alias.toLowerCase() && candidate !== state.originalAlias,
  );
  if (duplicate) {
    return invalid(elements.targetAlias, `机器别名与 ${duplicate} 重复。`);
  }
  const description = elements.targetDescription.value.trim();
  if (description.length > 256 || /[\u0000-\u001f\u007f]/u.test(description)) {
    return invalid(elements.targetDescription, "说明不能包含控制字符，且最多 256 个字符。");
  }
  const connectionMode = selectedRadio(elements.connectionModeInputs) ?? "openssh";
  if (connectionMode === "tailscale-ssh") {
    if (!state.tailscaleSettings.executable) return invalid(elements.connectionModeInputs.find((input) => input.value === "tailscale-ssh"), "请先在全局设置保存 Tailscale 程序路径。");
    if (selectedRadio(elements.platformInputs) === "windows") return invalid(elements.platformInputs[0], "原生 Tailscale SSH 服务端支持 Linux 和 macOS。");
    if (!/^[A-Za-z_][A-Za-z0-9._-]*$/u.test(elements.targetUsername.value.trim())) return invalid(elements.targetUsername, "请填写远端系统账号，例如 ubuntu 或 root。");
    elements.targetPort.value = "22";
  }
  let knownHostsFile;
  let accessClient;
  if (connectionMode === "openssh") {
    knownHostsFile = elements.knownHostsFile.value.trim();
    if (!knownHostsFile) {
      return invalid(elements.knownHostsFile, "请填写 known_hosts 的绝对路径。");
    }
  }
  if (connectionMode === "accessclient-share") {
    if (!state.accessClientSettings.plinkExecutable) {
      return invalid(
        elements.connectionModeInputs.find((input) => input.value === "accessclient-share"),
        "请先到全局设置保存 Plink 程序路径，再配置 AccessClient 机器。",
      );
    }
    const accessClientUsername = elements.accessClientGatewayUsername.value.trim();
    if (!validSshUsername(accessClientUsername)) {
      return invalid(
        elements.accessClientGatewayUsername,
        "AccessClient 账号格式不正确。",
      );
    }
    elements.targetUsername.value = accessClientUsername;
    const targetHost = elements.targetHost.value.trim();
    const targetPort = Number(elements.accessClientTargetPort.value);
    const savedExpectedHostname = state.originalAlias === null
      ? undefined
      : state.targets.get(state.originalAlias)?.accessClient?.expectedHostname;
    accessClient = {
      gatewayHost: targetHost,
      gatewayPort: targetPort,
      gatewayUsername: accessClientUsername,
      sharingHost: targetHost,
      sharingPort: targetPort,
      ...(savedExpectedHostname === undefined
        ? {}
        : { expectedHostname: savedExpectedHostname }),
    };
  }
  const endpoint = collectEndpoint({
    host: elements.targetHost,
    port: connectionMode === "accessclient-share"
      ? elements.accessClientTargetPort
      : elements.targetPort,
    username: elements.targetUsername,
    keyId: elements.targetKeyId,
    label: "目标机器",
  }, connectionMode === "openssh");
  if (endpoint.error) {
    return endpoint;
  }
  const policyMode = selectedRadio(elements.policyInputs) ?? "allow-list";
  let allowedCommands = [];
  if (policyMode === "allow-list") {
    allowedCommands = elements.allowedCommands.value
      .split(/\r?\n/u)
      .map((command) => command.trim())
      .filter(Boolean);
    if (allowedCommands.length === 0) {
      return invalid(elements.allowedCommands, "命令白名单至少需要一条命令。");
    }
    if (allowedCommands.length > 128) {
      return invalid(elements.allowedCommands, "命令白名单最多允许 128 条命令。");
    }
    if (new Set(allowedCommands).size !== allowedCommands.length) {
      return invalid(elements.allowedCommands, "命令白名单中不能有重复命令。");
    }
    if (allowedCommands.some((command) => command.includes("\0"))) {
      return invalid(elements.allowedCommands, "命令不能包含 NUL 字符。");
    }
  }
  if (options.requireFullConfirmation && policyMode === "full-access" && !elements.fullAccessConfirm.checked) {
    return invalid(elements.fullAccessConfirm, "保存 Full access 配置前必须确认风险。");
  }
  const maxTimeoutMs = Number(elements.maxTimeoutMs.value);
  if (!validInteger(maxTimeoutMs, 1, MAX_TIMEOUT_MS)) {
    return invalid(elements.maxTimeoutMs, "最长执行时间必须是 1 至 3,600,000 毫秒的整数。");
  }
  const selectedTransferMode = selectedRadio(elements.transferInputs) ?? "deny";
  const transferMode = connectionMode !== "openssh"
    ? "deny"
    : policyMode === "full-access"
      ? "bidirectional"
    : policyMode === "deny"
      ? "deny"
      : selectedTransferMode;
  let localRootPath;
  let remoteRoots = [];
  let maxTransferTimeoutMs;
  if (policyMode === "allow-list" && transferMode !== "deny") {
    maxTransferTimeoutMs = Number(elements.maxTransferTimeoutMs.value);
    if (!validInteger(maxTransferTimeoutMs, 1, MAX_TIMEOUT_MS)) {
      return invalid(elements.maxTransferTimeoutMs, "传输最长时间必须是 1 至 3,600,000 毫秒的整数。");
    }
    localRootPath = elements.localRootPath.value.trim();
    if (!localRootPath) {
      return invalid(elements.localRootPath, "请填写允许 Codex 访问的本机绝对目录。");
    }
    remoteRoots = elements.remoteRoots.value
      .split(/\r?\n/u)
      .map((value) => value.trim())
      .filter(Boolean);
    if (remoteRoots.length === 0 || remoteRoots.length > 32) {
      return invalid(elements.remoteRoots, "请填写 1 至 32 个远端绝对目录。");
    }
    if (new Set(remoteRoots).size !== remoteRoots.length) {
      return invalid(elements.remoteRoots, "远端授权目录不能重复。");
    }
    if (options.requireFullConfirmation && !elements.transferAccessConfirm.checked) {
      return invalid(elements.transferAccessConfirm, "保存文件传输权限前必须确认本机和远端目录。");
    }
  }
  return {
    alias,
    target: {
      ...(description ? { description } : {}),
      enabled: state.originalAlias
        ? state.targets.get(state.originalAlias)?.enabled ?? true
        : true,
      connectionMode,
      target: endpoint.endpoint,
      ...(connectionMode === "openssh"
        ? { knownHostsFile }
        : connectionMode === "accessclient-share" ? { accessClient } : {}),
      platform: selectedRadio(elements.platformInputs) ?? "linux",
      policyMode,
      allowedCommands: policyMode === "allow-list" ? allowedCommands : [],
      maxTimeoutMs,
      ...(connectionMode !== "openssh"
        ? { transferMode: "deny" }
        : policyMode === "allow-list"
        ? {
            transferMode,
            ...(localRootPath ? { localRootPath } : {}),
            ...(remoteRoots.length > 0 ? { remoteRoots } : {}),
            ...(maxTransferTimeoutMs === undefined ? {} : { maxTransferTimeoutMs }),
          }
        : {}),
    },
  };
}

function collectEndpoint(fields, requireKey = true) {
  const host = fields.host.value.trim();
  if (!host) {
    return invalid(fields.host, `请填写${fields.label}地址。`);
  }
  const port = Number(fields.port.value);
  if (!validInteger(port, 1, 65_535)) {
    return invalid(fields.port, `${fields.label}端口必须是 1 至 65535 的整数。`);
  }
  const username = fields.username.value.trim();
  if (!validSshUsername(username)) {
    return invalid(fields.username, `${fields.label}用户名必须是普通用户名，或 portal/IPv4/account 格式。`);
  }
  if (!requireKey) {
    return { endpoint: { host, port, username } };
  }
  if (!state.keysAvailable) {
    return invalid(fields.keyId, "私钥列表当前不可用，请刷新后重试。");
  }
  const keyId = fields.keyId.value;
  if (!KEY_ID_PATTERN.test(keyId) || !state.keys.has(keyId)) {
    return invalid(fields.keyId, `请选择可用的${fields.label}私钥。`);
  }
  return { endpoint: { host, port, username, keyId } };
}

function invalid(input, message) {
  input.setAttribute("aria-invalid", "true");
  input.focus();
  showAlert(elements.formError, message, "error");
  return { error: message };
}

function clearInvalidFields() {
  for (const input of elements.machineForm.querySelectorAll("[aria-invalid]")) {
    input.removeAttribute("aria-invalid");
  }
}

async function saveMachine(event) {
  event.preventDefault();
  if (
    state.mutationBusy ||
    state.keyMutationBusy ||
    state.tailscaleMutationBusy || state.accessClientMutationBusy ||
    state.checking ||
    state.inspecting ||
    state.running
  ) {
    return;
  }
  clearFormMessages();
  const form = collectForm({ requireFullConfirmation: true });
  if (form.error) {
    return;
  }
  state.mutationBusy = true;
  updateControls();
  showAlert(elements.formStatus, "正在保存并重新加载网关配置...", "progress");
  try {
    const body = {
      alias: form.alias,
      target: form.target,
      ...(state.originalAlias ? { previousAlias: state.originalAlias } : {}),
      ...(typeof state.fleetStatus?.revision === "string" ? { expectedRevision: state.fleetStatus.revision } : {}),
      ...(form.target.policyMode === "full-access" ? { fullAccessConfirmed: true } : {}),
      ...(form.target.policyMode === "allow-list" && form.target.transferMode !== "deny"
        ? { transferAccessConfirmed: true }
        : {}),
    };
    const result = await postApi("admin/target/save", body);
    applyFleetStatus(result, { preserveAccessClientDraft: true });
    state.originalAlias = form.alias;
    state.selectedAlias = form.alias;
    state.probes.delete(form.alias);
    fillForm(form.alias, state.targets.get(form.alias) ?? form.target);
    renderInventory();
    renderWorkspaceHeading();
    renderCommandTarget();
    showAlert(elements.formStatus, "配置已保存，Codex 将使用当前版本。", "success");
    showToast("机器配置已保存");
    void refreshGatewayTargets();
  } catch (error) {
    showAlert(elements.formError, messageForError(error), "error");
  } finally {
    state.mutationBusy = false;
    elements.fullAccessConfirm.checked = false;
    elements.transferAccessConfirm.checked = false;
    updateControls();
  }
}

async function removeMachine() {
  const alias = state.originalAlias;
  if (
    !alias ||
    state.mutationBusy ||
    state.keyMutationBusy ||
    state.tailscaleMutationBusy || state.accessClientMutationBusy ||
    state.checking ||
    state.inspecting ||
    state.running
  ) {
    return;
  }
  if (!window.confirm(`确定删除机器“${alias}”吗？Codex 将立即失去对该机器的访问。`)) {
    return;
  }
  state.mutationBusy = true;
  clearFormMessages();
  showAlert(elements.formStatus, "正在删除并重新加载网关配置...", "progress");
  updateControls();
  try {
    const result = await postApi("admin/target/remove", {
      alias,
      ...(typeof state.fleetStatus?.revision === "string" ? { expectedRevision: state.fleetStatus.revision } : {}),
    });
    applyFleetStatus(result, { preserveAccessClientDraft: true });
    state.probes.delete(alias);
    renderInventory();
    const next = sortedTargets()[0];
    if (next) {
      selectMachine(next[0], { force: true });
    } else {
      startNewMachine({ force: true });
    }
    showToast(`已删除 ${alias}`);
    void refreshGatewayTargets();
  } catch (error) {
    showAlert(elements.formError, messageForError(error), "error");
  } finally {
    state.mutationBusy = false;
    updateControls();
  }
}

function renderAccessClientSettings() {
  const configured = state.accessClientSettings.plinkExecutable.length > 0;
  elements.accessClientSettingsBadge.textContent = configured ? "已配置" : "未配置";
  elements.accessClientSettingsBadge.className = `state-badge ${configured ? "is-enabled" : "is-draft"}`;
  elements.accessClientSettingsDot.className = `status-dot ${configured ? "is-online" : "is-idle"}`;
  elements.accessClientSettingsLabel.textContent = configured ? "Plink 路径已保存" : "尚未配置 Plink";
  elements.accessClientSettingsDetail.textContent = configured
    ? "共享会话是否在线，请在对应机器的配置页使用“检测连接”确认。"
    : "先保存 Plink 路径，再到机器配置选择 AccessClient 会话并检测连接。";
}

function handleAccessClientSettingsInput() {
  state.accessClientSettingsDirty =
    elements.plinkExecutable.value.trim() !== state.accessClientSettingsBaseline;
  clearAlert(elements.accessClientSettingsError);
  clearAlert(elements.accessClientSettingsStatus);
  renderDirtyState();
  updateControls();
}

async function saveAccessClientSettings(event) {
  event.preventDefault();
  if (
    state.tailscaleMutationBusy || state.accessClientMutationBusy ||
    state.mutationBusy ||
    state.keyMutationBusy ||
    state.checking ||
    state.inspecting ||
    state.running ||
    !state.inventoryAvailable
  ) {
    return;
  }
  const plinkExecutable = elements.plinkExecutable.value.trim();
  if (
    !WINDOWS_ABSOLUTE_FILE_PATTERN.test(plinkExecutable) ||
    /[\u0000-\u001f\u007f"$]/u.test(plinkExecutable) ||
    plinkExecutable.startsWith("\\\\") ||
    plinkExecutable.slice(3).includes(":")
  ) {
    elements.plinkExecutable.setAttribute("aria-invalid", "true");
    elements.plinkExecutable.focus();
    showAlert(
      elements.accessClientSettingsError,
      "请填写本机 Plink 程序的 Windows 绝对路径。",
      "error",
    );
    return;
  }
  elements.plinkExecutable.removeAttribute("aria-invalid");
  state.accessClientMutationBusy = true;
  clearAlert(elements.accessClientSettingsError);
  showAlert(elements.accessClientSettingsStatus, "正在验证并保存 Plink 路径...", "progress");
  updateControls();
  try {
    const result = await postApi("admin/access-client/save", {
      plinkExecutable,
      ...(typeof state.fleetStatus?.revision === "string"
        ? { expectedRevision: state.fleetStatus.revision }
        : {}),
    });
    const status = result?.status && typeof result.status === "object" ? result.status : result;
    state.fleetStatus = status && typeof status === "object" ? status : state.fleetStatus;
    applyAccessClientSettingsSnapshot(status);
    if (typeof status?.revision === "string") {
      elements.revisionLabel.textContent = status.revision;
      elements.revisionLabel.title = status.revision;
    }
    renderWorkspaceHeading();
    renderDirtyState();
    showAlert(elements.accessClientSettingsStatus, "Plink 路径已保存。", "success");
    showToast("AccessClient 设置已保存");
  } catch (error) {
    showAlert(elements.accessClientSettingsError, messageForError(error), "error");
  } finally {
    state.accessClientMutationBusy = false;
    updateControls();
  }
}

function renderTailscaleSettings() {
  const configured = state.tailscaleSettings.executable.length > 0;
  elements.tailscaleSettingsBadge.textContent = configured ? "已配置" : "未配置";
  elements.tailscaleSettingsBadge.className = `state-badge ${configured ? "is-enabled" : "is-draft"}`;
  elements.tailscaleSettingsDot.className = `status-dot ${configured ? "is-online" : "is-idle"}`;
  elements.tailscaleSettingsLabel.textContent = configured ? "Tailscale 路径已保存" : "尚未配置 Tailscale";
  elements.tailscaleSettingsDetail.textContent = configured
    ? "请在对应机器使用“检测连接”确认 Tailscale 登录状态、目标身份和 SSH 授权。"
    : "先保存 Tailscale 路径，再在机器配置选择 Tailscale SSH。";
}

function handleTailscaleSettingsInput() {
  state.tailscaleSettingsDirty =
    elements.tailscaleExecutable.value.trim() !== state.tailscaleSettingsBaseline;
  clearAlert(elements.tailscaleSettingsError);
  clearAlert(elements.tailscaleSettingsStatus);
  renderDirtyState();
  updateControls();
}

async function saveTailscaleSettings(event) {
  event.preventDefault();
  if (
    state.tailscaleMutationBusy || state.accessClientMutationBusy ||
    state.mutationBusy ||
    state.keyMutationBusy ||
    state.checking ||
    state.inspecting ||
    state.running ||
    !state.inventoryAvailable
  ) {
    return;
  }
  const executable = elements.tailscaleExecutable.value.trim();
  if (
    !WINDOWS_ABSOLUTE_FILE_PATTERN.test(executable) ||
    /[\u0000-\u001f\u007f"$]/u.test(executable) ||
    executable.startsWith("\\\\") ||
    executable.slice(3).includes(":")
  ) {
    elements.tailscaleExecutable.setAttribute("aria-invalid", "true");
    elements.tailscaleExecutable.focus();
    showAlert(
      elements.tailscaleSettingsError,
      "请填写本机 Tailscale 程序的 Windows 绝对路径。",
      "error",
    );
    return;
  }
  elements.tailscaleExecutable.removeAttribute("aria-invalid");
  state.tailscaleMutationBusy = true;
  clearAlert(elements.tailscaleSettingsError);
  showAlert(elements.tailscaleSettingsStatus, "正在验证并保存 Tailscale 路径...", "progress");
  updateControls();
  try {
    const result = await postApi("admin/tailscale/save", {
      executable,
      ...(typeof state.fleetStatus?.revision === "string"
        ? { expectedRevision: state.fleetStatus.revision }
        : {}),
    });
    const status = result?.status && typeof result.status === "object" ? result.status : result;
    state.fleetStatus = status && typeof status === "object" ? status : state.fleetStatus;
    applyTailscaleSettingsSnapshot(status);
    if (typeof status?.revision === "string") {
      elements.revisionLabel.textContent = status.revision;
      elements.revisionLabel.title = status.revision;
    }
    renderWorkspaceHeading();
    renderDirtyState();
    showAlert(elements.tailscaleSettingsStatus, "Tailscale 路径已保存。", "success");
    showToast("Tailscale 设置已保存");
  } catch (error) {
    showAlert(elements.tailscaleSettingsError, messageForError(error), "error");
  } finally {
    state.tailscaleMutationBusy = false;
    updateControls();
  }
}

function renderKeyManagement() {
  elements.keyCount.textContent = state.keysLoaded ? String(state.keys.size) : "--";
  elements.keyList.replaceChildren();
  elements.keyList.hidden = !state.keysLoaded || state.keys.size === 0;
  elements.keyEmpty.hidden = !state.keysLoaded || state.keys.size > 0;
  if (state.keysLoaded) {
    for (const [, key] of sortedKeys()) elements.keyList.append(createKeyItem(key));
  }
  renderPublicKeyPanel();
}

function createKeyItem(key) {
  const item = document.createElement("article");
  item.className = "key-item";
  item.setAttribute("role", "listitem");

  const main = document.createElement("div");
  main.className = "key-item-main";
  const label = document.createElement("strong");
  label.textContent = key.label;
  const meta = document.createElement("span");
  meta.className = "key-item-meta";
  meta.textContent = [key.algorithm, key.fingerprint].filter(Boolean).join(" · ");
  const usage = document.createElement("span");
  usage.className = `key-usage ${key.inUseBy.length > 0 ? "is-used" : ""}`;
  usage.textContent = keyUsageText(key);
  main.append(label, meta, usage);

  const actions = document.createElement("div");
  actions.className = "key-item-actions";
  const publicButton = document.createElement("button");
  publicButton.type = "button";
  publicButton.className = "toolbar-button";
  publicButton.textContent = "公钥";
  publicButton.disabled = !key.publicKey;
  publicButton.dataset.unavailable = String(!key.publicKey);
  publicButton.addEventListener("click", () => showPublicKey(key.keyId));
  const renameButton = document.createElement("button");
  renameButton.type = "button";
  renameButton.className = "toolbar-button";
  renameButton.textContent = "重命名";
  renameButton.dataset.mutation = "true";
  renameButton.addEventListener("click", () => openKeyEditor("rename", key));
  const removeButton = document.createElement("button");
  removeButton.type = "button";
  removeButton.className = "danger-text-button compact-danger-button";
  removeButton.textContent = "删除";
  removeButton.dataset.mutation = "true";
  removeButton.disabled = key.inUseBy.length > 0;
  removeButton.dataset.inUse = String(key.inUseBy.length > 0);
  if (removeButton.disabled) removeButton.title = keyUsageText(key);
  removeButton.addEventListener("click", () => void removeKey(key));
  actions.append(publicButton, renameButton, removeButton);
  item.append(main, actions);
  return item;
}

function keyUsageText(key) {
  if (key.inUseBy.length === 0) return "未被机器使用";
  const references = key.inUseBy.slice(0, 3).map((reference) =>
    `${reference.alias}（${reference.role === "bastion" ? "堡垒机" : "目标机器"}）`);
  const remainder = key.inUseBy.length - references.length;
  return `被 ${references.join("、")}${remainder > 0 ? ` 等 ${key.inUseBy.length} 处` : ""}使用`;
}

function showPublicKey(keyId) {
  if (!state.keys.has(keyId)) return;
  state.publicKeyId = keyId;
  renderPublicKeyPanel();
  elements.keyPublicPanel.hidden = false;
}

function renderPublicKeyPanel() {
  const key = state.publicKeyId ? state.keys.get(state.publicKeyId) : null;
  const visible = Boolean(key?.publicKey);
  elements.keyPublicPanel.hidden = !visible;
  elements.keyPublicHeading.textContent = visible ? `${key.label} 公钥` : "公钥";
  elements.keyPublicMeta.textContent = visible ? [key.algorithm, key.fingerprint].filter(Boolean).join(" · ") : "";
  elements.publicKeyOutput.textContent = visible ? key.publicKey : "";
}

function openKeyEditor(mode, key = null) {
  if (
    !state.keysAvailable ||
    state.keyMutationBusy ||
    state.mutationBusy ||
    state.tailscaleMutationBusy || state.accessClientMutationBusy ||
    state.checking ||
    state.inspecting ||
    state.running
  ) return;
  state.keyEditorMode = mode;
  state.editingKeyId = mode === "rename" ? key?.keyId ?? null : null;
  elements.keyEditorTitle.textContent = mode === "generate"
    ? "生成私钥"
    : mode === "import" ? "导入现有私钥" : "重命名私钥";
  elements.keyEditorSubmitButton.textContent = mode === "generate" ? "生成" : mode === "import" ? "导入" : "保存名称";
  elements.keyAlgorithmField.hidden = mode !== "generate";
  elements.keySourceField.hidden = mode !== "import";
  elements.keyLabel.value = mode === "rename" ? key?.label ?? "" : "";
  elements.keyAlgorithm.value = "ed25519";
  elements.keySourcePath.value = "";
  elements.keyEditorForm.hidden = false;
  clearAlert(elements.keyError);
  clearAlert(elements.keyStatus);
  setActiveView("settings");
  elements.keyLabel.focus();
  updateControls();
}

function closeKeyEditor() {
  state.keyEditorMode = null;
  state.editingKeyId = null;
  elements.keyEditorForm.hidden = true;
  elements.keyLabel.value = "";
  elements.keyAlgorithm.value = "ed25519";
  elements.keySourcePath.value = "";
  elements.keyLabel.removeAttribute("aria-invalid");
  elements.keyAlgorithm.removeAttribute("aria-invalid");
  elements.keySourcePath.removeAttribute("aria-invalid");
  updateControls();
}

function collectKeyEditor() {
  elements.keyLabel.removeAttribute("aria-invalid");
  elements.keyAlgorithm.removeAttribute("aria-invalid");
  elements.keySourcePath.removeAttribute("aria-invalid");
  const label = elements.keyLabel.value.trim();
  if (!label || label.length > 128 || /[\u0000-\u001f\u007f]/u.test(label)) {
    return invalidKeyEditor(elements.keyLabel, "私钥名称不能为空、不能包含控制字符，且最多 128 个字符。");
  }
  const duplicate = [...state.keys.values()].find((key) =>
    key.keyId !== state.editingKeyId && key.label.toLowerCase() === label.toLowerCase());
  if (duplicate) return invalidKeyEditor(elements.keyLabel, `私钥名称与 ${duplicate.label} 重复。`);
  if (state.keyEditorMode === "import") {
    const sourcePath = elements.keySourcePath.value.trim();
    if (!sourcePath || !ABSOLUTE_LOCAL_PATH_PATTERN.test(sourcePath)) {
      return invalidKeyEditor(elements.keySourcePath, "请填写现有私钥的本机绝对路径。");
    }
    return { label, sourcePath };
  }
  if (state.keyEditorMode === "generate") {
    const algorithm = elements.keyAlgorithm.value;
    if (!KEY_GENERATION_ALGORITHMS.has(algorithm)) {
      return invalidKeyEditor(elements.keyAlgorithm, "请选择受支持的密钥算法。");
    }
    return { label, algorithm };
  }
  return { label };
}

function invalidKeyEditor(input, message) {
  input.setAttribute("aria-invalid", "true");
  input.focus();
  showAlert(elements.keyError, message, "error");
  return { error: message };
}

async function submitKeyEditor(event) {
  event.preventDefault();
  if (!state.keyEditorMode || state.keyMutationBusy || state.mutationBusy || state.tailscaleMutationBusy || state.accessClientMutationBusy || state.running) return;
  const form = collectKeyEditor();
  if (form.error) return;
  if (!state.keyRevision) {
    showAlert(elements.keyError, "私钥配置版本不可用，请刷新后重试。", "error");
    return;
  }
  const mode = state.keyEditorMode;
  const editingKeyId = state.editingKeyId;
  const previousKeyIds = new Set(state.keys.keys());
  state.keyMutationBusy = true;
  clearAlert(elements.keyError);
  showAlert(elements.keyStatus, mode === "generate" ? "正在生成私钥..." : mode === "import" ? "正在导入私钥..." : "正在保存名称...", "progress");
  updateControls();
  try {
    const route = mode === "generate" ? "admin/key/generate" : mode === "import" ? "admin/key/import" : "admin/key/rename";
    const body = {
      label: form.label,
      expectedKeyRevision: state.keyRevision,
      ...(mode === "generate" ? { algorithm: form.algorithm } : {}),
      ...(mode === "import" ? { sourcePath: form.sourcePath } : {}),
      ...(mode === "rename" ? { keyId: editingKeyId } : {}),
    };
    const result = await postApi(route, body);
    if (!applyKeySnapshot(result)) throw keySnapshotApiError();
    const createdKey = mode === "rename"
      ? state.keys.get(editingKeyId)
      : [...state.keys.values()].find((key) => !previousKeyIds.has(key.keyId));
    if (createdKey?.publicKey) state.publicKeyId = createdKey.keyId;
    closeKeyEditor();
    renderKeyManagement();
    renderDirtyState();
    showAlert(elements.keyStatus, mode === "rename" ? "私钥名称已保存。" : "私钥已加入全局设置。", "success");
    showToast(mode === "rename" ? "私钥已重命名" : "私钥已添加");
  } catch (error) {
    showAlert(elements.keyError, messageForError(error), "error");
  } finally {
    elements.keySourcePath.value = "";
    state.keyMutationBusy = false;
    updateControls();
  }
}

async function removeKey(key) {
  if (state.keyMutationBusy || state.mutationBusy || state.tailscaleMutationBusy || state.accessClientMutationBusy || state.running || !state.keysAvailable) return;
  if (key.inUseBy.length > 0) {
    showAlert(elements.keyError, `${key.label}${keyUsageText(key)}，不能删除。`, "error");
    return;
  }
  const usedByDraft = state.dirty && (
    selectedRadio(elements.connectionModeInputs) === "openssh" &&
    elements.targetKeyId.value === key.keyId
  );
  if (usedByDraft) {
    showAlert(elements.keyError, "当前未保存的机器配置正在使用这把私钥，请先更换私钥或放弃修改。", "error");
    return;
  }
  if (!state.keyRevision || !window.confirm(`确定删除私钥“${key.label}”吗？`)) return;
  state.keyMutationBusy = true;
  clearAlert(elements.keyError);
  showAlert(elements.keyStatus, "正在删除私钥...", "progress");
  updateControls();
  try {
    const result = await postApi("admin/key/remove", {
      keyId: key.keyId,
      expectedKeyRevision: state.keyRevision,
    });
    if (!applyKeySnapshot(result)) throw keySnapshotApiError();
    renderDirtyState();
    showAlert(elements.keyStatus, "私钥已删除。", "success");
    showToast(`已删除 ${key.label}`);
  } catch (error) {
    showAlert(elements.keyError, messageForError(error), "error");
  } finally {
    state.keyMutationBusy = false;
    updateControls();
  }
}

function applyAccessClientPreparationSnapshot(rawSnapshot) {
  const allowedStates = new Set([
    "idle",
    "armed",
    "detected",
    "ready",
    "timed-out",
    "cancelled",
    "error",
  ]);
  if (!rawSnapshot || typeof rawSnapshot !== "object" || !allowedStates.has(rawSnapshot.state)) {
    return false;
  }
  state.accessClientPreparation = {
    state: rawSnapshot.state,
    ...(typeof rawSnapshot.alias === "string" ? { alias: rawSnapshot.alias } : {}),
    ...(typeof rawSnapshot.sharingHost === "string" ? { sharingHost: rawSnapshot.sharingHost } : {}),
    ...(Number.isSafeInteger(rawSnapshot.sharingPort) ? { sharingPort: rawSnapshot.sharingPort } : {}),
    ...(typeof rawSnapshot.startedAt === "string" ? { startedAt: rawSnapshot.startedAt } : {}),
    ...(typeof rawSnapshot.deadlineAt === "string" ? { deadlineAt: rawSnapshot.deadlineAt } : {}),
    ...(typeof rawSnapshot.completedAt === "string" ? { completedAt: rawSnapshot.completedAt } : {}),
    ...(typeof rawSnapshot.hostname === "string" ? { hostname: rawSnapshot.hostname } : {}),
    ...(Number.isFinite(rawSnapshot.durationMs) ? { durationMs: rawSnapshot.durationMs } : {}),
    ...(typeof rawSnapshot.message === "string" ? { message: rawSnapshot.message } : {}),
  };
  if (
    state.accessClientPreparation.state === "ready" &&
    typeof state.accessClientPreparation.alias === "string"
  ) {
    const alias = state.accessClientPreparation.alias;
    state.probes.set(alias, {
      connected: true,
      checkedAt: Date.now(),
      hostname: state.accessClientPreparation.hostname ?? null,
    });
    renderInventory();
    if (alias === state.originalAlias) {
      const hostname = state.accessClientPreparation.hostname
        ? `，主机名 ${state.accessClientPreparation.hostname}`
        : "";
      showAlert(
        elements.formStatus,
        `连接成功${hostname}，耗时 ${formatDuration(state.accessClientPreparation.durationMs)}。`,
        "success",
      );
    }
  }
  renderAccessClientPreparation();
  scheduleAccessClientPreparationPoll();
  return true;
}

function accessClientPreparationIsActive(snapshot = state.accessClientPreparation) {
  return snapshot.state === "armed" || snapshot.state === "detected";
}

function renderAccessClientPreparation() {
  const alias = state.originalAlias;
  const target = alias ? state.targets.get(alias) : null;
  const savedAccessClient = target?.connectionMode === "accessclient-share";
  const snapshot = state.accessClientPreparation;
  const belongsToSelection = typeof snapshot.alias !== "string" || snapshot.alias === alias;
  const activeForAnotherTarget = accessClientPreparationIsActive(snapshot) && !belongsToSelection;

  let dotClass = "is-idle";
  let label = "AccessClient 会话尚未准备";
  let detail = "点击“检测连接”后，按提示从 AccessClient 打开这台机器。首次连接时请在 PuTTY 中核对并手动确认主机密钥。";
  if (activeForAnotherTarget) {
    dotClass = "is-checking";
    label = `${snapshot.alias} 正在准备 AccessClient 会话`;
    detail = "同一时间只能准备一台机器。";
  } else if (belongsToSelection) {
    switch (snapshot.state) {
      case "armed":
        dotClass = "is-checking";
        label = "等待 AccessClient 打开这台机器";
        detail = "请在两分钟内从 AccessClient 打开目标；首次连接时核对并手动确认 PuTTY 主机密钥。";
        break;
      case "detected":
        dotClass = "is-checking";
        label = "已发现新 PuTTY，正在验证机器身份";
        detail = "正在通过固定 hostname 探测确认它属于当前机器，请保持窗口打开。";
        break;
      case "ready":
        dotClass = "is-online";
        label = "AccessClient 会话已验证";
        detail = snapshot.hostname
          ? `已连接到主机 ${snapshot.hostname}，可以直接交给 Codex 使用。`
          : "机器身份验证成功，可以直接交给 Codex 使用。";
        break;
      case "timed-out":
        dotClass = "is-offline";
        label = "准备已超时";
        detail = "未检测到新的 PuTTY 进程，临时设置已恢复，可以重新准备。";
        break;
      case "cancelled":
        label = "准备已取消";
        detail = "临时 PuTTY 设置已恢复。";
        break;
      case "error":
        dotClass = "is-offline";
        label = "准备失败";
        detail = "请重启 SSH 管理服务确认临时 PuTTY 设置已恢复后再试。";
        break;
      default:
        break;
    }
  }
  elements.accessClientPrepareDot.className = `status-dot ${dotClass}`;
  elements.accessClientPrepareLabel.textContent = label;
  elements.accessClientPrepareDetail.textContent = detail;
  elements.cancelAccessClientPrepareButton.hidden = !(
    belongsToSelection && accessClientPreparationIsActive(snapshot)
  );
  elements.accessClientPreparePanel.hidden = !savedAccessClient && selectedRadio(elements.connectionModeInputs) !== "accessclient-share";
}

function accessClientPreparationRequest(alias = state.originalAlias) {
  const expectedRevision = state.fleetStatus?.revision;
  if (!alias || typeof expectedRevision !== "string") return null;
  return { alias, expectedRevision };
}

async function prepareAccessClientSession() {
  const request = accessClientPreparationRequest();
  if (
    request === null ||
    state.dirty ||
    state.accessClientPreparationBusy ||
    state.mutationBusy ||
    state.checking ||
    state.running
  ) {
    return;
  }
  state.accessClientPreparationBusy = true;
  clearFormMessages();
  showAlert(elements.formStatus, "正在为这台机器准备 AccessClient 会话...", "progress");
  updateControls();
  try {
    const snapshot = await postApi("admin/access-client/session/prepare", request);
    applyAccessClientPreparationSnapshot(snapshot);
    showAlert(elements.formStatus, "请现在从 AccessClient 打开这台机器，系统会自动识别新出现的 PuTTY。", "progress");
  } catch (error) {
    showAlert(elements.formError, messageForError(error), "error");
  } finally {
    state.accessClientPreparationBusy = false;
    updateControls();
  }
}

async function refreshAccessClientPreparation() {
  const alias = state.accessClientPreparation.alias;
  const request = accessClientPreparationRequest(alias);
  if (request === null || !accessClientPreparationIsActive()) return;
  try {
    const snapshot = await postApi("admin/access-client/session/status", request);
    if (snapshot?.status && typeof snapshot.status === "object") {
      applyFleetStatus(snapshot.status, { preserveAccessClientDraft: true });
      if (request.alias === state.originalAlias && state.targets.has(request.alias)) {
        fillForm(request.alias, state.targets.get(request.alias));
      }
    }
    applyAccessClientPreparationSnapshot(snapshot);
    updateControls();
  } catch (error) {
    if (state.accessClientPreparationTimer !== null) {
      window.clearTimeout(state.accessClientPreparationTimer);
      state.accessClientPreparationTimer = null;
    }
    showAlert(elements.formError, messageForError(error), "error");
  }
}

function scheduleAccessClientPreparationPoll() {
  if (state.accessClientPreparationTimer !== null) {
    window.clearTimeout(state.accessClientPreparationTimer);
    state.accessClientPreparationTimer = null;
  }
  if (!accessClientPreparationIsActive()) return;
  state.accessClientPreparationTimer = window.setTimeout(() => {
    state.accessClientPreparationTimer = null;
    void refreshAccessClientPreparation();
  }, 500);
}

async function cancelAccessClientPreparation() {
  const request = accessClientPreparationRequest(state.accessClientPreparation.alias);
  if (request === null || state.accessClientPreparationBusy || !accessClientPreparationIsActive()) return;
  state.accessClientPreparationBusy = true;
  updateControls();
  try {
    const snapshot = await postApi("admin/access-client/session/cancel", request);
    applyAccessClientPreparationSnapshot(snapshot);
    showAlert(elements.formStatus, "AccessClient 会话准备已取消。", "success");
  } catch (error) {
    showAlert(elements.formError, messageForError(error), "error");
  } finally {
    state.accessClientPreparationBusy = false;
    updateControls();
  }
}

async function checkConnection() {
  const alias = state.originalAlias;
  if (!alias || state.dirty || state.checking || state.mutationBusy || state.tailscaleMutationBusy || state.accessClientMutationBusy || state.running) {
    return;
  }
  state.checking = true;
  clearFormMessages();
  showAlert(elements.formStatus, "正在通过网关执行固定连接探测...", "progress");
  updateControls();
  try {
    const result = await postApi("admin/target/check", { target: alias });
    let target = state.targets.get(alias);
    if (result?.status && typeof result.status === "object") {
      applyFleetStatus(result.status, { preserveAccessClientDraft: true });
      fillForm(alias, state.targets.get(alias) ?? target);
      target = state.targets.get(alias);
    }
    const expectedHostname = target?.connectionMode === "accessclient-share"
      ? target.accessClient?.expectedHostname
      : undefined;
    const reportedHostname = typeof result?.hostname === "string" ? result.hostname : "";
    const hostnameMatches = expectedHostname === undefined ||
      reportedHostname.toLowerCase() === expectedHostname.toLowerCase();
    const connected = result?.connected === true && hostnameMatches;
    state.probes.set(alias, {
      connected,
      checkedAt: Date.now(),
      hostname: reportedHostname || null,
    });
    renderInventory();
    if (connected) {
      const hostname = typeof result.hostname === "string" && result.hostname ? `，主机名 ${result.hostname}` : "";
      showAlert(elements.formStatus, `连接成功${hostname}，耗时 ${formatDuration(result.durationMs)}。`, "success");
    } else if (result?.connected === true && !hostnameMatches) {
      showAlert(
        elements.formError,
        `连接到的主机名为 ${reportedHostname || "未知"}，与预期主机名 ${expectedHostname} 不一致。`,
        "error",
      );
    } else if (
      target?.connectionMode === "accessclient-share" &&
      result?.failureReason === "accessclient-session-unavailable"
    ) {
      state.probes.delete(alias);
      renderInventory();
      state.checking = false;
      updateControls();
      await prepareAccessClientSession();
    } else {
      const reason = checkFailureLabel(result);
      showAlert(elements.formError, `连接检测失败：${reason}，耗时 ${formatDuration(result?.durationMs)}。`, "error");
    }
  } catch (error) {
    state.probes.set(alias, { connected: false, checkedAt: Date.now() });
    renderInventory();
    showAlert(elements.formError, messageForError(error), "error");
  } finally {
    state.checking = false;
    updateControls();
  }
}

function checkFailureLabel(result) {
  const failureLabels = {
    "tailscale-unavailable": "本机 Tailscale 不可用，请确认程序路径、服务状态并登录 tailnet",
    "tailscale-peer-unavailable": "找不到唯一的 Tailscale 节点，请检查名称、IP 和 tailnet 可见性",
    "tailscale-host-key-unavailable": "目标未公布可用的 Tailscale SSH 主机密钥，请确认远端已启用 Tailscale SSH",
    "accessclient-session-unavailable": "AccessClient 共享会话不可用，请先在 AccessClient 中打开并登录这台机器",
    "accessclient-session-timeout": "AccessClient 共享会话在等待时限内未就绪，请保持目标会话打开后重试",
    "accessclient-host-mismatch": "AccessClient 当前共享会话连接到了另一台机器，请切换到配置的目标",
    "accessclient-session-ended": "AccessClient 共享会话在探测完成前已断开，请重新登录后重试",
  };
  if (typeof result?.failureReason === "string" && failureLabels[result.failureReason]) {
    return failureLabels[result.failureReason];
  }
  const termination = result?.termination;
  const exitCode = result?.exitCode;
  if (termination === "timeout") {
    return "连接超时";
  }
  if (termination === "cancel") {
    return "检测已取消";
  }
  if (termination === "exit") {
    return `探测命令退出码 ${Number.isInteger(exitCode) ? exitCode : "未知"}`;
  }
  return "SSH 握手或固定探测失败";
}

async function refreshGatewayTargets() {
  try {
    applyGatewayTargets(await postApi("targets", {}));
    renderInventory();
    renderCommandTarget();
  } catch {
    state.gatewayTargets.clear();
    renderCommandTarget();
  }
}

function renderCommandTarget() {
  const alias = state.selectedAlias;
  const target = alias ? state.targets.get(alias) : null;
  elements.commandTargetName.textContent = alias ?? "--";
  if (!target) {
    elements.commandPolicyBadge.textContent = "--";
    elements.commandPolicyBadge.className = "policy-chip";
    renderExecutionFormat();
    renderTransferOperation();
    return;
  }
  elements.commandPolicyBadge.textContent = POLICY_LABELS[target.policyMode];
  elements.commandPolicyBadge.className = `policy-chip ${policyClass(target.policyMode)}`;
  elements.runTimeoutMs.max = String(target.maxTimeoutMs);
  if (Number(elements.runTimeoutMs.value) > target.maxTimeoutMs) {
    elements.runTimeoutMs.value = String(Math.min(10_000, target.maxTimeoutMs));
  }
  if (target.policyMode === "allow-list") {
    elements.commandNote.textContent = `${target.allowedCommands.length} 条白名单命令，输入内容必须完全匹配。`;
  } else if (target.policyMode === "full-access") {
    elements.commandNote.textContent = "Full access：允许执行任意合法的单行命令。";
  } else {
    elements.commandNote.textContent = "该机器禁止执行命令。";
  }
  renderExecutionFormat();
  renderTransferOperation();
  const gatewayTarget = state.gatewayTargets.get(alias);
  const transferRoots = Array.isArray(gatewayTarget?.transferRoots) ? gatewayTarget.transferRoots : [];
  const transferTab = elements.operationTabs.find((tab) => tab.dataset.operation === "transfer");
  if (transferTab) {
    transferTab.disabled = target.transferMode === "deny"
      || (target.policyMode !== "full-access" && state.gatewayTargets.has(alias) && transferRoots.length === 0);
  }
  if (state.activeOperation === "transfer" && transferTab?.disabled) {
    setActiveOperation("exec");
  }
}

function validateCommand() {
  clearAlert(elements.commandError);
  const alias = state.selectedAlias;
  const target = alias ? state.targets.get(alias) : null;
  if (!alias || !target) {
    return { error: "请先选择一台已保存的机器。" };
  }
  if (state.dirty) {
    return { error: "请先保存当前配置，再执行命令。" };
  }
  if (!target.enabled) {
    return { error: "该机器已停用。" };
  }
  if (target.policyMode === "deny") {
    return { error: "该机器已禁止执行命令。" };
  }
  const timeoutMs = Number(elements.runTimeoutMs.value);
  if (!validInteger(timeoutMs, 1, target.maxTimeoutMs)) {
    return { error: `超时必须是 1 至 ${target.maxTimeoutMs.toLocaleString("zh-CN")} 毫秒的整数。` };
  }
  const format = selectedRadio(elements.executionFormatInputs) ?? "single";
  if (format === "single") {
    const command = elements.commandInput.value;
    if (!command.trim() || /[\0\r\n]/u.test(command)) {
      return { error: "命令必须是非空的单行文本。" };
    }
    if (utf8Bytes(command) > MAX_COMMAND_BYTES) {
      return { error: `命令不能超过 ${MAX_COMMAND_BYTES.toLocaleString("zh-CN")} 个 UTF-8 字节。` };
    }
    if (target.policyMode === "allow-list" && !target.allowedCommands.includes(command)) {
      return { error: "该命令不在此机器的白名单中。" };
    }
    return {
      params: { target: alias, command, timeoutMs },
      background: elements.backgroundTask.checked,
    };
  }
  if (target.policyMode !== "full-access") {
    return { error: "结构化脚本仅允许用于 Full access 机器。" };
  }
  const shell = selectedRadio(elements.remoteShellInputs);
  const shellAllowed = target.platform === "windows"
    ? shell === "powershell" || shell === "cmd"
    : shell === "bash";
  if (!shellAllowed) {
    return { error: `所选 Shell 不适用于 ${PLATFORM_LABELS[target.platform]}。` };
  }
  const script = elements.scriptInput.value;
  if (!script.trim() || script.includes("\0")) {
    return { error: "脚本不能为空，也不能包含 NUL 字符。" };
  }
  if (utf8Bytes(script) > MAX_COMMAND_BYTES) {
    return { error: `脚本不能超过 ${MAX_COMMAND_BYTES.toLocaleString("zh-CN")} 个 UTF-8 字节。` };
  }
  const cwd = elements.workingDirectory.value;
  if (cwd && (!cwd.trim() || /[\0\r\n]/u.test(cwd))) {
    return { error: "工作目录格式不正确。" };
  }
  const environment = parseEnvironmentText(elements.environmentInput.value, target.platform === "windows");
  if (environment.error) return environment;
  const aggregateBytes = utf8Bytes(script)
    + utf8Bytes(cwd)
    + Object.entries(environment.env).reduce(
      (total, [name, value]) => total + utf8Bytes(name) + utf8Bytes(value),
      0,
    );
  if (aggregateBytes > MAX_COMMAND_BYTES) {
    return { error: `脚本、工作目录和环境变量合计不能超过 ${MAX_COMMAND_BYTES.toLocaleString("zh-CN")} 个 UTF-8 字节。` };
  }
  return {
    params: {
      target: alias,
      shell,
      script,
      ...(cwd ? { cwd } : {}),
      ...(Object.keys(environment.env).length > 0 ? { env: environment.env } : {}),
      encoding: "utf-8",
      timeoutMs,
    },
    background: elements.backgroundTask.checked,
  };
}

function parseEnvironmentText(source, ignoreCase) {
  const env = {};
  const names = new Set();
  const lines = source.split(/\r?\n/u).filter((line) => line.length > 0);
  if (lines.length > MAX_ENVIRONMENT_ENTRIES) return { error: `环境变量最多允许 ${MAX_ENVIRONMENT_ENTRIES} 项。` };
  for (const line of lines) {
    const separator = line.indexOf("=");
    const name = separator < 0 ? "" : line.slice(0, separator).trim();
    const value = separator < 0 ? "" : line.slice(separator + 1);
    const identity = ignoreCase ? name.toLowerCase() : name;
    if (!ENVIRONMENT_NAME_PATTERN.test(name) || name.length > 128 || names.has(identity) || value.includes("\0")) {
      return { error: `环境变量格式不正确：${line.slice(0, 80)}` };
    }
    names.add(identity);
    env[name] = value;
  }
  return { env };
}

function utf8Bytes(value) {
  return new TextEncoder().encode(value).byteLength;
}

async function runCommand(event) {
  event.preventDefault();
  if (state.running || state.mutationBusy) {
    return;
  }
  const request = validateCommand();
  if (request.error) {
    showAlert(elements.commandError, request.error, "error");
    return;
  }
  if (request.background) {
    await startManagedTask("task/start", request.params, "远端任务");
    return;
  }
  state.running = true;
  state.cancelling = false;
  state.task = null;
  state.result = null;
  state.outputPages = createOutputPageState();
  setResultSummary("running", "正在执行");
  renderOutput();
  updateControls();
  try {
    const result = await postApi("run", {
      ...request.params,
    });
    state.result = normaliseResult(result);
    state.outputPages.stdout.text = state.result.stdout.text;
    state.outputPages.stderr.text = state.result.stderr.text;
    updateResultSummary(state.result);
  } catch (error) {
    showAlert(elements.commandError, messageForError(error), "error");
    setResultSummary("error", "执行请求失败");
  } finally {
    state.running = false;
    state.cancelling = false;
    updateControls();
    renderOutput();
  }
}

async function cancelCommand() {
  if (!state.running || state.cancelling) {
    return;
  }
  state.cancelling = true;
  updateControls();
  setResultSummary("running", "正在停止");
  try {
    const result = state.task?.runId
      ? await postApi("task/cancel", { runId: state.task.runId })
      : await postApi("cancel", {});
    if (result?.accepted !== true) {
      showAlert(elements.commandError, "当前没有可停止的命令。", "error");
    }
  } catch (error) {
    state.cancelling = false;
    showAlert(elements.commandError, messageForError(error), "error");
    setResultSummary("error", "停止请求失败");
    updateControls();
  }
}

async function startManagedTask(route, params, label) {
  if (state.running || state.mutationBusy || state.checking || state.inspecting) return;
  state.running = true;
  state.cancelling = false;
  state.result = {
    termination: "exit",
    exitCode: null,
    durationMs: 0,
    stdout: normaliseStream(null),
    stderr: normaliseStream(null),
    resultId: null,
    outputExpiresAt: null,
  };
  state.outputPages = createOutputPageState();
  const task = {
    runId: null,
    cursor: null,
    stdout: "",
    stderr: "",
    stdoutBytes: 0,
    stderrBytes: 0,
    droppedBytes: 0,
    label,
  };
  state.task = task;
  clearAlert(elements.commandError);
  setResultSummary("running", `正在启动${label}`);
  renderOutput();
  updateControls();
  try {
    const started = await postApi(route, params);
    if (typeof started?.runId !== "string") {
      throw new ApiError(500, "INVALID_RESPONSE", "网关没有返回任务编号。");
    }
    task.runId = started.runId;
    setResultSummary("running", `${label}运行中 · ${started.runId.slice(0, 10)}`);
    await pollManagedTask(task);
  } catch (error) {
    if (state.task === task) {
      showAlert(elements.commandError, messageForError(error), "error");
      setResultSummary("error", `${label}请求失败`);
    }
  } finally {
    if (state.task === task) {
      state.running = false;
      state.cancelling = false;
      updateControls();
      renderOutput();
    }
  }
}

async function pollManagedTask(task) {
  let failures = 0;
  while (state.task === task && task.runId) {
    try {
      const tailBody = {
        runId: task.runId,
        ...(task.cursor ? { cursor: task.cursor } : {}),
        limit: TASK_TAIL_BYTES,
      };
      const [tail, status] = await Promise.all([
        postApi("task/tail", tailBody),
        postApi("task/status", { runId: task.runId }),
      ]);
      failures = 0;
      task.cursor = typeof tail?.nextCursor === "string" ? tail.nextCursor : task.cursor;
      task.stdout += typeof tail?.stdout?.text === "string" ? tail.stdout.text : "";
      task.stderr += typeof tail?.stderr?.text === "string" ? tail.stderr.text : "";
      task.stdoutBytes = Number.isSafeInteger(tail?.stdout?.totalBytes) ? tail.stdout.totalBytes : task.stdoutBytes;
      task.stderrBytes = Number.isSafeInteger(tail?.stderr?.totalBytes) ? tail.stderr.totalBytes : task.stderrBytes;
      task.droppedBytes = Math.max(
        task.droppedBytes,
        Number(tail?.stdout?.droppedBytes ?? 0) + Number(tail?.stderr?.droppedBytes ?? 0),
      );
      state.result = {
        termination: typeof status?.termination === "string" ? status.termination : "exit",
        exitCode: Number.isInteger(status?.exitCode) ? status.exitCode : null,
        durationMs: Number.isFinite(status?.durationMs) ? status.durationMs : 0,
        stdout: { text: task.stdout, bytes: task.stdoutBytes, inlineTruncated: task.droppedBytes > 0 },
        stderr: { text: task.stderr, bytes: task.stderrBytes, inlineTruncated: task.droppedBytes > 0 },
        resultId: typeof status?.resultId === "string"
          ? status.resultId
          : state.result?.resultId ?? null,
        outputExpiresAt: typeof status?.outputExpiresAt === "string"
          ? status.outputExpiresAt
          : state.result?.outputExpiresAt ?? null,
      };
      state.outputPages.stdout.text = task.stdout;
      state.outputPages.stderr.text = task.stderr;
      renderOutput();
      if (status?.state !== "running" && tail?.eof === true) {
        updateTaskResultSummary(status, task);
        if (status?.error?.message) {
          showAlert(elements.commandError, `${status.error.message}（${status.error.gatewayCode ?? "TASK_FAILED"}）`, "error");
        }
        return;
      }
      if (status?.state === "running") {
        setResultSummary("running", `${task.label}运行中 · ${formatDuration(status?.durationMs)}`);
        await wait(TASK_POLL_INTERVAL_MS);
      }
    } catch (error) {
      failures += 1;
      if (failures >= 3) throw error;
      await wait(TASK_POLL_INTERVAL_MS * failures);
    }
  }
}

function updateTaskResultSummary(status, task) {
  const duration = formatDuration(status?.durationMs);
  if (status?.state === "succeeded") {
    setResultSummary("success", `${task.label}完成 · ${duration}`);
  } else {
    const labels = {
      failed: "任务失败",
      timed_out: "任务超时",
      cancelled: "任务已取消",
    };
    setResultSummary("error", `${labels[status?.state] ?? "任务结束"} · ${duration}`);
  }
  if (task.droppedBytes > 0) {
    elements.retentionNote.textContent = `实时日志已滚动，较早的 ${formatBytes(task.droppedBytes)} 不再保留`;
    elements.retentionNote.hidden = false;
  }
}

function wait(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

function validateTransfer() {
  clearAlert(elements.commandError);
  const alias = state.selectedAlias;
  const target = alias ? state.targets.get(alias) : null;
  if (!alias || !target || state.dirty) return { error: "请先选择并保存机器配置。" };
  if (!target.enabled) return { error: "该机器已停用。" };
  const kind = selectedRadio(elements.transferKindInputs) ?? "upload";
  const allowed = target.transferMode === "bidirectional"
    || (target.transferMode === "upload" && (kind === "upload" || kind === "sync"))
    || (target.transferMode === "download" && kind === "download");
  if (!allowed) return { error: "当前机器未授权该文件操作。" };
  const fullAccess = target.policyMode === "full-access";
  const localRoot = elements.transferLocalRoot.value;
  const localPath = elements.transferLocalPath.value.trim();
  const remotePath = elements.transferRemotePath.value.trim();
  if (!localPath || !remotePath || (!fullAccess && !localRoot)) {
    return { error: "请完整填写本机与远端路径。" };
  }
  if (
    fullAccess &&
    (!ABSOLUTE_LOCAL_PATH_PATTERN.test(localPath) ||
      localPath.startsWith("//") ||
      localPath.startsWith("\\\\"))
  ) {
    return { error: "Full access 模式下请填写本机绝对路径。" };
  }
  const timeoutMs = Number(elements.transferTimeoutMs.value);
  const maximum = target.maxTransferTimeoutMs ?? MAX_TIMEOUT_MS;
  if (!validInteger(timeoutMs, 1, maximum)) {
    return { error: `传输超时必须是 1 至 ${maximum.toLocaleString("zh-CN")} 毫秒的整数。` };
  }
  const checksum = elements.transferChecksum.value.trim().toLowerCase();
  if (checksum && !SHA256_PATTERN.test(checksum)) return { error: "SHA-256 必须是 64 位十六进制文本。" };
  const common = {
    target: alias,
    ...(fullAccess ? {} : { localRoot }),
    localPath,
    remotePath,
    overwrite: elements.transferOverwrite.checked,
    resume: elements.transferResume.checked,
    dryRun: elements.transferDryRun.checked,
    timeoutMs,
  };
  if (kind === "sync") {
    const exclude = elements.transferExcludes.value
      .split(/\r?\n/u)
      .map((value) => value.trim())
      .filter(Boolean);
    if (exclude.length > 128) return { error: "排除规则最多允许 128 条。" };
    if (exclude.some((value) => value.length > 512 || /[\0\r\n]/u.test(value))) {
      return { error: "每条排除规则最多 512 个字符，且不能包含控制换行。" };
    }
    return { kind, params: { ...common, exclude, verifyExisting: elements.verifyExisting.checked } };
  }
  return {
    kind,
    params: {
      ...common,
      ...(checksum ? { expectedSha256: checksum } : {}),
      ...(kind === "upload" ? { verify: "sha256" } : {}),
    },
  };
}

async function runTransfer(event) {
  event.preventDefault();
  if (state.running || state.mutationBusy) return;
  const request = validateTransfer();
  if (request.error) {
    showAlert(elements.commandError, request.error, "error");
    return;
  }
  const labels = { upload: "上传任务", download: "下载任务", sync: "同步任务" };
  await startManagedTask(`transfer/${request.kind}`, request.params, labels[request.kind]);
}

async function inspectTarget() {
  const alias = state.selectedAlias;
  if (!alias || state.dirty || state.running || state.inspecting) return;
  state.inspecting = true;
  clearAlert(elements.commandError);
  clearAlert(elements.targetInfoStatus);
  elements.targetInfoGrid.hidden = true;
  showAlert(elements.targetInfoStatus, "正在读取机器身份...", "progress");
  updateControls();
  try {
    const result = await postApi("inspect", { target: alias });
    if (!result?.connected || !result.machine) {
      showAlert(elements.targetInfoStatus, `目标探针失败，耗时 ${formatDuration(result?.durationMs)}。`, "error");
    } else {
      const machine = result.machine;
      const docker = machine.docker ?? {};
      renderFacts(elements.targetInfoGrid, [
        ["机器 ID", machine.machineId],
        ["SSH 主机密钥", Array.isArray(result.sshHostKeyFingerprints) && result.sshHostKeyFingerprints.length > 0 ? result.sshHostKeyFingerprints.join("\n") : "不可用"],
        ["主机名", machine.hostname],
        ["平台", `${PLATFORM_LABELS[machine.reportedPlatform] ?? machine.reportedPlatform}${machine.platformMatch ? "" : "（与配置不一致）"}`],
        ["系统", [machine.os?.name, machine.os?.version, machine.os?.build].filter(Boolean).join(" ") || "未知"],
        ["内核 / 架构", [machine.os?.kernel, machine.os?.architecture].filter(Boolean).join(" / ") || "未知"],
        ["磁盘", machine.disk ? `${formatBytes(machine.disk.availableBytes)} 可用 / ${formatBytes(machine.disk.totalBytes)}` : "不可用"],
        ["Docker daemon", docker.installed ? (docker.daemonReachable ? "可连接" : "不可连接") : "未安装"],
        ["Docker / Compose", [docker.serverVersion || docker.clientVersion, docker.composeVersion].filter(Boolean).join(" / ") || "不可用"],
      ]);
      const warningText = Array.isArray(result.warnings) && result.warnings.length > 0 ? `，警告：${result.warnings.join("、")}` : "";
      showAlert(elements.targetInfoStatus, `读取成功，耗时 ${formatDuration(result.durationMs)}${warningText}。`, result.warnings?.length ? "progress" : "success");
    }
  } catch (error) {
    showAlert(elements.targetInfoStatus, messageForError(error), "error");
  } finally {
    state.inspecting = false;
    updateControls();
  }
}

async function runDockerPreflight() {
  const alias = state.selectedAlias;
  const target = alias ? state.targets.get(alias) : null;
  if (!alias || !target || state.dirty || state.running || state.inspecting) return;
  if (target.policyMode !== "full-access") {
    showAlert(elements.dockerPreflightStatus, "Docker 预检仅允许用于 Full access 机器。", "error");
    return;
  }
  let request;
  try {
    request = collectDockerPreflight(alias);
  } catch (error) {
    showAlert(elements.dockerPreflightStatus, error.message, "error");
    return;
  }
  state.inspecting = true;
  clearAlert(elements.commandError);
  elements.dockerPreflightGrid.hidden = true;
  showAlert(elements.dockerPreflightStatus, "正在执行 Docker 部署预检...", "progress");
  updateControls();
  try {
    const result = await postApi("docker/preflight", request);
    const context = result.daemon?.context;
    const containers = result.containers;
    const facts = [
      ["总体", result.overall],
      ["操作意图", result.intent ?? request.intent],
      ["Docker daemon", `${result.daemon?.status ?? "unknown"} · ${result.daemon?.serverVersion ?? result.daemon?.clientVersion ?? "--"}`],
      ["Docker context", context ? `${context.name} · ${context.scope}` : "--"],
      ["Compose", `${result.compose?.status ?? "unknown"} · ${result.compose?.config ?? "--"} · ${result.compose?.version ?? "--"}`],
      ["容器", `${containers?.running ?? 0}/${containers?.total ?? 0} 运行 · ${containers?.healthy ?? 0} 健康 · ${containers?.unhealthy ?? 0} 不健康`],
      ["容器筛选", containers?.filter ?? "未指定 Compose 项目名"],
      ["磁盘", result.disk ? `${result.disk.status} · ${formatBytes(result.disk.availableBytes)} 可用` : "未检查"],
      ["端口", Array.isArray(result.ports) && result.ports.length > 0 ? result.ports.map((port) => `${port.protocol}:${port.port} · ${port.observation} · ${port.ownership ?? "unknown"}`).join("\n") : "未检查"],
      ["警告", Array.isArray(result.warnings) && result.warnings.length > 0 ? result.warnings.join("\n") : "无"],
    ];
    renderFacts(elements.dockerPreflightGrid, facts);
    const kind = result.overall === "ready" ? "success" : result.overall === "blocked" ? "error" : "progress";
    showAlert(elements.dockerPreflightStatus, `预检结果：${result.overall}，耗时 ${formatDuration(result.durationMs)}。`, kind);
  } catch (error) {
    showAlert(elements.dockerPreflightStatus, messageForError(error), "error");
  } finally {
    state.inspecting = false;
    updateControls();
  }
}

function collectDockerPreflight(alias) {
  const intent = selectedRadio(elements.dockerIntentInputs) ?? "update";
  const directory = elements.dockerProjectDirectory.value.trim();
  const composeFiles = elements.dockerComposeFiles.value.split(/\r?\n/u).map((value) => value.trim()).filter(Boolean);
  const name = elements.dockerProjectName.value.trim();
  if ((composeFiles.length > 0 || name) && !directory) throw new Error("填写 Compose 文件或项目名时必须指定项目目录。");
  if (composeFiles.length > 8) throw new Error("Compose 文件最多允许 8 个。");
  if (name && !DOCKER_PROJECT_PATTERN.test(name)) throw new Error("Docker 项目名格式不正确。");
  const ports = elements.dockerPorts.value.split(/\r?\n/u).map((value) => value.trim()).filter(Boolean).map((value) => {
    const match = /^(tcp|udp):(\d{1,5})$/u.exec(value.toLowerCase());
    const port = Number(match?.[2]);
    if (!match || !validInteger(port, 1, 65_535)) throw new Error(`端口格式不正确：${value}`);
    return { protocol: match[1], port };
  });
  if (ports.length > 64) throw new Error("检查端口最多允许 64 个。");
  const requiredFreeMb = Number(elements.dockerRequiredFreeMb.value || 0);
  if (!Number.isSafeInteger(requiredFreeMb) || requiredFreeMb < 0 || requiredFreeMb > Math.floor(Number.MAX_SAFE_INTEGER / 1_048_576)) {
    throw new Error("最低可用空间必须是非负整数。");
  }
  return {
    target: alias,
    intent,
    ...(directory ? { project: { directory, composeFiles, ...(name ? { name } : {}) } } : {}),
    ports,
    ...(requiredFreeMb > 0 ? { requiredFreeBytes: requiredFreeMb * 1_048_576 } : {}),
  };
}

function renderFacts(container, facts) {
  const nodes = [];
  for (const [label, rawValue] of facts) {
    const item = document.createElement("div");
    item.className = "fact-item";
    const term = document.createElement("dt");
    term.textContent = label;
    const detail = document.createElement("dd");
    detail.textContent = String(rawValue ?? "--");
    item.append(term, detail);
    nodes.push(item);
  }
  container.replaceChildren(...nodes);
  container.hidden = false;
}

function normaliseResult(value) {
  return {
    termination: typeof value?.termination === "string" ? value.termination : "spawn_error",
    exitCode: Number.isInteger(value?.exitCode) ? value.exitCode : null,
    durationMs: Number.isFinite(value?.durationMs) ? Math.max(0, value.durationMs) : 0,
    stdout: normaliseStream(value?.stdout),
    stderr: normaliseStream(value?.stderr),
    resultId: typeof value?.resultId === "string" ? value.resultId : null,
    outputExpiresAt: typeof value?.outputExpiresAt === "string" ? value.outputExpiresAt : null,
  };
}

function normaliseStream(value) {
  return {
    text: typeof value?.text === "string" ? value.text : "",
    bytes: Number.isSafeInteger(value?.bytes) && value.bytes >= 0 ? value.bytes : 0,
    inlineTruncated: value?.inlineTruncated === true,
  };
}

function updateResultSummary(result) {
  const duration = formatDuration(result.durationMs);
  if (result.termination === "exit" && result.exitCode === 0) {
    setResultSummary("success", `成功 · 退出码 0 · ${duration}`);
  } else if (result.termination === "exit") {
    setResultSummary("error", `执行结束 · 退出码 ${result.exitCode ?? "--"} · ${duration}`);
  } else {
    const labels = { timeout: "已超时", cancel: "已取消", output_limit: "输出超限", spawn_error: "启动失败" };
    setResultSummary("error", `${labels[result.termination] ?? "执行失败"} · ${duration}`);
  }
}

function setResultSummary(kind, text) {
  elements.resultSummary.className = `result-summary is-${kind}`;
  elements.resultSummaryText.textContent = text;
}

function selectOutputStream(stream, moveFocus = false) {
  if (stream !== "stdout" && stream !== "stderr") {
    return;
  }
  state.activeStream = stream;
  for (const tab of [elements.stdoutTab, elements.stderrTab]) {
    const selected = tab.dataset.stream === stream;
    tab.classList.toggle("is-active", selected);
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
    if (selected && moveFocus) {
      tab.focus();
    }
  }
  renderOutput();
}

function handleOutputTabKeydown(event) {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
    return;
  }
  event.preventDefault();
  selectOutputStream(state.activeStream === "stdout" ? "stderr" : "stdout", true);
}

function renderOutput() {
  elements.stdoutCount.textContent = formatBytes(state.result?.stdout.bytes ?? 0);
  elements.stderrCount.textContent = formatBytes(state.result?.stderr.bytes ?? 0);
  const page = state.outputPages[state.activeStream];
  let text = "";
  let placeholder = false;
  if (state.running && state.task) {
    text = state.result?.[state.activeStream]?.text ?? "";
    if (!text) {
      text = "正在等待远端输出...";
      placeholder = true;
    }
  } else if (state.running) {
    text = "正在等待远端输出...";
    placeholder = true;
  } else if (!state.result) {
    text = "执行结果会显示在这里。";
    placeholder = true;
  } else if (page.loading) {
    text = "正在读取完整输出...";
    placeholder = true;
  } else {
    text = page.mode === "full" ? page.text : state.result[state.activeStream].text;
  }
  if (!placeholder && !text) {
    text = state.activeStream === "stdout" ? "（没有标准输出）" : "（没有错误输出）";
    placeholder = true;
  }
  elements.outputView.textContent = text;
  elements.outputView.classList.toggle("is-placeholder", placeholder);
  elements.outputView.classList.toggle("is-wrapped", state.wrapped);
  elements.copyOutputButton.disabled = !state.result || page.loading;
  renderOutputFooter(page);
}

function renderOutputFooter(page) {
  const result = state.result;
  if (!result?.resultId) {
    if (state.task?.droppedBytes > 0) {
      elements.retentionNote.textContent = `实时日志已滚动，较早的 ${formatBytes(state.task.droppedBytes)} 不再保留`;
      elements.retentionNote.hidden = false;
    } else {
      elements.retentionNote.hidden = true;
    }
    elements.fullOutputButton.hidden = true;
    elements.pagination.hidden = true;
    return;
  }
  const expires = formatClockTime(result.outputExpiresAt);
  elements.retentionNote.textContent = expires ? `完整输出保留至 ${expires}` : "完整输出已临时保留";
  elements.retentionNote.hidden = false;
  if (page.mode !== "full") {
    elements.fullOutputButton.hidden = false;
    elements.fullOutputButton.disabled = page.loading;
    elements.pagination.hidden = true;
    return;
  }
  elements.fullOutputButton.hidden = true;
  elements.pagination.hidden = false;
  const start = page.offsets[page.index] ?? 0;
  const end = page.chunk?.nextOffset ?? start + base64ByteLength(page.chunk?.dataBase64 ?? "");
  const total = page.chunk?.totalBytes ?? 0;
  elements.pageLabel.textContent = `第 ${page.index + 1} 段 · ${formatBytes(start)}–${formatBytes(end)} / ${formatBytes(total)}`;
  elements.previousPage.disabled = page.loading || page.index === 0;
  elements.nextPage.disabled = page.loading || !page.chunk || page.chunk.eof || page.chunk.nextOffset === null;
}

async function loadFullOutput(offset, index) {
  const result = state.result;
  const stream = state.activeStream;
  const page = state.outputPages[stream];
  if (!result?.resultId || page.loading) {
    return;
  }
  page.loading = true;
  renderOutput();
  try {
    const chunk = await postApi("output", { resultId: result.resultId, stream, offset, limit: OUTPUT_PAGE_BYTES });
    if (state.result !== result || state.activeStream !== stream) {
      return;
    }
    page.mode = "full";
    page.chunk = chunk;
    page.index = index;
    page.text = decodeBase64Text(chunk.dataBase64);
  } catch (error) {
    if (error instanceof ApiError && (error.status === 410 || error.code === "OUTPUT_UNAVAILABLE")) {
      result.resultId = null;
      showAlert(elements.commandError, "完整输出已过期，请重新执行命令。", "error");
    } else {
      showAlert(elements.commandError, messageForError(error), "error");
    }
  } finally {
    page.loading = false;
    renderOutput();
  }
}

function nextOutputPage() {
  const page = state.outputPages[state.activeStream];
  if (page.chunk?.nextOffset === null || page.chunk?.nextOffset === undefined) {
    return;
  }
  const nextIndex = page.index + 1;
  page.offsets[nextIndex] = page.chunk.nextOffset;
  page.offsets.length = nextIndex + 1;
  void loadFullOutput(page.chunk.nextOffset, nextIndex);
}

function previousOutputPage() {
  const page = state.outputPages[state.activeStream];
  if (page.index > 0) {
    const previousIndex = page.index - 1;
    void loadFullOutput(page.offsets[previousIndex], previousIndex);
  }
}

function decodeBase64Text(value) {
  if (typeof value !== "string" || !value) {
    return "";
  }
  const binary = window.atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

function base64ByteLength(value) {
  if (!value) {
    return 0;
  }
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  return Math.max(0, Math.floor(value.length * 3 / 4) - padding);
}

async function copyPublicKey() {
  await copyWithFeedback(elements.publicKeyOutput.textContent, elements.copyPublicKeyButton, "公钥已复制");
}

async function copySshInstallCommand() {
  await copyWithFeedback(
    elements.sshInstallCommand.textContent,
    elements.copySshInstallCommandButton,
    "公钥安装命令已复制",
  );
}

async function launchSshInstall() {
  if (
    state.mutationBusy ||
    state.keyMutationBusy ||
    state.tailscaleMutationBusy ||
    state.accessClientMutationBusy ||
    state.checking ||
    state.inspecting ||
    state.running ||
    !elements.sshInstallCommand.textContent
  ) return;
  clearFormMessages();
  const form = collectForm({ requireFullConfirmation: false });
  if (form.error || form.target.connectionMode !== "openssh") return;
  elements.launchSshInstallButton.disabled = true;
  showAlert(
    elements.formStatus,
    "正在打开终端，请在终端中输入远端账号密码；密码不会保存到网关。",
    "progress",
  );
  try {
    await postApi("admin/ssh/install", { target: form.target });
    showAlert(
      elements.formStatus,
      "终端已打开。公钥安装完成后，回到这里保存配置并检测连接。",
      "success",
    );
    showToast("SSH 公钥安装终端已打开");
  } catch (error) {
    showAlert(elements.formError, messageForError(error), "error");
  } finally {
    updateControls();
  }
}

async function copyOutput() {
  const page = state.outputPages[state.activeStream];
  const text = page.mode === "full" ? page.text : state.result?.[state.activeStream]?.text ?? "";
  await copyWithFeedback(text, elements.copyOutputButton, "输出已复制");
}

async function copyWithFeedback(text, button, toastText) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const input = document.createElement("textarea");
      input.value = text;
      input.setAttribute("readonly", "");
      input.className = "sr-only";
      document.body.append(input);
      input.select();
      const copied = document.execCommand("copy");
      input.remove();
      if (!copied) {
        throw new Error("Copy failed");
      }
    }
    const oldText = button.textContent;
    button.textContent = "已复制";
    showToast(toastText);
    window.setTimeout(() => { button.textContent = oldText; }, 1_500);
  } catch {
    showToast("复制失败，请手动选择内容", "error");
  }
}

function updateControls() {
  const blocked = state.refreshing || state.mutationBusy || state.keyMutationBusy || state.tailscaleMutationBusy || state.accessClientMutationBusy || state.accessClientPreparationBusy || state.checking || state.inspecting;
  const inventoryBlocked = !state.inventoryAvailable;
  const selectedTarget = state.selectedAlias ? state.targets.get(state.selectedAlias) : null;
  const accessClientDraft = selectedRadio(elements.connectionModeInputs) === "accessclient-share";
  const tailscaleDraft = selectedRadio(elements.connectionModeInputs) === "tailscale-ssh";
  const externalIdentity = accessClientDraft || tailscaleDraft;
  const preparationActive = accessClientPreparationIsActive();
  elements.refreshButton.disabled = blocked || state.running;
  elements.newMachineButton.disabled = blocked || state.running || inventoryBlocked || preparationActive;
  elements.machineForm.querySelectorAll("input, textarea, select, button").forEach((control) => {
    control.disabled = blocked || state.running || inventoryBlocked || preparationActive;
  });
  for (const item of elements.machineList.querySelectorAll("button")) {
    item.disabled = blocked || state.running;
  }
  elements.deleteButton.hidden = !state.originalAlias;
  elements.deleteButton.disabled = blocked || state.running || inventoryBlocked || preparationActive;
  elements.checkButton.disabled = blocked || state.checking || state.running || inventoryBlocked || !state.originalAlias || state.dirty || preparationActive;
  elements.checkButton.textContent = state.checking ? "正在检测..." : "检测连接";
  elements.prepareAccessClientButton.hidden = true;
  elements.prepareAccessClientButton.disabled = blocked
    || state.running
    || inventoryBlocked
    || !state.originalAlias
    || state.dirty
    || !accessClientDraft
    || !state.accessClientSettings.plinkExecutable
    || preparationActive;
  elements.prepareAccessClientButton.textContent = state.accessClientPreparationBusy
    ? "正在准备..."
    : "准备会话";
  elements.cancelAccessClientPrepareButton.disabled = state.accessClientPreparationBusy;
  const selectedKeysAvailable = externalIdentity || state.keys.has(elements.targetKeyId.value);
  elements.saveButton.disabled = blocked || state.running || inventoryBlocked || preparationActive
    || (!externalIdentity && !state.keysAvailable)
    || !selectedKeysAvailable;
  elements.saveButton.textContent = state.mutationBusy ? "正在处理..." : "保存配置";
  elements.actionHint.textContent = inventoryBlocked
    ? "配置暂不可用，请刷新管理中心。"
    : state.mutationBusy ? "正在保存配置，请稍候…"
    : state.checking ? "正在检测连接，请稍候…"
    : preparationActive ? "正在准备 AccessClient 会话，请按上方提示操作。"
    : state.running ? "任务运行中，结束后可修改配置。"
    : !externalIdentity && !state.keysAvailable ? "私钥库不可用，请在全局设置中检查。"
    : !selectedKeysAvailable ? "请先在全局设置中添加并选择私钥。"
    : !state.originalAlias ? "配置填写完成后保存，再检测连接。"
    : state.dirty ? "有未保存的修改 · 保存后可检测连接。"
    : "配置已保存，可以检测连接或执行命令。";
  elements.checkButton.title = !state.originalAlias || state.dirty ? "请先保存机器配置，再检测连接" : "检测这台机器的 SSH 连接";
  elements.commandTab.title = !state.selectedAlias ? "保存机器后可执行命令" : "执行命令、传输文件与检查机器";
  const keyBlocked = blocked || state.running || preparationActive || !state.keysAvailable || !state.keyRevision;
  elements.generateKeyButton.disabled = keyBlocked;
  elements.importKeyButton.disabled = keyBlocked;
  for (const control of elements.keyEditorForm.querySelectorAll("input, select, button")) control.disabled = keyBlocked;
  elements.cancelKeyEditorButton.disabled = state.keyMutationBusy;
  for (const control of elements.keyList.querySelectorAll("button")) {
    control.disabled = (control.dataset.mutation === "true" && keyBlocked)
      || control.dataset.inUse === "true"
      || control.dataset.unavailable === "true";
  }
  elements.copyPublicKeyButton.disabled = !elements.publicKeyOutput.textContent;
  elements.launchSshInstallButton.disabled = blocked
    || state.running
    || inventoryBlocked
    || preparationActive
    || !elements.sshInstallCommand.textContent;
  elements.copySshInstallCommandButton.disabled = blocked
    || state.running
    || inventoryBlocked
    || preparationActive
    || !elements.sshInstallCommand.textContent;
  elements.commandTab.disabled = !state.selectedAlias;
  const operationBlocked = state.running || blocked || preparationActive || inventoryBlocked || state.dirty || !selectedTarget || !selectedTarget.enabled;
  elements.runButton.disabled = operationBlocked || selectedTarget?.policyMode === "deny";
  elements.cancelButton.hidden = !state.running || state.activeOperation !== "exec";
  elements.cancelButton.disabled = state.cancelling;
  for (const control of [
    elements.commandInput,
    elements.scriptInput,
    elements.workingDirectory,
    elements.environmentInput,
    elements.backgroundTask,
    elements.runTimeoutMs,
  ]) control.disabled = operationBlocked;
  for (const input of elements.executionFormatInputs) {
    input.disabled = operationBlocked || (input.value === "structured" && selectedTarget?.policyMode !== "full-access");
  }
  const supportedShells = selectedTarget?.platform === "windows"
    ? new Set(["powershell", "cmd"])
    : new Set(["bash"]);
  for (const input of elements.remoteShellInputs) {
    input.disabled = operationBlocked || !supportedShells.has(input.value);
  }
  for (const input of elements.transferInputs) {
    if (externalIdentity) input.disabled = true;
  }

  const windowsPlatform = elements.platformInputs.find((input) => input.value === "windows");
  if (tailscaleDraft && windowsPlatform) windowsPlatform.disabled = true;
  elements.tailscaleExecutable.disabled = blocked || state.running || inventoryBlocked || preparationActive;
  elements.saveTailscaleSettingsButton.disabled = elements.tailscaleExecutable.disabled || !state.tailscaleSettingsDirty;
  elements.saveTailscaleSettingsButton.textContent = state.tailscaleMutationBusy ? "正在保存..." : "保存 Tailscale 路径";
  const accessClientSettingsBlocked = blocked || state.running || inventoryBlocked || preparationActive;
  elements.plinkExecutable.disabled = accessClientSettingsBlocked;
  elements.saveAccessClientSettingsButton.disabled = accessClientSettingsBlocked || !state.accessClientSettingsDirty;
  elements.saveAccessClientSettingsButton.textContent = state.accessClientMutationBusy
    ? "正在保存..."
    : "保存 Plink 路径";

  for (const control of elements.transferForm.querySelectorAll("input, textarea, select, button")) {
    control.disabled = operationBlocked;
  }
  const transferMode = selectedTarget?.transferMode ?? "deny";
  const fullFileAccess = selectedTarget?.policyMode === "full-access";
  const gatewayTarget = state.selectedAlias ? state.gatewayTargets.get(state.selectedAlias) : null;
  const gatewayTransferRoots = Array.isArray(gatewayTarget?.transferRoots) ? gatewayTarget.transferRoots : [];
  const transferReady = transferMode !== "deny"
    && (fullFileAccess || !state.gatewayTargets.has(state.selectedAlias) || gatewayTransferRoots.length > 0);
  const transferAllowed = (kind) => transferMode === "bidirectional"
    || (transferMode === "upload" && (kind === "upload" || kind === "sync"))
    || (transferMode === "download" && kind === "download");
  for (const input of elements.transferKindInputs) {
    input.disabled = operationBlocked || !transferAllowed(input.value);
  }
  elements.transferRunButton.disabled = operationBlocked || !transferReady;
  elements.transferCancelButton.hidden = !state.running || state.activeOperation !== "transfer";
  elements.transferCancelButton.disabled = state.cancelling;
  elements.transferOverwrite.disabled = operationBlocked || selectedRadio(elements.transferKindInputs) === "sync";

  const hasTarget = Boolean(selectedTarget);
  for (const tab of elements.operationTabs) {
    const unavailableTransfer = tab.dataset.operation === "transfer" && !transferReady;
    tab.disabled = !hasTarget || state.running || blocked || unavailableTransfer;
  }
  elements.inspectTargetButton.disabled = operationBlocked;
  elements.dockerPreflightButton.disabled = operationBlocked || selectedTarget?.policyMode !== "full-access";
}

function confirmDiscardChanges() {
  return window.confirm("当前机器有未保存修改，确定放弃吗？");
}

function selectedRadio(inputs) {
  return inputs.find((input) => input.checked)?.value ?? null;
}

function validInteger(value, minimum, maximum) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function validSshUsername(value) {
  if (STANDARD_USERNAME_PATTERN.test(value)) return true;
  if (value.length > 128) return false;
  const segments = value.split("/");
  return segments.length === 3
    && PASSTHROUGH_ACCOUNT_PATTERN.test(segments[0])
    && validIpv4Address(segments[1])
    && PASSTHROUGH_ACCOUNT_PATTERN.test(segments[2]);
}

function validIpv4Address(value) {
  const octets = value.split(".");
  return octets.length === 4 && octets.every((octet) =>
    /^(?:0|[1-9][0-9]{0,2})$/u.test(octet) && Number(octet) <= 255);
}

function policyClass(mode) {
  if (mode === "full-access") {
    return "is-full";
  }
  if (mode === "deny") {
    return "is-deny";
  }
  return "is-allow";
}

function showAlert(element, message, kind) {
  element.textContent = message;
  element.className = `inline-alert is-${kind}`;
  element.hidden = false;
}

function clearAlert(element) {
  element.textContent = "";
  element.hidden = true;
}

function clearFormMessages() {
  clearAlert(elements.formError);
  clearAlert(elements.formStatus);
}

function showToast(message, kind = "success") {
  const toast = document.createElement("div");
  toast.className = `toast is-${kind}`;
  toast.textContent = message;
  elements.toastRegion.replaceChildren(toast);
  window.setTimeout(() => {
    if (toast.parentNode === elements.toastRegion) {
      toast.remove();
    }
  }, 3_000);
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }
  if (bytes < 1_024) {
    return `${bytes} B`;
  }
  if (bytes < 1_048_576) {
    return `${(bytes / 1_024).toFixed(1)} KB`;
  }
  return `${(bytes / 1_048_576).toFixed(1)} MB`;
}

function formatDuration(durationMs) {
  if (!Number.isFinite(durationMs)) {
    return "--";
  }
  return durationMs < 1_000 ? `${Math.max(0, Math.round(durationMs))} ms` : `${(durationMs / 1_000).toFixed(2)} s`;
}

function formatClockTime(value) {
  if (typeof value !== "string") {
    return "";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" });
}

function messageForError(error) {
  if (!(error instanceof ApiError)) {
    return "请求失败，请检查本机管理服务。";
  }
  const messages = {
    INVALID_SESSION: "此浏览器尚未授权或授权已过期。请通过本机管理入口（ssh_open_admin）或服务输出的完整管理链接授权一次；之后直接打开固定地址即可。机器配置仍保存在本机。",
    INVALID_REQUEST: "请求参数无效，请检查填写内容。",
    CONFIG_BUSY: "网关正在执行命令或处理其他配置，请稍后重试。",
    CONFIG_INVALID: "网关配置无效，请检查机器、连接方式和凭据设置。",
    CONFIG_CONFLICT: "配置已被其他窗口更新，请刷新后重新提交。",
    REVISION_CONFLICT: "配置版本已变化，请刷新后重新提交。",
    CAPABILITY_UNAVAILABLE: "当前网关不支持此操作。",
    DAEMON_NOT_ACTIVE: "SSH 网关后台未运行，请先启动服务。",
    KEY_REVISION_CONFLICT: "私钥列表已被其他窗口更新，请刷新后重试。",
    KEY_NOT_FOUND: "所选私钥已不存在，请刷新后重新选择。",
    KEY_IN_USE: "该私钥仍被机器配置引用，不能删除。",
    KEY_ALREADY_EXISTS: "相同私钥已经存在。",
    KEY_NAME_EXISTS: "已有同名私钥，请使用其他名称。",
    KEY_LABEL_EXISTS: "已有同名私钥，请使用其他名称。",
    KEY_INVALID: "无法读取该私钥，请检查文件格式和权限。",
    KEY_STORAGE_INVALID: "私钥存储已损坏，机器配置仍保留，但私钥管理已转为只读。",
    KEY_STORAGE_UNAVAILABLE: "私钥存储当前不可用，请检查本机管理服务。",
    RUN_ACTIVE: "已有命令正在执行，请等待或先停止。",
    TARGET_NOT_FOUND: "机器不在当前网关配置中，请刷新后重试。",
    TARGET_DISABLED: "该机器已停用。",
    COMMAND_DENIED: "命令被当前权限策略拒绝。",
    PROBE_FAILED: "连接探测失败，请确认 AccessClient 已登录目标会话，并核对网关和预期主机名。",
    ACCESSCLIENT_NOT_AVAILABLE: "AccessClient 共享会话不可用，请先在 AccessClient 中登录配置的目标。",
    ACCESSCLIENT_HOST_MISMATCH: "AccessClient 当前连接的主机与配置不一致，请切换到预期目标后重试。",
    ACCESSCLIENT_PREPARATION_UNSUPPORTED: "当前系统不支持自动准备 AccessClient 会话。",
    ACCESSCLIENT_PREPARATION_BUSY: "已有一台机器正在准备 AccessClient 会话，请完成或取消后重试。",
    ACCESSCLIENT_PREPARATION_FAILED: "AccessClient 会话准备失败，未读取任何登录凭据。",
    ACCESSCLIENT_RECOVERY_FAILED: "上次 AccessClient 准备未能安全恢复，请重启管理服务后再试。",
    ACCESSCLIENT_SHARING_HOST_REQUIRED: "这台旧配置尚未保存共享会话标识，请先保存机器配置完成迁移。",
    PLINK_NOT_FOUND: "找不到 Plink 程序，请在全局设置中检查 plink.exe 路径。",
    PLINK_INVALID: "Plink 程序无法启动，请确认路径指向可执行的 plink.exe。",
    SSH_HOST_KEY_MISMATCH: "主机指纹与 known_hosts 不一致，连接已拒绝。",
    INTERNAL_ERROR: "网关内部错误，请查看服务输出或重启 SSH 网关后重试。",
  };
  if (messages[error.code]) return messages[error.code];
  if (typeof error.code === "string" && error.code.startsWith("KEY_STORAGE_")) {
    return "私钥存储当前不可用，机器配置仍保留，请检查本机管理服务。";
  }
  return `${error.message}${error.code ? `（${error.code}）` : ""}`;
}

elements.refreshButton.addEventListener("click", () => {
  if ((!state.dirty && !state.accessClientSettingsDirty && !state.tailscaleSettingsDirty) || confirmDiscardChanges()) {
    void refreshApplication();
  }
});
elements.machineSearch.addEventListener("input", () => {
  if (state.inventoryAvailable) {
    renderInventory();
    updateControls();
  }
});
elements.machineSearch.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    elements.machineSearch.value = "";
    if (state.inventoryAvailable) {
      renderInventory();
      updateControls();
    }
  }
});
elements.newMachineButton.addEventListener("click", () => startNewMachine());
elements.machineForm.addEventListener("input", handleFormChange);
elements.machineForm.addEventListener("change", handleFormChange);
elements.machineForm.addEventListener("submit", saveMachine);
elements.deleteButton.addEventListener("click", removeMachine);
elements.generateKeyButton.addEventListener("click", () => openKeyEditor("generate"));
elements.importKeyButton.addEventListener("click", () => openKeyEditor("import"));
elements.keyEditorForm.addEventListener("submit", submitKeyEditor);
elements.cancelKeyEditorButton.addEventListener("click", closeKeyEditor);
elements.copyPublicKeyButton.addEventListener("click", copyPublicKey);
elements.launchSshInstallButton.addEventListener("click", launchSshInstall);
elements.copySshInstallCommandButton.addEventListener("click", copySshInstallCommand);
elements.tailscaleSettingsForm.addEventListener("input", handleTailscaleSettingsInput);
elements.tailscaleSettingsForm.addEventListener("submit", saveTailscaleSettings);
elements.accessClientSettingsForm.addEventListener("input", handleAccessClientSettingsInput);
elements.accessClientSettingsForm.addEventListener("submit", saveAccessClientSettings);
elements.targetManageKeysButton.addEventListener("click", () => setActiveView("settings"));
elements.prepareAccessClientButton.addEventListener("click", prepareAccessClientSession);
elements.cancelAccessClientPrepareButton.addEventListener("click", cancelAccessClientPreparation);
elements.checkButton.addEventListener("click", checkConnection);
elements.configTab.addEventListener("click", () => setActiveView("config"));
elements.commandTab.addEventListener("click", () => setActiveView("command"));
elements.settingsTab.addEventListener("click", () => setActiveView("settings"));
elements.configTab.addEventListener("keydown", handleWorkspaceTabKeydown);
elements.commandTab.addEventListener("keydown", handleWorkspaceTabKeydown);
elements.settingsTab.addEventListener("keydown", handleWorkspaceTabKeydown);
for (const tab of elements.operationTabs) {
  tab.addEventListener("click", () => setActiveOperation(tab.dataset.operation));
  tab.addEventListener("keydown", handleOperationTabKeydown);
}
for (const input of elements.executionFormatInputs) {
  input.addEventListener("change", () => {
    renderExecutionFormat();
    clearAlert(elements.commandError);
  });
}
for (const input of elements.transferKindInputs) {
  input.addEventListener("change", () => {
    renderTransferOperation();
    updateControls();
    clearAlert(elements.commandError);
  });
}
elements.commandForm.addEventListener("submit", runCommand);
elements.cancelButton.addEventListener("click", cancelCommand);
elements.transferForm.addEventListener("submit", runTransfer);
elements.transferCancelButton.addEventListener("click", cancelCommand);
elements.inspectTargetButton.addEventListener("click", inspectTarget);
elements.dockerPreflightButton.addEventListener("click", runDockerPreflight);
elements.stdoutTab.addEventListener("click", () => selectOutputStream("stdout"));
elements.stderrTab.addEventListener("click", () => selectOutputStream("stderr"));
elements.stdoutTab.addEventListener("keydown", handleOutputTabKeydown);
elements.stderrTab.addEventListener("keydown", handleOutputTabKeydown);
elements.wrapButton.addEventListener("click", () => {
  state.wrapped = !state.wrapped;
  elements.wrapButton.setAttribute("aria-pressed", String(state.wrapped));
  elements.wrapButton.classList.toggle("is-pressed", state.wrapped);
  renderOutput();
});
elements.copyOutputButton.addEventListener("click", copyOutput);
elements.fullOutputButton.addEventListener("click", () => {
  state.outputPages[state.activeStream].offsets = [0];
  void loadFullOutput(0, 0);
});
elements.previousPage.addEventListener("click", previousOutputPage);
elements.nextPage.addEventListener("click", nextOutputPage);

void refreshApplication();
