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
const COLLAPSED_GROUPS_STORAGE_KEY = "agent-ssh-collapsed-groups";
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
  presets: "预设命令组",
  "allow-list": "白名单",
  "full-access": "完全访问",
  deny: "禁止访问",
});
const PERMISSION_PRESET_LABELS = Object.freeze({
  "basic-inspection": "基础巡检", "log-inspection": "日志排查", "docker-readonly": "Docker 只读巡检", "docker-protection": "Docker 保护",
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

function readCollapsedGroups() {
  try {
    const names = JSON.parse(window.sessionStorage.getItem(COLLAPSED_GROUPS_STORAGE_KEY) ?? "[]");
    return new Set(Array.isArray(names) ? names.slice(0, 1024).filter((name) => typeof name === "string" && name.length <= 64) : []);
  } catch {
    return new Set();
  }
}

function persistCollapsedGroups() {
  try {
    window.sessionStorage.setItem(COLLAPSED_GROUPS_STORAGE_KEY, JSON.stringify([...state.collapsedGroups].slice(0, 1024)));
  } catch {
    // Directory navigation remains available if browser storage is disabled.
  }
}

const elements = {
  gatewayDot: document.querySelector("#gateway-dot"),
  gatewayLabel: document.querySelector("#gateway-label"),
  gatewayDetail: document.querySelector("#gateway-detail"),
  refreshButton: document.querySelector("#refresh-button"),
  machineCount: document.querySelector("#machine-count"),
  machineSearch: document.querySelector("#machine-search"),
  machineGroupFilter: document.querySelector("#machine-group-filter"),
  newGroupButton: document.querySelector("#new-group-button"),
  groupDialog: document.querySelector("#group-dialog"),
  groupDialogForm: document.querySelector("#group-dialog-form"),
  groupDialogTitle: document.querySelector("#group-dialog-title"),
  groupDialogDescription: document.querySelector("#group-dialog-description"),
  groupNameField: document.querySelector("#group-name-field"),
  groupName: document.querySelector("#group-name"),
  groupDestinationField: document.querySelector("#group-destination-field"),
  groupDestination: document.querySelector("#group-destination"),
  groupDialogError: document.querySelector("#group-dialog-error"),
  groupDialogStatus: document.querySelector("#group-dialog-status"),
  groupManageActions: document.querySelector("#group-manage-actions"),
  groupUpButton: document.querySelector("#group-up-button"),
  groupDownButton: document.querySelector("#group-down-button"),
  groupDeleteButton: document.querySelector("#group-delete-button"),
  groupCancelButton: document.querySelector("#group-cancel-button"),
  groupSubmitButton: document.querySelector("#group-submit-button"),
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
  targetGroup: document.querySelector("#target-group"),
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
  presetInputs: [...document.querySelectorAll('input[name="permission-preset"]')],
  presetFields: document.querySelector("#preset-fields"),
  presetLogFields: document.querySelector("#preset-log-fields"),
  presetLogPaths: document.querySelector("#preset-log-paths"),
  presetLogServices: document.querySelector("#preset-log-services"),
  presetEffective: document.querySelector("#preset-effective"),
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
  collapsedGroups: readCollapsedGroups(),
  groupEditor: null,
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
  elements.gatewayDetail.hidden = kind === "online";
  elements.gatewayLabel.title = detail;
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
    ...(typeof value.group === "string" && value.group.trim() ? { group: value.group.trim() } : {}),
    enabled: value.enabled === true,
    connectionMode,
    target: targetEndpoint,
    ...(connectionMode === "openssh"
      ? { knownHostsFile: typeof value.knownHostsFile === "string" ? value.knownHostsFile : "" }
      : connectionMode === "accessclient-share" ? { accessClient } : {}),
    ...(bastionEndpoint ? { bastion: bastionEndpoint } : {}),
    platform,
    policyMode,
    ...(policyMode === "presets" ? {
      permissionPresets: Array.isArray(value.permissionPresets) ? value.permissionPresets.filter((id) => typeof id === "string") : [],
      logPaths: Array.isArray(value.logPaths) ? value.logPaths.filter((item) => typeof item === "string") : [],
      logServices: Array.isArray(value.logServices) ? value.logServices.filter((item) => typeof item === "string") : [],
    } : {}),
    allowedCommands: Array.isArray(value.allowedCommands)
      ? value.allowedCommands.filter((command) => typeof command === "string")
      : [],
    maxTimeoutMs: validInteger(value.maxTimeoutMs, 1, MAX_TIMEOUT_MS) ? value.maxTimeoutMs : 30_000,
    transferMode: connectionMode === "tailscale-ssh" ? "deny" : policyMode === "full-access"
        ? "bidirectional"
      : policyMode === "deny" || policyMode === "presets"
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

function inventoryGroups() {
  const configured = Array.isArray(state.fleetStatus?.profile?.groups) ? state.fleetStatus.profile.groups : [];
  return [...new Set([...configured, ...[...state.targets.values()].map((target) => target.group)]
    .filter((group) => typeof group === "string" && group.trim()))];
}

function fillGroupOptions(select, selected = "") {
  select.replaceChildren();
  for (const group of ["", ...inventoryGroups()]) {
    const option = document.createElement("option");
    option.value = group;
    option.textContent = group || "默认分组";
    select.append(option);
  }
  select.value = selected;
}

function renderInventory(options = {}) {
  elements.machineList.replaceChildren();
  const targets = sortedTargets();
  elements.machineCount.textContent = String(targets.length);
  elements.inventoryEmpty.hidden = true;
  elements.machineList.hidden = false;
  const query = elements.machineSearch.value.trim().toLocaleLowerCase();
  const groups = inventoryGroups();
  const selectedGroup = options.groupFilter ?? elements.machineGroupFilter.value;
  elements.machineGroupFilter.replaceChildren();
  for (const [value, label] of [["", "全部分组"], ["ungrouped", "默认分组"], ...groups.map((group) => [`group:${group}`, group])]) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    elements.machineGroupFilter.append(option);
  }
  elements.machineGroupFilter.value = selectedGroup === "ungrouped" || groups.some((group) => `group:${group}` === selectedGroup) ? selectedGroup : "";
  fillGroupOptions(elements.targetGroup, elements.targetGroup.value);
  const filter = elements.machineGroupFilter.value;
  const matches = targets.filter(([alias, target]) =>
    (!filter || (filter === "ungrouped" ? !target.group : `group:${target.group}` === filter)) &&
    [alias, target.description, target.group || "默认分组", target.target.host, target.target.username]
      .some((value) => String(value ?? "").toLocaleLowerCase().includes(query)),
  );
  let visibleGroups = 0;
  for (const group of [undefined, ...groups]) {
    if (filter && (group ? `group:${group}` : "ungrouped") !== filter) continue;
    const members = matches.filter(([, target]) => target.group === group);
    if (query && !members.length && !(group || "默认分组").toLocaleLowerCase().includes(query)) continue;
    visibleGroups += 1;
    const key = group ?? "";
    const label = group ?? "默认分组";
    const count = targets.filter(([, target]) => target.group === group).length;
    const expanded = Boolean(query) || !state.collapsedGroups.has(key);
    const heading = document.createElement("div");
    heading.className = "machine-group-heading";
    heading.dataset.group = key;
    heading.setAttribute("role", "listitem");
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "machine-group-toggle";
    toggle.setAttribute("aria-expanded", String(expanded));
    toggle.setAttribute("aria-label", `${expanded ? "折叠" : "展开"}${label}，${count} 台机器`);
    const chevron = document.createElement("span");
    chevron.className = "group-chevron";
    chevron.setAttribute("aria-hidden", "true");
    chevron.textContent = expanded ? "▾" : "▸";
    const folder = document.createElement("span");
    folder.className = "group-folder";
    folder.setAttribute("aria-hidden", "true");
    const name = document.createElement("span");
    name.className = "machine-group-name";
    name.textContent = label;
    const badge = document.createElement("span");
    badge.className = "group-count";
    badge.textContent = String(count);
    toggle.append(chevron, folder, name, badge);
    toggle.addEventListener("click", () => {
      if (query) return;
      if (state.collapsedGroups.has(key)) state.collapsedGroups.delete(key);
      else state.collapsedGroups.add(key);
      persistCollapsedGroups();
      renderInventory();
      updateControls();
      elements.machineList.querySelectorAll(".machine-group-heading").forEach((row) => {
        if (row.dataset.group === key) row.querySelector(".machine-group-toggle")?.focus();
      });
    });
    if (query) toggle.title = "搜索时自动展开匹配分组，清空搜索后恢复折叠状态";
    heading.append(toggle);
    if (group) {
      const manage = document.createElement("button");
      manage.type = "button";
      manage.className = "machine-group-manage";
      manage.textContent = "···";
      manage.setAttribute("aria-label", `管理分组 ${group}`);
      manage.title = "重命名、排序或删除分组";
      manage.addEventListener("click", () => openGroupDialog("rename", { group }));
      heading.append(manage);
    } else {
      const protectedLabel = document.createElement("span");
      protectedLabel.className = "group-protected";
      protectedLabel.textContent = "固定";
      protectedLabel.title = "默认分组不可重命名、移动或删除";
      heading.append(protectedLabel);
    }
    elements.machineList.append(heading);
    for (const [alias, target] of members) {
      const item = createMachineItem(alias, target);
      item.hidden = !expanded;
      elements.machineList.append(item);
    }
    if (!members.length) {
      const empty = document.createElement("div");
      empty.className = "machine-group-empty";
      empty.textContent = "暂无机器 · 可新增或从其他分组移入";
      empty.hidden = !expanded;
      elements.machineList.append(empty);
    }
  }
  elements.inventoryNoResults.hidden = visibleGroups > 0;
}

function groupMutationBlocked() {
  return state.refreshing || state.mutationBusy || state.keyMutationBusy || state.tailscaleMutationBusy ||
    state.accessClientMutationBusy || state.accessClientPreparationBusy || accessClientPreparationIsActive() ||
    state.checking || state.inspecting || state.running || !state.inventoryAvailable;
}

function openGroupDialog(mode, details = {}) {
  if (groupMutationBlocked()) return;
  if (["rename", "delete"].includes(mode) && !details.group) return;
  state.groupEditor = { mode, ...details };
  clearAlert(elements.groupDialogError);
  elements.groupDialogTitle.textContent = { create: "新建分组", rename: "管理分组", move: "移动机器", delete: "删除分组" }[mode];
  elements.groupNameField.hidden = mode === "move" || mode === "delete";
  elements.groupDestinationField.hidden = mode !== "move";
  elements.groupManageActions.hidden = mode !== "rename";
  elements.groupName.value = details.group ?? "";
  fillGroupOptions(elements.groupDestination, state.targets.get(details.alias)?.group ?? "");
  const count = [...state.targets.values()].filter((target) => target.group === details.group).length;
  elements.groupDialogDescription.textContent = mode === "delete"
    ? `删除“${details.group}”后，${count} 台机器将移到默认分组。机器及其连接、权限配置会保留。`
    : mode === "move" ? `将机器“${details.alias}”移入所选分组，立即保存。`
    : mode === "rename" ? `管理“${details.group}”：重命名会同步更新组内机器，排序会保存到配置。`
    : "创建后可在机器配置中选择，也可将已有机器移入。";
  elements.groupSubmitButton.textContent = { create: "创建分组", rename: "保存名称", move: "确认移动", delete: "删除并移入默认分组" }[mode];
  elements.groupDialog.hidden = false;
  if (!elements.groupDialog.open) elements.groupDialog.showModal?.();
  updateControls();
  (mode === "move" ? elements.groupDestination : mode === "delete" ? elements.groupCancelButton : elements.groupName).focus();
}

function closeGroupDialog(options = {}) {
  if (state.mutationBusy) return;
  const editor = state.groupEditor;
  const committed = options.committed === true;
  const focusGroup = editor?.mode === "move" ? state.targets.get(editor.alias)?.group ?? ""
    : committed && editor?.mode === "delete" ? ""
    : committed && (editor?.mode === "create" || editor?.mode === "rename") ? elements.groupName.value.trim()
    : editor?.group;
  state.groupEditor = null;
  elements.groupDialog.close?.();
  elements.groupDialog.hidden = true;
  updateControls();
  const heading = [...elements.machineList.querySelectorAll(".machine-group-heading")]
    .find((row) => row.dataset.group === focusGroup);
  (heading?.querySelector(".machine-group-toggle") ?? elements.newGroupButton).focus();
}

async function submitGroupMutation(event, reorderDirection = 0) {
  event?.preventDefault();
  if (groupMutationBlocked() || !state.groupEditor) return;
  const { mode, group, alias } = state.groupEditor;
  const groups = inventoryGroups();
  if ((mode === "rename" || mode === "delete") && (!group || !groups.includes(group))) return;
  const name = elements.groupName.value.trim();
  const destination = elements.groupDestination.value;
  const affectsDraft = mode === "move" ? alias === state.originalAlias
    : (mode === "rename" || mode === "delete") &&
      (elements.targetGroup.value === group || state.targets.get(state.originalAlias)?.group === group);
  if (state.dirty && affectsDraft && !reorderDirection) {
    showAlert(elements.groupDialogError, "这台机器有未保存的修改，请先保存或撤销修改，再调整所属分组。", "error");
    return;
  }
  if (!reorderDirection && (mode === "create" || mode === "rename")) {
    if (!name || name.length > 64 || /[\u0000-\u001f\u007f]/u.test(name) || name === "默认分组") {
      showAlert(elements.groupDialogError, "请输入 1–64 个字符的分组名，不可使用默认分组或控制字符。", "error");
      return;
    }
    if (groups.includes(name) && (mode === "create" || name !== group)) {
      showAlert(elements.groupDialogError, "该分组已存在，请使用其他名称。", "error");
      return;
    }
  }
  if (mode === "move" && destination && !groups.includes(destination)) {
    showAlert(elements.groupDialogError, "目标分组已不存在，请刷新后重试。", "error");
    return;
  }
  let action = mode;
  let body = mode === "create" ? { name } : mode === "rename" ? { group, name }
    : mode === "delete" ? { group } : { aliases: [alias], ...(destination ? { group: destination } : {}) };
  if (reorderDirection) {
    const index = groups.indexOf(group);
    const next = index + reorderDirection;
    if (index < 0 || next < 0 || next >= groups.length) return;
    [groups[index], groups[next]] = [groups[next], groups[index]];
    action = "reorder";
    body = { groups };
  }
  state.mutationBusy = true;
  updateControls();
  clearAlert(elements.groupDialogError);
  try {
    const result = await postApi(`admin/group/${action}`, { ...body,
      ...(typeof state.fleetStatus?.revision === "string" ? { expectedRevision: state.fleetStatus.revision } : {}),
    });
    applyFleetStatus(result, { preserveAccessClientDraft: true });
    const groupFilter = action === "rename" && elements.machineGroupFilter.value === `group:${group}`
      ? `group:${name}` : elements.machineGroupFilter.value;
    if (action === "rename") {
      if (state.collapsedGroups.delete(group)) state.collapsedGroups.add(name);
    }
    if (action === "delete") state.collapsedGroups.delete(group);
    if (action === "create") state.collapsedGroups.delete(name);
    if (action === "move") state.collapsedGroups.delete(destination);
    persistCollapsedGroups();
    renderInventory({ groupFilter });
    if (!state.dirty && state.originalAlias && state.targets.has(state.originalAlias)) {
      fillForm(state.originalAlias, state.targets.get(state.originalAlias));
    }
    renderWorkspaceHeading();
    renderCommandTarget();
    renderDirtyState();
    state.mutationBusy = false;
    closeGroupDialog({ committed: true });
    showToast({ create: "分组已创建", rename: "分组名称已保存", delete: "分组已删除，机器已移入默认分组", move: "机器分组已更新", reorder: "分组顺序已保存" }[action]);
    void refreshGatewayTargets({ preserveInventory: true });
  } catch (error) {
    showAlert(elements.groupDialogError, messageForError(error), "error");
  } finally {
    state.mutationBusy = false;
    updateControls();
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
  const descriptionText = target.description?.trim();
  name.className = "machine-description";
  name.textContent = descriptionText || alias;
  name.title = descriptionText || alias;
  button.title = `${descriptionText || alias}\n别名：${alias}\n${target.target.username}@${target.target.host}:${target.target.port}`;
  const stateWrap = document.createElement("span");
  stateWrap.className = "machine-health";
  const dot = document.createElement("span");
  const health = machineHealth(alias, target);
  button.setAttribute("aria-label", `${descriptionText || alias}，编辑机器 ${alias}，${health.label}`);
  stateWrap.title = health.label;
  dot.className = `machine-health-dot is-${health.kind}`;
  dot.setAttribute("aria-hidden", "true");
  const healthText = document.createElement("span");
  healthText.textContent = health.label;
  stateWrap.append(dot, healthText);
  top.append(name, stateWrap);

  const endpoint = document.createElement("span");
  endpoint.className = "machine-endpoint";
  const addressHost = target.target.host.includes(":") && !target.target.host.startsWith("[") ? `[${target.target.host}]` : target.target.host;
  endpoint.textContent = `${addressHost}${target.target.port === 22 ? "" : `:${target.target.port}`}`;
  endpoint.title = `${target.target.username}@${target.target.host}:${target.target.port} · 别名：${alias}`;

  const meta = document.createElement("span");
  meta.className = "machine-meta";
  const platform = document.createElement("span");
  platform.textContent = `${PLATFORM_LABELS[target.platform]} · ${CONNECTION_MODE_LABELS[target.connectionMode]}`;
  const policy = document.createElement("span");
  policy.className = `mini-policy ${policyClass(target.policyMode)}`;
  policy.textContent = POLICY_LABELS[target.policyMode];
  meta.append(platform);
  button.append(top, endpoint, meta);
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

  const move = document.createElement("button");
  move.type = "button";
  move.className = "machine-move-button";
  move.textContent = "↗";
  move.title = "移动到其他分组";
  move.setAttribute("aria-label", `移动机器 ${alias} 到其他分组`);
  move.addEventListener("click", () => openGroupDialog("move", { alias }));
  item.append(button, policy, move, toggle);
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
  elements.targetGroup.value = target.group ?? "";
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
  for (const input of elements.presetInputs) input.checked = (target.permissionPresets ?? []).includes(input.value);
  elements.presetLogPaths.value = (target.logPaths ?? []).join("\n");
  elements.presetLogServices.value = (target.logServices ?? []).join("\n");
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
    group: elements.targetGroup.value,
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
    permissionPresets: selectedPermissionPresets(),
    logPaths: elements.presetLogPaths.value,
    logServices: elements.presetLogServices.value,
    allowedCommands: elements.allowedCommands.value,
    maxTimeoutMs: elements.maxTimeoutMs.value,
    transferMode: selectedRadio(elements.transferInputs),
    localRootPath: elements.localRootPath.value,
    remoteRoots: elements.remoteRoots.value,
    maxTransferTimeoutMs: elements.maxTransferTimeoutMs.value,
  });
}

function unchangedOperationalForm() {
  if (typeof state.baseline !== "string") return false;
  const { description: _oldDescription, group: _oldGroup, ...previous } = JSON.parse(state.baseline);
  const { description: _description, group: _group, ...current } = JSON.parse(rawFormSnapshot());
  return JSON.stringify(previous) === JSON.stringify(current);
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
  if (event.target.matches('input[name="permission-preset"]') || event.target === elements.presetLogPaths || event.target === elements.presetLogServices) renderPermissionFields();
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

function selectedPermissionPresets() {
  return elements.presetInputs.filter((input) => input.checked).map((input) => input.value);
}

function presetLines(element) {
  return element.value.split(/\r?\n/u).map((value) => value.trim()).filter(Boolean);
}

function renderPermissionFields() {
  const policyMode = selectedRadio(elements.policyInputs) ?? "allow-list";
  const selectedTransferMode = selectedRadio(elements.transferInputs) ?? "deny";
  const accessClient = selectedRadio(elements.connectionModeInputs) === "accessclient-share";
  const tailscale = selectedRadio(elements.connectionModeInputs) === "tailscale-ssh";
  const transferMode = tailscale ? "deny" : policyMode === "full-access"
      ? "bidirectional"
    : policyMode === "deny" || policyMode === "presets"
      ? "deny"
      : selectedTransferMode;
  const restrictedTransferEnabled = !accessClient && !tailscale && policyMode === "allow-list" && transferMode !== "deny";
  elements.allowListFields.hidden = policyMode !== "allow-list";
  elements.presetFields.hidden = policyMode !== "presets";
  const presets = selectedPermissionPresets();
  elements.presetLogFields.hidden = !presets.includes("log-inspection");
  const allowedNames = elements.presetInputs.filter((input) => input.checked && input.value !== "docker-protection" && (input.value !== "log-inspection" || presetLines(elements.presetLogPaths).length > 0 || presetLines(elements.presetLogServices).length > 0))
    .map((input) => PERMISSION_PRESET_LABELS[input.value]);
  elements.presetEffective.textContent = `允许：${allowedNames.join("、") || "尚未授予任何操作"}。禁止：任意命令、脚本、后台原始任务及文件传输${presets.includes("docker-protection") ? "；Docker 服务与容器变更" : ""}。`;
  elements.fullAccessWarning.hidden = policyMode !== "full-access";
  elements.denyNote.hidden = policyMode !== "deny";
  elements.permissionLimits.hidden = policyMode === "deny";
  elements.transferFields.hidden = !restrictedTransferEnabled;
  elements.transferDenyNote.hidden = accessClient || tailscale || policyMode !== "allow-list" || restrictedTransferEnabled;
  elements.accessClientTransferNote.hidden = !accessClient || policyMode === "deny" || policyMode === "presets";
  elements.transferTimeoutField.hidden = !restrictedTransferEnabled;
  elements.restrictedTransferSummary.textContent = TRANSFER_LABELS[transferMode];
  elements.fullAccessHeading.textContent = "完全访问 将开放完整命令与文件权限";
  elements.fullAccessDescription.textContent = accessClient
    ? "Codex 可以执行任意命令，并通过持久化 Plink 通道使用任意本机或远端绝对路径双向传输文件。每次保存都必须重新确认。"
    : "Codex 可以执行任意命令，并可使用任意本机或远端绝对路径双向传输文件，包括读取本机私钥、凭证等敏感文件，以及修改配置、停止服务或删除数据。每次保存都必须重新确认。";
  elements.fullAccessConfirmText.textContent = "我已核对目标机器，并确认授予 Codex 完整命令权限和全部本机、远端文件权限。";
  if (tailscale) {
    elements.fullAccessHeading.textContent = "完全访问 将开放完整命令权限";
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
  elements.singleCommandFields.hidden = structured || target?.policyMode === "presets";
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
    option.textContent = "完全访问";
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
  elements.savedIndicator.title = state.dirty || state.accessClientSettingsDirty || state.tailscaleSettingsDirty ? "有未保存修改" : "配置已保存";
  if (state.dirty) {
    elements.savedIndicator.textContent = state.activeView === "settings" ? "机器配置未保存" : "未保存";
    elements.savedIndicator.className = "saved-indicator is-dirty";
  } else if (state.accessClientSettingsDirty || state.tailscaleSettingsDirty) {
    elements.savedIndicator.textContent = "全局设置未保存";
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
  elements.breadcrumbCurrent.textContent = state.activeView === "settings" ? "全局设置" : state.activeView === "command" ? "命令工作台" : "机器管理";
  if (state.activeView === "settings") {
    elements.workspaceTitle.textContent = "全局设置";
    elements.workspaceSubtitle.textContent = state.keysAvailable ? "" : state.keysLoaded ? "私钥库只读" : "读取私钥中…";
    elements.selectedStateBadge.textContent = state.keysAvailable ? "可管理" : state.keysLoaded ? "只读" : "加载中";
    elements.selectedStateBadge.className = `state-badge ${state.keysAvailable ? "is-enabled" : "is-draft"}`;
    return;
  }
  const alias = state.selectedAlias;
  const target = alias ? state.targets.get(alias) : null;
  if (!target) {
    elements.workspaceTitle.textContent = "新增机器";
    elements.workspaceSubtitle.textContent = "";
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
  if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) {
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
      : (currentIndex + ((event.key === "ArrowLeft" || event.key === "ArrowUp") ? -1 : 1) + enabled.length) % enabled.length;
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
  const group = elements.targetGroup.value.trim();
  if (group.length > 64 || /[\u0000-\u001f\u007f]/u.test(group)) {
    return invalid(elements.targetGroup, "组名不能包含控制字符，且最多 64 个字符。");
  }
  if (group && !inventoryGroups().includes(group)) {
    return invalid(elements.targetGroup, "请选择已有分组，或先在左侧新建分组。");
  }
  if (description.length > 256 || /[\u0000-\u001f\u007f]/u.test(description)) {
    return invalid(elements.targetDescription, "说明不能包含控制字符，且最多 256 个字符。");
  }
  const savedTarget = state.originalAlias && state.fleetStatus?.profile?.targets?.[state.originalAlias];
  if (savedTarget && unchangedOperationalForm()) {
    if (savedTarget.connectionMode === "accessclient-share" && !state.accessClientSettings.plinkExecutable) {
      return invalid(elements.connectionModeInputs.find((input) => input.value === "accessclient-share"), "请先到全局设置保存 Plink 程序路径，再配置 AccessClient 机器。");
    }
    if (savedTarget.connectionMode === "tailscale-ssh" && !state.tailscaleSettings.executable) {
      return invalid(elements.connectionModeInputs.find((input) => input.value === "tailscale-ssh"), "请先在全局设置保存 Tailscale 程序路径。");
    }
    if (options.requireFullConfirmation && savedTarget.policyMode === "full-access" && !elements.fullAccessConfirm.checked) {
      return invalid(elements.fullAccessConfirm, "保存 完全访问 配置前必须确认风险。");
    }
    if (options.requireFullConfirmation && savedTarget.policyMode === "allow-list" && savedTarget.transferMode && savedTarget.transferMode !== "deny" && !elements.transferAccessConfirm.checked) {
      return invalid(elements.transferAccessConfirm, "保存文件传输权限前必须确认本机和远端目录。");
    }
    // The simplified form cannot round-trip legacy transport fields (or bastions).
    // Metadata/no-op saves must retain the raw persisted operational configuration.
    const { description: _savedDescription, group: _savedGroup, ...operational } = savedTarget;
    return { alias, target: { ...operational, ...(description ? { description } : {}), ...(group ? { group } : {}) } };
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
  const permissionPresets = selectedPermissionPresets();
  const logPaths = presetLines(elements.presetLogPaths);
  const logServices = presetLines(elements.presetLogServices);
  if (policyMode === "presets") {
    if (logPaths.length > 32 || new Set(logPaths).size !== logPaths.length) return invalid(elements.presetLogPaths, "最多填写 32 个不重复的日志文件路径。");
    if (logServices.length > 32 || new Set(logServices).size !== logServices.length) return invalid(elements.presetLogServices, "最多填写 32 个不重复的日志服务。");
  }
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
    return invalid(elements.fullAccessConfirm, "保存 完全访问 配置前必须确认风险。");
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
    : policyMode === "deny" || policyMode === "presets"
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
      ...(group ? { group } : {}),
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
      ...(policyMode === "presets" ? { permissionPresets, logPaths, logServices, transferMode: "deny" } : {}),
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
  showAlert(elements.formStatus, "正在保存配置...", "progress");
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
    ? ""
    : "";
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
    ? ""
    : "";
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
  decorateUiAction(publicButton, "key", "公钥");
  publicButton.disabled = !key.publicKey;
  publicButton.dataset.unavailable = String(!key.publicKey);
  publicButton.addEventListener("click", () => showPublicKey(key.keyId));
  const renameButton = document.createElement("button");
  renameButton.type = "button";
  renameButton.className = "toolbar-button";
  renameButton.textContent = "重命名";
  decorateUiAction(renameButton, "edit", "重命名");
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
  // Keep copy availability in sync when the panel is opened without a full render.
  elements.copyPublicKeyButton.disabled = !visible;
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

async function refreshGatewayTargets(options = {}) {
  try {
    applyGatewayTargets(await postApi("targets", {}));
    if (!options.preserveInventory) renderInventory();
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
    elements.commandNote.textContent = `${target.allowedCommands.length} 条白名单命令 · 逐字匹配`;
  } else if (target.policyMode === "full-access") {
    elements.commandNote.textContent = "";
  } else if (target.policyMode === "presets") {
    elements.commandNote.textContent = "此机器使用预设命令组。请让 MCP 调用 ssh_list_allowed_operations 查看操作，再用 ssh_run_operation 执行。此工作台不开放任意命令。";
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
  if (target.policyMode === "presets") return { error: "预设模式请通过 ssh_run_operation 执行已授权操作。" };
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
    return { error: "结构化脚本仅允许用于 完全访问 机器。" };
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
    return { error: "完全访问 模式下请填写本机绝对路径。" };
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
    showAlert(elements.dockerPreflightStatus, "Docker 预检仅允许用于 完全访问 机器。", "error");
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
    text = "暂无输出";
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


function decorateUiAction(button, icon, label) {
  if (!document.createElementNS || !button.replaceChildren) return;
  const paths = {
    key: '<circle cx="8" cy="8" r="4"/><path d="m11 11 9 9m-3-3 3-3m-6 0 3-3"/>',
    edit: '<path d="m15 4 5 5M4 20l5-1L20 8a2 2 0 0 0-5-5L4 14Z"/>',
  };
  if (!paths[icon]) return;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  for (const [key, value] of Object.entries({ viewBox: "0 0 24 24", class: "ui-icon action-icon", fill: "none", stroke: "currentColor", "stroke-width": "1.7", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", focusable: "false" })) svg.setAttribute(key, value);
  // Static, allowlisted SVG paths only; no user or server content enters innerHTML.
  svg.innerHTML = paths[icon];
  const text = document.createElement("span");
  text.className = "sr-only";
  text.textContent = label;
  button.replaceChildren(svg, text);
  button.classList.add("quiet-icon-button");
  button.dataset.uiIcon = icon;
  button.setAttribute("aria-label", label);
  button.title = label;
}

// Reuse one feedback timer per copy button; never replace the SVG or its event listeners.
const uiCopyFeedback = new WeakMap();
function markUiCopied(button) {
  const previous = uiCopyFeedback.get(button);
  if (previous) window.clearTimeout(previous.timer);
  const label = previous?.label || button.getAttribute?.("aria-label") || button.textContent;
  const oldText = previous?.oldText || button.textContent;
  const icon = Boolean(button.dataset?.uiIcon);
  if (icon) {
    button.dataset.copyState = "copied";
    button.setAttribute("aria-label", "已复制");
    button.title = "已复制";
  } else button.textContent = "已复制";
  const timer = window.setTimeout(() => {
    if (icon) {
      delete button.dataset.copyState;
      button.setAttribute("aria-label", label);
      button.title = label;
    } else button.textContent = oldText;
    uiCopyFeedback.delete(button);
  }, 1500);
  uiCopyFeedback.set(button, {timer, label, oldText});
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
    markUiCopied(button);
    showToast(toastText);
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
  elements.newGroupButton.disabled = groupMutationBlocked();
  elements.machineGroupFilter.disabled = !state.inventoryLoaded;
  for (const control of [elements.groupName, elements.groupDestination, elements.groupSubmitButton, elements.groupDeleteButton, elements.groupUpButton, elements.groupDownButton]) {
    control.disabled = groupMutationBlocked();
  }
  elements.groupCancelButton.disabled = state.mutationBusy;
  elements.groupDialogStatus.hidden = !state.groupEditor || !state.mutationBusy;
  if (state.groupEditor) {
    elements.groupSubmitButton.textContent = state.mutationBusy ? "保存中…"
      : { create: "创建分组", rename: "保存名称", move: "确认移动", delete: "删除并移入默认分组" }[state.groupEditor.mode];
  }
  const groupIndex = inventoryGroups().indexOf(state.groupEditor?.group);
  elements.groupUpButton.disabled ||= groupIndex <= 0;
  elements.groupDownButton.disabled ||= groupIndex < 0 || groupIndex >= inventoryGroups().length - 1;
  elements.machineForm.querySelectorAll("input, textarea, select, button").forEach((control) => {
    control.disabled = blocked || state.running || inventoryBlocked || preparationActive;
  });
  for (const item of elements.machineList.querySelectorAll("button")) {
    item.disabled = item.className === "machine-group-toggle" ? false : blocked || state.running || inventoryBlocked || preparationActive;
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
    : state.mutationBusy ? "保存中…"
    : state.checking ? "检测中…"
    : preparationActive ? "正在准备会话…"
    : state.running ? "任务运行中，结束后可修改配置。"
    : !externalIdentity && !state.keysAvailable ? "私钥库不可用，请在全局设置中检查。"
    : !selectedKeysAvailable ? "请先在全局设置中添加并选择私钥。"
    : !state.originalAlias ? "保存后可连接"
    : state.dirty ? "保存后可检测"
    : "";
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
  elements.runButton.disabled = operationBlocked || selectedTarget?.policyMode === "deny" || selectedTarget?.policyMode === "presets";
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
  elements.saveTailscaleSettingsButton.textContent = state.tailscaleMutationBusy ? "正在保存..." : "保存";
  const accessClientSettingsBlocked = blocked || state.running || inventoryBlocked || preparationActive;
  elements.plinkExecutable.disabled = accessClientSettingsBlocked;
  elements.saveAccessClientSettingsButton.disabled = accessClientSettingsBlocked || !state.accessClientSettingsDirty;
  elements.saveAccessClientSettingsButton.textContent = state.accessClientMutationBusy
    ? "正在保存..."
    : "保存";

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
  return window.confirm("当前机器未保存，确定放弃吗？");
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
elements.machineGroupFilter.addEventListener("change", () => {
  if (state.inventoryLoaded) {
    renderInventory();
    updateControls();
  }
});
elements.newGroupButton.addEventListener("click", () => openGroupDialog("create"));
elements.groupDialogForm.addEventListener("submit", (event) => void submitGroupMutation(event));
elements.groupCancelButton.addEventListener("click", closeGroupDialog);
elements.groupDialog.addEventListener("cancel", (event) => {
  event.preventDefault();
  closeGroupDialog();
});
elements.groupDeleteButton.addEventListener("click", () => openGroupDialog("delete", { group: state.groupEditor?.group }));
elements.groupUpButton.addEventListener("click", (event) => void submitGroupMutation(event, -1));
elements.groupDownButton.addEventListener("click", (event) => void submitGroupMutation(event, 1));

elements.machineSearch.addEventListener("input", () => {
  if (state.inventoryLoaded) {
    renderInventory();
    updateControls();
  }
});
elements.machineSearch.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    elements.machineSearch.value = "";
    if (state.inventoryLoaded) {
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

// Layout-only: keep the tablist semantics in sync with the mobile navigation.
if (typeof window.matchMedia === "function") {
  const narrowNavigation = window.matchMedia("(max-width: 640px)");
  const tablist = document.querySelector(".workspace-tabs");
  const syncOrientation = () => tablist?.setAttribute("aria-orientation", narrowNavigation.matches ? "horizontal" : "vertical");
  syncOrientation();
  narrowNavigation.addEventListener("change", syncOrientation);
}

void refreshApplication();

/* BEGIN GENERATED SSH MOTION BUNDLE */
;(function(){
if (typeof window === "undefined" || typeof document === "undefined" || document.documentElement?.nodeType !== 1) return;
/*!
 * GSAP 3.15.0
 * https://gsap.com
 *
 * @license Copyright 2026, GreenSock. All rights reserved.
 * Subject to the terms at https://gsap.com/standard-license.
 * @author: Jack Doyle, jack@greensock.com
 */

!function(t,e){"object"==typeof exports&&"undefined"!=typeof module?e(exports):"function"==typeof define&&define.amd?define(["exports"],e):e((t=t||self).window=t.window||{})}(this,function(e){"use strict";function _inheritsLoose(t,e){t.prototype=Object.create(e.prototype),(t.prototype.constructor=t).__proto__=e}function _assertThisInitialized(t){if(void 0===t)throw new ReferenceError("this hasn't been initialised - super() hasn't been called");return t}function r(t){return"string"==typeof t}function s(t){return"function"==typeof t}function t(t){return"number"==typeof t}function u(t){return void 0===t}function v(t){return"object"==typeof t}function w(t){return!1!==t}function x(){return"undefined"!=typeof window}function y(t){return s(t)||r(t)}function R(t){return(i=bt(t,ht))&&Fe}function S(t,e){return console.warn("Invalid property",t,"set to",e,"Missing plugin? gsap.registerPlugin()")}function T(t,e){return!e&&console.warn(t)}function U(t,e){return t&&(ht[t]=e)&&i&&(i[t]=e)||ht}function V(){return 0}function ga(t){var e,r,i=t[0];if(v(i)||s(i)||(t=[t]),!(e=(i._gsap||{}).harness)){for(r=yt.length;r--&&!yt[r].targetTest(i););e=yt[r]}for(r=t.length;r--;)t[r]&&(t[r]._gsap||(t[r]._gsap=new Xt(t[r],e)))||t.splice(r,1);return t}function ha(t){return t._gsap||ga(Pt(t))[0]._gsap}function ia(t,e,r){return(r=t[e])&&s(r)?t[e]():u(r)&&t.getAttribute&&t.getAttribute(e)||r}function ja(t,e){return(t=t.split(",")).forEach(e)||t}function ka(t){return Math.round(1e5*t)/1e5||0}function la(t){return Math.round(1e7*t)/1e7||0}function ma(t,e){var r=e.charAt(0),i=parseFloat(e.substr(2));return t=parseFloat(t),"+"===r?t+i:"-"===r?t-i:"*"===r?t*i:t/i}function na(t,e){for(var r=e.length,i=0;t.indexOf(e[i])<0&&++i<r;);return i<r}function oa(){var t,e,r=pt.length,i=pt.slice(0);for(_t={},t=pt.length=0;t<r;t++)(e=i[t])&&e._lazy&&(e.render(e._lazy[0],e._lazy[1],!0)._lazy=0)}function pa(t){return!!(t._initted||t._startAt||t.add)}function qa(t,e,r,i){pt.length&&!I&&oa(),t.render(e,r,i||!!(I&&e<0&&pa(t))),pt.length&&!I&&oa()}function ra(t){var e=parseFloat(t);return(e||0===e)&&(t+"").match(ot).length<2?e:r(t)?t.trim():t}function sa(t){return t}function ta(t,e){for(var r in e)r in t||(t[r]=e[r]);return t}function wa(t,e){for(var r in e)"__proto__"!==r&&"constructor"!==r&&"prototype"!==r&&(t[r]=v(e[r])?wa(t[r]||(t[r]={}),e[r]):e[r]);return t}function xa(t,e){var r,i={};for(r in t)r in e||(i[r]=t[r]);return i}function ya(t){var e=t.parent||L,r=t.keyframes?function _setKeyframeDefaults(i){return function(t,e){for(var r in e)r in t||"duration"===r&&i||"ease"===r||(t[r]=e[r])}}(K(t.keyframes)):ta;if(w(t.inherit))for(;e;)r(t,e.vars.defaults),e=e.parent||e._dp;return t}function Aa(t,e,r,i,n){void 0===r&&(r="_first"),void 0===i&&(i="_last");var a,s=t[i];if(n)for(a=e[n];s&&s[n]>a;)s=s._prev;return s?(e._next=s._next,s._next=e):(e._next=t[r],t[r]=e),e._next?e._next._prev=e:t[i]=e,e._prev=s,e.parent=e._dp=t,e}function Ba(t,e,r,i){void 0===r&&(r="_first"),void 0===i&&(i="_last");var n=e._prev,a=e._next;n?n._next=a:t[r]===e&&(t[r]=a),a?a._prev=n:t[i]===e&&(t[i]=n),e._next=e._prev=e.parent=null}function Ca(t,e){t.parent&&(!e||t.parent.autoRemoveChildren)&&t.parent.remove&&t.parent.remove(t),t._act=0}function Da(t,e){if(t&&(!e||e._end>t._dur||e._start<0))for(var r=t;r;)r._dirty=1,r=r.parent;return t}function Fa(t,e,r,i){return t._startAt&&(I?t._startAt.revert(ft):t.vars.immediateRender&&!t.vars.autoRevert||t._startAt.render(e,!0,i))}function Ha(t){return t._repeat?wt(t._tTime,t=t.duration()+t._rDelay)*t:0}function Ja(t,e){return(t-e._start)*e._ts+(0<=e._ts?0:e._dirty?e.totalDuration():e._tDur)}function Ka(t){return t._end=la(t._start+(t._tDur/Math.abs(t._ts||t._rts||q)||0))}function La(t,e){var r=t._dp;return r&&r.smoothChildTiming&&t._ts&&(t._start=la(r._time-(0<t._ts?e/t._ts:((t._dirty?t.totalDuration():t._tDur)-e)/-t._ts)),Ka(t),r._dirty||Da(r,t)),t}function Ma(t,e){var r;if((e._time||!e._dur&&e._initted||e._start<t._time&&(e._dur||!e.add))&&(r=Ja(t.rawTime(),e),(!e._dur||Mt(0,e.totalDuration(),r)-e._tTime>q)&&e.render(r,!0)),Da(t,e)._dp&&t._initted&&t._time>=t._dur&&t._ts){if(t._dur<t.duration())for(r=t;r._dp;)0<=r.rawTime()&&r.totalTime(r._tTime),r=r._dp;t._zTime=-q}}function Na(e,r,i,n){return r.parent&&Ca(r),r._start=la((t(i)?i:i||e!==L?Ot(e,i,r):e._time)+r._delay),r._end=la(r._start+(r.totalDuration()/Math.abs(r.timeScale())||0)),Aa(e,r,"_first","_last",e._sort?"_start":0),xt(r)||(e._recent=r),n||Ma(e,r),e._ts<0&&La(e,e._tTime),e}function Oa(t,e){return(ht.ScrollTrigger||S("scrollTrigger",e))&&ht.ScrollTrigger.create(e,t)}function Pa(t,e,r,i,n){return Ht(t,e,n),t._initted?!r&&t._pt&&!I&&(t._dur&&!1!==t.vars.lazy||!t._dur&&t.vars.lazy)&&f!==It.frame?(pt.push(t),t._lazy=[n,i],1):void 0:1}function Ua(t,e,r,i){var n=t._repeat,a=la(e)||0,s=t._tTime/t._tDur;return s&&!i&&(t._time*=a/t._dur),t._dur=a,t._tDur=n?n<0?1e10:la(a*(n+1)+t._rDelay*n):a,0<s&&!i&&La(t,t._tTime=t._tDur*s),t.parent&&Ka(t),r||Da(t.parent,t),t}function Va(t){return t instanceof Gt?Da(t):Ua(t,t._dur)}function Ya(e,r,i){var n,a,s=t(r[1]),o=(s?2:1)+(e<2?0:1),u=r[o];if(s&&(u.duration=r[1]),u.parent=i,e){for(n=u,a=i;a&&!("immediateRender"in n);)n=a.vars.defaults||{},a=w(a.vars.inherit)&&a.parent;u.immediateRender=w(n.immediateRender),e<2?u.runBackwards=1:u.startAt=r[o-1]}return new te(r[0],u,r[1+o])}function Za(t,e){return t||0===t?e(t):e}function _a(t,e){return r(t)&&(e=ut.exec(t))?e[1]:""}function cb(t,e){return t&&v(t)&&"length"in t&&(!e&&!t.length||t.length-1 in t&&v(t[0]))&&!t.nodeType&&t!==h}function fb(r){return r=Pt(r)[0]||T("Invalid scope")||{},function(t){var e=r.current||r.nativeElement||r;return Pt(t,e.querySelectorAll?e:e===r?T("Invalid scope")||a.createElement("div"):r)}}function gb(t){return t.sort(function(){return.5-Math.random()})}function hb(t){if(s(t))return t;var p=v(t)?t:{each:t},_=jt(p.ease),m=p.from||0,g=parseFloat(p.base)||0,y={},e=0<m&&m<1,T=isNaN(m)||e,b=p.axis,w=m,x=m;return r(m)?w=x={center:.5,edges:.5,end:1}[m]||0:!e&&T&&(w=m[0],x=m[1]),function(t,e,r){var i,n,a,s,o,u,h,l,f,c=(r||p).length,d=y[c];if(!d){if(!(f="auto"===p.grid?0:(p.grid||[1,X])[1])){for(h=-X;h<(h=r[f++].getBoundingClientRect().left)&&f<c;);f<c&&f--}for(d=y[c]=[],i=T?Math.min(f,c)*w-.5:m%f,n=f===X?0:T?c*x/f-.5:m/f|0,l=X,u=h=0;u<c;u++)a=u%f-i,s=n-(u/f|0),d[u]=o=b?Math.abs("y"===b?s:a):$(a*a+s*s),h<o&&(h=o),o<l&&(l=o);"random"===m&&gb(d),d.max=h-l,d.min=l,d.v=c=(parseFloat(p.amount)||parseFloat(p.each)*(c<f?c-1:b?"y"===b?c/f:f:Math.max(f,c/f))||0)*("edges"===m?-1:1),d.b=c<0?g-c:g,d.u=_a(p.amount||p.each)||0,_=_&&c<0?Yt(_):_}return c=(d[t]-d.min)/d.max||0,la(d.b+(_?_(c):c)*d.v)+d.u}}function ib(i){var n=Math.pow(10,((i+"").split(".")[1]||"").length);return function(e){var r=la(Math.round(parseFloat(e)/i)*i*n);return(r-r%1)/n+(t(e)?0:_a(e))}}function jb(h,e){var l,f,r=K(h);return!r&&v(h)&&(l=r=h.radius||X,h.values?(h=Pt(h.values),(f=!t(h[0]))&&(l*=l)):h=ib(h.increment)),Za(e,r?s(h)?function(t){return f=h(t),Math.abs(f-t)<=l?f:t}:function(e){for(var r,i,n=parseFloat(f?e.x:e),a=parseFloat(f?e.y:0),s=X,o=0,u=h.length;u--;)(r=f?(r=h[u].x-n)*r+(i=h[u].y-a)*i:Math.abs(h[u]-n))<s&&(s=r,o=u);return o=!l||s<=l?h[o]:e,f||o===e||t(e)?o:o+_a(e)}:ib(h))}function kb(t,e,r,i){return Za(K(t)?!e:!0===r?!!(r=0):!i,function(){return K(t)?t[~~(Math.random()*t.length)]:(r=r||1e-5)&&(i=r<1?Math.pow(10,(r+"").length-2):1)&&Math.floor(Math.round((t-r/2+Math.random()*(e-t+.99*r))/r)*r*i)/i})}function ob(e,r,t){return Za(t,function(t){return e[~~r(t)]})}function rb(t){return t.replace(tt,function(t){var e=t.indexOf("[")+1,r=t.substring(e||7,e?t.indexOf("]"):t.length-1).split(et);return kb(e?r:+r[0],e?0:+r[1],+r[2]||1e-5)})}function ub(t,e,r){var i,n,a,s=t.labels,o=X;for(i in s)(n=s[i]-e)<0==!!r&&n&&o>(n=Math.abs(n))&&(a=i,o=n);return a}function wb(t){return Ca(t),t.scrollTrigger&&t.scrollTrigger.kill(!!I),t.progress()<1&&At(t,"onInterrupt"),t}function zb(t){if(t)if(t=!t.name&&t.default||t,x()||t.headless){var e=t.name,r=s(t),i=e&&!r&&t.init?function(){this._props=[]}:t,n={init:V,render:_e,add:$t,kill:Te,modifier:ve,rawVars:0},a={targetTest:0,get:0,getSetter:ue,aliases:{},register:0};if(Lt(),t!==i){if(mt[e])return;ta(i,ta(xa(t,n),a)),bt(i.prototype,bt(n,xa(t,a))),mt[i.prop=e]=i,t.targetTest&&(yt.push(i),dt[e]=1),e=("css"===e?"CSS":e.charAt(0).toUpperCase()+e.substr(1))+"Plugin"}U(e,i),t.register&&t.register(Fe,i,we)}else Dt.push(t)}function Cb(t,e,r){return(6*(t+=t<0?1:1<t?-1:0)<1?e+(r-e)*t*6:t<.5?r:3*t<2?e+(r-e)*(2/3-t)*6:e)*zt+.5|0}function Db(e,r,i){var n,a,s,o,u,h,l,f,c,d,p=e?t(e)?[e>>16,e>>8&zt,e&zt]:0:Rt.black;if(!p){if(","===e.substr(-1)&&(e=e.substr(0,e.length-1)),Rt[e])p=Rt[e];else if("#"===e.charAt(0)){if(e.length<6&&(e="#"+(n=e.charAt(1))+n+(a=e.charAt(2))+a+(s=e.charAt(3))+s+(5===e.length?e.charAt(4)+e.charAt(4):"")),9===e.length)return[(p=parseInt(e.substr(1,6),16))>>16,p>>8&zt,p&zt,parseInt(e.substr(7),16)/255];p=[(e=parseInt(e.substr(1),16))>>16,e>>8&zt,e&zt]}else if("hsl"===e.substr(0,3))if(p=d=e.match(rt),r){if(~e.indexOf("="))return p=e.match(it),i&&p.length<4&&(p[3]=1),p}else o=+p[0]%360/360,u=p[1]/100,n=2*(h=p[2]/100)-(a=h<=.5?h*(u+1):h+u-h*u),3<p.length&&(p[3]*=1),p[0]=Cb(o+1/3,n,a),p[1]=Cb(o,n,a),p[2]=Cb(o-1/3,n,a);else p=e.match(rt)||Rt.transparent;p=p.map(Number)}return r&&!d&&(n=p[0]/zt,a=p[1]/zt,s=p[2]/zt,h=((l=Math.max(n,a,s))+(f=Math.min(n,a,s)))/2,l===f?o=u=0:(c=l-f,u=.5<h?c/(2-l-f):c/(l+f),o=l===n?(a-s)/c+(a<s?6:0):l===a?(s-n)/c+2:(n-a)/c+4,o*=60),p[0]=~~(o+.5),p[1]=~~(100*u+.5),p[2]=~~(100*h+.5)),i&&p.length<4&&(p[3]=1),p}function Eb(t){var r=[],i=[],n=-1;return t.split(Et).forEach(function(t){var e=t.match(nt)||[];r.push.apply(r,e),i.push(n+=e.length+1)}),r.c=i,r}function Fb(t,e,r){var i,n,a,s,o="",u=(t+o).match(Et),h=e?"hsla(":"rgba(",l=0;if(!u)return t;if(u=u.map(function(t){return(t=Db(t,e,1))&&h+(e?t[0]+","+t[1]+"%,"+t[2]+"%,"+t[3]:t.join(","))+")"}),r&&(a=Eb(t),(i=r.c).join(o)!==a.c.join(o)))for(s=(n=t.replace(Et,"1").split(nt)).length-1;l<s;l++)o+=n[l]+(~i.indexOf(l)?u.shift()||h+"0,0,0,0)":(a.length?a:u.length?u:r).shift());if(!n)for(s=(n=t.split(Et)).length-1;l<s;l++)o+=n[l]+u[l];return o+n[s]}function Ib(t){var e,r=t.join(" ");if(Et.lastIndex=0,Et.test(r))return e=Ft.test(r),t[1]=Fb(t[1],e),t[0]=Fb(t[0],e,Eb(t[1])),!0}function Rb(t){var e=(t+"").split("("),r=Bt[e[0]];return r&&1<e.length&&r.config?r.config.apply(null,~t.indexOf("{")?[function _parseObjectInString(t){for(var e,r,i,n={},a=t.substr(1,t.length-3).split(":"),s=a[0],o=1,u=a.length;o<u;o++)r=a[o],e=o!==u-1?r.lastIndexOf(","):r.length,i=r.substr(0,e),n[s]=isNaN(i)?i.replace(Ut,"").trim():+i,s=r.substr(e+1).trim();return n}(e[1])]:function _valueInParentheses(t){var e=t.indexOf("(")+1,r=t.indexOf(")"),i=t.indexOf("(",e);return t.substring(e,~i&&i<r?t.indexOf(")",r+1):r)}(t).split(",").map(ra)):Bt._CE&&Nt.test(t)?Bt._CE("",t):r}function Ub(t,e,r,i){void 0===r&&(r=function easeOut(t){return 1-e(1-t)}),void 0===i&&(i=function easeInOut(t){return t<.5?e(2*t)/2:1-e(2*(1-t))/2});var n,a={easeIn:e,easeOut:r,easeInOut:i};return ja(t,function(t){for(var e in Bt[t]=ht[t]=a,Bt[n=t.toLowerCase()]=r,a)Bt[n+("easeIn"===e?".in":"easeOut"===e?".out":".inOut")]=Bt[t+"."+e]=a[e]}),a}function Vb(e){return function(t){return t<.5?(1-e(1-2*t))/2:.5+e(2*(t-.5))/2}}function Wb(r,t,e){function Gm(t){return 1===t?1:i*Math.pow(2,-10*t)*Q((t-a)*n)+1}var i=1<=t?t:1,n=(e||(r?.3:.45))/(t<1?t:1),a=n/G*(Math.asin(1/i)||0),s="out"===r?Gm:"in"===r?function(t){return 1-Gm(1-t)}:Vb(Gm);return n=G/n,s.config=function(t,e){return Wb(r,t,e)},s}function Xb(e,r){function Om(t){return t?--t*t*((r+1)*t+r)+1:0}void 0===r&&(r=1.70158);var t="out"===e?Om:"in"===e?function(t){return 1-Om(1-t)}:Vb(Om);return t.config=function(t){return Xb(e,t)},t}var F,I,l,L,h,n,a,i,o,f,c,d,p,_,m,g,b,k,O,M,C,P,A,D,z,E,B,N,Y={autoSleep:120,force3D:"auto",nullTargetWarn:1,units:{lineHeight:""}},j={duration:.5,overwrite:!1,delay:0},X=1e8,q=1/X,G=2*Math.PI,Z=G/4,W=0,$=Math.sqrt,H=Math.cos,Q=Math.sin,J="function"==typeof ArrayBuffer&&ArrayBuffer.isView||function(){},K=Array.isArray,tt=/random\([^)]+\)/g,et=/,\s*/g,rt=/(?:-?\.?\d|\.)+/gi,it=/[-+=.]*\d+[.e\-+]*\d*[e\-+]*\d*/g,nt=/[-+=.]*\d+[.e-]*\d*[a-z%]*/g,at=/[-+=.]*\d+\.?\d*(?:e-|e\+)?\d*/gi,st=/[+-]=-?[.\d]+/,ot=/[^,'"\[\]\s]+/gi,ut=/^[+\-=e\s\d]*\d+[.\d]*([a-z]*|%)\s*$/i,ht={},lt={suppressEvents:!0,isStart:!0,kill:!1},ft={suppressEvents:!0,kill:!1},ct={suppressEvents:!0},dt={},pt=[],_t={},mt={},gt={},vt=30,yt=[],Tt="",bt=function _merge(t,e){for(var r in e)t[r]=e[r];return t},wt=function _animationCycle(t,e){var r=Math.floor(t=la(t/e));return t&&r===t?r-1:r},xt=function _isFromOrFromStart(t){var e=t.data;return"isFromStart"===e||"isStart"===e},kt={_start:0,endTime:V,totalDuration:V},Ot=function _parsePosition(t,e,i){var n,a,s,o=t.labels,u=t._recent||kt,h=t.duration()>=X?u.endTime(!1):t._dur;return r(e)&&(isNaN(e)||e in o)?(a=e.charAt(0),s="%"===e.substr(-1),n=e.indexOf("="),"<"===a||">"===a?(0<=n&&(e=e.replace(/=/,"")),("<"===a?u._start:u.endTime(0<=u._repeat))+(parseFloat(e.substr(1))||0)*(s?(n<0?u:i).totalDuration()/100:1)):n<0?(e in o||(o[e]=h),o[e]):(a=parseFloat(e.charAt(n-1)+e.substr(n+1)),s&&i&&(a=a/100*(K(i)?i[0]:i).totalDuration()),1<n?_parsePosition(t,e.substr(0,n-1),i)+a:h+a)):null==e?h:+e},Mt=function _clamp(t,e,r){return r<t?t:e<r?e:r},Ct=[].slice,Pt=function toArray(t,e,i){return l&&!e&&l.selector?l.selector(t):!r(t)||i||!n&&Lt()?K(t)?function _flatten(t,e,i){return void 0===i&&(i=[]),t.forEach(function(t){return r(t)&&!e||cb(t,1)?i.push.apply(i,Pt(t)):i.push(t)})||i}(t,i):cb(t)?Ct.call(t,0):t?[t]:[]:Ct.call((e||a).querySelectorAll(t),0)},St=function mapRange(e,t,r,i,n){var a=t-e,s=i-r;return Za(n,function(t){return r+((t-e)/a*s||0)})},At=function _callback(t,e,r){var i,n,a,s=t.vars,o=s[e],u=l,h=t._ctx;if(o)return i=s[e+"Params"],n=s.callbackScope||t,r&&pt.length&&oa(),h&&(l=h),a=i?o.apply(n,i):o.call(n),l=u,a},Dt=[],zt=255,Rt={aqua:[0,zt,zt],lime:[0,zt,0],silver:[192,192,192],black:[0,0,0],maroon:[128,0,0],teal:[0,128,128],blue:[0,0,zt],navy:[0,0,128],white:[zt,zt,zt],olive:[128,128,0],yellow:[zt,zt,0],orange:[zt,165,0],gray:[128,128,128],purple:[128,0,128],green:[0,128,0],red:[zt,0,0],pink:[zt,192,203],cyan:[0,zt,zt],transparent:[zt,zt,zt,0]},Et=function(){var t,e="(?:\\b(?:(?:rgb|rgba|hsl|hsla)\\(.+?\\))|\\B#(?:[0-9a-f]{3,4}){1,2}\\b";for(t in Rt)e+="|"+t+"\\b";return new RegExp(e+")","gi")}(),Ft=/hsl[a]?\(/,It=(O=Date.now,M=500,C=33,P=O(),A=P,z=D=1e3/240,g={time:0,frame:0,tick:function tick(){zl(!0)},deltaRatio:function deltaRatio(t){return b/(1e3/(t||60))},wake:function wake(){o&&(!n&&x()&&(h=n=window,a=h.document||{},ht.gsap=Fe,(h.gsapVersions||(h.gsapVersions=[])).push(Fe.version),R(i||h.GreenSockGlobals||!h.gsap&&h||{}),Dt.forEach(zb)),m="undefined"!=typeof requestAnimationFrame&&requestAnimationFrame,p&&g.sleep(),_=m||function(t){return setTimeout(t,z-1e3*g.time+1|0)},d=1,zl(2))},sleep:function sleep(){(m?cancelAnimationFrame:clearTimeout)(p),d=0,_=V},lagSmoothing:function lagSmoothing(t,e){M=t||1/0,C=Math.min(e||33,M)},fps:function fps(t){D=1e3/(t||240),z=1e3*g.time+D},add:function add(n,t,e){var a=t?function(t,e,r,i){n(t,e,r,i),g.remove(a)}:n;return g.remove(n),E[e?"unshift":"push"](a),Lt(),a},remove:function remove(t,e){~(e=E.indexOf(t))&&E.splice(e,1)&&e<=k&&k--},_listeners:E=[]}),Lt=function _wake(){return!d&&It.wake()},Bt={},Nt=/^[\d.\-M][\d.\-,\s]/,Ut=/["']/g,Yt=function _invertEase(e){return function(t){return 1-e(1-t)}},jt=function _parseEase(t,e){return t&&(s(t)?t:Bt[t]||Rb(t))||e};function zl(t){var e,r,i,n,a=O()-A,s=!0===t;if((M<a||a<0)&&(P+=a-C),(0<(e=(i=(A+=a)-P)-z)||s)&&(n=++g.frame,b=i-1e3*g.time,g.time=i/=1e3,z+=e+(D<=e?4:D-e),r=1),s||(p=_(zl)),r)for(k=0;k<E.length;k++)E[k](i,b,n,t)}function dn(t){return t<N?B*t*t:t<.7272727272727273?B*Math.pow(t-1.5/2.75,2)+.75:t<.9090909090909092?B*(t-=2.25/2.75)*t+.9375:B*Math.pow(t-2.625/2.75,2)+.984375}ja("Linear,Quad,Cubic,Quart,Quint,Strong",function(t,e){var r=e<5?e+1:e;Ub(t+",Power"+(r-1),e?function(t){return Math.pow(t,r)}:function(t){return t},function(t){return 1-Math.pow(1-t,r)},function(t){return t<.5?Math.pow(2*t,r)/2:1-Math.pow(2*(1-t),r)/2})}),Bt.Linear.easeNone=Bt.none=Bt.Linear.easeIn,Ub("Elastic",Wb("in"),Wb("out"),Wb()),B=7.5625,N=1/2.75,Ub("Bounce",function(t){return 1-dn(1-t)},dn),Ub("Expo",function(t){return Math.pow(2,10*(t-1))*t+t*t*t*t*t*t*(1-t)}),Ub("Circ",function(t){return-($(1-t*t)-1)}),Ub("Sine",function(t){return 1===t?1:1-H(t*Z)}),Ub("Back",Xb("in"),Xb("out"),Xb()),Bt.SteppedEase=Bt.steps=ht.SteppedEase={config:function config(t,e){void 0===t&&(t=1);var r=1/t,i=t+(e?0:1),n=e?1:0;return function(t){return((i*Mt(0,.99999999,t)|0)+n)*r}}},j.ease=Bt["quad.out"],ja("onComplete,onUpdate,onStart,onRepeat,onReverseComplete,onInterrupt",function(t){return Tt+=t+","+t+"Params,"});var Vt,Xt=function GSCache(t,e){this.id=W++,(t._gsap=this).target=t,this.harness=e,this.get=e?e.get:ia,this.set=e?e.getSetter:ue},qt=((Vt=Animation.prototype).delay=function delay(t){return t||0===t?(this.parent&&this.parent.smoothChildTiming&&this.startTime(this._start+t-this._delay),this._delay=t,this):this._delay},Vt.duration=function duration(t){return arguments.length?this.totalDuration(0<this._repeat?t+(t+this._rDelay)*this._repeat:t):this.totalDuration()&&this._dur},Vt.totalDuration=function totalDuration(t){return arguments.length?(this._dirty=0,Ua(this,this._repeat<0?t:(t-this._repeat*this._rDelay)/(this._repeat+1))):this._tDur},Vt.totalTime=function totalTime(t,e){if(Lt(),!arguments.length)return this._tTime;var r=this._dp;if(r&&r.smoothChildTiming&&this._ts){for(La(this,t),!r._dp||r.parent||Ma(r,this);r&&r.parent;)r.parent._time!==r._start+(0<=r._ts?r._tTime/r._ts:(r.totalDuration()-r._tTime)/-r._ts)&&r.totalTime(r._tTime,!0),r=r.parent;!this.parent&&this._dp.autoRemoveChildren&&(0<this._ts&&t<this._tDur||this._ts<0&&0<t||!this._tDur&&!t)&&Na(this._dp,this,this._start-this._delay)}return(this._tTime!==t||!this._dur&&!e||this._initted&&Math.abs(this._zTime)===q||!this._initted&&this._dur&&t||!t&&!this._initted&&(this.add||this._ptLookup))&&(this._ts||(this._pTime=t),qa(this,t,e)),this},Vt.time=function time(t,e){return arguments.length?this.totalTime(Math.min(this.totalDuration(),t+Ha(this))%(this._dur+this._rDelay)||(t?this._dur:0),e):this._time},Vt.totalProgress=function totalProgress(t,e){return arguments.length?this.totalTime(this.totalDuration()*t,e):this.totalDuration()?Math.min(1,this._tTime/this._tDur):0<=this.rawTime()&&this._initted?1:0},Vt.progress=function progress(t,e){return arguments.length?this.totalTime(this.duration()*(!this._yoyo||1&this.iteration()?t:1-t)+Ha(this),e):this.duration()?Math.min(1,this._time/this._dur):0<this.rawTime()?1:0},Vt.iteration=function iteration(t,e){var r=this.duration()+this._rDelay;return arguments.length?this.totalTime(this._time+(t-1)*r,e):this._repeat?wt(this._tTime,r)+1:1},Vt.timeScale=function timeScale(t,e){if(!arguments.length)return this._rts===-q?0:this._rts;if(this._rts===t)return this;var r=this.parent&&this._ts?Ja(this.parent._time,this):this._tTime;return this._rts=+t||0,this._ts=this._ps||t===-q?0:this._rts,this.totalTime(Mt(-Math.abs(this._delay),this.totalDuration(),r),!1!==e),Ka(this),function _recacheAncestors(t){for(var e=t.parent;e&&e.parent;)e._dirty=1,e.totalDuration(),e=e.parent;return t}(this)},Vt.paused=function paused(t){return arguments.length?(this._ps!==t&&((this._ps=t)?(this._pTime=this._tTime||Math.max(-this._delay,this.rawTime()),this._ts=this._act=0):(Lt(),this._ts=this._rts,this.totalTime(this.parent&&!this.parent.smoothChildTiming?this.rawTime():this._tTime||this._pTime,1===this.progress()&&Math.abs(this._zTime)!==q&&(this._tTime-=q)))),this):this._ps},Vt.startTime=function startTime(t){if(arguments.length){this._start=la(t);var e=this.parent||this._dp;return!e||!e._sort&&this.parent||Na(e,this,this._start-this._delay),this}return this._start},Vt.endTime=function endTime(t){return this._start+(w(t)?this.totalDuration():this.duration())/Math.abs(this._ts||1)},Vt.rawTime=function rawTime(t){var e=this.parent||this._dp;return e?t&&(!this._ts||this._repeat&&this._time&&this.totalProgress()<1)?this._tTime%(this._dur+this._rDelay):this._ts?Ja(e.rawTime(t),this):this._tTime:this._tTime},Vt.revert=function revert(t){void 0===t&&(t=ct);var e=I;return I=t,pa(this)&&(this.timeline&&this.timeline.revert(t),this.totalTime(-.01,t.suppressEvents)),"nested"!==this.data&&!1!==t.kill&&this.kill(),I=e,this},Vt.globalTime=function globalTime(t){for(var e=this,r=arguments.length?t:e.rawTime();e;)r=e._start+r/(Math.abs(e._ts)||1),e=e._dp;return!this.parent&&this._sat?this._sat.globalTime(t):r},Vt.repeat=function repeat(t){return arguments.length?(this._repeat=t===1/0?-2:t,Va(this)):-2===this._repeat?1/0:this._repeat},Vt.repeatDelay=function repeatDelay(t){if(arguments.length){var e=this._time;return this._rDelay=t,Va(this),e?this.time(e):this}return this._rDelay},Vt.yoyo=function yoyo(t){return arguments.length?(this._yoyo=t,this):this._yoyo},Vt.seek=function seek(t,e){return this.totalTime(Ot(this,t),w(e))},Vt.restart=function restart(t,e){return this.play().totalTime(t?-this._delay:0,w(e)),this._dur||(this._zTime=-q),this},Vt.play=function play(t,e){return null!=t&&this.seek(t,e),this.reversed(!1).paused(!1)},Vt.reverse=function reverse(t,e){return null!=t&&this.seek(t||this.totalDuration(),e),this.reversed(!0).paused(!1)},Vt.pause=function pause(t,e){return null!=t&&this.seek(t,e),this.paused(!0)},Vt.resume=function resume(){return this.paused(!1)},Vt.reversed=function reversed(t){return arguments.length?(!!t!==this.reversed()&&this.timeScale(-this._rts||(t?-q:0)),this):this._rts<0},Vt.invalidate=function invalidate(){return this._initted=this._act=0,this._zTime=-q,this},Vt.isActive=function isActive(){var t,e=this.parent||this._dp,r=this._start;return!(e&&!(this._ts&&this._initted&&e.isActive()&&(t=e.rawTime(!0))>=r&&t<this.endTime(!0)-q))},Vt.eventCallback=function eventCallback(t,e,r){var i=this.vars;return 1<arguments.length?(e?(i[t]=e,r&&(i[t+"Params"]=r),"onUpdate"===t&&(this._onUpdate=e)):delete i[t],this):i[t]},Vt.then=function then(t){var i=this,n=i._prom;return new Promise(function(e){function Ao(){var t=i.then;i.then=null,n&&n(),s(r)&&(r=r(i))&&(r.then||r===i)&&(i.then=t),e(r),i.then=t}var r=s(t)?t:sa;i._initted&&1===i.totalProgress()&&0<=i._ts||!i._tTime&&i._ts<0?Ao():i._prom=Ao})},Vt.kill=function kill(){wb(this)},Animation);function Animation(t){this.vars=t,this._delay=+t.delay||0,(this._repeat=t.repeat===1/0?-2:t.repeat||0)&&(this._rDelay=t.repeatDelay||0,this._yoyo=!!t.yoyo||!!t.yoyoEase),this._ts=1,Ua(this,+t.duration,1,1),this.data=t.data,l&&(this._ctx=l).data.push(this),d||It.wake()}ta(qt.prototype,{_time:0,_start:0,_end:0,_tTime:0,_tDur:0,_dirty:0,_repeat:0,_yoyo:!1,parent:null,_initted:!1,_rDelay:0,_ts:1,_dp:0,ratio:0,_zTime:-q,_prom:0,_ps:!1,_rts:1});var Gt=function(i){function Timeline(t,e){var r;return void 0===t&&(t={}),(r=i.call(this,t)||this).labels={},r.smoothChildTiming=!!t.smoothChildTiming,r.autoRemoveChildren=!!t.autoRemoveChildren,r._sort=w(t.sortChildren),L&&Na(t.parent||L,_assertThisInitialized(r),e),t.reversed&&r.reverse(),t.paused&&r.paused(!0),t.scrollTrigger&&Oa(_assertThisInitialized(r),t.scrollTrigger),r}_inheritsLoose(Timeline,i);var e=Timeline.prototype;return e.to=function to(t,e,r){return Ya(0,arguments,this),this},e.from=function from(t,e,r){return Ya(1,arguments,this),this},e.fromTo=function fromTo(t,e,r,i){return Ya(2,arguments,this),this},e.set=function set(t,e,r){return e.duration=0,e.parent=this,ya(e).repeatDelay||(e.repeat=0),e.immediateRender=!!e.immediateRender,new te(t,e,Ot(this,r),1),this},e.call=function call(t,e,r){return Na(this,te.delayedCall(0,t,e),r)},e.staggerTo=function staggerTo(t,e,r,i,n,a,s){return r.duration=e,r.stagger=r.stagger||i,r.onComplete=a,r.onCompleteParams=s,r.parent=this,new te(t,r,Ot(this,n)),this},e.staggerFrom=function staggerFrom(t,e,r,i,n,a,s){return r.runBackwards=1,ya(r).immediateRender=w(r.immediateRender),this.staggerTo(t,e,r,i,n,a,s)},e.staggerFromTo=function staggerFromTo(t,e,r,i,n,a,s,o){return i.startAt=r,ya(i).immediateRender=w(i.immediateRender),this.staggerTo(t,e,i,n,a,s,o)},e.render=function render(t,e,r){var i,n,a,s,o,u,h,l,f,c,d,p,_=this._time,m=this._dirty?this.totalDuration():this._tDur,g=this._dur,v=t<=0?0:la(t),y=this._zTime<0!=t<0&&(this._initted||!g);if(this!==L&&m<v&&0<=t&&(v=m),v!==this._tTime||r||y){if(_!==this._time&&g&&(v+=this._time-_,t+=this._time-_),i=v,f=this._start,u=!(l=this._ts),y&&(g||(_=this._zTime),!t&&e||(this._zTime=t)),this._repeat){if(d=this._yoyo,o=g+this._rDelay,this._repeat<-1&&t<0)return this.totalTime(100*o+t,e,r);if(i=la(v%o),v===m?(s=this._repeat,i=g):((s=~~(c=la(v/o)))&&s===c&&(i=g,s--),g<i&&(i=g)),c=wt(this._tTime,o),!_&&this._tTime&&c!==s&&this._tTime-c*o-this._dur<=0&&(c=s),d&&1&s&&(i=g-i,p=1),s!==c&&!this._lock){var T=d&&1&c,b=T===(d&&1&s);if(s<c&&(T=!T),_=T?0:v%g?g:v,this._lock=1,this.render(_||(p?0:la(s*o)),e,!g)._lock=0,this._tTime=v,!e&&this.parent&&At(this,"onRepeat"),this.vars.repeatRefresh&&!p&&(this.invalidate()._lock=1,c=s),_&&_!==this._time||u!=!this._ts||this.vars.onRepeat&&!this.parent&&!this._act)return this;if(g=this._dur,m=this._tDur,b&&(this._lock=2,_=T?g:-1e-4,this.render(_,!0),this.vars.repeatRefresh&&!p&&this.invalidate()),this._lock=0,!this._ts&&!u)return this}}if(this._hasPause&&!this._forcing&&this._lock<2&&(h=function _findNextPauseTween(t,e,r){var i;if(e<r)for(i=t._first;i&&i._start<=r;){if("isPause"===i.data&&i._start>e)return i;i=i._next}else for(i=t._last;i&&i._start>=r;){if("isPause"===i.data&&i._start<e)return i;i=i._prev}}(this,la(_),la(i)))&&(v-=i-(i=h._start)),this._tTime=v,this._time=i,this._act=!!l,this._initted||(this._onUpdate=this.vars.onUpdate,this._initted=1,this._zTime=t,_=0),!_&&v&&g&&!e&&!c&&(At(this,"onStart"),this._tTime!==v))return this;if(_<=i&&0<=t)for(n=this._first;n;){if(a=n._next,(n._act||i>=n._start)&&n._ts&&h!==n){if(n.parent!==this)return this.render(t,e,r);if(n.render(0<n._ts?(i-n._start)*n._ts:(n._dirty?n.totalDuration():n._tDur)+(i-n._start)*n._ts,e,r),i!==this._time||!this._ts&&!u){h=0,a&&(v+=this._zTime=-q);break}}n=a}else{n=this._last;for(var w=t<0?t:i;n;){if(a=n._prev,(n._act||w<=n._end)&&n._ts&&h!==n){if(n.parent!==this)return this.render(t,e,r);if(n.render(0<n._ts?(w-n._start)*n._ts:(n._dirty?n.totalDuration():n._tDur)+(w-n._start)*n._ts,e,r||I&&pa(n)),i!==this._time||!this._ts&&!u){h=0,a&&(v+=this._zTime=w?-q:q);break}}n=a}}if(h&&!e&&(this.pause(),h.render(_<=i?0:-q)._zTime=_<=i?1:-1,this._ts))return this._start=f,Ka(this),this.render(t,e,r);this._onUpdate&&!e&&At(this,"onUpdate",!0),(v===m&&this._tTime>=this.totalDuration()||!v&&_)&&(f!==this._start&&Math.abs(l)===Math.abs(this._ts)||this._lock||(!t&&g||!(v===m&&0<this._ts||!v&&this._ts<0)||Ca(this,1),e||t<0&&!_||!v&&!_&&m||(At(this,v===m&&0<=t?"onComplete":"onReverseComplete",!0),!this._prom||v<m&&0<this.timeScale()||this._prom())))}return this},e.add=function add(e,i){var n=this;if(t(i)||(i=Ot(this,i,e)),!(e instanceof qt)){if(K(e))return e.forEach(function(t){return n.add(t,i)}),this;if(r(e))return this.addLabel(e,i);if(!s(e))return this;e=te.delayedCall(0,e)}return this!==e?Na(this,e,i):this},e.getChildren=function getChildren(t,e,r,i){void 0===t&&(t=!0),void 0===e&&(e=!0),void 0===r&&(r=!0),void 0===i&&(i=-X);for(var n=[],a=this._first;a;)a._start>=i&&(a instanceof te?e&&n.push(a):(r&&n.push(a),t&&n.push.apply(n,a.getChildren(!0,e,r)))),a=a._next;return n},e.getById=function getById(t){for(var e=this.getChildren(1,1,1),r=e.length;r--;)if(e[r].vars.id===t)return e[r]},e.remove=function remove(t){return r(t)?this.removeLabel(t):s(t)?this.killTweensOf(t):(t.parent===this&&Ba(this,t),t===this._recent&&(this._recent=this._last),Da(this))},e.totalTime=function totalTime(t,e){return arguments.length?(this._forcing=1,!this._dp&&this._ts&&(this._start=la(It.time-(0<this._ts?t/this._ts:(this.totalDuration()-t)/-this._ts))),i.prototype.totalTime.call(this,t,e),this._forcing=0,this):this._tTime},e.addLabel=function addLabel(t,e){return this.labels[t]=Ot(this,e),this},e.removeLabel=function removeLabel(t){return delete this.labels[t],this},e.addPause=function addPause(t,e,r){var i=te.delayedCall(0,e||V,r);return i.data="isPause",this._hasPause=1,Na(this,i,Ot(this,t))},e.removePause=function removePause(t){var e=this._first;for(t=Ot(this,t);e;)e._start===t&&"isPause"===e.data&&Ca(e),e=e._next},e.killTweensOf=function killTweensOf(t,e,r){for(var i=this.getTweensOf(t,r),n=i.length;n--;)Zt!==i[n]&&i[n].kill(t,e);return this},e.getTweensOf=function getTweensOf(e,r){for(var i,n=[],a=Pt(e),s=this._first,o=t(r);s;)s instanceof te?na(s._targets,a)&&(o?(!Zt||s._initted&&s._ts)&&s.globalTime(0)<=r&&s.globalTime(s.totalDuration())>r:!r||s.isActive())&&n.push(s):(i=s.getTweensOf(a,r)).length&&n.push.apply(n,i),s=s._next;return n},e.tweenTo=function tweenTo(t,e){e=e||{};var r,i=this,n=Ot(i,t),a=e.startAt,s=e.onStart,o=e.onStartParams,u=e.immediateRender,h=te.to(i,ta({ease:e.ease||"none",lazy:!1,immediateRender:!1,time:n,overwrite:"auto",duration:e.duration||Math.abs((n-(a&&"time"in a?a.time:i._time))/i.timeScale())||q,onStart:function onStart(){if(i.pause(),!r){var t=e.duration||Math.abs((n-(a&&"time"in a?a.time:i._time))/i.timeScale());h._dur!==t&&Ua(h,t,0,1).render(h._time,!0,!0),r=1}s&&s.apply(h,o||[])}},e));return u?h.render(0):h},e.tweenFromTo=function tweenFromTo(t,e,r){return this.tweenTo(e,ta({startAt:{time:Ot(this,t)}},r))},e.recent=function recent(){return this._recent},e.nextLabel=function nextLabel(t){return void 0===t&&(t=this._time),ub(this,Ot(this,t))},e.previousLabel=function previousLabel(t){return void 0===t&&(t=this._time),ub(this,Ot(this,t),1)},e.currentLabel=function currentLabel(t){return arguments.length?this.seek(t,!0):this.previousLabel(this._time+q)},e.shiftChildren=function shiftChildren(t,e,r){void 0===r&&(r=0);var i,n=this._first,a=this.labels;for(t=la(t);n;)n._start>=r&&(n._start+=t,n._end+=t),n=n._next;if(e)for(i in a)a[i]>=r&&(a[i]+=t);return Da(this)},e.invalidate=function invalidate(t){var e=this._first;for(this._lock=0;e;)e.invalidate(t),e=e._next;return i.prototype.invalidate.call(this,t)},e.clear=function clear(t){void 0===t&&(t=!0);for(var e,r=this._first;r;)e=r._next,this.remove(r),r=e;return this._dp&&(this._time=this._tTime=this._pTime=0),t&&(this.labels={}),Da(this)},e.totalDuration=function totalDuration(t){var e,r,i,n=0,a=this,s=a._last,o=X;if(arguments.length)return a.timeScale((a._repeat<0?a.duration():a.totalDuration())/(a.reversed()?-t:t));if(a._dirty){for(i=a.parent;s;)e=s._prev,s._dirty&&s.totalDuration(),o<(r=s._start)&&a._sort&&s._ts&&!a._lock?(a._lock=1,Na(a,s,r-s._delay,1)._lock=0):o=r,r<0&&s._ts&&(n-=r,(!i&&!a._dp||i&&i.smoothChildTiming)&&(a._start+=la(r/a._ts),a._time-=r,a._tTime-=r),a.shiftChildren(-r,!1,-Infinity),o=0),s._end>n&&s._ts&&(n=s._end),s=e;Ua(a,a===L&&a._time>n?a._time:n,1,1),a._dirty=0}return a._tDur},Timeline.updateRoot=function updateRoot(t){if(L._ts&&(qa(L,Ja(t,L)),f=It.frame),It.frame>=vt){vt+=Y.autoSleep||120;var e=L._first;if((!e||!e._ts)&&Y.autoSleep&&It._listeners.length<2){for(;e&&!e._ts;)e=e._next;e||It.sleep()}}},Timeline}(qt);ta(Gt.prototype,{_lock:0,_hasPause:0,_forcing:0});function cc(t,e,i,n,a,o){var u,h,l,f;if(mt[t]&&!1!==(u=new mt[t]).init(a,u.rawVars?e[t]:function _processVars(t,e,i,n,a){if(s(t)&&(t=Qt(t,a,e,i,n)),!v(t)||t.style&&t.nodeType||K(t)||J(t))return r(t)?Qt(t,a,e,i,n):t;var o,u={};for(o in t)u[o]=Qt(t[o],a,e,i,n);return u}(e[t],n,a,o,i),i,n,o)&&(i._pt=h=new we(i._pt,a,t,0,1,u.render,u,0,u.priority),i!==c))for(l=i._ptLookup[i._targets.indexOf(a)],f=u._props.length;f--;)l[u._props[f]]=h;return u}function ic(t,r,e,i){var n,a,s=r.ease||i||"power1.inOut";if(K(r))a=e[t]||(e[t]=[]),r.forEach(function(t,e){return a.push({t:e/(r.length-1)*100,v:t,e:s})});else for(n in r)a=e[n]||(e[n]=[]),"ease"===n||a.push({t:parseFloat(t),v:r[n],e:s})}var Zt,Wt,$t=function _addPropTween(t,e,i,n,a,o,u,h,l,f){s(n)&&(n=n(a||0,t,o));var c,d=t[e],p="get"!==i?i:s(d)?l?t[e.indexOf("set")||!s(t["get"+e.substr(3)])?e:"get"+e.substr(3)](l):t[e]():d,_=s(d)?l?se:ae:ie;if(r(n)&&(~n.indexOf("random(")&&(n=rb(n)),"="===n.charAt(1)&&(!(c=ma(p,n)+(_a(p)||0))&&0!==c||(n=c))),!f||p!==n||Wt)return isNaN(p*n)||""===n?(d||e in t||S(e,n),function _addComplexStringPropTween(t,e,r,i,n,a,s){var o,u,h,l,f,c,d,p,_=new we(this._pt,t,e,0,1,pe,null,n),m=0,g=0;for(_.b=r,_.e=i,r+="",(d=~(i+="").indexOf("random("))&&(i=rb(i)),a&&(a(p=[r,i],t,e),r=p[0],i=p[1]),u=r.match(at)||[];o=at.exec(i);)l=o[0],f=i.substring(m,o.index),h?h=(h+1)%5:"rgba("===f.substr(-5)&&(h=1),l!==u[g++]&&(c=parseFloat(u[g-1])||0,_._pt={_next:_._pt,p:f||1===g?f:",",s:c,c:"="===l.charAt(1)?ma(c,l)-c:parseFloat(l)-c,m:h&&h<4?Math.round:0},m=at.lastIndex);return _.c=m<i.length?i.substring(m,i.length):"",_.fp=s,(st.test(i)||d)&&(_.e=0),this._pt=_}.call(this,t,e,p,n,_,h||Y.stringFilter,l)):(c=new we(this._pt,t,e,+p||0,n-(p||0),"boolean"==typeof d?de:fe,0,_),l&&(c.fp=l),u&&c.modifier(u,this,t),this._pt=c)},Ht=function _initTween(t,e,r){var i,n,a,s,o,u,h,l,f,c,d,p,_,m=t.vars,g=m.ease,v=m.startAt,y=m.immediateRender,T=m.lazy,b=m.onUpdate,x=m.runBackwards,k=m.yoyoEase,O=m.keyframes,M=m.autoRevert,C=t._dur,P=t._startAt,S=t._targets,A=t.parent,D=A&&"nested"===A.data?A.vars.targets:S,z="auto"===t._overwrite&&!F,R=t.timeline,E=m.easeReverse||k;if(!R||O&&g||(g="none"),t._ease=jt(g,j.ease),t._rEase=E&&(jt(E)||t._ease),t._from=!R&&!!m.runBackwards,t._from&&(t.ratio=1),!R||O&&!m.stagger){if(p=(l=S[0]?ha(S[0]).harness:0)&&m[l.prop],i=xa(m,dt),P&&(P._zTime<0&&P.progress(1),e<0&&x&&y&&!M?P.render(-1,!0):P.revert(x&&C?ft:lt),P._lazy=0),v){if(Ca(t._startAt=te.set(S,ta({data:"isStart",overwrite:!1,parent:A,immediateRender:!0,lazy:!P&&w(T),startAt:null,delay:0,onUpdate:b&&function(){return At(t,"onUpdate")},stagger:0},v))),t._startAt._dp=0,t._startAt._sat=t,e<0&&(I||!y&&!M)&&t._startAt.revert(ft),y&&C&&e<=0&&r<=0)return void(e&&(t._zTime=e))}else if(x&&C&&!P)if(e&&(y=!1),a=ta({overwrite:!1,data:"isFromStart",lazy:y&&!P&&w(T),immediateRender:y,stagger:0,parent:A},i),p&&(a[l.prop]=p),Ca(t._startAt=te.set(S,a)),t._startAt._dp=0,t._startAt._sat=t,e<0&&(I?t._startAt.revert(ft):t._startAt.render(-1,!0)),t._zTime=e,y){if(!e)return}else _initTween(t._startAt,q,q);for(t._pt=t._ptCache=0,T=C&&w(T)||T&&!C,n=0;n<S.length;n++){if(h=(o=S[n])._gsap||ga(S)[n]._gsap,t._ptLookup[n]=c={},_t[h.id]&&pt.length&&oa(),d=D===S?n:D.indexOf(o),l&&!1!==(f=new l).init(o,p||i,t,d,D)&&(t._pt=s=new we(t._pt,o,f.name,0,1,f.render,f,0,f.priority),f._props.forEach(function(t){c[t]=s}),f.priority&&(u=1)),!l||p)for(a in i)mt[a]&&(f=cc(a,i,t,d,o,D))?f.priority&&(u=1):c[a]=s=$t.call(t,o,a,"get",i[a],d,D,0,m.stringFilter);t._op&&t._op[n]&&t.kill(o,t._op[n]),z&&t._pt&&(Zt=t,L.killTweensOf(o,c,t.globalTime(e)),_=!t.parent,Zt=0),t._pt&&T&&(_t[h.id]=1)}u&&be(t),t._onInit&&t._onInit(t)}t._onUpdate=b,t._initted=(!t._op||t._pt)&&!_,O&&e<=0&&R.render(X,!0,!0)},Qt=function _parseFuncOrString(t,e,i,n,a){return s(t)?t.call(e,i,n,a):r(t)&&~t.indexOf("random(")?rb(t):t},Jt=Tt+"repeat,repeatDelay,yoyo,repeatRefresh,yoyoEase,easeReverse,autoRevert",Kt={};ja(Jt+",id,stagger,delay,duration,paused,scrollTrigger",function(t){return Kt[t]=1});var te=function(E){function Tween(e,r,i,n){var a;"number"==typeof r&&(i.duration=r,r=i,i=null);var s,o,u,h,l,f,c,d,p=(a=E.call(this,n?r:ya(r))||this).vars,_=p.duration,m=p.delay,g=p.immediateRender,b=p.stagger,x=p.overwrite,k=p.keyframes,O=p.defaults,M=p.scrollTrigger,C=r.parent||L,P=(K(e)||J(e)?t(e[0]):"length"in r)?[e]:Pt(e);if(a._targets=P.length?ga(P):T("GSAP target "+e+" not found. https://gsap.com",!Y.nullTargetWarn)||[],a._ptLookup=[],a._overwrite=x,k||b||y(_)||y(m)){var S=(r=a.vars).easeReverse||r.yoyoEase;if((s=a.timeline=new Gt({data:"nested",defaults:O||{},targets:C&&"nested"===C.data?C.vars.targets:P})).kill(),s.parent=s._dp=_assertThisInitialized(a),s._start=0,b||y(_)||y(m)){if(h=P.length,c=b&&hb(b),v(b))for(l in b)~Jt.indexOf(l)&&((d=d||{})[l]=b[l]);for(o=0;o<h;o++)(u=xa(r,Kt)).stagger=0,S&&(u.easeReverse=S),d&&bt(u,d),f=P[o],u.duration=+Qt(_,_assertThisInitialized(a),o,f,P),u.delay=(+Qt(m,_assertThisInitialized(a),o,f,P)||0)-a._delay,!b&&1===h&&u.delay&&(a._delay=m=u.delay,a._start+=m,u.delay=0),s.to(f,u,c?c(o,f,P):0),s._ease=Bt.none;s.duration()?_=m=0:a.timeline=0}else if(k){ya(ta(s.vars.defaults,{ease:"none"})),s._ease=jt(k.ease||r.ease||"none");var A,D,z,R=0;if(K(k))k.forEach(function(t){return s.to(P,t,">")}),s.duration();else{for(l in u={},k)"ease"===l||"easeEach"===l||ic(l,k[l],u,k.easeEach);for(l in u)for(A=u[l].sort(function(t,e){return t.t-e.t}),o=R=0;o<A.length;o++)(z={ease:(D=A[o]).e,duration:(D.t-(o?A[o-1].t:0))/100*_})[l]=D.v,s.to(P,z,R),R+=z.duration;s.duration()<_&&s.to({},{duration:_-s.duration()})}}_||a.duration(_=s.duration())}else a.timeline=0;return!0!==x||F||(Zt=_assertThisInitialized(a),L.killTweensOf(P),Zt=0),Na(C,_assertThisInitialized(a),i),r.reversed&&a.reverse(),r.paused&&a.paused(!0),(g||!_&&!k&&a._start===la(C._time)&&w(g)&&function _hasNoPausedAncestors(t){return!t||t._ts&&_hasNoPausedAncestors(t.parent)}(_assertThisInitialized(a))&&"nested"!==C.data)&&(a._tTime=-q,a.render(Math.max(0,-m)||0)),M&&Oa(_assertThisInitialized(a),M),a}_inheritsLoose(Tween,E);var e=Tween.prototype;return e.render=function render(t,e,r){var i,n,a,s,o,u,h,l,f=this._time,c=this._tDur,d=this._dur,p=t<0,_=c-q<t&&!p?c:t<q?0:t;if(d){if(_!==this._tTime||!t||r||!this._initted&&this._tTime||this._startAt&&this._zTime<0!=p||this._lazy){if(i=_,l=this.timeline,this._repeat){if(s=d+this._rDelay,this._repeat<-1&&p)return this.totalTime(100*s+t,e,r);if(i=la(_%s),_===c?(a=this._repeat,i=d):(a=~~(o=la(_/s)))&&a===o?(i=d,a--):d<i&&(i=d),(u=this._yoyo&&1&a)&&(i=d-i),o=wt(this._tTime,s),i===f&&!r&&this._initted&&a===o)return this._tTime=_,this;a!==o&&this.vars.repeatRefresh&&!u&&!this._lock&&i!==s&&this._initted&&(this._lock=r=1,this.render(la(s*a),!0).invalidate()._lock=0)}if(!this._initted){if(Pa(this,p?t:i,r,e,_))return this._tTime=0,this;if(!(f===this._time||r&&this.vars.repeatRefresh&&a!==o))return this;if(d!==this._dur)return this.render(t,e,r)}if(this._rEase){var m=i<f;if(m!==this._inv){var g=m?f:d-f;this._inv=m,this._from&&(this.ratio=1-this.ratio),this._invRatio=this.ratio,this._invTime=f,this._invRecip=g?(m?-1:1)/g:0,this._invScale=m?-this.ratio:1-this.ratio,this._invEase=m?this._rEase:this._ease}this.ratio=h=this._invRatio+this._invScale*this._invEase((i-this._invTime)*this._invRecip)}else this.ratio=h=this._ease(i/d);if(this._from&&(this.ratio=h=1-h),this._tTime=_,this._time=i,!this._act&&this._ts&&(this._act=1,this._lazy=0),!f&&_&&!e&&!o&&(At(this,"onStart"),this._tTime!==_))return this;for(n=this._pt;n;)n.r(h,n.d),n=n._next;l&&l.render(t<0?t:l._dur*l._ease(i/this._dur),e,r)||this._startAt&&(this._zTime=t),this._onUpdate&&!e&&(p&&Fa(this,t,0,r),At(this,"onUpdate")),this._repeat&&a!==o&&this.vars.onRepeat&&!e&&this.parent&&At(this,"onRepeat"),_!==this._tDur&&_||this._tTime!==_||(p&&!this._onUpdate&&Fa(this,t,0,!0),!t&&d||!(_===this._tDur&&0<this._ts||!_&&this._ts<0)||Ca(this,1),e||p&&!f||!(_||f||u)||(At(this,_===c?"onComplete":"onReverseComplete",!0),!this._prom||_<c&&0<this.timeScale()||this._prom()))}}else!function _renderZeroDurationTween(t,e,r,i){var n,a,s,o=t.ratio,u=e<0||!e&&(!t._start&&function _parentPlayheadIsBeforeStart(t){var e=t.parent;return e&&e._ts&&e._initted&&!e._lock&&(e.rawTime()<0||_parentPlayheadIsBeforeStart(e))}(t)&&(t._initted||!xt(t))||(t._ts<0||t._dp._ts<0)&&!xt(t))?0:1,h=t._rDelay,l=0;if(h&&t._repeat&&(l=Mt(0,t._tDur,e),a=wt(l,h),t._yoyo&&1&a&&(u=1-u),a!==wt(t._tTime,h)&&(o=1-u,t.vars.repeatRefresh&&t._initted&&t.invalidate())),u!==o||I||i||t._zTime===q||!e&&t._zTime){if(!t._initted&&Pa(t,e,i,r,l))return;for(s=t._zTime,t._zTime=e||(r?q:0),r=r||e&&!s,t.ratio=u,t._from&&(u=1-u),t._time=0,t._tTime=l,n=t._pt;n;)n.r(u,n.d),n=n._next;e<0&&Fa(t,e,0,!0),t._onUpdate&&!r&&At(t,"onUpdate"),l&&t._repeat&&!r&&t.parent&&At(t,"onRepeat"),(e>=t._tDur||e<0)&&t.ratio===u&&(u&&Ca(t,1),r||I||(At(t,u?"onComplete":"onReverseComplete",!0),t._prom&&t._prom()))}else t._zTime||(t._zTime=e)}(this,t,e,r);return this},e.targets=function targets(){return this._targets},e.invalidate=function invalidate(t){return t&&this.vars.runBackwards||(this._startAt=0),this._pt=this._op=this._onUpdate=this._lazy=this.ratio=0,this._ptLookup=[],this.timeline&&this.timeline.invalidate(t),E.prototype.invalidate.call(this,t)},e.resetTo=function resetTo(t,e,r,i,n){d||It.wake(),this._ts||this.play();var a,s=Math.min(this._dur,(this._dp._time-this._start)*this._ts);return this._initted||Ht(this,s),a=this._ease(s/this._dur),function _updatePropTweens(t,e,r,i,n,a,s,o){var u,h,l,f,c=(t._pt&&t._ptCache||(t._ptCache={}))[e];if(!c)for(c=t._ptCache[e]=[],l=t._ptLookup,f=t._targets.length;f--;){if((u=l[f][e])&&u.d&&u.d._pt)for(u=u.d._pt;u&&u.p!==e&&u.fp!==e;)u=u._next;if(!u)return Wt=1,t.vars[e]="+=0",Ht(t,s),Wt=0,o?T(e+" not eligible for reset. Try splitting into individual properties"):1;c.push(u)}for(f=c.length;f--;)(u=(h=c[f])._pt||h).s=!i&&0!==i||n?u.s+(i||0)+a*u.c:i,u.c=r-u.s,h.e&&(h.e=ka(r)+_a(h.e)),h.b&&(h.b=u.s+_a(h.b))}(this,t,e,r,i,a,s,n)?this.resetTo(t,e,r,i,1):(La(this,0),this.parent||Aa(this._dp,this,"_first","_last",this._dp._sort?"_start":0),this.render(0))},e.kill=function kill(t,e){if(void 0===e&&(e="all"),!(t||e&&"all"!==e))return this._lazy=this._pt=0,this.parent?wb(this):this.scrollTrigger&&this.scrollTrigger.kill(!!I),this;if(this.timeline){var i=this.timeline.totalDuration();return this.timeline.killTweensOf(t,e,Zt&&!0!==Zt.vars.overwrite)._first||wb(this),this.parent&&i!==this.timeline.totalDuration()&&Ua(this,this._dur*this.timeline._tDur/i,0,1),this}var n,a,s,o,u,h,l,f=this._targets,c=t?Pt(t):f,d=this._ptLookup,p=this._pt;if((!e||"all"===e)&&function _arraysMatch(t,e){for(var r=t.length,i=r===e.length;i&&r--&&t[r]===e[r];);return r<0}(f,c))return"all"===e&&(this._pt=0),wb(this);for(n=this._op=this._op||[],"all"!==e&&(r(e)&&(u={},ja(e,function(t){return u[t]=1}),e=u),e=function _addAliasesToVars(t,e){var r,i,n,a,s=t[0]?ha(t[0]).harness:0,o=s&&s.aliases;if(!o)return e;for(i in r=bt({},e),o)if(i in r)for(n=(a=o[i].split(",")).length;n--;)r[a[n]]=r[i];return r}(f,e)),l=f.length;l--;)if(~c.indexOf(f[l]))for(u in a=d[l],"all"===e?(n[l]=e,o=a,s={}):(s=n[l]=n[l]||{},o=e),o)(h=a&&a[u])&&("kill"in h.d&&!0!==h.d.kill(u)||Ba(this,h,"_pt"),delete a[u]),"all"!==s&&(s[u]=1);return this._initted&&!this._pt&&p&&wb(this),this},Tween.to=function to(t,e,r){return new Tween(t,e,r)},Tween.from=function from(t,e){return Ya(1,arguments)},Tween.delayedCall=function delayedCall(t,e,r,i){return new Tween(e,0,{immediateRender:!1,lazy:!1,overwrite:!1,delay:t,onComplete:e,onReverseComplete:e,onCompleteParams:r,onReverseCompleteParams:r,callbackScope:i})},Tween.fromTo=function fromTo(t,e,r){return Ya(2,arguments)},Tween.set=function set(t,e){return e.duration=0,e.repeatDelay||(e.repeat=0),new Tween(t,e)},Tween.killTweensOf=function killTweensOf(t,e,r){return L.killTweensOf(t,e,r)},Tween}(qt);ta(te.prototype,{_targets:[],_lazy:0,_startAt:0,_op:0,_onInit:0}),ja("staggerTo,staggerFrom,staggerFromTo",function(r){te[r]=function(){var t=new Gt,e=Ct.call(arguments,0);return e.splice("staggerFromTo"===r?5:4,0,0),t[r].apply(t,e)}});function qc(t,e,r){return t.setAttribute(e,r)}function yc(t,e,r,i){i.mSet(t,e,i.m.call(i.tween,r,i.mt),i)}var ie=function _setterPlain(t,e,r){return t[e]=r},ae=function _setterFunc(t,e,r){return t[e](r)},se=function _setterFuncWithParam(t,e,r,i){return t[e](i.fp,r)},ue=function _getSetter(t,e){return s(t[e])?ae:u(t[e])&&t.setAttribute?qc:ie},fe=function _renderPlain(t,e){return e.set(e.t,e.p,Math.round(1e6*(e.s+e.c*t))/1e6,e)},de=function _renderBoolean(t,e){return e.set(e.t,e.p,!!(e.s+e.c*t),e)},pe=function _renderComplexString(t,e){var r=e._pt,i="";if(!t&&e.b)i=e.b;else if(1===t&&e.e)i=e.e;else{for(;r;)i=r.p+(r.m?r.m(r.s+r.c*t):Math.round(1e4*(r.s+r.c*t))/1e4)+i,r=r._next;i+=e.c}e.set(e.t,e.p,i,e)},_e=function _renderPropTweens(t,e){for(var r=e._pt;r;)r.r(t,r.d),r=r._next},ve=function _addPluginModifier(t,e,r,i){for(var n,a=this._pt;a;)n=a._next,a.p===i&&a.modifier(t,e,r),a=n},Te=function _killPropTweensOf(t){for(var e,r,i=this._pt;i;)r=i._next,i.p===t&&!i.op||i.op===t?Ba(this,i,"_pt"):i.dep||(e=1),i=r;return!e},be=function _sortPropTweensByPriority(t){for(var e,r,i,n,a=t._pt;a;){for(e=a._next,r=i;r&&r.pr>a.pr;)r=r._next;(a._prev=r?r._prev:n)?a._prev._next=a:i=a,(a._next=r)?r._prev=a:n=a,a=e}t._pt=i},we=(PropTween.prototype.modifier=function modifier(t,e,r){this.mSet=this.mSet||this.set,this.set=yc,this.m=t,this.mt=r,this.tween=e},PropTween);function PropTween(t,e,r,i,n,a,s,o,u){this.t=e,this.s=i,this.c=n,this.p=r,this.r=a||fe,this.d=s||this,this.set=o||ie,this.pr=u||0,(this._next=t)&&(t._prev=this)}ja(Tt+"parent,duration,ease,delay,overwrite,runBackwards,startAt,yoyo,immediateRender,repeat,repeatDelay,data,paused,reversed,lazy,callbackScope,stringFilter,id,yoyoEase,stagger,inherit,repeatRefresh,keyframes,autoRevert,scrollTrigger,easeReverse",function(t){return dt[t]=1}),ht.TweenMax=ht.TweenLite=te,ht.TimelineLite=ht.TimelineMax=Gt,L=new Gt({sortChildren:!1,defaults:j,autoRemoveChildren:!0,id:"root",smoothChildTiming:!0}),Y.stringFilter=Ib;function Gc(t){return(Oe[t]||Me).map(function(t){return t()})}function Hc(){var t=Date.now(),o=[];2<t-Ce&&(Gc("matchMediaInit"),ke.forEach(function(t){var e,r,i,n,a=t.queries,s=t.conditions;for(r in a)(e=h.matchMedia(a[r]).matches)&&(i=1),e!==s[r]&&(s[r]=e,n=1);n&&(t.revert(),i&&o.push(t))}),Gc("matchMediaRevert"),o.forEach(function(e){return e.onMatch(e,function(t){return e.add(null,t)})}),Ce=t,Gc("matchMedia"))}var xe,ke=[],Oe={},Me=[],Ce=0,Pe=0,Se=((xe=Context.prototype).add=function add(t,i,n){function Gw(){var t,e=l,r=a.selector;return e&&e!==a&&e.data.push(a),n&&(a.selector=fb(n)),l=a,t=i.apply(a,arguments),s(t)&&a._r.push(t),l=e,a.selector=r,a.isReverted=!1,t}s(t)&&(n=i,i=t,t=s);var a=this;return a.last=Gw,t===s?Gw(a,function(t){return a.add(null,t)}):t?a[t]=Gw:Gw},xe.ignore=function ignore(t){var e=l;l=null,t(this),l=e},xe.getTweens=function getTweens(){var e=[];return this.data.forEach(function(t){return t instanceof Context?e.push.apply(e,t.getTweens()):t instanceof te&&!(t.parent&&"nested"===t.parent.data)&&e.push(t)}),e},xe.clear=function clear(){this._r.length=this.data.length=0},xe.kill=function kill(i,t){var n=this;if(i?function(){for(var t,e=n.getTweens(),r=n.data.length;r--;)"isFlip"===(t=n.data[r]).data&&(t.revert(),t.getChildren(!0,!0,!1).forEach(function(t){return e.splice(e.indexOf(t),1)}));for(e.map(function(t){return{g:t._dur||t._delay||t._sat&&!t._sat.vars.immediateRender?t.globalTime(0):-1/0,t:t}}).sort(function(t,e){return e.g-t.g||-1/0}).forEach(function(t){return t.t.revert(i)}),r=n.data.length;r--;)(t=n.data[r])instanceof Gt?"nested"!==t.data&&(t.scrollTrigger&&t.scrollTrigger.revert(),t.kill()):t instanceof te||!t.revert||t.revert(i);n._r.forEach(function(t){return t(i,n)}),n.isReverted=!0}():this.data.forEach(function(t){return t.kill&&t.kill()}),this.clear(),t)for(var e=ke.length;e--;)ke[e].id===this.id&&ke.splice(e,1)},xe.revert=function revert(t){this.kill(t||{})},Context);function Context(t,e){this.selector=e&&fb(e),this.data=[],this._r=[],this.isReverted=!1,this.id=Pe++,t&&this.add(t)}var De,Re=((De=MatchMedia.prototype).add=function add(t,e,r){v(t)||(t={matches:t});var i,n,a,s=new Se(0,r||this.scope),o=s.conditions={};for(n in l&&!s.selector&&(s.selector=l.selector),this.contexts.push(s),e=s.add("onMatch",e),s.queries=t)"all"===n?a=1:(i=h.matchMedia(t[n]))&&(ke.indexOf(s)<0&&ke.push(s),(o[n]=i.matches)&&(a=1),i.addListener?i.addListener(Hc):i.addEventListener("change",Hc));return a&&e(s,function(t){return s.add(null,t)}),this},De.revert=function revert(t){this.kill(t||{})},De.kill=function kill(e){this.contexts.forEach(function(t){return t.kill(e,!0)})},MatchMedia);function MatchMedia(t){this.contexts=[],this.scope=t,l&&l.data.push(this)}var Ee={registerPlugin:function registerPlugin(){for(var t=arguments.length,e=new Array(t),r=0;r<t;r++)e[r]=arguments[r];e.forEach(function(t){return zb(t)})},timeline:function timeline(t){return new Gt(t)},getTweensOf:function getTweensOf(t,e){return L.getTweensOf(t,e)},getProperty:function getProperty(i,t,e,n){r(i)&&(i=Pt(i)[0]);var a=ha(i||{}).get,s=e?sa:ra;return"native"===e&&(e=""),i?t?s((mt[t]&&mt[t].get||a)(i,t,e,n)):function(t,e,r){return s((mt[t]&&mt[t].get||a)(i,t,e,r))}:i},quickSetter:function quickSetter(r,e,i){if(1<(r=Pt(r)).length){var n=r.map(function(t){return Fe.quickSetter(t,e,i)}),a=n.length;return function(t){for(var e=a;e--;)n[e](t)}}r=r[0]||{};var s=mt[e],o=ha(r),u=o.harness&&(o.harness.aliases||{})[e]||e,h=s?function(t){var e=new s;c._pt=0,e.init(r,i?t+i:t,c,0,[r]),e.render(1,e),c._pt&&_e(1,c)}:o.set(r,u);return s?h:function(t){return h(r,u,i?t+i:t,o,1)}},quickTo:function quickTo(t,i,e){function $x(t,e,r){return n.resetTo(i,t,e,r)}var r,n=Fe.to(t,ta(((r={})[i]="+=0.1",r.paused=!0,r.stagger=0,r),e||{}));return $x.tween=n,$x},isTweening:function isTweening(t){return 0<L.getTweensOf(t,!0).length},defaults:function defaults(t){return t&&t.ease&&(t.ease=jt(t.ease,j.ease)),wa(j,t||{})},config:function config(t){return wa(Y,t||{})},registerEffect:function registerEffect(t){var i=t.name,n=t.effect,e=t.plugins,a=t.defaults,r=t.extendTimeline;(e||"").split(",").forEach(function(t){return t&&!mt[t]&&!ht[t]&&T(i+" effect requires "+t+" plugin.")}),gt[i]=function(t,e,r){return n(Pt(t),ta(e||{},a),r)},r&&(Gt.prototype[i]=function(t,e,r){return this.add(gt[i](t,v(e)?e:(r=e)&&{},this),r)})},registerEase:function registerEase(t,e){Bt[t]=jt(e)},parseEase:function parseEase(t,e){return arguments.length?jt(t,e):Bt},getById:function getById(t){return L.getById(t)},exportRoot:function exportRoot(t,e){void 0===t&&(t={});var r,i,n=new Gt(t);for(n.smoothChildTiming=w(t.smoothChildTiming),L.remove(n),n._dp=0,n._time=n._tTime=L._time,r=L._first;r;)i=r._next,!e&&!r._dur&&r instanceof te&&r.vars.onComplete===r._targets[0]||Na(n,r,r._start-r._delay),r=i;return Na(L,n,0),n},context:function context(t,e){return t?new Se(t,e):l},matchMedia:function matchMedia(t){return new Re(t)},matchMediaRefresh:function matchMediaRefresh(){return ke.forEach(function(t){var e,r,i=t.conditions;for(r in i)i[r]&&(i[r]=!1,e=1);e&&t.revert()})||Hc()},addEventListener:function addEventListener(t,e){var r=Oe[t]||(Oe[t]=[]);~r.indexOf(e)||r.push(e)},removeEventListener:function removeEventListener(t,e){var r=Oe[t],i=r&&r.indexOf(e);0<=i&&r.splice(i,1)},utils:{wrap:function wrap(e,t,r){var i=t-e;return K(e)?ob(e,wrap(0,e.length),t):Za(r,function(t){return(i+(t-e)%i)%i+e})},wrapYoyo:function wrapYoyo(e,t,r){var i=t-e,n=2*i;return K(e)?ob(e,wrapYoyo(0,e.length-1),t):Za(r,function(t){return e+(i<(t=(n+(t-e)%n)%n||0)?n-t:t)})},distribute:hb,random:kb,snap:jb,normalize:function normalize(t,e,r){return St(t,e,0,1,r)},getUnit:_a,clamp:function clamp(e,r,t){return Za(t,function(t){return Mt(e,r,t)})},splitColor:Db,toArray:Pt,selector:fb,mapRange:St,pipe:function pipe(){for(var t=arguments.length,e=new Array(t),r=0;r<t;r++)e[r]=arguments[r];return function(t){return e.reduce(function(t,e){return e(t)},t)}},unitize:function unitize(e,r){return function(t){return e(parseFloat(t))+(r||_a(t))}},interpolate:function interpolate(e,i,t,n){var a=isNaN(e+i)?0:function(t){return(1-t)*e+t*i};if(!a){var s,o,u,h,l,f=r(e),c={};if(!0===t&&(n=1)&&(t=null),f)e={p:e},i={p:i};else if(K(e)&&!K(i)){for(u=[],h=e.length,l=h-2,o=1;o<h;o++)u.push(interpolate(e[o-1],e[o]));h--,a=function func(t){t*=h;var e=Math.min(l,~~t);return u[e](t-e)},t=i}else n||(e=bt(K(e)?[]:{},e));if(!u){for(s in i)$t.call(c,e,s,"get",i[s]);a=function func(t){return _e(t,c)||(f?e.p:e)}}}return Za(t,a)},shuffle:gb},install:R,effects:gt,ticker:It,updateRoot:Gt.updateRoot,plugins:mt,globalTimeline:L,core:{PropTween:we,globals:U,Tween:te,Timeline:Gt,Animation:qt,getCache:ha,_removeLinkedListItem:Ba,reverting:function reverting(){return I},context:function context(t){return t&&l&&(l.data.push(t),t._ctx=l),l},suppressOverwrites:function suppressOverwrites(t){return F=t}}};ja("to,from,fromTo,delayedCall,set,killTweensOf",function(t){return Ee[t]=te[t]}),It.add(Gt.updateRoot),c=Ee.to({},{duration:0});function Lc(t,e){for(var r=t._pt;r&&r.p!==e&&r.op!==e&&r.fp!==e;)r=r._next;return r}function Nc(t,a){return{name:t,headless:1,rawVars:1,init:function init(t,n,e){e._onInit=function(t){var e,i;if(r(n)&&(e={},ja(n,function(t){return e[t]=1}),n=e),a){for(i in e={},n)e[i]=a(n[i]);n=e}!function _addModifiers(t,e){var r,i,n,a=t._targets;for(r in e)for(i=a.length;i--;)(n=(n=t._ptLookup[i][r])&&n.d)&&(n._pt&&(n=Lc(n,r)),n&&n.modifier&&n.modifier(e[r],t,a[i],r))}(t,n)}}}}var Fe=Ee.registerPlugin({name:"attr",init:function init(t,e,r,i,n){var a,s,o;for(a in this.tween=r,e)o=t.getAttribute(a)||"",(s=this.add(t,"setAttribute",(o||0)+"",e[a],i,n,0,0,a)).op=a,s.b=o,this._props.push(a)},render:function render(t,e){for(var r=e._pt;r;)I?r.set(r.t,r.p,r.b,r):r.r(t,r.d),r=r._next}},{name:"endArray",headless:1,init:function init(t,e){for(var r=e.length;r--;)this.add(t,r,t[r]||0,e[r],0,0,0,0,0,1)}},Nc("roundProps",ib),Nc("modifiers"),Nc("snap",jb))||Ee;te.version=Gt.version=Fe.version="3.15.0",o=1,x()&&Lt();function xd(t,e){return e.set(e.t,e.p,Math.round(1e4*(e.s+e.c*t))/1e4+e.u,e)}function yd(t,e){return e.set(e.t,e.p,1===t?e.e:Math.round(1e4*(e.s+e.c*t))/1e4+e.u,e)}function zd(t,e){return e.set(e.t,e.p,t?Math.round(1e4*(e.s+e.c*t))/1e4+e.u:e.b,e)}function Ad(t,e){return e.set(e.t,e.p,1===t?e.e:t?Math.round(1e4*(e.s+e.c*t))/1e4+e.u:e.b,e)}function Bd(t,e){var r=e.s+e.c*t;e.set(e.t,e.p,~~(r+(r<0?-.5:.5))+e.u,e)}function Cd(t,e){return e.set(e.t,e.p,t?e.e:e.b,e)}function Dd(t,e){return e.set(e.t,e.p,1!==t?e.b:e.e,e)}function Ed(t,e,r){return t.style[e]=r}function Fd(t,e,r){return t.style.setProperty(e,r)}function Gd(t,e,r){return t._gsap[e]=r}function Hd(t,e,r){return t._gsap.scaleX=t._gsap.scaleY=r}function Id(t,e,r,i,n){var a=t._gsap;a.scaleX=a.scaleY=r,a.renderTransform(n,a)}function Jd(t,e,r,i,n){var a=t._gsap;a[e]=r,a.renderTransform(n,a)}function Md(t,e){var r=this,i=this.target,n=i.style,a=i._gsap;if(t in ur&&n){if(this.tfm=this.tfm||{},"transform"===t)return _r.transform.split(",").forEach(function(t){return Md.call(r,t,e)});if(~(t=_r[t]||t).indexOf(",")?t.split(",").forEach(function(t){return r.tfm[t]=wr(i,t)}):this.tfm[t]=a.x?a[t]:wr(i,t),t===gr&&(this.tfm.zOrigin=a.zOrigin),0<=this.props.indexOf(mr))return;a.svg&&(this.svgo=i.getAttribute("data-svg-origin"),this.props.push(gr,e,"")),t=mr}(n||e)&&this.props.push(t,e,n[t])}function Nd(t){t.translate&&(t.removeProperty("translate"),t.removeProperty("scale"),t.removeProperty("rotate"))}function Od(){var t,e,r=this.props,i=this.target,n=i.style,a=i._gsap;for(t=0;t<r.length;t+=3)r[t+1]?2===r[t+1]?i[r[t]](r[t+2]):i[r[t]]=r[t+2]:r[t+2]?n[r[t]]=r[t+2]:n.removeProperty("--"===r[t].substr(0,2)?r[t]:r[t].replace(cr,"-$1").toLowerCase());if(this.tfm){for(e in this.tfm)a[e]=this.tfm[e];a.svg&&(a.renderTransform(),i.setAttribute("data-svg-origin",this.svgo||"")),(t=je())&&t.isStart||n[mr]||(Nd(n),a.zOrigin&&n[gr]&&(n[gr]+=" "+a.zOrigin+"px",a.zOrigin=0,a.renderTransform()),a.uncache=1)}}function Pd(t,e){var r={target:t,props:[],revert:Od,save:Md};return t._gsap||Fe.core.getCache(t),e&&t.style&&t.nodeType&&e.split(",").forEach(function(t){return r.save(t)}),r}function Rd(t,e){var r=Le.createElementNS?Le.createElementNS((e||"http://www.w3.org/1999/xhtml").replace(/^https/,"http"),t):Le.createElement(t);return r&&r.style?r:Le.createElement(t)}function Sd(t,e,r){var i=getComputedStyle(t);return i[e]||i.getPropertyValue(e.replace(cr,"-$1").toLowerCase())||i.getPropertyValue(e)||!r&&Sd(t,yr(e)||e,1)||""}function Vd(){(function _windowExists(){return"undefined"!=typeof window})()&&window.document&&(Ie=window,Le=Ie.document,Be=Le.documentElement,Ue=Rd("div")||{style:{}},Rd("div"),mr=yr(mr),gr=mr+"Origin",Ue.style.cssText="border-width:0;line-height:0;position:absolute;padding:0",Ve=!!yr("perspective"),je=Fe.core.reverting,Ne=1)}function Wd(t){var e,r=t.ownerSVGElement,i=Rd("svg",r&&r.getAttribute("xmlns")||"http://www.w3.org/2000/svg"),n=t.cloneNode(!0);n.style.display="block",i.appendChild(n),Be.appendChild(i);try{e=n.getBBox()}catch(t){}return i.removeChild(n),Be.removeChild(i),e}function Xd(t,e){for(var r=e.length;r--;)if(t.hasAttribute(e[r]))return t.getAttribute(e[r])}function Yd(e){var r,i;try{r=e.getBBox()}catch(t){r=Wd(e),i=1}return r&&(r.width||r.height)||i||(r=Wd(e)),!r||r.width||r.x||r.y?r:{x:+Xd(e,["x","cx","x1"])||0,y:+Xd(e,["y","cy","y1"])||0,width:0,height:0}}function Zd(t){return!(!t.getCTM||t.parentNode&&!t.ownerSVGElement||!Yd(t))}function $d(t,e){if(e){var r,i=t.style;e in ur&&e!==gr&&(e=mr),i.removeProperty?("ms"!==(r=e.substr(0,2))&&"webkit"!==e.substr(0,6)||(e="-"+e),i.removeProperty("--"===r?e:e.replace(cr,"-$1").toLowerCase())):i.removeAttribute(e)}}function _d(t,e,r,i,n,a){var s=new we(t._pt,e,r,0,1,a?Dd:Cd);return(t._pt=s).b=i,s.e=n,t._props.push(r),s}function ce(t,e,r,i){var n,a,s,o,u=parseFloat(r)||0,h=(r+"").trim().substr((u+"").length)||"px",l=Ue.style,f=dr.test(e),c="svg"===t.tagName.toLowerCase(),d=(c?"client":"offset")+(f?"Width":"Height"),p="px"===i,_="%"===i;if(i===h||!u||Tr[i]||Tr[h])return u;if("px"===h||p||(u=ce(t,e,r,"px")),o=t.getCTM&&Zd(t),(_||"%"===h)&&(ur[e]||~e.indexOf("adius")))return n=o?t.getBBox()[f?"width":"height"]:t[d],ka(_?u/n*100:u/100*n);if(l[f?"width":"height"]=100+(p?h:i),a="rem"!==i&&~e.indexOf("adius")||"em"===i&&t.appendChild&&!c?t:t.parentNode,o&&(a=(t.ownerSVGElement||{}).parentNode),a&&a!==Le&&a.appendChild||(a=Le.body),(s=a._gsap)&&_&&s.width&&f&&s.time===It.time&&!s.uncache)return ka(u/s.width*100);if(!_||"height"!==e&&"width"!==e)!_&&"%"!==h||br[Sd(a,"display")]||(l.position=Sd(t,"position")),a===t&&(l.position="static"),a.appendChild(Ue),n=Ue[d],a.removeChild(Ue),l.position="absolute";else{var m=t.style[e];t.style[e]=100+i,n=t[d],m?t.style[e]=m:$d(t,e)}return f&&_&&((s=ha(a)).time=It.time,s.width=a[d]),ka(p?n*u/100:n&&u?100/n*u:0)}function ee(t,e,r,i){if(!r||"none"===r){var n=yr(e,t,1),a=n&&Sd(t,n,1);a&&a!==r?(e=n,r=a):"borderColor"===e&&(r=Sd(t,"borderTopColor"))}var s,o,u,h,l,f,c,d,p,_,m,g=new we(this._pt,t.style,e,0,1,pe),v=0,y=0;if(g.b=r,g.e=i,r+="","var(--"===(i+="").substring(0,6)&&(i=Sd(t,i.substring(4,i.indexOf(")")))),"auto"===i&&(f=t.style[e],t.style[e]=i,i=Sd(t,e)||i,f?t.style[e]=f:$d(t,e)),Ib(s=[r,i]),i=s[1],u=(r=s[0]).match(nt)||[],(i.match(nt)||[]).length){for(;o=nt.exec(i);)c=o[0],p=i.substring(v,o.index),l?l=(l+1)%5:"rgba("!==p.substr(-5)&&"hsla("!==p.substr(-5)||(l=1),c!==(f=u[y++]||"")&&(h=parseFloat(f)||0,m=f.substr((h+"").length),"="===c.charAt(1)&&(c=ma(h,c)+m),d=parseFloat(c),_=c.substr((d+"").length),v=nt.lastIndex-_.length,_||(_=_||Y.units[e]||m,v===i.length&&(i+=_,g.e+=_)),m!==_&&(h=ce(t,e,f,_)||0),g._pt={_next:g._pt,p:p||1===y?p:",",s:h,c:d-h,m:l&&l<4||"zIndex"===e?Math.round:0});g.c=v<i.length?i.substring(v,i.length):""}else g.r="display"===e&&"none"===i?Dd:Cd;return st.test(i)&&(g.e=0),this._pt=g}function ge(t){var e=t.split(" "),r=e[0],i=e[1]||"50%";return"top"!==r&&"bottom"!==r&&"left"!==i&&"right"!==i||(t=r,r=i,i=t),e[0]=xr[r]||r,e[1]=xr[i]||i,e.join(" ")}function he(t,e){if(e.tween&&e.tween._time===e.tween._dur){var r,i,n,a=e.t,s=a.style,o=e.u,u=a._gsap;if("all"===o||!0===o)s.cssText="",i=1;else for(n=(o=o.split(",")).length;-1<--n;)r=o[n],ur[r]&&(i=1,r="transformOrigin"===r?gr:mr),$d(a,r);i&&($d(a,mr),u&&(u.svg&&a.removeAttribute("transform"),s.scale=s.rotate=s.translate="none",Cr(a,1),u.uncache=1,Nd(s)))}}function le(t){return"matrix(1, 0, 0, 1, 0, 0)"===t||"none"===t||!t}function me(t){var e=Sd(t,mr);return le(e)?Or:e.substr(7).match(it).map(ka)}function ne(t,e){var r,i,n,a,s=t._gsap||ha(t),o=t.style,u=me(t);return s.svg&&t.getAttribute("transform")?"1,0,0,1,0,0"===(u=[(n=t.transform.baseVal.consolidate().matrix).a,n.b,n.c,n.d,n.e,n.f]).join(",")?Or:u:(u!==Or||t.offsetParent||t===Be||s.svg||(n=o.display,o.display="block",(r=t.parentNode)&&(t.offsetParent||t.getBoundingClientRect().width)||(a=1,i=t.nextElementSibling,Be.appendChild(t)),u=me(t),n?o.display=n:$d(t,"display"),a&&(i?r.insertBefore(t,i):r?r.appendChild(t):Be.removeChild(t))),e&&6<u.length?[u[0],u[1],u[4],u[5],u[12],u[13]]:u)}function oe(t,e,r,i,n,a){var s,o,u,h=t._gsap,l=n||ne(t,!0),f=h.xOrigin||0,c=h.yOrigin||0,d=h.xOffset||0,p=h.yOffset||0,_=l[0],m=l[1],g=l[2],v=l[3],y=l[4],T=l[5],b=e.split(" "),w=parseFloat(b[0])||0,x=parseFloat(b[1])||0;r?l!==Or&&(o=_*v-m*g)&&(u=w*(-m/o)+x*(_/o)-(_*T-m*y)/o,w=w*(v/o)+x*(-g/o)+(g*T-v*y)/o,x=u):(w=(s=Yd(t)).x+(~b[0].indexOf("%")?w/100*s.width:w),x=s.y+(~(b[1]||b[0]).indexOf("%")?x/100*s.height:x)),i||!1!==i&&h.smooth?(y=w-f,T=x-c,h.xOffset=d+(y*_+T*g)-y,h.yOffset=p+(y*m+T*v)-T):h.xOffset=h.yOffset=0,h.xOrigin=w,h.yOrigin=x,h.smooth=!!i,h.origin=e,h.originIsAbsolute=!!r,t.style[gr]="0px 0px",a&&(_d(a,h,"xOrigin",f,w),_d(a,h,"yOrigin",c,x),_d(a,h,"xOffset",d,h.xOffset),_d(a,h,"yOffset",p,h.yOffset)),t.setAttribute("data-svg-origin",w+" "+x)}function re(t,e,r){var i=_a(e);return ka(parseFloat(e)+parseFloat(ce(t,"x",r+"px",i)))+i}function ye(t,e,i,n,a){var s,o,u=360,h=r(a),l=parseFloat(a)*(h&&~a.indexOf("rad")?hr:1)-n,f=n+l+"deg";return h&&("short"===(s=a.split("_")[1])&&(l%=u)!==l%180&&(l+=l<0?u:-u),"cw"===s&&l<0?l=(l+36e9)%u-~~(l/u)*u:"ccw"===s&&0<l&&(l=(l-36e9)%u-~~(l/u)*u)),t._pt=o=new we(t._pt,e,i,n,l,yd),o.e=f,o.u="deg",t._props.push(i),o}function ze(t,e){for(var r in e)t[r]=e[r];return t}function Ae(t,e,r){var i,n,a,s,o,u,h,l=ze({},r._gsap),f=r.style;for(n in l.svg?(a=r.getAttribute("transform"),r.setAttribute("transform",""),f[mr]=e,i=Cr(r,1),$d(r,mr),r.setAttribute("transform",a)):(a=getComputedStyle(r)[mr],f[mr]=e,i=Cr(r,1),f[mr]=a),ur)(a=l[n])!==(s=i[n])&&"perspective,force3D,transformOrigin,svgOrigin".indexOf(n)<0&&(o=_a(a)!==(h=_a(s))?ce(r,n,a,h):parseFloat(a),u=parseFloat(s),t._pt=new we(t._pt,i,n,o,u-o,xd),t._pt.u=h||0,t._props.push(n));ze(i,l)}var Ie,Le,Be,Ne,Ue,Ye,je,Ve,Xe=Bt.Power0,qe=Bt.Power1,Ge=Bt.Power2,Ze=Bt.Power3,We=Bt.Power4,$e=Bt.Linear,He=Bt.Quad,Qe=Bt.Cubic,Je=Bt.Quart,Ke=Bt.Quint,tr=Bt.Strong,er=Bt.Elastic,rr=Bt.Back,ir=Bt.SteppedEase,nr=Bt.Bounce,ar=Bt.Sine,sr=Bt.Expo,or=Bt.Circ,ur={},hr=180/Math.PI,lr=Math.PI/180,fr=Math.atan2,cr=/([A-Z])/g,dr=/(left|right|width|margin|padding|x)/i,pr=/[\s,\(]\S/,_r={autoAlpha:"opacity,visibility",scale:"scaleX,scaleY",alpha:"opacity"},mr="transform",gr=mr+"Origin",vr="O,Moz,ms,Ms,Webkit".split(","),yr=function _checkPropPrefix(t,e,r){var i=(e||Ue).style,n=5;if(t in i&&!r)return t;for(t=t.charAt(0).toUpperCase()+t.substr(1);n--&&!(vr[n]+t in i););return n<0?null:(3===n?"ms":0<=n?vr[n]:"")+t},Tr={deg:1,rad:1,turn:1},br={grid:1,flex:1},wr=function _get(t,e,r,i){var n;return Ne||Vd(),e in _r&&"transform"!==e&&~(e=_r[e]).indexOf(",")&&(e=e.split(",")[0]),ur[e]&&"transform"!==e?(n=Cr(t,i),n="transformOrigin"!==e?n[e]:n.svg?n.origin:Pr(Sd(t,gr))+" "+n.zOrigin+"px"):(n=t.style[e])&&"auto"!==n&&!i&&!~(n+"").indexOf("calc(")||(n=kr[e]&&kr[e](t,e,r)||Sd(t,e)||ia(t,e)||("opacity"===e?1:0)),r&&!~(n+"").trim().indexOf(" ")?ce(t,e,n,r)+r:n},xr={top:"0%",bottom:"100%",left:"0%",right:"100%",center:"50%"},kr={clearProps:function clearProps(t,e,r,i,n){if("isFromStart"!==n.data){var a=t._pt=new we(t._pt,e,r,0,0,he);return a.u=i,a.pr=-10,a.tween=n,t._props.push(r),1}}},Or=[1,0,0,1,0,0],Mr={},Cr=function _parseTransform(t,e){var r=t._gsap||new Xt(t);if("x"in r&&!e&&!r.uncache)return r;var i,n,a,s,o,u,h,l,f,c,d,p,_,m,g,v,y,T,b,w,x,k,O,M,C,P,S,A,D,z,R,E,F=t.style,I=r.scaleX<0,L="deg",B=getComputedStyle(t),N=Sd(t,gr)||"0";return i=n=a=u=h=l=f=c=d=0,s=o=1,r.svg=!(!t.getCTM||!Zd(t)),B.translate&&("none"===B.translate&&"none"===B.scale&&"none"===B.rotate||(F[mr]=("none"!==B.translate?"translate3d("+(B.translate+" 0 0").split(" ").slice(0,3).join(", ")+") ":"")+("none"!==B.rotate?"rotate("+B.rotate+") ":"")+("none"!==B.scale?"scale("+B.scale.split(" ").join(",")+") ":"")+("none"!==B[mr]?B[mr]:"")),F.scale=F.rotate=F.translate="none"),m=ne(t,r.svg),r.svg&&(M=r.uncache?(C=t.getBBox(),N=r.xOrigin-C.x+"px "+(r.yOrigin-C.y)+"px",""):!e&&t.getAttribute("data-svg-origin"),oe(t,M||N,!!M||r.originIsAbsolute,!1!==r.smooth,m)),p=r.xOrigin||0,_=r.yOrigin||0,m!==Or&&(T=m[0],b=m[1],w=m[2],x=m[3],i=k=m[4],n=O=m[5],6===m.length?(s=Math.sqrt(T*T+b*b),o=Math.sqrt(x*x+w*w),u=T||b?fr(b,T)*hr:0,(f=w||x?fr(w,x)*hr+u:0)&&(o*=Math.abs(Math.cos(f*lr))),r.svg&&(i-=p-(p*T+_*w),n-=_-(p*b+_*x))):(E=m[6],z=m[7],S=m[8],A=m[9],D=m[10],R=m[11],i=m[12],n=m[13],a=m[14],h=(g=fr(E,D))*hr,g&&(M=k*(v=Math.cos(-g))+S*(y=Math.sin(-g)),C=O*v+A*y,P=E*v+D*y,S=k*-y+S*v,A=O*-y+A*v,D=E*-y+D*v,R=z*-y+R*v,k=M,O=C,E=P),l=(g=fr(-w,D))*hr,g&&(v=Math.cos(-g),R=x*(y=Math.sin(-g))+R*v,T=M=T*v-S*y,b=C=b*v-A*y,w=P=w*v-D*y),u=(g=fr(b,T))*hr,g&&(M=T*(v=Math.cos(g))+b*(y=Math.sin(g)),C=k*v+O*y,b=b*v-T*y,O=O*v-k*y,T=M,k=C),h&&359.9<Math.abs(h)+Math.abs(u)&&(h=u=0,l=180-l),s=ka(Math.sqrt(T*T+b*b+w*w)),o=ka(Math.sqrt(O*O+E*E)),g=fr(k,O),f=2e-4<Math.abs(g)?g*hr:0,d=R?1/(R<0?-R:R):0),r.svg&&(M=t.getAttribute("transform"),r.forceCSS=t.setAttribute("transform","")||!le(Sd(t,mr)),M&&t.setAttribute("transform",M))),90<Math.abs(f)&&Math.abs(f)<270&&(I?(s*=-1,f+=u<=0?180:-180,u+=u<=0?180:-180):(o*=-1,f+=f<=0?180:-180)),e=e||r.uncache,r.x=i-((r.xPercent=i&&(!e&&r.xPercent||(Math.round(t.offsetWidth/2)===Math.round(-i)?-50:0)))?t.offsetWidth*r.xPercent/100:0)+"px",r.y=n-((r.yPercent=n&&(!e&&r.yPercent||(Math.round(t.offsetHeight/2)===Math.round(-n)?-50:0)))?t.offsetHeight*r.yPercent/100:0)+"px",r.z=a+"px",r.scaleX=ka(s),r.scaleY=ka(o),r.rotation=ka(u)+L,r.rotationX=ka(h)+L,r.rotationY=ka(l)+L,r.skewX=f+L,r.skewY=c+L,r.transformPerspective=d+"px",(r.zOrigin=parseFloat(N.split(" ")[2])||!e&&r.zOrigin||0)&&(F[gr]=Pr(N)),r.xOffset=r.yOffset=0,r.force3D=Y.force3D,r.renderTransform=r.svg?Er:Ve?Rr:Sr,r.uncache=0,r},Pr=function _firstTwoOnly(t){return(t=t.split(" "))[0]+" "+t[1]},Sr=function _renderNon3DTransforms(t,e){e.z="0px",e.rotationY=e.rotationX="0deg",e.force3D=0,Rr(t,e)},Ar="0deg",Dr="0px",zr=") ",Rr=function _renderCSSTransforms(t,e){var r=e||this,i=r.xPercent,n=r.yPercent,a=r.x,s=r.y,o=r.z,u=r.rotation,h=r.rotationY,l=r.rotationX,f=r.skewX,c=r.skewY,d=r.scaleX,p=r.scaleY,_=r.transformPerspective,m=r.force3D,g=r.target,v=r.zOrigin,y="",T="auto"===m&&t&&1!==t||!0===m;if(v&&(l!==Ar||h!==Ar)){var b,w=parseFloat(h)*lr,x=Math.sin(w),k=Math.cos(w);w=parseFloat(l)*lr,b=Math.cos(w),a=re(g,a,x*b*-v),s=re(g,s,-Math.sin(w)*-v),o=re(g,o,k*b*-v+v)}_!==Dr&&(y+="perspective("+_+zr),(i||n)&&(y+="translate("+i+"%, "+n+"%) "),!T&&a===Dr&&s===Dr&&o===Dr||(y+=o!==Dr||T?"translate3d("+a+", "+s+", "+o+") ":"translate("+a+", "+s+zr),u!==Ar&&(y+="rotate("+u+zr),h!==Ar&&(y+="rotateY("+h+zr),l!==Ar&&(y+="rotateX("+l+zr),f===Ar&&c===Ar||(y+="skew("+f+", "+c+zr),1===d&&1===p||(y+="scale("+d+", "+p+zr),g.style[mr]=y||"translate(0, 0)"},Er=function _renderSVGTransforms(t,e){var r,i,n,a,s,o=e||this,u=o.xPercent,h=o.yPercent,l=o.x,f=o.y,c=o.rotation,d=o.skewX,p=o.skewY,_=o.scaleX,m=o.scaleY,g=o.target,v=o.xOrigin,y=o.yOrigin,T=o.xOffset,b=o.yOffset,w=o.forceCSS,x=parseFloat(l),k=parseFloat(f);c=parseFloat(c),d=parseFloat(d),(p=parseFloat(p))&&(d+=p=parseFloat(p),c+=p),c||d?(c*=lr,d*=lr,r=Math.cos(c)*_,i=Math.sin(c)*_,n=Math.sin(c-d)*-m,a=Math.cos(c-d)*m,d&&(p*=lr,s=Math.tan(d-p),n*=s=Math.sqrt(1+s*s),a*=s,p&&(s=Math.tan(p),r*=s=Math.sqrt(1+s*s),i*=s)),r=ka(r),i=ka(i),n=ka(n),a=ka(a)):(r=_,a=m,i=n=0),(x&&!~(l+"").indexOf("px")||k&&!~(f+"").indexOf("px"))&&(x=ce(g,"x",l,"px"),k=ce(g,"y",f,"px")),(v||y||T||b)&&(x=ka(x+v-(v*r+y*n)+T),k=ka(k+y-(v*i+y*a)+b)),(u||h)&&(s=g.getBBox(),x=ka(x+u/100*s.width),k=ka(k+h/100*s.height)),s="matrix("+r+","+i+","+n+","+a+","+x+","+k+")",g.setAttribute("transform",s),w&&(g.style[mr]=s)};ja("padding,margin,Width,Radius",function(e,r){var t="Right",i="Bottom",n="Left",o=(r<3?["Top",t,i,n]:["Top"+n,"Top"+t,i+t,i+n]).map(function(t){return r<2?e+t:"border"+t+e});kr[1<r?"border"+e:e]=function(e,t,r,i,n){var a,s;if(arguments.length<4)return a=o.map(function(t){return wr(e,t,r)}),5===(s=a.join(" ")).split(a[0]).length?a[0]:s;a=(i+"").split(" "),s={},o.forEach(function(t,e){return s[t]=a[e]=a[e]||a[(e-1)/2|0]}),e.init(t,s,n)}});var Fr,Ir,Lr,Br={name:"css",register:Vd,targetTest:function targetTest(t){return t.style&&t.nodeType},init:function init(t,e,i,n,a){var s,o,u,h,l,f,c,d,p,_,m,g,v,y,T,b,w,x=this._props,k=t.style,O=i.vars.startAt;for(c in Ne||Vd(),this.styles=this.styles||Pd(t),b=this.styles.props,this.tween=i,e)if("autoRound"!==c&&(o=e[c],!mt[c]||!cc(c,e,i,n,t,a)))if(l=typeof o,f=kr[c],"function"===l&&(l=typeof(o=o.call(i,n,t,a))),"string"===l&&~o.indexOf("random(")&&(o=rb(o)),f)f(this,t,c,o,i)&&(T=1);else if("--"===c.substr(0,2))s=(getComputedStyle(t).getPropertyValue(c)+"").trim(),o+="",Et.lastIndex=0,Et.test(s)||(d=_a(s),(p=_a(o))?d!==p&&(s=ce(t,c,s,p)+p):d&&(o+=d)),this.add(k,"setProperty",s,o,n,a,0,0,c),x.push(c),b.push(c,0,k[c]);else if("undefined"!==l){if(O&&c in O?(s="function"==typeof O[c]?O[c].call(i,n,t,a):O[c],r(s)&&~s.indexOf("random(")&&(s=rb(s)),_a(s+"")||"auto"===s||(s+=Y.units[c]||_a(wr(t,c))||""),"="===(s+"").charAt(1)&&(s=wr(t,c))):s=wr(t,c),h=parseFloat(s),(_="string"===l&&"="===o.charAt(1)&&o.substr(0,2))&&(o=o.substr(2)),u=parseFloat(o),c in _r&&("autoAlpha"===c&&(1===h&&"hidden"===wr(t,"visibility")&&u&&(h=0),b.push("visibility",0,k.visibility),_d(this,k,"visibility",h?"inherit":"hidden",u?"inherit":"hidden",!u)),"scale"!==c&&"transform"!==c&&~(c=_r[c]).indexOf(",")&&(c=c.split(",")[0])),m=c in ur){if(this.styles.save(c),w=o,"string"===l&&"var(--"===o.substring(0,6)){if("calc("===(o=Sd(t,o.substring(4,o.indexOf(")")))).substring(0,5)){var M=t.style.perspective;t.style.perspective=o,o=Sd(t,"perspective"),M?t.style.perspective=M:$d(t,"perspective")}u=parseFloat(o)}if(g||((v=t._gsap).renderTransform&&!e.parseTransform||Cr(t,e.parseTransform),y=!1!==e.smoothOrigin&&v.smooth,(g=this._pt=new we(this._pt,k,mr,0,1,v.renderTransform,v,0,-1)).dep=1),"scale"===c)this._pt=new we(this._pt,v,"scaleY",v.scaleY,(_?ma(v.scaleY,_+u):u)-v.scaleY||0,xd),this._pt.u=0,x.push("scaleY",c),c+="X";else{if("transformOrigin"===c){b.push(gr,0,k[gr]),o=ge(o),v.svg?oe(t,o,0,y,0,this):((p=parseFloat(o.split(" ")[2])||0)!==v.zOrigin&&_d(this,v,"zOrigin",v.zOrigin,p),_d(this,k,c,Pr(s),Pr(o)));continue}if("svgOrigin"===c){oe(t,o,1,y,0,this);continue}if(c in Mr){ye(this,v,c,h,_?ma(h,_+o):o);continue}if("smoothOrigin"===c){_d(this,v,"smooth",v.smooth,o);continue}if("force3D"===c){v[c]=o;continue}if("transform"===c){Ae(this,o,t);continue}}}else c in k||(c=yr(c)||c);if(m||(u||0===u)&&(h||0===h)&&!pr.test(o)&&c in k)u=u||0,(d=(s+"").substr((h+"").length))!==(p=_a(o)||(c in Y.units?Y.units[c]:d))&&(h=ce(t,c,s,p)),this._pt=new we(this._pt,m?v:k,c,h,(_?ma(h,_+u):u)-h,m||"px"!==p&&"zIndex"!==c||!1===e.autoRound?xd:Bd),this._pt.u=p||0,m&&w!==o?(this._pt.b=s,this._pt.e=w,this._pt.r=Ad):d!==p&&"%"!==p&&(this._pt.b=s,this._pt.r=zd);else if(c in k)ee.call(this,t,c,s,_?_+o:o);else if(c in t)this.add(t,c,s||t[c],_?_+o:o,n,a);else if("parseTransform"!==c){S(c,o);continue}m||(c in k?b.push(c,0,k[c]):"function"==typeof t[c]?b.push(c,2,t[c]()):b.push(c,1,s||t[c])),x.push(c)}T&&be(this)},render:function render(t,e){if(e.tween._time||!je())for(var r=e._pt;r;)r.r(t,r.d),r=r._next;else e.styles.revert()},get:wr,aliases:_r,getSetter:function getSetter(t,e,r){var i=_r[e];return i&&i.indexOf(",")<0&&(e=i),e in ur&&e!==gr&&(t._gsap.x||wr(t,"x"))?r&&Ye===r?"scale"===e?Hd:Gd:(Ye=r||{})&&("scale"===e?Id:Jd):t.style&&!u(t.style[e])?Ed:~e.indexOf("-")?Fd:ue(t,e)},core:{_removeProperty:$d,_getMatrix:ne}};Fe.utils.checkPrefix=yr,Fe.core.getStyleSaver=Pd,Lr=ja((Fr="x,y,z,scale,scaleX,scaleY,xPercent,yPercent")+","+(Ir="rotation,rotationX,rotationY,skewX,skewY")+",transform,transformOrigin,svgOrigin,force3D,smoothOrigin,transformPerspective",function(t){ur[t]=1}),ja(Ir,function(t){Y.units[t]="deg",Mr[t]=1}),_r[Lr[13]]=Fr+","+Ir,ja("0:translateX,1:translateY,2:translateZ,8:rotate,8:rotationZ,8:rotateZ,9:rotateX,10:rotateY",function(t){var e=t.split(":");_r[e[1]]=Lr[e[0]]}),ja("x,y,z,top,right,bottom,left,width,height,fontSize,padding,margin,perspective",function(t){Y.units[t]="px"}),Fe.registerPlugin(Br);var Nr=Fe.registerPlugin(Br)||Fe,Ur=Nr.core.Tween;e.Back=rr,e.Bounce=nr,e.CSSPlugin=Br,e.Circ=or,e.Cubic=Qe,e.Elastic=er,e.Expo=sr,e.Linear=$e,e.Power0=Xe,e.Power1=qe,e.Power2=Ge,e.Power3=Ze,e.Power4=We,e.Quad=He,e.Quart=Je,e.Quint=Ke,e.Sine=ar,e.SteppedEase=ir,e.Strong=tr,e.TimelineLite=Gt,e.TimelineMax=Gt,e.TweenLite=te,e.TweenMax=Ur,e.default=Nr,e.gsap=Nr;if (typeof(window)==="undefined"||window!==e){Object.defineProperty(e,"__esModule",{value:!0})} else {delete e.default}});


/**
 * SSH Workbench — Liquid selection, v3 (always-on, demand-driven).
 * GSAP Core / Timeline / Performance skills (greensock/gsap-skills).
 * This layer observes committed presentation state. It never calls an API,
 * checks a radio, changes focus, clones labels, or delays a business action.
 * Glass is an intentionally restrained CSS approximation, not Apple's renderer.
 */
(function installSshMotion() {
  'use strict';
  const gsap = window.gsap;
  const PLAYBACK_RATE = 2; // Double animation speed without changing easing or business timers.
  const root = document.querySelector('.app-shell');
  if (!gsap || !root) return;
  window.SSHMotion?.destroy();
  // This application's explicit policy is to play motion independently of the OS.
  // Reduced transparency and forced colors remain separate CSS preferences.
  const context = gsap.context(() => {});
  const groupsSelector = '.segmented-control, .operation-tabs, .workspace-tabs, .machine-list';
  const visible = (el) => Boolean(el?.isConnected && !el.closest('[hidden]') && el.getClientRects().length);
  const clamp = (min, max, value) => Math.max(min, Math.min(max, value));
  let disposed = false;
  let currentMode = 'animated';
  let activeCount = () => 0;
  let requestSync = () => {};

  const disposeMotion = (() => {
    document.documentElement.classList.add('ssh-motion-enabled', 'ssh-liquid-enabled');
    const active = new Map();
    const touched = new Set();
    const markers = new Map();
    const cleanup = [];
    const pressed = new Set();
    const pressedLenses = new Set();
    let frame = 0;
    let dead = false;
    // These groups are static in the real application. Cache their identity once;
    // the machine ROWS may be replaced, but their owning group is not.
    const groups = [...root.querySelectorAll(groupsSelector)];
    const pending = new Map(); // group -> true when geometry must snap (e.g. resize)
    const observedSizes = new WeakMap();
    const busyDot = document.querySelector('#gateway-dot');
    const busyIcon = document.querySelector('#refresh-button .ui-icon');
    let busyPending = true;
    activeCount = () => active.size;

    function listen(el, type, fn, options) {
      el?.addEventListener(type, fn, options);
      cleanup.push(() => el?.removeEventListener(type, fn, options));
    }
    function observe(el, options, fn) {
      if (!el) return;
      const observer = new MutationObserver(fn);
      observer.observe(el, options);
      cleanup.push(() => observer.disconnect());
    }
    function stop(el, clear = true) {
      active.get(el)?.kill();
      active.delete(el);
      if (clear && el?.style) {
        gsap.set(el, { clearProps: 'transform,opacity,visibility,willChange,transformOrigin' });
        touched.delete(el);
      }
    }
    function animate(el, vars, from) {
      if (!el || dead || document.hidden) return;
      stop(el, false);
      touched.add(el);
      el.style.willChange = 'transform, opacity';
      context.ignore(() => {
        const done = vars.onComplete;
        const options = { ...vars, overwrite: 'auto', onComplete() {
          active.delete(el);
          el.style.removeProperty('will-change');
          if (vars.clearProps) touched.delete(el);
          done?.();
        } };
        const tween = (from ? gsap.fromTo(el, from, options) : gsap.to(el, options)).timeScale(PLAYBACK_RATE);
        active.set(el, tween);
      });
    }
    function schedule() {
      if (!frame && !dead && !document.hidden) frame = requestAnimationFrame(flush);
    }
    function queue(group, instant = false) {
      if (!group || dead) return;
      pending.set(group, Boolean(instant || pending.get(group)));
      schedule();
    }
    function queueAll(instant = false) {
      for (const group of groups) pending.set(group, Boolean(instant || pending.get(group)));
      schedule();
    }
    function queueRelated(element) {
      // Visibility can affect descendants and controls inside the same container.
      // Relative group coordinates do not change when an unrelated panel moves.
      for (const group of groups) {
        if (group === element || element.contains(group) || group.contains(element)) queue(group);
      }
    }
    requestSync = () => queueAll(true);

    function selectedBox(group) {
      if (group.matches('.machine-list')) return group.querySelector('.machine-item.is-selected');
      return group.matches('.segmented-control')
        ? group.querySelector('input:checked + span')
        : group.querySelector('[aria-selected="true"]');
    }
    function selectionKey(group, selected) {
      if (group.matches('.machine-list')) return selected.dataset.alias;
      if (group.matches('.segmented-control')) return selected.previousElementSibling.value;
      return selected.id;
    }
    function makeMarker(group) {
      const node = document.createElement('span');
      const surface = document.createElement('span');
      const light = document.createElement('span');
      const rim = document.createElement('span');
      node.className = 'selection-marker liquid-marker';
      node.setAttribute('aria-hidden', 'true');
      surface.className = 'liquid-surface';
      light.className = 'liquid-light';
      rim.className = 'liquid-rim';
      surface.append(light, rim);
      node.append(surface);
      const kind = group.matches('.machine-list') ? 'inventory'
        : group.matches('.workspace-tabs') ? 'rail'
        : group.matches('.operation-tabs') ? 'tabs' : 'segment';
      node.dataset.motionKind = kind;
      const record = { group, node, surface, light, rim, kind, key: '', layoutKey: '', width: 0, height: 0, wasVisible: false };
      markers.set(group, record);
      return record;
    }
    function clearLens(record) {
      const { node, surface, light, rim } = record;
      stop(node, false);
      stop(surface);
      gsap.set([light, rim], { clearProps: 'transform,opacity,willChange' });
      node.style.removeProperty('will-change');
      node.classList.remove('is-travelling');
      pressedLenses.delete(record);
    }
    function finishLens(record) {
      const { node, surface, light, rim } = record;
      active.delete(node);
      gsap.set([surface, light, rim], { clearProps: 'transform,opacity,willChange' });
      node.style.removeProperty('will-change');
      node.classList.remove('is-travelling');
    }

    // Inventory markers are reattached as the same object after app.js
    // replaceChildren(), retaining their in-flight transform and visual identity.
    function measure(group) {
      const record = markers.get(group);
      if (!record) return null;
      if (!group.isConnected || group.closest('[hidden]')) {
        record.measuredWidth = record.measuredHeight = 0;
        return { record, hide: true };
      }
      const selected = selectedBox(group);
      if (!selected) return { record, hide: true };
      // Read the two rectangles once. No append(), class/style mutation or
      // visibility geometry probe is interleaved with the read phase.
      const parent = group.getBoundingClientRect();
      record.measuredWidth = parent.width;
      record.measuredHeight = parent.height;
      if (!parent.width || !parent.height) return { record, hide: true };
      const box = selected.getBoundingClientRect();
      const x = box.left - parent.left - group.clientLeft + group.scrollLeft;
      const y = box.top - parent.top - group.clientTop + group.scrollTop;
      const w = box.width, h = box.height;
      const key = selectionKey(group, selected);
      const layoutKey = [x, y, w, h].map(v => v.toFixed(2)).join(':');
      return { record, key, layoutKey, x, y, w, h, hide: !w || !h };
    }
    function syncMarker(plan, instant = false) {
      if (!plan) return;
      const { record } = plan;
      const { group, node, surface, light, rim, kind } = record;
      if (plan.hide) {
        if (record.wasVisible) clearLens(record);
        record.wasVisible = false;
        if (!node.hidden) node.hidden = true;
        if (group.classList.contains('has-motion-marker')) group.classList.remove('has-motion-marker');
        return;
      }
      const { x, y, w, h, key, layoutKey } = plan;
      if (record.wasVisible && key === record.key && layoutKey === record.layoutKey && !instant) return;
      if (node.hidden) node.hidden = false;
      if (!group.classList.contains('has-motion-marker')) group.classList.add('has-motion-marker');
      // Reappearing controls, search results, and reflow snap to correct geometry.
      // Only a genuinely different selection glides; resizing never triggers a show.
      const glide = !instant && record.wasVisible && record.key && key !== record.key && !document.hidden;
      const oldX = Number(gsap.getProperty(node, 'x')) || 0;
      const oldY = Number(gsap.getProperty(node, 'y')) || 0;
      const oldW = record.width * (Number(gsap.getProperty(node, 'scaleX')) || 1);
      const oldH = record.height * (Number(gsap.getProperty(node, 'scaleY')) || 1);
      const centerX = oldX + record.width / 2;
      const centerY = oldY + record.height / 2;
      stop(node, false);
      stop(surface, false);
      pressedLenses.delete(record);
      // Dimensions are written only at a genuine size change, never per frame.
      if (record.width !== w) node.style.width = w + 'px';
      if (record.height !== h) node.style.height = h + 'px';
      record.key = key; record.layoutKey = layoutKey;
      record.width = w; record.height = h; record.wasVisible = true;
      if (!glide) {
        clearLens(record);
        gsap.set(node, { x, y, scaleX: 1, scaleY: 1 });
        return;
      }
      const dx = x + w / 2 - centerX;
      const dy = y + h / 2 - centerY;
      const horizontal = Math.abs(dx) > Math.abs(dy);
      const distance = Math.hypot(dx, dy);
      // The larger inventory panel is quieter than the compact capsules.
      const stretch = kind === 'inventory' ? .045 : kind === 'rail' ? .12 : .17;
      const travel = kind === 'inventory' ? .48 + clamp(0, .055, distance / 6000)
        : kind === 'rail' ? .44 + clamp(0, .08, distance / 4500) : .44;
      const axis = horizontal ? 'xPercent' : 'yPercent';
      const direction = Math.sign(horizontal ? dx : dy) || 1;
      const elongate = horizontal
        ? { scaleX: 1 + stretch, scaleY: 1 - stretch * .62 }
        : { scaleX: 1 - stretch * .55, scaleY: 1 + stretch };
      const settle = horizontal ? { scaleX: .991, scaleY: 1.012 } : { scaleX: 1.007, scaleY: .991 };
      gsap.set(node, { x: centerX - w / 2, y: centerY - h / 2, scaleX: oldW / w, scaleY: oldH / h });
      gsap.set(light, { xPercent: 0, yPercent: 0, [axis]: -direction * 75, opacity: 0 });
      node.classList.add('is-travelling');
      node.style.willChange = surface.style.willChange = 'transform';
      light.style.willChange = 'transform, opacity';
      context.ignore(() => {
        const timeline = gsap.timeline({ defaults: { overwrite: 'auto' }, onComplete: () => finishLens(record) }).timeScale(PLAYBACK_RATE);
        timeline.addLabel('travel', 0)
          .to(node, { x, y, scaleX: 1, scaleY: 1, duration: travel, ease: 'power2.inOut' }, 'travel')
          .to(surface, { ...elongate, duration: travel * .28, ease: 'power2.out' }, 'travel')
          .to(surface, { ...settle, duration: travel * .60, ease: 'power2.inOut' }, travel * .28)
          .to(surface, { scaleX: 1, scaleY: 1, duration: .14, ease: 'sine.out' }, travel * .88)
          // A soft moving highlight signals material thickness, not a sparkle loop.
          .to(light, { opacity: kind === 'inventory' ? .28 : .60, duration: travel * .23, ease: 'sine.out' }, 0)
          .to(light, { [axis]: direction * 75, duration: travel, ease: 'sine.inOut' }, 0)
          .to(light, { opacity: 0, duration: travel * .47, ease: 'sine.out' }, travel * .53);
        // The rim stays static. One moving light already communicates the glass;
        // no separate rim tween or persistent compositor hint is needed.
        active.set(node, timeline);
      });
    }
    function flush() {
      frame = 0;
      if (dead || document.hidden) return;
      const work = [...pending];
      pending.clear();
      // Phase 1: create/reattach nodes. The inventory keeps the SAME lens even
      // after app.js replaceChildren(). Never measure between these appends.
      for (const [group] of work) {
        if (!group.isConnected) continue;
        let record = markers.get(group);
        if (!record && !group.closest('[hidden]') && selectedBox(group)) record = makeMarker(group);
        if (record && record.node.parentNode !== group) group.append(record.node);
      }
      // Reattach first so a replaced machine row doesn't erase an in-flight
      // marker transform. Hidden lenses are handled by syncMarker/clearLens.
      for (const el of [...active.keys()]) {
        if (!el.matches('.liquid-marker') && (!el.isConnected || el.closest('[hidden]'))) stop(el);
      }
      // Phase 2: all geometry reads. Phase 3: all styles/timelines.
      const plans = work.map(([group, instant]) => [measure(group), instant]);
      for (const [plan, instant] of plans) syncMarker(plan, instant);
      if (busyPending) {
        busyPending = false;
        const busy = busyDot?.classList.contains('is-checking');
        if (busy && busyIcon && !active.has(busyIcon)) {
          animate(busyIcon, { rotation: '+=360', repeat: -1, duration: 1, ease: 'none' });
        } else if (!busy && busyIcon && active.has(busyIcon)) stop(busyIcon);
      }
    }

    // Ignore terminal text, CSS transforms and unrelated action-button states.
    // A copy feedback or gateway status update must not remeasure every control.
    observe(root, { attributes: true, subtree: true, attributeOldValue: true, attributeFilter: ['hidden', 'aria-selected', 'data-copy-state', 'disabled'] }, (records) => {
      for (const change of records) {
        const target = change.target;
        if (change.oldValue === target.getAttribute(change.attributeName) || target.closest('.liquid-marker')) continue;
        if (change.attributeName === 'data-copy-state') {
          if (target.dataset.copyState === 'copied') {
            const check = target.querySelector('.copy-check');
            if (visible(check)) animate(check, { scale: 1, opacity: 1, duration: .18, ease: 'power2.out', clearProps: 'transform,opacity,willChange' }, { scale: .82, opacity: .6 });
          }
          continue;
        }
        if (change.attributeName === 'hidden') queueRelated(target);
        else queue(target.closest(groupsSelector));
      }
    });
    observe(document.querySelector('#machine-list'), { childList: true }, (records) => {
      if (records.some(record => [...record.addedNodes, ...record.removedNodes].some(node => !node.classList?.contains('liquid-marker')))) {
        // Choosing a machine also fills native checked properties without firing
        // change events. Reconcile all group selections for this actual UI render.
        queueAll();
      }
    });
    observe(busyDot, { attributes: true, attributeFilter: ['class'] }, () => { busyPending = true; schedule(); });
    observe(document.querySelector('#toast-region'), { childList: true }, () => {
      const toast = document.querySelector('#toast-region .toast');
      if (toast) animate(toast, { opacity: 1, y: 0, duration: .18, ease: 'power2.out', clearProps: 'transform,opacity,willChange' }, { opacity: .7, y: 4 });
    });
    listen(root, 'change', event => {
      if (event.target.matches('input[type="radio"]')) queue(event.target.closest('.segmented-control'));
    });
    listen(root, 'toggle', event => {
      const details = event.target;
      if (!details.matches('details')) return;
      const arrow = details.querySelector('.disclosure-chevron');
      if (arrow) animate(arrow, { rotation: details.open ? 180 : 0, duration: .18, ease: 'power2.out' });
      queueRelated(details);
    }, true);

    function press(event) {
      if (event.type === 'keydown' && (!['Enter', ' '].includes(event.key) || event.repeat)) return;
      if (event.type === 'pointerdown' && event.button !== 0) return;
      const control = event.target.closest('button, .segmented-control > label');
      if (!control || control.matches(':disabled') || control.querySelector('input:disabled')) return;
      const group = control.closest(groupsSelector);
      if (group && !control.matches('.machine-mcp-toggle')) {
        const record = markers.get(group);
        const selected = selectedBox(group);
        if (record && selected && (control.contains(selected) || selected.contains(control)) && !active.has(record.node)) {
          pressedLenses.add(record);
          animate(record.surface, { scaleX: .975, scaleY: .96, duration: .1, ease: 'power2.out' });
        }
        return;
      }
      if (!control.matches('button') || control.matches('.output-tab')) return;
      pressed.add(control);
      animate(control, { scale: .98, duration: .09, ease: 'power1.out' });
    }
    function release() {
      for (const control of pressed) animate(control, { scale: 1, duration: .16, ease: 'power2.out', clearProps: 'transform,willChange' });
      pressed.clear();
      for (const record of pressedLenses) if (!active.has(record.node)) animate(record.surface, { scaleX: 1, scaleY: 1, duration: .22, ease: 'power2.out', clearProps: 'transform,willChange' });
      pressedLenses.clear();
    }
    listen(root, 'pointerdown', press);
    listen(root, 'keydown', press);
    listen(window, 'pointerup', release);
    listen(window, 'pointercancel', release);
    listen(window, 'keyup', release);
    listen(window, 'blur', release);
    listen(window, 'resize', () => queueAll(true));
    if (typeof ResizeObserver === 'function') {
      const ro = new ResizeObserver(entries => {
        for (const { target, contentRect, borderBoxSize } of entries) {
          const size = `${contentRect.width}:${contentRect.height}`;
          if (observedSizes.get(target) === size) continue;
          observedSizes.set(target, size);
          const box = borderBoxSize?.[0] || borderBoxSize;
          const record = markers.get(target);
          // A visibility change is often measured in our rAF before RO delivers
          // the same size. Don't schedule a second, identical read next frame.
          // Groups have horizontal writing-mode and no transform of their own.
          if (box && record && Math.abs(record.measuredWidth - box.inlineSize) < .1
            && Math.abs(record.measuredHeight - box.blockSize) < .1) continue;
          queue(target);
        }
      });
      groups.forEach(group => ro.observe(group));
      cleanup.push(() => ro.disconnect());
    }
    if (document.fonts?.ready) document.fonts.ready.then(() => { if (!dead) queueAll(true); });
    listen(document, 'visibilitychange', () => {
      if (document.hidden) {
        if (frame) { cancelAnimationFrame(frame); frame = 0; }
        pending.clear();
        for (const record of markers.values()) clearLens(record);
        for (const el of [...active.keys()]) stop(el);
        pressed.clear();
      } else {
        busyPending = true;
        queueAll(true);
      }
    });
    queueAll(true);
    return () => {
      dead = true;
      if (frame) cancelAnimationFrame(frame);
      cleanup.forEach(fn => fn());
      for (const record of markers.values()) { clearLens(record); record.node.remove(); record.group.classList.remove('has-motion-marker'); }
      for (const el of [...touched]) stop(el);
      markers.clear(); active.clear(); pressed.clear(); pressedLenses.clear(); pending.clear();
      document.documentElement.classList.remove('ssh-motion-enabled', 'ssh-liquid-enabled');
      activeCount = () => 0; requestSync = () => {};
    };
  })();

  function closeHelp(event) {
    if (event.key !== 'Escape') return;
    const disclosure = event.target.closest?.('details[open]');
    if (disclosure) { disclosure.open = false; disclosure.querySelector('summary')?.focus(); }
  }
  document.addEventListener('keydown', closeHelp);
  window.SSHMotion = Object.freeze({
    get version() { return gsap.version; },
    get design() { return 'liquid-selection-v3'; },
    get motionPolicy() { return 'always'; },
    get mode() { return currentMode; },
    get activeAnimations() { return activeCount(); },
    refresh() { requestSync(); },
    destroy() {
      if (disposed) return;
      disposed = true; currentMode = 'destroyed'; disposeMotion(); context.revert(); document.removeEventListener('keydown', closeHelp);
    }
  });
})();

}).call(typeof window !== "undefined" ? {window} : {});
/* END GENERATED SSH MOTION BUNDLE */
