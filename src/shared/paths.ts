import path from "node:path";

export const DATA_DIRECTORY_ENV = "AGENT_SSH_GATEWAY_DATA_DIR";
export const CONFIG_PATH_ENV = "AGENT_SSH_GATEWAY_CONFIG";

export function defaultDataDirectory(): string {
  if (process.platform === "win32") {
    return path.join(process.env.ProgramData ?? "C:\\ProgramData", "agent-ssh-gateway");
  }
  return path.join(process.env.XDG_RUNTIME_DIR ?? "/var/run", "agent-ssh-gateway");
}

export function resolveDataDirectory(explicit?: string): string {
  const selected = explicit ?? process.env[DATA_DIRECTORY_ENV] ?? defaultDataDirectory();
  return path.resolve(selected);
}
