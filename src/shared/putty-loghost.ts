import { isIP } from "node:net";

export function formatPuttyLogicalHost(host: string, port?: number): string {
  if (port === undefined) return host;
  return `${isIP(host) === 6 ? `[${host}]` : host}:${port}`;
}
