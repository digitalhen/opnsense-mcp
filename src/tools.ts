// ---------------------------------------------------------------------------
// Tool discovery, introspection, and execution
// ---------------------------------------------------------------------------

import { OPNsenseClient } from "@richard-stovall/opnsense-typescript-client";
import { createLogger } from "./logger.js";
import type { Config } from "./config.js";

const log = createLogger("tools");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface MethodInfo {
  name: string;
  paramNames: string[]; // excluding 'config'
  paramCount: number;
  description: string;
}

export interface ToolDef {
  name: string;
  description: string;
  module: string;
  submodule?: string;
  methods: Map<string, MethodInfo>;
  inputSchema: object;
}

// ---------------------------------------------------------------------------
// OPNsense client init
// ---------------------------------------------------------------------------

let opnsense: OPNsenseClient;
let includePlugins = false;

export function initClient(config: Config): void {
  includePlugins = config.includePlugins;
  if (!config.verifySsl) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  }
  opnsense = new OPNsenseClient({
    baseUrl: config.opnsenseUrl,
    apiKey: config.apiKey,
    apiSecret: config.apiSecret,
    verifySsl: config.verifySsl,
  });
}

export function getClient(): OPNsenseClient {
  return opnsense;
}

// ---------------------------------------------------------------------------
// Parameter introspection — done ONCE at startup, not per-call
// ---------------------------------------------------------------------------

const SIG_PATTERNS = [
  /^async\s+\w+\s*\(([^)]*)\)/,
  /^async\s*\(([^)]*)\)/,
  /^\w+\s*\(([^)]*)\)/,
  /^\(([^)]*)\)/,
  /^function\s*\w*\s*\(([^)]*)\)/,
];

function parseParamNames(fn: Function): string[] {
  const src = fn.toString();
  for (const pattern of SIG_PATTERNS) {
    const match = src.match(pattern);
    if (match) {
      return match[1]
        .split(",")
        .map((p: string) => p.trim().replace(/\s*=.*$/, "").replace(/\s*:.*$/, ""))
        .filter((p: string) => p && p !== "config");
    }
  }
  // Last resort: use fn.length minus 1 (for config param)
  const count = Math.max(0, fn.length - 1);
  return Array.from({ length: count }, (_, i) => `arg${i}`);
}

function describeMethod(name: string, paramNames: string[]): string {
  // Generate a human-readable description from method name + params
  // e.g. "aliasGetItem" → "alias get item", params: [uuid]
  const words = name.replace(/([A-Z])/g, " $1").trim().toLowerCase();
  if (paramNames.length === 0) return words;
  return `${words} (params: ${paramNames.join(", ")})`;
}

function introspectMethod(obj: any, methodName: string): MethodInfo | null {
  const fn = obj[methodName];
  if (typeof fn !== "function") return null;

  const paramNames = parseParamNames(fn);
  return {
    name: methodName,
    paramNames,
    paramCount: paramNames.length,
    description: describeMethod(methodName, paramNames),
  };
}

function getModuleMethods(obj: unknown): string[] {
  if (!obj || typeof obj !== "object") return [];
  const proto = Object.getPrototypeOf(obj);
  if (!proto) return [];
  return Object.getOwnPropertyNames(proto).filter(
    (k) => typeof (proto as any)[k] === "function" && k !== "constructor",
  );
}

// ---------------------------------------------------------------------------
// Per-method schema generation — much better than a generic schema for all
// ---------------------------------------------------------------------------

function buildMethodParamSchema(info: MethodInfo): object {
  const props: Record<string, object> = {};
  for (const p of info.paramNames) {
    if (p === "data" || p === "item") {
      props[p] = { type: "object", description: `Data payload for ${info.name}` };
    } else if (p === "uuid" || p.toLowerCase().endsWith("uuid")) {
      props[p] = { type: "string", description: `UUID identifier` };
    } else if (p === "searchPhrase") {
      props[p] = { type: "string", description: "Search text" };
    } else if (p === "current") {
      props[p] = { type: "integer", description: "Page number (default 1)", default: 1 };
    } else if (p === "rowCount") {
      props[p] = { type: "integer", description: "Rows per page (default 20)", default: 20 };
    } else {
      props[p] = { type: "string", description: `Parameter: ${p}` };
    }
  }
  return props;
}

function makeToolSchema(methods: Map<string, MethodInfo>): object {
  const methodNames = [...methods.keys()];

  // Build a description of what params each method expects
  const methodDescriptions = methodNames.map((name) => {
    const info = methods.get(name)!;
    if (info.paramCount === 0) return `  ${name} — no params`;
    return `  ${name}(${info.paramNames.join(", ")})`;
  });

  // Collect all unique param names across methods to build a union schema
  const allParamProps: Record<string, object> = {};
  for (const info of methods.values()) {
    const paramSchema = buildMethodParamSchema(info);
    Object.assign(allParamProps, paramSchema);
  }

  return {
    type: "object" as const,
    properties: {
      method: {
        type: "string",
        description: `Method to call. Signatures:\n${methodDescriptions.join("\n")}`,
        enum: methodNames,
      },
      params: {
        type: "object",
        description: "Parameters for the chosen method — see method signatures above for which params each method expects",
        properties: allParamProps,
      },
    },
    required: ["method"],
  };
}

// ---------------------------------------------------------------------------
// Tool discovery
// ---------------------------------------------------------------------------

const CORE_MODULES: Record<string, string> = {
  core: "Core system management (backup, firmware, dashboard, system status)",
  firewall: "Firewall rules, aliases, categories, NAT, and filter management",
  auth: "Authentication, users, groups, and privileges",
  interfaces: "Network interfaces, VIPs, VLANs, and link status",
  captiveportal: "Captive portal zones, sessions, and vouchers",
  cron: "Scheduled cron jobs",
  dhcpv4: "DHCPv4 leases, static mappings, and settings",
  dhcpv6: "DHCPv6 leases, static mappings, and settings",
  dhcrelay: "DHCP relay configuration",
  diagnostics: "Diagnostics: ping, traceroute, DNS lookup, netstat, packet capture, activity, netflow",
  dnsmasq: "Dnsmasq DNS/DHCP service configuration",
  firmware: "Firmware updates, package management, and changelogs",
  ids: "Intrusion Detection System (Suricata) rules and alerts",
  ipsec: "IPsec VPN tunnels, phases, and status",
  kea: "Kea DHCP server configuration",
  monit: "Monit service monitoring and alerts",
  openvpn: "OpenVPN server and client instances",
  routes: "Static route management",
  routing: "Gateway groups and routing configuration",
  syslog: "Syslog destinations and statistics",
  trafficshaper: "Traffic shaping / QoS pipes, queues, and rules",
  trust: "TLS certificates, CAs, and CRLs",
  unbound: "Unbound DNS resolver, overrides, and DNSBL",
  wireguard: "WireGuard VPN peers, endpoints, and status",
};

export function discoverTools(): ToolDef[] {
  const tools: ToolDef[] = [];

  for (const [mod, desc] of Object.entries(CORE_MODULES)) {
    const obj = (opnsense as any)[mod];
    if (!obj) {
      log.warn(`Module '${mod}' not found on client — skipping`);
      continue;
    }
    const methodNames = getModuleMethods(obj);
    if (methodNames.length === 0) continue;

    const methods = new Map<string, MethodInfo>();
    for (const name of methodNames) {
      const info = introspectMethod(obj, name);
      if (info) methods.set(name, info);
    }

    tools.push({
      name: `${mod}_manage`,
      description: `${desc}. ${methods.size} methods available — use the 'method' param to choose one.`,
      module: mod,
      methods,
      inputSchema: makeToolSchema(methods),
    });
  }

  // Plugins (only if enabled)
  if (!includePlugins) return tools;
  const plugins = (opnsense as any).plugins;
  if (plugins) {
    for (const [name, obj] of Object.entries(plugins)) {
      if (name === "http") continue;
      const methodNames = getModuleMethods(obj);
      if (methodNames.length === 0) continue;

      const methods = new Map<string, MethodInfo>();
      for (const mn of methodNames) {
        const info = introspectMethod(obj as any, mn);
        if (info) methods.set(mn, info);
      }

      tools.push({
        name: `plugin_${name}_manage`,
        description: `Plugin: ${name}. ${methods.size} methods available.`,
        module: "plugins",
        submodule: name,
        methods,
        inputSchema: makeToolSchema(methods),
      });
    }
  }

  return tools;
}

// ---------------------------------------------------------------------------
// Retry with exponential backoff
// ---------------------------------------------------------------------------

function isTransient(err: any): boolean {
  if (!err) return false;
  // Network errors
  const code = err.code;
  if (code === "ECONNRESET" || code === "ECONNREFUSED" || code === "ETIMEDOUT" || code === "ENOTFOUND" || code === "EAI_AGAIN") {
    return true;
  }
  // HTTP 5xx or 429
  const status = err?.response?.status;
  if (status && (status >= 500 || status === 429)) return true;
  return false;
}

async function withRetry<T>(fn: () => Promise<T>, label: string, maxRetries = 2): Promise<T> {
  let lastErr: any;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err: any) {
      lastErr = err;
      if (!isTransient(err) || attempt === maxRetries) throw err;
      const delayMs = 1000 * Math.pow(2, attempt);
      log.warn(`Retrying ${label} (attempt ${attempt + 1}/${maxRetries}) after ${delayMs}ms`, {
        error: err?.message,
        status: err?.response?.status,
      });
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  throw lastErr;
}

// ---------------------------------------------------------------------------
// Tool execution
// ---------------------------------------------------------------------------

export function getModuleObject(tool: ToolDef): any {
  if (tool.module === "plugins" && tool.submodule) {
    return (opnsense as any).plugins[tool.submodule];
  }
  return (opnsense as any)[tool.module];
}

export async function executeMethod(
  tool: ToolDef,
  methodName: string,
  rawArgs: Record<string, any>,
): Promise<{ result: any; isError?: boolean }> {
  const info = tool.methods.get(methodName);
  if (!info) {
    return {
      result: `Unknown method '${methodName}'. Available methods: ${[...tool.methods.keys()].join(", ")}`,
      isError: true,
    };
  }

  const moduleObj = getModuleObject(tool);
  const fn = moduleObj[methodName];
  if (typeof fn !== "function") {
    return { result: `Method '${methodName}' is not callable`, isError: true };
  }

  const { method: _, params = {}, ...rest } = rawArgs;
  const callParams: Record<string, any> = { ...params, ...rest };

  const label = `${tool.name}.${methodName}`;
  log.info(`Calling ${label}`, { params: Object.keys(callParams) });

  try {
    const result = await withRetry(async () => {
      if (info.paramCount === 0) {
        return fn.call(moduleObj);
      }

      if (info.paramCount === 1 && info.paramNames[0] === "data") {
        // Single 'data' param — pass explicit data or the whole callParams
        const data = callParams.data !== undefined ? callParams.data : callParams;
        return fn.call(moduleObj, data);
      }

      // Multiple params — map each by name from callParams
      const positionalArgs = info.paramNames.map((name: string, i: number) => {
        if (callParams[name] !== undefined) return callParams[name];
        // If this is the last param named 'data' and not explicitly provided,
        // pass remaining callParams (minus other named params) as the data
        if (name === "data" && i === info.paramNames.length - 1) {
          const remaining = { ...callParams };
          info.paramNames.forEach((n: string) => {
            if (n !== "data") delete remaining[n];
          });
          return Object.keys(remaining).length > 0 ? remaining : undefined;
        }
        return undefined;
      });

      return fn.call(moduleObj, ...positionalArgs);
    }, label);

    log.info(`${label} succeeded`);
    return { result };
  } catch (err: any) {
    const status = err?.response?.status;
    const responseData = err?.response?.data;
    let msg: string;

    if (status) {
      msg = `HTTP ${status}`;
      if (status === 401 || status === 403) {
        msg += ": Authentication/authorization failed — check API key permissions";
      } else if (status === 404) {
        msg += ": Endpoint not found — this method may not be available on your OPNsense version";
      } else if (status >= 500) {
        msg += `: OPNsense server error — ${JSON.stringify(responseData) || "no details"}`;
      } else {
        msg += `: ${JSON.stringify(responseData) || err.message}`;
      }
    } else if (err.code === "ECONNREFUSED") {
      msg = `Cannot connect to OPNsense at configured URL — connection refused`;
    } else if (err.code === "ETIMEDOUT" || err.code === "ECONNRESET") {
      msg = `Connection to OPNsense timed out / was reset after retries`;
    } else {
      msg = err.message || "Unknown error";
    }

    log.error(`${label} failed: ${msg}`);
    return { result: `Error calling ${label}: ${msg}`, isError: true };
  }
}
