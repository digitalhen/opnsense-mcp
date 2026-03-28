import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { OPNsenseClient } from "@richard-stovall/opnsense-typescript-client";
import express from "express";
import crypto from "crypto";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const config = {
  opnsenseUrl: process.env.OPNSENSE_URL || "https://192.168.50.1",
  apiKey: process.env.OPNSENSE_API_KEY || "",
  apiSecret: process.env.OPNSENSE_API_SECRET || "",
  verifySsl: process.env.OPNSENSE_VERIFY_SSL !== "false",
  includePlugins: process.env.INCLUDE_PLUGINS === "true",
  oauthPassword: process.env.OAUTH_PASSWORD || "",
  port: parseInt(process.env.PORT || "3100", 10),
  publicUrl: process.env.PUBLIC_URL || "",
};

if (!config.apiKey || !config.apiSecret) {
  console.error("Error: OPNSENSE_API_KEY and OPNSENSE_API_SECRET are required");
  process.exit(1);
}
if (!config.oauthPassword) {
  console.error("Error: OAUTH_PASSWORD is required");
  process.exit(1);
}
if (!config.publicUrl) {
  console.error("Error: PUBLIC_URL is required (e.g. https://opnsense-mcp.digitalhen.com)");
  process.exit(1);
}

// Disable TLS verification if configured
if (!config.verifySsl) {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

// ---------------------------------------------------------------------------
// OAuth 2.0 — simple implementation for Claude.ai
// ---------------------------------------------------------------------------

// In-memory stores (survive container restarts via long-lived tokens)
const authCodes = new Map<string, { clientId: string; codeChallenge?: string; codeChallengeMethod?: string; redirectUri: string; expiresAt: number }>();
const accessTokens = new Set<string>();
const registeredClients = new Map<string, { clientId: string; clientSecret: string; redirectUris: string[] }>();

// OAuth metadata endpoint (RFC 8414)
function oauthMetadata() {
  const issuer = config.publicUrl;
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
    code_challenge_methods_supported: ["S256", "plain"],
  };
}

// ---------------------------------------------------------------------------
// OPNsense client
// ---------------------------------------------------------------------------
const opnsense = new OPNsenseClient({
  baseUrl: config.opnsenseUrl,
  apiKey: config.apiKey,
  apiSecret: config.apiSecret,
  verifySsl: config.verifySsl,
});

// ---------------------------------------------------------------------------
// Tool discovery
// ---------------------------------------------------------------------------
interface ToolDef {
  name: string;
  description: string;
  module: string;
  submodule?: string;
  methods: string[];
  inputSchema: object;
}

function getModuleMethods(obj: unknown): string[] {
  if (!obj || typeof obj !== "object") return [];
  const proto = Object.getPrototypeOf(obj);
  if (!proto) return [];
  return Object.getOwnPropertyNames(proto).filter(
    (k) => typeof (proto as any)[k] === "function" && k !== "constructor"
  );
}

function makeSchema(methods: string[]) {
  return {
    type: "object" as const,
    properties: {
      method: {
        type: "string",
        description: "The method to call on this module",
        enum: methods,
      },
      params: {
        type: "object",
        description: "Parameters for the method (varies by method)",
        properties: {
          uuid: { type: "string", description: "Item UUID (for get/set/del)" },
          data: { type: "object", description: "Config data (for set ops)" },
          item: { type: "object", description: "Item data (for add/set)" },
          searchPhrase: { type: "string", description: "Search text" },
          current: { type: "integer", description: "Page number", default: 1 },
          rowCount: {
            type: "integer",
            description: "Rows per page",
            default: 20,
          },
        },
      },
    },
    required: ["method"],
  };
}

function discoverTools(): ToolDef[] {
  const tools: ToolDef[] = [];
  const coreModules: Record<string, string> = {
    core: "Core system management",
    firewall: "Firewall rules, aliases, NAT",
    auth: "Authentication & users",
    interfaces: "Network interfaces",
    captiveportal: "Captive portal",
    cron: "Cron jobs",
    dhcpv4: "DHCPv4 leases & settings",
    dhcpv6: "DHCPv6 leases & settings",
    dhcrelay: "DHCP relay",
    diagnostics: "Diagnostics & troubleshooting",
    dnsmasq: "Dnsmasq DNS/DHCP",
    firmware: "Firmware updates",
    ids: "Intrusion detection",
    ipsec: "IPsec VPN",
    kea: "Kea DHCP",
    monit: "Service monitoring",
    openvpn: "OpenVPN",
    routes: "Static routes",
    routing: "Gateway routing",
    syslog: "System logging",
    trafficshaper: "Traffic shaping / QoS",
    trust: "Certificates & CAs",
    unbound: "Unbound DNS",
    wireguard: "WireGuard VPN",
  };

  for (const [mod, desc] of Object.entries(coreModules)) {
    const obj = (opnsense as any)[mod];
    if (!obj) continue;
    const methods = getModuleMethods(obj);
    if (methods.length === 0) continue;
    tools.push({
      name: `${mod}_manage`,
      description: `${desc} — ${methods.length} methods: ${methods.slice(0, 5).join(", ")}…`,
      module: mod,
      methods,
      inputSchema: makeSchema(methods),
    });
  }

  if (config.includePlugins) {
    const plugins = (opnsense as any).plugins;
    if (plugins) {
      for (const [name, obj] of Object.entries(plugins)) {
        if (name === "http") continue;
        const methods = getModuleMethods(obj);
        if (methods.length === 0) continue;
        tools.push({
          name: `plugin_${name}_manage`,
          description: `Plugin: ${name} — ${methods.length} methods: ${methods.slice(0, 5).join(", ")}…`,
          module: "plugins",
          submodule: name,
          methods,
          inputSchema: makeSchema(methods),
        });
      }
    }
  }

  return tools;
}

const TOOLS = discoverTools();
console.error(`Discovered ${TOOLS.length} tools`);

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------
function createServer(): Server {
  const server = new Server(
    { name: "opnsense-mcp", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const tool = TOOLS.find((t) => t.name === name);
    if (!tool) {
      throw new McpError(ErrorCode.MethodNotFound, `Tool ${name} not found`);
    }

    const methodName = (args as any)?.method;
    if (!methodName || !tool.methods.includes(methodName)) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Invalid method '${methodName}'. Available: ${tool.methods.join(", ")}`
      );
    }

    let moduleObj: any;
    if (tool.module === "plugins" && tool.submodule) {
      moduleObj = (opnsense as any).plugins[tool.submodule];
    } else {
      moduleObj = (opnsense as any)[tool.module];
    }

    const fn = moduleObj[methodName];
    if (typeof fn !== "function") {
      throw new McpError(ErrorCode.InternalError, `Method ${methodName} is not callable`);
    }

    try {
      const { method: _, params = {}, ...rest } = args as any;
      const callParams = { ...params, ...rest };
      const result =
        Object.keys(callParams).length > 0
          ? await fn.call(moduleObj, callParams)
          : await fn.call(moduleObj);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (err: any) {
      const msg =
        err?.response?.status
          ? `HTTP ${err.response.status}: ${JSON.stringify(err.response.data)}`
          : err?.message || "Unknown error";
      return {
        content: [{ type: "text", text: `Error calling ${name}.${methodName}: ${msg}` }],
        isError: true,
      };
    }
  });

  return server;
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();
// Parse JSON/form bodies everywhere EXCEPT /mcp (the MCP transport handles its own parsing)
app.use((req, res, next) => {
  if (req.path === "/mcp") return next();
  express.json()(req, res, next);
});
app.use((req, res, next) => {
  if (req.path === "/mcp") return next();
  express.urlencoded({ extended: true })(req, res, next);
});

// ---------------------------------------------------------------------------
// OAuth endpoints
// ---------------------------------------------------------------------------

// RFC 8414 metadata
app.get("/.well-known/oauth-authorization-server", (_req, res) => {
  res.json(oauthMetadata());
});

// Dynamic client registration (RFC 7591) — MCP spec requires this
app.post("/register", (req, res) => {
  const { redirect_uris, client_name } = req.body;
  const clientId = crypto.randomUUID();
  const clientSecret = crypto.randomBytes(32).toString("hex");
  registeredClients.set(clientId, {
    clientId,
    clientSecret,
    redirectUris: redirect_uris || [],
  });
  console.error(`Registered OAuth client: ${client_name || clientId}`);
  res.status(201).json({
    client_id: clientId,
    client_secret: clientSecret,
    client_name: client_name || "MCP Client",
    redirect_uris: redirect_uris || [],
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "client_secret_post",
  });
});

// Authorization endpoint — shows a simple password form
app.get("/authorize", (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, response_type } = req.query;

  if (response_type !== "code") {
    res.status(400).send("Unsupported response_type");
    return;
  }

  res.type("html").send(`<!DOCTYPE html>
<html><head><title>OPNsense MCP — Authorize</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body { font-family: system-ui; max-width: 400px; margin: 80px auto; padding: 0 20px; }
  h1 { font-size: 1.3em; }
  input { display: block; width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; font-size: 16px; border: 1px solid #ccc; border-radius: 6px; }
  button { width: 100%; padding: 12px; background: #0066cc; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
  button:hover { background: #0052a3; }
  .error { color: red; }
</style></head><body>
<h1>Authorize OPNsense MCP</h1>
<p>Enter your password to allow Claude to manage your OPNsense router.</p>
<form method="POST" action="/authorize">
  <input type="hidden" name="client_id" value="${client_id}">
  <input type="hidden" name="redirect_uri" value="${redirect_uri}">
  <input type="hidden" name="state" value="${state || ""}">
  <input type="hidden" name="code_challenge" value="${code_challenge || ""}">
  <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ""}">
  <input type="password" name="password" placeholder="Password" required autofocus>
  <button type="submit">Authorize</button>
</form>
</body></html>`);
});

// Authorization POST — validate password, issue code
app.post("/authorize", (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, password } = req.body;

  if (password !== config.oauthPassword) {
    res.type("html").send(`<!DOCTYPE html>
<html><head><title>OPNsense MCP — Authorize</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body { font-family: system-ui; max-width: 400px; margin: 80px auto; padding: 0 20px; }
  h1 { font-size: 1.3em; }
  input { display: block; width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; font-size: 16px; border: 1px solid #ccc; border-radius: 6px; }
  button { width: 100%; padding: 12px; background: #0066cc; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
  .error { color: red; margin-bottom: 10px; }
</style></head><body>
<h1>Authorize OPNsense MCP</h1>
<p class="error">Wrong password. Try again.</p>
<form method="POST" action="/authorize">
  <input type="hidden" name="client_id" value="${client_id}">
  <input type="hidden" name="redirect_uri" value="${redirect_uri}">
  <input type="hidden" name="state" value="${state || ""}">
  <input type="hidden" name="code_challenge" value="${code_challenge || ""}">
  <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ""}">
  <input type="password" name="password" placeholder="Password" required autofocus>
  <button type="submit">Authorize</button>
</form>
</body></html>`);
    return;
  }

  // Password correct — issue authorization code
  const code = crypto.randomBytes(32).toString("hex");
  authCodes.set(code, {
    clientId: client_id,
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
    redirectUri: redirect_uri,
    expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
  });

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set("code", code);
  if (state) redirectUrl.searchParams.set("state", state);

  res.redirect(302, redirectUrl.toString());
});

// Token endpoint — exchange code for access token
app.post("/token", (req, res) => {
  const { grant_type, code, code_verifier, redirect_uri } = req.body;

  if (grant_type !== "authorization_code") {
    res.status(400).json({ error: "unsupported_grant_type" });
    return;
  }

  const stored = authCodes.get(code);
  if (!stored || stored.expiresAt < Date.now()) {
    authCodes.delete(code);
    res.status(400).json({ error: "invalid_grant" });
    return;
  }

  // Verify PKCE if used
  if (stored.codeChallenge && stored.codeChallengeMethod) {
    let computedChallenge: string;
    if (stored.codeChallengeMethod === "S256") {
      computedChallenge = crypto
        .createHash("sha256")
        .update(code_verifier || "")
        .digest("base64url");
    } else {
      computedChallenge = code_verifier || "";
    }
    if (computedChallenge !== stored.codeChallenge) {
      res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
      return;
    }
  }

  // Verify redirect_uri matches
  if (redirect_uri && redirect_uri !== stored.redirectUri) {
    res.status(400).json({ error: "invalid_grant", error_description: "redirect_uri mismatch" });
    return;
  }

  // Issue access token
  const token = crypto.randomBytes(32).toString("hex");
  accessTokens.add(token);
  authCodes.delete(code);

  console.error(`Issued OAuth access token for client ${stored.clientId}`);

  res.json({
    access_token: token,
    token_type: "Bearer",
    // No expiry — token lives as long as the server is running
  });
});

// ---------------------------------------------------------------------------
// MCP endpoint with OAuth bearer token auth
// ---------------------------------------------------------------------------
app.use("/mcp", (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const token = auth.slice(7);
  if (!accessTokens.has(token)) {
    res.status(401).json({ error: "Invalid token" });
    return;
  }
  next();
});

// Track transports for session management
const transports = new Map<string, StreamableHTTPServerTransport>();

app.post("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;

  if (sessionId && transports.has(sessionId)) {
    const transport = transports.get(sessionId)!;
    await transport.handleRequest(req, res);
    return;
  }

  const server = createServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => crypto.randomUUID(),
    onsessioninitialized: (sid) => {
      transports.set(sid, transport);
    },
  });

  transport.onclose = () => {
    const sid = [...transports.entries()].find(([, t]) => t === transport)?.[0];
    if (sid) transports.delete(sid);
  };

  await server.connect(transport);
  await transport.handleRequest(req, res);
});

app.get("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  if (!sessionId || !transports.has(sessionId)) {
    res.status(400).json({ error: "Invalid or missing session" });
    return;
  }
  await transports.get(sessionId)!.handleRequest(req, res);
});

app.delete("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  if (!sessionId || !transports.has(sessionId)) {
    res.status(400).json({ error: "Invalid or missing session" });
    return;
  }
  await transports.get(sessionId)!.handleRequest(req, res);
});

// Health check (no auth required)
app.get("/health", (_req, res) => {
  res.json({ status: "ok", tools: TOOLS.length, opnsense: config.opnsenseUrl });
});

app.listen(config.port, "0.0.0.0", () => {
  console.error(`OPNsense MCP server listening on http://0.0.0.0:${config.port}/mcp`);
  console.error(`OAuth endpoints: /authorize, /token, /register`);
  console.error(`Metadata: /.well-known/oauth-authorization-server`);
  console.error(`Router: ${config.opnsenseUrl}`);
  console.error(`Tools: ${TOOLS.length} (plugins: ${config.includePlugins ? "enabled" : "disabled"})`);
});
