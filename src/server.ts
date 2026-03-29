// ---------------------------------------------------------------------------
// OPNsense MCP Server — main entry point
// ---------------------------------------------------------------------------

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import express from "express";
import crypto from "crypto";
import { loadConfig } from "./config.js";
import { createLogger } from "./logger.js";
import { initClient, discoverTools, executeMethod, type ToolDef } from "./tools.js";
import { createOAuthRouter, isValidToken } from "./oauth.js";

const log = createLogger("server");

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

const config = loadConfig();
initClient(config);

const TOOLS = discoverTools();
log.info(`Discovered ${TOOLS.length} tools, ${TOOLS.reduce((n, t) => n + t.methods.size, 0)} total methods`);

// Build a lookup map for fast tool resolution
const toolMap = new Map<string, ToolDef>(TOOLS.map((t) => [t.name, t]));

// ---------------------------------------------------------------------------
// MCP Server factory
// ---------------------------------------------------------------------------

function createMcpServer(): Server {
  const server = new Server(
    { name: "opnsense-mcp", version: "2.0.0" },
    { capabilities: { tools: {} } },
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
    const tool = toolMap.get(name);
    if (!tool) {
      throw new McpError(ErrorCode.MethodNotFound, `Tool '${name}' not found`);
    }

    const methodName = (args as any)?.method;
    if (!methodName || !tool.methods.has(methodName)) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Invalid method '${methodName}'. Available: ${[...tool.methods.keys()].join(", ")}`,
      );
    }

    const { result, isError } = await executeMethod(tool, methodName, (args as any) || {});

    const text = typeof result === "string" ? result : JSON.stringify(result, null, 2);
    return {
      content: [{ type: "text" as const, text }],
      ...(isError ? { isError: true } : {}),
    };
  });

  return server;
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();

// Parse JSON/form bodies everywhere EXCEPT /mcp (transport handles its own)
app.use((req, res, next) => {
  if (req.path === "/mcp") return next();
  express.json()(req, res, next);
});
app.use((req, res, next) => {
  if (req.path === "/mcp") return next();
  express.urlencoded({ extended: true })(req, res, next);
});

// OAuth routes
app.use(createOAuthRouter(config));

// Bearer token auth for /mcp
app.use("/mcp", (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  if (!isValidToken(auth.slice(7))) {
    res.status(401).json({ error: "Invalid or expired token" });
    return;
  }
  next();
});

// ---------------------------------------------------------------------------
// MCP transport management
// ---------------------------------------------------------------------------

const transports = new Map<string, StreamableHTTPServerTransport>();

function cleanupTransport(sessionId: string) {
  const transport = transports.get(sessionId);
  if (transport) {
    transports.delete(sessionId);
    log.info(`Session closed: ${sessionId}`);
  }
}

app.post("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;

  if (sessionId && transports.has(sessionId)) {
    await transports.get(sessionId)!.handleRequest(req, res);
    return;
  }

  const server = createMcpServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => crypto.randomUUID(),
    onsessioninitialized: (sid) => {
      transports.set(sid, transport);
      log.info(`Session created: ${sid}`);
    },
  });

  transport.onclose = () => {
    const sid = [...transports.entries()].find(([, t]) => t === transport)?.[0];
    if (sid) cleanupTransport(sid);
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

// Health check
app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    tools: TOOLS.length,
    methods: TOOLS.reduce((n, t) => n + t.methods.size, 0),
    sessions: transports.size,
    opnsense: config.opnsenseUrl,
  });
});

// ---------------------------------------------------------------------------
// Start with graceful shutdown
// ---------------------------------------------------------------------------

const server = app.listen(config.port, "0.0.0.0", () => {
  log.info(`Listening on http://0.0.0.0:${config.port}/mcp`);
  log.info(`OAuth endpoints: /authorize, /token, /register`);
  log.info(`Router: ${config.opnsenseUrl}`);
  log.info(`Tools: ${TOOLS.length} (plugins: ${config.includePlugins ? "enabled" : "disabled"})`);
});

function shutdown(signal: string) {
  log.info(`${signal} received — shutting down`);
  // Close all MCP transports
  for (const [sid, transport] of transports) {
    try {
      transport.close?.();
    } catch {
      // ignore
    }
    transports.delete(sid);
  }
  server.close(() => {
    log.info("Server closed");
    process.exit(0);
  });
  // Force exit after 5s
  setTimeout(() => process.exit(1), 5000);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
