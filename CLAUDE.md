# CLAUDE.md

## Project overview

OPNsense MCP server — a hosted Model Context Protocol server that connects Claude.ai to an OPNsense router's API. Runs natively on macOS via launchd, exposed through a Cloudflare Tunnel.

## Architecture

- `src/config.ts` — env validation with dotenv
- `src/logger.ts` — structured stderr logging with component tags
- `src/tools.ts` — OPNsense SDK introspection, tool discovery, parameter mapping, retry with backoff
- `src/oauth.ts` — OAuth 2.0 + PKCE for Claude.ai auth, token expiry, XSS-safe HTML
- `src/server.ts` — Express app, MCP transport (StreamableHTTP), session management, graceful shutdown

## Key patterns

- Tool methods are introspected at startup from the OPNsense TypeScript SDK. Parameter names are parsed from `fn.toString()` with multiple regex fallbacks.
- The `config` param (always last in SDK methods) is filtered out — only user-facing params are exposed.
- Transient errors (5xx, 429, ECONNRESET, ETIMEDOUT) trigger automatic retry with exponential backoff (up to 2 retries).
- Each MCP session gets its own Server instance. Transports are tracked in a Map by session ID.

## Build & run

```bash
npm run build   # tsc
npm start       # node dist/server.js
npm run dev     # tsx src/server.ts
```

Requires `.env` file — see `.env.example`.

## Deployment

Runs as a native macOS launchd service (not Docker — macOS Docker VM can't reach LAN).
Plist: `~/Library/LaunchAgents/com.opnsense-mcp.plist`
Cloudflare tunnel routes to `host.docker.internal:3100`.

## Important

- This connects to a LIVE PRODUCTION ROUTER. Do not make destructive API calls without explicit user consent.
- The OPNsense API key has full access. Be careful with set/del/apply methods.
- `.env` contains real secrets — never commit it.
