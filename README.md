# OPNsense MCP Server

A hosted [Model Context Protocol](https://modelcontextprotocol.io/) server that gives Claude (and other MCP clients) full access to your OPNsense router's API. Connects Claude.ai to your firewall, diagnostics, VPN, DNS, DHCP, and 20+ other OPNsense modules via a single MCP integration.

Inspired by [Pixelworlds/opnsense-mcp-server](https://github.com/Pixelworlds/opnsense-mcp-server), rebuilt from scratch with a focus on reliability and Claude.ai hosted MCP support.

## Features

- **24 core tool modules** covering firewall, diagnostics, interfaces, VPN (WireGuard/OpenVPN/IPsec), DNS, DHCP, and more
- **750+ methods** auto-discovered from the OPNsense TypeScript SDK with per-method parameter introspection
- **OAuth 2.0 + PKCE** for secure authentication from Claude.ai
- **Retry with backoff** on transient API failures (5xx, timeouts, connection resets)
- **Structured logging** with timestamps and component tags
- **Graceful shutdown** on SIGTERM/SIGINT
- **Optional plugin support** — enable `INCLUDE_PLUGINS=true` to expose 60+ additional plugin modules

## Architecture

```
Claude.ai → Cloudflare Tunnel → MCP Server (Node.js) → OPNsense API
                                     ↑
                              OAuth 2.0 bearer token
```

The server runs natively on your LAN (not in Docker) so it can reach the OPNsense router directly. A Cloudflare Tunnel (or similar reverse proxy) exposes it to Claude.ai.

## Quick start

### 1. Create an OPNsense API key

In your OPNsense web UI: **System > Access > Users > edit your user > API keys > +**

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your API key, secret, OAuth password, and public URL
```

### 3. Build and run

```bash
npm install
npm run build
npm start
```

### 4. Connect Claude.ai

Add the MCP server in Claude.ai settings using your public URL (e.g. `https://opnsense-mcp.yourdomain.com`). Claude will redirect to the OAuth flow — enter the password you set in `OAUTH_PASSWORD`.

## Running as a service (macOS)

Create a launchd plist at `~/Library/LaunchAgents/com.opnsense-mcp.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.opnsense-mcp</string>
    <key>WorkingDirectory</key>
    <string>/path/to/opnsense-mcp</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/homebrew/bin/node</string>
        <string>/path/to/opnsense-mcp/dist/server.js</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/path/to/opnsense-mcp/logs/stderr.log</string>
</dict>
</plist>
```

Then load it:

```bash
mkdir -p logs
launchctl load ~/Library/LaunchAgents/com.opnsense-mcp.plist
```

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPNSENSE_URL` | | `https://192.168.50.1` | Router API URL |
| `OPNSENSE_API_KEY` | Yes | | API key from OPNsense |
| `OPNSENSE_API_SECRET` | Yes | | API secret from OPNsense |
| `OPNSENSE_VERIFY_SSL` | | `true` | Set to `false` for self-signed certs |
| `OAUTH_PASSWORD` | Yes | | Password for the OAuth authorize form |
| `PUBLIC_URL` | Yes | | Public URL (e.g. Cloudflare Tunnel hostname) |
| `INCLUDE_PLUGINS` | | `false` | Enable OPNsense plugin modules |
| `TOKEN_TTL_HOURS` | | `24` | OAuth token lifetime in hours |
| `PORT` | | `3100` | Server listen port |
| `LOG_LEVEL` | | `info` | Logging level: debug, info, warn, error |

## Available tools

Each tool exposes all methods from the corresponding OPNsense API module:

| Tool | Description | Methods |
|---|---|---|
| `core_manage` | System management, backups, dashboard | 46 |
| `firewall_manage` | Rules, aliases, categories, NAT | 67 |
| `diagnostics_manage` | Ping, traceroute, DNS, netstat, packet capture, netflow | 90 |
| `interfaces_manage` | Network interfaces, VIPs, VLANs | 63 |
| `ipsec_manage` | IPsec VPN tunnels and status | 80 |
| `unbound_manage` | Unbound DNS resolver and DNSBL | 42 |
| `wireguard_manage` | WireGuard VPN peers and status | 28 |
| `openvpn_manage` | OpenVPN servers and clients | 28 |
| `ids_manage` | Intrusion Detection (Suricata) | 40 |
| `firmware_manage` | Firmware updates and packages | 26 |
| `auth_manage` | Users, groups, and privileges | 19 |
| `trust_manage` | Certificates and CAs | 25 |
| ...and 12 more | DHCP, DNS, routing, traffic shaping, etc. | |

With `INCLUDE_PLUGINS=true`, 60+ additional plugin modules are available (HAProxy, Caddy, Tailscale, CrowdSec, etc.).

## Project structure

```
src/
  config.ts    — Environment validation
  logger.ts    — Structured logging
  tools.ts     — Tool discovery, parameter introspection, retry logic
  oauth.ts     — OAuth 2.0 with PKCE
  server.ts    — Express app, MCP transport, graceful shutdown
```

## License

MIT
