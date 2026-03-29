// ---------------------------------------------------------------------------
// OAuth 2.0 — simple implementation for Claude.ai hosted MCP
// ---------------------------------------------------------------------------

import { Router } from "express";
import crypto from "crypto";
import type { Config } from "./config.js";
import { createLogger } from "./logger.js";

const log = createLogger("oauth");

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

interface AuthCode {
  clientId: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  redirectUri: string;
  expiresAt: number;
}

interface TokenRecord {
  clientId: string;
  issuedAt: number;
  expiresAt: number;
}

interface RegisteredClient {
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
}

const authCodes = new Map<string, AuthCode>();
const accessTokens = new Map<string, TokenRecord>();
const registeredClients = new Map<string, RegisteredClient>();

// Periodic cleanup of expired tokens and codes
setInterval(() => {
  const now = Date.now();
  for (const [code, data] of authCodes) {
    if (data.expiresAt < now) authCodes.delete(code);
  }
  for (const [token, data] of accessTokens) {
    if (data.expiresAt < now) accessTokens.delete(token);
  }
}, 60_000);

// ---------------------------------------------------------------------------
// Token validation — used by MCP auth middleware
// ---------------------------------------------------------------------------

export function isValidToken(token: string): boolean {
  const record = accessTokens.get(token);
  if (!record) return false;
  if (record.expiresAt < Date.now()) {
    accessTokens.delete(token);
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// HTML escaping to prevent XSS
// ---------------------------------------------------------------------------

function esc(str: unknown): string {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

export function createOAuthRouter(config: Config): Router {
  const router = Router();

  // RFC 8414 metadata
  router.get("/.well-known/oauth-authorization-server", (_req, res) => {
    res.json({
      issuer: config.publicUrl,
      authorization_endpoint: `${config.publicUrl}/authorize`,
      token_endpoint: `${config.publicUrl}/token`,
      registration_endpoint: `${config.publicUrl}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
      code_challenge_methods_supported: ["S256", "plain"],
    });
  });

  // Dynamic client registration (RFC 7591)
  router.post("/register", (req, res) => {
    const { redirect_uris, client_name } = req.body;
    const clientId = crypto.randomUUID();
    const clientSecret = crypto.randomBytes(32).toString("hex");
    registeredClients.set(clientId, {
      clientId,
      clientSecret,
      redirectUris: redirect_uris || [],
    });
    log.info(`Registered OAuth client: ${client_name || clientId}`);
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

  // Authorization GET — show password form
  router.get("/authorize", (req, res) => {
    const { client_id, redirect_uri, state, code_challenge, code_challenge_method, response_type } = req.query;

    if (response_type !== "code") {
      res.status(400).send("Unsupported response_type");
      return;
    }

    res.type("html").send(renderAuthForm({
      clientId: esc(client_id),
      redirectUri: esc(redirect_uri),
      state: esc(state),
      codeChallenge: esc(code_challenge),
      codeChallengeMethod: esc(code_challenge_method),
    }));
  });

  // Authorization POST — validate password, issue code
  router.post("/authorize", (req, res) => {
    const { client_id, redirect_uri, state, code_challenge, code_challenge_method, password } = req.body;

    if (password !== config.oauthPassword) {
      log.warn("Failed authorization attempt");
      res.type("html").send(renderAuthForm({
        clientId: esc(client_id),
        redirectUri: esc(redirect_uri),
        state: esc(state),
        codeChallenge: esc(code_challenge),
        codeChallengeMethod: esc(code_challenge_method),
        error: "Wrong password. Try again.",
      }));
      return;
    }

    const code = crypto.randomBytes(32).toString("hex");
    authCodes.set(code, {
      clientId: client_id,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method,
      redirectUri: redirect_uri,
      expiresAt: Date.now() + 10 * 60 * 1000,
    });

    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set("code", code);
    if (state) redirectUrl.searchParams.set("state", state);

    log.info(`Authorization code issued for client ${client_id}`);
    res.redirect(302, redirectUrl.toString());
  });

  // Token endpoint — exchange code for access token
  router.post("/token", (req, res) => {
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

    // PKCE verification
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
      const a = Buffer.from(computedChallenge, "utf8");
      const b = Buffer.from(stored.codeChallenge, "utf8");
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
        return;
      }
    }

    // Verify redirect_uri matches
    if (redirect_uri && redirect_uri !== stored.redirectUri) {
      res.status(400).json({ error: "invalid_grant", error_description: "redirect_uri mismatch" });
      return;
    }

    // Issue access token with expiry
    const token = crypto.randomBytes(32).toString("hex");
    const now = Date.now();
    accessTokens.set(token, {
      clientId: stored.clientId,
      issuedAt: now,
      expiresAt: now + config.tokenTtlMs,
    });
    authCodes.delete(code);

    log.info(`Issued access token for client ${stored.clientId}`);

    res.json({
      access_token: token,
      token_type: "Bearer",
      expires_in: Math.floor(config.tokenTtlMs / 1000),
    });
  });

  return router;
}

// ---------------------------------------------------------------------------
// Auth form template
// ---------------------------------------------------------------------------

function renderAuthForm(opts: {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  error?: string;
}): string {
  const errorHtml = opts.error ? `<p class="error">${esc(opts.error)}</p>` : "";
  return `<!DOCTYPE html>
<html><head><title>OPNsense MCP — Authorize</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body { font-family: system-ui; max-width: 400px; margin: 80px auto; padding: 0 20px; }
  h1 { font-size: 1.3em; }
  input { display: block; width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; font-size: 16px; border: 1px solid #ccc; border-radius: 6px; }
  button { width: 100%; padding: 12px; background: #0066cc; color: white; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
  button:hover { background: #0052a3; }
  .error { color: red; margin-bottom: 10px; }
</style></head><body>
<h1>Authorize OPNsense MCP</h1>
<p>Enter your password to allow Claude to manage your OPNsense router.</p>
${errorHtml}
<form method="POST" action="/authorize">
  <input type="hidden" name="client_id" value="${opts.clientId}">
  <input type="hidden" name="redirect_uri" value="${opts.redirectUri}">
  <input type="hidden" name="state" value="${opts.state}">
  <input type="hidden" name="code_challenge" value="${opts.codeChallenge}">
  <input type="hidden" name="code_challenge_method" value="${opts.codeChallengeMethod}">
  <input type="password" name="password" placeholder="Password" required autofocus>
  <button type="submit">Authorize</button>
</form>
</body></html>`;
}
