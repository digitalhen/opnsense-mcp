// ---------------------------------------------------------------------------
// Configuration — validated at startup
// ---------------------------------------------------------------------------

import "dotenv/config";

export interface Config {
  opnsenseUrl: string;
  apiKey: string;
  apiSecret: string;
  verifySsl: boolean;
  includePlugins: boolean;
  oauthPassword: string;
  port: number;
  publicUrl: string;
  tokenTtlMs: number;
}

export function loadConfig(): Config {
  const missing: string[] = [];

  const apiKey = process.env.OPNSENSE_API_KEY || "";
  const apiSecret = process.env.OPNSENSE_API_SECRET || "";
  const oauthPassword = process.env.OAUTH_PASSWORD || "";
  const publicUrl = process.env.PUBLIC_URL || "";

  if (!apiKey) missing.push("OPNSENSE_API_KEY");
  if (!apiSecret) missing.push("OPNSENSE_API_SECRET");
  if (!oauthPassword) missing.push("OAUTH_PASSWORD");
  if (!publicUrl) missing.push("PUBLIC_URL");

  if (missing.length > 0) {
    console.error(`Missing required environment variables: ${missing.join(", ")}`);
    process.exit(1);
  }

  return {
    opnsenseUrl: process.env.OPNSENSE_URL || "https://192.168.50.1",
    apiKey,
    apiSecret,
    verifySsl: process.env.OPNSENSE_VERIFY_SSL !== "false",
    includePlugins: process.env.INCLUDE_PLUGINS === "true",
    oauthPassword,
    port: parseInt(process.env.PORT || "3100", 10),
    publicUrl,
    tokenTtlMs: parseInt(process.env.TOKEN_TTL_HOURS || "24", 10) * 60 * 60 * 1000,
  };
}
