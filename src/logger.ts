// ---------------------------------------------------------------------------
// Structured logger — writes to stderr so it doesn't interfere with MCP
// ---------------------------------------------------------------------------

type Level = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<Level, number> = { debug: 0, info: 1, warn: 2, error: 3 };

const minLevel: Level = (process.env.LOG_LEVEL as Level) || "info";

function shouldLog(level: Level): boolean {
  return LEVEL_ORDER[level] >= LEVEL_ORDER[minLevel];
}

function fmt(level: Level, component: string, msg: string, extra?: Record<string, unknown>): string {
  const ts = new Date().toISOString();
  const base = `${ts} [${level.toUpperCase()}] [${component}] ${msg}`;
  if (extra && Object.keys(extra).length > 0) {
    return `${base} ${JSON.stringify(extra)}`;
  }
  return base;
}

export function createLogger(component: string) {
  return {
    debug(msg: string, extra?: Record<string, unknown>) {
      if (shouldLog("debug")) console.error(fmt("debug", component, msg, extra));
    },
    info(msg: string, extra?: Record<string, unknown>) {
      if (shouldLog("info")) console.error(fmt("info", component, msg, extra));
    },
    warn(msg: string, extra?: Record<string, unknown>) {
      if (shouldLog("warn")) console.error(fmt("warn", component, msg, extra));
    },
    error(msg: string, extra?: Record<string, unknown>) {
      if (shouldLog("error")) console.error(fmt("error", component, msg, extra));
    },
  };
}
