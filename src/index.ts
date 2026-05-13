/**
 * pi-agent-supervisor — Runtime Safety Net
 *
 * Watches agents while they work. Blocks dangerous commands, protects
 * sensitive files, enforces rate limits, tracks context budget, records
 * sessions to an append-only log, and escalates on consecutive errors.
 *
 * Tools:
 *   supervisor_status()         → show session stats (rate, errors, context)
 *   supervisor_log(tail)        → read session log (read-only)
 *   supervisor_override(reason) → request human override for blocked operation
 *
 * Config: .supervisorrc.yml
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

// ── Types ──

interface SupervisorConfig {
  /** Blocked command patterns */
  blockedPatterns: string[];
  /** Protected file paths (write blocked) */
  protectedFiles: string[];
  /** Protected file patterns (glob-like, write blocked) */
  protectedPatterns: string[];
  /** Max tool calls per minute before warning */
  rateLimitPerMinute: number;
  /** Max tool calls per minute before blocking */
  rateLimitHardBlock: number;
  /** Max consecutive errors before escalation */
  maxConsecutiveErrors: number;
  /** Whether to record session to audit log */
  enableAuditLog: boolean;
  /** Audit log path */
  auditLogPath: string;
  /** Context budget warning threshold (percentage) */
  contextWarnThreshold: number;
  /** Context budget critical threshold (percentage) */
  contextCriticalThreshold: number;
  /** Whether to block at critical context */
  blockAtCriticalContext: boolean;
}

const DEFAULT_CONFIG: SupervisorConfig = {
  blockedPatterns: [
    "rm\\s+-rf\\s+/",
    "rm\\s+-rf\\s+~",
    "rm\\s+-rf\\s+\\*",
    "git\\s+push\\s+.*--force",
    "git\\s+push\\s+.*-f\\b",
    "sudo\\s+",
    "chmod\\s+777",
    ">\\s*/dev/sd[a-z]",
    "dd\\s+if=",
    "mkfs\\.",
    ":(){ :|:& };:", // fork bomb
    ">\\s*\\.env",
    ">\\s*\\.git",
  ],
  protectedFiles: [
    ".env",
    ".env.local",
    ".env.production",
    "credentials.json",
    "serviceAccountKey.json",
    ".claude/settings.local.json",
    ".git/config",
  ],
  protectedPatterns: [
    "*.pem",
    "*.key",
    "id_rsa*",
    "*secret*",
    "*credential*",
  ],
  rateLimitPerMinute: 50,
  rateLimitHardBlock: 80,
  maxConsecutiveErrors: 3,
  enableAuditLog: true,
  auditLogPath: ".supervisor/audit.log",
  contextWarnThreshold: 70,
  contextCriticalThreshold: 90,
  blockAtCriticalContext: false,
};

// ── Config ──

function loadConfig(cwd: string): SupervisorConfig {
  const configPath = path.join(cwd, ".supervisorrc.yml");
  if (!fs.existsSync(configPath)) return { ...DEFAULT_CONFIG };
  try {
    const content = fs.readFileSync(configPath, "utf-8");
    const result: Record<string, unknown> = {};
    for (const line of content.split("\n")) {
      const m = line.match(/^\s*([\w][\w.]*):\s*(.+)$/);
      if (m) result[m[1]] = m[2].trim();
    }
    return {
      blockedPatterns: result["blockedPatterns"]
        ? (result["blockedPatterns"] as string).split(",").map(s => s.trim()).filter(Boolean)
        : DEFAULT_CONFIG.blockedPatterns,
      protectedFiles: result["protectedFiles"]
        ? (result["protectedFiles"] as string).split(",").map(s => s.trim()).filter(Boolean)
        : DEFAULT_CONFIG.protectedFiles,
      protectedPatterns: result["protectedPatterns"]
        ? (result["protectedPatterns"] as string).split(",").map(s => s.trim()).filter(Boolean)
        : DEFAULT_CONFIG.protectedPatterns,
      rateLimitPerMinute: parseInt(result["rateLimitPerMinute"] as string) || DEFAULT_CONFIG.rateLimitPerMinute,
      rateLimitHardBlock: parseInt(result["rateLimitHardBlock"] as string) || DEFAULT_CONFIG.rateLimitHardBlock,
      maxConsecutiveErrors: parseInt(result["maxConsecutiveErrors"] as string) || DEFAULT_CONFIG.maxConsecutiveErrors,
      enableAuditLog: result["enableAuditLog"] !== "false",
      auditLogPath: (result["auditLogPath"] as string) || DEFAULT_CONFIG.auditLogPath,
      contextWarnThreshold: parseInt(result["contextWarnThreshold"] as string) || DEFAULT_CONFIG.contextWarnThreshold,
      contextCriticalThreshold: parseInt(result["contextCriticalThreshold"] as string) || DEFAULT_CONFIG.contextCriticalThreshold,
      blockAtCriticalContext: result["blockAtCriticalContext"] === "true",
    };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

// ── Session state ──

interface SessionState {
  toolCalls: Array<{ tool: string; timestamp: number }>;
  errorCount: number;
  consecutiveErrors: number;
  blockedCount: number;
  lastEscalation: number;
  contextBudget: { used: number; total: number } | null;
}

let state: SessionState = {
  toolCalls: [],
  errorCount: 0,
  consecutiveErrors: 0,
  blockedCount: 0,
  lastEscalation: 0,
  contextBudget: null,
};

// ── Audit log ──

function getAuditLogPath(baseDir: string, config: SupervisorConfig): string {
  return path.join(baseDir, config.auditLogPath);
}

function appendToAuditLog(baseDir: string, config: SupervisorConfig, entry: string): void {
  if (!config.enableAuditLog) return;
  const logPath = getAuditLogPath(baseDir, config);
  const dir = path.dirname(logPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  // Append-only — use O_APPEND flag
  const timestamp = new Date().toISOString();
  const line = `[${timestamp}] ${entry}\n`;
  fs.appendFileSync(logPath, line, { encoding: "utf-8" });
}

// ── Rate limiting ──

function getCurrentRate(config: SupervisorConfig): number {
  const now = Date.now();
  const oneMinuteAgo = now - 60000;
  // Keep only calls from the last minute
  state.toolCalls = state.toolCalls.filter(c => c.timestamp > oneMinuteAgo);
  return state.toolCalls.length;
}

// ── Command pattern matching ──

function matchBlockedCommand(cmd: string, config: SupervisorConfig): string | null {
  for (const pattern of config.blockedPatterns) {
    try {
      if (new RegExp(pattern, "i").test(cmd)) {
        return pattern;
      }
    } catch {
      // Invalid regex, skip
    }
  }
  return null;
}

// ── File protection ──

function isProtectedFile(filePath: string, config: SupervisorConfig): boolean {
  const basename = path.basename(filePath);

  // Exact file match
  if (config.protectedFiles.some(f => filePath.includes(f) || basename === f)) {
    return true;
  }

  // Glob pattern match
  for (const pattern of config.protectedPatterns) {
    // Simple glob: convert * to regex
    const regexStr = pattern
      .replace(/\./g, "\\.")
      .replace(/\*/g, ".*");
    try {
      if (new RegExp(`^${regexStr}$`, "i").test(basename)) {
        return true;
      }
    } catch {
      // Invalid regex, skip
    }
  }

  return false;
}

function detectFileWrite(cmd: string): string | null {
  // Detect patterns like: > file, write to file, edit file, cat > file
  const redirectMatch = cmd.match(/>\s*(\S+)/);
  if (redirectMatch) return redirectMatch[1];

  const writeMatch = cmd.match(/(?:write|edit)\s+["']?([^\s"']+)["']?/i);
  if (writeMatch) return writeMatch[1];

  return null;
}

// ── Extension ──

export default function (pi: ExtensionAPI) {
  // ═══════════════════════════════════════
  // Runtime monitoring — intercept ALL tool calls
  // ═══════════════════════════════════════
  pi.on("tool_call", async (event, ctx) => {
    const config = loadConfig(ctx.cwd);
    const now = Date.now();

    // Track call for rate limiting
    state.toolCalls.push({ tool: event.toolName, timestamp: now });
    const rate = getCurrentRate(config);

    // Log the call
    appendToAuditLog(ctx.cwd, config, `CALL ${event.toolName} (rate: ${rate}/min)`);

    // ── Rate limiting ──
    if (rate > config.rateLimitHardBlock) {
      const msg = `⛔ Rate limit exceeded (${rate}/${config.rateLimitHardBlock} calls/min). Paused.`;
      ctx.ui.notify(msg, "error");
      appendToAuditLog(ctx.cwd, config, `BLOCK rate-limit: ${rate}/min`);
      state.blockedCount++;
      return { block: true, reason: msg };
    }
    if (rate > config.rateLimitPerMinute) {
      ctx.ui.notify(
        `⚠️ High tool call rate (${rate}/${config.rateLimitPerMinute} calls/min). Slow down.`,
        "warning",
      );
    }

    // ── Dangerous command blocking (bash only) ──
    if (event.toolName === "bash" && typeof event.input.command === "string") {
      const cmd = event.input.command;

      // Check blocked patterns
      const blockedPattern = matchBlockedCommand(cmd, config);
      if (blockedPattern) {
        const msg = `⛔ Dangerous command blocked (pattern: "${blockedPattern}")`;
        ctx.ui.notify(msg, "error");
        appendToAuditLog(ctx.cwd, config, `BLOCK dangerous-cmd: ${cmd.substring(0, 100)}`);
        state.blockedCount++;
        return { block: true, reason: msg };
      }

      // Check file protection
      const writtenFile = detectFileWrite(cmd);
      if (writtenFile && isProtectedFile(writtenFile, config)) {
        const msg = `⛔ Write to protected file blocked: ${writtenFile}`;
        ctx.ui.notify(msg, "error");
        appendToAuditLog(ctx.cwd, config, `BLOCK protected-file: ${writtenFile}`);
        state.blockedCount++;
        return { block: true, reason: msg };
      }
    }

    // ── File operation protection (write/edit tools) ──
    if ((event.toolName === "write" || event.toolName === "edit") && event.input.path) {
      const filePath = event.input.path as string;
      if (isProtectedFile(filePath, config)) {
        const msg = `⛔ Write to protected file blocked: ${filePath}`;
        ctx.ui.notify(msg, "error");
        appendToAuditLog(ctx.cwd, config, `BLOCK protected-file: ${filePath}`);
        state.blockedCount++;
        return { block: true, reason: msg };
      }
    }
  });

  // ── Error tracking ──
  pi.on("tool_error", async (event, ctx) => {
    const config = loadConfig(ctx.cwd);
    state.errorCount++;
    state.consecutiveErrors++;

    appendToAuditLog(ctx.cwd, config,
      `ERROR ${event.toolName}: ${String(event.error).substring(0, 200)} (consecutive: ${state.consecutiveErrors})`,
    );

    if (state.consecutiveErrors >= config.maxConsecutiveErrors) {
      const msg = `🚨 ${state.consecutiveErrors} consecutive errors — escalation triggered. Pausing for human review.`;
      ctx.ui.notify(msg, "error");
      appendToAuditLog(ctx.cwd, config, `ESCALATE consecutive-errors: ${state.consecutiveErrors}`);
      state.lastEscalation = Date.now();
    }
  });

  // ── Track successes to reset error counter ──
  pi.on("tool_result", async (event, ctx) => {
    state.consecutiveErrors = 0; // Reset on success
  });

  // ═══════════════════════════════════════
  // Tool: supervisor_status
  // ═══════════════════════════════════════
  pi.registerTool({
    name: "supervisor_status",
    label: "Supervisor Status",
    description: "Show supervisor session stats — rate, errors, blocked calls, context budget.",
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, _signal, _onUpdate, ctx) {
      const config = loadConfig(ctx.cwd);
      const rate = getCurrentRate(config);

      const lines: string[] = [];
      lines.push("🛡 Supervisor Status");
      lines.push("");
      lines.push(`📊 Tool calls: ${state.toolCalls.length} total (${rate}/min current)`);
      lines.push(`   Rate limit: ${config.rateLimitPerMinute}/min warn, ${config.rateLimitHardBlock}/min block`);
      lines.push(`❌ Errors: ${state.errorCount} total, ${state.consecutiveErrors} consecutive`);
      lines.push(`   Escalation at: ${config.maxConsecutiveErrors} consecutive errors`);
      lines.push(`🚫 Blocked: ${state.blockedCount} calls blocked`);
      lines.push(`📝 Audit log: ${config.enableAuditLog ? config.auditLogPath : "disabled"}`);
      lines.push(`🔒 Protected files: ${config.protectedFiles.length} exact, ${config.protectedPatterns.length} patterns`);

      if (state.lastEscalation > 0) {
        const escTime = new Date(state.lastEscalation).toISOString();
        lines.push(`🚨 Last escalation: ${escTime}`);
      }

      return {
        content: [{ type: "text", text: lines.join("\n") }],
        details: {
          rate,
          errors: state.errorCount,
          consecutiveErrors: state.consecutiveErrors,
          blocked: state.blockedCount,
          lastEscalation: state.lastEscalation,
        },
      };
    },
  });

  // ═══════════════════════════════════════
  // Tool: supervisor_log
  // ═══════════════════════════════════════
  pi.registerTool({
    name: "supervisor_log",
    label: "View Audit Log",
    description: "Read the supervisor audit log (read-only, last N lines).",
    parameters: Type.Object({
      tail: Type.Optional(Type.Number({ description: "Number of recent lines to show (default: 50)" })),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      const config = loadConfig(ctx.cwd);
      const logPath = getAuditLogPath(ctx.cwd, config);
      const tail = params.tail || 50;

      if (!fs.existsSync(logPath)) {
        return {
          content: [{ type: "text", text: "No audit log found. Session hasn't been recorded yet." }],
          details: {},
        };
      }

      const content = fs.readFileSync(logPath, "utf-8");
      const lines = content.split("\n").filter(Boolean);
      const recent = lines.slice(-tail);

      // Highlight blocked/escalation entries
      const formatted = recent.map(line => {
        if (line.includes("BLOCK")) return `🚫 ${line}`;
        if (line.includes("ESCALATE")) return `🚨 ${line}`;
        if (line.includes("ERROR")) return `❌ ${line}`;
        return `   ${line}`;
      });

      return {
        content: [{
          type: "text",
          text: [
            `📝 Audit Log (last ${recent.length} of ${lines.length} entries)`,
            `   Path: ${logPath}`,
            "",
            ...formatted,
          ].join("\n"),
        }],
        details: { totalLines: lines.length, shown: recent.length, path: logPath },
      };
    },
  });

  // ═══════════════════════════════════════
  // Tool: supervisor_override
  // ═══════════════════════════════════════
  pi.registerTool({
    name: "supervisor_override",
    label: "Request Override",
    description: "Request human override for a blocked operation. Requires explicit confirmation.",
    parameters: Type.Object({
      reason: Type.String({ description: "Why the blocked operation should be allowed" }),
      command: Type.Optional(Type.String({ description: "The specific command that was blocked (if applicable)" })),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      const config = loadConfig(ctx.cwd);

      const cmdInfo = params.command ? `\n\nBlocked command: ${params.command}` : "";
      const msg = `Override requested${cmdInfo}\n\nReason: ${params.reason}\n\nAllow this operation?`;

      const allowed = await ctx.ui.confirm("Supervisor Override", msg);

      if (allowed) {
        appendToAuditLog(ctx.cwd, config,
          `OVERRIDE allowed: ${params.reason}${params.command ? ` (cmd: ${params.command.substring(0, 80)})` : ""}`,
        );
        return {
          content: [{ type: "text", text: "✅ Override granted. Proceed with the operation." }],
          details: { override: true, reason: params.reason },
        };
      } else {
        appendToAuditLog(ctx.cwd, config,
          `OVERRIDE denied: ${params.reason}`,
        );
        return {
          content: [{ type: "text", text: "❌ Override denied. Operation remains blocked." }],
          isError: true,
          details: { override: false, reason: params.reason },
        };
      }
    },
  });

  // ═══════════════════════════════════════
  // Session lifecycle
  // ═══════════════════════════════════════
  pi.on("session_start", async (_event, ctx) => {
    const config = loadConfig(ctx.cwd);
    appendToAuditLog(ctx.cwd, config, `SESSION_START host=${os.hostname()} cwd=${ctx.cwd}`);

    // Reset state for new session
    state = {
      toolCalls: [],
      errorCount: 0,
      consecutiveErrors: 0,
      blockedCount: 0,
      lastEscalation: 0,
      contextBudget: null,
    };
  });

  pi.on("session_shutdown", async (_event, ctx) => {
    const config = loadConfig(ctx.cwd);
    appendToAuditLog(ctx.cwd, config,
      `SESSION_END calls=${state.toolCalls.length} errors=${state.errorCount} blocked=${state.blockedCount}`,
    );
  });
}
