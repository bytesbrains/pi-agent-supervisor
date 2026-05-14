import { Type } from "typebox";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { loadConfig } from "../config";
import { getAuditLogPath, appendToAuditLog, getCurrentRate } from "../helpers";
import { state } from "../state";
import * as fs from "node:fs";

export const statusTool = {
  name: "supervisor_status" as const, label: "Supervisor Status",
  description: "Show supervisor session stats.",
  parameters: Type.Object({}),
  async execute(_id: string, _p: any, _s: any, _u: any, ctx: ExtensionContext) {
    const config = loadConfig(ctx.cwd);
    const rate = getCurrentRate(config);
    const lines = ["🛡 Supervisor Status", "",
      `📊 Tool calls: ${state.toolCalls.length} total (${rate}/min)`,
      `   Rate limit: ${config.rateLimitPerMinute}/min warn, ${config.rateLimitHardBlock}/min block`,
      `❌ Errors: ${state.errorCount} total, ${state.consecutiveErrors} consecutive`,
      `   Escalation at: ${config.maxConsecutiveErrors}`,
      `🚫 Blocked: ${state.blockedCount}`,
      `📝 Audit log: ${config.enableAuditLog ? config.auditLogPath : "disabled"}`,
      `🔒 Protected: ${config.protectedFiles.length} files, ${config.protectedPatterns.length} patterns`,
    ];
    if (state.lastEscalation > 0) lines.push(`🚨 Last escalation: ${new Date(state.lastEscalation).toISOString()}`);
    return { content: [{ type: "text", text: lines.join("\n") }], details: { rate, errors: state.errorCount, blocked: state.blockedCount } };
  },
};

export const logTool = {
  name: "supervisor_log" as const, label: "View Audit Log",
  description: "Read the supervisor audit log (read-only).",
  parameters: Type.Object({ tail: Type.Optional(Type.Number({})) }),
  async execute(_id: string, params: any, _s: any, _u: any, ctx: ExtensionContext) {
    const config = loadConfig(ctx.cwd);
    const logPath = getAuditLogPath(ctx.cwd, config);
    const tail = params.tail || 50;
    if (!fs.existsSync(logPath)) return { content: [{ type: "text", text: "No audit log found." }], details: {} };
    const content = fs.readFileSync(logPath, "utf-8");
    const lines = content.split("\n").filter(Boolean);
    const recent = lines.slice(-tail).map(line => {
      if (line.includes("BLOCK")) return `🚫 ${line}`;
      if (line.includes("ESCALATE")) return `🚨 ${line}`;
      if (line.includes("ERROR")) return `❌ ${line}`;
      return `   ${line}`;
    });
    return { content: [{ type: "text", text: [`📝 Audit Log (last ${recent.length} of ${lines.length})`, "", ...recent].join("\n") }], details: { totalLines: lines.length } };
  },
};

export const overrideTool = {
  name: "supervisor_override" as const, label: "Request Override",
  description: "Request human override for a blocked operation.",
  parameters: Type.Object({ reason: Type.String({}), command: Type.Optional(Type.String({})) }),
  async execute(_id: string, params: any, _s: any, _u: any, ctx: ExtensionContext) {
    const config = loadConfig(ctx.cwd);
    const cmdInfo = params.command ? `\n\nBlocked command: ${params.command}` : "";
    const allowed = await ctx.ui.confirm("Supervisor Override", `Override requested${cmdInfo}\n\nReason: ${params.reason}\n\nAllow?`);
    if (allowed) {
      appendToAuditLog(ctx.cwd, config, `OVERRIDE allowed: ${params.reason}`);
      return { content: [{ type: "text", text: "✅ Override granted." }], details: { override: true } };
    }
    appendToAuditLog(ctx.cwd, config, `OVERRIDE denied: ${params.reason}`);
    return { content: [{ type: "text", text: "❌ Override denied." }], isError: true, details: { override: false } };
  },
};
