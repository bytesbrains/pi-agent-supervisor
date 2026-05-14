/**
 * pi-agent-supervisor — Runtime Safety Net
 *
 * Tools: supervisor_status, supervisor_log, supervisor_override
 * Config: .supervisorrc.yml
 * Patterns: patterns/*.txt
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import * as path from "node:path";
import * as os from "node:os";
import { loadConfig } from "./config";
import { appendToAuditLog } from "./helpers";
import { resetState } from "./state";
import { interceptToolCall, trackToolError, trackToolSuccess } from "./intercepts";
import { statusTool, logTool, overrideTool } from "./tools/supervisor";

export default function (pi: ExtensionAPI) {
  const extensionDir = path.dirname(__filename || path.join(__dirname, ".."));

  pi.on("tool_call", (event, ctx) => interceptToolCall(event, ctx, extensionDir));
  pi.on("tool_error", (event, ctx) => trackToolError(event, ctx, extensionDir));
  pi.on("tool_result", () => trackToolSuccess());

  pi.registerTool(statusTool);
  pi.registerTool(logTool);
  pi.registerTool(overrideTool);

  pi.on("session_start", (_event, ctx) => {
    const config = loadConfig(ctx.cwd, extensionDir);
    resetState();
    appendToAuditLog(ctx.cwd, config, `SESSION_START host=${os.hostname()} cwd=${ctx.cwd}`);
  });

  pi.on("session_shutdown", (_event, ctx) => {
    const config = loadConfig(ctx.cwd, extensionDir);
    const { state } = require("./state");
    appendToAuditLog(ctx.cwd, config, `SESSION_END calls=${state.toolCalls.length} errors=${state.errorCount} blocked=${state.blockedCount}`);
  });
}
