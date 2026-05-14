import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { loadConfig } from "./config";
import { getCurrentRate, matchBlockedCommand, isProtectedFile, detectFileWrite, appendToAuditLog } from "./helpers";
import { state } from "./state";

export async function interceptToolCall(event: any, ctx: ExtensionContext, extensionDir: string) {
  const config = loadConfig(ctx.cwd, extensionDir);
  const now = Date.now();
  state.toolCalls.push({ tool: event.toolName, timestamp: now });
  const rate = getCurrentRate(config);
  appendToAuditLog(ctx.cwd, config, `CALL ${event.toolName} (rate: ${rate}/min)`);

  if (rate > config.rateLimitHardBlock) {
    const msg = `⛔ Rate limit exceeded (${rate}/${config.rateLimitHardBlock}/min).`;
    ctx.ui.notify(msg, "error");
    appendToAuditLog(ctx.cwd, config, `BLOCK rate-limit: ${rate}/min`);
    state.blockedCount++;
    return { block: true, reason: msg };
  }
  if (rate > config.rateLimitPerMinute) {
    ctx.ui.notify(`⚠️ High rate (${rate}/${config.rateLimitPerMinute}/min).`, "warning");
  }

  if (event.toolName === "bash" && typeof event.input.command === "string") {
    const cmd = event.input.command;
    const blocked = matchBlockedCommand(cmd, config);
    if (blocked) {
      const msg = `⛔ Dangerous command blocked (pattern: "${blocked}")`;
      ctx.ui.notify(msg, "error");
      appendToAuditLog(ctx.cwd, config, `BLOCK dangerous-cmd: ${cmd.substring(0, 100)}`);
      state.blockedCount++;
      return { block: true, reason: msg };
    }
    const written = detectFileWrite(cmd);
    if (written && isProtectedFile(written, config)) {
      const msg = `⛔ Write to protected file blocked: ${written}`;
      ctx.ui.notify(msg, "error");
      appendToAuditLog(ctx.cwd, config, `BLOCK protected-file: ${written}`);
      state.blockedCount++;
      return { block: true, reason: msg };
    }
  }

  if ((event.toolName === "write" || event.toolName === "edit") && event.input.path) {
    if (isProtectedFile(event.input.path as string, config)) {
      const msg = `⛔ Write to protected file blocked: ${event.input.path}`;
      ctx.ui.notify(msg, "error");
      appendToAuditLog(ctx.cwd, config, `BLOCK protected-file: ${event.input.path}`);
      state.blockedCount++;
      return { block: true, reason: msg };
    }
  }
}

export function trackToolError(event: any, ctx: ExtensionContext, extensionDir: string) {
  const config = loadConfig(ctx.cwd, extensionDir);
  state.errorCount++;
  state.consecutiveErrors++;
  appendToAuditLog(ctx.cwd, config, `ERROR ${event.toolName}: ${String(event.error).substring(0, 200)} (consecutive: ${state.consecutiveErrors})`);
  if (state.consecutiveErrors >= config.maxConsecutiveErrors) {
    const msg = `🚨 ${state.consecutiveErrors} consecutive errors — escalation triggered.`;
    ctx.ui.notify(msg, "error");
    appendToAuditLog(ctx.cwd, config, `ESCALATE consecutive-errors: ${state.consecutiveErrors}`);
    state.lastEscalation = Date.now();
  }
}

export function trackToolSuccess() {
  state.consecutiveErrors = 0;
}
