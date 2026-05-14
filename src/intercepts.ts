import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { loadConfig } from "./config";
import {
  getCurrentRate, matchBlockedCommand, isProtectedFile,
  detectFileWrite, detectBashWriteTargets, isOutsideWorkspace,
  appendToAuditLog,
} from "./helpers";
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

    // ── Workspace boundary: block bash writes outside cwd ──
    if (config.restrictToWorkspace) {
      const writeTargets = detectBashWriteTargets(cmd);
      for (const target of writeTargets) {
        if (isOutsideWorkspace(target, ctx.cwd, config.allowedPaths)) {
          const msg = `⛔ Bash write outside workspace blocked: ${target}`;
          ctx.ui.notify(msg, "error");
          appendToAuditLog(ctx.cwd, config, `BLOCK workspace-boundary: ${target} (cmd: ${cmd.substring(0, 80)})`);
          state.blockedCount++;
          return { block: true, reason: `${msg}\n  Command: ${cmd.substring(0, 120)}\n  Workspace: ${ctx.cwd}\n  To allow: add path to allowedPaths in .supervisorrc.yml` };
        }
      }
    }
  }

  if ((event.toolName === "write" || event.toolName === "edit") && event.input.path) {
    const filePath = event.input.path as string;

    if (isProtectedFile(filePath, config)) {
      const msg = `⛔ Write to protected file blocked: ${filePath}`;
      ctx.ui.notify(msg, "error");
      appendToAuditLog(ctx.cwd, config, `BLOCK protected-file: ${filePath}`);
      state.blockedCount++;
      return { block: true, reason: msg };
    }

    // ── Workspace boundary: block writes outside cwd ──
    if (config.restrictToWorkspace && isOutsideWorkspace(filePath, ctx.cwd, config.allowedPaths)) {
      const msg = `⛔ Write outside workspace blocked: ${filePath}`;
      ctx.ui.notify(msg, "error");
      appendToAuditLog(ctx.cwd, config, `BLOCK workspace-boundary: ${filePath}`);
      state.blockedCount++;
      return { block: true, reason: `${msg}\n  Workspace: ${ctx.cwd}\n  To write outside the workspace, add the path to allowedPaths in .supervisorrc.yml or use supervisor_override().` };
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
