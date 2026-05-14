import * as fs from "node:fs";
import * as path from "node:path";
import type { SupervisorConfig } from "./config";
import { state } from "./state";

export function getAuditLogPath(baseDir: string, config: SupervisorConfig): string {
  return path.join(baseDir, config.auditLogPath);
}

export function appendToAuditLog(baseDir: string, config: SupervisorConfig, entry: string): void {
  if (!config.enableAuditLog) return;
  const logPath = getAuditLogPath(baseDir, config);
  const dir = path.dirname(logPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.appendFileSync(logPath, `[${new Date().toISOString()}] ${entry}\n`, { encoding: "utf-8" });
}

export function getCurrentRate(config: SupervisorConfig): number {
  const now = Date.now();
  state.toolCalls = state.toolCalls.filter(c => c.timestamp > now - 60000);
  return state.toolCalls.length;
}

export function matchBlockedCommand(cmd: string, config: SupervisorConfig): string | null {
  for (const pattern of config.blockedPatterns) {
    try { if (new RegExp(pattern, "i").test(cmd)) return pattern; } catch { /* skip */ }
  }
  return null;
}

export function isProtectedFile(filePath: string, config: SupervisorConfig): boolean {
  const basename = path.basename(filePath);
  if (config.protectedFiles.some(f => basename === f || filePath.endsWith(f))) return true;
  for (const pattern of config.protectedPatterns) {
    const regexStr = pattern.replace(/\./g, "\\.").replace(/\*/g, ".*");
    try { if (new RegExp(`^${regexStr}$`, "i").test(basename)) return true; } catch { /* skip */ }
  }
  return false;
}

export function detectFileWrite(cmd: string): string | null {
  const m = cmd.match(/>>?\s*(\S+)/);
  return m ? m[1] : null;
}
