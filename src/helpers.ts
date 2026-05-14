import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
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

// ── Workspace boundary ──

/**
 * Resolve a target path and check if it falls within the workspace (cwd)
 * or an explicitly allowed path. Returns true if the path is outside bounds.
 */
export function isOutsideWorkspace(
  targetPath: string,
  cwd: string,
  allowedPaths: string[],
): boolean {
  // Expand ~ to home directory
  const expanded = targetPath.startsWith("~")
    ? path.join(os.homedir(), targetPath.slice(1))
    : targetPath;

  // Resolve relative paths against cwd, keep absolute paths as-is
  const resolved = path.resolve(cwd, expanded);

  // Check against cwd
  const normCwd = path.resolve(cwd);
  if (resolved === normCwd || resolved.startsWith(normCwd + path.sep)) {
    return false;
  }

  // Check against allowed paths
  for (const allowed of allowedPaths) {
    const normAllowed = path.resolve(allowed);
    if (resolved === normAllowed || resolved.startsWith(normAllowed + path.sep)) {
      return false;
    }
  }

  return true;
}

/**
 * Extract all target file paths from a bash command that would be written to.
 * Handles: redirects (> , >>), tee, cp/mv destination, dd of=, mkdir, touch.
 */
export function detectBashWriteTargets(cmd: string): string[] {
  const targets: string[] = [];

  // Redirects: > file, >> file, 1> file, 2> file, &> file
  const redirectRe = /\d?>>?&?\s*(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = redirectRe.exec(cmd)) !== null) {
    const t = m[1].replace(/["']/g, "");
    if (t && t !== "/dev/null" && t !== "/dev/stderr" && t !== "/dev/stdout") {
      targets.push(t);
    }
  }

  // tee <path> [path...]
  const teeRe = /\btee\s+(?![<>-])(\S[\S\s]*?)(?=\s*($|\||;|&&|\|\|))/;
  const teeMatch = cmd.match(teeRe);
  if (teeMatch) {
    const teeArgs = teeMatch[1].split(/\s+/).filter(Boolean);
    for (const arg of teeArgs) {
      if (!arg.startsWith("-")) targets.push(arg.replace(/["']/g, ""));
    }
  }

  // cp <src> <dst>
  const cpRe = /\bcp\s+(?:-[a-zA-Z]+\s+)*(\S+)\s+(\S+)/;
  const cpMatch = cmd.match(cpRe);
  if (cpMatch) targets.push(cpMatch[2].replace(/["']/g, ""));

  // mv <src> <dst>
  const mvRe = /\bmv\s+(?:-[a-zA-Z]+\s+)*(\S+)\s+(\S+)/;
  const mvMatch = cmd.match(mvRe);
  if (mvMatch) targets.push(mvMatch[2].replace(/["']/g, ""));

  // dd of=<path>
  const ddRe = /\bdd\s+.*\bof=(\S+)/;
  const ddMatch = cmd.match(ddRe);
  if (ddMatch) targets.push(ddMatch[1].replace(/["']/g, ""));

  // mkdir [-p] <path>
  const mkdirRe = /\bmkdir\s+(?:-[a-zA-Z]+\s+)*(\S+)/g;
  while ((m = mkdirRe.exec(cmd)) !== null) {
    const t = m[1].replace(/["']/g, "");
    if (!t.startsWith("-")) targets.push(t);
  }

  // touch <path>
  const touchRe = /\btouch\s+(\S+)/;
  const touchMatch = cmd.match(touchRe);
  if (touchMatch) targets.push(touchMatch[1].replace(/["']/g, ""));

  // ln [-s] <src> <dst> — block writing dst outside workspace
  const lnRe = /\bln\s+(?:-[a-zA-Z]+\s+)*(\S+)\s+(\S+)/;
  const lnMatch = cmd.match(lnRe);
  if (lnMatch) targets.push(lnMatch[2].replace(/["']/g, ""));

  return targets;
}
