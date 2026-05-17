import * as fs from "node:fs";
import * as path from "node:path";

export interface SupervisorConfig {
  blockedPatterns: string[];
  protectedFiles: string[];
  protectedPatterns: string[];
  restrictToWorkspace: boolean;
  allowedPaths: string[];
  rateLimitPerMinute: number;
  rateLimitHardBlock: number;
  maxConsecutiveErrors: number;
  enableAuditLog: boolean;
  auditLogPath: string;
  contextWarnThreshold: number;
  contextCriticalThreshold: number;
  blockAtCriticalContext: boolean;
}

export const DEFAULT_CONFIG: SupervisorConfig = {
  blockedPatterns: [],
  protectedFiles: [".env", ".env.local", ".env.production", "credentials.json", "serviceAccountKey.json", ".claude/settings.local.json", ".git/config"],
  protectedPatterns: ["*.pem", "*.key", "id_rsa*", "*secret*", "*credential*"],
  restrictToWorkspace: true,
  allowedPaths: ["/tmp"],
  rateLimitPerMinute: 50, rateLimitHardBlock: 80, maxConsecutiveErrors: 3,
  enableAuditLog: true, auditLogPath: ".supervisor/audit.log",
  contextWarnThreshold: 70, contextCriticalThreshold: 90, blockAtCriticalContext: false,
};

export function loadBlockedPatterns(extensionDir: string): string[] {
  const patternsDir = path.join(extensionDir, "patterns");
  if (!fs.existsSync(patternsDir)) return [];
  const patterns: string[] = [];
  try {
    for (const file of fs.readdirSync(patternsDir).filter(f => f.endsWith(".txt"))) {
      const content = fs.readFileSync(path.join(patternsDir, file), "utf-8");
      for (const line of content.split("\n")) {
        const t = line.trim();
        if (t && !t.startsWith("#")) patterns.push(t);
      }
    }
  } catch { /* ignore */ }
  return patterns;
}

export function loadConfig(cwd: string, extensionDir?: string): SupervisorConfig {
  const configPath = path.join(cwd, ".supervisorrc.yml");
  const config = { ...DEFAULT_CONFIG };
  if (extensionDir) config.blockedPatterns = loadBlockedPatterns(extensionDir);
  if (!fs.existsSync(configPath)) return config;
  try {
    const content = fs.readFileSync(configPath, "utf-8");
    const result: Record<string, unknown> = {};
    for (const line of content.split("\n")) {
      const m = line.match(/^\s*([\w][\w.]*):\s*(.+)$/);
      if (m) { let v = m[2].trim(); if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1); result[m[1]] = v; }
    }
    const rateLimitPerMinute = parseInt(result["rateLimitPerMinute"] as string);
    const rateLimitHardBlock = parseInt(result["rateLimitHardBlock"] as string);
    const maxConsecutiveErrors = parseInt(result["maxConsecutiveErrors"] as string);
    const contextWarnThreshold = parseInt(result["contextWarnThreshold"] as string);
    const contextCriticalThreshold = parseInt(result["contextCriticalThreshold"] as string);
    return {
      blockedPatterns: result["blockedPatterns"] ? (result["blockedPatterns"] as string).split(",").map(s => s.trim()).filter(Boolean) : config.blockedPatterns,
      protectedFiles: result["protectedFiles"] ? (result["protectedFiles"] as string).split(",").map(s => s.trim()).filter(Boolean) : DEFAULT_CONFIG.protectedFiles,
      protectedPatterns: result["protectedPatterns"] ? (result["protectedPatterns"] as string).split(",").map(s => s.trim()).filter(Boolean) : DEFAULT_CONFIG.protectedPatterns,
      restrictToWorkspace: result["restrictToWorkspace"] !== "false",
      allowedPaths: result["allowedPaths"] ? (result["allowedPaths"] as string).split(",").map(s => s.trim()).filter(Boolean) : DEFAULT_CONFIG.allowedPaths,
      rateLimitPerMinute: isNaN(rateLimitPerMinute) ? DEFAULT_CONFIG.rateLimitPerMinute : rateLimitPerMinute,
      rateLimitHardBlock: isNaN(rateLimitHardBlock) ? DEFAULT_CONFIG.rateLimitHardBlock : rateLimitHardBlock,
      maxConsecutiveErrors: isNaN(maxConsecutiveErrors) ? DEFAULT_CONFIG.maxConsecutiveErrors : maxConsecutiveErrors,
      enableAuditLog: result["enableAuditLog"] !== "false",
      auditLogPath: (result["auditLogPath"] as string) || DEFAULT_CONFIG.auditLogPath,
      contextWarnThreshold: isNaN(contextWarnThreshold) ? DEFAULT_CONFIG.contextWarnThreshold : contextWarnThreshold,
      contextCriticalThreshold: isNaN(contextCriticalThreshold) ? DEFAULT_CONFIG.contextCriticalThreshold : contextCriticalThreshold,
      blockAtCriticalContext: result["blockAtCriticalContext"] === "true",
    };
  } catch { return config; }
}
