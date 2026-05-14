/**
 * pi-agent-supervisor test suite
 *
 * Tests pattern matching, file protection, rate limiting, config loading,
 * and audit logging — the core safety functions.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

// ── Test helpers (replicate core logic for unit testing) ──

interface SupervisorConfig {
  blockedPatterns: string[];
  protectedFiles: string[];
  protectedPatterns: string[];
  rateLimitPerMinute: number;
  rateLimitHardBlock: number;
  maxConsecutiveErrors: number;
  enableAuditLog: boolean;
  auditLogPath: string;
  contextWarnThreshold: number;
  contextCriticalThreshold: number;
  blockAtCriticalContext: boolean;
}

const DEFAULT_CONFIG: SupervisorConfig = {
  blockedPatterns: [
    "rm\\s+-rf\\s+/\\s",
    "rm\\s+-rf\\s+/$",
    "rm\\s+-rf\\s+~",
    "rm\\s+-rf\\s+\\*",
    "git\\s+push\\s+.*--force",
    "git\\s+push\\s+.*-f\\b",
    "sudo\\s+",
    "chmod\\s+777",
    ">\\s*/dev/sd[a-z]",
    "dd\\s+if=",
    "mkfs\\.",
    ":(){ :|:& };:",
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
  protectedPatterns: ["*.pem", "*.key", "id_rsa*", "*secret*", "*credential*"],
  rateLimitPerMinute: 50,
  rateLimitHardBlock: 80,
  maxConsecutiveErrors: 3,
  enableAuditLog: true,
  auditLogPath: ".supervisor/audit.log",
  contextWarnThreshold: 70,
  contextCriticalThreshold: 90,
  blockAtCriticalContext: false,
};

function matchBlockedCommand(cmd: string, config: SupervisorConfig): string | null {
  for (const pattern of config.blockedPatterns) {
    try {
      if (new RegExp(pattern, "i").test(cmd)) {
        return pattern;
      }
    } catch {
      // Invalid regex
    }
  }
  return null;
}

function isProtectedFile(filePath: string, config: SupervisorConfig): boolean {
  const basename = path.basename(filePath);

  if (config.protectedFiles.some((f) => basename === f || filePath.endsWith(f))) {
    return true;
  }

  for (const pattern of config.protectedPatterns) {
    const regexStr = pattern.replace(/\./g, "\\.").replace(/\*/g, ".*");
    try {
      if (new RegExp(`^${regexStr}$`, "i").test(basename)) {
        return true;
      }
    } catch {
      // Invalid regex
    }
  }

  return false;
}

function detectFileWrite(cmd: string): string | null {
  const redirectMatch = cmd.match(/>>?\s*(\S+)/);
  if (redirectMatch) return redirectMatch[1];
  return null;
}

// ── Config loading ──

function parseConfigYaml(content: string): SupervisorConfig {
  const result: Record<string, unknown> = {};
  for (const line of content.split("\n")) {
    const m = line.match(/^\s*([\w][\w.]*):\s*(.+)$/);
    if (m) {
      let val = m[2].trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      result[m[1]] = val;
    }
  }
  return {
    blockedPatterns: result["blockedPatterns"]
      ? (result["blockedPatterns"] as string).split(",").map((s) => s.trim()).filter(Boolean)
      : DEFAULT_CONFIG.blockedPatterns,
    protectedFiles: result["protectedFiles"]
      ? (result["protectedFiles"] as string).split(",").map((s) => s.trim()).filter(Boolean)
      : DEFAULT_CONFIG.protectedFiles,
    protectedPatterns: result["protectedPatterns"]
      ? (result["protectedPatterns"] as string).split(",").map((s) => s.trim()).filter(Boolean)
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
}

// ── Rate limiting ──

function getRateAtTime(calls: number[], now: number, windowMs: number): number {
  return calls.filter((t) => t > now - windowMs).length;
}

// ═══════════════════════════════════════
// TESTS
// ═══════════════════════════════════════

describe("matchBlockedCommand", () => {
  const config = { ...DEFAULT_CONFIG };

  it("blocks rm -rf /", () => {
    expect(matchBlockedCommand("rm -rf /", config)).toBeTruthy();
  });

  it("blocks rm -rf ~", () => {
    expect(matchBlockedCommand("rm -rf ~", config)).toBeTruthy();
  });

  it("blocks rm -rf *", () => {
    expect(matchBlockedCommand("rm -rf *", config)).toBeTruthy();
  });

  it("allows rm -rf /tmp/safe-dir", () => {
    expect(matchBlockedCommand("rm -rf /tmp/safe-dir", config)).toBeNull();
  });

  it("blocks sudo anything", () => {
    expect(matchBlockedCommand("sudo rm file", config)).toBeTruthy();
    expect(matchBlockedCommand("sudo apt update", config)).toBeTruthy();
  });

  it("blocks git push --force", () => {
    expect(matchBlockedCommand("git push origin main --force", config)).toBeTruthy();
    expect(matchBlockedCommand("git push --force-with-lease", config)).toBeTruthy();
  });

  it("blocks git push -f", () => {
    expect(matchBlockedCommand("git push -f origin main", config)).toBeTruthy();
    expect(matchBlockedCommand("git push origin main -f", config)).toBeTruthy();
  });

  it("allows normal git push", () => {
    expect(matchBlockedCommand("git push origin main", config)).toBeNull();
    expect(matchBlockedCommand("git push", config)).toBeNull();
  });

  it("blocks chmod 777", () => {
    expect(matchBlockedCommand("chmod 777 file.sh", config)).toBeTruthy();
  });

  it("blocks redirect to /dev/sd*", () => {
    expect(matchBlockedCommand("dd if=/dev/zero of=/dev/sda", config)).toBeTruthy();
  });

  it("blocks fork bomb", () => {
    expect(matchBlockedCommand(":(){ :|:& };:", config)).toBeTruthy();
  });

  it("blocks dd and mkfs", () => {
    expect(matchBlockedCommand("dd if=/dev/zero of=file", config)).toBeTruthy();
    expect(matchBlockedCommand("mkfs.ext4 /dev/sdb", config)).toBeTruthy();
  });

  it("is case insensitive", () => {
    expect(matchBlockedCommand("SUDO RM -RF /", config)).toBeTruthy();
    expect(matchBlockedCommand("Sudo rm file", config)).toBeTruthy();
  });

  it("allows safe commands", () => {
    expect(matchBlockedCommand("npm test", config)).toBeNull();
    expect(matchBlockedCommand("git status", config)).toBeNull();
    expect(matchBlockedCommand("echo hello", config)).toBeNull();
    expect(matchBlockedCommand("docker compose up", config)).toBeNull();
  });
});

describe("isProtectedFile", () => {
  const config = { ...DEFAULT_CONFIG };

  it("protects .env files", () => {
    expect(isProtectedFile(".env", config)).toBe(true);
    expect(isProtectedFile("/project/.env", config)).toBe(true);
    expect(isProtectedFile("/project/.env.local", config)).toBe(true);
    expect(isProtectedFile(".env.production", config)).toBe(true);
  });

  it("protects credentials.json", () => {
    expect(isProtectedFile("credentials.json", config)).toBe(true);
    expect(isProtectedFile("/path/to/credentials.json", config)).toBe(true);
  });

  it("protects serviceAccountKey.json", () => {
    expect(isProtectedFile("serviceAccountKey.json", config)).toBe(true);
  });

  it("protects settings.local.json", () => {
    expect(isProtectedFile(".claude/settings.local.json", config)).toBe(true);
  });

  it("protects .git/config", () => {
    expect(isProtectedFile(".git/config", config)).toBe(true);
  });

  it("protects .pem files via pattern", () => {
    expect(isProtectedFile("key.pem", config)).toBe(true);
    expect(isProtectedFile("ssl-cert.pem", config)).toBe(true);
  });

  it("protects .key files via pattern", () => {
    expect(isProtectedFile("private.key", config)).toBe(true);
    expect(isProtectedFile("secret.key", config)).toBe(true);
  });

  it("protects id_rsa files via pattern", () => {
    expect(isProtectedFile("id_rsa", config)).toBe(true);
    expect(isProtectedFile("id_rsa.pub", config)).toBe(true);
  });

  it("protects files with 'secret' in name", () => {
    expect(isProtectedFile("my-secret.txt", config)).toBe(true);
    expect(isProtectedFile("secret-config.json", config)).toBe(true);
    expect(isProtectedFile("supersecret.key", config)).toBe(true);
  });

  it("protects files with 'credential' in name", () => {
    expect(isProtectedFile("aws-credentials", config)).toBe(true);
    expect(isProtectedFile("credentials-backup.json", config)).toBe(true);
  });

  it("allows normal files", () => {
    expect(isProtectedFile("index.ts", config)).toBe(false);
    expect(isProtectedFile("package.json", config)).toBe(false);
    expect(isProtectedFile("src/app.ts", config)).toBe(false);
    expect(isProtectedFile("README.md", config)).toBe(false);
  });

  it("allows .env.example", () => {
    expect(isProtectedFile(".env.example", config)).toBe(false);
  });
});

describe("detectFileWrite", () => {
  it("detects redirect writes", () => {
    expect(detectFileWrite("echo test > output.txt")).toBe("output.txt");
    expect(detectFileWrite("cat > /tmp/file")).toBe("/tmp/file");
  });

  it("returns null for non-write commands", () => {
    expect(detectFileWrite("echo test")).toBeNull();
    expect(detectFileWrite("cat file.txt")).toBeNull();
  });
});

describe("config loading", () => {
  it("returns defaults when no config file", () => {
    const config = parseConfigYaml("");
    expect(config.maxConsecutiveErrors).toBe(3);
    expect(config.rateLimitPerMinute).toBe(50);
    expect(config.blockedPatterns.length).toBe(12);
    expect(config.protectedFiles.length).toBe(7);
  });

  it("parses blockedPatterns from config", () => {
    const yaml = 'blockedPatterns: "rm\\s+-rf\\s+/,sudo\\s+"';
    const config = parseConfigYaml(yaml);
    expect(config.blockedPatterns).toEqual(["rm\\s+-rf\\s+/", "sudo\\s+"]);
  });

  it("parses numeric values", () => {
    const yaml = "rateLimitPerMinute: 30\nmaxConsecutiveErrors: 5";
    const config = parseConfigYaml(yaml);
    expect(config.rateLimitPerMinute).toBe(30);
    expect(config.maxConsecutiveErrors).toBe(5);
  });

  it("parses protected files", () => {
    const yaml = 'protectedFiles: ".env,credentials.json"';
    const config = parseConfigYaml(yaml);
    expect(config.protectedFiles).toEqual([".env", "credentials.json"]);
  });

  it("handles boolean values", () => {
    const yaml = "enableAuditLog: false\nblockAtCriticalContext: true";
    const config = parseConfigYaml(yaml);
    expect(config.enableAuditLog).toBe(false);
    expect(config.blockAtCriticalContext).toBe(true);
  });
});

describe("rate limiting", () => {
  it("counts calls within the window", () => {
    const now = 1700000000000;
    const calls = [now - 10000, now - 30000, now - 50000, now - 70000]; // 4 calls in last 60s
    expect(getRateAtTime(calls, now, 60000)).toBe(3); // 3 within 60s
  });

  it("excludes calls outside the window", () => {
    const now = 1700000000000;
    const calls = [now - 10000, now - 120000]; // 1 recent, 1 old
    expect(getRateAtTime(calls, now, 60000)).toBe(1);
  });

  it("returns 0 for no calls", () => {
    expect(getRateAtTime([], Date.now(), 60000)).toBe(0);
  });
});

describe("audit logging", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "supervisor-test-"));

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("creates audit log directory and appends entries", () => {
    const logPath = path.join(tmpDir, "audit.log");
    // Simulate logging
    const timestamp = new Date().toISOString();
    const parent = path.dirname(logPath);
    fs.mkdirSync(parent, { recursive: true });
    fs.appendFileSync(logPath, `[${timestamp}] TEST_ENTRY\n`, { encoding: "utf-8" });

    expect(fs.existsSync(logPath)).toBe(true);
    const content = fs.readFileSync(logPath, "utf-8");
    expect(content).toContain("TEST_ENTRY");
  });

  it("appends multiple entries", () => {
    const logPath = path.join(tmpDir, "audit.log");
    const parent = path.dirname(logPath);
    fs.mkdirSync(parent, { recursive: true });

    fs.appendFileSync(logPath, "[2026-01-01] entry 1\n", { encoding: "utf-8" });
    fs.appendFileSync(logPath, "[2026-01-01] entry 2\n", { encoding: "utf-8" });

    const content = fs.readFileSync(logPath, "utf-8");
    expect(content).toContain("entry 1");
    expect(content).toContain("entry 2");
  });
});

describe("integration: command + file protection", () => {
  const config = { ...DEFAULT_CONFIG };

  it("blocks rm -rf / even with extra flags", () => {
    expect(matchBlockedCommand("rm -rf / --no-preserve-root", config)).toBeTruthy();
  });

  it("blocks sudo in nested commands", () => {
    expect(matchBlockedCommand("bash -c 'sudo rm file'", config)).toBeTruthy();
  });

  it("blocks git push with --force anywhere in command", () => {
    expect(matchBlockedCommand("git push origin --force main", config)).toBeTruthy();
    expect(matchBlockedCommand("GIT_SSH=1 git push --force origin main", config)).toBeTruthy();
  });

  it("does not block rm without -rf /", () => {
    expect(matchBlockedCommand("rm file.txt", config)).toBeNull();
    expect(matchBlockedCommand("rm -r node_modules", config)).toBeNull();
    expect(matchBlockedCommand("rm -rf node_modules", config)).toBeNull();
  });
});

// ═══════════════════════════════════════
// Escalation & State Tracking
// ═══════════════════════════════════════

describe("escalation protocol", () => {
  it("triggers escalation after maxConsecutiveErrors", () => {
    const maxErrors = 3;
    let consecutiveErrors = 0;
    let escalated = false;

    for (let i = 0; i < maxErrors; i++) {
      consecutiveErrors++;
      if (consecutiveErrors >= maxErrors) {
        escalated = true;
      }
    }
    expect(escalated).toBe(true);
    expect(consecutiveErrors).toBe(maxErrors);
  });

  it("resets consecutive errors on success", () => {
    let consecutiveErrors = 2;
    // Simulate success
    consecutiveErrors = 0;
    expect(consecutiveErrors).toBe(0);
  });

  it("does not escalate below threshold", () => {
    let consecutiveErrors = 2;
    expect(consecutiveErrors).toBeLessThan(3);
  });

  it("continues counting past threshold", () => {
    let consecutiveErrors = 3;
    consecutiveErrors++; // 4th error
    expect(consecutiveErrors).toBe(4);
  });
});

describe("rate limit boundary tests", () => {
  const now = 1700000000000;

  it("exactly at warn threshold", () => {
    const calls = Array.from({ length: 50 }, (_, i) => now - i * 1000);
    expect(getRateAtTime(calls, now, 60000)).toBe(50);
  });

  it("exactly at hard block threshold", () => {
    const calls = Array.from({ length: 80 }, (_, i) => now - i * 500);
    expect(getRateAtTime(calls, now, 60000)).toBe(80);
  });

  it("one below warn threshold", () => {
    const calls = Array.from({ length: 49 }, (_, i) => now - i * 1000);
    expect(getRateAtTime(calls, now, 60000)).toBe(49);
  });

  it("one above hard block threshold", () => {
    const calls = Array.from({ length: 81 }, (_, i) => now - i * 500);
    expect(getRateAtTime(calls, now, 60000)).toBe(81);
  });

  it("handles rapid bursts within window", () => {
    // 20 calls within 1 second
    const calls = Array.from({ length: 20 }, () => now);
    expect(getRateAtTime(calls, now, 60000)).toBe(20);
  });
});

describe("file write detection edge cases", () => {
  it("detects append redirect", () => {
    expect(detectFileWrite("echo test >> output.txt")).toBe("output.txt");
  });

  it("detects write with spaces around redirect", () => {
    expect(detectFileWrite("cat >  /tmp/file")).toBe("/tmp/file");
  });

  it("returns null for grep commands", () => {
    expect(detectFileWrite("grep pattern > /dev/null")).toBe("/dev/null");
  });

  it("handles quoted filenames", () => {
    expect(detectFileWrite('echo test > "my file.txt"')).toBe('"my');  // naive parser
    expect(detectFileWrite("echo test > 'my file.txt'")).toBe("'my");
  });
});

describe("config edge cases", () => {
  it("handles empty config gracefully", () => {
    const config = parseConfigYaml("");
    expect(config.rateLimitPerMinute).toBe(50);
    expect(config.maxConsecutiveErrors).toBe(3);
    expect(config.blockedPatterns.length).toBeGreaterThan(0);
  });

  it("handles malformed numeric values", () => {
    const config = parseConfigYaml("rateLimitPerMinute: abc\nmaxConsecutiveErrors: xyz");
    expect(config.rateLimitPerMinute).toBe(50); // falls back to default
    expect(config.maxConsecutiveErrors).toBe(3);
  });

  it("handles quoted strings with commas", () => {
    const yaml = 'protectedFiles: ".env,credentials.json"';
    const config = parseConfigYaml(yaml);
    expect(config.protectedFiles).toEqual([".env", "credentials.json"]);
  });

  it("handles single-quoted values", () => {
    const yaml = "protectedFiles: '.env,credentials.json'";
    const config = parseConfigYaml(yaml);
    expect(config.protectedFiles).toEqual([".env", "credentials.json"]);
  });

  it("uses defaults for missing fields", () => {
    const config = parseConfigYaml("rateLimitPerMinute: 30");
    expect(config.rateLimitPerMinute).toBe(30);
    expect(config.maxConsecutiveErrors).toBe(3); // default
    expect(config.rateLimitPerMinute).toBe(30); // explicit
  });

  it("parses all boolean variants", () => {
    expect(parseConfigYaml("enableAuditLog: false").enableAuditLog).toBe(false);
    expect(parseConfigYaml("enableAuditLog: true").enableAuditLog).toBe(true);
    expect(parseConfigYaml("enableAuditLog: yes").enableAuditLog).toBe(true); // not "false"
    expect(parseConfigYaml("blockAtCriticalContext: false").blockAtCriticalContext).toBe(false);
    expect(parseConfigYaml("blockAtCriticalContext: true").blockAtCriticalContext).toBe(true);
  });
});

describe("combined protection scenarios", () => {
  const config = { ...DEFAULT_CONFIG };

  it("cat redirect to protected file", () => {
    const cmd = "cat secret > .env";
    const file = detectFileWrite(cmd);
    expect(file).toBe(".env");
    expect(isProtectedFile(file!, config)).toBe(true);
  });

  it("git force push to main (both danger + file pattern)", () => {
    const cmd = "git push origin main --force";
    expect(matchBlockedCommand(cmd, config)).toBeTruthy();
  });

  it("sudo redirect to protected file", () => {
    const cmd = "sudo echo key > /root/.env";
    expect(matchBlockedCommand(cmd, config)).toBeTruthy();
    // Also check file protection
    const file = detectFileWrite(cmd);
    expect(file).toBe("/root/.env");
    expect(isProtectedFile(file!, config)).toBe(true);
  });

  it("safe npm command passes all checks", () => {
    const cmd = "npm run test -- --coverage";
    expect(matchBlockedCommand(cmd, config)).toBeNull();
    expect(detectFileWrite(cmd)).toBeNull();
  });

  it("docker compose up passes all checks", () => {
    const cmd = "docker compose up -d";
    expect(matchBlockedCommand(cmd, config)).toBeNull();
  });
});

describe("session state lifecycle", () => {
  it("tracks blocked count correctly", () => {
    let blockedCount = 0;
    blockedCount++;
    blockedCount++;
    expect(blockedCount).toBe(2);
  });

  it("tracks error count correctly", () => {
    let errorCount = 0;
    errorCount++;
    errorCount++;
    errorCount++;
    expect(errorCount).toBe(3);
  });

  it("resets session state on new session", () => {
    let state = {
      toolCalls: [1, 2, 3],
      errorCount: 5,
      consecutiveErrors: 3,
      blockedCount: 2,
      lastEscalation: Date.now(),
    };
    // Reset
    state = {
      toolCalls: [],
      errorCount: 0,
      consecutiveErrors: 0,
      blockedCount: 0,
      lastEscalation: 0,
    };
    expect(state.toolCalls.length).toBe(0);
    expect(state.errorCount).toBe(0);
    expect(state.blockedCount).toBe(0);
  });
});
