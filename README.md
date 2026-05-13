# Agent Supervisor for Pi

[![npm version](https://img.shields.io/npm/v/pi-agent-supervisor)](https://www.npmjs.com/package/pi-agent-supervisor)
[![license](https://img.shields.io/npm/l/pi-agent-supervisor)](./LICENSE)

> Runtime safety net for AI agents — blocks dangerous commands, protects sensitive files, enforces rate limits, and records sessions to an append-only audit log.

## Philosophy

The other three gates handle *what* agents do (contrib, review, project). The supervisor handles *how* agents do it — in real-time, while they work.

## Install

```bash
pi install npm:pi-agent-supervisor
```

## Tools

| Tool | What it does |
|---|---|
| `supervisor_status()` | Show session stats — rate, errors, blocked calls |
| `supervisor_log(tail)` | Read audit log (read-only, last N lines) |
| `supervisor_override(reason)` | Request human override for blocked operation |

## Runtime Protections

These run **passively on every tool call** — no agent action needed:

| Protection | Default | Behavior |
|---|---|---|
| Dangerous commands | 12 patterns | Blocks `rm -rf /`, `git push --force`, `sudo`, fork bombs, etc. |
| File protection | 6 files + 5 patterns | Blocks writes to `.env`, credentials, SSH keys, secrets |
| Rate limiting | 50/min warn, 80/min block | Pauses agent if tool call rate exceeds threshold |
| Error escalation | 3 consecutive | Alerts human after 3+ consecutive errors |
| Audit logging | Enabled | Append-only log of all tool calls, errors, blocks |

## Configuration

Create `.supervisorrc.yml`:

```yaml
# Blocked command patterns (comma-separated regex)
blockedPatterns: "rm\\s+-rf\\s+/,rm\\s+-rf\\s+~,git\\s+push\\s+.*--force,sudo,chmod\\s+777"

# Protected files (write blocked)
protectedFiles: ".env,.env.local,credentials.json,.claude/settings.local.json,.git/config"

# Protected file patterns (glob)
protectedPatterns: "*.pem,*.key,id_rsa*,*secret*,*credential*"

# Rate limiting
rateLimitPerMinute: 50     # Warn threshold
rateLimitHardBlock: 80     # Block threshold

# Error escalation
maxConsecutiveErrors: 3    # Escalate after this many consecutive errors

# Audit log
enableAuditLog: true
auditLogPath: ".supervisor/audit.log"
```

## Audit Log

Every action is recorded to an append-only log:

```
[2026-05-14T04:00:00.000Z] SESSION_START host=macbook cwd=/project
[2026-05-14T04:00:01.000Z] CALL bash (rate: 1/min)
[2026-05-14T04:00:02.000Z] CALL edit (rate: 2/min)
[2026-05-14T04:00:03.000Z] BLOCK dangerous-cmd: rm -rf /tmp/*
[2026-05-14T04:00:04.000Z] ERROR bash: command not found (consecutive: 1)
[2026-05-14T04:00:05.000Z] SESSION_END calls=15 errors=1 blocked=1
```

The log is **append-only** — agents cannot modify or delete it.

## Examples

### Blocked: Dangerous Command

```
→ bash("sudo rm -rf /")
⛔ Dangerous command blocked (pattern: "sudo")
→ supervisor_override(reason="Need to clean deployment directory")
Human confirmation required...
```

### Blocked: Protected File

```
→ write(".env", "SECRET=xyz")
⛔ Write to protected file blocked: .env
```

### Rate Limited

```
⚠️ High tool call rate (55/50 calls/min). Slow down.
⛔ Rate limit exceeded (85/80 calls/min). Paused.
```

## Integration

Install all four gates for full agent governance:

```bash
pi install npm:pi-contrib-gate
pi install npm:pi-review-gate
pi install npm:pi-project-gate
pi install npm:pi-agent-supervisor
```

## License

MIT © [nandal](https://github.com/nandal)
