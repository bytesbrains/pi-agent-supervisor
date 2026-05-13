# Agent Supervisor — Agent Usage Guide

> You are an AI agent. The supervisor is ALWAYS watching. It blocks dangerous operations automatically. You cannot disable it.

## What the Supervisor Does

The supervisor runs passively on every tool call you make. It:

1. **Blocks dangerous commands** — `rm -rf /`, `git push --force`, `sudo`, fork bombs
2. **Protects sensitive files** — can't write to `.env`, credentials, SSH keys
3. **Enforces rate limits** — warns at 50 calls/min, blocks at 80
4. **Tracks errors** — escalates to human after 3 consecutive errors
5. **Records everything** — append-only audit log in `.supervisor/audit.log`

## When You Get Blocked

If a command is blocked, you have two options:

1. **Find an alternative** — use a safer approach
2. **Request override** — call `supervisor_override(reason)` to ask the human

```
→ supervisor_override(reason="Need to force push the rebased feature branch")
```

The human will see the request and can approve or deny.

## Checking Status

```
supervisor_status()
```

Shows:
- Current tool call rate
- Error count and consecutive errors
- Number of blocked calls
- Audit log location

## Reading the Audit Log

```
supervisor_log(tail=20)
```

Reads the last 20 lines of the audit log. This is **read-only** — you cannot modify it.

## What NOT to Do

| Don't | Why |
|---|---|
| Don't try `rm -rf /` or `sudo rm` | Blocked — use `rm` without `-rf /` |
| Don't write to `.env` directly | Blocked — use the proper secrets management |
| Don't spam tool calls | Rate limited — batch operations when possible |
| Don't ignore 3+ errors in a row | Escalation triggered — fix the root cause |
| Don't try to delete `.supervisor/` | Protected directory |
