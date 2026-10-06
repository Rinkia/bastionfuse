# Changelog

## 0.1.0 (unreleased)

First release. The CONTAIN leg of the bastion suite: a sticky kill switch driven by what the
agent does, not by what its text says.

- **Tripwires:** honeytokens (raw, hex, URL-encoded, base64 at every alignment; NFKC, case and
  zero-width folded), decoy paths (`bastionfuse plant`), canary tools, and a decoy MCP server
  (`bastionfuse decoy-mcp`).
- **Taint then trip:** a honeytoken in a tool *result*, or a decoy path in a call, taints the
  session. Any later egress trips.
- **Budgets** in sliding windows: calls, egress / fetch / destructive, per tool, distinct egress
  hosts, bytes out. Operator-written budgets enforce; the built-in defaults and the repeat
  detector only log (`shadow`).
- **Shell command classification** for Claude Code's `Bash` / `PowerShell` tools.
- **Sticky, per-session trips** in sqlite, shared across hook processes. Operator signals (KILL
  file, `trip --global`) stop every session and survive deletion of the KILL file.
- **Modes:** `kill`, `degrade` (read-only tools keep working), `pause`.
- **Claude Code hook** (`bastionfuse hook pre|post`), fail closed: any error blocks the call.
- **Self-protect:** blocks calls that touch the fuse state, its policy, Claude Code settings or
  `bastionfuse reset`.
- **Trip snapshots** as bastiontrace v1 traces (honeytokens redacted), plus a JSONL log with a
  `bastionfuse log --summary` tally.
- **Hook watchdog:** a check that runs past 10 s denies (exit 2) before Claude Code's hook
  timeout, which would otherwise let the tool run. Remote paths are never resolved or globbed;
  globbing is lazy and bounded by hits and time.
  Self-protect regexes are bounded (they hold the GIL, so a quadratic match would also stall
  the watchdog), and the hook keeps exit code 2 even when stderr is closed.
- **Self-protect** also blocks writes to Python startup files (`sitecustomize.py`,
  `usercustomize.py`, `.pth` in site-packages) and any change to the installed package;
  read-only tools may still read the package source. `operator_paths` was removed (it let an
  editable install's package be edited).
- **Assume-breach demo** (`bastionfuse demo`): a scripted attacker vs the fuse, no API key.
