# Changelog

## 0.1.1 (2026-10-09)

- **`log --summary` no longer counts post-trip refusals as trips** (#6). Once the fuse is
  tripped, every refused call was logged as `tripped: true` and tallied under the rule that
  fired, so one trip plus N refusals read as N+1 trips — inflating the dogfood bar the
  heuristic detectors are promoted against. `Decision` now carries `fresh` ("this call tripped
  the fuse"); `trips_by_rule` counts only those, and the refusals after a trip are tallied
  separately under `refused_after_trip`, which measures how long the agent kept trying after
  containment. Log records written before this change have no `fresh` key and still tally the
  old way.
- **Docs:** three self-protect scan-scope limits now in README Limits, all found by dogfooding
  (#5 and the 2026-10-08 round): a shell command is scanned whole, inline script bodies
  included, so a heredoc that merely *mentions* a protected path is denied; and self-protect
  does not distinguish reading from writing, so a read-only `grep` of your settings file and
  read-only `bastionfuse log` / `status` are denied along with the mutating commands. Also the
  Windows + Claude Desktop install note (install outside `AppData`, or the operator CLI and the
  hook see different files).

## 0.1.0 (2026-10-06)

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
- **Self-protect reads actions, not content:** its text rules look only at commands and
  path fields, so a file whose body mentions the fuse or its settings isn't blocked. The
  package-manager rule needs an install/remove verb; running the console script is allowed.
  The decoy check reads the same way: a file whose body names a decoy path doesn't taint the
  session. (Dogfood: 5 false blocks and 1 false trip, all from file content; fixed.)
- **Assume-breach demo** (`bastionfuse demo`): a scripted attacker vs the fuse, no API key.
