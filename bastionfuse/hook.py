"""Claude Code hook adapter.

Claude Code runs `bastionfuse hook pre` before every tool call (PreToolUse) and
`bastionfuse hook post` after a successful one (PostToolUse), passing one JSON
object on stdin (session_id, cwd, tool_name, tool_input; post adds the tool's
response).

Blocking uses exit code 2 with the reason on stderr: Claude Code blocks the call
and shows the reason to the model. Exit 2 doesn't depend on parsing any stdout
JSON, so it is the sturdiest way to block. A crash or a non-2 exit code would let
the tool run, so pre() catches everything and blocks (fail closed).

Every trip, block and shadow note is appended to <state_dir>/log.jsonl, which is
the tally for dogfooding (`bastionfuse log`).
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, TextIO

from .fuse import Decision, Fuse
from .policy import FusePolicy, default_state_dir, load_policy, policy_from_dict

BLOCK = 2
LOG_MAX_BYTES = 5 * 1024 * 1024
_SKIP_POST_KEYS = ("tool_input", "transcript_path", "cwd", "session_id", "hook_event_name",
                   "permission_mode", "tool_use_id", "tool_name")


def resolve_policy(path: str | None) -> FusePolicy:
    """Explicit path (flag or $BASTIONFUSE_POLICY) must load; otherwise use
    <state_dir>/fuse.yaml or fuse.json if present, else the built-in defaults
    (KILL file, self-protect, decoy MCP canaries and planted decoys still work)."""
    explicit = path or os.environ.get("BASTIONFUSE_POLICY")
    if explicit:
        return load_policy(explicit)
    home = default_state_dir()
    for name in ("fuse.yaml", "fuse.yml", "fuse.json"):
        if (home / name).exists():
            return load_policy(home / name)
    return policy_from_dict({"policy_version": 2, "fuse": {}})


def pre(stdin: TextIO, stderr: TextIO, policy_path: str | None = None) -> int:
    try:
        payload = _read(stdin)
        policy = resolve_policy(policy_path)
        fuse = Fuse(policy)
        tool = str(payload.get("tool_name") or "")
        session = str(payload.get("session_id") or "default")
        decision = fuse.check(tool, payload.get("tool_input"), session=session, cwd=payload.get("cwd"))
        _log(policy, session, tool, decision)
    except Exception as e:  # noqa: BLE001 - fail closed: a crashed hook would let the tool run
        stderr.write(f"bastionfuse: internal error ({type(e).__name__}: {e}); tool call blocked to stay safe. "
                     "Check the fuse policy.\n")
        return BLOCK
    if decision.allowed:
        return 0
    stderr.write(decision.reason + "\n")
    return BLOCK


def post(stdin: TextIO, stderr: TextIO, policy_path: str | None = None) -> int:
    """Scan the tool's response for honeytokens (taints the session). PostToolUse
    can't undo a call, so errors here are reported but never block."""
    try:
        payload = _read(stdin)
        policy = resolve_policy(policy_path)
        response = {k: v for k, v in payload.items() if k not in _SKIP_POST_KEYS}
        session = str(payload.get("session_id") or "default")
        tool = str(payload.get("tool_name") or "")
        source = Fuse(policy).record(tool, response, session=session)
        if source:
            _log(policy, session, tool, None, taint=source)
    except Exception as e:  # noqa: BLE001
        stderr.write(f"bastionfuse: post-hook error ({type(e).__name__}: {e})\n")
    return 0


def _read(stdin: TextIO) -> dict:
    payload = json.loads(stdin.read() or "{}")
    if not isinstance(payload, dict):
        raise ValueError("hook input must be a JSON object")
    return payload


def _log(policy: FusePolicy, session: str, tool: str, decision: Decision | None, *, taint: str = "") -> None:
    """Append a JSONL record for anything worth tallying. Best effort, bounded."""
    if decision is not None and decision.allowed and not decision.shadow and not decision.tripped:
        return
    record: dict[str, Any] = {"ts": round(time.time(), 3), "session": session[:64], "tool": tool[:128]}
    if decision is not None:
        record.update(allowed=decision.allowed, rule=decision.rule, tripped=decision.tripped,
                      reason=decision.reason[:500], shadow=list(decision.shadow))
    if taint:
        record["taint"] = taint[:300]
    path = policy.state_dir / "log.jsonl"
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > LOG_MAX_BYTES:
            os.replace(path, path.with_suffix(".jsonl.1"))
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass


def settings_snippet(command: str = "bastionfuse") -> dict:
    """The Claude Code settings block that registers the fuse for every tool."""
    def hook(event: str) -> list:
        return [{"matcher": "", "hooks": [{"type": "command", "command": f"{command} hook {event}", "timeout": 15}]}]
    return {"hooks": {"PreToolUse": hook("pre"), "PostToolUse": hook("post")}}


def main_hook(event: str, policy_path: str | None = None) -> int:
    if event == "pre":
        return pre(sys.stdin, sys.stderr, policy_path)
    return post(sys.stdin, sys.stderr, policy_path)

