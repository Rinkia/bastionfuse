"""Claude Code hook adapter.

Claude Code runs `bastionfuse hook pre` before every tool call (PreToolUse) and
`bastionfuse hook post` after it (PostToolUse, and PostToolUseFailure for a call
that failed), passing one JSON
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

import hashlib
import io
import json
import os
import sys
import time
from typing import Any, TextIO

from .fuse import RECORD_RETRY_S, Decision, Fuse, spool_taint
from .policy import FusePolicy, default_state_dir, load_policy, policy_from_dict
from .rules import Oversize, TokenMatcher, flatten
from .state import StoreBusy

BLOCK = 2
LOG_MAX_BYTES = 5 * 1024 * 1024
_SKIP_POST_KEYS = ("tool_input", "transcript_path", "cwd", "session_id", "hook_event_name",
                   "permission_mode", "tool_use_id", "tool_name")


def resolve_policy(path: str | None, *, use_env: bool = True) -> FusePolicy:
    """Explicit path (flag, or $BASTIONFUSE_POLICY unless `use_env` is off) must
    load; otherwise use <state_dir>/fuse.yaml or fuse.json if present, else the
    built-in defaults (KILL file, self-protect, decoy MCP canaries and planted
    decoys still work). The hook turns `use_env` off when `--home` is given, so an
    env var from the agent's project can't swap the policy."""
    explicit = path or (os.environ.get("BASTIONFUSE_POLICY") if use_env else None)
    if explicit:
        return load_policy(explicit)
    home = default_state_dir()
    for name in ("fuse.yaml", "fuse.yml", "fuse.json"):
        if (home / name).exists():
            return load_policy(home / name)
    return policy_from_dict({"policy_version": 2, "fuse": {}})


def pre(stdin: TextIO, stderr: TextIO, policy_path: str | None = None, *, use_env: bool = True) -> int:
    try:
        payload = _read(stdin)
        policy = resolve_policy(policy_path, use_env=use_env)
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


def post(stdin: TextIO, stderr: TextIO, policy_path: str | None = None, *, use_env: bool = True) -> int:
    """Scan the tool's response for honeytokens (taints the session). PostToolUse
    can't undo a call, so errors here are reported but never block. A store too
    busy to even open still never drops a taint: it goes to the spool."""
    try:
        payload = _read(stdin)
        policy = resolve_policy(policy_path, use_env=use_env)
        response = {k: v for k, v in payload.items() if k not in _SKIP_POST_KEYS}
        session = str(payload.get("session_id") or "default")
        tool = str(payload.get("tool_name") or "")
        try:
            fuse = _open_fuse(policy)
        except StoreBusy:
            source = _scan_only(policy, tool, response)
            if source:
                spool_taint(policy, session, source)
                _log(policy, session, tool, None, taint=source)
            return 0
        source = fuse.record(tool, response, session=session)
        if source:
            _log(policy, session, tool, None, taint=source)
    except Exception as e:  # noqa: BLE001
        stderr.write(f"bastionfuse: post-hook error ({type(e).__name__}: {e})\n")
    return 0


def _open_fuse(policy: FusePolicy) -> Fuse:
    """Opening the store runs a schema transaction; retry it like record() does."""
    deadline = time.monotonic() + RECORD_RETRY_S
    while True:
        try:
            return Fuse(policy)
        except StoreBusy:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


def _scan_only(policy: FusePolicy, tool: str, response: Any) -> str | None:
    """record()'s scan without the store."""
    try:
        hit = TokenMatcher(policy.honeytokens).find(flatten(response))
    except Oversize:
        return f"{tool} result too large to scan"
    return f"honeytoken #{hashlib.sha256(hit.encode()).hexdigest()[:8]} in a {tool} result" if hit else None


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


def settings_snippet(command: str = "bastionfuse", home: str | None = None) -> dict:
    """The Claude Code settings block that registers the fuse for every tool. With
    `home`, the state dir is baked into the command (`--home`), so an environment
    variable the agent's project sets can't point the hook at an empty state dir."""
    base = f'{command} --home "{home}"' if home else command

    def hook(event: str) -> list:
        return [{"matcher": "", "hooks": [{"type": "command", "command": f"{base} hook {event}", "timeout": 15}]}]
    # PostToolUseFailure: a failed call's output (`cat decoy; false`) reaches the model too
    return {"hooks": {"PreToolUse": hook("pre"), "PostToolUse": hook("post"), "PostToolUseFailure": hook("post")}}


def main_hook(event: str, policy_path: str | None = None, *, home_pinned: bool = False) -> int:
    """Read hook JSON as UTF-8 bytes: the Windows console codepage would mangle it
    (and with it every Unicode-folding defense)."""
    raw = sys.stdin.buffer.read().decode("utf-8", "replace")
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    except (AttributeError, ValueError):
        pass
    stdin = io.StringIO(raw)
    if event == "pre":
        return pre(stdin, sys.stderr, policy_path, use_env=not home_pinned)
    return post(stdin, sys.stderr, policy_path, use_env=not home_pinned)
