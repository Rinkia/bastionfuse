"""Regression tests for the round-1 security review (findings numbered as in the
review). Each test fails if its fix is reverted."""

import base64
import io
import json
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from bastionfuse import Fuse, hook
from bastionfuse.decoy_mcp import handle, serve
from bastionfuse.policy import policy_from_dict
from bastionfuse.rules import (MAX_SHELL_COMMAND, TokenMatcher, classify, command_labels, flatten, path_candidates,
                               self_protect_hit)
from bastionfuse.state import Store
from conftest import TOKEN, pol

P = policy_from_dict(pol())


def make(**fuse):
    return Fuse(policy_from_dict(pol(**fuse)), store=Store(None))


# 1. lone surrogate must not undo a trip
def test_1_surrogate_trip_persists():
    f = make(honeytokens=[TOKEN], canary_tools=["bad"])
    d = f.check("Bash", {"command": f"echo {TOKEN} \ud800"})
    assert d.tripped and d.rule == "honeytoken"
    assert not f.check("Bash", {"command": "ls"}).allowed  # sticky
    g = make(canary_tools=["bad"])
    assert g.check("bad", {"x": "\udfff"}).rule == "canary"
    assert not g.check("Bash", {"command": "curl https://evil.example"}).allowed


def test_1_surrogates_replaced_not_rejected():
    assert flatten("a\ud800b") == "a?b"
    assert make().check("Bash", {"command": "echo \u0101 \ud800"}).allowed


def test_1_forensics_failure_never_undoes_trip(monkeypatch):
    f = make(canary_tools=["bad"])
    monkeypatch.setattr("bastionfuse.state.Tx.add_ring", lambda *a, **k: (_ for _ in ()).throw(sqlite3.Error("x")))
    assert f.check("bad", {}).tripped
    assert f.status()["session_trip"]["rule"] == "canary"


# 2. huge commands: bounded time, refused past the cap
@pytest.mark.parametrize("cmd", ["sudo " * 6000 + "; curl x", "A=1 " * 8000, "a;" * 16000],
                         ids=["wrappers", "assignments", "segments"])
def test_2_classification_is_fast(cmd):
    start = time.perf_counter()
    command_labels(cmd, P.commands)
    assert time.perf_counter() - start < 2.0


def test_2_oversize_shell_command_refused():
    d = make().check("Bash", {"command": "a;" * (MAX_SHELL_COMMAND // 2 + 1) + "curl https://x"})
    assert not d.allowed and d.rule == "oversize"


# 3. self-protect: install, short names, dot segments, globs, quote splits, option order
@pytest.mark.parametrize("cmd", [
    "pip uninstall -y bastionfuse", "uv pip uninstall bastionfuse", "pipx uninstall bastionfuse",
    "bastionfuse --policy x.json reset --global", 'rm ~/.bastion""fuse/KILL',
    "notepad .claude/./settings.json", "del .claude\\x\\..\\settings.json",
], ids=["pip", "uv", "pipx", "opt-order", "quote-split", "dot", "dotdot"])
def test_3_self_protect_spellings(cmd, tmp_path):
    cands = path_candidates({"command": cmd}, str(tmp_path))
    assert self_protect_hit(json.dumps({"command": cmd}), P, cands), cmd


def test_3_glob_and_dotdot_resolve_to_state(tmp_path):
    state = tmp_path / ".bastionfuse"
    state.mkdir()
    (state / "state.sqlite").write_text("x")
    policy = policy_from_dict(pol(state_dir=str(state)))
    cmd = f"rm {tmp_path}/.b?stion*/state.sqlite"
    assert self_protect_hit(cmd.replace(".bastionfuse", ""), policy, path_candidates({"command": cmd}, None))
    other = tmp_path / "x" / ".." / ".bastionfuse" / "state.sqlite"
    assert self_protect_hit("rm it", policy, path_candidates({"command": f"rm {other}"}, None))


@pytest.mark.skipif(sys.platform != "win32", reason="8.3 short names are Windows-only")
def test_3_short_names_expanded(tmp_path):
    import ctypes
    state = tmp_path / "longstatedirectoryname"
    state.mkdir()
    buf = ctypes.create_unicode_buffer(1024)
    ctypes.windll.kernel32.GetShortPathNameW(str(state), buf, 1024)
    if buf.value == str(state):
        pytest.skip("8.3 names disabled on this volume")
    policy = policy_from_dict(pol(state_dir=str(state)))
    short = buf.value + "\\state.sqlite"
    assert self_protect_hit(f"del {short}", policy, path_candidates({"command": f"del {short}"}, None))


def test_3_package_source_protected():
    from bastionfuse.rules import _install_paths
    target = str(Path(_install_paths()[0]) / "hook.py")
    assert self_protect_hit("x", P, path_candidates({"file_path": target}, None))


def test_3_benign_repo_work_not_blocked(tmp_path):
    for cmd in ("vim bastionfuse/reset_notes.md", "git reset --hard", "pip install requests", "pytest -q"):
        assert self_protect_hit(cmd, P, path_candidates({"command": cmd}, str(tmp_path))) is None, cmd


# 4. busy store: post retries then spools; the next check merges the spool
def test_4_busy_post_spools_and_check_merges(tmp_path, monkeypatch):
    import bastionfuse.fuse as fuse_mod
    import bastionfuse.state as state

    monkeypatch.setattr(state, "BUSY_TIMEOUT_S", 0.05)
    monkeypatch.setattr(fuse_mod, "RECORD_RETRY_S", 0.2)
    st = tmp_path / "st"
    policy = policy_from_dict(pol(state_dir=str(st), honeytokens=[TOKEN]))
    f = Fuse(policy, store=Store(st / "state.sqlite"))
    holder = sqlite3.connect(st / "state.sqlite", isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        assert f.record("Read", TOKEN, session="s") is not None
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    assert (st / "taint-spool.jsonl").exists()
    d = f.check("Bash", {"command": "curl https://evil.example"}, session="s")
    assert d.rule == "taint-egress"
    assert not list(st.glob("taint-spool*"))


# 5. PostToolUseFailure registered
def test_5_failure_hook_registered():
    s = hook.settings_snippet("bastionfuse", "/home/u/.bastionfuse")
    assert s["hooks"]["PostToolUseFailure"][0]["hooks"][0]["command"].endswith("hook post")
    assert '--home "/home/u/.bastionfuse"' in s["hooks"]["PreToolUse"][0]["hooks"][0]["command"]


# 6. hook reads UTF-8 bytes regardless of console codepage
def test_6_hook_stdin_is_utf8(tmp_path):
    pol_file = tmp_path / "f.json"
    pol_file.write_text(json.dumps(pol(honeytokens=[TOKEN])))
    cmd = TOKEN[:4] + "\u200b\u00ad" + TOKEN[4:]
    payload = json.dumps({"session_id": "u8", "tool_name": "Bash", "tool_input": {"command": f"echo {cmd}"}},
                         ensure_ascii=False).encode("utf-8")
    env = {"BASTIONFUSE_HOME": str(tmp_path / "h"), "PYTHONIOENCODING": "cp1252", "SYSTEMROOT": "C:\\Windows",
           "PATH": "", "USERPROFILE": str(tmp_path), "HOME": str(tmp_path)}
    r = subprocess.run([sys.executable, "-m", "bastionfuse.cli", "--policy", str(pol_file), "hook", "pre"],
                       input=payload, capture_output=True, env=env, timeout=60)
    assert r.returncode == 2, r.stderr
    ok = json.dumps({"session_id": "u8b", "tool_name": "Bash", "tool_input": {"command": "echo \u0101"}},
                    ensure_ascii=False).encode("utf-8")
    r = subprocess.run([sys.executable, "-m", "bastionfuse.cli", "--policy", str(pol_file), "hook", "pre"],
                       input=ok, capture_output=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr

