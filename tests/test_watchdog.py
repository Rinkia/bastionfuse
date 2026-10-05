"""HIGH-1: the hook must deny before Claude Code's hook timeout, never run long."""

import io
import json
import subprocess
import sys
import threading
import time

from bastionfuse import hook
from bastionfuse.rules import path_candidates


def test_watchdog_fires_with_block_code():
    fired = threading.Event()
    codes = []
    err = io.StringIO()

    def fake_exit(code):
        codes.append(code)
        fired.set()

    hook.start_watchdog(0.05, err, fake_exit)
    assert fired.wait(2)
    assert codes == [hook.BLOCK] and "blocked to stay safe" in err.getvalue()


def test_watchdog_cancelled_on_fast_check():
    codes = []
    t = hook.start_watchdog(0.2, io.StringIO(), codes.append)
    t.cancel()
    time.sleep(0.4)
    assert codes == []


def test_watchdog_below_hook_timeout():
    assert hook.WATCHDOG_S < hook.HOOK_TIMEOUT_S
    s = hook.settings_snippet()
    assert s["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] == hook.HOOK_TIMEOUT_S


SLOW_HOOK = """
import sys, time
import bastionfuse.hook as h
h.WATCHDOG_S = 0.5
def slow(*a, **k):
    time.sleep(30)
    return 0
h.pre = slow
from bastionfuse.cli import main
sys.exit(main(["hook", "pre"]))
"""


def test_real_process_slow_check_denied_quickly(tmp_path):
    payload = json.dumps({"session_id": "w", "tool_name": "Bash", "tool_input": {"command": "ls"}})
    start = time.perf_counter()
    r = subprocess.run([sys.executable, "-c", SLOW_HOOK], input=payload.encode(), capture_output=True,
                       timeout=60, env={"BASTIONFUSE_HOME": str(tmp_path), "USERPROFILE": str(tmp_path),
                                        "HOME": str(tmp_path), "SYSTEMROOT": "C:\\Windows", "PATH": ""})
    assert r.returncode == hook.BLOCK, r.stderr
    assert time.perf_counter() - start < 10
    assert b"blocked to stay safe" in r.stderr


def test_remote_paths_never_touch_filesystem(monkeypatch):
    import os.path
    import glob

    def boom(*a, **k):
        raise AssertionError("filesystem touched for a remote path")

    monkeypatch.setattr(os.path, "realpath", boom)
    monkeypatch.setattr(glob, "iglob", boom)
    cands = path_candidates({"command": "ls //server/share/x* \\\\host\\s~1\\y"}, None)
    assert any(c.startswith("//server") for c in cands)


def test_broad_glob_is_bounded(tmp_path):
    for i in range(200):
        (tmp_path / f"f{i}").write_text("x")
    start = time.perf_counter()
    cands = path_candidates({"command": f"ls {tmp_path}/*"}, None)
    assert time.perf_counter() - start < 3
    assert len([c for c in cands if "/f" in c]) <= 32
