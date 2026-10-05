"""Round-3 review regressions: no scan may hold the GIL long enough to stall the watchdog,
and the hook's exit code survives a closed stderr."""

import json
import subprocess
import sys
import time

import pytest

from bastionfuse.policy import policy_from_dict
from bastionfuse.rules import self_protect_hit
from conftest import pol

P = policy_from_dict(pol())


@pytest.mark.parametrize("unit", ["pip ", "bastionfuse ", ".claude/"], ids=["pkg", "verbs", "settings"])
def test_self_protect_regexes_linear(unit):
    text = unit * (1_000_000 // len(unit))  # ~1 MB, the input cap
    start = time.perf_counter()
    self_protect_hit(text, P)
    assert time.perf_counter() - start < 3.0  # was minutes while quadratic


def test_self_protect_still_matches_after_bounding():
    assert self_protect_hit("pip uninstall -y bastionfuse", P)
    assert self_protect_hit("bastionfuse --policy x.json reset --global", P)
    assert self_protect_hit("edit .claude/sub/settings.local.json", P)


def test_closed_stderr_keeps_block_exit_code(tmp_path):
    pol_file = tmp_path / "f.json"
    pol_file.write_text(json.dumps(pol(canary_tools=["bad"])))
    env = {"BASTIONFUSE_HOME": str(tmp_path / "h"), "USERPROFILE": str(tmp_path), "HOME": str(tmp_path),
           "SYSTEMROOT": "C:\\Windows", "PATH": ""}
    p = subprocess.Popen([sys.executable, "-m", "bastionfuse.cli", "--policy", str(pol_file), "hook", "pre"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    p.stderr.close()
    p.stdin.write(json.dumps({"session_id": "c", "tool_name": "bad", "tool_input": {}}).encode())
    p.stdin.close()
    assert p.wait(timeout=60) == 2
    p.stdout.close()
