"""Regressions for the false blocks found in the first dogfood session (2026-10-06,
bastionfuse-DOGFOOD.md findings 1-4), plus the protections they must not weaken."""

from pathlib import Path

import pytest

from bastionfuse import Fuse
from bastionfuse.policy import policy_from_dict
from bastionfuse.rules import _package_dir, self_protect_hit
from bastionfuse.state import Store
from conftest import pol

DOC = ("Install: uv tool install --force dist/bastionfuse-0.1.0-py3-none-any.whl\n"
       "Hooks live in ~/.claude/settings.json; reset with `bastionfuse reset --session <id>`.\n"
       "State: ~/.bastionfuse\n")


def make():
    return Fuse(policy_from_dict(pol()), store=Store(None))


# finding 1: package-tool word near the name, no install/remove verb
def test_1_uv_query_then_path_allowed():
    cmd = 'gh pr checks 2; "$(uv tool dir)/bastionfuse/Scripts/bastionfuse.exe" log --summary'
    assert make().check("Bash", {"command": cmd}).allowed


# finding 2: running the installed console script by its full path
def test_2_running_script_by_path_allowed():
    exe = r"C:\Users\me\AppData\Roaming\uv\tools\bastionfuse\Scripts\bastionfuse.exe"
    assert make().check("Bash", {"command": f'"{exe}" log --summary'}).allowed


# findings 3 and 4: file content that merely mentions the fuse, its install or settings
@pytest.mark.parametrize("tool, field", [("Write", "content"), ("Edit", "new_string")])
def test_3_4_content_mentions_allowed(tool, field, tmp_path):
    target = str(tmp_path / "DOGFOOD.md")
    inp = {"file_path": target, field: DOC}
    if tool == "Edit":
        inp["old_string"] = "x"
    assert make().check(tool, inp).allowed


# the protections the fix must keep
@pytest.mark.parametrize("tool, inp, why", [
    ("Bash", {"command": "pip uninstall -y bastionfuse"}, "installation"),
    ("Bash", {"command": "uv tool uninstall bastionfuse"}, "installation"),
    ("Bash", {"command": "uv pip install --force-reinstall bastionfuse==0.0.1"}, "installation"),
    ("Bash", {"command": "bastionfuse reset --global"}, "operator command"),
    ("Bash", {"command": "rm -r ~/.bastionfuse"}, "state"),
    ("Write", {"file_path": str(Path.home() / ".claude" / "settings.json"), "content": "{}"}, "settings"),
    ("Edit", {"file_path": ".claude/settings.local.json", "old_string": "a", "new_string": "b"}, "settings"),
], ids=["pip-uninstall", "uv-tool-uninstall", "uv-reinstall", "reset", "rm-state", "write-settings",
        "edit-settings"])
def test_protections_kept(tool, inp, why):
    d = make().check(tool, inp)
    assert not d.allowed and d.rule == "self-protect" and why in d.reason


def test_package_source_still_unwritable():
    src = str(Path(_package_dir()) / "fuse.py")
    d = make().check("Write", {"file_path": src, "content": "pass"})
    assert not d.allowed and "installed bastionfuse package" in d.reason


def test_action_text_ignores_content_keys():
    policy = policy_from_dict(pol())
    from bastionfuse.rules import action_text
    assert self_protect_hit(action_text({"file_path": "notes.md", "content": DOC}), policy) is None
    assert self_protect_hit(action_text({"command": "cat ~/.claude/settings.json"}), policy)
