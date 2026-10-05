"""Round-1 security review regressions, findings 7 onward: plain behaviour checks."""

import base64
import io
import json

import pytest

from bastionfuse import Fuse, cli
from bastionfuse.decoy_mcp import handle, serve
from bastionfuse.policy import policy_from_dict
from bastionfuse.rules import TokenMatcher, command_labels
from bastionfuse.state import Store
from conftest import TOKEN, pol

P = policy_from_dict(pol())


def make(**fuse):
    return Fuse(policy_from_dict(pol(**fuse)), store=Store(None))


# 7. classifier unwrapping mechanics
@pytest.mark.parametrize("cmd, label", [
    ("bash -c 'git push origin main'", "egress"),
    ("sudo -u builder git push origin main", "egress"),
    ("if true; then git push origin main; fi", "egress"),
    ("rm --recursive build", "destructive"),
    ("git push --force-with-lease origin main", "destructive"),
], ids=["shell-c", "sudo-u", "if-then", "rm-long", "force-lease"])
def test_7_unwrapping(cmd, label):
    assert label in command_labels(cmd, P.commands)


def test_7_inline_code_is_opaque():
    assert "opaque" in command_labels("python -c 'print(1)'", P.commands)
    assert "opaque" not in command_labels("python script.py", P.commands)


# 8. a tainted session trips on any call that can send data, not only `egress`
def test_8_taint_trips_on_fetch_and_mcp():
    f = make(honeytokens=[TOKEN])
    f.record("Read", TOKEN, session="a")
    assert f.check("Read", {"file_path": "x"}, session="a").allowed
    assert f.check("Bash", {"command": "pip install requests"}, session="a").rule == "taint-egress"
    f.record("Read", TOKEN, session="b")
    assert f.check("mcp__notes__save", {"text": "hi"}, session="b").rule == "taint-egress"


# 9. decoy referenced by a relative path still taints
def test_9_relative_decoy_path(tmp_path):
    decoy = tmp_path / ".env.backup"
    f = make(decoy_paths=[str(decoy)])
    f.check("Read", {"file_path": ".env.backup"}, cwd=str(tmp_path))
    assert f.status()["taint"].startswith("decoy path")


# 10. encoded token forms are matched
def test_10_spaced_hex_matched():
    spaced = " ".join(f"{b:02x}" for b in TOKEN.encode())
    assert TokenMatcher((TOKEN,)).find(spaced) == TOKEN


# 12. stored forensics never hold the token, encoded or not
def test_12_redaction_covers_encoded_token():
    m = TokenMatcher((TOKEN,))
    blob = base64.b64encode(TOKEN.encode()).decode()
    out = m.redact(f"a {blob} b {TOKEN.lower()}")
    assert blob not in out and TOKEN.lower() not in out


# 16. degrade mode refuses remote paths even for read-only tools
def test_16_degrade_refuses_remote_paths():
    f = make(mode="degrade", canary_tools=["bad"])
    f.check("bad", {})
    assert f.check("Read", {"file_path": "notes.md"}).allowed
    assert not f.check("Read", {"file_path": "\\\\server\\share\\x"}).allowed


# 17. a malformed decoy MCP message never kills the server
def test_17_decoy_survives_bad_tool_name():
    reply = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": ["x"]}}, lambda n: None)
    assert reply["error"]["code"] == -32602
    out = io.StringIO()
    lines = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": ["x"]}}) + "\n" + \
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}) + "\n"
    serve(io.StringIO(lines), out, lambda n: None)
    assert [json.loads(x)["id"] for x in out.getvalue().splitlines()] == [1, 2]


# 21. a damaged log line never breaks the tally
def test_21_log_summary_skips_bad_lines(capsys, fuse_home):
    fuse_home.mkdir(parents=True, exist_ok=True)
    good = {"ts": 1, "session": "a", "tool": "x", "allowed": False, "rule": "canary", "tripped": True, "shadow": []}
    (fuse_home / "log.jsonl").write_text("garbage\n[1]\n" + json.dumps(good) + "\n")
    assert cli.main(["log", "--summary"]) == 0
    assert json.loads(capsys.readouterr().out)["trips_by_rule"] == {"canary": 1}
