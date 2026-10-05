import io
import json
import subprocess
import sys

import pytest

from bastionfuse import cli, decoy_mcp
from bastionfuse.demo import run
from bastionfuse.policy import policy_from_dict


def call(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_help_and_version(capsys):
    assert call(capsys)[0] == 0
    with pytest.raises(SystemExit):
        cli.main(["--version"])


def test_trip_status_reset_cycle(capsys):
    assert call(capsys, "trip", "--reason", "manual", "--session", "s1")[0] == 0
    status = json.loads(call(capsys, "status", "--session", "s1")[1])
    assert status["tripped"] and status["session_trip"]["reason"] == "manual"
    assert "reset done" in call(capsys, "reset", "--session", "s1")[1]
    assert not json.loads(call(capsys, "status", "--session", "s1")[1])["tripped"]
    assert "nothing was tripped" in call(capsys, "reset", "--session", "s1")[1]


def test_kill_then_global_reset(capsys, fuse_home):
    call(capsys, "kill", "--reason", "incident 42")
    assert (fuse_home / "KILL").read_text().startswith("incident 42")
    assert json.loads(call(capsys, "status")[1])["signal"].startswith("operator KILL file")
    out = call(capsys, "reset", "--global")[1]
    assert "removed KILL file" in out and not (fuse_home / "KILL").exists()


def test_trip_global(capsys):
    assert "GLOBAL" in call(capsys, "trip", "--reason", "x", "--global")[1]
    assert json.loads(call(capsys, "status", "--session", "any")[1])["global"]["rule"] == "operator"


def test_plant_registers_decoys_and_tokens(capsys, tmp_path, fuse_home):
    d = tmp_path / "proj"
    assert call(capsys, "plant", "--dir", str(d))[0] == 0
    decoy = d / ".env.backup"
    assert decoy.exists()
    # never overwrites
    assert "already exists" in call(capsys, "plant", "--dir", str(d))[2]
    policy = policy_from_dict({"policy_version": 2, "fuse": {}})
    assert len(policy.honeytokens) == 3 and policy.decoy_paths == (str(decoy.resolve()),)
    assert all(t in decoy.read_text() for t in policy.honeytokens)


def test_tokens_and_install_hook(capsys):
    code, out, _ = call(capsys, "tokens", "new", "--kind", "github")
    assert code == 0 and out.startswith("ghp_")
    code, out, err = call(capsys, "install-hook")
    assert json.loads(out)["hooks"]["PreToolUse"] and "managed settings" in err


def test_log(capsys, fuse_home):
    assert "no log yet" in call(capsys, "log")[1]
    fuse_home.mkdir(parents=True, exist_ok=True)
    recs = [{"ts": 1, "session": "a", "tool": "x", "allowed": False, "rule": "canary", "tripped": True,
             "reason": "r", "shadow": []},
            {"ts": 2, "session": "b", "tool": "Bash", "allowed": True, "rule": "", "tripped": False, "reason": "ok",
             "shadow": ["would trip: repeat (same 'Bash' call 21 times in 60s)"]},
            {"ts": 3, "session": "b", "tool": "Read", "taint": "honeytoken #abc"}]
    (fuse_home / "log.jsonl").write_text("\n".join(json.dumps(r) for r in recs))
    summary = json.loads(call(capsys, "log", "--summary")[1])
    assert summary["trips_by_rule"] == {"canary": 1} and summary["sessions"] == 2
    assert summary["shadow_notes"] == {"would trip: repeat": 1} and summary["taints"] == 1
    assert len(call(capsys, "log", "--tail", "2")[1].splitlines()) == 2


def test_bad_policy_exit_2(capsys, tmp_path):
    bad = tmp_path / "f.json"
    bad.write_text("{}")
    code, _, err = call(capsys, "--policy", str(bad), "status")
    assert code == 2 and "policy_version" in err


def test_demo_stops_every_attack(capsys):
    outcomes = run()
    assert outcomes and all(o.stopped_at for o in outcomes)
    rules = {o.rule for o in outcomes}
    assert {"taint-egress", "honeytoken", "canary", "budget:destructive", "budget:egress_hosts",
            "self-protect"} <= rules
    assert call(capsys, "demo")[0] == 0


def test_cli_entrypoint_subprocess():
    r = subprocess.run([sys.executable, "-m", "bastionfuse.cli", "tokens", "new"], capture_output=True, text=True,
                       timeout=60)
    assert r.returncode == 0 and r.stdout.startswith("AKIA")


# --- decoy MCP server --------------------------------------------------------

def rpc(method, mid=1, **params):
    return {"jsonrpc": "2.0", "id": mid, "method": method, "params": params}


def test_decoy_protocol():
    calls = []
    init = decoy_mcp.handle(rpc("initialize", protocolVersion="2025-03-26", capabilities={}), calls.append)
    assert init["result"]["protocolVersion"] == "2025-03-26"
    assert decoy_mcp.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, calls.append) is None
    tools = decoy_mcp.handle(rpc("tools/list"), calls.append)["result"]["tools"]
    assert {t["name"] for t in tools} == {"export_all_secrets", "get_admin_credentials", "disable_audit_logging"}
    res = decoy_mcp.handle(rpc("tools/call", name="export_all_secrets", arguments={}), calls.append)
    assert res["result"]["isError"] and calls == ["export_all_secrets"]
    assert decoy_mcp.handle(rpc("tools/call", name="nope"), calls.append)["error"]["code"] == -32602
    assert decoy_mcp.handle(rpc("ping"), calls.append)["result"] == {}
    assert decoy_mcp.handle(rpc("resources/list"), calls.append)["error"]["code"] == -32601
    assert decoy_mcp.handle([1], calls.append)["error"]["code"] == -32600
    assert decoy_mcp.handle(rpc("initialize"), calls.append)["result"]["protocolVersion"] == decoy_mcp.PROTOCOL_VERSION


def test_decoy_serve_loop():
    lines = "\n".join([json.dumps(rpc("ping")), "", "{bad json", json.dumps(rpc("tools/list", mid=2))]) + "\n"
    out = io.StringIO()
    decoy_mcp.serve(io.StringIO(lines), out, lambda name: None)
    replies = [json.loads(x) for x in out.getvalue().splitlines()]
    assert [r.get("id") for r in replies] == [1, None, 2]
    assert replies[1]["error"]["code"] == -32700


def test_decoy_call_trips_global(fuse_home, capsys):
    decoy_mcp._trip_global("export_all_secrets")
    status = json.loads(call(capsys, "status", "--session", "whatever")[1])
    assert status["global"]["rule"] == "canary"
