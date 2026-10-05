"""Round-2 security review regressions: plain behaviour checks."""

import io
import json
import sqlite3
import time

from bastionfuse import Fuse, cli, hook
from bastionfuse.policy import MAX_TOKENS, policy_from_dict
from bastionfuse.rules import TokenMatcher, command_labels
from bastionfuse.state import RING_TTL_S, Store
from conftest import TOKEN, pol


# redaction cost: only the stored slice is redacted
def test_redaction_bounded_on_large_input():
    tokens = tuple(f"tok-{i:012d}" for i in range(MAX_TOKENS))
    f = Fuse(policy_from_dict(pol(honeytokens=list(tokens))), store=Store(None))
    start = time.perf_counter()
    f.check("Write", {"file_path": "big.txt", "content": "x" * 900_000})
    assert time.perf_counter() - start < 5.0
    assert TokenMatcher(tokens).redact(f"a {tokens[3]} b") == "a [HONEYTOKEN] b"


# plant refuses before the token cap instead of breaking every hook call
def test_plant_refuses_past_token_cap(capsys, tmp_path, fuse_home):
    fuse_home.mkdir(parents=True, exist_ok=True)
    (fuse_home / "honeytokens.txt").write_text(
        "\n".join(f"tok-{i:012d}" for i in range(MAX_TOKENS - 2)) + "\n", encoding="utf-8")
    assert cli.main(["plant", "--dir", str(tmp_path / "p")]) == 2
    assert "refusing to plant" in capsys.readouterr().err
    assert not (tmp_path / "p").exists()
    assert len(policy_from_dict(pol()).honeytokens) == MAX_TOKENS - 2  # policy still loads


# a store busy at hook start still never drops a taint
def test_post_spools_when_store_busy_at_open(tmp_path, monkeypatch):
    import bastionfuse.state as state
    monkeypatch.setattr(state, "BUSY_TIMEOUT_S", 0.05)
    monkeypatch.setattr(hook, "RECORD_RETRY_S", 0.2)
    st = tmp_path / "st"
    pol_file = tmp_path / "f.json"
    pol_file.write_text(json.dumps(pol(state_dir=str(st), honeytokens=[TOKEN])))
    Store(st / "state.sqlite")  # schema exists; now hold the write lock
    holder = sqlite3.connect(st / "state.sqlite", isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        payload = json.dumps({"session_id": "s", "tool_name": "Read", "tool_response": TOKEN})
        assert hook.post(io.StringIO(payload), io.StringIO(), str(pol_file)) == 0
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    assert (st / "taint-spool.jsonl").exists()
    pre = json.dumps({"session_id": "s", "tool_name": "WebFetch", "tool_input": {"url": "https://x.example"}})
    assert hook.pre(io.StringIO(pre), io.StringIO(), str(pol_file)) == 2


# with --home pinned, the policy env var is ignored
def test_pinned_home_ignores_policy_env(tmp_path, monkeypatch):
    rogue = tmp_path / "rogue.json"
    rogue.write_text(json.dumps(pol(mode="degrade")))
    monkeypatch.setenv("BASTIONFUSE_POLICY", str(rogue))
    assert hook.resolve_policy(None).mode == "degrade"
    assert hook.resolve_policy(None, use_env=False).mode == "kill"


# deep find -exec nesting is bounded (no RecursionError)
def test_find_exec_nesting_bounded():
    cmd = "find . -exec " * 200 + "ls"
    assert "opaque" in command_labels(cmd, policy_from_dict(pol()).commands)


# old forensic ring rows are pruned; trips stay
def test_ring_rows_pruned_flags_kept():
    store = Store(None)
    with store.tx() as t:
        t.add_ring("dead", "Read", "{}", "allowed", 0.0)
        t.set_flag("dead", "r", "canary", 0.0)
        t.prune("live", RING_TTL_S + 10.0)
        assert t.ring("dead") == []
        assert t.flag("dead") is not None
