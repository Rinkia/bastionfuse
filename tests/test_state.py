import sqlite3
import time
import subprocess
import sys
import textwrap

import pytest

from bastionfuse import Fuse
from bastionfuse.policy import policy_from_dict
from bastionfuse.state import GLOBAL, Store, StoreBusy, StoreCorrupt
from conftest import pol

WORKER = textwrap.dedent("""
    import sys
    from bastionfuse import Fuse
    from bastionfuse.policy import policy_from_dict
    from bastionfuse.state import Store
    st = sys.argv[1]
    policy = policy_from_dict({"policy_version": 2, "fuse": {"state_dir": st,
        "budgets": {"tools": {"t": {"max": 30, "window_s": 3600}}}}})
    f = Fuse(policy, store=Store(st + "/state.sqlite"))
    print(sum(f.check("t", {}, session="s").allowed for _ in range(20)))
""")


def test_two_processes_share_budget_without_lost_increments(tmp_path):
    st = tmp_path / "st"
    procs = [subprocess.Popen([sys.executable, "-c", WORKER, str(st)], stdout=subprocess.PIPE, text=True)
             for _ in range(3)]
    total = sum(int(p.communicate(timeout=120)[0].strip()) for p in procs)
    assert total == 30  # 60 attempts, exactly the budget passes


def test_corrupt_file_fails_closed(tmp_path):
    db = tmp_path / "state.sqlite"
    db.write_bytes(b"this is not a sqlite database at all" * 100)
    with pytest.raises(StoreCorrupt):
        Store(db)


def test_corrupt_after_open_denies(tmp_path):
    db = tmp_path / "state.sqlite"
    policy = policy_from_dict(pol(state_dir=str(tmp_path)))
    f = Fuse(policy, store=Store(db))
    db.write_bytes(b"garbage" * 1000)
    d = f.check("Read", {})
    assert not d.allowed and d.rule == "store"


def test_busy_raises_store_busy(tmp_path, monkeypatch):
    import bastionfuse.state as state

    monkeypatch.setattr(state, "BUSY_TIMEOUT_S", 0.1)
    db = tmp_path / "state.sqlite"
    store = Store(db)
    holder = sqlite3.connect(db, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(StoreBusy):
            with store.tx():
                pass
    finally:
        holder.execute("ROLLBACK")
        holder.close()


def test_flags_first_trip_wins_and_sessions_listed():
    store = Store(None)
    with store.tx() as t:
        t.set_flag("s1", "first", "canary", 1.0)
        t.set_flag("s1", "second", "budget", 2.0)
        t.set_taint("s2", "decoy", 1.0)
        t.add_event("s3", "call", "*", 1.0)
    with store.tx() as t:
        assert t.flag("s1") == ("first", "canary", 1.0)
        assert t.sessions() == ["s1", "s2", "s3"]
        assert t.flag(GLOBAL) is None


def test_ring_and_events_bounded(monkeypatch):
    import bastionfuse.state as state

    monkeypatch.setattr(state, "MAX_EVENTS_PER_SESSION", 10)
    store = Store(None)
    with store.tx() as t:
        for i in range(300):
            t.add_ring("s", "Read", "{}", "allowed", float(i))
            t.add_event("s", "call", "*", float(10**6 + i))
        t.add_event("s", "call", "*", 0.0)  # older than the longest window: pruned
        t.prune("s", float(10**6 + 300))
        assert len(t.ring("s")) == state.RING_SIZE
        assert t.count("s", "call", None, 0.0) == 10


def test_schema_creation_retries_then_reports_busy(tmp_path, monkeypatch):
    import bastionfuse.state as state

    monkeypatch.setattr(state, "BUSY_TIMEOUT_S", 0.05)
    monkeypatch.setattr(state, "SCHEMA_RETRY_S", 0.3)
    db = tmp_path / "state.sqlite"
    holder = sqlite3.connect(db, isolation_level=None)
    holder.execute("BEGIN EXCLUSIVE")  # fresh file, no schema, writer holds the lock
    try:
        start = time.perf_counter()
        with pytest.raises(StoreBusy):
            Store(db)
        assert time.perf_counter() - start >= 0.25  # it retried before giving up
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    Store(db)  # lock released: creation succeeds
    assert Store(db)._has_schema()
