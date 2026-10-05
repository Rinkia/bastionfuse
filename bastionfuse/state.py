"""Fuse state in sqlite, shared by every process that guards a session.

Claude Code runs each hook as a new process, so trips, taint and budget windows
must live outside memory. The connection pattern follows bastiongate's
taint_store: one short connection per transaction, BEGIN IMMEDIATE so check and
record are atomic across processes, and a busy timeout that surfaces as
StoreBusy (the caller then fails closed).

Scopes: "global" holds operator signals (KILL file, `bastionfuse trip --global`);
every other row is keyed by session id, so one session's trip doesn't stop another.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .policy import MAX_WINDOW_S

BUSY_TIMEOUT_S = 2.0
MAX_EVENTS_PER_SESSION = 50_000
RING_SIZE = 256
GLOBAL = "global"

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS flags (scope TEXT PRIMARY KEY, reason TEXT, rule TEXT, ts REAL)",
    "CREATE TABLE IF NOT EXISTS taint (session TEXT PRIMARY KEY, source TEXT, ts REAL)",
    "CREATE TABLE IF NOT EXISTS events (session TEXT, kind TEXT, key TEXT, amount INTEGER, ts REAL)",
    "CREATE INDEX IF NOT EXISTS events_idx ON events (session, kind, key, ts)",
    "CREATE TABLE IF NOT EXISTS ring (id INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT, tool TEXT, "
    "args TEXT, verdict TEXT, ts REAL)",
    "CREATE INDEX IF NOT EXISTS ring_idx ON ring (session, id)",
)


class StoreBusy(Exception):
    """Another process held the lock past the timeout. The caller fails closed."""


class StoreCorrupt(Exception):
    """The state file is not a usable database. The caller fails closed."""


class Store:
    """`path=None` keeps state in memory (library use in one process)."""

    def __init__(self, path: str | os.PathLike | None) -> None:
        self.path = Path(path) if path is not None else None
        self._lock = threading.RLock()
        self._mem: sqlite3.Connection | None = None
        if self.path is None:
            self._mem = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
        else:  # exist_ok: hook processes start together and race to create it
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.tx() as t:
            for stmt in _SCHEMA:
                t.db.execute(stmt)
        if self.path is not None and os.name != "nt":
            os.chmod(self.path, 0o600)

    def close(self) -> None:
        if self._mem is not None:
            self._mem.close()
            self._mem = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:  # noqa: BLE001 - interpreter shutdown
            pass

    @contextmanager
    def tx(self) -> Iterator["Tx"]:
        """One atomic transaction. Lock timeout -> StoreBusy; bad file -> StoreCorrupt."""
        with self._lock:
            db = self._mem or sqlite3.connect(self.path, timeout=BUSY_TIMEOUT_S, isolation_level=None)
            try:
                db.execute("BEGIN IMMEDIATE")
                yield Tx(db)
                db.execute("COMMIT")
            except BaseException as exc:
                if db.in_transaction:
                    try:
                        db.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                if isinstance(exc, sqlite3.OperationalError) and "locked" in str(exc):
                    raise StoreBusy(str(exc)) from exc
                if isinstance(exc, sqlite3.DatabaseError) and not isinstance(exc, sqlite3.OperationalError):
                    raise StoreCorrupt(f"{self.path}: {exc}") from exc
                raise
            finally:
                if self._mem is None:
                    db.close()


class Tx:
    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db

    # flags (sticky trips)
    def flag(self, scope: str) -> tuple[str, str, float] | None:
        row = self.db.execute("SELECT reason, rule, ts FROM flags WHERE scope = ?", (scope,)).fetchone()
        return tuple(row) if row else None

    def set_flag(self, scope: str, reason: str, rule: str, now: float) -> None:
        """First trip wins: a later reason never overwrites the original one."""
        self.db.execute("INSERT OR IGNORE INTO flags VALUES (?, ?, ?, ?)", (scope, reason, rule, now))

    def clear_flag(self, scope: str) -> bool:
        return self.db.execute("DELETE FROM flags WHERE scope = ?", (scope,)).rowcount > 0

    # taint (honeytoken or decoy seen)
    def taint(self, session: str) -> str | None:
        row = self.db.execute("SELECT source FROM taint WHERE session = ?", (session,)).fetchone()
        return row[0] if row else None

    def set_taint(self, session: str, source: str, now: float) -> None:
        self.db.execute("INSERT OR IGNORE INTO taint VALUES (?, ?, ?)", (session, source, now))

    def clear_session(self, session: str) -> None:
        for table in ("taint", "events", "ring"):
            self.db.execute(f"DELETE FROM {table} WHERE session = ?", (session,))
        self.clear_flag(session)

    # windowed events
    def add_event(self, session: str, kind: str, key: str, now: float, amount: int = 1) -> None:
        self.db.execute("INSERT INTO events VALUES (?, ?, ?, ?, ?)", (session, kind, key, amount, now))

    def count(self, session: str, kind: str, key: str | None, since: float) -> int:
        if key is None:
            sql, args = "SELECT COUNT(*) FROM events WHERE session=? AND kind=? AND ts>=?", (session, kind, since)
        else:
            sql = "SELECT COUNT(*) FROM events WHERE session=? AND kind=? AND key=? AND ts>=?"
            args = (session, kind, key, since)
        return self.db.execute(sql, args).fetchone()[0]

    def total(self, session: str, kind: str, since: float) -> int:
        return self.db.execute("SELECT COALESCE(SUM(amount), 0) FROM events WHERE session=? AND kind=? AND ts>=?",
                               (session, kind, since)).fetchone()[0]

    def distinct(self, session: str, kind: str, since: float) -> set[str]:
        rows = self.db.execute("SELECT DISTINCT key FROM events WHERE session=? AND kind=? AND ts>=?",
                               (session, kind, since))
        return {r[0] for r in rows}

    # forensic ring (last RING_SIZE calls per session)
    def add_ring(self, session: str, tool: str, args: str, verdict: str, now: float) -> None:
        self.db.execute("INSERT INTO ring (session, tool, args, verdict, ts) VALUES (?, ?, ?, ?, ?)",
                        (session, tool, args, verdict, now))
        self.db.execute("DELETE FROM ring WHERE session = ? AND id NOT IN (SELECT id FROM ring WHERE session = ? "
                        "ORDER BY id DESC LIMIT ?)", (session, session, RING_SIZE))

    def ring(self, session: str) -> list[tuple[str, str, str, float]]:
        return [tuple(r) for r in self.db.execute(
            "SELECT tool, args, verdict, ts FROM ring WHERE session = ? ORDER BY id", (session,))]

    def prune(self, session: str, now: float) -> None:
        self.db.execute("DELETE FROM events WHERE ts < ?", (now - MAX_WINDOW_S,))
        self.db.execute("DELETE FROM events WHERE session = ? AND rowid NOT IN (SELECT rowid FROM events "
                        "WHERE session = ? ORDER BY ts DESC LIMIT ?)", (session, session, MAX_EVENTS_PER_SESSION))

    def sessions(self) -> list[str]:
        rows = self.db.execute("SELECT session FROM events UNION SELECT session FROM taint "
                               "UNION SELECT scope FROM flags")
        return sorted(r[0] for r in rows)

