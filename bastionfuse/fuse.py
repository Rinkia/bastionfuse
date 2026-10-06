"""The fuse: check a tool call before it runs, record its result after.

Order inside check() (first hit wins; cheap and certain first):

  1  operator signals: KILL file, kill env, stale heartbeat  -> trip (global)
  2  already tripped                                          -> deny (degrade: local read-only passes)
  3  canary tool                                              -> trip
  4  honeytoken (raw/hex/base32/base64/...) in the input      -> trip
  5  decoy path in the input                                  -> taint session
  6  self-protect: touches the fuse, its install or settings  -> deny, no trip
  7  classify: egress | fetch | destructive | read_only | opaque
  8  tainted session + anything that can send data           -> trip
  9  budgets (operator-written enforce, defaults shadow)      -> trip / log
 10  repeat detector                                          -> shadow by default
 11  allow

The CPU-heavy scans run before the state lock is taken; the trip is committed in
its own transaction before any forensics are written, so a forensics failure can
never undo it. A trip is sticky until an operator resets it. Any internal error
makes check() deny (fail closed).
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .policy import FusePolicy
from .rules import (OPAQUE, Oversize, PathMatcher, TokenMatcher, action_text, classify, flatten, hosts_of,
                    path_candidates, self_protect_hit)
from .state import GLOBAL, Store, StoreBusy, StoreCorrupt, Tx

RING_ARGS_CAP = 4096  # bytes of args kept per call in the forensic ring
MAX_TRIP_FILES = 500
RECORD_RETRY_S = 8.0  # PostToolUse can't undo anything, so waiting for the lock costs nothing
SPOOL = "taint-spool"
_SENDS = frozenset({"egress", "fetch", OPAQUE})
_REMOTE_PATH = re.compile(r"^\s*(?:\\\\|//|[a-z][a-z0-9+.-]*://)", re.IGNORECASE)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = "allowed"
    rule: str = ""
    tripped: bool = False  # the fuse is tripped (by this call or earlier)
    shadow: tuple[str, ...] = field(default_factory=tuple)  # would-trip notes from shadow rules


class FuseBlocked(Exception):
    def __init__(self, tool: str, decision: Decision) -> None:
        self.tool = tool
        self.decision = decision
        super().__init__(f"bastionfuse blocked '{tool}': {decision.reason}")


@dataclass
class _Verdict:
    allowed: bool = True
    reason: str = "allowed"
    rule: str = ""
    trip: bool = False
    shadow: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _Facts:
    """Everything about a call that needs no state. Computed outside the lock."""
    text: str
    token: str | None
    decoy: str | None
    protect: str | None
    labels: frozenset[str]
    hosts: frozenset[str]
    size: int
    repeat_key: str
    remote_path: bool


class Fuse:
    def __init__(self, policy: FusePolicy, *, store: Store | None = None, session: str = "default",
                 clock: Callable[[], float] = time.time,
                 on_trip: Callable[[str, Decision], None] | None = None) -> None:
        self.policy = policy
        self.store = store if store is not None else Store(policy.state_dir / "state.sqlite")
        self.session = session
        self.clock = clock
        self.on_trip = on_trip
        self.tokens = TokenMatcher(policy.honeytokens)
        self.decoys = PathMatcher(policy.decoy_paths)

    # --- public API ----------------------------------------------------------

    def check(self, tool: str, tool_input: Any = None, *, session: str | None = None,
              cwd: str | None = None) -> Decision:
        """Decide one call before it runs. Never raises; errors deny."""
        s = session or self.session
        try:
            return self._check(s, tool, tool_input, cwd)
        except StoreBusy:
            return Decision(False, "fuse state is busy (another process holds the lock); denied to stay safe",
                            "store")
        except StoreCorrupt as e:
            return Decision(False, f"fuse state store is unusable ({e}); an operator must inspect it", "store",
                            tripped=True)
        except Exception as e:  # noqa: BLE001 - a kill switch fails closed, never open
            return Decision(False, f"fuse internal error ({type(e).__name__}); denied to stay safe", "error")

    def record(self, tool: str, result: Any, *, session: str | None = None) -> str | None:
        """Scan a tool result. A honeytoken in it taints the session (the agent read a
        decoy); a later call that can send data then trips. Returns the taint source.
        A busy store is retried, then the taint goes to a spool the next check merges,
        so lock contention can never drop it."""
        s = session or self.session
        try:
            text = flatten(result)
            hit = self.tokens.find(text)
            source = f"honeytoken {self._token_id(hit)} in a {tool} result" if hit else None
        except Oversize:
            source = f"{tool} result too large to scan"  # fail closed: treat as tainted
        if source:
            deadline = time.monotonic() + RECORD_RETRY_S
            while True:
                try:
                    with self.store.tx() as t:
                        t.set_taint(s, source, self.clock())
                    break
                except StoreBusy:
                    if time.monotonic() >= deadline:
                        self._spool(s, source)
                        break
                    time.sleep(0.1)
        return source

    def trip(self, reason: str, *, session: str | None = None, global_: bool = False, rule: str = "operator") -> None:
        scope = GLOBAL if global_ else (session or self.session)
        with self.store.tx() as t:
            t.set_flag(scope, reason, rule, self.clock())

    def reset(self, *, session: str | None = None, global_: bool = False) -> bool:
        """Operator reset. Clears the trip plus that session's taint and windows."""
        with self.store.tx() as t:
            if global_:
                return t.clear_flag(GLOBAL)
            s = session or self.session
            was = t.flag(s) is not None
            t.clear_session(s)
            return was

    def status(self, *, session: str | None = None) -> dict:
        s = session or self.session
        with self.store.tx() as t:
            g, f = t.flag(GLOBAL), t.flag(s)
            return {
                "session": s,
                "tripped": bool(g or f),
                "global": _flag_dict(g),
                "session_trip": _flag_dict(f),
                "taint": t.taint(s),
                "signal": self._signal(),
                "sessions": t.sessions(),
            }

    def guard(self, func: Callable | None = None, *, name: str | None = None) -> Callable:
        """Decorator for library use: check before, record after, FuseBlocked on deny."""
        def wrap(f: Callable) -> Callable:
            tool = name or f.__name__

            @functools.wraps(f)
            def inner(*args, **kwargs):
                decision = self.check(tool, kwargs if kwargs or not args else list(args))
                if not decision.allowed:
                    raise FuseBlocked(tool, decision)
                result = f(*args, **kwargs)
                self.record(tool, result)
                return result
            return inner
        return wrap(func) if func is not None else wrap

    # --- internals -----------------------------------------------------------

    def _facts(self, tool: str, tool_input: Any, cwd: str | None) -> _Facts:
        text = flatten(tool_input)
        candidates = path_candidates(tool_input, cwd)
        labels = frozenset(classify(tool, tool_input, self.policy))
        return _Facts(
            text=text,
            token=self.tokens.find(text),
            decoy=self.decoys.find(text, candidates),
            protect=self_protect_hit(action_text(tool_input), self.policy, candidates,
                                     read_only="read_only" in labels, shell=tool in self.policy.shell_tools),
            labels=labels,
            hosts=frozenset(hosts_of(text)) if "egress" in labels else frozenset(),
            size=len(text.encode("utf-8")),
            repeat_key=hashlib.sha256(f"{tool}\0{text}".encode()).hexdigest()[:16],
            remote_path=any(_REMOTE_PATH.match(v) for v in _string_values(tool_input)),
        )

    def _check(self, s: str, tool: str, tool_input: Any, cwd: str | None) -> Decision:
        try:
            facts = self._facts(tool, tool_input, cwd)
        except Oversize as e:
            return Decision(False, f"tool input too large to scan ({e}); refused", "oversize")
        now = self.clock()
        signal = self._signal()
        spooled, claims = self._claim_spool()
        with self.store.tx() as t:
            for sess, source in spooled:
                t.set_taint(sess, source, now)
            if signal:
                t.set_flag(GLOBAL, signal, "signal", now)
            prior = t.flag(GLOBAL) or t.flag(s)
            if prior:
                d = self._tripped(tool, facts, prior)
                v = None
            else:
                v = self._evaluate(t, s, tool, facts, now)
                if v.trip:
                    t.set_flag(s, v.reason, v.rule, now)
                t.prune(s, now)
        _release(claims)
        if v is not None:
            d = Decision(v.allowed and not v.trip, self._deny_text(v.reason, v.rule) if v.trip else v.reason,
                         v.rule, v.trip, tuple(v.shadow))
        verdict = "tripped" if v is not None and v.trip else ("allowed" if d.allowed else "blocked")
        ring = self._forensics(s, tool, facts.text, verdict, now, want_ring=v is not None and v.trip)
        if v is not None and v.trip:
            self._after_trip(s, d, ring)
        return d

    def _evaluate(self, t: Tx, s: str, tool: str, f: _Facts, now: float) -> _Verdict:
        p = self.policy
        if p.is_canary(tool):
            return _Verdict(False, f"called canary tool '{tool}' (no legitimate flow uses it)", "canary", True)
        if f.token:
            return _Verdict(False, f"honeytoken {self._token_id(f.token)} in the input of '{tool}'", "honeytoken",
                            True)
        if f.decoy:
            t.set_taint(s, f"decoy path {f.decoy} touched by {tool}", now)
        if f.protect:
            return _Verdict(False, f"bastionfuse blocked '{tool}': it {f.protect}", "self-protect")
        taint = t.taint(s)
        if taint and (f.labels & _SENDS or (tool.startswith("mcp__") and "read_only" not in f.labels)):
            return _Verdict(False, f"'{tool}' can send data out, and this session touched a decoy ({taint})",
                            "taint-egress", True)
        v = _Verdict()
        self._budgets(t, s, tool, f, now, v)
        self._repeat(t, s, tool, f, now, v)
        return v

    def _budgets(self, t: Tx, s: str, tool: str, f: _Facts, now: float, v: _Verdict) -> None:
        p, b = self.policy, self.policy.budgets
        over: list[tuple[str, str, str]] = []  # (name, detail, action)

        def check_count(name: str, kind: str, key: str | None, budget) -> None:
            if budget is not None and t.count(s, kind, key, now - budget.window_s) + 1 > budget.max:
                over.append((name, f"more than {budget.max} in {budget.window_s}s", budget.action))

        check_count("calls", "call", None, b.get("calls"))
        for label in ("egress", "fetch", "destructive"):
            if label in f.labels:
                check_count(label, "label", label, b.get(label))
        check_count(f"tool {tool}", "tool", tool, p.tool_budgets.get(tool))
        if "egress" in f.labels:
            hb, bb = b.get("egress_hosts"), b.get("bytes_out")
            if hb is not None:
                seen = t.distinct(s, "host", now - hb.window_s) | f.hosts
                if len(seen) > hb.max:
                    over.append(("egress_hosts", f"{len(seen)} distinct hosts in {hb.window_s}s (max {hb.max})",
                                 hb.action))
            if bb is not None and t.total(s, "bytes", now - bb.window_s) + f.size > bb.max:
                over.append(("bytes_out", f"more than {bb.max} bytes out in {bb.window_s}s", bb.action))
            t.add_event(s, "bytes", "*", now, f.size)
        t.add_event(s, "call", "*", now)
        for label in f.labels & {"egress", "fetch", "destructive"}:
            t.add_event(s, "label", label, now)
        t.add_event(s, "tool", tool, now)
        for h in f.hosts:
            t.add_event(s, "host", h, now)
        for name, detail, action in over:
            if action == "enforce":
                v.allowed, v.trip, v.rule = False, True, f"budget:{name}"
                v.reason = f"budget {name} exceeded: {detail}"
                return
            v.shadow.append(f"would trip: budget {name} ({detail})")

    def _repeat(self, t: Tx, s: str, tool: str, f: _Facts, now: float, v: _Verdict) -> None:
        r = self.policy.repeat
        if r.action == "off" or v.trip:
            return
        n = t.count(s, "repeat", f.repeat_key, now - r.window_s) + 1
        t.add_event(s, "repeat", f.repeat_key, now)
        if n > r.max:
            detail = f"same '{tool}' call {n} times in {r.window_s}s"
            if r.action == "enforce":
                v.allowed, v.trip, v.rule, v.reason = False, True, "repeat", f"runaway loop: {detail}"
            else:
                v.shadow.append(f"would trip: repeat ({detail})")

    def _tripped(self, tool: str, f: _Facts, prior: tuple) -> Decision:
        reason, rule, _ts = prior
        if (self.policy.mode == "degrade" and "read_only" in f.labels and not f.token and not f.protect
                and not f.remote_path):
            return Decision(True, f"fuse tripped ({rule}); degraded mode allows read-only '{tool}'", rule, True)
        return Decision(False, self._deny_text(reason, rule), rule, True)

    def _deny_text(self, reason: str, rule: str) -> str:
        if self.policy.mode == "pause":
            tail = "Paused for human review: an operator must inspect the trip and reset the fuse."
        elif self.policy.mode == "degrade":
            tail = "Degraded: only local read-only tools run until an operator resets the fuse."
        else:
            tail = "All tool calls are stopped until an operator resets the fuse."
        return f"bastionfuse TRIPPED ({rule}): {reason}. {tail}"

    def _signal(self) -> str | None:
        p = self.policy
        if p.kill_file is not None and p.kill_file.exists():
            return f"operator KILL file present ({p.kill_file})"
        if os.environ.get(p.kill_env, "").strip() not in ("", "0"):
            return f"operator kill env ${p.kill_env} is set"
        if p.heartbeat is not None:
            try:
                age = self.clock() - p.heartbeat.file.stat().st_mtime
            except OSError:
                return f"supervisor heartbeat file missing ({p.heartbeat.file})"
            if age > p.heartbeat.stale_s:
                return f"supervisor heartbeat stale ({int(age)}s > {p.heartbeat.stale_s}s)"
        return None

    # taint spool: record() falls back here when the store stays busy
    def _spool(self, session: str, source: str) -> None:
        spool_taint(self.policy, session, source)

    def _claim_spool(self) -> tuple[list[tuple[str, str]], list[Path]]:
        """Move the spool aside (atomic rename) and read every claimed spool file.
        Claimed files are deleted only after the taint commits (_release)."""
        d = self.policy.state_dir
        main = d / f"{SPOOL}.jsonl"
        if main.exists():
            try:
                os.replace(main, d / f"{SPOOL}.claim.{uuid.uuid4().hex}.jsonl")
            except OSError:
                pass
        out: list[tuple[str, str]] = []
        claimed: list[Path] = []
        try:
            claims = list(d.glob(f"{SPOOL}.claim.*.jsonl"))
        except OSError:
            claims = []
        for c in claims[:64]:
            try:
                for line in c.read_text(encoding="utf-8").splitlines()[:10_000]:
                    rec = json.loads(line)
                    if isinstance(rec, dict) and isinstance(rec.get("session"), str):
                        out.append((rec["session"][:256], str(rec.get("source", "spooled taint"))[:300]))
                claimed.append(c)
            except (OSError, ValueError):
                continue
        return out, claimed

    def _forensics(self, s: str, tool: str, text: str, verdict: str, now: float, *, want_ring: bool) -> list:
        """Ring write in its own transaction: evidence, never the guarantee."""
        try:
            with self.store.tx() as t:
                # slice first (with room for a token straddling the cut): redacting 1 MB is slow
                t.add_ring(s, tool, self.tokens.redact(text[:RING_ARGS_CAP + 1024])[:RING_ARGS_CAP], verdict, now)
                return t.ring(s) if want_ring else []
        except Exception:  # noqa: BLE001
            return []

    def _token_id(self, token: str | None) -> str:
        """Never echo a honeytoken back: the agent would learn which strings are decoys."""
        return "#" + hashlib.sha256((token or "").encode()).hexdigest()[:8]

    def _after_trip(self, session: str, decision: Decision, ring: list) -> None:
        if self.policy.snapshot:
            try:
                write_snapshot(self.policy, session, decision, ring, self.clock())
            except OSError:
                pass  # the trip already holds; the snapshot is evidence, not the guarantee
        if self.on_trip is not None:
            try:
                self.on_trip(session, decision)
            except Exception:  # noqa: BLE001 - a callback error never un-trips
                pass


def spool_taint(policy: FusePolicy, session: str, source: str) -> None:
    """Append a taint the store couldn't take; the next check() merges it."""
    path = policy.state_dir / f"{SPOOL}.jsonl"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"session": session, "source": source}) + "\n")


def _release(claims: list[Path]) -> None:
    for c in claims:
        try:
            c.unlink()
        except OSError:
            pass


def _string_values(value: Any, depth: int = 0) -> list[str]:
    if isinstance(value, str):
        return [value]
    if depth > 4:
        return []
    if isinstance(value, dict):
        return [s for v in value.values() for s in _string_values(v, depth + 1)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _string_values(v, depth + 1)]
    return []


def _flag_dict(flag: tuple | None) -> dict | None:
    if flag is None:
        return None
    reason, rule, ts = flag
    return {"reason": reason, "rule": rule, "ts": ts}


def write_snapshot(policy: FusePolicy, session: str, decision: Decision, ring: list, now: float) -> Path:
    """Write the session's recent calls as a bastiontrace v1 trace (evidence only:
    today's analyzer doesn't score fuse trips as landings). Keeps the newest
    MAX_TRIP_FILES snapshots."""
    sid = hashlib.sha256(session.encode()).hexdigest()[:10]
    out_dir = policy.state_dir / "trips"
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = out_dir / f"{int(now)}-{sid}.jsonl"
    header = {
        "type": "trace", "v": 1, "trace_id": f"fuse-{sid}-{int(now)}", "source": "bastionfuse",
        "policy": {"forbidden_tools": sorted(policy.canary_tools)},
        "fuse": {"rule": decision.rule, "reason": decision.reason, "session_sha256": sid,
                 "honeytoken_sha256": [hashlib.sha256(t.encode()).hexdigest()[:12] for t in policy.honeytokens]},
    }
    lines = [json.dumps(header)]
    for seq, (tool, args, verdict, ts) in enumerate(ring):
        try:
            parsed = json.loads(args)
        except ValueError:
            parsed = None
        event = {"type": "tool_call", "seq": seq, "tool": tool, "args_from": None, "verdict": verdict, "ts": ts}
        event["args"] = parsed if isinstance(parsed, dict) else {"raw": args}
        lines.append(json.dumps(event))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    old = sorted(out_dir.glob("*.jsonl"))[:-MAX_TRIP_FILES]
    for f in old:
        try:
            f.unlink()
        except OSError:
            pass
    return path
