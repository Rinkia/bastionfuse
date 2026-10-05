"""The fuse: check a tool call before it runs, record its result after.

Order inside check() (first hit wins; cheap and certain first):

  1  operator signals: KILL file, kill env, stale heartbeat  -> trip (global)
  2  already tripped                                          -> deny (degrade: read-only passes)
  3  canary tool                                              -> trip
  4  honeytoken (raw/hex/url/base64) in the input             -> trip
  5  decoy path in the input                                  -> taint session
  6  self-protect: touches the fuse, its policy or settings   -> deny, no trip
  7  classify: egress | fetch | destructive | read_only
  8  tainted session + egress                                 -> trip
  9  budgets (operator-written enforce, defaults shadow)      -> trip / log
 10  repeat detector                                          -> shadow by default
 11  allow

A trip is sticky: it holds until an operator resets it. Any internal error makes
check() deny (fail closed).
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .policy import FusePolicy
from .rules import Oversize, PathMatcher, TokenMatcher, classify, flatten, hosts_of, self_protect_hit
from .state import GLOBAL, Store, StoreBusy, StoreCorrupt, Tx

RING_ARGS_CAP = 4096  # bytes of args kept per call in the forensic ring


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
        decoy); a later egress call then trips. Returns the taint source, if any."""
        s = session or self.session
        try:
            text = flatten(result)
            hit = self.tokens.find(text)
            source = f"honeytoken {self._token_id(hit)} in a {tool} result" if hit else None
        except Oversize:
            source = f"{tool} result too large to scan"  # fail closed: treat as tainted
        if source:
            with self.store.tx() as t:
                t.set_taint(s, source, self.clock())
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

    def _check(self, s: str, tool: str, tool_input: Any, cwd: str | None) -> Decision:
        try:
            text = flatten(tool_input)
        except Oversize as e:
            return Decision(False, f"tool input too large to scan ({e}); refused", "oversize")
        now = self.clock()
        signal = self._signal()
        with self.store.tx() as t:
            if signal:
                t.set_flag(GLOBAL, signal, "signal", now)
            prior = t.flag(GLOBAL) or t.flag(s)
            if prior:
                d = self._tripped(tool, tool_input, text, prior, cwd)
                t.add_ring(s, tool, self._ring_args(text), "allowed" if d.allowed else "blocked", now)
                return d
            v = self._evaluate(t, s, tool, tool_input, text, cwd, now)
            t.add_ring(s, tool, self._ring_args(text), "tripped" if v.trip else
                       ("allowed" if v.allowed else "blocked"), now)
            if v.trip:
                t.set_flag(s, v.reason, v.rule, now)
            t.prune(s, now)
            ring = t.ring(s) if v.trip else []
        d = Decision(v.allowed and not v.trip, self._deny_text(v.reason, v.rule) if v.trip else v.reason,
                     v.rule, v.trip, tuple(v.shadow))
        if v.trip:
            self._after_trip(s, d, ring)
        return d

    def _evaluate(self, t: Tx, s: str, tool: str, tool_input: Any, text: str, cwd: str | None,
                  now: float) -> _Verdict:
        p = self.policy
        if p.is_canary(tool):
            return _Verdict(False, f"called canary tool '{tool}' (no legitimate flow uses it)", "canary", True)
        hit = self.tokens.find(text)
        if hit:
            return _Verdict(False, f"honeytoken {self._token_id(hit)} in the input of '{tool}'", "honeytoken", True)
        decoy = self.decoys.find(text)
        if decoy:
            t.set_taint(s, f"decoy path {decoy} touched by {tool}", now)
        why = self_protect_hit(text, p, cwd)
        if why:
            return _Verdict(False, f"bastionfuse blocked '{tool}': it {why}", "self-protect")
        labels = classify(tool, tool_input, p)
        taint = t.taint(s)
        if taint and "egress" in labels:
            return _Verdict(False, f"egress via '{tool}' after the session touched a decoy ({taint})",
                            "taint-egress", True)
        v = _Verdict()
        self._budgets(t, s, tool, labels, text, now, v)
        self._repeat(t, s, tool, text, now, v)
        return v

    def _budgets(self, t: Tx, s: str, tool: str, labels: set[str], text: str, now: float, v: _Verdict) -> None:
        p, b = self.policy, self.policy.budgets
        over: list[tuple[str, str, str]] = []  # (name, detail, action)

        def check_count(name: str, kind: str, key: str | None, budget) -> None:
            if budget is not None and t.count(s, kind, key, now - budget.window_s) + 1 > budget.max:
                over.append((name, f"more than {budget.max} in {budget.window_s}s", budget.action))

        check_count("calls", "call", None, b.get("calls"))
        for label in ("egress", "fetch", "destructive"):
            if label in labels:
                check_count(label, "label", label, b.get(label))
        check_count(f"tool {tool}", "tool", tool, p.tool_budgets.get(tool))
        hosts = hosts_of(text) if "egress" in labels else set()
        if "egress" in labels:
            hb, bb = b.get("egress_hosts"), b.get("bytes_out")
            if hb is not None:
                seen = t.distinct(s, "host", now - hb.window_s) | hosts
                if len(seen) > hb.max:
                    over.append(("egress_hosts", f"{len(seen)} distinct hosts in {hb.window_s}s (max {hb.max})",
                                 hb.action))
            size = len(text.encode("utf-8", "surrogatepass"))
            if bb is not None and t.total(s, "bytes", now - bb.window_s) + size > bb.max:
                over.append(("bytes_out", f"more than {bb.max} bytes out in {bb.window_s}s", bb.action))
            t.add_event(s, "bytes", "*", now, size)
        t.add_event(s, "call", "*", now)
        for label in labels & {"egress", "fetch", "destructive"}:
            t.add_event(s, "label", label, now)
        t.add_event(s, "tool", tool, now)
        for h in hosts:
            t.add_event(s, "host", h, now)
        for name, detail, action in over:
            if action == "enforce":
                v.allowed, v.trip, v.rule = False, True, f"budget:{name}"
                v.reason = f"budget {name} exceeded: {detail}"
                return
            v.shadow.append(f"would trip: budget {name} ({detail})")

    def _repeat(self, t: Tx, s: str, tool: str, text: str, now: float, v: _Verdict) -> None:
        r = self.policy.repeat
        if r.action == "off" or v.trip:
            return
        key = hashlib.sha256(f"{tool}\0{text}".encode("utf-8", "surrogatepass")).hexdigest()[:16]
        n = t.count(s, "repeat", key, now - r.window_s) + 1
        t.add_event(s, "repeat", key, now)
        if n > r.max:
            detail = f"same '{tool}' call {n} times in {r.window_s}s"
            if r.action == "enforce":
                v.allowed, v.trip, v.rule, v.reason = False, True, "repeat", f"runaway loop: {detail}"
            else:
                v.shadow.append(f"would trip: repeat ({detail})")

    def _tripped(self, tool: str, tool_input: Any, text: str, prior: tuple, cwd: str | None) -> Decision:
        reason, rule, _ts = prior
        if (self.policy.mode == "degrade" and "read_only" in classify(tool, tool_input, self.policy)
                and not self.tokens.find(text) and not self_protect_hit(text, self.policy, cwd)):
            return Decision(True, f"fuse tripped ({rule}); degraded mode allows read-only '{tool}'", rule, True)
        return Decision(False, self._deny_text(reason, rule), rule, True)

    def _deny_text(self, reason: str, rule: str) -> str:
        if self.policy.mode == "pause":
            tail = "Paused for human review: an operator must inspect the trip and reset the fuse."
        elif self.policy.mode == "degrade":
            tail = "Degraded: only read-only tools run until an operator resets the fuse."
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

    def _token_id(self, token: str | None) -> str:
        """Never echo a honeytoken back: the agent would learn which strings are decoys."""
        return "#" + hashlib.sha256((token or "").encode()).hexdigest()[:8]

    def _ring_args(self, text: str) -> str:
        return self.tokens.redact(text)[:RING_ARGS_CAP]

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


def _flag_dict(flag: tuple | None) -> dict | None:
    if flag is None:
        return None
    reason, rule, ts = flag
    return {"reason": reason, "rule": rule, "ts": ts}


def write_snapshot(policy: FusePolicy, session: str, decision: Decision, ring: list, now: float) -> Path:
    """Write the session's recent calls as a bastiontrace v1 trace (evidence only:
    today's analyzer doesn't score fuse trips as landings)."""
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
    return path
