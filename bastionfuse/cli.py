"""bastionfuse command line.

    bastionfuse hook pre|post          Claude Code hook (reads the hook JSON on stdin)
    bastionfuse install-hook           print the settings.json block that registers the hook
    bastionfuse status [--session S]   trip state, taint, operator signals
    bastionfuse kill                   operator stop: create the KILL file (every session)
    bastionfuse trip --reason R        trip one session (or --global)
    bastionfuse reset [--session S | --global]
    bastionfuse plant --dir D          write decoy files holding fresh honeytokens
    bastionfuse tokens new             print a fresh honeytoken
    bastionfuse decoy-mcp              run the decoy MCP server (stdio)
    bastionfuse log [--summary]        trips, blocks and shadow notes (the dogfood tally)
    bastionfuse demo                   assume-breach demo, no API key
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys
from pathlib import Path

from . import __version__
from .fuse import Fuse
from .hook import main_hook, resolve_policy, settings_snippet
from .policy import MAX_TOKENS, PolicyError, default_state_dir
from .rules import new_token

TOKEN_KINDS = ("aws", "github", "openai", "generic")
TOKENS_PER_PLANT = 3


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.home:  # the flag wins over the environment (the agent's project can set env vars)
        os.environ["BASTIONFUSE_HOME"] = str(Path(args.home).expanduser())
    if args.cmd is None:
        parser.print_help()
        return 0
    if args.cmd == "hook":
        return main_hook(args.event, args.policy, home_pinned=args.home is not None)
    if args.cmd == "decoy-mcp":
        from .decoy_mcp import main as decoy_main
        return decoy_main()
    if args.cmd == "demo":
        from .demo import run
        outcomes = run(sys.stdout)
        return 0 if all(o.stopped_at for o in outcomes) else 1
    if args.cmd == "install-hook":
        home = str(default_state_dir().resolve())
        print(json.dumps(settings_snippet(args.command, home), indent=2))
        print("\nAdd this block to ~/.claude/settings.json (better: a managed settings file the agent can't "
              f"edit).\nDecoy tools: claude mcp add bastionfuse-decoy -- {args.command} --home \"{home}\" decoy-mcp",
              file=sys.stderr)
        return 0
    if args.cmd == "tokens":
        print(new_token(args.kind))
        return 0
    try:
        policy = resolve_policy(args.policy)
    except PolicyError as e:
        print(f"bastionfuse: {e}", file=sys.stderr)
        return 2
    return _COMMANDS[args.cmd](args, policy)


def _status(args, policy) -> int:
    print(json.dumps(Fuse(policy).status(session=args.session), indent=2))
    return 0


def _kill(args, policy) -> int:
    policy.kill_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    policy.kill_file.write_text(args.reason + "\n", encoding="utf-8")
    print(f"KILL file written: {policy.kill_file}. Every guarded session stops at its next tool call.")
    return 0


def _trip(args, policy) -> int:
    Fuse(policy).trip(args.reason, session=args.session, global_=args.global_)
    print("tripped " + ("GLOBAL" if args.global_ else f"session {args.session}"))
    return 0


def _reset(args, policy) -> int:
    fuse = Fuse(policy)
    if args.global_:
        if policy.kill_file is not None and policy.kill_file.exists():
            policy.kill_file.unlink()
            print(f"removed KILL file {policy.kill_file}")
        cleared = fuse.reset(global_=True)
    else:
        cleared = fuse.reset(session=args.session)
    print("reset done" if cleared else "nothing was tripped (state cleared anyway)")
    return 0


def _plant(args, policy) -> int:
    """Write a decoy .env file per --dir and register its tokens and path."""
    tokens_file = policy.state_dir / "honeytokens.txt"
    decoys_file = policy.state_dir / "decoys.txt"
    room = (MAX_TOKENS - len(policy.honeytokens)) // TOKENS_PER_PLANT
    if len(args.dir) > room:  # past the cap every hook call would fail to load the policy
        print(f"bastionfuse: refusing to plant {len(args.dir)} decoy(s): only room for {room} more "
              f"(at most {MAX_TOKENS} honeytokens, {len(policy.honeytokens)} registered)", file=sys.stderr)
        return 2
    policy.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    for d in args.dir:
        target = Path(d).expanduser() / args.name
        if target.exists():
            print(f"skip {target}: already exists (never overwrite a real file)", file=sys.stderr)
            continue
        aws, gh, generic = new_token("aws"), new_token("github"), new_token("generic")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            "# production credentials - do not commit\n"
            f"AWS_ACCESS_KEY_ID={aws}\nGITHUB_TOKEN={gh}\nDATABASE_PASSWORD={generic}\n", encoding="utf-8")
        with tokens_file.open("a", encoding="utf-8") as fh:
            fh.write(f"{aws}\n{gh}\n{generic}\n")
        with decoys_file.open("a", encoding="utf-8") as fh:
            fh.write(f"{target.resolve()}\n")
        print(f"planted {target}")
    return 0


def _log(args, policy) -> int:
    path = policy.state_dir / "log.jsonl"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        print("no log yet")
        return 0
    records = []
    for ln in lines:
        try:
            rec = json.loads(ln)
        except ValueError:
            continue  # a damaged line never hides the rest of the tally
        if isinstance(rec, dict):
            records.append(rec)
    if not args.summary:
        for r in records[-args.tail:]:
            print(json.dumps(r))
        return 0
    trips = collections.Counter(str(r.get("rule")) for r in records if r.get("tripped") and not r.get("allowed"))
    shadow = collections.Counter(str(n).split("(")[0].strip() for r in records for n in r.get("shadow") or [])
    sessions = {str(r.get("session")) for r in records}
    print(json.dumps({"records": len(records), "sessions": len(sessions), "trips_by_rule": trips,
                      "shadow_notes": shadow, "taints": sum(1 for r in records if r.get("taint"))}, indent=2))
    return 0


_COMMANDS = {"status": _status, "kill": _kill, "trip": _trip, "reset": _reset, "plant": _plant, "log": _log}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bastionfuse", description="Kill switch and tripwires for AI agents.")
    p.add_argument("--version", action="version", version=f"bastionfuse {__version__}")
    p.add_argument("--policy", help="policy file (default: $BASTIONFUSE_POLICY, then <state_dir>/fuse.yaml)")
    p.add_argument("--home", help="state dir (default: $BASTIONFUSE_HOME, then ~/.bastionfuse)")
    sub = p.add_subparsers(dest="cmd")
    h = sub.add_parser("hook", help="Claude Code hook entry point")
    h.add_argument("event", choices=("pre", "post"))
    ih = sub.add_parser("install-hook", help="print the Claude Code settings block")
    ih.add_argument("--command", default="bastionfuse", help="command Claude Code runs (default: bastionfuse)")
    st = sub.add_parser("status", help="show trip state")
    st.add_argument("--session", default="default")
    k = sub.add_parser("kill", help="operator stop for every session (KILL file)")
    k.add_argument("--reason", default="operator kill")
    t = sub.add_parser("trip", help="trip a session or every session")
    t.add_argument("--reason", required=True)
    t.add_argument("--session", default="default")
    t.add_argument("--global", dest="global_", action="store_true")
    r = sub.add_parser("reset", help="operator reset")
    r.add_argument("--session", default="default")
    r.add_argument("--global", dest="global_", action="store_true", help="clear the global trip and KILL file")
    pl = sub.add_parser("plant", help="write decoy secret files")
    pl.add_argument("--dir", action="append", required=True, help="directory to plant a decoy in (repeatable)")
    pl.add_argument("--name", default=".env.backup")
    tk = sub.add_parser("tokens", help="honeytoken tools")
    tk.add_argument("action", choices=("new",))
    tk.add_argument("--kind", choices=TOKEN_KINDS, default="aws")
    sub.add_parser("decoy-mcp", help="run the decoy MCP server on stdio")
    lg = sub.add_parser("log", help="show the trip/shadow log")
    lg.add_argument("--summary", action="store_true")
    lg.add_argument("--tail", type=int, default=20)
    sub.add_parser("demo", help="assume-breach demo")
    return p


if __name__ == "__main__":
    sys.exit(main())
