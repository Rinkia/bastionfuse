"""Load and strictly validate a fuse policy.

A fuse policy is a `policy_version: 2` file whose `fuse:` block holds every knob.
The fuse reads only its own block and ignores the other tools' blocks, so the same
block can later move into the suite's shared policy.yaml unchanged.

    policy_version: 2
    fuse:
      mode: kill                      # kill | degrade | pause
      honeytokens: [AKIAFUSE7Q2X9EXAMPLE]
      canary_tools: [export_all_secrets]
      budgets:
        egress: {max: 20, window_s: 600}

Strict: unknown keys and bad values are errors (a kill switch must never look
configured when it is not). Budgets the operator writes enforce; the built-in
default budgets only log (`shadow`) until an operator writes them.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MODES = ("kill", "degrade", "pause")
ACTIONS = ("off", "shadow", "enforce")
LABELS = ("egress", "fetch", "destructive", "read_only")
BUDGET_LABELS = ("calls", "egress", "fetch", "destructive", "egress_hosts", "bytes_out")
DECOY_TOOL_PREFIX = "mcp__bastionfuse-decoy__"

MIN_TOKEN_LEN = 12  # shorter tokens collide with ordinary text
MAX_TOKEN_LEN = 256
MAX_TOKENS = 256
MAX_LIST = 256
MAX_WINDOW_S = 86400

_V2_CORE = frozenset({"policy_version", "default", "allow", "deny", "rate_limits", "detectors"})
_V2_BLOCKS = frozenset({"gate", "bastion", "supply", "skill", "fuse"})
_FUSE_KEYS = frozenset({
    "mode", "honeytokens", "honeytokens_env", "decoy_paths", "canary_tools", "labels",
    "shell_tools", "commands", "budgets", "repeat", "kill_file", "kill_env", "heartbeat",
    "self_protect", "operator_paths", "state_dir", "snapshot",
})

# Claude Code built-in tools. Shell tools are classified by their command text.
DEFAULT_LABELS: dict[str, frozenset[str]] = {
    "egress": frozenset({"WebFetch"}),
    "fetch": frozenset({"WebSearch"}),
    "destructive": frozenset(),
    "read_only": frozenset({"Read", "Glob", "Grep", "LS", "NotebookRead"}),
}
DEFAULT_SHELL_TOOLS = ("Bash", "PowerShell")
# A command entry matches when its first word is the command and every later word
# appears among that command's arguments (a short flag like -r also matches inside
# a cluster such as -rf). See rules.classify.
DEFAULT_COMMANDS: dict[str, tuple[str, ...]] = {
    "egress": (
        "curl", "wget", "nc", "ncat", "netcat", "telnet", "socat", "ftp", "tftp", "scp",
        "sftp", "ssh", "rsync", "invoke-webrequest", "iwr", "invoke-restmethod", "irm",
        "git push", "npm publish", "twine upload", "gh gist create", "gh release upload",
    ),
    "fetch": (
        "pip install", "pip download", "uv pip", "uv add", "npm install", "npm i", "npm ci",
        "yarn add", "pnpm add", "git fetch", "git pull", "git clone", "cargo add", "go get",
    ),
    "destructive": (
        "rm -r", "rm -R", "rmdir", "rd", "del", "remove-item", "shred", "mkfs", "dd",
        "git reset --hard", "git clean -f", "git push --force", "git push -f",
        "git branch -D", "drop table", "truncate",
    ),
    "read_only": (),
}
DEFAULT_BUDGETS: dict[str, tuple[int, int]] = {  # shadow until the operator writes them
    "calls": (2000, 3600),
    "egress": (60, 600),
    "destructive": (30, 600),
    "egress_hosts": (20, 3600),
    "bytes_out": (1_048_576, 3600),
}


class PolicyError(ValueError):
    """A policy that must not load. Raised instead of ignoring a line."""


@dataclass(frozen=True)
class Budget:
    max: int
    window_s: int
    action: str = "enforce"  # enforce (operator-written) | shadow (built-in default)


@dataclass(frozen=True)
class Heartbeat:
    file: Path
    stale_s: int


@dataclass(frozen=True)
class FusePolicy:
    mode: str = "kill"
    honeytokens: tuple[str, ...] = ()
    decoy_paths: tuple[str, ...] = ()
    canary_tools: frozenset[str] = frozenset()
    labels: dict[str, frozenset[str]] = field(default_factory=lambda: dict(DEFAULT_LABELS))
    shell_tools: frozenset[str] = frozenset(DEFAULT_SHELL_TOOLS)
    commands: dict[str, tuple[str, ...]] = field(default_factory=lambda: dict(DEFAULT_COMMANDS))
    budgets: dict[str, Budget] = field(default_factory=dict)
    tool_budgets: dict[str, Budget] = field(default_factory=dict)
    repeat: Budget = Budget(20, 60, "shadow")
    kill_file: Path | None = None
    kill_env: str = "BASTIONFUSE_KILL"
    heartbeat: Heartbeat | None = None
    self_protect: bool = True
    operator_paths: tuple[Path, ...] = ()
    state_dir: Path = Path("~/.bastionfuse").expanduser()
    snapshot: bool = True
    source: Path | None = None  # the policy file, protected by self-protect

    def is_canary(self, tool: str) -> bool:
        return tool in self.canary_tools or tool.startswith(DECOY_TOOL_PREFIX)


def default_state_dir() -> Path:
    return Path(os.environ.get("BASTIONFUSE_HOME") or "~/.bastionfuse").expanduser()


# --- loading -----------------------------------------------------------------

def load_policy(path: str | os.PathLike, *, cache: bool = True) -> FusePolicy:
    """Load a policy file (.json, or YAML with the `yaml` extra).

    With `cache`, the parsed mapping is cached as JSON under the state dir, keyed by
    the file's sha256, so a hook process skips importing pyyaml on every tool call."""
    path = Path(path).expanduser().resolve()
    try:
        data = path.read_bytes()
    except OSError as e:
        raise PolicyError(f"cannot read policy {path}: {e}") from e
    digest = hashlib.sha256(data).hexdigest()
    cache_file = default_state_dir() / "policy-cache.json"
    raw = _cached(cache_file, path, digest) if cache else None
    if raw is None:
        raw = _parse(path, data)
        if cache:
            _store_cache(cache_file, path, digest, raw)
    return policy_from_dict(raw, source=path)


def _parse(path: Path, data: bytes) -> Any:
    text = data.decode("utf-8-sig")
    if path.suffix.lower() == ".json":
        try:
            return json.loads(text)
        except ValueError as e:
            raise PolicyError(f"{path}: invalid JSON: {e}") from e
    try:
        import yaml
    except ImportError as e:
        raise PolicyError(
            f"{path} is YAML; install the extra (pip install \"bastionfuse[yaml]\") "
            "or write the policy as .json"
        ) from e
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise PolicyError(f"{path}: invalid YAML: {e}") from e


def _cached(cache_file: Path, path: Path, digest: str) -> Any:
    try:
        entry = json.loads(cache_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if isinstance(entry, dict) and entry.get("path") == str(path) and entry.get("sha256") == digest:
        return entry.get("raw")
    return None


def _store_cache(cache_file: Path, path: Path, digest: str, raw: Any) -> None:
    """Best effort: a cache that can't be written only costs speed."""
    try:
        cache_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = cache_file.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps({"path": str(path), "sha256": digest, "raw": raw}), encoding="utf-8")
        os.replace(tmp, cache_file)
    except (OSError, TypeError, ValueError):
        pass


def policy_from_dict(obj: Any, *, source: Path | None = None) -> FusePolicy:
    if not isinstance(obj, dict):
        raise PolicyError("policy must be a mapping")
    version = obj.get("policy_version")
    if isinstance(version, bool) or version != 2:
        raise PolicyError(f"`policy_version: 2` is required at the top, got {version!r}")
    unknown = set(obj) - _V2_CORE - _V2_BLOCKS
    if unknown:
        misplaced = sorted(unknown & _FUSE_KEYS)
        if misplaced:
            raise PolicyError(f"fuse knobs live under `fuse:`; move {misplaced} there")
        raise PolicyError(f"unknown top-level key(s) {sorted(unknown)}; allowed: {sorted(_V2_CORE | _V2_BLOCKS)}")
    block = obj.get("fuse")
    if block is None:
        raise PolicyError("a `fuse:` block is required")
    if not isinstance(block, dict):
        raise PolicyError("`fuse:` must be a mapping")
    stray = set(block) - _FUSE_KEYS
    if stray:
        raise PolicyError(f"unknown key(s) in `fuse:` {sorted(stray)}; allowed: {sorted(_FUSE_KEYS)}")
    return _build(block, source)


def _build(b: dict, source: Path | None) -> FusePolicy:
    state_dir = _path(b.get("state_dir"), "state_dir") if "state_dir" in b else default_state_dir()
    mode = _choice(b.get("mode", "kill"), MODES, "mode")
    env_name = _str(b.get("honeytokens_env", "BASTIONFUSE_HONEYTOKENS"), "honeytokens_env")
    tokens = _tokens(_str_list(b.get("honeytokens", []), "honeytokens"), "honeytokens")
    env_tokens = [t.strip() for t in os.environ.get(env_name, "").split(",") if t.strip()]
    tokens += _tokens(env_tokens, f"${env_name}")
    planted_tokens, planted_decoys = _planted(state_dir)
    tokens = _dedupe(tokens + planted_tokens)
    if len(tokens) > MAX_TOKENS:
        raise PolicyError(f"at most {MAX_TOKENS} honeytokens, got {len(tokens)}")
    decoys = _dedupe(_str_list(b.get("decoy_paths", []), "decoy_paths") + planted_decoys)
    labels = _labels(b.get("labels"))
    canary = frozenset(_str_list(b.get("canary_tools", []), "canary_tools"))
    overlap = canary & labels["read_only"]
    if overlap:
        raise PolicyError(f"canary tool(s) {sorted(overlap)} cannot also be read_only")
    budgets, tool_budgets = _budgets(b.get("budgets"))
    hb = b.get("heartbeat")
    return FusePolicy(
        mode=mode,
        honeytokens=tuple(tokens),
        decoy_paths=tuple(decoys),
        canary_tools=canary,
        labels=labels,
        shell_tools=frozenset(_str_list(b.get("shell_tools", list(DEFAULT_SHELL_TOOLS)), "shell_tools")),
        commands=_commands(b.get("commands")),
        budgets=budgets,
        tool_budgets=tool_budgets,
        repeat=_repeat(b.get("repeat")),
        kill_file=_path(b["kill_file"], "kill_file") if "kill_file" in b else state_dir / "KILL",
        kill_env=_str(b.get("kill_env", "BASTIONFUSE_KILL"), "kill_env"),
        heartbeat=_heartbeat(hb) if hb is not None else None,
        self_protect=_bool(b.get("self_protect", True), "self_protect"),
        operator_paths=tuple(_path(p, "operator_paths") for p in _str_list(b.get("operator_paths", []),
                                                                            "operator_paths")),
        state_dir=state_dir,
        snapshot=_bool(b.get("snapshot", True), "snapshot"),
        source=source,
    )


def _planted(state_dir: Path) -> tuple[list[str], list[str]]:
    """Tokens and decoy paths written by `bastionfuse plant` (one per line)."""
    out = []
    for name in ("honeytokens.txt", "decoys.txt"):
        try:
            lines = (state_dir / name).read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        out.append([ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")])
    return _tokens(out[0], str(state_dir / "honeytokens.txt")), out[1]


# --- validators --------------------------------------------------------------

def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _str(v: Any, where: str) -> str:
    if not isinstance(v, str) or not v:
        raise PolicyError(f"`fuse.{where}` must be a non-empty string, got {v!r}")
    return v


def _bool(v: Any, where: str) -> bool:
    if not isinstance(v, bool):
        raise PolicyError(f"`fuse.{where}` must be true or false, got {v!r}")
    return v


def _choice(v: Any, allowed: tuple[str, ...], where: str) -> str:
    if v not in allowed:
        raise PolicyError(f"`fuse.{where}`: {v!r} is not one of {' | '.join(allowed)}")
    return v


def _int(v: Any, where: str, lo: int, hi: int) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise PolicyError(f"`fuse.{where}` must be an integer in {lo}..{hi}, got {v!r}")
    return v


def _str_list(v: Any, where: str) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise PolicyError(f"`fuse.{where}` must be a list of non-empty strings, got {v!r}")
    if len(v) > MAX_LIST:
        raise PolicyError(f"`fuse.{where}` has {len(v)} entries; at most {MAX_LIST}")
    return list(v)


def _path(v: Any, where: str) -> Path:
    return Path(_str(v, where)).expanduser()


def _tokens(tokens: list[str], where: str) -> list[str]:
    for t in tokens:
        if not MIN_TOKEN_LEN <= len(t) <= MAX_TOKEN_LEN or any(c.isspace() for c in t):
            raise PolicyError(
                f"honeytoken from {where} must be {MIN_TOKEN_LEN}-{MAX_TOKEN_LEN} characters with no "
                f"whitespace (short tokens match ordinary text); got one of length {len(t)}"
            )
    return list(tokens)


def _labels(v: Any) -> dict[str, frozenset[str]]:
    if v is None:
        return dict(DEFAULT_LABELS)
    if not isinstance(v, dict) or set(v) - set(LABELS):
        raise PolicyError(f"`fuse.labels` must map {' | '.join(LABELS)} to tool-name lists, got {v!r}")
    out = {k: frozenset(_str_list(v[k], f"labels.{k}")) if k in v else DEFAULT_LABELS[k] for k in LABELS}
    for other in ("egress", "fetch", "destructive"):
        both = out["read_only"] & out[other]
        if both:
            raise PolicyError(f"tool(s) {sorted(both)} cannot be both read_only and {other}")
    return out


def _commands(v: Any) -> dict[str, tuple[str, ...]]:
    if v is None:
        return dict(DEFAULT_COMMANDS)
    if not isinstance(v, dict) or set(v) - set(LABELS):
        raise PolicyError(f"`fuse.commands` must map {' | '.join(LABELS)} to command lists, got {v!r}")
    return {k: tuple(_str_list(v[k], f"commands.{k}")) if k in v else DEFAULT_COMMANDS[k] for k in LABELS}


def _budget(v: Any, where: str) -> Budget:
    if not isinstance(v, dict) or set(v) != {"max", "window_s"}:
        raise PolicyError(f"`fuse.{where}` must be {{max: N, window_s: S}}, got {v!r}")
    return Budget(_int(v["max"], f"{where}.max", 1, 10**12),
                  _int(v["window_s"], f"{where}.window_s", 1, MAX_WINDOW_S))


def _budgets(v: Any) -> tuple[dict[str, Budget], dict[str, Budget]]:
    budgets = {k: Budget(m, w, "shadow") for k, (m, w) in DEFAULT_BUDGETS.items()}
    if v is None:
        return budgets, {}
    if not isinstance(v, dict) or set(v) - set(BUDGET_LABELS) - {"tools"}:
        raise PolicyError(f"`fuse.budgets` keys must be among {sorted(BUDGET_LABELS) + ['tools']}, got {v!r}")
    for k in BUDGET_LABELS:
        if k in v:
            budgets[k] = _budget(v[k], f"budgets.{k}")
    tools = v.get("tools", {})
    if not isinstance(tools, dict):
        raise PolicyError("`fuse.budgets.tools` must map tool names to {max, window_s}")
    return budgets, {t: _budget(b, f"budgets.tools.{t}") for t, b in tools.items()}


def _repeat(v: Any) -> Budget:
    if v is None:
        return Budget(20, 60, "shadow")
    if not isinstance(v, dict) or not {"max", "window_s"} <= set(v) <= {"max", "window_s", "action"}:
        raise PolicyError(f"`fuse.repeat` must be {{max, window_s, action}}, got {v!r}")
    return Budget(_int(v["max"], "repeat.max", 2, 10**6), _int(v["window_s"], "repeat.window_s", 1, MAX_WINDOW_S),
                  _choice(v.get("action", "shadow"), ACTIONS, "repeat.action"))


def _heartbeat(v: Any) -> Heartbeat:
    if not isinstance(v, dict) or set(v) != {"file", "stale_s"}:
        raise PolicyError(f"`fuse.heartbeat` must be {{file, stale_s}}, got {v!r}")
    return Heartbeat(_path(v["file"], "heartbeat.file"), _int(v["stale_s"], "heartbeat.stale_s", 1, MAX_WINDOW_S))
