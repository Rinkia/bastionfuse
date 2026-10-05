"""Pure rule logic: honeytoken matching, decoy paths, tool classification,
self-protection and token generation. No I/O, no state (state.py and fuse.py own
those), so every rule is testable on its own.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import string
import unicodedata
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .policy import FusePolicy

MAX_INPUT_BYTES = 1_048_576  # larger inputs are refused (oversize), never partially scanned


class Oversize(ValueError):
    """Tool input or result too large to scan; the caller fails closed."""


def flatten(value: Any) -> str:
    """Tool input/result as one string. JSON when possible, repr otherwise, so a
    value that isn't JSON-serializable is still scanned."""
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, default=repr)
        except (TypeError, ValueError):
            text = repr(value)
    if len(text.encode("utf-8", "surrogatepass")) > MAX_INPUT_BYTES:
        raise Oversize(f"input over {MAX_INPUT_BYTES} bytes")
    return text


def fold(text: str) -> str:
    """NFKC, strip format characters (zero-width joiners, BOMs), casefold."""
    text = unicodedata.normalize("NFKC", text)
    return "".join(c for c in text if unicodedata.category(c) != "Cf").casefold()


def _strip_cf(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    return "".join(c for c in text if unicodedata.category(c) != "Cf")


def _b64_forms(token: bytes) -> set[str]:
    """The base64 substrings a token produces at each of the 3 byte alignments.
    Only characters fully determined by the token are kept, so the form matches
    wherever the token sits inside a larger base64 blob."""
    forms = set()
    n = len(token)
    for k in range(3):
        enc = base64.b64encode(b"\0" * k + token).decode()
        start = -(-8 * k // 6)  # ceil
        end = (8 * (k + n)) // 6
        forms.add(enc[start:end])
        enc_url = base64.urlsafe_b64encode(b"\0" * k + token).decode()
        forms.add(enc_url[start:end])
    return forms


@dataclass(frozen=True)
class TokenMatcher:
    """Precomputed forms of every honeytoken: raw (folded), hex, URL-encoded and
    base64 at three alignments. Matching is plain substring search (linear)."""

    tokens: tuple[str, ...]

    @cached_property
    def _folded(self) -> dict[str, str]:
        out = {}
        for t in self.tokens:
            raw = t.encode()
            for form in (t, raw.hex(), quote(t, safe="")):
                out[fold(form)] = t
        return out

    @cached_property
    def _exact(self) -> dict[str, str]:  # base64 is case-sensitive
        return {f: t for t in self.tokens for f in _b64_forms(t.encode())}

    def find(self, text: str) -> str | None:
        """The honeytoken present in `text` (any supported encoding), or None."""
        if not self.tokens or not text:
            return None
        folded = fold(text)
        for form, tok in self._folded.items():
            if form in folded:
                return tok
        plain = _strip_cf(text)
        for form, tok in self._exact.items():
            if form in plain:
                return tok
        return None

    def redact(self, text: str) -> str:
        for t in self.tokens:
            text = text.replace(t, "[HONEYTOKEN]")
        return text


# --- paths -------------------------------------------------------------------

def _path_forms(p: str | Path) -> set[str]:
    """Spellings of a path an agent might use: as written, expanded, both slash
    styles, plus `~/...`. Folded for case-insensitive comparison."""
    raw = str(p)
    expanded = str(Path(raw).expanduser())
    forms = {raw, expanded}
    home = str(Path.home())
    if expanded.startswith(home):
        forms.add("~" + expanded[len(home):])
    out = set()
    for f in forms:
        for v in (f, f.replace("\\", "/"), f.replace("/", "\\")):
            if len(v) >= 4:  # never match on tiny fragments
                out.add(fold(v))
    return out


@dataclass(frozen=True)
class PathMatcher:
    paths: tuple[str, ...]

    @cached_property
    def _forms(self) -> dict[str, str]:
        return {f: p for p in self.paths for f in _path_forms(p)}

    def find(self, text: str) -> str | None:
        folded = fold(text).replace("\\\\", "\\")  # JSON doubles backslashes
        for form, p in self._forms.items():
            if form in folded:
                return p
        return None


# --- classification ----------------------------------------------------------

_SPLIT = re.compile(r"\|\||&&|[;|&\n`()]|\$\(")
_URL_HOST = re.compile(r"https?://([^/\s'\"<>\\]+)", re.IGNORECASE)
_SSH_HOST = re.compile(r"(?:^|\s)(?:[\w.-]+@)?([A-Za-z0-9][\w.-]*\.[A-Za-z]{2,}):", re.ASCII)


def _words(segment: str) -> list[str]:
    return [w.strip("'\"") for w in segment.split() if w.strip("'\"")]


def _cmd_name(word: str) -> str:
    name = re.split(r"[\\/]", word)[-1].casefold()
    return name[:-4] if name.endswith(".exe") else name


def _arg_matches(want: str, args: list[str]) -> bool:
    is_flag = want.startswith("-")  # flags are case-sensitive (-d != -D); words are not
    for a in args:
        if (a == want) if is_flag else (a.casefold() == want.casefold()):
            return True
        # short flag inside a cluster: -r matches -rf, -fr; case-sensitive (-D != -d)
        if (len(want) == 2 and want[0] == "-" and want[1] != "-" and a.startswith("-")
                and not a.startswith("--") and want[1] in a[1:]):
            return True
    return False


def command_labels(command: str, commands: dict[str, tuple[str, ...]]) -> set[str]:
    """Labels a shell command earns. Each simple command (split on ; | & && || ( ) `
    and newlines) is matched against every entry: the entry's first word is the
    command name, its other words must appear among that command's arguments."""
    labels: set[str] = set()
    for segment in _SPLIT.split(command):
        words = _words(segment)
        # skip leading env assignments and wrappers (sudo, env, time, nohup)
        while words and ("=" in words[0] and not words[0].startswith("-")
                         or _cmd_name(words[0]) in ("sudo", "env", "time", "nohup", "command", "exec")):
            words = words[1:]
        if not words:
            continue
        name, args = _cmd_name(words[0]), words[1:]
        for label, entries in commands.items():
            for entry in entries:
                parts = entry.split()
                if parts and _cmd_name(parts[0]) == name and all(_arg_matches(p, args) for p in parts[1:]):
                    labels.add(label)
                    break
    return labels


def classify(tool: str, tool_input: Any, policy: FusePolicy) -> set[str]:
    """Labels for one call: explicit tool labels, plus command labels for shell tools."""
    labels = {label for label, tools in policy.labels.items() if tool in tools}
    if tool in policy.shell_tools:
        command = tool_input.get("command") if isinstance(tool_input, dict) else tool_input
        if isinstance(command, str):
            labels |= command_labels(command, policy.commands)
    if labels - {"read_only"}:
        labels.discard("read_only")  # a shell command that also sends is never read-only
    return labels


def hosts_of(text: str) -> set[str]:
    """Destination hosts named in a call: URL hosts and scp/rsync `host:` targets."""
    hosts = set()
    for h in _URL_HOST.findall(text):
        h = h.rsplit("@", 1)[-1].lower()
        hosts.add(h[1:].split("]")[0] if h.startswith("[") else h.split(":")[0])
    hosts.update(h.lower() for h in _SSH_HOST.findall(text))
    return {h for h in hosts if h}


# --- self-protection ---------------------------------------------------------

_FUSE_VERBS = re.compile(r"bastionfuse(?:\.exe)?\W+(?:reset|plant|untrip)\b|bastionfuse\.cli", re.IGNORECASE)
_SETTINGS = re.compile(r"\.claude[\\/]+settings(?:\.local)?\.json", re.IGNORECASE)


def self_protect_hit(text: str, policy: FusePolicy, cwd: str | None = None) -> str | None:
    """Why this call touches the fuse itself, or None. Raises the bar only: a
    same-user agent with a shell can always find a spelling this misses."""
    if not policy.self_protect:
        return None
    if cwd and _under_operator_path(cwd, policy):
        return None
    if _FUSE_VERBS.search(text):
        return "runs a bastionfuse operator command"
    if _SETTINGS.search(text):
        return "touches Claude Code settings (where the fuse hook is registered)"
    protected = [str(policy.state_dir)]
    if policy.source is not None:
        protected.append(str(policy.source))
    if policy.kill_file is not None:
        protected.append(str(policy.kill_file))
    if PathMatcher(tuple(protected)).find(text) or ".bastionfuse" in fold(text):
        return "touches the fuse state or policy"
    return None


def _under_operator_path(cwd: str, policy: FusePolicy) -> bool:
    try:
        here = Path(cwd).resolve()
    except (OSError, ValueError):
        return False
    for p in policy.operator_paths:
        try:
            here.relative_to(p.resolve())
            return True
        except (ValueError, OSError):
            continue
    return False


# --- token generation --------------------------------------------------------

_ALNUM_UP = string.ascii_uppercase + string.digits
_ALNUM = string.ascii_letters + string.digits


def new_token(kind: str = "aws") -> str:
    """A honeytoken shaped like a real secret, so an attacker wants it. The shapes
    deliberately fail the providers' checksums/formats where one exists, so the
    token can never be a working credential."""
    r = secrets.choice
    if kind == "aws":
        return "AKIA" + "".join(r(_ALNUM_UP) for _ in range(16))
    if kind == "github":
        return "ghp_" + "".join(r(_ALNUM) for _ in range(36))
    if kind == "openai":
        return "sk-proj-" + "".join(r(_ALNUM) for _ in range(40))
    if kind == "generic":
        return "fuse_" + secrets.token_urlsafe(24).replace("-", "x").replace("_", "y")
    raise ValueError(f"unknown token kind {kind!r}; one of aws, github, openai, generic")

