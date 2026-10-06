"""Pure rule logic: honeytoken matching, path views, tool classification,
self-protection and token generation. No state (state.py and fuse.py own it), so
every rule is testable on its own. The only I/O is bounded path resolution
(realpath for Windows short names, glob expansion) in path_candidates.
"""

from __future__ import annotations

import base64
import codecs
import glob
import json
import ntpath
import os
import re
import secrets
import shlex
import shutil
import site
import string
import time
import unicodedata
from dataclasses import dataclass
from functools import cached_property, lru_cache
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import unquote

from .policy import FusePolicy

MAX_INPUT_BYTES = 1_048_576  # larger inputs are refused (oversize), never partially scanned
MAX_SHELL_COMMAND = 32_768  # longer shell commands are refused: classification must stay fast
MAX_PATH_TOKENS = 2000
MAX_GLOBS = 8
MAX_GLOB_HITS = 32
PATH_BUDGET_S = 2.0  # wall-clock budget for filesystem work (realpath, glob) per call
MAX_DEPTH = 3  # nested `bash -c` / `powershell -enc` levels to unwrap


class Oversize(ValueError):
    """Tool input or result too large to scan; the caller fails closed."""


def flatten(value: Any) -> str:
    """Tool input/result as one string. JSON when possible, repr otherwise, so a
    value that isn't JSON-serializable is still scanned. Lone surrogates become
    "?": they can't be stored, and a storage error must never undo a trip."""
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, default=repr)
        except (TypeError, ValueError):
            text = repr(value)
    text = text.encode("utf-8", "replace").decode("utf-8")
    if len(text.encode("utf-8")) > MAX_INPUT_BYTES:
        raise Oversize(f"input over {MAX_INPUT_BYTES} bytes")
    return text


def fold(text: str) -> str:
    """NFKC, strip format characters (zero-width joiners, BOMs, soft hyphens), casefold."""
    return _strip_cf(text).casefold()


def _strip_cf(text: str) -> str:
    if text.isascii():  # NFKC is the identity on ASCII, and ASCII has no format characters
        return text
    return unicodedata.normalize("NFKC", text).translate(_cf_table())


@lru_cache(maxsize=1)
def _cf_table() -> dict[int, None]:
    """Every format (Cf) code point -> deleted. str.translate runs in C (a per-char loop was
    the slowest part of a 1 MB scan). Built lazily: it costs ~0.2 s, and ASCII never needs it."""
    return {cp: None for cp in range(0x110000) if unicodedata.category(chr(cp)) == "Cf"}


# separators an attacker sprinkles inside a token: whitespace, quotes, shell
# concatenation, hex/url prefixes, punctuation. Removed from text AND forms alike.
_SEPARATORS = re.compile(r"\\x|0x|%|[\s'\"`.,:;+_\-|^$(){}\[\]\\/]")


def _squash(text: str) -> str:
    return _SEPARATORS.sub("", text)


def _aligned(encode, data: bytes, bits: int, block: int) -> set[str]:
    """Substrings of encode(prefix + data) fully determined by data, for every byte
    alignment, so the form matches wherever data sits inside a larger encoded blob."""
    out, n = set(), len(data)
    for k in range(block):
        enc = encode(b"\0" * k + data).decode().rstrip("=")
        start = -(-8 * k // bits)
        end = (8 * (k + n)) // bits
        if end - start >= 10:
            out.add(enc[start:end])
    return out


def _forms(token: str) -> tuple[set[str], set[str]]:
    """(case-insensitive forms, case-sensitive forms) of one honeytoken."""
    raw = token.encode()
    folded = {token, token[::-1], codecs.encode(token, "rot13"), raw.hex()}
    folded |= _aligned(base64.b32encode, raw, 5, 5)
    exact = set()
    for data in (raw, token.encode("utf-16-le")):  # utf-16: PowerShell -EncodedCommand
        exact |= _aligned(base64.b64encode, data, 6, 3)
        exact |= _aligned(base64.urlsafe_b64encode, data, 6, 3)
    return {fold(f) for f in folded}, exact


@dataclass(frozen=True)
class TokenMatcher:
    """Precomputed forms of every honeytoken: raw, reversed, rot13, hex, base32,
    base64 (standard and URL-safe, UTF-8 and UTF-16LE) at every alignment. Searched
    in the raw text and in a "squashed" view with separators removed (catches
    `41 4b 49`, `\\x41\\x4b`, partial %-encoding, line-wrapped base64, quote-split
    tokens). Plain substring search, linear in the input."""

    tokens: tuple[str, ...]

    @cached_property
    def _tables(self) -> tuple[dict, dict, dict, dict]:
        f_raw, f_sq, e_raw, e_sq = {}, {}, {}, {}
        for t in self.tokens:
            folded, exact = _forms(t)
            for f in folded:
                f_raw[f] = t
                if len(sq := _squash(f)) >= 10:
                    f_sq[sq] = t
            for f in exact:
                e_raw[f] = t
                if len(sq := _squash(f)) >= 10:
                    e_sq[sq] = t
        return f_raw, f_sq, e_raw, e_sq

    def find(self, text: str) -> str | None:
        """The honeytoken present in `text` (any supported encoding), or None."""
        if not self.tokens or not text:
            return None
        f_raw, f_sq, e_raw, e_sq = self._tables
        plain = _strip_cf(text)
        folded = plain.casefold()
        views = [(folded, f_raw), (_squash(folded), f_sq), (plain, e_raw), (_squash(plain), e_sq)]
        if "%" in text:
            views.append((fold(unquote(text)), f_raw))
        for view, table in views:
            for form, tok in table.items():
                if form in view:
                    return tok
        return None

    @cached_property
    def _redactor(self) -> re.Pattern | None:
        f_raw, _, e_raw, _ = self._tables
        alts = [re.escape(f) for f in sorted(f_raw, key=len, reverse=True)]
        alts += [re.escape(f) for f in sorted(e_raw, key=len, reverse=True)]
        return re.compile("|".join(alts), re.IGNORECASE) if alts else None

    def redact(self, text: str) -> str:
        """Remove honeytokens (raw and encoded) and common secret shapes from text
        that will be stored (forensic ring, snapshots)."""
        if self._redactor is not None:
            text = self._redactor.sub("[HONEYTOKEN]", text)
        return _SECRET_SHAPES.sub(lambda m: next((g for g in m.groups() if g), "") + "[REDACTED]", text)


_SECRET_SHAPES = re.compile(
    r"((?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=-]{8,}"
    r"|((?:password|passwd|secret|api[_-]?key|token)[\"']?\s*[:=]\s*[\"']?)[^\s\"',;&]{4,}"
    r"|()\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    r"|()\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}"
    r"|()\bsk-[A-Za-z0-9_-]{16,}"
    r"|()\bxox[abposr]-[A-Za-z0-9-]{10,}",
    re.IGNORECASE,
)


# --- paths -------------------------------------------------------------------

_PATH_KEYS = frozenset({"file_path", "path", "paths", "notebook_path", "command", "cwd", "directory", "dir",
                        "source", "destination", "target", "filename", "files", "url", "uri"})
_ACTION_KEYS = _PATH_KEYS | {"cmd", "script", "args", "argv", "arguments"}


def action_text(tool_input: Any) -> str:
    """The parts of a call that say what it does (commands, paths, URLs), without file
    content. Self-protect's text rules read only this: a Write whose body merely
    mentions the settings path or the package name is not an attack on the fuse."""
    if isinstance(tool_input, dict):
        return flatten({k: v for k, v in tool_input.items() if str(k).casefold() in _ACTION_KEYS})
    return flatten(tool_input)
_TOKEN_SPLIT = re.compile(r"[\s|;&<>()=,`]+")
_GIT_BASH = re.compile(r"^/(?:mnt/)?([a-zA-Z])(/.*)?$")


def _strings(value: Any, budget: list[int]) -> Iterator[str]:
    """String leaves of a tool input, bounded."""
    if budget[0] <= 0:
        return
    if isinstance(value, str):
        budget[0] -= 1
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v, budget)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v, budget)


def _norm(p: str) -> str:
    return os.path.normcase(os.path.normpath(p)).replace("\\", "/")


def path_candidates(tool_input: Any, cwd: str | None) -> set[str]:
    """Normalized absolute paths a call may refer to: every path-like word of every
    string in the input, with quotes removed, ~ and $VARS expanded, Git-Bash/WSL
    drive prefixes mapped, relative paths resolved against cwd, `.`/`..` collapsed,
    Windows short names (8.3) expanded and globs expanded (bounded)."""
    out: set[str] = set()
    words, globs = 0, 0
    deadline = time.monotonic() + PATH_BUDGET_S
    if isinstance(tool_input, dict):  # path-bearing fields only: file content isn't a path
        tool_input = [v for k, v in tool_input.items() if str(k).casefold() in _PATH_KEYS]
    for s in _strings(tool_input if not isinstance(tool_input, str) else [tool_input], [64]):
        for word in _TOKEN_SPLIT.split(s.replace('"', "").replace("'", "")):
            if not word or words >= MAX_PATH_TOKENS:
                continue
            words += 1
            p = os.path.expandvars(os.path.expanduser(word))
            if os.name == "nt" and (m := _GIT_BASH.match(p.replace("\\", "/"))):
                p = f"{m.group(1)}:{m.group(2) or '/'}"
            if not os.path.isabs(p) and not ntpath.isabs(p):
                if not cwd:
                    continue
                p = os.path.join(cwd, p)
            out.add(_norm(p))
            # filesystem work only on local paths, and only within the time budget:
            # a remote path can block for tens of seconds (and contacts that host)
            if _is_remote(p) or time.monotonic() > deadline:
                continue
            if os.name == "nt" and "~" in p:
                try:
                    out.add(_norm(os.path.realpath(p)))
                except (OSError, ValueError):
                    pass
            if any(c in p for c in "*?[") and globs < MAX_GLOBS:
                globs += 1
                out |= _bounded_glob(p, deadline)
    return out


def _is_remote(p: str) -> bool:
    return bool(_REMOTE.match(p.replace("\\", "/")))


def _bounded_glob(pattern: str, deadline: float) -> set[str]:
    """Lazy glob: stop at MAX_GLOB_HITS or the deadline instead of listing everything."""
    out: set[str] = set()
    try:
        it = glob.iglob(pattern, include_hidden=True) if _GLOB_HIDDEN else glob.iglob(pattern)
        for h in it:
            if _is_remote(h):
                continue
            out.add(_norm(os.path.realpath(h)))
            if len(out) >= MAX_GLOB_HITS or time.monotonic() > deadline:
                break
    except (OSError, ValueError, re.error):
        pass
    return out


_GLOB_HIDDEN = "include_hidden" in glob.iglob.__code__.co_varnames
_REMOTE = re.compile(r"^(?://|[a-z][a-z0-9+.-]*://)", re.IGNORECASE)


@dataclass(frozen=True)
class PathMatcher:
    """Matches decoy/protected paths against a call: substring of the folded text,
    or equality/prefix against path_candidates."""

    paths: tuple[str, ...]

    @cached_property
    def _forms(self) -> dict[str, str]:
        out = {}
        for p in self.paths:
            raw, expanded = str(p), str(Path(p).expanduser())
            forms = {raw, expanded}
            home = str(Path.home())
            if expanded.startswith(home):
                forms.add("~" + expanded[len(home):])
            for f in forms:
                for v in (f, f.replace("\\", "/"), f.replace("/", "\\")):
                    if len(v) >= 4:
                        out[fold(v)] = p
        return out

    @cached_property
    def _normed(self) -> dict[str, str]:
        out = {}
        for p in self.paths:
            expanded = os.path.expanduser(str(p))
            out[_norm(expanded)] = p
            try:
                out[_norm(os.path.realpath(expanded))] = p
            except (OSError, ValueError):
                pass
        return out

    def find(self, text: str, candidates: set[str] = frozenset(), *, prefix: bool = False) -> str | None:
        folded = fold(text).replace("\\\\", "\\")  # JSON doubles backslashes
        for form, p in self._forms.items():
            if form in folded:
                return p
        for c in candidates:
            for normed, p in self._normed.items():
                if c == normed or (prefix and c.startswith(normed.rstrip("/") + "/")):
                    return p
        return None


# --- classification ----------------------------------------------------------

OPAQUE = "opaque"  # code whose effect can't be classified: inline interpreters, eval, $CMD
_KEYWORDS = frozenset({"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "for", "in", "case",
                       "esac", "function", "select", "!", "{", "}", "[[", "]]", "coproc"})
_WRAPPERS = {  # wrapper -> options that take a value
    "sudo": {"-u", "-g", "-C", "-h", "-p", "-U", "-r", "-t", "-D"}, "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-S"}, "nohup": set(), "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "nice": {"-n", "--adjustment"}, "ionice": {"-c", "-n", "-p"}, "stdbuf": {"-i", "-o", "-e"},
    "chrt": set(), "taskset": set(), "xargs": {"-I", "-n", "-P", "-L", "-d", "-s", "-a", "-E", "-i"},
    "watch": {"-n", "-d"}, "command": set(), "exec": {"-a"}, "builtin": set(), "busybox": set(),
    "strace": {"-e", "-o", "-p", "-s"}, "ltrace": {"-e", "-o"}, "unbuffer": set(), "start-process": {"-argumentlist"},
    "start": set(), "caffeinate": set(), "firejail": set(), "proxychains": set(), "proxychains4": set(),
    "torsocks": set(), "flock": set(), "setsid": set(), "runuser": {"-u"}, "time": {"-f", "-o"},
}
_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "fish", "ash", "mksh", "tcsh", "csh"})
_POWERSHELL = frozenset({"powershell", "pwsh"})
_INLINE = {  # interpreter -> flags that run inline code
    "python": {"-c"}, "python3": {"-c"}, "python2": {"-c"}, "py": {"-c"}, "pypy": {"-c"}, "pypy3": {"-c"},
    "node": {"-e", "--eval", "-p", "--print"}, "deno": {"eval"}, "bun": {"-e", "--eval"},
    "perl": {"-e", "-E"}, "ruby": {"-e"}, "php": {"-r"}, "osascript": {"-e"}, "lua": {"-e"},
    "rscript": {"-e"},
}
_EVAL = frozenset({"eval", "iex", "invoke-expression", "source", "."})
_PS_CMD = frozenset({"-c", "-command", "/c", "-commandwithargs"})
_PS_ENC = frozenset({"-e", "-ec", "-en", "-enc", "-encodedcommand", "-encoded"})
_TEXT_EGRESS = re.compile(r"/dev/(?:tcp|udp)/|net\.webclient|system\.net\.(?:sockets|http|webclient|webrequest)"
                          r"|\bupload(?:string|file|data|values)\b|\[net\.sockets", re.IGNORECASE)
_DURATION = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")


def _cmd_name(word: str) -> str:
    name = re.split(r"[\\/]", word.lstrip("`$(&"))[-1].casefold().rstrip("`)")
    for ext in (".exe", ".cmd", ".bat", ".com", ".ps1"):
        if name.endswith(ext):
            return name[: -len(ext)]
    return name


@lru_cache(maxsize=32)
def _entries(commands: tuple[tuple[str, tuple[str, ...]], ...]) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    out = []
    for label, entries in commands:
        for entry in entries:
            parts = entry.split()
            if parts:
                out.append((label, _cmd_name(parts[0]), tuple(parts[1:])))
    return tuple(out)


def _arg_matches(want: str, args: list[str]) -> bool:
    is_flag = want.startswith("-")  # flags are case-sensitive (-d != -D); words are not
    for a in args:
        if (a == want) if is_flag else (a.casefold() == want.casefold()):
            return True
        # short flag inside a cluster: -r matches -rf, -fr
        if (len(want) == 2 and is_flag and want[1] != "-" and a.startswith("-")
                and not a.startswith("--") and want[1] in a[1:]):
            return True
    return False


def _segments(command: str) -> list[list[str]]:
    """Simple commands as word lists, tokenized twice: with POSIX backslash escapes
    (`c\\url` -> curl) and without (`C:\\tools\\curl.exe` keeps its path). shlex
    handles quoting (`cu''rl` -> curl); ; | & ( ) < > and newlines separate commands."""
    out: list[list[str]] = []
    for escape in ("\\", ""):
        for seg in _tokenize(command, escape):
            if seg not in out:
                out.append(seg)
    return out


def _tokenize(command: str, escape: str) -> list[list[str]]:
    """Unbalanced quotes fall back to a plain split, which over-approximates (fine
    for a security classifier)."""
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars="();<>|&\n")
        lex.whitespace = " \t\r"
        lex.whitespace_split = True
        lex.commenters = ""
        lex.escape = escape
        tokens = list(lex)
    except ValueError:
        tokens = [w.strip("'\"") for w in re.split(r"([;|&()<>\n])|\s+", command) if w and w.strip("'\"")]
    segments, cur = [], []
    for tok in tokens:
        if tok and all(c in "();<>|&\n" for c in tok):
            if cur:
                segments.append(cur)
            cur = []
        else:
            cur.append(tok.replace("${IFS}", " ").replace("$IFS", " "))
    if cur:
        segments.append(cur)
    return segments


def command_labels(command: str, commands: dict[str, tuple[str, ...]], _depth: int = 0) -> set[str]:
    """Labels a shell command earns. Each simple command is matched against every
    entry: the entry's first word is the command name, its other words must appear
    among that command's arguments. Wrappers (sudo, env, timeout, xargs...), shell
    keywords and nested shells (`bash -c`, `powershell -enc`) are unwrapped."""
    labels: set[str] = set()
    if _TEXT_EGRESS.search(command):
        labels.add("egress")
    entries = _entries(tuple(sorted(commands.items())))
    for words in _segments(command):
        labels |= _simple(words, entries, commands, _depth)
    return labels


def _simple(words: list[str], entries, commands, depth: int) -> set[str]:
    labels: set[str] = set()
    i, n = 0, len(words)
    while i < n:  # unwrap keywords, env assignments and wrappers (index, not slicing: linear)
        w = words[i]
        name = _cmd_name(w)
        if w in _KEYWORDS or ("=" in w and not w.startswith("-") and name not in _WRAPPERS):
            i += 1
            continue
        if i + 1 < n and words[i + 1] == "=":  # PowerShell `$x = ...`
            i += 2
            continue
        if name in _WRAPPERS:
            value_opts = _WRAPPERS[name]
            i += 1
            while i < n and (words[i].startswith("-") or (name == "env" and "=" in words[i])
                             or (name in ("timeout", "nice") and _DURATION.match(words[i]))):
                i += 2 if words[i] in value_opts or words[i].casefold() in value_opts else 1
            continue
        break
    if i >= n:
        return labels
    word, args = words[i], words[i + 1:]
    name = _cmd_name(word)
    if word.startswith(("$", "`")) or "$(" in word:
        return {OPAQUE}  # the command itself is computed at runtime
    if name in _EVAL:
        labels.add(OPAQUE)
        if depth < MAX_DEPTH and name != ".":
            labels |= command_labels(" ".join(args), commands, depth + 1)
    if name in _INLINE and (not _INLINE[name] or any(a in _INLINE[name] for a in args)):
        labels.add(OPAQUE)
    if depth < MAX_DEPTH:
        labels |= _nested(name, args, commands, depth)
    for j, a in enumerate(args):  # find -exec CMD ... ;
        if a in ("-exec", "-execdir", "-ok", "-okdir") and j + 1 < len(args):
            if depth < MAX_DEPTH:
                labels |= _simple(args[j + 1:], entries, commands, depth + 1)
            else:
                labels.add(OPAQUE)  # nested deeper than we unwrap: treat as unclassifiable
            break
    for label, ename, rest in entries:
        if ename == name and all(_arg_matches(p, args) for p in rest):
            labels.add(label)
    return labels


def _nested(name: str, args: list[str], commands, depth: int) -> set[str]:
    """Commands hidden inside `bash -c`, `cmd /c`, `powershell -Command/-EncodedCommand`."""
    lowered = [a.casefold() for a in args]
    if name in _SHELLS or name == "su":
        for j, a in enumerate(args):
            if a.startswith("-") and not a.startswith("--") and "c" in a[1:] and j + 1 < len(args):
                return command_labels(args[j + 1], commands, depth + 1)
    if name == "cmd":
        for j, a in enumerate(lowered):
            if a in ("/c", "/k", "/r"):
                return command_labels(" ".join(args[j + 1:]), commands, depth + 1)
    if name in _POWERSHELL:
        for j, a in enumerate(lowered):
            if a in _PS_ENC and j + 1 < len(args):
                try:
                    script = base64.b64decode(args[j + 1], validate=False).decode("utf-16-le", "replace")
                except (ValueError, TypeError):
                    return {OPAQUE}
                return command_labels(script, commands, depth + 1) | {OPAQUE}
            if a in _PS_CMD:
                return command_labels(" ".join(args[j + 1:]), commands, depth + 1)
        if args and not args[0].startswith("-"):
            return command_labels(" ".join(args), commands, depth + 1)
    return set()


def classify(tool: str, tool_input: Any, policy: FusePolicy) -> set[str]:
    """Labels for one call: explicit tool labels, plus command labels for shell
    tools. Raises Oversize for a shell command too long to classify quickly."""
    labels = {label for label, tools in policy.labels.items() if tool in tools}
    if tool in policy.shell_tools:
        command = tool_input.get("command") if isinstance(tool_input, dict) else tool_input
        if isinstance(command, str):
            if len(command) > MAX_SHELL_COMMAND:
                raise Oversize(f"shell command over {MAX_SHELL_COMMAND} characters")
            labels |= command_labels(command, policy.commands)
    if labels - {"read_only"}:
        labels.discard("read_only")  # a command that also sends or runs code is never read-only
    return labels


_URL_HOST = re.compile(r"https?://([^/\s'\"<>\\]+)", re.IGNORECASE)
_SSH_HOST = re.compile(r"(?:^|\s)(?:[\w.-]+@)?([A-Za-z0-9][\w.-]*\.[A-Za-z]{2,}):", re.ASCII)


def hosts_of(text: str) -> set[str]:
    """Destination hosts named in a call: URL hosts and scp/rsync `host:` targets."""
    hosts = set()
    for h in _URL_HOST.findall(text):
        h = h.rsplit("@", 1)[-1].lower()
        hosts.add(h[1:].split("]")[0] if h.startswith("[") else h.split(":")[0])
    hosts.update(h.lower() for h in _SSH_HOST.findall(text))
    return {h for h in hosts if h}


# --- self-protection ---------------------------------------------------------

# Every repetition is bounded: `re` holds the GIL, so an unbounded quadratic match on a
# large input would also stall the hook watchdog (round-3 review).
_FUSE_VERBS = re.compile(r"(?:^|[\s;&|(])bastionfuse(?:\.exe)?(?=\s)[^\n;&|]{0,128}?\b(?:reset|plant|untrip)\b"
                         r"|bastionfuse\.cli", re.IGNORECASE)
# a package manager, then (within a few words) a verb that changes an install, then the name
_PKG_TOOLS = re.compile(r"(?:^|[\s;&|(])(?:pip3?|pipx|uv|conda|mamba|poetry|pdm|rye|hatch)(?:\s+[\w.-]{1,32}){0,3}?"
                        r"\s+(?:uninstall|remove|rm|install|reinstall|add|upgrade|update|sync)\b"
                        r"[^\n;&|]{0,128}?\bbastionfuse\b", re.IGNORECASE)
_SETTINGS = re.compile(r"\.claude[\\/]{1,4}(?:[^\s\\/\"']{1,64}[\\/]{1,4}){0,8}settings(?:\.local)?\.json",
                       re.IGNORECASE)
_SETTINGS_TAIL = re.compile(r"/\.claude/settings(?:\.local)?\.json$")


@lru_cache(maxsize=1)
def _install_paths() -> tuple[str, ...]:
    """The installed package and its console script: deleting or editing either
    disables the hook (a missing command exits 127, which the host treats as allow)."""
    script = _script_path()
    return (_package_dir(),) + ((script,) if script else ())


def _package_dir() -> str:
    return str(Path(__file__).resolve().parent)


@lru_cache(maxsize=1)
def _script_path() -> str | None:
    script = shutil.which("bastionfuse")
    return str(Path(script).resolve()) if script else None


@lru_cache(maxsize=1)
def _site_dirs() -> tuple[str, ...]:
    """Directories whose startup files (sitecustomize.py, usercustomize.py, *.pth) run
    inside every Python process, the hook's included."""
    dirs = list(site.getsitepackages()) if hasattr(site, "getsitepackages") else []
    try:
        dirs.append(site.getusersitepackages())
    except (AttributeError, OSError):
        pass
    return tuple(_norm(d) for d in dirs if d)


def _is_startup_file(candidate: str) -> bool:
    name = candidate.rsplit("/", 1)[-1]
    if name not in _STARTUP_NAMES and not name.endswith(".pth"):
        return False
    parent = candidate.rsplit("/", 1)[0]
    return parent in _site_dirs() or name in _STARTUP_NAMES


_STARTUP_NAMES = frozenset({"sitecustomize.py", "usercustomize.py"})


def self_protect_hit(text: str, policy: FusePolicy, candidates: set[str] = frozenset(), *,
                     read_only: bool = False, shell: bool = False) -> str | None:
    """Why this call touches the fuse itself, or None. Raises the bar only: a
    same-user agent with a shell can always find a spelling this misses.

    `text` should be action_text() of the call (commands and paths, not file content).
    `read_only` calls may read the package source; nothing may change it. In a `shell`
    command the console script is usually being run, not changed, so only file-writing
    tools are refused for it (deleting it from a shell is a documented limit)."""
    if not policy.self_protect:
        return None
    unquoted = text.replace('"', "").replace("'", "").replace("\\\\", "\\")
    if _FUSE_VERBS.search(unquoted):
        return "runs a bastionfuse operator command"
    if _PKG_TOOLS.search(unquoted):
        return "changes the bastionfuse installation"
    if _SETTINGS.search(unquoted) or any(_SETTINGS_TAIL.search(c) for c in candidates):
        return "touches Claude Code settings (where the fuse hook is registered)"
    protected = [str(policy.state_dir)]
    if policy.source is not None:
        protected.append(str(policy.source))
    if policy.kill_file is not None:
        protected.append(str(policy.kill_file))
    if (PathMatcher(tuple(protected)).find(unquoted, candidates, prefix=True)
            or ".bastionfuse" in fold(unquoted)):
        return "touches the fuse state or policy"
    if read_only:
        return None
    if any(_is_startup_file(c) for c in candidates):
        return "writes a Python startup file (it would run inside the fuse hook)"
    protected_install = (_package_dir(),) if shell or not _script_path() else _install_paths()
    if PathMatcher(protected_install).find("", candidates, prefix=True):
        return "touches the installed bastionfuse package"
    return None


# --- token generation --------------------------------------------------------

_ALNUM_UP = string.ascii_uppercase + string.digits
_ALNUM = string.ascii_letters + string.digits


def new_token(kind: str = "aws") -> str:
    """A honeytoken shaped like a real secret, so an attacker wants it. Random, so
    it is never a working credential."""
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
