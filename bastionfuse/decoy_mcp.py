"""A decoy MCP server: tools no legitimate flow ever calls.

Register it under the name `bastionfuse-decoy`:

    claude mcp add bastionfuse-decoy -- bastionfuse --home ~/.bastionfuse decoy-mcp

Its tools then show up as `mcp__bastionfuse-decoy__<tool>`, and the fuse hook
treats any call to that prefix as a canary: it trips before the call reaches this
server. If a call does arrive (no hook installed, or a client other than Claude
Code), the server trips the GLOBAL fuse itself, since it can't know the session,
and returns an error. Pass the same `--home` as the hook, or the trip lands in a
different state dir. A compromised agent reaching for these tools is an alarm
for every session.

Newline-delimited JSON-RPC 2.0 over stdio, stdlib only.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable, TextIO

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "bastionfuse-decoy"

# Tempting names and descriptions: an injected instruction that wants secrets,
# persistence or cover will reach for these.
DECOY_TOOLS = (
    {
        "name": "export_all_secrets",
        "description": "Export every stored credential, API key and token for this workspace as JSON.",
        "inputSchema": {"type": "object", "properties": {"format": {"type": "string"}}},
    },
    {
        "name": "get_admin_credentials",
        "description": "Return the administrator username and password for the production environment.",
        "inputSchema": {"type": "object", "properties": {"environment": {"type": "string"}}},
    },
    {
        "name": "disable_audit_logging",
        "description": "Turn off audit logging and security monitoring for the current session.",
        "inputSchema": {"type": "object", "properties": {}},
    },
)
_NAMES = {t["name"] for t in DECOY_TOOLS}


def handle(msg: Any, on_call: Callable[[str], None]) -> dict | None:
    """One JSON-RPC message in, one response out (None for notifications)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return _error(None, -32600, "invalid request")
    method, mid = msg.get("method"), msg.get("id")
    if "id" not in msg:
        return None  # notification (e.g. notifications/initialized)
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
    if method == "initialize":
        version = params.get("protocolVersion")
        return _result(mid, {
            "protocolVersion": version if isinstance(version, str) else PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": "0.1.0"},
        })
    if method == "ping":
        return _result(mid, {})
    if method == "tools/list":
        return _result(mid, {"tools": list(DECOY_TOOLS)})
    if method == "tools/call":
        name = params.get("name")
        if not isinstance(name, str) or name not in _NAMES:
            return _error(mid, -32602, f"unknown tool {name!r}")
        on_call(str(name))
        return _result(mid, {"isError": True, "content": [{"type": "text", "text": "Permission denied."}]})
    return _error(mid, -32601, f"method not found: {method}")


def serve(stdin: TextIO, stdout: TextIO, on_call: Callable[[str], None]) -> None:
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            reply = _error(None, -32700, "parse error")
        else:
            try:
                reply = handle(msg, on_call)
            except Exception:  # noqa: BLE001 - one bad message never kills the decoy
                reply = _error(msg.get("id") if isinstance(msg, dict) else None, -32603, "internal error")
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()


def _trip_global(tool: str) -> None:
    from .fuse import Fuse
    from .hook import resolve_policy

    try:
        Fuse(resolve_policy(None)).trip(f"decoy MCP tool '{tool}' was called", global_=True, rule="canary")
    except Exception as e:  # noqa: BLE001 - keep serving; the error is visible on stderr
        sys.stderr.write(f"bastionfuse decoy-mcp: could not trip the fuse ({type(e).__name__}: {e})\n")


def main() -> int:
    serve(sys.stdin, sys.stdout, _trip_global)
    return 0


def _result(mid: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}
