"""Daemon IPC client for AgentShield (Unix socket / Windows named pipe)."""

from __future__ import annotations

import json
import os
import sys
from typing import Any
from uuid import UUID

_REQ_ID = 0
_SESSION_ID: UUID | None = None

if sys.platform == "win32":
    _PIPE_PATH = r"\\.\pipe\agentshield"
else:
    _PIPE_PATH = (
        os.environ.get("XDG_RUNTIME_DIR", "/tmp")
        + "/agentshield/daemon.sock"
    )


def _next_id() -> int:
    global _REQ_ID
    _REQ_ID += 1
    return _REQ_ID


def daemon_available() -> bool:
    if sys.platform == "win32":
        try:
            with open(_PIPE_PATH, "r+b", buffering=0):
                return True
        except OSError:
            return False
    return os.path.exists(_PIPE_PATH)


def analyze_via_daemon(command: str, cwd: str | None = None) -> dict[str, Any] | None:
    global _SESSION_ID
    req = {
        "id": _next_id(),
        "method": "analyze",
        "params": {
            "command": command,
            "cwd": cwd,
            "session_id": str(_SESSION_ID) if _SESSION_ID else None,
        },
    }
    try:
        resp = _call_daemon(req)
    except OSError:
        return None

    if resp.get("error"):
        return None
    result = resp.get("result") or {}
    sid = result.get("session_id")
    if sid:
        _SESSION_ID = UUID(str(sid))
    return result


def _call_daemon(req: dict[str, Any]) -> dict[str, Any]:
    payload = (json.dumps(req) + "\n").encode("utf-8")
    if sys.platform == "win32":
        with open(_PIPE_PATH, "r+b", buffering=0) as pipe:
            pipe.write(payload)
            line = _read_line(pipe)
    else:
        import socket

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(2.0)
            sock.connect(_PIPE_PATH)
            sock.sendall(payload)
            line = _recv_line(sock)
    return json.loads(line.decode("utf-8"))


def _read_line(pipe: Any) -> bytes:
    buf = bytearray()
    while True:
        chunk = pipe.read(1)
        if not chunk or chunk == b"\n":
            break
        buf.extend(chunk)
    return bytes(buf)


def _recv_line(sock: Any) -> bytes:
    buf = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk or chunk == b"\n":
            break
        buf.extend(chunk)
    return bytes(buf)