"""Route subprocess calls through the AgentShield CLI or daemon."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from typing import Any, Callable

from agentshield.ipc import analyze_via_daemon, daemon_available

_ACTIVE = False
_PATCH_LOCK = threading.RLock()
_ORIGINAL_RUN: Callable[..., subprocess.CompletedProcess[Any]] | None = None
_ORIGINAL_POPEN: type[subprocess.Popen[Any]] | None = None
_ORIGINAL_SYSTEM: Callable[[str], int] | None = None
_ORIGINAL_EXECV: Callable[..., Never] | None = None
_ORIGINAL_EXECVP: Callable[..., Never] | None = None
_ORIGINAL_EXECL: Callable[..., Never] | None = None

try:
    from typing import Never
except ImportError:
    Never = Any  # type: ignore[misc,assignment]


def _agentshield_binary() -> str:
    return os.environ.get("AGENTSHIELD_BIN", "agentshield")


def _fail_open() -> bool:
    return os.environ.get("AGENTSHIELD_FAIL_OPEN", "").lower() in ("1", "true", "yes")


def _analyze(command: str) -> tuple[str, dict[str, Any] | None]:
    """Return decision and optional daemon payload."""
    if daemon_available():
        payload = analyze_via_daemon(command)
        if payload and "decision" in payload:
            decision = payload["decision"]
            if isinstance(decision, dict):
                return decision.get("kind", "allow"), payload
            return str(decision), payload

    binary = _agentshield_binary()
    if not shutil.which(binary):
        return "allow", None

    proc = subprocess.run(
        [binary, "analyze", "--format", "json", command],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 and not proc.stdout.strip():
        return ("allow" if _fail_open() else "block"), None

    try:
        payload = json.loads(proc.stdout)
        return payload["decision"]["kind"], payload
    except (json.JSONDecodeError, KeyError, TypeError):
        return ("allow" if _fail_open() else "block"), None


def _guard_command(command: str) -> None:
    decision, _ = _analyze(command)
    if decision == "block":
        raise PermissionError(f"AgentShield blocked: {command}")
    if decision == "prompt":
        answer = input("[agentshield] Allow command? [Y/n] ").strip().lower()
        if answer not in ("", "y", "yes"):
            raise PermissionError(f"AgentShield blocked: {command}")


def _guarded_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
    cmd = args[0] if args else kwargs.get("args", "")
    if isinstance(cmd, (list, tuple)):
        command = subprocess.list2cmdline(list(cmd))
    else:
        command = str(cmd)
    _guard_command(command)
    assert _ORIGINAL_RUN is not None
    return _ORIGINAL_RUN(*args, **kwargs)


def _guarded_system(command: str) -> int:
    _guard_command(command)
    assert _ORIGINAL_SYSTEM is not None
    return _ORIGINAL_SYSTEM(command)


def _guarded_exec(path: str, argv: Any) -> Never:
    if isinstance(argv, (list, tuple)):
        command = subprocess.list2cmdline([path, *argv[1:]])
    else:
        command = str(path)
    _guard_command(command)
    raise PermissionError("exec* hooks block in-place execution under AgentShield")


def activate() -> None:
    global _ACTIVE, _ORIGINAL_RUN, _ORIGINAL_POPEN, _ORIGINAL_SYSTEM
    global _ORIGINAL_EXECV, _ORIGINAL_EXECVP, _ORIGINAL_EXECL
    with _PATCH_LOCK:
        if _ACTIVE:
            return
        _ORIGINAL_RUN = subprocess.run
        _ORIGINAL_POPEN = subprocess.Popen
        _ORIGINAL_SYSTEM = os.system
        subprocess.run = _guarded_run  # type: ignore[assignment]
        os.system = _guarded_system  # type: ignore[assignment]

        if hasattr(os, "execv"):
            _ORIGINAL_EXECV = os.execv  # type: ignore[attr-defined]
            os.execv = _guarded_exec  # type: ignore[assignment]
        if hasattr(os, "execvp"):
            _ORIGINAL_EXECVP = os.execvp  # type: ignore[attr-defined]
            os.execvp = _guarded_exec  # type: ignore[assignment]
        if hasattr(os, "execl"):
            _ORIGINAL_EXECL = os.execl  # type: ignore[attr-defined]
            os.execl = _guarded_exec  # type: ignore[assignment]

        _ACTIVE = True


def deactivate() -> None:
    global _ACTIVE, _ORIGINAL_RUN, _ORIGINAL_POPEN, _ORIGINAL_SYSTEM
    global _ORIGINAL_EXECV, _ORIGINAL_EXECVP, _ORIGINAL_EXECL
    with _PATCH_LOCK:
        if not _ACTIVE:
            return
        if _ORIGINAL_RUN is not None:
            subprocess.run = _ORIGINAL_RUN  # type: ignore[assignment]
        if _ORIGINAL_SYSTEM is not None:
            os.system = _ORIGINAL_SYSTEM  # type: ignore[assignment]
        if _ORIGINAL_EXECV is not None:
            os.execv = _ORIGINAL_EXECV  # type: ignore[assignment]
        if _ORIGINAL_EXECVP is not None:
            os.execvp = _ORIGINAL_EXECVP  # type: ignore[assignment]
        if _ORIGINAL_EXECL is not None:
            os.execl = _ORIGINAL_EXECL  # type: ignore[assignment]
        _ACTIVE = False


def is_active() -> bool:
    return _ACTIVE