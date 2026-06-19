"""Route subprocess calls through the AgentShield CLI."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Callable

_ACTIVE = False
_ORIGINAL_RUN: Callable[..., subprocess.CompletedProcess[Any]] | None = None
_ORIGINAL_POPEN: type[subprocess.Popen[Any]] | None = None
_ORIGINAL_SYSTEM: Callable[[str], int] | None = None


def _agentshield_binary() -> str:
    return os.environ.get("AGENTSHIELD_BIN", "agentshield")


def _fail_open() -> bool:
    return os.environ.get("AGENTSHIELD_FAIL_OPEN", "").lower() in ("1", "true", "yes")


def _analyze(command: str) -> str:
    """Return decision: allow, block, or prompt."""
    binary = _agentshield_binary()
    if not shutil.which(binary):
        return "allow"

    proc = subprocess.run(
        [binary, "analyze", "--format", "json", command],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 and not proc.stdout.strip():
        return "allow" if _fail_open() else "block"

    try:
        payload = json.loads(proc.stdout)
        return payload["decision"]["kind"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return "allow" if _fail_open() else "block"


def _guarded_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
    cmd = args[0] if args else kwargs.get("args", "")
    if isinstance(cmd, (list, tuple)):
        command = subprocess.list2cmdline(list(cmd))
    else:
        command = str(cmd)

    decision = _analyze(command)
    if decision == "block":
        raise PermissionError(f"AgentShield blocked: {command}")
    if decision == "prompt":
        answer = input("[agentshield] Allow command? [Y/n] ").strip().lower()
        if answer not in ("", "y", "yes"):
            raise PermissionError(f"AgentShield blocked: {command}")

    assert _ORIGINAL_RUN is not None
    return _ORIGINAL_RUN(*args, **kwargs)


def _guarded_system(command: str) -> int:
    decision = _analyze(command)
    if decision == "block":
        raise PermissionError(f"AgentShield blocked: {command}")
    if decision == "prompt":
        answer = input("[agentshield] Allow command? [Y/n] ").strip().lower()
        if answer not in ("", "y", "yes"):
            raise PermissionError(f"AgentShield blocked: {command}")
    assert _ORIGINAL_SYSTEM is not None
    return _ORIGINAL_SYSTEM(command)


def activate() -> None:
    global _ACTIVE, _ORIGINAL_RUN, _ORIGINAL_POPEN, _ORIGINAL_SYSTEM
    if _ACTIVE:
        return
    _ORIGINAL_RUN = subprocess.run
    _ORIGINAL_POPEN = subprocess.Popen
    _ORIGINAL_SYSTEM = os.system
    subprocess.run = _guarded_run  # type: ignore[assignment]
    os.system = _guarded_system  # type: ignore[assignment]
    _ACTIVE = True


def deactivate() -> None:
    global _ACTIVE, _ORIGINAL_RUN, _ORIGINAL_POPEN, _ORIGINAL_SYSTEM
    if not _ACTIVE:
        return
    if _ORIGINAL_RUN is not None:
        subprocess.run = _ORIGINAL_RUN  # type: ignore[assignment]
    if _ORIGINAL_SYSTEM is not None:
        os.system = _ORIGINAL_SYSTEM  # type: ignore[assignment]
    _ACTIVE = False


def is_active() -> bool:
    return _ACTIVE