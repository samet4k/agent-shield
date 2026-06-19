"""Decorator to guard tool functions invoked by LangChain, CrewAI, etc."""

from __future__ import annotations

import functools
from typing import Any, Callable, TypeVar

from agentshield.hooks import _analyze

F = TypeVar("F", bound=Callable[..., Any])


def guard(func: F) -> F:
    """Wrap a tool function so its shell side-effects pass through AgentShield."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        command_repr = f"{func.__name__}({args!r}, {kwargs!r})"
        decision, _ = _analyze(command_repr)
        if decision == "block":
            raise PermissionError(f"AgentShield blocked tool {func.__name__}")
        return func(*args, **kwargs)

    return wrapper  # type: ignore[return-value]