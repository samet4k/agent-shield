"""Decorator to guard tool functions invoked by LangChain, CrewAI, etc."""

from __future__ import annotations

import functools
import json
from typing import Any, Callable, Literal, TypeVar

from agentshield.hooks import _analyze

F = TypeVar("F", bound=Callable[..., Any])

AnalysisType = Literal["command", "filesystem", "network", "tool_metadata"]


def guard(
    func: F | None = None,
    *,
    analysis_type: AnalysisType = "tool_metadata",
    tool_rules: dict[str, Any] | None = None,
) -> F | Callable[[F], F]:
    """Wrap a tool function so its side-effects pass through AgentShield."""

    def decorator(inner: F) -> F:
        @functools.wraps(inner)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if analysis_type == "command" and args:
                command_repr = str(args[0])
            elif analysis_type == "filesystem" and args:
                command_repr = f"cat {args[0]}"
            elif analysis_type == "network" and args:
                command_repr = f"curl {args[0]}"
            else:
                command_repr = json.dumps(
                    {
                        "tool": inner.__name__,
                        "args": [repr(a) for a in args],
                        "kwargs": {k: repr(v) for k, v in kwargs.items()},
                        "rules": tool_rules or {},
                    },
                    sort_keys=True,
                )

            decision, _ = _analyze(command_repr)
            if decision == "block":
                raise PermissionError(f"AgentShield blocked tool {inner.__name__}")
            return inner(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    if func is not None:
        return decorator(func)
    return decorator