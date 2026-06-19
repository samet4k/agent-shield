"""Context manager for scoped subprocess interception."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from agentshield.hooks import activate, deactivate


@contextmanager
def session() -> Generator[None, None, None]:
    """Activate AgentShield hooks for the duration of the context block."""
    activate()
    try:
        yield
    finally:
        deactivate()