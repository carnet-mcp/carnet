"""Core: the broker, and the things the broker orchestrates.

Import order matters conceptually, not mechanically:

    broker      the only path from a caller to a tool
    permissions may this agent, for this principal, do this?
    patterns    does this resource fall inside a grant?
    limits      has this run already done too much?
    credentials what secret does it need?
    audit       what happened?
    principal   who the call is made for
    context     the run a call belongs to: id, principal, budget, cancellation

Nothing in core knows about a specific tool or a specific agent.
"""

from .context import Cancellation, RunContext
from .principal import Principal

__all__ = [
    "Cancellation",
    "Principal",
    "RunContext",
]
