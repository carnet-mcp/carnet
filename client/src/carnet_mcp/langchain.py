"""LangChain: the door's tools as `StructuredTool`s, with both slots filled.

    from carnet_mcp.langchain import tools
    tools = tools(door_url, token)
    agent = create_agent(model, tools)

`StructuredTool` takes a `func` and a `coroutine`, and an agent uses whichever matches
how it was invoked — so each tool here carries a sync call over `Door` and an async call
over `AsyncDoor`, and neither blocks the other's loop. The arguments schema is the
door's `inputSchema` as it is; LangChain accepts a JSON Schema dict there.

## A refusal is a tool error, not an exception

`ToolException` with `handle_tool_error=True` is LangChain's tool-error channel: the
`ToolMessage` carries the text with an error status, the agent's turn continues, and the
model reads the door's sentence — *no agent granted to this token provides a tool called
'x'*, or *denied: 'OTHER' is outside this agent's 'read' scope (carnet call door-…)* —
and can say so. `DoorUnavailable` is not caught: a door that did not answer is not a
thing a model adapts to, and the turn ends with the real error.

## Verified

Run on 2026-09-20 by `backend/scripts/e2e_client_langchain.py`: a real door on a socket,
`langchain-core` 1.6, a tool invoked through LangChain's own `invoke` and `ainvoke`, a
denial arriving as a `ToolMessage` in the door's words with the call id, and the grant
revoked mid-session with the *next* call refused by name while the tool was still in the
cached list — which is the proof that visibility going stale is safe.
"""

from __future__ import annotations

from typing import Any

from ._door import AsyncDoor, Door, Tool
from .errors import DoorRefused

EXTRA = "carnet-mcp[langchain]"


def tools(url: str, token: str, *, timeout: float = 30.0) -> list[Any]:
    """The three-line form. Builds a `Door` and an `AsyncDoor` over `url` and returns
    one `StructuredTool` per tool the token is granted."""
    return from_doors(Door(url, token, timeout=timeout), AsyncDoor(url, token, timeout=timeout))


def from_doors(door: Door, async_door: AsyncDoor | None = None) -> list[Any]:
    """The same, over doors you built — for a custom `httpx` client, or a test
    transport. Without an `async_door` the coroutine slot is left empty and LangChain
    runs the sync call in a thread for `ainvoke`."""
    try:
        from langchain_core.tools import StructuredTool, ToolException
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError(f'LangChain is not installed. pip install "{EXTRA}"') from exc
    return [_one(StructuredTool, ToolException, door, async_door, spec) for spec in door.tools()]


def _one(StructuredTool: Any, ToolException: Any, door: Door, async_door: AsyncDoor | None, spec: Tool) -> Any:
    def run(**arguments: Any) -> str:
        try:
            result = door.call(spec.name, arguments)
        except DoorRefused as exc:
            raise ToolException(exc.message) from exc
        if result.is_error:
            raise ToolException(result.sentence)
        return result.text

    async def arun(**arguments: Any) -> str:
        assert async_door is not None
        try:
            result = await async_door.call(spec.name, arguments)
        except DoorRefused as exc:
            raise ToolException(exc.message) from exc
        if result.is_error:
            raise ToolException(result.sentence)
        return result.text

    return StructuredTool.from_function(
        func=run,
        coroutine=arun if async_door is not None else None,
        name=spec.name,
        description=spec.description or spec.name,
        args_schema=spec.input_schema,
        handle_tool_error=True,
    )
