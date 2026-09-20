"""The OpenAI Agents SDK: the door's tools as `FunctionTool`s.

    from carnet_mcp.openai_agents import tools
    agent = Agent(name="triage", instructions=..., tools=await tools(url, token))

The SDK is async-first — `Runner.run` is a coroutine and a `FunctionTool`'s
`on_invoke_tool` is awaited — so this adapter is over `AsyncDoor` and `tools()` is a
coroutine. `params_json_schema` is the door's `inputSchema` as it is, with
`strict_json_schema=False` because a connector's schema is rarely written to the strict
subset and the door validates the arguments on the call anyway. The tool's return is the
string the model reads, so a refusal is returned in the door's words with the call id.

**Run against a real door from here on 2026-09-20** (`openai-agents` 0.22.3): the list
arrived, a call in scope ran under the broker's credential, and a call outside scope
returned the broker's sentence with the call id. A `Runner.run` with a real model has
not been made; the stub-door suite in `tests/` holds the shape.
"""

from __future__ import annotations

import json
from typing import Any

from ._door import AsyncDoor
from .errors import DoorRefused

EXTRA = "carnet-mcp[openai-agents]"


async def tools(url: str, token: str, *, timeout: float = 30.0) -> list[Any]:
    return await from_door(AsyncDoor(url, token, timeout=timeout))


async def from_door(door: AsyncDoor) -> list[Any]:
    try:
        from agents import FunctionTool
    except ImportError as exc:  # pragma: no cover
        raise ImportError(f'The OpenAI Agents SDK is not installed. pip install "{EXTRA}"') from exc

    made = []
    for spec in await door.tools():

        async def on_invoke(_context: Any, arguments_json: str, _name: str = spec.name) -> str:
            arguments = json.loads(arguments_json) if arguments_json else {}
            try:
                result = await door.call(_name, arguments if isinstance(arguments, dict) else {})
            except DoorRefused as exc:
                return exc.message
            return result.relay

        schema = dict(spec.input_schema)
        schema.setdefault("type", "object")
        schema.setdefault("properties", {})
        made.append(
            FunctionTool(
                name=spec.name,
                description=spec.description or spec.name,
                params_json_schema=schema,
                on_invoke_tool=on_invoke,
                strict_json_schema=False,
            )
        )
    return made
