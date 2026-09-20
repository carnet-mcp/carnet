"""AutoGen: the door's tools as `autogen_core.tools.BaseTool` subclasses.

    from carnet_mcp.autogen import tools
    agent = AssistantAgent("triage", model_client=..., tools=await tools(url, token))

AutoGen's tool base is generic over two pydantic models — the arguments and the return —
and `run` is a coroutine, so this adapter is over `AsyncDoor`, the arguments type is the
door's `inputSchema` converted by `_schema.py`, and the return is a one-field model whose
`return_value_as_string` is the door's text, so the model sees the sentence and not a
JSON wrapper around it. A refusal is returned in the door's words with the call id.

**Run against a real door from here on 2026-09-20** (`autogen-core` 0.7.5): the list
arrived, a call in scope ran under the broker's credential, and a call outside scope
returned the broker's sentence with the call id — where AutoGen's own MCP adapter raises
instead. An `AssistantAgent` with a real model has not been run; the stub-door suite in
`tests/` holds the shape. Worth knowing beside it: `autogen-ext[mcp]` 0.7.5 does not
import against the `mcp` 2.x it pulls in — that is the vendor's adapter, which this
package does not use, but a project holding both needs `mcp<2`.
"""

from __future__ import annotations

from typing import Any

from ._door import AsyncDoor
from .errors import DoorRefused

EXTRA = "carnet-mcp[autogen]"


async def tools(url: str, token: str, *, timeout: float = 30.0) -> list[Any]:
    return await from_door(AsyncDoor(url, token, timeout=timeout))


async def from_door(door: AsyncDoor) -> list[Any]:
    try:
        from autogen_core.tools import BaseTool
        from pydantic import BaseModel
    except ImportError as exc:  # pragma: no cover
        raise ImportError(f'AutoGen is not installed. pip install "{EXTRA}"') from exc
    from ._schema import arguments_from, model_from_schema

    class Said(BaseModel):
        text: str

    class CarnetTool(BaseTool[BaseModel, Said]):  # type: ignore[misc,type-arg]
        def __init__(self, name: str, description: str, args_type: Any):
            super().__init__(args_type=args_type, return_type=Said, name=name, description=description)
            self._at_door = name

        async def run(self, args: Any, cancellation_token: Any) -> Said:
            try:
                result = await door.call(self._at_door, arguments_from(args))
            except DoorRefused as exc:
                return Said(text=exc.message)
            return Said(text=result.relay)

        def return_value_as_string(self, value: Any) -> str:
            return value.text if isinstance(value, Said) else str(value)

    return [
        CarnetTool(spec.name, spec.description or spec.name, model_from_schema(spec.name, spec.input_schema))
        for spec in await door.tools()
    ]
