"""CrewAI: the door's tools as `crewai.tools.BaseTool` instances.

    from carnet_mcp.crewai import tools
    agent = Agent(role=..., goal=..., backstory=..., tools=tools(url, token))

CrewAI's tool contract is synchronous (`_run(**kwargs) -> str`) and its arguments schema
is a pydantic model type, so each tool here is over `Door` and its schema is the door's
`inputSchema` converted by `_schema.py`. CrewAI's only channel back to the model is the
returned string, so a refusal is *returned*, in the door's words with the call id, rather
than raised: raising would end the task, and a model that is told no can say so.

**Run against a real door from here on 2026-09-20** (`crewai` 1.15.22, a fileborne door
on uvicorn): the list arrived, a call in scope ran under the broker's credential, and a
call outside scope returned the broker's sentence with the call id. A real crew with a
real model completing a task through it has not been run; the stub-door suite in
`tests/` holds the shape. Worth knowing beside it: CrewAI's *own* MCP adapter needs
`crewai-tools[mcp]` or it stops at an interactive prompt; this module does not use it.
"""

from __future__ import annotations

from typing import Any

from ._door import Door
from .errors import DoorRefused

EXTRA = "carnet-mcp[crewai]"


def tools(url: str, token: str, *, timeout: float = 30.0) -> list[Any]:
    return from_door(Door(url, token, timeout=timeout))


def from_door(door: Door) -> list[Any]:
    try:
        from crewai.tools import BaseTool
        from pydantic import PrivateAttr
    except ImportError as exc:  # pragma: no cover
        raise ImportError(f'CrewAI is not installed. pip install "{EXTRA}"') from exc
    from ._schema import model_from_schema

    class CarnetTool(BaseTool):  # type: ignore[misc,valid-type]
        _door: Any = PrivateAttr(default=None)
        _at_door: str = PrivateAttr(default="")

        def _run(self, **arguments: Any) -> str:
            given = {k: v for k, v in arguments.items() if v is not None}
            try:
                result = self._door.call(self._at_door, given)
            except DoorRefused as exc:
                return exc.message
            return result.relay

    made = []
    for spec in door.tools():
        tool = CarnetTool(
            name=spec.name,
            description=spec.description or spec.name,
            args_schema=model_from_schema(spec.name, spec.input_schema),
        )
        tool._door = door
        tool._at_door = spec.name
        made.append(tool)
    return made
