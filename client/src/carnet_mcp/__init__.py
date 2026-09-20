"""`carnet-mcp` — the Carnet door, as a Python client.

    pip install "carnet-mcp[langchain]"

    from carnet_mcp.langchain import tools
    tools = tools(door_url, token)   # the MCP server URL on the connect card, and an access token

Three lines from an agent framework to a tool list that is scoped to the token, called
under a credential the agent never holds, and audited per call. The frameworks are
LangChain, CrewAI, AutoGen and the OpenAI Agents SDK, one module each, and each is an
extra: the bare install pulls `httpx` and nothing else.

Under the adapters is `Door` and `AsyncDoor`, the protocol itself — `initialize`,
`tools/list`, `tools/call` — for anyone wiring a framework not listed here. Each module
here carries its own argument in its docstring, and the short form is:

- **The door's sentence, relayed.** A refusal reaches the model in the door's own words
  on the framework's tool-error channel, with the audit row's id appended, and never as
  an exception that ends the agent's turn. See `errors.py`.
- **One host.** This package makes HTTP requests to exactly one URL: the one it was
  constructed with. No telemetry, no version check, nothing anonymous. The test suite
  asserts it, and a reviewer can check it by grep.
- **Fetched once, enforced always.** The tool list is read at construction and cached
  for the life of the object, because that is what every framework's API does. A tool
  revoked while an agent is up may stay in its list; the door refuses the call, uncached,
  and the refusal is on the audit trail. Visibility goes stale; enforcement does not.
"""

from ._door import AsyncDoor, CallResult, Door, Tool
from ._version import __version__
from .errors import DoorError, DoorRefused, DoorUnavailable, ProtocolVersionWarning

__all__ = [
    "AsyncDoor",
    "CallResult",
    "Door",
    "DoorError",
    "DoorRefused",
    "DoorUnavailable",
    "ProtocolVersionWarning",
    "Tool",
    "__version__",
]
