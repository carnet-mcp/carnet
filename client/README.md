# carnet-mcp

The [Carnet](https://github.com/carnet-mcp/carnet) door, as a Python client. Three lines
from an agent framework to a tool list that is scoped to the token, called under a
credential the agent never holds, and audited per call.

```bash
pip install "carnet-mcp[langchain]"     # or [crewai], [autogen], [openai-agents]
```

```python
from carnet_mcp.langchain import tools

tools = tools("https://carnet.example.com/api/mcp", token)   # the URL on the connect card
agent = create_agent(model, tools)
```

The same for the others: `carnet_mcp.crewai.tools(url, token)` returns CrewAI tools;
`await carnet_mcp.openai_agents.tools(url, token)` returns `FunctionTool`s for the OpenAI
Agents SDK; `await carnet_mcp.autogen.tools(url, token)` returns AutoGen tools. Each
framework is an extra and is imported only by its own module. The bare install pulls
`httpx` and nothing else.

`token` is a Carnet access token — a service token granted one agent is the right shape
for a process: the agent's scope is the process's reach. Nothing else is configured here
and nothing is written to disk.

## What you get, and why it is shaped this way

- **The door's sentence, relayed.** A call the token is not allowed comes back to the
  model on the framework's tool-error channel, in the door's own words, with the audit
  row's id appended — *denied: 'OTHER' is outside this agent's 'read' scope. Allowed:
  ACME (carnet call door-…)* — and never as an exception that ends the agent's turn. The
  model can say so, which is the outcome least privilege exists to produce. A door that
  did not answer at all raises `DoorUnavailable`, because that is not something a model
  adapts to.
- **One host.** This package makes HTTP requests to exactly one URL: the one you
  constructed it with. No telemetry, no version check, no anonymous anything. The test
  suite reads the source to assert there is no other address in it.
- **Fetched once, enforced always.** The tool list is read when the tools are built and
  cached for the life of the object, because that is what every framework's API does. A
  grant revoked while an agent is up may leave the tool in its list; the door refuses
  the call, uncached, as it always did, and the refusal is on the audit trail. Visibility
  goes stale; enforcement does not.
- **No retries.** A retried `tools/call` is a second brokered call with a second audit
  row and possibly a second side effect. `httpx`'s defaults and nothing more.

## Under the adapters

`carnet_mcp.Door` and `carnet_mcp.AsyncDoor` are the protocol itself, for a framework
not listed here or for code that is not a framework at all:

```python
from carnet_mcp import Door

with Door(url, token) as door:
    for tool in door.tools():            # name, description, input_schema
        ...
    result = door.call("jira_search_issues", {"project": "ACME"})
    result.text        # what the tool said
    result.is_error    # a brokered denial or a failed tool
    result.sentence    # the door's reason, with the call id
    result.call_id     # `door-<hex>`, the row on the door-calls page
```

Both take `timeout=` or your own `httpx` client (a proxy, a private CA, a pool).
`DoorRefused` is raised for a token the door does not accept and for a tool the token
is not granted; `DoorUnavailable` when the door did not answer — including a wrong
address (a 404, or a redirect, which this client does not follow) with a sentence saying
to check the `/mcp` URL. A pasted token is trimmed, and a whole `Bearer …` header pasted
as the token loses its prefix rather than being sent twice. An `AsyncDoor` that owns its
client survives a sync agent's `asyncio.run` per call; one given a borrowed client says
so if it is moved to another loop.

## Compatibility

**This client speaks to any Carnet door from 0.11.0 onward.** It is versioned separately
from the server on purpose — a client must talk to a range of self-hosted doors — and a
door speaking a protocol revision this client does not know produces one warning at the
handshake, not a refusal.

## Verified, and not yet

All four adapters have been run against a real door: the tool list, a call in scope
under the broker's credential, and a call outside scope returned to the framework as the
door's sentence with the call id. LangChain further has an end-to-end script
(`backend/scripts/e2e_client_langchain.py`) that drives its tools through LangChain's own
`invoke` and `ainvoke`, reads the denial as a `ToolMessage` with an error status, and
revokes the grant mid-session to watch the next call refused by name. What has not been
run here is an agent with a real model completing a task through any of the four; the
script has a flag for that half and says so.

Apache-2.0. Issues, the source and the reasoning behind every decision here are in the
[Carnet repository](https://github.com/carnet-mcp/carnet); the reasoning lives beside the
code it explains, so the module docstrings are the design record.
