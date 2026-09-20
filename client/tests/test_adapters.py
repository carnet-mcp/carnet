"""The adapters, against the stub door — shape conversion and the refusal channel.

The adapters are shape conversion and their real test is a real agent completing a real
call (`backend/scripts/e2e_client_langchain.py`). What the stub can hold in place is
cheaper and still worth it: the tool the framework sees has the door's name, description
and schema; a call round-trips the arguments; a denial reaches the framework's tool-error
channel in the door's words with the call id; an ungranted tool does the same; and the
door being down propagates, because that is not something a model adapts to.

Each file skips itself when its framework is absent — except LangChain, whose extra CI
installs, so that one fails rather than skips there.
"""

from __future__ import annotations

import asyncio

import pytest

from carnet_mcp import AsyncDoor, Door, DoorUnavailable

from conftest import CALL_ID, DENIAL, TOKEN, URL

UNGRANTED = "provides a tool called 'jira_search_issues'"


def doors(stub):
    return Door(URL, TOKEN, client=stub.client()), AsyncDoor(URL, TOKEN, client=stub.async_client())


# --- LangChain -------------------------------------------------------------------------


def test_langchain_tools_have_both_slots_and_relay_a_refusal_as_a_tool_error(stub):
    pytest.importorskip("langchain_core")
    from carnet_mcp.langchain import from_doors

    door, adoor = doors(stub)
    made = from_doors(door, adoor)
    assert [t.name for t in made] == ["jira_search_issues", "jira_create_issue"]
    search = made[0]
    assert search.description == "Search issues in a project."
    assert search.func is not None and search.coroutine is not None
    assert search.args_schema["required"] == ["project"]

    assert '"ACME-1"' in search.invoke({"project": "ACME"})
    assert stub.bodies[-1]["params"]["arguments"] == {"project": "ACME"}

    stub.mode = "denied"
    # `handle_tool_error=True`: the ToolException's text comes back as the tool's output
    # rather than raising through the agent — the model reads it.
    out = search.invoke({"project": "OTHER"})
    assert out == f"{DENIAL} (carnet call {CALL_ID})"
    stub.mode = "ungranted"
    assert UNGRANTED in search.invoke({"project": "ACME"})

    # The coroutine slot, on one loop: a borrowed AsyncClient (the stub's) cannot follow
    # a second `asyncio.run`; an owned one can (`test_door.py` covers that).
    async def through_the_coroutine():
        stub.mode = "ok"
        okay = await search.ainvoke({"project": "ACME"})
        stub.mode = "ungranted"
        refused = await search.ainvoke({"project": "ACME"})
        return okay, refused

    okay, refused = asyncio.run(through_the_coroutine())
    assert '"ACME-1"' in okay and UNGRANTED in refused

    stub.mode = "down"
    with pytest.raises(DoorUnavailable):
        search.invoke({"project": "ACME"})


def test_langchain_tool_message_carries_the_error_status(stub):
    pytest.importorskip("langchain_core")
    from carnet_mcp.langchain import from_doors

    door, adoor = doors(stub)
    search = from_doors(door, adoor)[0]
    stub.mode = "denied"
    message = search.invoke({"name": "jira_search_issues", "args": {"project": "OTHER"}, "id": "call_1", "type": "tool_call"})
    assert message.status == "error"
    assert DENIAL in message.content


# --- CrewAI ----------------------------------------------------------------------------


def test_crewai_tools_take_a_model_schema_and_return_a_refusal(stub):
    pytest.importorskip("crewai")
    from carnet_mcp.crewai import from_door

    door, _ = doors(stub)
    made = from_door(door)
    search = made[0]
    assert search.name == "jira_search_issues"
    fields = search.args_schema.model_fields
    assert fields["project"].is_required() and not fields["jql"].is_required()

    assert '"ACME-1"' in search.run(project="ACME")
    assert stub.bodies[-1]["params"]["arguments"] == {"project": "ACME"}
    stub.mode = "denied"
    assert search.run(project="OTHER") == f"{DENIAL} (carnet call {CALL_ID})"
    stub.mode = "ungranted"
    assert UNGRANTED in search.run(project="ACME")


# --- OpenAI Agents SDK -----------------------------------------------------------------


async def test_openai_agents_function_tools(stub):
    pytest.importorskip("agents")
    from carnet_mcp.openai_agents import from_door

    _, adoor = doors(stub)
    made = await from_door(adoor)
    search = made[0]
    assert search.name == "jira_search_issues"
    assert search.params_json_schema["required"] == ["project"]
    assert search.strict_json_schema is False

    assert '"ACME-1"' in await search.on_invoke_tool(None, '{"project": "ACME"}')
    assert stub.bodies[-1]["params"]["arguments"] == {"project": "ACME"}
    stub.mode = "denied"
    assert await search.on_invoke_tool(None, '{"project": "OTHER"}') == f"{DENIAL} (carnet call {CALL_ID})"
    stub.mode = "ungranted"
    assert UNGRANTED in await search.on_invoke_tool(None, "{}")


# --- AutoGen ---------------------------------------------------------------------------


async def test_autogen_tools(stub):
    pytest.importorskip("autogen_core")
    from autogen_core import CancellationToken

    from carnet_mcp.autogen import from_door

    _, adoor = doors(stub)
    made = await from_door(adoor)
    search = made[0]
    assert search.name == "jira_search_issues"
    assert search.schema["parameters"]["required"] == ["project"]

    said = await search.run_json({"project": "ACME"}, CancellationToken())
    assert '"ACME-1"' in search.return_value_as_string(said)
    assert stub.bodies[-1]["params"]["arguments"] == {"project": "ACME"}
    stub.mode = "denied"
    said = await search.run_json({"project": "OTHER"}, CancellationToken())
    assert search.return_value_as_string(said) == f"{DENIAL} (carnet call {CALL_ID})"
