"""The protocol, against the stub door — both doors, the same scenarios.

What is worth asserting is the table in `_door.py`'s docstring: which answer becomes
which outcome. Each scenario is a plain function over a `Door` and the async twin calls
the same function with `await`, so the two cannot drift.
"""

from __future__ import annotations

import warnings

import pytest

from carnet_mcp import AsyncDoor, Door, DoorRefused, DoorUnavailable, ProtocolVersionWarning
from carnet_mcp._door import CALL_ID_META_KEY

from conftest import CALL_ID, DENIAL, TOKEN, URL, StubDoor


def sync_door(stub: StubDoor, token: str = TOKEN) -> Door:
    return Door(URL, token, client=stub.client())


def async_door(stub: StubDoor, token: str = TOKEN) -> AsyncDoor:
    return AsyncDoor(URL, token, client=stub.async_client())


# --- the handshake ---------------------------------------------------------------------


def test_initialize_runs_once_and_sends_the_initialized_notification(stub):
    door = sync_door(stub)
    door.tools()
    door.tools()
    door.call("jira_search_issues", {"project": "ACME"})
    assert stub.initializes == 1
    methods = [b.get("method") for b in stub.bodies]
    assert methods[:2] == ["initialize", "notifications/initialized"]
    assert "id" not in stub.bodies[1]
    assert door.server_info == {"name": "carnet", "version": "0.11.0"}
    # The negotiated revision goes on every request after the handshake, not before.
    assert "mcp-protocol-version" not in stub.requests[0].headers
    assert stub.requests[2].headers["mcp-protocol-version"] == "2025-06-18"


async def test_async_initialize_runs_once(stub):
    door = async_door(stub)
    await door.tools()
    await door.call("jira_search_issues", {"project": "ACME"})
    assert stub.initializes == 1
    assert door.server_info["name"] == "carnet"


def test_an_unknown_protocol_version_warns_and_continues():
    stub = StubDoor(protocol="2031-01-01")
    door = sync_door(stub)
    with pytest.warns(ProtocolVersionWarning, match="2031-01-01"):
        listed = door.tools()
    assert [t.name for t in listed] == ["jira_search_issues", "jira_create_issue"]
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        door.call("jira_search_issues", {"project": "ACME"})  # warned once, at the handshake


def test_a_known_protocol_version_does_not_warn(stub):
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        sync_door(stub).tools()


# --- the token is checked before dispatch, so the first call is the real check -------


def test_a_bad_token_is_refused_on_the_first_call_whatever_it_is(stub):
    door = sync_door(stub, token="art_m_wrong.nope")
    with pytest.raises(DoorRefused) as caught:
        door.tools()
    assert caught.value.status == 401
    assert caught.value.code is None
    assert "not a live token" in str(caught.value)
    assert stub.initializes == 0  # refused at initialize, before any method ran


async def test_async_bad_token(stub):
    with pytest.raises(DoorRefused) as caught:
        await async_door(stub, token="nope").call("jira_search_issues", {"project": "ACME"})
    assert caught.value.status == 401


# --- the tool list is the grant list, cached ------------------------------------------


def test_tools_carry_the_schema_and_are_fetched_once(stub):
    door = sync_door(stub)
    first = door.tools()
    second = door.tools()
    assert stub.lists == 1
    assert first == second
    assert first[0].name == "jira_search_issues"
    assert first[0].description == "Search issues in a project."
    assert first[0].input_schema["required"] == ["project"]
    first.append(None)  # a caller's copy, not the cache
    assert len(door.tools()) == 2


# --- a call: result, denial, ungranted, unavailable ------------------------------------


def test_a_result_carries_the_text_the_structure_and_the_call_id(stub):
    result = sync_door(stub).call("jira_search_issues", {"project": "ACME"})
    assert not result.is_error
    assert result.call_id == CALL_ID
    assert result.structured["issues"] == ["ACME-1", "ACME-2"]
    assert '"ACME-1"' in result.text
    assert result.relay == result.text
    sent = stub.bodies[-1]["params"]
    assert sent == {"name": "jira_search_issues", "arguments": {"project": "ACME"}}


def test_a_brokered_denial_is_a_result_not_an_exception(stub):
    stub.mode = "denied"
    result = sync_door(stub).call("jira_search_issues", {"project": "OTHER"})
    assert result.is_error
    assert result.call_id == CALL_ID
    # The door's sentence, not the JSON envelope it travelled in, and the id appended.
    assert result.sentence == f"{DENIAL} (carnet call {CALL_ID})"
    assert result.relay == result.sentence
    assert "denied_by" not in result.sentence


async def test_async_denial(stub):
    stub.mode = "denied"
    result = await async_door(stub).call("jira_search_issues", {"project": "OTHER"})
    assert result.is_error and result.sentence.endswith(f"(carnet call {CALL_ID})")


def test_an_ungranted_tool_is_refused_in_the_doors_words_with_no_call_id(stub):
    door = sync_door(stub)
    with pytest.raises(DoorRefused) as caught:
        door.call("github_merge", {})
    assert caught.value.code == -32602
    assert caught.value.status is None
    assert "provides a tool called 'github_merge'" in caught.value.message


def test_a_dead_door_is_unavailable(stub):
    stub.mode = "down"
    with pytest.raises(DoorUnavailable, match="could not reach the door"):
        sync_door(stub).tools()


async def test_async_dead_door(stub):
    stub.mode = "down"
    with pytest.raises(DoorUnavailable):
        await async_door(stub).tools()


def test_a_gateway_error_is_unavailable_not_a_refusal(stub):
    door = sync_door(stub)
    door.tools()
    stub.mode = "gateway"
    with pytest.raises(DoorUnavailable, match="502"):
        door.call("jira_search_issues", {"project": "ACME"})


def test_a_body_that_is_not_json_is_unavailable_and_says_to_check_the_address(stub):
    door = sync_door(stub)
    door.tools()
    stub.mode = "garbage"
    with pytest.raises(DoorUnavailable, match="/mcp address"):
        door.call("jira_search_issues", {"project": "ACME"})


def test_a_result_without_meta_has_no_call_id():
    from carnet_mcp._door import _call_from

    result = _call_from({"content": [{"type": "text", "text": "hi"}], "isError": False})
    assert result.call_id is None and result.text == "hi" and result.sentence == "hi"
    assert _call_from({"isError": True, "structuredContent": {"error": "no"}, "_meta": {CALL_ID_META_KEY: "door-1"}}).sentence == "no (carnet call door-1)"


# --- construction ----------------------------------------------------------------------


def test_construction_needs_both_and_never_shows_the_token(stub):
    with pytest.raises(ValueError):
        Door(URL, "")
    with pytest.raises(ValueError):
        AsyncDoor("", TOKEN)
    door = sync_door(stub)
    assert TOKEN not in repr(door)
    assert stub.initializes == 0  # constructing costs no request


def test_the_context_managers_close_only_a_client_they_made(stub):
    own = stub.client()
    with Door(URL, TOKEN, client=own) as door:
        door.tools()
    assert not own.is_closed
    made = Door(URL, TOKEN)
    made.close()
    assert made._client.is_closed


# --- the edge pass of 2026-09-20, each row found against a real door ------------------


def test_a_redirect_is_unavailable_and_names_the_address(stub):
    import httpx

    def redirecting(request):
        return httpx.Response(307, headers={"Location": URL})

    door = Door(URL + "/", TOKEN, client=httpx.Client(transport=httpx.MockTransport(redirecting)))
    with pytest.raises(DoorUnavailable, match=r"redirected initialize \(307\) to .*use that address"):
        door.tools()


@pytest.mark.parametrize("status", [404, 405])
def test_nothing_at_this_address_is_unavailable_not_a_refusal(stub, status):
    import httpx

    door = Door(URL, TOKEN, client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(status, text="Not Found"))))
    with pytest.raises(DoorUnavailable, match="is this the /mcp address"):
        door.tools()


def test_text_prefers_the_structured_half_without_ascii_escapes():
    from carnet_mcp._door import _call_from

    said = {"note": "café ☕"}
    result = _call_from({"content": [{"type": "text", "text": json_ascii(said)}], "structuredContent": said})
    assert "café ☕" in result.text and "\\u00e9" not in result.text
    # Only text blocks: joined as they are.
    assert _call_from({"content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]}).text == "a\nb"


def json_ascii(value):
    import json

    return json.dumps(value)  # ensure_ascii=True, the door's serialisation


def test_a_pasted_token_is_trimmed_and_whitespace_inside_is_refused(stub):
    door = Door(URL, f"  {TOKEN}\n", client=stub.client())
    door.tools()
    assert stub.requests[0].headers["authorization"] == f"Bearer {TOKEN}"
    # The whole header pasted as the token: the prefix is ours to add, not to send twice.
    Door(URL, f"Bearer {TOKEN}", client=stub.client()).tools()
    assert stub.requests[-1].headers["authorization"] == f"Bearer {TOKEN}"
    with pytest.raises(ValueError, match="whitespace"):
        Door(URL, "art_m_x.abc def")
    with pytest.raises(ValueError, match="whitespace"):
        AsyncDoor(URL, "art_m_x.abc\ndef")


def test_a_closed_door_is_unavailable_not_a_runtime_error(stub):
    door = Door(URL, TOKEN, client=stub.client())
    door.tools()
    door._client.close()  # as if the caller's own client was closed under it
    with pytest.raises(DoorUnavailable, match="closed"):
        door.call("jira_search_issues", {"project": "ACME"})


def test_an_async_door_survives_a_second_event_loop(stub, monkeypatch):
    """A sync agent calling `asyncio.run` per tool use closes a loop every call. The
    door owns its client, so it replaces it on the new loop; the handshake is not
    repeated and the tool list survives."""
    import asyncio

    import httpx

    real = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(stub.handle)))
    door = AsyncDoor(URL, TOKEN)  # owns its client
    assert len(asyncio.run(door.tools())) == 2
    first = door._client
    assert not asyncio.run(door.call("jira_search_issues", {"project": "ACME"})).is_error
    assert door._client is not first
    assert stub.initializes == 1 and stub.lists == 1


async def test_a_borrowed_async_client_on_another_loop_says_so(stub):
    import asyncio

    door = AsyncDoor(URL, TOKEN, client=stub.async_client())
    await door.tools()

    def elsewhere():
        return asyncio.run(door.call("jira_search_issues", {"project": "ACME"}))

    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(1) as pool:
        with pytest.raises(DoorUnavailable, match="another"):
            pool.submit(elsewhere).result()
