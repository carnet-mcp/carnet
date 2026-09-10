"""The OpenAI-compatible surface — step 108, sequencing item 3.

What these pin is the translation on each side of one brokered call: both SDK dialects
in, the vendor's answer out byte for byte, and every refusal in the error dialect an SDK
raises on. The door and the broker are not re-tested here — `test_door.py` and
`test_broker.py` own them — except at the seam where a refusal has to arrive wearing
OpenAI's clothes.

The vendor is `test_rest.py`'s fake: `rest._request` replaced by a recorder that answers
queued responses, streamed or whole. `scripts/e2e_openai_surface.py` drives the real
`openai` package against a real socket; this file is the unit half.
"""

import json

import pytest
from fastapi.testclient import TestClient

from carnet import agents, config, storage, tools
from carnet.access import tokens
from carnet.api import create_app
from carnet.tools import rest
from carnet.tools.base import Resource
from conftest import TEST_ACTOR, TEST_HOST, TEST_TENANT, read_audit
from test_rest import FakeHttp, FakeStream, sse

FOUNDRY = f"https://{TEST_HOST}"
OWNER = "u-priya"

CHAT_SCHEMA = {
    "type": "object",
    "properties": {
        "model": {"type": "string"},
        "api-version": {"type": "string"},
        "messages": {"type": "array"},
        "stream": {"type": "boolean"},
        "stream_options": {"type": "object"},
        "temperature": {"type": "number"},
        "max_tokens": {"type": "integer"},
        "tools": {"type": "array"},
        "tool_choice": {},
    },
    "required": ["model", "messages"],
}
CHAT_BINDING = {
    "method": "POST",
    "path": "/openai/deployments/{model}/chat/completions",
    "query": ["api-version"],
    "body": ["messages", "stream", "stream_options", "temperature", "max_tokens", "tools",
             "tool_choice"],
    "input_schema": CHAT_SCHEMA,
    "usage_map": {
        "model": "model",
        "input_tokens": "usage.prompt_tokens",
        "output_tokens": "usage.completion_tokens",
    },
}
EMBED_BINDING = {
    "method": "POST",
    "path": "/openai/deployments/{model}/embeddings",
    "query": ["api-version"],
    "body": ["input"],
    "input_schema": {
        "type": "object",
        "properties": {"model": {"type": "string"}, "api-version": {"type": "string"},
                       "input": {}},
        "required": ["model", "input"],
    },
    "usage_map": {"model": "model", "input_tokens": "usage.prompt_tokens"},
}
DEPLOYMENT = Resource("azure.deployment", "model")

PROMPT = {"messages": [{"role": "user", "content": "the secret prompt"}]}


def _reply(**overrides):
    return {
        "id": "chatcmpl-1", "object": "chat.completion", "model": "gpt-4o-2024-08-06",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 12, "completion_tokens": 3, "total_tokens": 15},
        **overrides,
    }


@pytest.fixture
def http(monkeypatch):
    fake = FakeHttp(FakeStream([json.dumps(_reply()).encode()], content_type="application/json"))
    monkeypatch.setattr(rest, "_request", fake)
    return fake


@pytest.fixture
def foundry(isolated_storage, monkeypatch):
    """A model connector vetted the way the recipe vets it, and an engineer's token
    granted a permission list that admits one deployment."""
    monkeypatch.setenv("AZURE_OPENAI_KEY", "azure-secret-key")
    tools.register_connector(
        TEST_TENANT, "foundry", url=FOUNDRY, kind="rest",
        credential_env="AZURE_OPENAI_KEY", description="Azure AI Foundry.", actor=TEST_ACTOR,
    )
    tools.vet_tool(
        TEST_TENANT, "foundry", "chat_completions", effect="write", resources=(DEPLOYMENT,),
        binding=CHAT_BINDING, description="A chat completion.", actor=TEST_ACTOR,
        redact_args=("messages",), max_response_bytes=100_000,
    )
    tools.vet_tool(
        TEST_TENANT, "foundry", "embeddings", effect="write", resources=(DEPLOYMENT,),
        binding=EMBED_BINDING, description="An embedding.", actor=TEST_ACTOR,
        redact_args=("input",),
    )
    storage.active().create_user(
        TEST_TENANT,
        {"id": OWNER, "issuer": "https://idp.example", "subject": "00u1", "email": "priya@acme.com"},
    )
    agents.save(
        TEST_TENANT,
        {
            "name": "coding-agent",
            "system": "irrelevant",
            "runtime": "simple",
            "permissions": {
                "tools": ["foundry_chat_completions", "foundry_embeddings"],
                "scope": {"azure.deployment": {"write": ["gpt-4o-prod", "text-embedding-3-small"]}},
            },
        },
        actor=TEST_ACTOR,
    )
    row, presented = tokens.mint(TEST_TENANT, "coding-agent", OWNER, actor="system:cli",
                                 acts_as_owner=True)
    storage.active().grant_agent(
        TEST_TENANT, "coding-agent", "user", OWNER, role="user", granted_by=TEST_ACTOR,
        actor=TEST_ACTOR,
    )
    return row, presented


@pytest.fixture
def client():
    return TestClient(create_app())


@pytest.fixture
def azure(foundry):
    _, presented = foundry
    return {"api-key": presented}


@pytest.fixture
def bearer(foundry):
    _, presented = foundry
    return {"Authorization": f"Bearer {presented}"}


def azure_url(deployment="gpt-4o-prod", kind="chat/completions"):
    return f"/openai/deployments/{deployment}/{kind}?api-version=2024-10-21"


def last_row():
    return [r for r in read_audit() if r["tool"].startswith("foundry_")][-1]


# --- both dialects, one call ---------------------------------------------------------


def test_the_azure_shape_carries_the_deployment_and_the_api_version(client, azure, http):
    response = client.post(azure_url(), headers=azure, json=PROMPT)

    assert response.status_code == 200, response.text
    assert response.json() == _reply()
    sent = http.calls[-1]
    assert sent["url"] == f"{FOUNDRY}/openai/deployments/gpt-4o-prod/chat/completions"
    assert sent["params"] == {"api-version": "2024-10-21"}
    assert sent["json"]["messages"] == PROMPT["messages"]
    # Under whatever header the connector's launch was registered with — the recipe
    # sets `api-key`; this fixture took the default — and never the caller's token.
    assert any("azure-secret-key" in str(v) for v in sent["headers"].values())
    assert not any("art_" in str(v) for v in sent["headers"].values())


def test_the_openai_shape_takes_the_model_from_the_body_and_the_bearer_header(client, bearer, http):
    response = client.post("/v1/chat/completions", headers=bearer,
                           json={**PROMPT, "model": "gpt-4o-prod"})

    assert response.status_code == 200, response.text
    assert response.json() == _reply()
    assert http.calls[-1]["url"].endswith("/openai/deployments/gpt-4o-prod/chat/completions")
    # No api-version was sent, so none is invented (S24).
    assert http.calls[-1]["params"] == {}


def test_the_body_comes_back_byte_for_byte(client, azure, monkeypatch):
    """S4. Not re-serialised, not re-ordered, not re-indented: the SDK's `choices[0]`
    is the vendor's own bytes."""
    body = b'{"choices":[{"message":{"content":"x"}}],"usage":{"prompt_tokens":1},"model":"m","odd":  1}'
    monkeypatch.setattr(rest, "_request", FakeHttp(FakeStream([body], content_type="application/json")))

    response = client.post(azure_url(), headers=azure, json=PROMPT)

    assert response.content == body
    assert response.headers["content-type"] == "application/json"


def test_the_row_carries_the_usage_and_never_the_prompt(client, azure, http):
    """Decision 10. The tool was vetted to redact `messages`; the surface redacts it
    regardless, and `tools` with it. The counters and the served model land on the row."""
    client.post(azure_url(), headers=azure, json={**PROMPT, "tools": [{"type": "function", "function": {"name": "secret_tool"}}], "temperature": 0.2})

    row = last_row()
    assert (row["decision"], row["outcome"]) == ("allow", "ok")
    assert (row["model"], row["input_tokens"], row["output_tokens"]) == ("gpt-4o-2024-08-06", 12, 3)
    args = json.dumps(row["args"])
    assert "secret prompt" not in args and "secret_tool" not in args
    assert row["args"]["model"] == "gpt-4o-prod"
    assert row["args"]["temperature"] == 0.2
    assert row["run_id"].startswith("door-")


def test_the_sdks_own_headers_never_reach_the_vendor(client, azure, http):
    """S23. Nothing about the engineer's SDK version, organisation or client reaches
    Foundry: the REST tool builds its own headers from the binding and the credential."""
    client.post(azure_url(), headers={**azure, "x-stainless-lang": "python",
                                       "OpenAI-Organization": "org-1", "User-Agent": "agent/1"},
                json=PROMPT)

    sent = http.calls[-1]["headers"]
    assert not any(k.lower().startswith("x-stainless") for k in sent)
    assert "OpenAI-Organization" not in sent and "User-Agent" not in sent


def test_tool_calling_is_forwarded_untouched(client, azure, http):
    """S22. The request's `tools` and `tool_choice` travel; the response's `tool_calls`
    come back as sent. Carnet governs the model call and records nothing of the tools the
    model chose."""
    reply = _reply(choices=[{"message": {"tool_calls": [{"id": "call_1", "function": {"name": "read_file"}}]}}])
    http.responses = [FakeStream([json.dumps(reply).encode()], content_type="application/json")]

    response = client.post(azure_url(), headers=azure, json={
        **PROMPT, "tools": [{"type": "function", "function": {"name": "read_file"}}],
        "tool_choice": "auto",
    })

    assert response.json()["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "read_file"
    assert http.calls[-1]["json"]["tools"][0]["function"]["name"] == "read_file"
    assert http.calls[-1]["json"]["tool_choice"] == "auto"


# --- streaming -----------------------------------------------------------------------


def test_a_streamed_answer_is_relayed_chunk_for_chunk_with_usage_injected(client, azure, http):
    """S5. `stream_options.include_usage` goes out on every streamed request that did not
    set it; the SSE comes back as sent; the usage object in the final chunk is what the
    row records."""
    chunks = sse(
        {"model": "gpt-4o-2024-08-06", "choices": [{"delta": {"content": "hel"}}], "usage": None},
        {"model": "gpt-4o-2024-08-06", "choices": [{"delta": {"content": "lo"}}], "usage": None},
        {"model": "gpt-4o-2024-08-06", "choices": [], "usage": {"prompt_tokens": 9, "completion_tokens": 2}},
    )
    http.responses = [FakeStream(chunks)]

    with client.stream("POST", azure_url(), headers=azure, json={**PROMPT, "stream": True}) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        received = b"".join(response.iter_bytes())

    assert received == b"".join(chunks)
    assert http.calls[-1]["json"]["stream_options"] == {"include_usage": True}
    row = last_row()
    assert (row["outcome"], row["model"], row["input_tokens"], row["output_tokens"]) == ("ok", "gpt-4o-2024-08-06", 9, 2)
    assert row["args"]["stream"] is True


def test_a_clients_own_stream_options_keep_their_keys(client, azure, http):
    http.responses = [FakeStream(sse({}))]

    client.post(azure_url(), headers=azure, json={**PROMPT, "stream": True,
                                                  "stream_options": {"include_obfuscation": False}})

    assert http.calls[-1]["json"]["stream_options"] == {"include_obfuscation": False, "include_usage": True}


def test_a_stream_past_the_byte_cap_ends_with_an_error_event_and_done(client, azure, http, monkeypatch):
    """S7. The bytes up to the cap are already on the wire and cannot be un-sent; what
    the client is owed is a terminal event it knows how to read, then `[DONE]`. The row
    says `oversize`."""
    tools.vet_tool(
        TEST_TENANT, "foundry", "chat_completions", effect="write", resources=(DEPLOYMENT,),
        binding=CHAT_BINDING, description="A chat completion.", actor=TEST_ACTOR,
        redact_args=("messages",), max_response_bytes=30,
    )
    http.responses = [FakeStream([b"data: " + b"x" * 20 + b"\n\n"] * 5)]

    with client.stream("POST", azure_url(), headers=azure, json={**PROMPT, "stream": True}) as response:
        received = b"".join(response.iter_bytes())

    events = received.split(b"\n\n")
    assert events[0] == b"data: " + b"x" * 20
    assert json.loads(events[1][6:])["error"]["code"] == "response_too_large"
    assert events[2] == b"data: [DONE]"
    assert last_row()["outcome"] == "oversize"


def test_a_stall_mid_stream_ends_with_the_brokers_sentence(client, azure, http):
    """S11 on the wire: the chunks that arrived, then an error event naming the stall,
    then `[DONE]`; the row says `error`."""
    import requests

    http.responses = [FakeStream([b"data: {}\n\n"], raise_after=requests.exceptions.ReadTimeout())]

    with client.stream("POST", azure_url(), headers=azure, json={**PROMPT, "stream": True}) as response:
        received = b"".join(response.iter_bytes())

    events = received.split(b"\n\n")
    assert events[0] == b"data: {}"
    error = json.loads(events[1][6:])["error"]
    assert error["code"] == "upstream_unavailable" and "stopped sending" in error["message"]
    assert last_row()["outcome"] == "error"


# --- refusals, in the dialect ---------------------------------------------------------


def error_of(response):
    body = response.json()
    assert set(body) == {"error"}, body
    return body["error"]


def test_no_token_is_401_invalid_api_key(client, foundry):
    response = client.post("/v1/chat/completions", json={**PROMPT, "model": "gpt-4o-prod"})
    assert response.status_code == 401
    assert error_of(response)["code"] == "invalid_api_key"


def test_a_revoked_token_is_401_in_the_dialect(client, foundry, azure):
    row, _ = foundry
    tokens_store = storage.active()
    tokens_store.revoke_api_token(TEST_TENANT, row["id"], actor=TEST_ACTOR)

    response = client.post(azure_url(), headers=azure, json=PROMPT)

    assert response.status_code == 401
    assert error_of(response) == {"message": "not a valid token for this service",
                                  "type": "authentication_error", "code": "invalid_api_key",
                                  "param": None}


def test_a_disabled_owner_is_403_account_deactivated(client, foundry, azure):
    """S14. The agent reads this and stops; it does not re-mint."""
    storage.active().set_user_status(TEST_TENANT, OWNER, "disabled", actor=TEST_ACTOR)

    response = client.post(azure_url(), headers=azure, json=PROMPT)

    assert response.status_code == 403
    assert error_of(response)["code"] == "account_deactivated"


def test_a_deployment_outside_the_scope_is_403_and_nothing_is_dialled(client, azure, http):
    """S12. The sentence names the deployment and the pattern; the denial is recorded;
    the vendor never hears about it."""
    response = client.post(azure_url("gpt-4o-eu"), headers=azure, json=PROMPT)

    assert response.status_code == 403
    error = error_of(response)
    assert error["code"] == "insufficient_scope"
    assert "gpt-4o-eu" in error["message"]
    assert http.calls == []
    # The denial is a row: the route hands the call to the door and the broker refuses
    # it, audited, rather than deciding it here where the log would never see it.
    denied = [r for r in read_audit() if r["tool"] == "foundry_chat_completions"]
    assert [r["decision"] for r in denied] == ["deny"]
    assert denied[0]["args"]["model"] == "gpt-4o-eu"


def test_the_daily_ceiling_is_429_daily_limit_reached(client, azure, http, monkeypatch):
    """S13. The refusal is the broker's own sentence — the same one `--simulate` and the
    door log carry — under the code an SDK's backoff will not retry into all night."""
    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 1)
    http.responses = [FakeStream([json.dumps(_reply()).encode()], content_type="application/json")]

    assert client.post(azure_url(), headers=azure, json=PROMPT).status_code == 200
    response = client.post(azure_url(), headers=azure, json=PROMPT)

    assert response.status_code == 429
    error = error_of(response)
    assert (error["type"], error["code"]) == ("insufficient_quota", "daily_limit_reached")
    assert "CARNET_MCP_CALLS_PER_DAY" in error["message"]
    assert len(http.calls) == 1


def test_a_request_over_the_cap_is_413_before_anything_happens(client, azure, http, monkeypatch):
    """S9. Nothing dialled, no ceiling consumed."""
    monkeypatch.setattr(config, "MODEL_MAX_REQUEST_BYTES", 2_000)

    response = client.post(azure_url(), headers=azure,
                           json={"messages": [{"role": "user", "content": "x" * 5_000}]})

    assert response.status_code == 413
    assert error_of(response)["code"] == "request_too_large"
    assert http.calls == []
    assert storage.active().mcp_calls_spent(TEST_TENANT, OWNER, __import__("carnet.door", fromlist=["budget_window"]).budget_window()) == 0


def test_a_prompt_under_the_cap_is_accepted(client, azure, http):
    """S8: a megabyte of file context is an ordinary coding prompt."""
    response = client.post(azure_url(), headers=azure,
                           json={"messages": [{"role": "user", "content": "x" * 1_000_000}]})
    assert response.status_code == 200


def test_the_vendor_refusing_carnets_key_is_502_naming_the_connector(client, azure, http):
    """S18. The key is in no response and no row."""
    http.responses = [FakeStream([b'{"error": "bad key azure-secret-key"}'], status=401,
                                 content_type="application/json")]

    response = client.post(azure_url(), headers=azure, json=PROMPT)

    assert response.status_code == 502
    error = error_of(response)
    assert error["code"] == "upstream_credential_refused"
    assert "'foundry'" in error["message"] and "azure-secret-key" not in response.text
    row = last_row()
    assert row["outcome"] == "error" and "azure-secret-key" not in json.dumps(row)


def test_a_vendor_429_is_relayed_with_its_retry_after(client, azure, http):
    """S19. The SDK's own backoff works only on the vendor's body and header."""
    body = b'{"error": {"code": "429", "message": "Requests to the ChatCompletions_Create Operation have exceeded"}}'
    http.responses = [FakeStream([body], status=429, content_type="application/json",
                                 headers={"Retry-After": "7", "x-ms-request-id": "abc"})]

    response = client.post(azure_url(), headers=azure, json=PROMPT)

    assert response.status_code == 429
    assert response.content == body
    assert response.headers["retry-after"] == "7"
    assert "x-ms-request-id" not in response.headers
    assert last_row()["outcome"] == "error"


def test_a_content_filter_400_is_relayed_unchanged(client, azure, http):
    """S20."""
    body = b'{"error": {"code": "content_filter", "message": "filtered", "innererror": {"content_filter_result": {}}}}'
    http.responses = [FakeStream([body], status=400, content_type="application/json")]

    response = client.post(azure_url(), headers=azure, json=PROMPT)

    assert (response.status_code, response.content) == (400, body)


def test_a_vendor_that_did_not_answer_is_504(client, azure, http):
    import requests

    http.responses = [requests.exceptions.ReadTimeout()]

    response = client.post(azure_url(), headers=azure, json=PROMPT)

    assert response.status_code == 504
    assert error_of(response)["code"] == "upstream_unavailable"


def test_a_parameter_the_vetting_did_not_admit_is_400_naming_it(client, azure, http):
    """The vetted schema is the contract. An argument outside it is refused with a
    sentence naming it — never dropped, so the agent's author is not told a value
    applied when it did not."""
    response = client.post(azure_url(), headers=azure, json={**PROMPT, "seed": 7})

    assert response.status_code == 400
    error = error_of(response)
    assert error["code"] == "unknown_parameter" and "seed" in error["message"]
    assert http.calls == []


def test_a_body_that_is_not_an_object_and_a_missing_model_are_400s(client, bearer, http):
    assert error_of(client.post("/v1/chat/completions", headers=bearer, json=[1]))["code"] == "invalid_body"
    assert error_of(client.post("/v1/chat/completions", headers=bearer, json=PROMPT))["code"] == "missing_model"
    assert http.calls == []


def test_a_token_granted_no_model_tool_is_told_what_to_ask_for(client, foundry, azure):
    storage.active().revoke_agent(TEST_TENANT, "coding-agent", "user", OWNER, actor=TEST_ACTOR)

    response = client.post(azure_url(), headers=azure, json=PROMPT)

    assert response.status_code == 403
    error = error_of(response)
    assert error["code"] == "insufficient_scope" and "--from-recipe azure-openai" in error["message"]


def test_the_legacy_and_unoffered_endpoints_are_404_in_the_dialect(client, azure):
    for path in ("/v1/completions", "/v1/audio/speech", "/v1/files", "/openai/deployments/x/images/generations"):
        response = client.post(path, headers=azure, json={})
        assert response.status_code == 404, path
        assert error_of(response)["code"] == "not_offered"


# --- embeddings and the models list ----------------------------------------------------


def test_embeddings_travel_the_same_way_and_record_only_the_prompt_tokens(client, azure, http):
    reply = {"object": "list", "data": [{"embedding": [0.1, 0.2]}], "model": "text-embedding-3-small",
             "usage": {"prompt_tokens": 4, "total_tokens": 4}}
    http.responses = [FakeStream([json.dumps(reply).encode()], content_type="application/json")]

    response = client.post(azure_url("text-embedding-3-small", "embeddings"), headers=azure,
                           json={"input": "the secret file"})

    assert response.status_code == 200 and response.json() == reply
    row = last_row()
    assert (row["tool"], row["input_tokens"], row["output_tokens"]) == ("foundry_embeddings", 4, 0)
    assert "secret file" not in json.dumps(row["args"])


def test_the_models_list_is_the_scope_in_openais_shape(client, azure, bearer):
    """S21. The deployments this token may reach — the grant, not Foundry's catalogue."""
    for headers, path in ((azure, "/openai/models?api-version=2024-10-21"), (bearer, "/v1/models")):
        response = client.get(path, headers=headers)
        assert response.status_code == 200
        body = response.json()
        assert body["object"] == "list"
        assert [m["id"] for m in body["data"]] == ["gpt-4o-prod", "text-embedding-3-small"]
        assert {m["owned_by"] for m in body["data"]} == {"foundry"}
        assert all(m["object"] == "model" for m in body["data"])


def test_the_models_list_writes_no_row(client, azure):
    client.get("/v1/models", headers=azure)
    assert [r for r in read_audit() if r["tool"].startswith("foundry_")] == []


# --- the route table ------------------------------------------------------------------


def test_every_openai_route_is_sync():
    import inspect

    from carnet.api import routes_openai

    for route in routes_openai.router.routes:
        assert not inspect.iscoroutinefunction(route.endpoint), route.path


# --- the shipped recipe -----------------------------------------------------------------
#
# Step 108, item 5. The surface recognises a tool by the request it makes, and the
# `azure-openai` recipe is what vets that request; the two are built to meet here.


@pytest.fixture
def from_recipe(isolated_storage, monkeypatch):
    """The admin's hour, through the production functions the CLI calls: the connector
    from the recipe with the admin's own resource, every tool from its proposal."""
    from carnet.access import recipes

    recipe = recipes.load("azure-openai")
    monkeypatch.setenv("AZURE_OPENAI_KEY", "azure-secret-key")
    preset = recipe["connector"]
    tools.register_connector(
        TEST_TENANT, "foundry", url=FOUNDRY, kind=preset["kind"],
        credential_env=preset["credential_env"], credential_header=preset["credential_header"],
        credential_prefix=preset["credential_prefix"], description=preset["description"],
        from_recipe=recipe["id"], actor=TEST_ACTOR,
    )
    for proposal in recipe["tools"]:
        tools.vet_tool(
            TEST_TENANT, "foundry", proposal["remote_name"], effect=proposal["effect"],
            identity=proposal["identity"],
            resources=tuple(
                Resource(type=r["type"], args=tuple(r["args"]), template=r.get("template"),
                         families=tuple(r.get("families") or ()))
                for r in proposal["resources"]
            ),
            binding=proposal["binding"], description=proposal["description"],
            note=proposal.get("note", ""), redact_args=tuple(proposal["redact_args"]),
            max_response_bytes=proposal.get("max_response_bytes"), actor=TEST_ACTOR,
        )
    storage.active().create_user(
        TEST_TENANT,
        {"id": OWNER, "issuer": "https://idp.example", "subject": "00u1", "email": "priya@acme.com"},
    )
    agents.save(
        TEST_TENANT,
        {"name": "coding-agent", "system": "irrelevant", "runtime": "simple",
         "permissions": {"tools": ["foundry_chat_completions", "foundry_embeddings", "foundry_list_models"],
                         "scope": {"azure.deployment": {"write": ["*"]}}}},
        actor=TEST_ACTOR,
    )
    row, presented = tokens.mint(TEST_TENANT, "coding-agent", OWNER, actor="system:cli", acts_as_owner=True)
    storage.active().grant_agent(TEST_TENANT, "coding-agent", "user", OWNER, role="user",
                                 granted_by=TEST_ACTOR, actor=TEST_ACTOR)
    return {"api-key": presented}


def test_the_recipes_tools_are_the_ones_the_surface_calls(client, from_recipe, http):
    """The connector's credential goes under `api-key` with no prefix, as Azure expects;
    the chat tool is found by its path; every documented parameter is accepted as sent;
    the row carries the served model, the counters and the cached tokens the recipe's
    `usage_map` names, and none of the prompt."""
    reply = _reply(usage={"prompt_tokens": 120, "completion_tokens": 8, "total_tokens": 128,
                          "prompt_tokens_details": {"cached_tokens": 100}})
    http.responses = [FakeStream([json.dumps(reply).encode()], content_type="application/json")]

    response = client.post(azure_url("gpt-4o-mini-prod"), headers=from_recipe, json={
        **PROMPT, "seed": 7, "temperature": 0.1, "response_format": {"type": "json_object"},
        "tools": [{"type": "function", "function": {"name": "read_file"}}], "user": "u1",
    })

    assert response.status_code == 200, response.text
    sent = http.calls[-1]
    assert sent["headers"]["api-key"] == "azure-secret-key"
    assert "Authorization" not in sent["headers"]
    assert sent["url"] == f"{FOUNDRY}/openai/deployments/gpt-4o-mini-prod/chat/completions"
    assert sent["json"]["seed"] == 7 and sent["json"]["tools"][0]["function"]["name"] == "read_file"
    row = last_row()
    assert (row["tool"], row["input_tokens"], row["output_tokens"], row["cache_read_tokens"]) == (
        "foundry_chat_completions", 120, 8, 100)
    assert "secret prompt" not in json.dumps(row["args"]) and "read_file" not in json.dumps(row["args"])


def test_the_recipes_cap_admits_a_long_completion(client, from_recipe, http):
    """4 MiB, not the 64 KiB default: a long answer is several hundred kilobytes."""
    body = json.dumps(_reply(choices=[{"message": {"content": "x" * 300_000}}])).encode()
    http.responses = [FakeStream([body], content_type="application/json")]

    response = client.post(azure_url(), headers=from_recipe, json=PROMPT)

    assert response.status_code == 200 and response.content == body


def test_the_recipes_prices_reach_the_overview(client, from_recipe, http):
    """The price table on the binding is what `door_spend_today` prices with, so the
    served model's family is found longest-key-first: `gpt-4o-mini` before `gpt-4o`."""
    from carnet import door
    from carnet.core import Principal

    reply = _reply(model="gpt-4o-mini-2024-07-18", usage={"prompt_tokens": 1_000_000, "completion_tokens": 0, "total_tokens": 1_000_000})
    http.responses = [FakeStream([json.dumps(reply).encode()], content_type="application/json")]
    client.post(azure_url("gpt-4o-mini-prod"), headers=from_recipe, json=PROMPT)

    (token,) = [t for t in storage.active().list_api_tokens(TEST_TENANT) if t["name"] == "coding-agent"]
    spent = door.door_spend_today(Principal.machine(token["id"], TEST_TENANT))
    assert spent["usd"] == pytest.approx(0.15)
    assert spent["unpriced_models"] == []


def test_the_models_list_from_the_recipe_is_the_wildcard(client, from_recipe):
    """Known limit: a scope of `*` answers the wildcard, because Carnet does not
    enumerate Foundry. The SDK tolerates it."""
    body = client.get("/v1/models", headers=from_recipe).json()
    assert [m["id"] for m in body["data"]] == ["*"]


# --- what the edge pass found ----------------------------------------------------------
#
# Three defects, all from driving the surface the way a company's agent drives it rather
# than the way a test does. Each is one assertion here because each was silent: the
# calls succeeded or failed plausibly, and only the audit table showed the hole.


def _brokered_rows():
    return [r for r in read_audit() if r["tool"].startswith("foundry_")]


def test_a_vendor_that_never_answered_still_writes_a_row(client, azure, http):
    """**The claim this product sells is that a routed call is recorded**, and this path
    spent the budget, resolved the credential and left the log empty. `_relay` raised
    before anything iterated the `Streamed`, so the broker's row — written when the
    iteration ends — was never written at all. The route closes it now, on every exit."""
    import requests

    http.responses = [requests.exceptions.ConnectTimeout()]

    response = client.post(azure_url(), headers=azure, json=PROMPT)

    assert response.status_code in (502, 504)
    row = _brokered_rows()[-1]
    assert (row["decision"], row["outcome"]) == ("allow", "error")
    assert "did not accept a connection in time" in row["reason"]
    assert row["response_bytes"] == 0


def test_a_streamed_call_that_never_began_still_writes_a_row(client, azure, http):
    """The same hole on the streamed path, where the answer never started arriving."""
    import requests

    http.responses = [requests.exceptions.ConnectTimeout()]

    response = client.post(azure_url(), headers=azure, json={**PROMPT, "stream": True})

    assert response.status_code in (502, 504)
    assert [r["outcome"] for r in _brokered_rows()] == ["error"]


def test_an_argument_the_tool_refuses_still_writes_a_row(client, azure, http):
    """A caller's mistake is still a call the door admitted: the grant was checked, the
    ceiling was charged and the credential was read before the tool refused the
    argument. The row is what says the attempt happened."""
    response = client.post(azure_url(), headers=azure, json={**PROMPT, "seed": 7})

    assert response.status_code == 400
    row = _brokered_rows()[-1]
    assert (row["decision"], row["outcome"]) == ("allow", "error")
    assert "does not accept seed" in row["reason"]
    assert http.calls == []


def test_text_the_audit_column_cannot_hold_is_refused_where_the_caller_is(client, azure, http):
    """**A lone surrogate is legal JSON and Postgres refuses it in jsonb.** Driven
    against a real database, such a call executed, the vendor was paid, and the audit
    insert then failed and was diverted to step 060's degraded-mode file — a gap in the
    table that any caller could open at will. It is a caller's own text, so it is
    refused before anything is dialled, with the position named."""
    body = json.dumps({**PROMPT, "model": "gpt-4o-\ud800"}).encode("utf-8", "surrogatepass")

    response = client.post("/v1/chat/completions", headers={**azure, "Content-Type": "application/json"},
                           content=body)

    assert response.status_code == 400
    error = error_of(response)
    assert error["code"] == "unencodable_text"
    # The position is named, and named precisely: `arguments.model` rather than `model`,
    # because the acting-for claim is checked in the same breath and a reader has to be
    # able to tell which half of the call is at fault.
    assert "unpaired surrogate" in error["message"]
    assert "at arguments.model" in error["message"]
    assert http.calls == []
    assert _brokered_rows() == []


def test_the_prompt_itself_may_hold_anything_because_it_is_hashed(client, azure, http):
    """The other half of that rule, and the one that keeps the product usable: a coding
    agent reading a file with `errors="surrogateescape"` puts undecodable bytes in its
    prompt, and the prompt is stored as a digest rather than as text. Refusing it would
    refuse the customer's actual traffic to protect a column it never reaches."""
    body = json.dumps({**PROMPT, "model": "gpt-4o-prod",
                       "messages": [{"role": "user", "content": "file\ud800bytes"}]}
                      ).encode("utf-8", "surrogatepass")

    response = client.post("/v1/chat/completions", headers={**azure, "Content-Type": "application/json"},
                           content=body)

    assert response.status_code == 200
    assert str(_brokered_rows()[-1]["args"]["messages"]).startswith("sha256:")


def test_a_deployment_name_cannot_splice_the_url_or_escape_the_scope(client, azure, http):
    """The scope is written against the deployment, so the deployment is the value worth
    attacking. Each of these is refused before anything is dialled — the path shape
    admits no `/`, and an encoded one makes the URL match no route at all."""
    for deployment, expected in (
        ("gpt-4o-eu", 403),                                  # simply not granted
        ("*", 403),                                          # the pattern, not a name
        ("GPT-4O-PROD", 403),                                # scope matching is exact
        ("gpt-4o-prod ", 403),                               # and not trimmed
        ("gpt-4o-prod%2F..%2Fgpt-4o-eu", 404),               # no route has two segments there
        ("..%2F..%2Fopenai%2Fdeployments%2Fgpt-4o-eu", 404),
    ):
        response = client.post(azure_url(deployment), headers=azure, json=PROMPT)
        assert response.status_code == expected, deployment
        assert set(response.json()) == {"error"}, deployment
    assert http.calls == []


def test_the_body_cannot_override_the_deployment_in_the_path(client, azure, http):
    """The Azure SDK sends the deployment in the path and some versions echo it in the
    body. The path is what the scope was checked against, so the path is what travels."""
    response = client.post(azure_url("gpt-4o-prod"), headers=azure,
                           json={**PROMPT, "model": "gpt-4o-eu"})

    assert response.status_code == 200
    assert http.calls[-1]["url"].endswith("/deployments/gpt-4o-prod/chat/completions")
    assert _brokered_rows()[-1]["args"]["model"] == "gpt-4o-prod"


def test_a_vendor_cannot_report_its_own_spend(client, azure, http):
    """`_lift_usage` clears the reserved key unconditionally, and this is the reason:
    the vendor's body is the result, so a vendor putting our key in it would be metering
    itself — and a counter that big would spend somebody's whole allowance."""
    http.responses = [FakeStream(
        [json.dumps({**_reply(), "carnet_reported_usage": {"input_tokens": 10 ** 9}}).encode()],
        content_type="application/json")]

    client.post(azure_url(), headers=azure, json=PROMPT)

    assert _brokered_rows()[-1]["input_tokens"] == 12


def test_a_vendors_impossible_counters_are_dropped_whole(client, azure, http):
    """`parse_report`'s refusal, reached through this surface: a negative or an absurd
    count is a claim on somebody's daily allowance, and the row says nothing rather
    than something wrong."""
    for usage in ({"prompt_tokens": -5, "completion_tokens": 1},
                  {"prompt_tokens": 10 ** 15, "completion_tokens": 1}):
        http.responses = [FakeStream([json.dumps(_reply(usage=usage)).encode()],
                                     content_type="application/json")]
        client.post(azure_url(), headers=azure, json=PROMPT)
        assert _brokered_rows()[-1]["input_tokens"] is None
