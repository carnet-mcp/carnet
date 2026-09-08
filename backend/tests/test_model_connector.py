"""The model connector — step 045c. Two providers, brokered like anything else.

The premise this file exists to hold is a negative one: **there is nothing
model-specific in the platform.** A model API is a REST API (045a), a model name is a
resource, token usage is a field in a response body (045b), and a rate is a line in the
operator's own file (045c). So every test below drives *two* vendors with deliberately
different shapes — one presenting its credential as `x-api-key` with no prefix and
counting `usage.input_tokens`, the other as `Authorization: Bearer` counting
`usage.prompt_tokens` — and asserts that the door, the broker, the scope matcher and the
meter treat them identically and keep them apart.

Two providers rather than one is the whole design of the file. A single fixture would
pass just as well against a platform that had quietly special-cased a vendor, and the
cross-provider leak in `test_a_wildcard_on_one_provider_cannot_reach_another` is a real
authorization question that cannot be asked with one.

Nothing opens a socket: `rest._request` is the seam, monkeypatched per test, resolved per
call so a tool bound before the patch still reaches it. The recipe in the README is what
was run against real vendors by hand.
"""

import json

import pytest
from fastapi.testclient import TestClient

from carnet import agents, config, door, storage, tools
from carnet.access import tokens
from carnet.api import create_app
from carnet.core.usage import TokenUsage, estimate_cost, model_family
from carnet.core.usage import RATES as RATES_BUILT_IN
from carnet.core.usage import price_buckets
from carnet.core import Principal
from carnet.tools import mcp, rest
from carnet.tools.base import Resource

from conftest import TEST_ACTOR, TEST_TENANT, read_audit

OWNER = "u-priya"

# Two vendors, two hosts. Neither is a real one: an allowlisted host in a test is a
# fixture, and naming `api.openai.com` here would make a suite that pretends to have
# dialled it.
OPENAI_HOST = "api.openai.example"
ANTHROPIC_HOST = "api.anthropic.example"
OPENAI_URL = f"https://{OPENAI_HOST}"
ANTHROPIC_URL = f"https://{ANTHROPIC_HOST}"

# The authored schema, which is the same shape for both vendors because the chat
# completion request is the same shape for both vendors. `model` is the scoped argument;
# `messages` is the prompt and is what `redact_args` keeps out of the log.
CHAT_SCHEMA = {
    "type": "object",
    "properties": {
        "model": {"type": "string", "description": "The model id to think with."},
        "messages": {"type": "array", "description": "The conversation so far."},
        "max_tokens": {"type": "integer"},
    },
    "required": ["model", "messages"],
}

OPENAI_BINDING = {
    "method": "POST",
    "path": "/v1/chat/completions",
    "body": ["model", "messages", "max_tokens"],
    "input_schema": CHAT_SCHEMA,
    # OpenAI's spelling. The counters are ours; the paths are theirs.
    "usage_map": {
        "model": "model",
        "input_tokens": "usage.prompt_tokens",
        "output_tokens": "usage.completion_tokens",
    },
}

ANTHROPIC_BINDING = {
    "method": "POST",
    "path": "/v1/messages",
    "body": ["model", "messages", "max_tokens"],
    "input_schema": CHAT_SCHEMA,
    # A different vendor's spelling of the same four numbers, which is the entire
    # difference between the two connectors as far as the meter is concerned.
    "usage_map": {
        "model": "model",
        "input_tokens": "usage.input_tokens",
        "output_tokens": "usage.output_tokens",
        "cache_read_tokens": "usage.cache_read_input_tokens",
        "cache_write_tokens": "usage.cache_creation_input_tokens",
    },
}

# An operator's own rate file, as a table. Keyed by *their* model ids, which is what
# 045c made reachable — before it, both keys here were unreachable and both providers
# priced at nothing.
RATES = {
    "gpt-5": {"input": 1.0, "output": 4.0, "cache_read": 0.1, "cache_write": 0.0},
    "claude-opus-5": {"input": 15.0, "output": 75.0, "cache_read": 1.5, "cache_write": 18.75},
}

A_PROMPT = [{"role": "user", "content": "what did the deploy change?"}]


class FakeResponse:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        body = json.dumps(payload if payload is not None else {})
        self.text = body
        self.content = body.encode()
        self.headers = {"Content-Type": "application/json"}

    def json(self):
        return json.loads(self.text)


class FakeVendors:
    """Both endpoints behind one seam, answering by URL.

    Keyed on the host rather than queued in order, because the tests that matter here
    call one provider and assert the *other* was never dialled — a queue would answer
    whichever call arrived and hide exactly that.
    """

    def __init__(self, openai=None, anthropic=None):
        self.calls = []
        self.answers = {
            OPENAI_HOST: openai or openai_reply(),
            ANTHROPIC_HOST: anthropic or anthropic_reply(),
        }

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        host = kwargs["url"].split("/")[2]
        return FakeResponse(payload=self.answers[host])

    def sent_to(self, host):
        return [call for call in self.calls if call["url"].split("/")[2] == host]


def openai_reply(model="gpt-5-mini", prompt=120, completion=30):
    return {
        "model": model,
        "choices": [{"message": {"role": "assistant", "content": "it bumped the image"}}],
        "usage": {"prompt_tokens": prompt, "completion_tokens": completion},
    }


def anthropic_reply(model="claude-opus-5", input_tokens=200, output_tokens=40):
    return {
        "model": model,
        "content": [{"type": "text", "text": "it bumped the image"}],
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
    }


@pytest.fixture
def vendors(monkeypatch):
    fake = FakeVendors()
    monkeypatch.setattr(rest, "_request", fake)
    return fake


@pytest.fixture
def registered(isolated_storage, monkeypatch):
    """Both providers, registered and vetted through the production path.

    This is the README recipe, run as code: four commands per provider, and the only
    lines that differ between them are the ones a vendor's own documentation decides.
    """
    store = storage.active()
    store.allow_host(TEST_TENANT, OPENAI_HOST, actor=TEST_ACTOR)
    store.allow_host(TEST_TENANT, ANTHROPIC_HOST, actor=TEST_ACTOR)
    monkeypatch.setenv("OPENAI_BROKERED_KEY", "sk-openai-secret")
    monkeypatch.setenv("ANTHROPIC_BROKERED_KEY", "sk-anthropic-secret")

    tools.register_connector(
        TEST_TENANT,
        "openai",
        url=OPENAI_URL,
        kind="rest",
        credential_env="OPENAI_BROKERED_KEY",
        description="OpenAI, chat completions only.",
        actor=TEST_ACTOR,
    )
    tools.register_connector(
        TEST_TENANT,
        "anthropic",
        url=ANTHROPIC_URL,
        kind="rest",
        credential_env="ANTHROPIC_BROKERED_KEY",
        # The vendor that wants its own header and no prefix at all — the case
        # `RestLaunch` named in its comment and nothing could reach until 045c.
        credential_header="x-api-key",
        credential_prefix="",
        headers={"anthropic-version": "2023-06-01"},
        description="Anthropic, the Messages API.",
        actor=TEST_ACTOR,
    )

    vet("openai", binding=OPENAI_BINDING)
    vet("anthropic", binding=ANTHROPIC_BINDING)
    return store


def vet(connector_id, *, binding, redact_args=("messages",), **kwargs):
    return tools.vet_tool(
        TEST_TENANT,
        connector_id,
        "chat",
        effect="write",
        resources=(Resource(f"{connector_id}.model", "model"),),
        actor=TEST_ACTOR,
        binding=binding,
        description=f"Think with a model on {connector_id}.",
        redact_args=tuple(redact_args),
        **kwargs,
    )


AGENT = {
    "name": "thinker",
    "runtime": "simple",
    "system": "You think.",
    "permissions": {
        "tools": ["openai_chat", "anthropic_chat"],
        "scope": {
            # Named per provider, which is decision 2: a wildcard means *any model from
            # this one vendor*, which is a sentence somebody can defend in a review.
            "openai.model": {"write": ["gpt-5-mini"]},
            "anthropic.model": {"write": ["*"]},
        },
    },
}


@pytest.fixture
def owner_row(isolated_storage):
    storage.active().create_user(
        TEST_TENANT,
        {"id": OWNER, "issuer": "https://idp.example", "subject": "00u1",
         "email": "priya@acme.com"},
    )
    return OWNER


@pytest.fixture
def token(owner_row):
    row, presented = tokens.mint(TEST_TENANT, "priya-cursor", owner_row, actor="system:cli")
    return row, presented


@pytest.fixture
def auth(token):
    _, presented = token
    return {"Authorization": f"Bearer {presented}"}


@pytest.fixture
def client():
    return TestClient(create_app())


@pytest.fixture
def granted(registered, token):
    row, _ = token
    agents.save(TEST_TENANT, AGENT, actor=TEST_ACTOR)
    storage.active().grant_agent(
        TEST_TENANT, AGENT["name"], "machine", row["id"],
        role="user", granted_by=TEST_ACTOR, actor=TEST_ACTOR,
    )
    return row


def think(client, auth, tool, model, messages=A_PROMPT):
    return client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": {"model": model, "messages": messages, "max_tokens": 64},
            },
        },
        headers=auth,
    )


def result(answered):
    return answered.json()["result"]


# --- registration: no provider is special ------------------------------------------


def test_each_vendor_presents_its_credential_the_way_it_asks_to(
    granted, vendors, client, auth
):
    """**The registration half of provider-neutrality.** One vendor reads
    `Authorization: Bearer`, the other reads `x-api-key` with no prefix and demands a
    version header. Both are four commands and neither is a code change here."""
    assert result(think(client, auth, "openai_chat", "gpt-5-mini")).get("isError") is not True
    assert result(think(client, auth, "anthropic_chat", "claude-opus-5")).get("isError") is not True

    sent = vendors.sent_to(OPENAI_HOST)[0]["headers"]
    assert sent["Authorization"] == "Bearer sk-openai-secret"

    sent = vendors.sent_to(ANTHROPIC_HOST)[0]["headers"]
    assert sent["x-api-key"] == "sk-anthropic-secret", "an empty prefix must survive storage"
    assert "Authorization" not in sent
    assert sent["anthropic-version"] == "2023-06-01"


def test_an_empty_credential_prefix_round_trips_rather_than_defaulting(registered):
    """The stored-row half of the assertion above, because `or "Bearer "` on the way back
    out would restore the default and nothing at the call site would look wrong."""
    connector = mcp.get_connector(TEST_TENANT, "anthropic")

    assert connector.launch.credential_header == "x-api-key"
    assert connector.launch.credential_prefix == ""
    assert connector.launch.headers == {"anthropic-version": "2023-06-01"}


def test_the_platform_key_cannot_be_borrowed_by_a_connector(
    isolated_storage, monkeypatch
):
    """Step 050 (blocker B1): the platform's model key is refused at **registration**.

    A brokered Anthropic connector names its *own* variable, which is why the fixture
    above uses `ANTHROPIC_BROKERED_KEY`. Naming the platform's own key used to write a
    row that could never be called; it is now refused before the row exists, where a
    person can act on it while the command is still in their shell.
    """
    storage.active().allow_host(TEST_TENANT, ANTHROPIC_HOST, actor=TEST_ACTOR)
    with pytest.raises(tools.RegistrationRefused, match="ANTHROPIC_API_KEY"):
        tools.register_connector(
            TEST_TENANT, "borrowed", url=ANTHROPIC_URL, kind="rest",
            credential_env="ANTHROPIC_API_KEY", actor=TEST_ACTOR,
        )


def test_the_read_refuses_a_platform_key_even_on_a_row_that_skipped_registration(
    isolated_storage, monkeypatch
):
    """The load-bearing backstop: `_shared_credential` refuses independently of how the
    row was written, so a legacy row — or one created by a path that skipped
    `register_connector` — still cannot be dialled."""
    from carnet.core import credentials

    monkeypatch.setenv("CARNET_SECRET_KEY", "the-deployments-master-key")
    with pytest.raises(credentials.CredentialError, match="CARNET_SECRET_KEY"):
        credentials.for_tool(
            "borrowed_chat", {}, None, connector="borrowed",
            env_var="CARNET_SECRET_KEY",
        )


# --- scope: a model is a resource, namespaced per provider --------------------------


def test_a_granted_model_reaches_the_vendor_with_the_callers_own_arguments(
    granted, vendors, client, auth
):
    answered = result(think(client, auth, "openai_chat", "gpt-5-mini"))

    assert answered.get("isError") is not True
    body = vendors.sent_to(OPENAI_HOST)[0]["json"]
    assert body["model"] == "gpt-5-mini"
    assert body["messages"] == A_PROMPT
    # The vendor's own reply comes back whole — 045a's contract, and the meter's key is
    # not in it.
    assert answered["structuredContent"]["choices"][0]["message"]["content"]


def test_a_model_outside_the_scope_is_refused_by_the_ordinary_matcher(
    granted, vendors, client, auth
):
    """No new sentence, which is the edge table's answer: this is the broker's existing
    scope refusal, and it names the resource type so the remedy is a scope line."""
    answered = result(think(client, auth, "openai_chat", "gpt-5-pro"))

    assert answered["isError"] is True
    assert vendors.calls == [], "nothing may be dialled for a call the scope refuses"
    record = read_audit()[-1]
    assert record["decision"] == "deny"
    assert "openai.model" in record["reason"]


def test_an_argument_the_schema_does_not_carry_is_refused_before_the_vendor(
    granted, vendors, client, auth
):
    """**The schema is the contract.** `stream: true` is in no authored schema, and this
    door is JSON-only — so a caller asking for a streamed answer is told the tool does
    not offer it rather than handed a buffered one with the flag silently discarded.

    Refused rather than dropped is the fail-closed direction: dropping tells a caller a
    value applied when it did not, which for a model call is the difference between
    *your temperature was ignored* and an answer that reads as if it was honoured."""
    answered = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "anthropic_chat",
                "arguments": {
                    "model": "claude-opus-5", "messages": A_PROMPT, "stream": True
                },
            },
        },
        headers=auth,
    )

    body = result(answered)
    assert body["isError"] is True
    assert "stream" in json.dumps(body)
    assert vendors.calls == [], "nothing may be dialled for an argument nobody vetted"


def test_a_wildcard_on_one_provider_cannot_reach_another(granted, vendors, client, auth):
    """**Decision 2, and the reason the type is namespaced.** `anthropic.model` is granted
    `["*"]`. Under a shared `llm.model` type that same wildcard would have granted every
    model on every provider this tenant has ever registered — including one registered
    next month. Namespaced, it means *any model from this one vendor*.
    """
    # The wildcard genuinely is wide, within its own provider.
    assert result(think(client, auth, "anthropic_chat", "claude-haiku-4-5")).get("isError") is not True

    # And it reaches nothing on the other one, whose scope names a single id.
    refused = result(think(client, auth, "openai_chat", "claude-haiku-4-5"))
    assert refused["isError"] is True
    assert vendors.sent_to(OPENAI_HOST) == []


# --- the meter: what the call spent, on the audit row -------------------------------


def test_each_vendors_own_spelling_of_usage_lands_on_the_audit_row(
    granted, vendors, client, auth
):
    """One `usage_map` per vendor, one set of columns. Nothing between the two knows
    which provider it is reading."""
    think(client, auth, "openai_chat", "gpt-5-mini")
    openai_row = read_audit()[-1]
    think(client, auth, "anthropic_chat", "claude-opus-5")
    anthropic_row = read_audit()[-1]

    assert (openai_row["model"], openai_row["input_tokens"], openai_row["output_tokens"]) == (
        "gpt-5-mini", 120, 30,
    )
    assert (
        anthropic_row["model"],
        anthropic_row["input_tokens"],
        anthropic_row["output_tokens"],
    ) == ("claude-opus-5", 200, 40)
    # A door call, not a run — the premise's own rule, asserted where the money is.
    assert openai_row["run_id"].startswith(storage.DOOR_CALL_ID_PREFIX)
    assert storage.active().list_runs(TEST_TENANT) == []


def test_the_served_model_id_is_what_is_recorded_when_it_differs(
    granted, vendors, client, auth, monkeypatch
):
    """A vendor resolving an alias to a dated id is the ordinary case, and the served id
    is the one the bill is computed against. Known limit 3 is about pricing under the
    *requested* id in a scope; what the row keeps is what answered."""
    vendors.answers[OPENAI_HOST] = openai_reply(model="gpt-5-mini-2026-04-01")

    think(client, auth, "openai_chat", "gpt-5-mini")

    assert read_audit()[-1]["model"] == "gpt-5-mini-2026-04-01"


def test_the_prompt_is_hashed_in_the_audit_log_rather_than_stored(
    granted, vendors, client, auth
):
    """**The one thing a brokered model call must not leave behind.** Every door call
    writes its arguments to an append-only table with no UPDATE and no designed retention
    window; the argument here is the whole conversation. `redact_args` is what the recipe
    marks and what migration 049 made expressible."""
    think(client, auth, "openai_chat", "gpt-5-mini", messages=[{"role": "user", "content": "salary review notes"}])

    record = read_audit()[-1]
    assert record["args"]["model"] == "gpt-5-mini", "the scoped argument stays readable"
    assert record["args"]["messages"].startswith("sha256:")
    assert "salary" not in json.dumps(record["args"])


def test_a_redaction_naming_an_argument_the_tool_does_not_take_is_refused(registered):
    """A policy that reads as applied and is not — `Resource`'s argument-existence rule
    at the other end of the same descriptor. The failure it prevents is silent and in the
    reassuring direction: `--redact-arg mesages` would look approved and log every
    prompt."""
    with pytest.raises(tools.RegistrationRefused, match="mesages"):
        vet("openai", binding=OPENAI_BINDING, redact_args=("mesages",))


# --- money: the operator's own rate table reaches the operator's own models ----------


def test_an_operators_rate_table_prices_both_providers(granted, vendors, client, auth):
    """**045c's blocker, end to end.** Before this step both keys in `RATES` were
    unreachable — `model_family` matched three Anthropic literals — so a customer with
    correct prices for their own models still saw `$0.00` and a dollar ceiling over that
    traffic bounded nothing.

    **Through `price_buckets` since step 084**, where it went through `usage_query.cost_of`
    before. Not a translation: `cost_of` was the *run report's* pricer and 084 deleted it
    with the rest of that module, while `price_buckets` is the one the door and the
    Overview actually call on these exact audit rows. Same two rules, same arithmetic —
    priced per model bucket, an unpriced model contributing nothing and named — asserted
    now against the function a customer's dollar figure is really computed by. That this
    claim survived being re-aimed at the production path, unchanged, is the evidence that
    the property is the estimator's rather than the report's."""
    think(client, auth, "openai_chat", "gpt-5-mini")
    think(client, auth, "anthropic_chat", "claude-opus-5")

    rows = [
        {"model": r["model"], "input_tokens": r["input_tokens"], "output_tokens": r["output_tokens"]}
        for r in read_audit()
        if r.get("input_tokens") is not None
    ]
    priced, _, unpriced = price_buckets(rows, RATES)

    assert unpriced == []
    assert priced == pytest.approx(
        (120 * 1.0 + 30 * 4.0) / 1e6 + (200 * 15.0 + 40 * 75.0) / 1e6
    )
    # And with the built-in table it is exactly the failure the step exists to end: the
    # OpenAI half prices at nothing and is named.
    _, _, without = price_buckets(rows, None)
    assert without == ["gpt-5-mini"]


def test_a_dollar_ceiling_refuses_the_call_after_the_one_that_crossed_it(
    granted, vendors, client, auth, monkeypatch, tmp_path
):
    """045b's gate, over a REST model connector and an operator's own prices.

    A gate on the **next** call, not a reservation: a call's cost exists only once it
    returns, so the crossing call completes and the one after it is refused with a
    sentence naming the dial.
    """
    table = tmp_path / "rates.json"
    table.write_text(json.dumps(RATES))
    monkeypatch.setattr(config, "MODEL_RATES_PATH", str(table))
    monkeypatch.setattr(config, "MCP_USD_PER_DAY", 0.01)
    vendors.answers[ANTHROPIC_HOST] = anthropic_reply(input_tokens=1_000_000)

    assert result(think(client, auth, "anthropic_chat", "claude-opus-5")).get("isError") is not True
    refused = result(think(client, auth, "anthropic_chat", "claude-opus-5"))

    assert refused["isError"] is True
    reason = read_audit()[-1]["reason"]
    assert storage.SPEND_REFUSAL_MARKER in reason
    assert "CARNET_MCP_USD_PER_DAY" in reason
    # Refused before anything was dialled a second time.
    assert len(vendors.sent_to(ANTHROPIC_HOST)) == 1


def test_an_unpriced_model_is_named_and_bounded_by_the_token_ceiling(
    granted, vendors, client, auth, monkeypatch
):
    """**Decision 4, both halves.** A model the rate table cannot value is *recorded,
    priced at nothing and named* — never refused, because a new model id appearing
    mid-day must not stop an agent working and refusing would make the rate file a
    release dependency. What still bounds it is the token ceiling, which needs no rates
    at all and is therefore the vendor-neutral one.
    """
    monkeypatch.setattr(config, "MCP_USD_PER_DAY", 100.0)
    monkeypatch.setattr(config, "MCP_TOKENS_PER_DAY", 500_000)
    vendors.answers[ANTHROPIC_HOST] = anthropic_reply(
        model="mistral-large-3", input_tokens=1_000_000
    )

    allowed = result(think(client, auth, "anthropic_chat", "claude-opus-5"))
    assert allowed.get("isError") is not True, "an unpriced model must not be refused"
    assert read_audit()[-1]["input_tokens"] == 1_000_000

    refused = result(think(client, auth, "anthropic_chat", "claude-opus-5"))
    assert refused["isError"] is True
    reason = read_audit()[-1]["reason"]
    assert "CARNET_MCP_TOKENS_PER_DAY" in reason
    assert "mistral-large-3" in reason, "the gap is named, never silently dropped"


def test_the_spend_response_names_what_its_dollar_figure_is_short_by(
    granted, vendors, client, auth, token, monkeypatch, tmp_path
):
    """**Decision 4 on the response, which is what the screen renders.**

    `door_spend_today` is the one function the gate refuses from and
    `GET /me/tokens/{id}/budget` serializes, so a figure and its shortfall cannot
    disagree — 045b's *"one function, two readers"*. Asserted in both directions here:
    unpriced with the built-in table, priced once the operator's own file names the id.
    """
    from carnet import door
    from carnet.core import Principal

    row, _ = token
    principal = Principal.machine(row["id"], TEST_TENANT)
    vendors.answers[OPENAI_HOST] = openai_reply(model="gpt-5-mini", prompt=1_000_000)
    think(client, auth, "openai_chat", "gpt-5-mini")

    short = door.door_spend_today(principal)
    assert short["unpriced_models"] == ["gpt-5-mini"]
    assert short["usd"] == 0
    assert short["tokens"] == 1_000_030

    table = tmp_path / "rates.json"
    table.write_text(json.dumps(RATES))
    monkeypatch.setattr(config, "MODEL_RATES_PATH", str(table))

    whole = door.door_spend_today(principal)
    assert whole["unpriced_models"] == []
    assert whole["usd"] == pytest.approx((1_000_000 * 1.0 + 30 * 4.0) / 1e6)
    # The tokens never moved: the rate file changes what a number is worth, never what
    # was counted. That is what makes the token ceiling the vendor-neutral one.
    assert whole["tokens"] == short["tokens"]


# --- the recipe, driven as a person drives it ---------------------------------------
#
# Verification 5 of the plan asks for the README's commands run verbatim. Against a real
# provider that is a hand-run with a real key; what is asserted here is everything short
# of the socket — that the flags exist, that they mean what the recipe says, and that
# what they store is what the vendor would have been sent. A recipe that has never been
# parsed is documentation of a command line somebody imagined.


@pytest.fixture
def one_store(monkeypatch, isolated_storage):
    """`test_cli.py`'s fixture, for its reason: `main()` configures storage on every
    invocation, so in-process the second command would throw away what the first
    created — a continuity a person gets from having a database. `DATABASE_URL` is faked
    truthy because these commands refuse without one, and a test driving them must take
    the path a real user takes rather than a bypass."""
    from carnet import cli

    # The CLI reads its tenant from `CARNET_TENANT`, and `conftest`'s store holds
    # exactly one. Set rather than defaulted so the commands below are the ones a person
    # runs against their own deployment.
    monkeypatch.setattr(cli, "DEFAULT_TENANT_ID", TEST_TENANT)
    monkeypatch.setattr(cli, "DATABASE_URL", "postgresql://not-actually-connected")
    monkeypatch.setattr(
        cli.bootstrap, "configure", lambda tenant_id=None, seed=True: storage.active()
    )


def test_the_readme_recipe_registers_and_vets_both_providers(
    one_store, monkeypatch, tmp_path
):
    import sys

    from carnet import cli

    def run(*args):
        monkeypatch.setattr(sys, "argv", ["carnet", *args])
        cli.main()

    schema = tmp_path / "chat.schema.json"
    schema.write_text(json.dumps(CHAT_SCHEMA))
    monkeypatch.setenv("OPENAI_BROKERED_KEY", "sk-openai-secret")
    monkeypatch.setenv("ANTHROPIC_BROKERED_KEY", "sk-anthropic-secret")

    run("--allow-host", OPENAI_HOST)
    run("--allow-host", ANTHROPIC_HOST)

    run(
        "--add-connector", "openai", "--kind", "rest",
        "--url", OPENAI_URL,
        "--credential-env", "OPENAI_BROKERED_KEY",
        "--description", "OpenAI, chat completions only",
    )
    run(
        "--vet", "openai", "--tool", "chat", "--effect", "write",
        "--method", "POST", "--path", "/v1/chat/completions",
        "--schema", str(schema),
        "--body", "model", "--body", "messages", "--body", "max_tokens",
        "--resource", "openai.model=model",
        "--redact-arg", "messages",
        "--usage-map", json.dumps(OPENAI_BINDING["usage_map"]),
        "--tool-description", "Think with an OpenAI model.",
    )

    run(
        "--add-connector", "anthropic", "--kind", "rest",
        "--url", ANTHROPIC_URL,
        "--credential-env", "ANTHROPIC_BROKERED_KEY",
        # The pair the recipe exists to show, and `""` is a value rather than an
        # absence: passed through unchanged, it is what puts the bare key in the header.
        "--credential-header", "x-api-key", "--credential-prefix", "",
        "--header", "anthropic-version=2023-06-01",
        "--description", "Anthropic, the Messages API",
    )
    run(
        "--vet", "anthropic", "--tool", "chat", "--effect", "write",
        "--method", "POST", "--path", "/v1/messages",
        "--schema", str(schema),
        "--body", "model", "--body", "messages", "--body", "max_tokens",
        "--resource", "anthropic.model=model",
        "--redact-arg", "messages",
        "--usage-map", json.dumps(ANTHROPIC_BINDING["usage_map"]),
        "--tool-description", "Think with an Anthropic model.",
    )

    anthropic = mcp.get_connector(TEST_TENANT, "anthropic")
    assert anthropic.launch.credential_header == "x-api-key"
    assert anthropic.launch.credential_prefix == ""
    assert anthropic.launch.headers == {"anthropic-version": "2023-06-01"}
    assert anthropic.launch.headers_for("sk-anthropic-secret") == {
        "anthropic-version": "2023-06-01",
        "x-api-key": "sk-anthropic-secret",
    }

    (vetted,) = anthropic.vetted
    assert vetted.redact_args == ("messages",)
    assert vetted.binding["usage_map"] == ANTHROPIC_BINDING["usage_map"]
    assert [ref.type for ref in vetted.resources] == ["anthropic.model"]

    openai = mcp.get_connector(TEST_TENANT, "openai")
    assert openai.launch.headers_for("sk-openai-secret") == {
        "Authorization": "Bearer sk-openai-secret"
    }


def test_a_header_that_is_not_name_equals_value_is_refused_with_an_example(
    one_store, monkeypatch, capsys
):
    """A header that silently did not arrive is a vendor rejecting every call for a
    reason nothing in this deployment names."""
    import sys

    from carnet import cli

    storage.active().allow_host(TEST_TENANT, ANTHROPIC_HOST, actor=TEST_ACTOR)
    monkeypatch.setattr(
        sys, "argv",
        ["carnet", "--add-connector", "anthropic", "--kind", "rest",
         "--url", ANTHROPIC_URL, "--header", "anthropic-version"],
    )

    with pytest.raises(SystemExit):
        cli.main()

    printed = capsys.readouterr()
    assert "NAME=VALUE" in printed.out + printed.err


# --- the arithmetic, without a door -------------------------------------------------


def test_a_model_id_resolves_against_whichever_table_is_in_force():
    """The unit underneath all of the above, stated once: the vocabulary is the rate
    table's keys, and with no override it is the built-in three unchanged."""
    assert model_family("gpt-5-mini", RATES) == "gpt-5"
    assert model_family("gpt-5-mini") == ""
    assert model_family("claude-opus-5") == "opus"
    assert estimate_cost("gpt-5-mini", TokenUsage(input_tokens=1_000_000), RATES) == pytest.approx(1.0)


# --- step 086: a scope that names a family, and a price on the binding ---------------


FAMILY_AGENT = {
    "name": "family-thinker",
    "runtime": "simple",
    "system": "You think.",
    "permissions": {
        "tools": ["openai_chat", "anthropic_chat"],
        "scope": {
            # The sentence plan 045 promised and could not express: *the small model but
            # not the large one*, on one line, per provider.
            "openai.model": {"write": ["gpt-5"]},
            "anthropic.model": {"write": ["haiku"]},
        },
    },
}


@pytest.fixture
def registered_with_families(isolated_storage, monkeypatch, registered):
    """The same two connectors, re-vetted with the families their vendors actually have.

    Re-vetting rather than a second fixture, because that is the upgrade an existing
    customer performs: a row written before this step declares no families, a family
    scope against it refuses, and `--vet` again is what fixes it.
    """
    vet_with_families("openai", OPENAI_BINDING, ("gpt-5", "gpt-4"))
    vet_with_families("anthropic", ANTHROPIC_BINDING, ("opus", "sonnet", "haiku"))
    return registered


def vet_with_families(connector_id, binding, families):
    """`vet()` with the vendor's own families on the resource. A second helper rather
    than a keyword on the first, because `vet()` fixes `resources` deliberately — every
    test above it is about a scope over a raw id."""
    return tools.vet_tool(
        TEST_TENANT,
        connector_id,
        "chat",
        effect="write",
        resources=(Resource(f"{connector_id}.model", "model", families=families),),
        actor=TEST_ACTOR,
        binding=binding,
        description=f"Think with a model on {connector_id}.",
        redact_args=("messages",),
    )


@pytest.fixture
def granted_family(registered_with_families, token):
    row, _ = token
    agents.save(TEST_TENANT, FAMILY_AGENT, actor=TEST_ACTOR)
    storage.active().grant_agent(
        TEST_TENANT, FAMILY_AGENT["name"], "machine", row["id"],
        role="user", granted_by=TEST_ACTOR, actor=TEST_ACTOR,
    )
    return row


def test_a_family_scope_admits_the_dated_id_the_caller_actually_sends(
    granted_family, vendors, client, auth
):
    """**080's E8, through the door.** The scope says `haiku`; the caller sends a dated
    id it has never seen; the vendor is dialled. Before this step the only two policies
    expressible over a model were one exact dated id and every model on the vendor."""
    vendors.answers[ANTHROPIC_HOST] = anthropic_reply(model="claude-haiku-4-5-20251001")

    answered = result(think(client, auth, "anthropic_chat", "claude-haiku-4-5-20251001"))

    assert answered.get("isError") is not True
    assert len(vendors.sent_to(ANTHROPIC_HOST)) == 1


def test_a_family_scope_still_refuses_the_larger_model(
    granted_family, vendors, client, auth
):
    """A family narrows. If it did not, it would be `*` with extra words."""
    answered = result(think(client, auth, "anthropic_chat", "claude-opus-5-20260910"))

    assert answered["isError"] is True
    assert vendors.sent_to(ANTHROPIC_HOST) == []


def test_a_family_scope_cannot_reach_the_other_provider(
    granted_family, vendors, client, auth
):
    """045c's decision 2 holds under families exactly as it holds under a wildcard: the
    type is namespaced per provider, so `haiku` on one vendor says nothing about the
    other. A shared `llm.family` would have made one line mean two vendors."""
    answered = result(think(client, auth, "openai_chat", "claude-haiku-4-5-20251001"))

    assert answered["isError"] is True
    assert vendors.sent_to(OPENAI_HOST) == []


def test_the_release_a_customer_has_never_heard_of_is_admitted(
    granted_family, vendors, client, auth
):
    """**The trigger, and it needs no second vendor.** An Anthropic-only customer whose
    scope named a dated id is refused on the morning the next one ships. Named by family,
    the same policy admits it — which is the whole of why this fired before anybody
    registered OpenAI."""
    vendors.answers[ANTHROPIC_HOST] = anthropic_reply(model="claude-haiku-9-9-29991231")

    answered = result(think(client, auth, "anthropic_chat", "claude-haiku-9-9-29991231"))

    assert answered.get("isError") is not True


def test_a_row_vetted_before_families_refuses_a_family_scope(
    registered, token, vendors, client, auth
):
    """**The upgrade story, asserted rather than described.** A stored row declares no
    families, so a family scope against it matches nothing and refuses — fail-closed, and
    the same state that row is in today. Defaulting a vocabulary onto stored rows would
    be inventing an approval nobody gave."""
    row, _ = token
    agents.save(TEST_TENANT, FAMILY_AGENT, actor=TEST_ACTOR)
    storage.active().grant_agent(
        TEST_TENANT, FAMILY_AGENT["name"], "machine", row["id"],
        role="user", granted_by=TEST_ACTOR, actor=TEST_ACTOR,
    )

    answered = result(think(client, auth, "anthropic_chat", "claude-haiku-4-5-20251001"))

    assert answered["isError"] is True
    assert vendors.sent_to(ANTHROPIC_HOST) == []


PRICED_OPENAI_BINDING = dict(
    OPENAI_BINDING,
    pricing={
        "gpt-5": {"input": 1.0, "output": 4.0, "cache_read": 0.0, "cache_write": 0.0}
    },
)


def test_a_price_on_the_binding_reaches_a_model_no_file_prices(
    registered, granted, vendors, client, auth
):
    """**080's E5.** No `CARNET_MODEL_RATES` anywhere: the deployment's table is the
    built-in three, which cannot value a GPT id at all. The price the person who
    registered the key wrote on the binding is what makes the figure a figure."""
    vet("openai", binding=PRICED_OPENAI_BINDING)
    think(client, auth, "openai_chat", "gpt-5-mini")

    spend = door.door_spend_today(Principal.machine(granted["id"], TEST_TENANT))

    assert spend["unpriced_models"] == []
    assert spend["usd"] == pytest.approx((120 * 1.0 + 30 * 4.0) / 1e6)


def test_without_a_price_anywhere_the_door_still_says_so(
    registered, granted, vendors, client, auth
):
    """The state E5 does not change and should not: a model nobody has priced is
    *reported as unpriced* rather than reported as free."""
    think(client, auth, "openai_chat", "gpt-5-mini")

    spend = door.door_spend_today(Principal.machine(granted["id"], TEST_TENANT))

    assert spend["unpriced_models"] == ["gpt-5-mini"]
    assert spend["usd"] == 0.0


def test_an_operators_file_outranks_a_connectors_price(
    registered, granted, vendors, client, auth, monkeypatch, tmp_path
):
    """**The precedence, in the one direction that could be argued either way.**
    `config.model_rates`' own docstring is the argument: *"somebody who set this variable
    did so precisely because the built-in numbers are wrong for them"* — that is a
    statement about the deployment, and it outranks one connector's list price."""
    vet("openai", binding=PRICED_OPENAI_BINDING)
    table = tmp_path / "rates.json"
    table.write_text(json.dumps(
        {"gpt-5": {"input": 9.0, "output": 9.0, "cache_read": 0.0, "cache_write": 0.0}}
    ))
    monkeypatch.setattr(config, "MODEL_RATES_PATH", str(table))

    think(client, auth, "openai_chat", "gpt-5-mini")
    spend = door.door_spend_today(Principal.machine(granted["id"], TEST_TENANT))

    assert spend["usd"] == pytest.approx((120 * 9.0 + 30 * 9.0) / 1e6)


def test_an_operators_file_still_replaces_the_built_in_rather_than_layering(
    registered, granted, vendors, client, auth, monkeypatch, tmp_path
):
    """013's posture, preserved exactly. Quietly filling an operator's gaps from the
    table they explicitly rejected would produce a plausible figure computed from it."""
    table = tmp_path / "rates.json"
    table.write_text(json.dumps(
        {"gpt-5": {"input": 1.0, "output": 1.0, "cache_read": 0.0, "cache_write": 0.0}}
    ))
    monkeypatch.setattr(config, "MODEL_RATES_PATH", str(table))

    think(client, auth, "anthropic_chat", "claude-opus-5")
    spend = door.door_spend_today(Principal.machine(granted["id"], TEST_TENANT))

    assert spend["unpriced_models"] == ["claude-opus-5"]


def test_with_nothing_set_anywhere_the_table_is_the_built_in_one(registered):
    """The no-op case, which is every deployment that has not written a price: the
    composed table is `core.usage.RATES` and every figure is what it was."""
    assert door.rates_for(TEST_TENANT) == RATES_BUILT_IN


# --- the two flags, driven the way a person drives them -----------------------------


def test_the_cli_authors_a_family_and_a_price(one_store, monkeypatch, tmp_path):
    """**Step 086 through the terminal**, which is the only interface a REST model
    connector is vetted from in any path this tree documents.

    `--resource-family` is a separate flag rather than a third colon-delimited field on
    `--resource`, whose own docstring already calls its spelling ugly-and-explicit; and
    `--pricing` sits beside `--usage-map`, because one says where the counters are and
    the other says what they cost.
    """
    import sys

    from carnet import cli

    def run(*args):
        monkeypatch.setattr(sys, "argv", ["carnet", *args])
        cli.main()

    schema = tmp_path / "chat.schema.json"
    schema.write_text(json.dumps(CHAT_SCHEMA))
    prices = {"gpt-5": {"input": 1.25, "output": 10.0, "cache_read": 0.125, "cache_write": 0.0}}

    run("--allow-host", OPENAI_HOST)
    run(
        "--add-connector", "openai", "--kind", "rest",
        "--url", OPENAI_URL, "--credential-env", "OPENAI_BROKERED_KEY",
        "--description", "OpenAI, chat completions only",
    )
    run(
        "--vet", "openai", "--tool", "chat", "--effect", "write",
        "--method", "POST", "--path", "/v1/chat/completions",
        "--schema", str(schema),
        "--body", "model", "--body", "messages", "--body", "max_tokens",
        "--resource", "openai.model=model",
        "--resource-family", "openai.model=gpt-5,gpt-4",
        "--redact-arg", "messages",
        "--usage-map", json.dumps(OPENAI_BINDING["usage_map"]),
        "--pricing", json.dumps(prices),
        "--tool-description", "Think with an OpenAI model.",
    )

    (vetted,) = mcp.get_connector(TEST_TENANT, "openai").vetted
    (ref,) = vetted.resources
    assert ref.families == ("gpt-5", "gpt-4")
    assert ref.family_of("gpt-5-mini") == "gpt-5"
    assert vetted.binding["pricing"] == prices

    # And the price is reachable as a rate without any file on the server, which is the
    # whole of E5.
    assert door.rates_for(TEST_TENANT)["gpt-5"]["output"] == 10.0


def test_a_family_for_a_resource_the_tool_does_not_touch_is_refused(
    one_store, monkeypatch, tmp_path
):
    """A vocabulary that would be silently dropped, and a scope written against it would
    then refuse every call with no way to see why. Refused where the vetter is still at
    the terminal, which is `check_binding`'s whole reason for existing one flag over."""
    import sys

    from carnet import cli

    def run(*args):
        monkeypatch.setattr(sys, "argv", ["carnet", *args])
        cli.main()

    schema = tmp_path / "chat.schema.json"
    schema.write_text(json.dumps(CHAT_SCHEMA))
    run("--allow-host", OPENAI_HOST)
    run(
        "--add-connector", "openai", "--kind", "rest",
        "--url", OPENAI_URL, "--credential-env", "OPENAI_BROKERED_KEY",
    )
    with pytest.raises(SystemExit):
        run(
            "--vet", "openai", "--tool", "chat", "--effect", "write",
            "--method", "POST", "--path", "/v1/chat/completions",
            "--schema", str(schema),
            "--body", "model", "--body", "messages", "--body", "max_tokens",
            "--resource", "openai.model=model",
            "--resource-family", "anthropic.model=haiku",
            "--tool-description", "Think with an OpenAI model.",
        )


def test_a_price_on_a_binding_makes_a_dollar_ceiling_bound(
    registered, granted, vendors, client, auth, monkeypatch
):
    """**The payoff, and the reason E5 is a governance item rather than a reporting one.**
    A ceiling in dollars over traffic nobody priced bounds nothing — it is a dial that
    reads as set and refuses nothing, which is worse than no dial. The price written by
    whoever registered the key is what turns it back into a limit."""
    vet("openai", binding=PRICED_OPENAI_BINDING)
    vendors.answers[OPENAI_HOST] = openai_reply(model="gpt-5-mini", prompt=1_000_000)
    monkeypatch.setattr(config, "MCP_USD_PER_DAY", 0.5)

    assert result(think(client, auth, "openai_chat", "gpt-5-mini")).get("isError") is not True
    refused = result(think(client, auth, "openai_chat", "gpt-5-mini"))

    assert refused["isError"] is True
    assert storage.SPEND_REFUSAL_MARKER in read_audit()[-1]["reason"]


def test_two_connectors_pricing_one_model_resolve_deterministically(
    registered, monkeypatch
):
    """A known limit, pinned so it is at least not arbitrary. Spend is aggregated by
    `model` alone — the audit row carries no connector — so two connectors to one vendor
    with divergent contracts cannot both be right, and the composed table takes one.
    `connectors_for` is ordered by id and the overlay is a left-to-right update, so the
    later id wins. Nothing warns; this asserts it does not depend on write order."""
    tools.register_connector(
        TEST_TENANT, "zz-openai", url=OPENAI_URL, kind="rest",
        credential_env="OPENAI_BROKERED_KEY", actor=TEST_ACTOR,
    )
    vet("openai", binding=PRICED_OPENAI_BINDING)
    tools.vet_tool(
        TEST_TENANT, "zz-openai", "chat", effect="write",
        resources=(Resource("zz-openai.model", "model"),), actor=TEST_ACTOR,
        binding=dict(
            OPENAI_BINDING,
            pricing={"gpt-5": {"input": 7.0, "output": 7.0, "cache_read": 0.0, "cache_write": 0.0}},
        ),
        description="Think.", redact_args=("messages",),
    )

    assert door.rates_for(TEST_TENANT)["gpt-5"]["input"] == 7.0


def test_one_tenants_price_never_reaches_anothers_figure(isolated_storage):
    """Prices are per connector and connectors are per tenant, so this should hold by
    construction — asserted anyway, because *by construction* is what every isolation bug
    was believed to be. Driven against real Postgres in 086's edge pass as well."""
    other = "t-other-086"
    storage.active().create_tenant(other, "Other")
    storage.active().allow_host(other, OPENAI_HOST, actor=TEST_ACTOR)
    tools.register_connector(
        other, "openai", url=OPENAI_URL, kind="rest",
        credential_env="OPENAI_BROKERED_KEY", actor=TEST_ACTOR,
    )
    tools.vet_tool(
        other, "openai", "chat", effect="write",
        resources=(Resource("openai.model", "model"),), actor=TEST_ACTOR,
        description="Think.", redact_args=("messages",),
        binding=dict(
            OPENAI_BINDING,
            pricing={"gpt-5": {"input": 99.0, "output": 99.0,
                               "cache_read": 0.0, "cache_write": 0.0}},
        ),
    )

    assert door.rates_for(other)["gpt-5"]["input"] == 99.0
    # The tenant under test registered nothing, so it sees the built-in table and no
    # trace of the price next door.
    assert "gpt-5" not in door.rates_for(TEST_TENANT)
    assert sorted(door.rates_for(TEST_TENANT)) == ["haiku", "opus", "sonnet"]


def test_pricing_on_an_mcp_connector_is_refused_with_the_reason(one_store, monkeypatch):
    """A price describes a REST response's cost and an MCP server describes its own
    tools, so a stored price it would never use reads as honoured. Refused rather than
    dropped, which is `--usage-map`'s rule and now `--pricing`'s."""
    import sys

    from carnet import cli

    def run(*args):
        monkeypatch.setattr(sys, "argv", ["carnet", *args])
        cli.main()

    storage.active().allow_host(TEST_TENANT, "mcp.example.com", actor=TEST_ACTOR)
    run("--add-connector", "srv", "--url", "https://mcp.example.com/mcp")
    with pytest.raises(SystemExit):
        run("--vet", "srv", "--tool", "chat", "--effect", "read",
            "--pricing", '{"gpt-5": {"input": 1.0, "output": 1.0, '
                         '"cache_read": 0.0, "cache_write": 0.0}}')
