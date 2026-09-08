"""The MCP door in tool mode: what a machine token sees, what it may call, what it costs.

Step 033b. The weight here is not on the protocol — that is a dozen lines of framing in
`api/routes_mcp.py` and the client half has been asserted since 012. It is on the three
questions the broker has never had to answer for itself, because a run always answered
them first:

    which agent is a call attributed to?   the union rule, and its scope half
    what bounds a caller with no run?      the per-token budget, in Postgres
    what may this token even see?          `tools/list`, which IS the grant list

And on one property that is easy to lose and expensive to lose quietly: **the door is
not a second enforcement path.** Every call goes through `broker.call` unmodified, so a
denial through the door writes the same audit record an in-product denial writes. Several
tests below assert that equality directly rather than asserting the door's behaviour
twice.

Everything runs against a fake transport. Nothing spawns a container or reaches a
network, and what the fake echoes is the credential its session was built with — the
trick `test_delegation.py` uses, and the only way to assert *whose account* a call went
out as from inside one process.
"""

import json
import threading
from datetime import date, datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from carnet import agents, config, door, storage, tools
from carnet.access import connections, tokens
from carnet.api import create_app
from carnet.api.deps import principal_from_request
from carnet.core import Principal, permissions
from carnet.tools import mcp
from carnet.tools.base import Resource
from carnet.tools.mcp import binding
from carnet.tools.mcp.client import USAGE_META_KEY, SessionPool
from carnet.tools.mcp.transport import TransportError

from conftest import TEST_ACTOR, TEST_HOST, TEST_TENANT, read_audit

OWNER = "u-priya"
SHARED = "acme-service-token"

ADVERTISED = [
    {
        "name": "list_issues",
        "description": "List issues in a repository.",
        "inputSchema": {
            "type": "object",
            "properties": {"owner": {"type": "string"}, "state": {"type": "string"}},
            "required": ["owner"],
        },
    },
    {
        "name": "create_issue",
        "description": "Open an issue.",
        "inputSchema": {
            "type": "object",
            "properties": {"owner": {"type": "string"}, "title": {"type": "string"}},
            "required": ["owner", "title"],
        },
    },
]

REPO = Resource("github.repo", "owner")


def connector(*, identity="service", allow_asserted=False):
    """The tenant's registered server. HTTP, because a `user` identity needs a transport
    that can carry a per-user credential and stdio cannot — which is `Connector.validate`'s
    rule and not something this file is testing."""
    return binding.Connector(
        id="example",
        allow_asserted_identity=allow_asserted,
        launch=binding.HttpLaunch(
            url=f"https://{TEST_HOST}/mcp/", credential_env="EXAMPLE_TOKEN"
        ),
        vetted=[
            binding.Vetted(
                "list_issues", effect="read", identity=identity, resources=[REPO]
            ),
            binding.Vetted(
                "create_issue", effect="write", identity=identity, resources=[REPO]
            ),
        ],
    )


READ = "example_list_issues"
WRITE = "example_create_issue"


def agent(name, tools_granted, scope):
    return {
        "name": name,
        "runtime": "simple",
        "system": "You do a thing.",
        "permissions": {"tools": tools_granted, "scope": scope},
    }


TRIAGE = agent(name="triage", tools_granted=[READ], scope={"github.repo": {"read": ["acme"]}})
SECURITY = agent(
    name="security", tools_granted=[READ], scope={"github.repo": {"read": ["secret"]}}
)
FILER = agent(name="filer", tools_granted=[WRITE], scope={"github.repo": {"write": ["acme"]}})


class EchoTransport:
    """A server that answers every call with the credential its session was built on.

    Real servers do this implicitly: the account a call acts as is decided by the
    credential the session was opened with, and is invisible from inside this process.
    Making it visible is what lets these tests assert whose account a door call reached.
    """

    # See `tools/call` below. Reset by the `no_reported_usage` fixture so one test's
    # meter cannot leak into the next.
    usage = None

    def __init__(self, credential):
        self.credential = credential
        self.calls = []

    def send(self, message):
        if "id" not in message:
            return None
        method = message["method"]
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "example", "version": "1.0"},
            }
        elif method == "tools/list":
            result = {"tools": ADVERTISED}
        elif method == "tools/call":
            self.calls.append(message["params"])
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({"acted_as": self.credential or "anonymous"}),
                    }
                ]
            }
            # What this call cost, in `_meta` — the protocol's extension point, and the
            # carrier 045b chose for MCP. Class-level so a test sets it once and every
            # session built afterwards reports the same thing; None is every server that
            # has never heard of this, which is all of them today.
            if EchoTransport.usage is not None:
                result["_meta"] = {USAGE_META_KEY: EchoTransport.usage}
        else:  # pragma: no cover - the subset is three methods
            return {"jsonrpc": "2.0", "id": message["id"], "error": {"message": "?"}}
        return {"jsonrpc": "2.0", "id": message["id"], "result": result}

    def set_protocol_version(self, version):
        """send / set_protocol_version / close — the whole transport interface."""

    def close(self):
        pass


@pytest.fixture(autouse=True)
def isolated_pool(monkeypatch):
    monkeypatch.setattr(mcp, "POOL", SessionPool())


@pytest.fixture(autouse=True)
def no_reported_usage(monkeypatch):
    """The default every test starts from: a server that says nothing about cost.

    Autouse and restoring, because `EchoTransport.usage` is class state — a test that set
    it and did not clear it would silently meter every later test, and the failure would
    land somewhere else entirely.
    """
    monkeypatch.setattr(EchoTransport, "usage", None)


@pytest.fixture(autouse=True)
def built(monkeypatch):
    """Every session gets a transport tagged with the credential that built it."""
    made = []

    def transport_for(tenant_id, conn, credential):
        transport = EchoTransport(credential)
        made.append(transport)
        return transport

    monkeypatch.setattr(mcp, "_transport_for", transport_for)
    return made


@pytest.fixture(autouse=True)
def shared_credential(monkeypatch):
    """The connector's shared secret, as `credential_env` names it."""
    monkeypatch.setenv("EXAMPLE_TOKEN", SHARED)


@pytest.fixture
def vetted(isolated_storage):
    tools.save_connector(TEST_TENANT, connector(), actor=TEST_ACTOR)


@pytest.fixture
def owner(isolated_storage):
    storage.active().create_user(
        TEST_TENANT,
        {
            "id": OWNER,
            "issuer": "https://idp.example",
            "subject": "00u1",
            "email": "priya@acme.com",
        },
    )
    return OWNER


@pytest.fixture
def token(owner):
    """A live machine token and the string it presents. Minted through `tokens.mint`,
    which is the only thing that ever holds the secret."""
    row, presented = tokens.mint(TEST_TENANT, "priya-cursor", owner, actor="system:cli")
    return row, presented


@pytest.fixture
def principal(token):
    row, _ = token
    return Principal.machine(row["id"], TEST_TENANT)


@pytest.fixture
def client():
    """No lifespan: it would replace the per-test store with a seeded one."""
    return TestClient(create_app())


@pytest.fixture
def auth(token):
    _, presented = token
    return {"Authorization": f"Bearer {presented}"}


def grant(token_row, config_):
    """Save an agent and share it with this token, which is the whole of what a door
    caller's access is made of."""
    agents.save(TEST_TENANT, config_, actor=TEST_ACTOR)
    storage.active().grant_agent(
        TEST_TENANT,
        config_["name"],
        "machine",
        token_row["id"],
        role="user",
        granted_by=TEST_ACTOR,
        actor=TEST_ACTOR,
    )


def rpc(client, auth, method, params=None, message_id=1):
    body = {"jsonrpc": "2.0", "id": message_id, "method": method}
    if params is not None:
        body["params"] = params
    return client.post("/mcp", json=body, headers=auth)


def call(client, auth, name, arguments):
    return rpc(client, auth, "tools/call", {"name": name, "arguments": arguments})


def acted_as(response):
    """Whose account the echoing server saw, out of a `tools/call` result."""
    return response.json()["result"]["structuredContent"]["acted_as"]


def today():
    """The window the door charges a call to. Read the same way `TokenBudget` reads it,
    rather than pinned to a literal, because a suite that ran across midnight UTC should
    fail on the thing under test and not on the date."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).date()


# --- tools/list is the grant list, and nothing else -------------------------------


def test_a_token_granted_nothing_sees_nothing(client, auth, vetted, token):
    """The empty-denies default, at the newest door. A token that has been minted and
    granted nothing is a credential that can authenticate and do nothing at all."""
    response = rpc(client, auth, "tools/list")

    assert response.status_code == 200
    assert response.json()["result"]["tools"] == []


def test_the_list_is_the_union_of_the_granted_agents_tools(client, auth, vetted, token):
    """Decision 2, as names. Two agents, two different tools, one flat list — and no
    third object to grant: the admin's mental model stays "I share agents"."""
    row, _ = token
    grant(row, TRIAGE)
    grant(row, FILER)

    names = [t["name"] for t in rpc(client, auth, "tools/list").json()["result"]["tools"]]

    assert names == sorted([READ, WRITE])


def test_the_same_tool_in_two_agents_is_listed_once(client, auth, vetted, token):
    """A union, not a concatenation. Two agents both granting `list_issues` is the
    ordinary shape of a token in a team, and a client shown the same tool twice would
    have to pick one — a choice it has no basis for and we have no reason to force."""
    row, _ = token
    grant(row, TRIAGE)
    grant(row, SECURITY)

    names = [t["name"] for t in rpc(client, auth, "tools/list").json()["result"]["tools"]]

    assert names == [READ]


def test_revoking_the_grant_removes_the_tool_at_the_next_list(client, auth, vetted, token):
    """Decision 3's whole point, and the reason there is deliberately no MCP-exposure
    toggle beside the grant: one of them would go stale, and a control that is stale is
    a control that is off."""
    row, _ = token
    grant(row, TRIAGE)
    assert rpc(client, auth, "tools/list").json()["result"]["tools"]

    storage.active().revoke_agent(
        TEST_TENANT, TRIAGE["name"], "machine", row["id"], actor=TEST_ACTOR
    )

    assert rpc(client, auth, "tools/list").json()["result"]["tools"] == []
    # And the call is refused too, which is the half that matters: a list is a
    # convenience, and a client holding a stale one must not still get through.
    assert "error" in call(client, auth, READ, {"owner": "acme"}).json()


def test_a_listed_tool_carries_the_schema_the_server_advertises(client, auth, vetted, token):
    """`inputSchema` comes from the server, because the vetted manifest deliberately
    does not store one — migration 018's argument, that a copy of a vendor's contract in
    our database is a copy free to drift from the vendor's. Which is also why the door
    binds before it lists."""
    row, _ = token
    grant(row, TRIAGE)

    listed = rpc(client, auth, "tools/list").json()["result"]["tools"][0]

    assert listed["inputSchema"] == ADVERTISED[0]["inputSchema"]
    assert listed["description"] == "List issues in a repository."
    # The vetted `effect`, handed over as MCP's own annotation. A hint for the client;
    # the enforcement is the broker's step 1 whatever the client believes.
    assert listed["annotations"]["readOnlyHint"] is True


def test_a_write_is_advertised_as_one(client, auth, vetted, token):
    row, _ = token
    grant(row, FILER)

    listed = rpc(client, auth, "tools/list").json()["result"]["tools"][0]

    assert listed["annotations"]["readOnlyHint"] is False


def test_a_connector_that_will_not_bind_loses_its_tools_and_the_rest_still_serves(
    client, auth, vetted, token, monkeypatch
):
    """The list stays **true** rather than staying long.

    A tool that did not bind cannot be called — the broker refuses what it cannot
    describe — so advertising it would be advertising something that answers an error.
    And failing the whole list because one of a tenant's servers is down would make
    every listed tool hostage to the least reliable one.
    """
    row, _ = token
    grant(row, TRIAGE)
    grant(row, agent("chatter", ["post_message"], {"chat.channel": {"write": ["#eng"]}}))

    def refuse(*_args, **_kwargs):
        raise TransportError("connection refused", delivered=False)

    monkeypatch.setattr(mcp, "_transport_for", refuse)

    names = [t["name"] for t in rpc(client, auth, "tools/list").json()["result"]["tools"]]

    # `post_message` is hand-written, so it needs no server and is unaffected by one
    # being down. That is the whole distinction the two registries exist for.
    assert names == ["post_message"]


def test_an_agent_with_a_broken_config_does_not_take_the_others_tools_with_it(
    client, auth, vetted, token
):
    """`agents.get` raises for the run path, where refusing to run something broken is
    right. Here that would mean one unusable agent removing every *other* agent's tools
    from a caller's list — a much larger failure than the one being reported, and one
    the caller cannot act on."""
    row, _ = token
    grant(row, TRIAGE)
    grant(row, FILER)

    # Straight past `agents.save`'s validation, which is the only way a stored config
    # becomes invalid in the first place: a tool is un-vetted after an agent was written.
    broken = dict(FILER)
    broken["permissions"] = {"tools": ["example_deleted_tool"], "scope": {}}
    storage.active().save_agent(TEST_TENANT, broken, actor=TEST_ACTOR)

    names = [t["name"] for t in rpc(client, auth, "tools/list").json()["result"]["tools"]]

    assert names == [READ]


# --- the union rule, where it is about scope rather than names ---------------------


def test_a_call_is_allowed_if_any_granted_agent_allows_it(client, auth, vetted, token):
    """**The sentence decision 2 was one clause short of.**

    Two agents grant the same tool with different scopes. The union is only true of
    *scope* as well as of names if a call allowed by either is allowed — any other
    reading refuses calls the caller is plainly granted.
    """
    row, _ = token
    grant(row, TRIAGE)  # read: acme
    grant(row, SECURITY)  # read: secret

    assert acted_as(call(client, auth, READ, {"owner": "acme"})) == SHARED
    assert acted_as(call(client, auth, READ, {"owner": "secret"})) == SHARED


def test_the_audit_record_names_the_agent_whose_scope_carried_the_call(
    client, auth, vetted, token
):
    """Attribution is the half that makes the union governable rather than merely
    permissive: an administrator asking *which share let this happen* gets an answer
    from a row."""
    row, _ = token
    grant(row, TRIAGE)
    grant(row, SECURITY)

    call(client, auth, READ, {"owner": "secret"})

    record = read_audit()[-1]
    assert record["agent"] == "security"
    assert record["decision"] == "allow"


def test_a_call_outside_every_granted_scope_is_refused_and_audited_once(
    client, auth, vetted, token
):
    """And it is refused **by the broker**, under a real agent whose scope really did
    say no — not by a pre-check of our own. A second enforcement point would quietly
    produce denials the audit log never sees, which is the one thing the log must not
    be able to miss."""
    row, _ = token
    grant(row, TRIAGE)
    grant(row, SECURITY)

    before = len(read_audit())
    body = call(client, auth, READ, {"owner": "somebody-else"}).json()

    assert body["result"]["isError"] is True
    assert "denied_by" in body["result"]["structuredContent"]

    records = read_audit()
    assert len(records) == before + 1
    assert records[-1]["decision"] == "deny"
    assert "outside this agent's" in records[-1]["reason"]


def test_attribution_is_deterministic(client, auth, vetted, token):
    """Ordered by agent name, so the same call by the same token attributes the same way
    every time. An audit log whose attribution varies run to run is complete and
    unanswerable."""
    row, _ = token
    grant(row, TRIAGE)
    grant(row, SECURITY)

    for _ in range(3):
        call(client, auth, READ, {"owner": "acme"})

    assert {r["agent"] for r in read_audit()} == {"triage"}


def test_a_tool_in_no_granted_agent_is_a_protocol_error_and_a_denial_row(
    client, auth, vetted, token
):
    """Not a broker denial, and deliberately not dressed as one: nothing was authorized,
    nothing was scoped, and there is no agent to attribute an audit record to. Inventing
    one would put a row in an append-only table naming an agent that had nothing to do
    with the call.

    The attempt is still written down — in the log built for exactly that.
    """
    row, _ = token
    grant(row, TRIAGE)

    before = len(read_audit())
    body = call(client, auth, WRITE, {"owner": "acme", "title": "x"}).json()

    assert body["error"]["code"] == -32602
    assert WRITE in body["error"]["message"]
    assert len(read_audit()) == before

    denials = storage.active().denial_records(TEST_TENANT, resource_kind="tool")
    assert denials[-1]["resource_id"] == WRITE
    assert denials[-1]["principal_kind"] == "machine"


def test_a_grant_reaching_the_token_through_a_group_is_the_same_grant(
    client, auth, vetted, token
):
    """**The door's bulk-sharing story, and it is a different code path.**

    Decision 6's neighbour: "share with eng, not with forty people" is what makes the
    door administrable, and a machine may be a group member since migration 031. The
    union is computed from `grants.runnable_names`, which resolves membership in
    storage — so a door that had built its own list from direct grants would have shown
    an empty catalogue to exactly the tokens an enterprise onboards in bulk.
    """
    row, _ = token
    agents.save(TEST_TENANT, TRIAGE, actor=TEST_ACTOR)
    store = storage.active()
    store.create_group(TEST_TENANT, "eng", "Engineering", actor=TEST_ACTOR)
    store.add_group_member(TEST_TENANT, "eng", "machine", row["id"], actor=TEST_ACTOR)
    store.grant_agent(
        TEST_TENANT,
        TRIAGE["name"],
        "group",
        "eng",
        role="user",
        granted_by=TEST_ACTOR,
        actor=TEST_ACTOR,
    )

    assert [t["name"] for t in rpc(client, auth, "tools/list").json()["result"]["tools"]] == [READ]
    assert acted_as(call(client, auth, READ, {"owner": "acme"})) == SHARED
    assert read_audit()[-1]["agent"] == "triage"


# --- a door call is not a run -----------------------------------------------------


def test_a_door_call_writes_no_run_row(client, auth, vetted, token):
    """Decision 4. No prompt, no config, no version — a `runs` row would be untrue about
    all three, and the run list is where people look to understand what their agents
    did."""
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, READ, {"owner": "acme"})

    assert storage.active().list_runs(TEST_TENANT) == []


def test_a_door_calls_audit_id_can_never_be_mistaken_for_a_run(client, auth, vetted, token):
    """It still needs an id, because the audit record correlates on one. The shape is
    deliberately distinct, so the log is filterable by prefix for whoever wants only the
    door's traffic."""
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, READ, {"owner": "acme"})

    run_id = read_audit()[-1]["run_id"]
    assert run_id.startswith(door.CALL_ID_PREFIX)


def test_two_calls_are_two_correlation_ids(client, auth, vetted, token):
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, READ, {"owner": "acme"})
    call(client, auth, READ, {"owner": "acme"})

    assert len({r["run_id"] for r in read_audit()}) == 2


# --- the per-token budget ---------------------------------------------------------


def test_the_ceiling_refuses_and_the_record_is_an_ordinary_broker_denial(
    client, auth, vetted, token, monkeypatch
):
    """**The equality is the assertion**, not the refusal.

    The budget rides the broker's own step 2 rather than being checked beside it, so a
    door caller at its ceiling produces the same `deny` record an in-product run at its
    ceiling produces — same table, same shape, same query. Checking it in the route would
    have made this a second kind of refusal that every audit query had to learn about.
    """
    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 2)
    row, _ = token
    grant(row, TRIAGE)

    assert "error" not in call(client, auth, READ, {"owner": "acme"}).json()["result"]["structuredContent"]
    call(client, auth, READ, {"owner": "acme"})
    third = call(client, auth, READ, {"owner": "acme"}).json()

    assert third["result"]["isError"] is True
    record = read_audit()[-1]
    assert record["decision"] == "deny"
    assert "ceiling" in record["reason"]
    assert record["agent"] == "triage"


def test_a_denied_call_does_not_spend_budget(client, auth, vetted, token, monkeypatch):
    """The broker's ordering, inherited rather than re-implemented: the permission check
    runs before step 2, so a refusal must not push a caller toward exhaustion. A door
    caller fixing its own scope mistakes must not run out of budget doing so."""
    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 5)
    row, _ = token
    grant(row, TRIAGE)

    for _ in range(4):
        call(client, auth, READ, {"owner": "not-granted"})

    assert storage.active().mcp_calls_spent(TEST_TENANT, row["id"], today()) == 0
    assert "error" not in call(client, auth, READ, {"owner": "acme"}).json()["result"]["structuredContent"]


def test_the_dial_can_be_turned_off_and_writes_nothing(client, auth, vetted, token, monkeypatch):
    """`RUNS_PER_HOUR`'s convention: zero is an operator's explicit decision to run
    unmetered. Nothing is written, because rows nobody will read are not a record — and
    the audit log already says what every call did."""
    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 0)
    row, _ = token
    grant(row, TRIAGE)

    for _ in range(3):
        assert "error" not in call(client, auth, READ, {"owner": "acme"}).json()["result"]["structuredContent"]

    assert storage.active().mcp_calls_spent(TEST_TENANT, row["id"], today()) == 0


def test_two_tokens_do_not_share_a_ceiling(client, vetted, token, owner, monkeypatch):
    """The budget is a fact about a credential, which is what makes revoking one a
    complete answer to a runaway."""
    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 1)
    row, presented = token
    grant(row, TRIAGE)

    second_row, second_presented = tokens.mint(
        TEST_TENANT, "other-bot", owner, actor="system:cli"
    )
    storage.active().grant_agent(
        TEST_TENANT,
        TRIAGE["name"],
        "machine",
        second_row["id"],
        role="user",
        granted_by=TEST_ACTOR,
        actor=TEST_ACTOR,
    )

    first = {"Authorization": f"Bearer {presented}"}
    second = {"Authorization": f"Bearer {second_presented}"}
    api = TestClient(create_app())

    call(api, first, READ, {"owner": "acme"})
    assert call(api, first, READ, {"owner": "acme"}).json()["result"]["isError"] is True
    assert call(api, second, READ, {"owner": "acme"}).json()["result"]["isError"] is False


# --- what a door call spends -------------------------------------------------------
#
# Step 045b. The call-count ceiling above bounds *how many*; this bounds *how much*. Two
# things are being asserted, and they are separable: that usage a tool reports lands on
# the call's own audit row, and that a money ceiling read from those rows refuses.
#
# Every test drives the real door — a `tools/call` over HTTP through `broker.call` — for
# the reason the ceiling tests above do: the gate rides the broker's step 2, so what is
# under test is the whole path or it is nothing.

OPUS = "claude-opus-5"

# A million input tokens of Opus is $15.00 at `core/usage.RATES`, which makes every
# assertion below a round number somebody can check by hand rather than a float nobody
# can read.
A_MILLION = {"model": OPUS, "input_tokens": 1_000_000}


def spend_row():
    """The last audit row's five usage columns."""
    record = read_audit()[-1]
    return (
        record["model"],
        record["input_tokens"],
        record["output_tokens"],
        record["cache_read_tokens"],
        record["cache_write_tokens"],
    )


def test_reported_usage_lands_on_the_call_s_own_audit_row(
    client, auth, vetted, token, monkeypatch
):
    """**The whole reason 045b exists.** A door call writes no `runs` row, so before this
    the counters had nowhere to go. One row, written once, at INSERT — `audit` forbids UPDATE by trigger, so there
    was never a write-then-fill-in shape available."""
    monkeypatch.setattr(
        EchoTransport,
        "usage",
        {**A_MILLION, "output_tokens": 5, "cache_read_tokens": 3, "cache_write_tokens": 1},
    )
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, READ, {"owner": "acme"})

    assert spend_row() == (OPUS, 1_000_000, 5, 3, 1)


def test_a_call_that_touched_no_model_records_null_and_not_zero(
    client, auth, vetted, token
):
    """The distinction migration 048 is built on: NULL is *not applicable*, 0 would be *a
    model call that cost nothing*. Every ordinary tool call is the first, and the spend
    query filters on `IS NOT NULL` — so zeros here would enrol the whole audit log in a
    money question."""
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, READ, {"owner": "acme"})

    assert spend_row() == ("", None, None, None, None)


def test_a_refused_call_reports_no_spend(client, auth, vetted, token, monkeypatch):
    """A refusal happens before anything executes, so it cannot carry usage however
    loudly the server would have reported it. That is what makes a denied-then-retried
    call impossible to double-count."""
    monkeypatch.setattr(EchoTransport, "usage", A_MILLION)
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, READ, {"owner": "not-granted"})

    record = read_audit()[-1]
    assert record["decision"] == "deny"
    assert record["input_tokens"] is None
    assert door.door_spend_today(Principal.machine(row["id"], TEST_TENANT))["usd"] == 0


def test_the_crossing_call_completes_and_the_next_one_is_refused(
    client, auth, vetted, token, monkeypatch
):
    """**Read-then-decide, stated as a behaviour rather than a caveat.**

    A door call's token cost exists only after it returns, so — unlike the call-count
    ceiling, which reserves a unit known in advance — nothing can be held back. The call
    that crosses the line completes at whatever it cost; the one after it is refused.
    Migration 046's header made this argument for runs before there was a door call that
    needed it.
    """
    monkeypatch.setattr(EchoTransport, "usage", A_MILLION)
    monkeypatch.setattr(config, "MCP_USD_PER_DAY", 10.0)
    row, _ = token
    grant(row, TRIAGE)

    first = call(client, auth, READ, {"owner": "acme"}).json()
    assert first["result"]["isError"] is False, "the crossing call must complete"

    second = call(client, auth, READ, {"owner": "acme"}).json()
    assert second["result"]["isError"] is True


def test_the_money_refusal_is_an_ordinary_broker_denial_naming_its_dial(
    client, auth, vetted, token, monkeypatch
):
    """`test_the_ceiling_refuses_and_the_record_is_an_ordinary_broker_denial`'s assertion
    for the second ceiling, and the equality is again the point: the money check sits in
    the budget's own seat, so it writes the same `deny` row every other refusal writes and
    no audit query had to learn a new shape."""
    monkeypatch.setattr(EchoTransport, "usage", A_MILLION)
    monkeypatch.setattr(config, "MCP_USD_PER_DAY", 10.0)
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, READ, {"owner": "acme"})
    call(client, auth, READ, {"owner": "acme"})

    record = read_audit()[-1]
    assert record["decision"] == "deny"
    assert record["agent"] == "triage"
    assert storage.SPEND_REFUSAL_MARKER in record["reason"]
    assert "$15.00" in record["reason"] and "$10.00" in record["reason"]
    assert "CARNET_MCP_USD_PER_DAY" in record["reason"]
    # The refusal itself spent nothing — nothing executed.
    assert record["input_tokens"] is None


def test_the_two_door_refusals_never_read_as_each_other(
    client, auth, vetted, token, monkeypatch
):
    """**The coupling `SPEND_REFUSAL_MARKER` exists to pin.**

    The Overview tells the two ceilings apart by matching substrings, so if either
    sentence ever contained the other's marker, one band would silently absorb the other
    and the absorbed line would read zero forever — a wrong number nobody would think to
    check. Asserted against the real sentences rather than the constants.
    """
    monkeypatch.setattr(EchoTransport, "usage", A_MILLION)
    monkeypatch.setattr(config, "MCP_USD_PER_DAY", 10.0)
    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 1)
    row, _ = token
    grant(row, TRIAGE)

    # Money is checked before the call count, so the second call is refused for spend
    # even though the call allowance is also exhausted by then.
    call(client, auth, READ, {"owner": "acme"})
    call(client, auth, READ, {"owner": "acme"})
    money = read_audit()[-1]["reason"]

    monkeypatch.setattr(config, "MCP_USD_PER_DAY", 0.0)
    call(client, auth, READ, {"owner": "acme"})
    calls = read_audit()[-1]["reason"]

    assert storage.SPEND_REFUSAL_MARKER in money
    assert storage.CEILING_REFUSAL_MARKER not in money
    assert storage.CEILING_REFUSAL_MARKER in calls
    assert storage.SPEND_REFUSAL_MARKER not in calls


def test_a_spend_refusal_does_not_burn_the_call_allowance(
    client, auth, vetted, token, monkeypatch
):
    """The money check runs **before** the call-count reserve, and the order is
    load-bearing: the count consumes, so checking it first would charge a call to a caller
    about to be refused for spend — and a token refused all afternoon would burn its whole
    call allowance doing it. The broker makes the same promise one layer up."""
    monkeypatch.setattr(EchoTransport, "usage", A_MILLION)
    monkeypatch.setattr(config, "MCP_USD_PER_DAY", 10.0)
    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 100)
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, READ, {"owner": "acme"})
    for _ in range(5):
        call(client, auth, READ, {"owner": "acme"})

    assert storage.active().mcp_calls_spent(TEST_TENANT, row["id"], today()) == 1


def test_the_token_ceiling_catches_what_the_dollar_one_cannot_see(
    client, auth, vetted, token, monkeypatch
):
    """**Why there are two dials rather than one.**

    `estimate_cost` returns None for a model nobody has a price for, so its tokens cost
    `$0.00` against a dollar ceiling however many of them there are. At the door that is
    the ordinary case, because a customer
    brokers whichever provider they run. The token net is what bounds them, and the
    refusal names which ceiling was met and what the dollar figure is short by.
    """
    monkeypatch.setattr(
        EchoTransport, "usage", {"model": "llama-3-70b", "input_tokens": 1_000_000}
    )
    monkeypatch.setattr(config, "MCP_USD_PER_DAY", 10.0)
    monkeypatch.setattr(config, "MCP_TOKENS_PER_DAY", 500_000)
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, READ, {"owner": "acme"})
    assert call(client, auth, READ, {"owner": "acme"}).json()["result"]["isError"] is True

    reason = read_audit()[-1]["reason"]
    assert "CARNET_MCP_TOKENS_PER_DAY" in reason
    assert "llama-3-70b" in reason, "an unpriced model must be named, not silently dropped"


def test_both_dials_off_means_nothing_is_read_and_nothing_refuses(
    client, auth, vetted, token, monkeypatch
):
    """Off by default, and off means the gate returns before touching storage — the shape
    `TokenBudget.reserve` already has, and the reason an unmetered door pays nothing for
    the check."""
    monkeypatch.setattr(EchoTransport, "usage", A_MILLION)
    monkeypatch.setattr(config, "MCP_USD_PER_DAY", 0.0)
    monkeypatch.setattr(config, "MCP_TOKENS_PER_DAY", 0)
    row, _ = token
    grant(row, TRIAGE)

    def refuse(*args, **kwargs):  # pragma: no cover - reached only on regression
        raise AssertionError("the spend gate read storage with both dials off")

    monkeypatch.setattr(storage.active(), "door_spend_since", refuse)

    for _ in range(3):
        assert call(client, auth, READ, {"owner": "acme"}).json()["result"]["isError"] is False


def test_a_negative_dial_is_off_rather_than_a_ceiling_of_zero(
    client, auth, vetted, token, monkeypatch
):
    """The comparison is `<= 0`, not `== 0` — `RUNS_PER_HOUR`'s convention, and the reason
    `core.usage.metered` is one expression with a name rather than an inline test. A
    reader writing the obvious equality would turn `-1` into a ceiling of zero and refuse
    every call on a deployment that meant to opt out."""
    monkeypatch.setattr(EchoTransport, "usage", A_MILLION)
    monkeypatch.setattr(config, "MCP_USD_PER_DAY", -1.0)
    row, _ = token
    grant(row, TRIAGE)

    for _ in range(2):
        assert call(client, auth, READ, {"owner": "acme"}).json()["result"]["isError"] is False


def test_a_lying_connector_cannot_spend_somebody_s_ceiling(
    client, auth, vetted, token, monkeypatch
):
    """**The refusal direction that costs money.**

    These counters are a callee's word — a vendor's response body, not a reply this
    process received. A connector reporting an absurd number would exhaust a principal's
    allowance in one call without making an expensive one, which is a denial of service
    written in a JSON field. So a malformed report is dropped whole, and the call is
    audited as unmeasured: under-counting costs a customer nothing, over-counting refuses
    their traffic.
    """
    monkeypatch.setattr(config, "MCP_USD_PER_DAY", 10.0)
    row, _ = token
    grant(row, TRIAGE)

    for report in (
        {"model": OPUS, "input_tokens": 10**15},          # past MAX_REPORTED_TOKENS
        {"model": OPUS, "input_tokens": -1_000_000},      # would subtract from the sum
        {"model": OPUS, "input_tokens": "many"},          # not a number at all
        {"model": OPUS, "input_tokens": True},            # a bool is an int in Python
        "9000",                                            # not a mapping
    ):
        monkeypatch.setattr(EchoTransport, "usage", report)
        assert call(client, auth, READ, {"owner": "acme"}).json()["result"]["isError"] is False
        assert spend_row() == ("", None, None, None, None), report

    assert door.door_spend_today(Principal.machine(row["id"], TEST_TENANT))["usd"] == 0


def test_a_report_naming_only_a_model_records_nothing(
    client, auth, vetted, token, monkeypatch
):
    """The live end-to-end's find, driven through the door. A server that names what
    answered and nothing about what it cost has reported nothing — and a row of zeros
    would claim a model call that spent nothing, which does not happen."""
    monkeypatch.setattr(EchoTransport, "usage", {"model": OPUS})
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, READ, {"owner": "acme"})

    assert spend_row() == ("", None, None, None, None)


def test_a_partly_bad_report_is_dropped_whole_rather_than_partly_trusted(
    client, auth, vetted, token, monkeypatch
):
    """A report with one bad counter is a report from something that does not know what it
    is reporting. Keeping the three that parsed would put a confidently wrong number in
    the meter, which is worse than an honest gap."""
    monkeypatch.setattr(
        EchoTransport,
        "usage",
        {"model": OPUS, "input_tokens": 100, "output_tokens": -1},
    )
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, READ, {"owner": "acme"})

    assert spend_row() == ("", None, None, None, None)


def test_a_server_cannot_report_its_own_spend_in_the_result_body(
    client, auth, vetted, token, monkeypatch
):
    """**The reserved key is cleared before `_meta` is read, and this is why.**

    `normalize` returns `structuredContent` — a mapping the *server* composed — as the
    result. Without the unconditional clear, a server could meter itself simply by putting
    our key in its response body and skipping `_meta` entirely. The only route to the
    meter is the extension point we read.
    """
    row, _ = token
    grant(row, TRIAGE)

    class SmugglingTransport(EchoTransport):
        def send(self, message):
            reply = super().send(message)
            if reply and message.get("method") == "tools/call":
                reply["result"]["structuredContent"] = {
                    "acted_as": "x",
                    "carnet_reported_usage": {"model": OPUS, "input_tokens": 10**9},
                }
            return reply

    monkeypatch.setattr(
        mcp, "_transport_for", lambda tenant_id, conn, cred: SmugglingTransport(cred)
    )

    call(client, auth, READ, {"owner": "acme"})

    assert spend_row() == ("", None, None, None, None)


def test_the_refusal_quotes_the_same_arithmetic_the_screen_reads(
    client, auth, vetted, token, monkeypatch
):
    """**One function, two readers**, which is the whole reason `door_spend_today` exists
    rather than a query written in each place: `GET /me/tokens/{id}/budget` renders from
    it and the gate refuses from it, so a person refused at $15.00 cannot open their token
    page and read a different number. The route's half is asserted in `test_api.py`, where
    there is a browser session to read it with.

    Only the *first* call is in the total: the second was refused, and a refusal spends
    nothing. That is the read-then-decide shape stated as a number.
    """
    monkeypatch.setattr(EchoTransport, "usage", A_MILLION)
    monkeypatch.setattr(config, "MCP_USD_PER_DAY", 10.0)
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, READ, {"owner": "acme"})
    call(client, auth, READ, {"owner": "acme"})
    refusal = read_audit()[-1]["reason"]

    spend = door.door_spend_today(Principal.machine(row["id"], TEST_TENANT))

    assert f"${spend['usd']:,.2f}" in refusal
    assert spend["usd"] == 15.0
    assert spend["tokens"] == 1_000_000
    assert spend["by_model"] == [
        {
            "model": OPUS,
            "input_tokens": 1_000_000,
            "output_tokens": 0,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
        }
    ]


def test_the_window_is_frozen_for_the_length_of_a_call(principal):
    """A call that straddles midnight UTC is charged to one window rather than checked
    against one and written to another."""
    budget = door.TokenBudget(principal, 5, window=date(2026, 8, 21))

    assert budget.window == date(2026, 8, 21)
    assert budget.reserve(tools.REGISTRY["post_message"]).allowed
    assert storage.active().mcp_calls_spent(
        TEST_TENANT, principal.id, date(2026, 8, 21)
    ) == 1


def test_the_window_has_one_definition_and_the_default_uses_it(principal):
    """**Step 035e, and the reason `budget_window` is a function at all.**

    It acquired a second caller: `GET /me/tokens/{id}/budget` has to read back the same
    day the door charges against, or the screen and the door disagree about whether a
    token is exhausted — for a few milliseconds a day, at the boundary, where nobody
    would have written a test. So the default here is not `datetime.now(...).date()`
    spelled a second time; it is the one definition, and this is what says so.
    """
    from datetime import datetime, timezone

    assert door.budget_window() == datetime.now(timezone.utc).date()
    assert door.TokenBudget(principal, 5).window == door.budget_window()


def test_the_metered_predicate_is_not_an_equality(principal):
    """`reserve` compares `<= 0`, not `== 0` — `RUNS_PER_HOUR`'s convention, where a
    negative value disables the dial too.

    Extracted because the second reader is a **screen**, and a page writing the obvious
    `ceiling == 0` would report a deployment set to `-1` as metered and render a count
    of nothing as a count of calls. That is the reassuring direction, which is the one
    nobody rechecks — so the comparison has one home and both callers use it.
    """
    assert door.TokenBudget.metered(1) is True
    assert door.TokenBudget.metered(1000) is True
    assert door.TokenBudget.metered(0) is False
    assert door.TokenBudget.metered(-5) is False

    # And the branch it governs: an unmetered ceiling admits without writing, so there
    # is no row to read back — which is the whole of trap 1.
    assert door.TokenBudget(principal, -5).reserve(
        tools.REGISTRY["post_message"]
    ).allowed
    assert storage.active().mcp_calls_spent(
        TEST_TENANT, principal.id, door.budget_window()
    ) == 0


# --- 033a's three distinctions, through the newest caller -------------------------


def test_the_tom_scenario_door_shaped(client, auth, token, isolated_storage):
    """**The defect this whole plan was arranged around, at the door that makes it
    urgent.**

    A `user`-identity tool called by a service token with no connection is *refused* —
    with the connector's shared credential configured and provably unused. Before 033a
    this fell back to it, and an intern's question reached a repository only the security
    team can read with every check passing.
    """
    tools.save_connector(TEST_TENANT, connector(identity="user"), actor=TEST_ACTOR)
    row, _ = token
    grant(row, TRIAGE)

    body = call(client, auth, READ, {"owner": "acme"}).json()

    assert body["result"]["isError"] is True
    assert "unavailable" in body["result"]["structuredContent"]["error"]
    # `allow` + `outcome="error"`: the call was authorized and affordable, and the
    # credential is what stopped it. The distinction the record has carried since 7a.
    record = read_audit()[-1]
    assert (record["decision"], record["outcome"]) == ("allow", "error")
    assert record["credential"] is None


def test_a_service_tool_ignores_a_delegated_connection(client, auth, vetted, token, principal):
    """The silent-widening half. Somebody connecting their own account must not change
    how a shared tool behaves — the bot posts as the bot, whoever asked."""
    connections.connect_account(principal, "example", "priyas-own-token", actor=TEST_ACTOR)
    row, _ = token
    grant(row, TRIAGE)

    assert acted_as(call(client, auth, READ, {"owner": "acme"})) == SHARED
    assert read_audit()[-1]["credential"] == "shared"


def test_a_user_tool_uses_the_callers_own_account(client, auth, token, principal, isolated_storage):
    """And the audit row says so. The token's *own* connection, because through the door
    the caller is the token — which is exactly the thing acting-for exists to refine, in
    its own chunk, on top of this one."""
    tools.save_connector(TEST_TENANT, connector(identity="user"), actor=TEST_ACTOR)
    connections.connect_account(principal, "example", "cursors-own-token", actor=TEST_ACTOR)
    row, _ = token
    grant(row, TRIAGE)

    assert acted_as(call(client, auth, READ, {"owner": "acme"})) == "cursors-own-token"
    assert read_audit()[-1]["credential"] == "delegated"


def test_re_vetting_takes_effect_without_a_restart(client, auth, vetted, token, principal):
    """033a's fourth review defect, which the door inherits rather than reintroduces.

    `_BOUND` snapshots the descriptor and the broker reads `identity` off it, so an
    administrator who changes whose account a tool acts as saw storage and the admin
    screen agree with them while every process kept the old credential. `ensure_available`
    compares the bound descriptor against the manifest it re-reads each run — and the
    door goes through the same function, so it must not have found a way around it.
    """
    connections.connect_account(principal, "example", "cursors-own-token", actor=TEST_ACTOR)
    row, _ = token
    grant(row, TRIAGE)

    assert acted_as(call(client, auth, READ, {"owner": "acme"})) == SHARED

    tools.save_connector(TEST_TENANT, connector(identity="user"), actor=TEST_ACTOR)

    assert acted_as(call(client, auth, READ, {"owner": "acme"})) == "cursors-own-token"


def test_the_session_credential_is_not_the_calls_credential(
    client, auth, vetted, token, principal, built, monkeypatch
):
    """033a's first review defect, in the shape the door could have reintroduced.

    Binding is a tenant fact and a session is a credential fact. The door resolves what
    opens a session through `for_session` — shared first — exactly as a run does, and the
    per-call account stays the vetted `identity`'s answer. If the door had used
    `for_connector` here, a tenant where everybody connects their own account and no
    shared variable is set would meet a real server's 401 before listing a single tool.
    """
    monkeypatch.delenv("EXAMPLE_TOKEN")
    connections.connect_account(principal, "example", "cursors-own-token", actor=TEST_ACTOR)
    row, _ = token
    grant(row, TRIAGE)

    assert rpc(client, auth, "tools/list").json()["result"]["tools"]
    assert [t.credential for t in built] == ["cursors-own-token"]


# --- who may reach the door at all ------------------------------------------------


def test_the_door_needs_a_credential(client):
    assert client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}).status_code == 401


def test_a_persons_sign_in_token_is_refused_with_the_command_that_fixes_it(client):
    """Decision 1. A refusal rather than an accommodation: a person's OIDC token expires
    within the hour, so a client configured with one works this afternoon and fails
    tomorrow in a way that looks like the product being broken.

    403 rather than 401 — authenticating again with the same kind of credential is
    exactly what will not help.
    """
    app = create_app()
    app.dependency_overrides[principal_from_request] = lambda: Principal.user(
        OWNER, TEST_TENANT
    )
    person = TestClient(app)

    # **The handshake itself, not just the first useful call.** Refusing at `tools/list`
    # alone would let a misconfigured client connect and then break, which is the
    # confusing half of the failure rather than the honest one.
    handshake = person.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    listing = person.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})

    assert (handshake.status_code, listing.status_code) == (403, 403)
    assert "--mint-token" in handshake.json()["detail"]


def test_a_door_caller_cannot_supply_its_own_credential(client, auth, vetted, token, built):
    """**The broker's oldest rule, at its newest and least trusted input.**

    `permissions.check` refuses any `tool_input` carrying a credential-shaped name,
    because the broker injects those and nothing else may. Until now the thing on the
    other end of that rule was a model inside our own loop; through the door it is
    somebody else's agent, sending arbitrary JSON over the internet — which is a much
    better reason for the rule and exactly why it is worth asserting here rather than
    trusting that the door reaches the same function.

    Note what is checked besides the refusal: the token the server *would* have seen is
    the connector's, not the caller's string, and the audit record redacts the smuggled
    value rather than storing it in a table kept forever.
    """
    row, _ = token
    grant(row, TRIAGE)

    body = call(client, auth, READ, {"owner": "acme", "token": "attacker-supplied"}).json()

    assert body["result"]["isError"] is True
    assert "supplied by the broker" in body["result"]["structuredContent"]["error"]
    # Nothing was executed, so no session was ever opened under that string.
    assert "attacker-supplied" not in {t.credential for t in built}
    assert read_audit()[-1]["args"]["token"].startswith("sha256:")


def test_no_mcp_request_can_produce_a_system_principal(client, auth, vetted, token):
    """The 020 tripwire family's promised sibling.

    `access/roles.py` treats every `system` principal as an administrator before storage
    is touched, and says that is safe *because no HTTP caller can be one*. This is the
    newest HTTP caller, and it inherits the property from `deps.py` by construction — so
    this asserts it rather than trusting the inheritance.
    """
    row, _ = token
    grant(row, TRIAGE)
    call(client, auth, READ, {"owner": "acme"})

    assert {r["principal_kind"] for r in read_audit()} == {"machine"}


def test_a_token_sees_nothing_from_another_customer(client, auth, vetted, token):
    """The tenancy shape, at the new door. The tenant comes off the token's own row and
    there is no parameter through which a caller could assert one."""
    storage.active().create_tenant("t-other", "Other")
    tools.save_connector("t-other", connector(), actor=TEST_ACTOR)
    other = dict(TRIAGE)
    storage.active().save_agent("t-other", other, actor=TEST_ACTOR)
    row, _ = token
    storage.active().grant_agent(
        "t-other", other["name"], "machine", row["id"], role="user",
        granted_by=TEST_ACTOR, actor=TEST_ACTOR,
    )

    assert rpc(client, auth, "tools/list").json()["result"]["tools"] == []


# --- the protocol -----------------------------------------------------------------


def test_the_handshake_answers_with_tools_and_nothing_else(client, auth):
    """No `listChanged`: this server sends no notifications, and claiming a capability it
    does not have leaves a client waiting for an event that is never coming."""
    result = rpc(client, auth, "initialize", {"protocolVersion": "2025-06-18"}).json()["result"]

    assert result["protocolVersion"] == "2025-06-18"
    assert result["capabilities"] == {"tools": {}}
    assert result["serverInfo"]["name"] == "carnet"


def test_the_two_halves_of_this_repository_agree_about_the_newest_version():
    """**Two constants in two modules, pinned rather than trusted.**

    `tools/mcp/client.py` says what we send as a client; `routes_mcp.py` says what we
    answer as a server. They are deliberately separate — one is about talking to somebody
    else's server and the other about being one — and the `_OAUTH_ACCESS` precedent
    applies: the cost of that boundary is a test that fails when they drift.

    The specific drift this catches: somebody bumps the client to a newer revision and
    the server keeps answering an older one as its latest, so our own e2e passes (the
    client asks for the new one, which is not in the server's supported list, and gets
    told the old one) while every other client is quietly negotiated down.
    """
    from carnet.api.routes_mcp import LATEST_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS
    from carnet.tools.mcp.client import PROTOCOL_VERSION

    assert LATEST_PROTOCOL_VERSION == PROTOCOL_VERSION
    assert PROTOCOL_VERSION in SUPPORTED_PROTOCOL_VERSIONS


def test_an_unknown_protocol_version_is_answered_with_ours(client, auth):
    """Negotiation, not insistence — and not agreement either. A client asking for
    something this subset has never been checked against gets told what we speak."""
    result = rpc(client, auth, "initialize", {"protocolVersion": "1999-01-01"}).json()["result"]

    from carnet.api.routes_mcp import LATEST_PROTOCOL_VERSION

    assert result["protocolVersion"] == LATEST_PROTOCOL_VERSION


def test_a_notification_is_answered_with_202_and_no_body(client, auth):
    """What the specification asks for, and what this repository's own `HttpTransport`
    asserts on the other side of the wire."""
    response = client.post(
        "/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=auth
    )

    assert response.status_code == 202
    assert response.content == b""


def test_ping_costs_nothing(client, auth):
    assert rpc(client, auth, "ping").json()["result"] == {}


def test_an_unimplemented_method_says_which_four_exist(client, auth):
    body = rpc(client, auth, "resources/list").json()

    assert body["error"]["code"] == -32601
    assert "tools/call" in body["error"]["message"]


def test_a_call_with_no_name_is_invalid_params(client, auth):
    assert rpc(client, auth, "tools/call", {"arguments": {}}).json()["error"]["code"] == -32602


def test_the_id_comes_back_on_every_answer(client, auth):
    """JSON-RPC's whole correlation mechanism, and the one thing a client cannot work
    around."""
    assert rpc(client, auth, "ping", message_id="abc-1").json()["id"] == "abc-1"


def test_the_door_does_not_answer_get(client, auth):
    """`GET` opens a server-initiated stream and `DELETE` ends a session id. This server
    is stateless and has neither, and both are optional in the specification — so they
    are answered by not existing."""
    assert client.get("/mcp", headers=auth).status_code == 405
    assert client.delete("/mcp", headers=auth).status_code == 405


def test_a_brokered_denial_is_a_result_with_iserror_not_a_protocol_error(
    client, auth, vetted, token
):
    """The mapping decision 4 rests on, and `api/errors.py`'s rule at a new door: a
    brokered denial is the system working exactly as designed. The calling agent is told
    and carries on, exactly as a model does — and it gets the broker's own sentence,
    which is something it can act on by narrowing its request."""
    row, _ = token
    grant(row, TRIAGE)

    body = call(client, auth, READ, {"owner": "not-granted"}).json()

    assert "error" not in body
    assert body["result"]["isError"] is True
    assert body["result"]["structuredContent"]["denied_by"] == "broker"


def test_a_tool_that_fails_at_the_server_is_audited_as_an_error_not_a_denial(
    client, auth, vetted, token, monkeypatch
):
    """The other half of `isError`, and the two must stay distinguishable in the log:
    *this was refused* and *this was permitted and did not work* call for opposite
    responses from whoever reads the record."""
    row, _ = token
    grant(row, TRIAGE)

    class Failing(EchoTransport):
        def send(self, message):
            if "id" in message and message["method"] == "tools/call":
                return {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "error": {"code": -32602, "message": "no such repository"},
                }
            return super().send(message)

    monkeypatch.setattr(mcp, "_transport_for", lambda t, c, cred: Failing(cred))
    body = call(client, auth, READ, {"owner": "acme"}).json()

    assert body["result"]["isError"] is True
    record = read_audit()[-1]
    assert (record["decision"], record["outcome"]) == ("allow", "error")
    # Permitted, so it spent budget and the credential is recorded — neither of which is
    # true of a denial. That is the difference the two fields exist to carry.
    assert record["credential"] == "shared"


def test_a_connector_that_will_not_answer_a_named_call_says_so(
    client, auth, vetted, token, monkeypatch
):
    """Loud where `tools/list` is quiet, and the asymmetry is the point: the caller named
    one tool and is owed the real reason. Dropping it silently here would reach the
    broker as "not a registered tool" — a true sentence about a false cause."""
    row, _ = token
    grant(row, TRIAGE)

    def refuse(*_args, **_kwargs):
        raise TransportError("connection refused", delivered=False)

    monkeypatch.setattr(mcp, "_transport_for", refuse)
    body = call(client, auth, READ, {"owner": "acme"}).json()

    assert body["error"]["code"] == -32603
    assert "example" in body["error"]["message"]


# --- edges: the protocol at its awkward inputs ------------------------------------
#
# Everything below was found by probing rather than by design, and each one is here
# because the answer was not obvious before it was run.


def test_a_falsy_id_is_still_a_request(client, auth):
    """`0` and `""` are legal JSON-RPC ids and both are falsy in Python.

    Dispatch turns on `message.id is None` rather than on truthiness, and this is the
    test that keeps it that way: a client numbering its messages from zero — which is
    exactly what a `for` loop does — would otherwise have every request treated as a
    notification and answered 202 with no body, silently doing nothing.
    """
    for message_id in (0, ""):
        answered = rpc(client, auth, "ping", message_id=message_id).json()
        assert answered["id"] == message_id
        assert answered["result"] == {}


def test_a_message_with_no_id_executes_nothing(client, auth, vetted, token, built):
    """**A notification must not be a way to make an unlogged call.**

    JSON-RPC says a message with no id wants no answer, and the honest reading is that
    a `tools/call` shaped that way is a caller mistake rather than a fire-and-forget
    request: executing it would spend budget and touch a real system to produce a result
    nobody will ever see, and the only trace would be in a log the caller is not reading.

    So it is answered 202 and dropped. Asserted three ways, because "nothing happened"
    is the kind of claim that needs to be checked at each place it could be false.
    """
    row, _ = token
    grant(row, TRIAGE)

    response = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "tools/call",
              "params": {"name": READ, "arguments": {"owner": "acme"}}},
        headers=auth,
    )

    assert (response.status_code, response.content) == (202, b"")
    assert read_audit() == []
    assert not [t for t in built if t.calls]


def test_a_batch_and_a_positional_params_list_are_refused_without_a_500(client, auth):
    """Neither is something MCP sends. Batching was removed from the specification in
    2025-06-18, and `params` is always an object there — but both are legal JSON-RPC in
    general, so a client library could produce one, and the answer has to be a refusal
    rather than an unhandled exception.

    422 rather than a JSON-RPC `-32700`: there is no `id` to answer against in a batch,
    and a caller sending either is not speaking this protocol. Written down here because
    the plan promised `-32700` and the honest reading turned out to be the other one.
    """
    batch = client.post("/mcp", json=[{"jsonrpc": "2.0", "id": 1, "method": "ping"}], headers=auth)
    positional = rpc(client, auth, "ping", [1, 2])

    assert (batch.status_code, positional.status_code) == (422, 422)


def test_a_call_with_arguments_that_are_not_an_object_is_invalid_params(client, auth):
    assert rpc(client, auth, "tools/call", {"name": READ, "arguments": [1]}).json()["error"][
        "code"
    ] == -32602


def test_a_call_with_no_arguments_reaches_the_broker_and_is_audited(
    client, auth, vetted, token
):
    """Missing arguments are the *broker's* question, not the framing's. A tool whose
    resource argument was not supplied is refused by `permissions.check` — fail-closed,
    with a sentence naming the argument — and that refusal is a decision, so it is
    recorded like any other."""
    row, _ = token
    grant(row, TRIAGE)

    body = rpc(client, auth, "tools/call", {"name": READ}).json()

    assert body["result"]["isError"] is True
    assert "none was supplied" in body["result"]["structuredContent"]["error"]
    assert read_audit()[-1]["decision"] == "deny"


def test_a_cursor_we_never_issued_is_ignored_rather_than_refused(client, auth, vetted, token):
    """This server pages nothing, so a `nextCursor` never leaves it. A client echoing
    one back is confused, and the complete list is the answer that unconfuses it —
    refusing would strand a client that cannot know why."""
    row, _ = token
    grant(row, TRIAGE)

    with_cursor = rpc(client, auth, "tools/list", {"cursor": "nonsense"}).json()

    assert [t["name"] for t in with_cursor["result"]["tools"]] == [READ]
    assert "nextCursor" not in with_cursor["result"]


def test_every_other_verb_on_the_door_is_405(client, auth):
    """`GET` and `DELETE` are the two the specification defines and this server has
    neither — no server-initiated stream, no session id to terminate. The rest were never
    anything. All of them answer by the route not existing for that method."""
    for verb in ("get", "put", "delete", "options", "head"):
        assert getattr(client, verb)("/mcp", headers=auth).status_code == 405


# --- edges: who is refused, and with which status ----------------------------------


def test_the_three_ways_a_token_stops_working(client, vetted, token, owner):
    """Revoked is a 401 (the e2e drives that one against a live server); the other two
    are 403s with sentences, because authenticating again would not help and the person
    reading the failure needs to know which it was. Both are `access/tokens.py`'s rules,
    inherited by this door rather than restated in it — which is what this asserts."""
    row, presented = token
    grant(row, TRIAGE)
    headers = {"Authorization": f"Bearer {presented}"}
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    store = storage.active()

    store.set_user_status(TEST_TENANT, OWNER, "disabled", actor="system:test")
    disabled = client.post("/mcp", json=body, headers=headers)
    store.set_user_status(TEST_TENANT, OWNER, "active", actor="system:test")

    store.set_tenant_status(TEST_TENANT, "suspended")
    suspended = client.post("/mcp", json=body, headers=headers)
    store.set_tenant_status(TEST_TENANT, "active")

    assert (disabled.status_code, suspended.status_code) == (403, 403)
    assert "no longer an active account" in disabled.json()["detail"]
    assert "suspended" in suspended.json()["detail"]


def test_a_malformed_credential_is_one_sentence_whatever_is_wrong_with_it(client):
    """The anti-enumeration rule, at the newest door. A caller must not be able to tell
    an id that exists from one that does not, or a wrong secret from a revoked token."""
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    answers = {
        client.post("/mcp", json=body, headers={"Authorization": h}).json()["detail"]
        for h in ("Bearer art_m_nope.secret", "Bearer art_m_x.y", "Bearer eyJhbGc.x.y")
    }

    assert answers == {"not a valid token for this service"}


# --- edges: what the grant list does at its boundaries ----------------------------


def test_an_agent_granting_no_tools_contributes_nothing(client, auth, vetted, token):
    row, _ = token
    grant(row, agent("empty", [], {}))

    assert rpc(client, auth, "tools/list").json()["result"]["tools"] == []


def test_a_hand_written_tool_needs_no_server_and_works_through_the_door(
    client, auth, token, isolated_var_dir
):
    """`post_message` is in `REGISTRY`, not in any connector, so it binds nothing and is
    unaffected by every server being down. The two registries are a security boundary
    rather than a filing convenience, and the door has to respect the same split."""
    row, _ = token
    grant(row, agent("chatter", ["post_message"], {"chat.channel": {"write": ["#eng"]}}))

    listed = rpc(client, auth, "tools/list").json()["result"]["tools"]
    called = call(client, auth, "post_message", {"channel": "#eng", "text": "hello"})

    assert [t["name"] for t in listed] == ["post_message"]
    assert called.json()["result"]["isError"] is False
    assert read_audit()[-1]["credential"] == "shared"


def test_un_vetting_a_tool_takes_it_off_the_door(client, auth, vetted, token):
    """**And the control that does it is `agents.get`'s validation, which is worth
    pinning rather than trusting.**

    A tool bound earlier in this process stays in the process-global bound registry —
    `ensure_available` adds and never removes, which predates this step and is true of
    runs too. What keeps an un-vetted tool from being reachable is that every path to the
    broker loads its agent through `agents.get`, which validates the config against
    `known_names` and refuses one naming a tool the tenant no longer vets.

    So this asserts the outcome rather than the mechanism, and it is the test that would
    fail if somebody made `_granted_agents` skip validation for speed.
    """
    row, _ = token
    grant(row, TRIAGE)
    call(client, auth, READ, {"owner": "acme"})
    assert tools.get(READ, TEST_TENANT) is not None, "precondition: it is bound"

    tools.save_connector(
        TEST_TENANT,
        binding.Connector(id="example", launch=connector().launch, vetted=[]),
        actor=TEST_ACTOR,
    )

    assert rpc(client, auth, "tools/list").json()["result"]["tools"] == []
    refused = call(client, auth, READ, {"owner": "acme"}).json()
    assert refused["error"]["code"] == -32602
    # Still bound in this process, which is exactly why the check above is load-bearing.
    assert tools.get(READ, TEST_TENANT) is not None


def test_one_broken_agent_does_not_take_a_tool_another_agent_still_carries(
    client, auth, vetted, token
):
    """The interaction between skipping an invalid agent and the union rule.

    Two agents grant the same tool; one of them is edited into invalidity. The tool must
    survive on the other, and the call must attribute to it — otherwise one broken config
    silently removes capability that a second, perfectly good grant still provides.
    """
    row, _ = token
    grant(row, TRIAGE)
    grant(row, SECURITY)

    broken = dict(SECURITY)
    broken["permissions"] = {"tools": [READ, "example_deleted"], "scope": {}}
    storage.active().save_agent(TEST_TENANT, broken, actor=TEST_ACTOR)

    assert [t["name"] for t in rpc(client, auth, "tools/list").json()["result"]["tools"]] == [READ]
    assert acted_as(call(client, auth, READ, {"owner": "acme"})) == SHARED
    assert read_audit()[-1]["agent"] == "triage"


# --- edges: the budget at its boundaries ------------------------------------------


def test_the_ceiling_is_exact_at_one(client, auth, vetted, token, monkeypatch):
    """A boundary must have one answer, and the one that keeps spending is the wrong one
    to guess — `check_row_is_live`'s reasoning about `expires_at`, at a second dial."""
    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 1)
    row, _ = token
    grant(row, TRIAGE)

    first = call(client, auth, READ, {"owner": "acme"}).json()["result"]["isError"]
    second = call(client, auth, READ, {"owner": "acme"}).json()["result"]["isError"]

    assert (first, second) == (False, True)


def test_a_negative_ceiling_is_off_rather_than_impossible(client, auth, vetted, token, monkeypatch):
    """`<= 0`, not `== 0`. An operator who types `-1` meant "off", and a dial that read
    it as "refuse everything" would take the door down for a typo."""
    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", -5)
    row, _ = token
    grant(row, TRIAGE)

    assert call(client, auth, READ, {"owner": "acme"}).json()["result"]["isError"] is False
    assert storage.active().mcp_calls_spent(TEST_TENANT, row["id"], today()) == 0


def test_a_tool_that_fails_still_spends_its_call(client, auth, vetted, token, monkeypatch):
    """`Budget.reserve` consumes before execution because the point is to bound calls
    that *reach an external system*, and a call that failed still hit it. The door
    inherits that rather than deciding it, and a caller retrying a broken tool must not
    get unlimited retries."""
    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 50)
    row, _ = token
    grant(row, TRIAGE)

    class Failing(EchoTransport):
        def send(self, message):
            if "id" in message and message["method"] == "tools/call":
                return {"jsonrpc": "2.0", "id": message["id"],
                        "error": {"code": -1, "message": "boom"}}
            return super().send(message)

    monkeypatch.setattr(mcp, "_transport_for", lambda t, c, cred: Failing(cred))
    call(client, auth, READ, {"owner": "acme"})

    assert storage.active().mcp_calls_spent(TEST_TENANT, row["id"], today()) == 1


def test_the_ceiling_holds_when_ten_calls_arrive_at_once(client, auth, vetted, token, monkeypatch):
    """The API runs endpoints in a threadpool, so simultaneous door calls are the
    ordinary shape rather than a hypothetical. Exactly the ceiling may pass.

    This is the in-memory store's half of the property; `test_concurrency.py` holds the
    Postgres statement's half, which is the one that matters for replicas.
    """
    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 5)
    row, _ = token
    grant(row, TRIAGE)
    # Bound first, so ten threads race the budget rather than the binding.
    call(client, auth, READ, {"owner": "acme"})

    outcomes: list = []
    lock = threading.Lock()

    def go():
        answered = call(client, auth, READ, {"owner": "acme"}).json()["result"]["isError"]
        with lock:
            outcomes.append(answered)

    threads = [threading.Thread(target=go) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # One was spent by the warm-up call, so four of the ten may pass.
    assert outcomes.count(False) == 4
    assert storage.active().mcp_calls_spent(TEST_TENANT, row["id"], today()) == 5


# --- edges: a caller whose own account is broken ----------------------------------
#
# The defect this family was written for: a `CredentialError` raised while *binding* was
# reported as "'example' could not be reached" — false in every clause, at a JSON-RPC
# code meaning the server broke — and, worse, it happened before the broker, so the call
# left **no audit record at all**, while the neighbouring case (no connection row, where
# `for_session` returns None rather than raising) reached the broker and was audited.
#
# It bites only where `for_session` falls back to the caller's own credential: the
# deployment with no shared variable set, which is 033a's own first review defect one
# layer up.


def _expired_connection(principal):
    connections.connect_account(
        principal,
        "example",
        "expired-token",
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        actor=TEST_ACTOR,
    )


def test_a_broken_connection_is_answered_by_the_broker_and_written_down(
    client, auth, token, principal, isolated_storage, monkeypatch
):
    """The case the fix recovers: the tool is bound, so the call proceeds and step 3
    produces both the refusal and the record — identically to a caller with no connection
    at all, which is the point."""
    tools.save_connector(TEST_TENANT, connector(identity="user"), actor=TEST_ACTOR)
    row, _ = token
    grant(row, TRIAGE)
    connections.connect_account(principal, "example", "good-token", actor=TEST_ACTOR)
    rpc(client, auth, "tools/list")  # binds while the credential still works

    _expired_connection(principal)
    monkeypatch.delenv("EXAMPLE_TOKEN")
    body = call(client, auth, READ, {"owner": "acme"}).json()

    assert "error" not in body, "a credential problem is a tool error, not a protocol one"
    assert body["result"]["isError"] is True
    record = read_audit()[-1]
    assert (record["decision"], record["outcome"]) == ("allow", "error")
    assert "credential fetch failed" in record["reason"]


def test_an_unbindable_broken_connection_names_the_account_not_the_server(
    client, auth, token, principal, isolated_storage, monkeypatch
):
    """And the case the fix cannot recover, answered honestly instead.

    With nothing bound there is no descriptor and none can be fetched, so the call cannot
    reach the broker — but the sentence must still be about the caller's own connection
    rather than about a server that was never dialled. No audit record, because no
    decision was made: `ToolUnavailable`'s docstring is the argument.
    """
    tools.save_connector(TEST_TENANT, connector(identity="user"), actor=TEST_ACTOR)
    row, _ = token
    grant(row, TRIAGE)
    _expired_connection(principal)
    monkeypatch.delenv("EXAMPLE_TOKEN")

    body = call(client, auth, READ, {"owner": "acme"}).json()

    assert "expired" in body["error"]["message"]
    assert "could not be reached" not in body["error"]["message"]
    assert read_audit() == []


def test_a_service_tool_is_untouched_by_the_callers_broken_connection(
    client, auth, token, principal, isolated_storage
):
    """033a's first review defect, at the door. A connector whose tools are all `service`
    must not break because one caller's own account expired — `for_session` prefers the
    shared credential precisely so that a person's broken connection cannot take down a
    tool that would never have read their row."""
    tools.save_connector(TEST_TENANT, connector(identity="service"), actor=TEST_ACTOR)
    row, _ = token
    grant(row, TRIAGE)
    _expired_connection(principal)

    assert [t["name"] for t in rpc(client, auth, "tools/list").json()["result"]["tools"]] == [READ]
    assert acted_as(call(client, auth, READ, {"owner": "acme"})) == SHARED


# --- edges: a caller with no account at all, against a server that demands one -----
#
# Step 046, and the last member of the family above. Its siblings cover a credential
# that *raises* — broken, expired, unreadable. This is the caller with **nothing**:
# a service token (no person behind it), no shared variable, no connection row — so
# `for_session` returns None rather than raising, the door dials the handshake with
# no credential, and a server that demands one answers 401. Before the fix that 401
# was dressed as "'example' could not be reached ... (401)" — the exact sentence the
# family's header calls false in every clause, one branch over — and the caller was
# sent to check a vendor that had answered perfectly. Observed in the wild by the
# external harness against the hosted GitHub MCP server, 2026-08-28.


class DemandsAuth(EchoTransport):
    """A server that refuses the anonymous handshake, as real credentialed ones do.

    The autouse `built` fixture's servers accept anonymity, which is what keeps the
    designed anonymous-bind path (list, then let the broker refuse and audit) alive
    in the rest of the suite. This one is the other kind of vendor.
    """

    def send(self, message):
        if not self.credential:
            raise TransportError(
                "server refused the request (401). Server said: bad request: "
                "missing required Authorization header",
                delivered=False,
                status=401,
            )
        return super().send(message)


def test_a_server_demanding_an_account_names_the_token_not_the_server(
    client, auth, token, isolated_storage, monkeypatch
):
    """The strict half: the caller named one tool, and the answer it is owed is the
    credential fact — a service token has no person behind it — with the remedies,
    not a vendor outage that never happened. No audit record, on the family's own
    precedent: nothing bound, so no decision was made."""
    tools.save_connector(TEST_TENANT, connector(identity="user"), actor=TEST_ACTOR)
    row, _ = token
    grant(row, TRIAGE)
    monkeypatch.delenv("EXAMPLE_TOKEN")
    monkeypatch.setattr(mcp, "_transport_for", lambda t, c, cred: DemandsAuth(cred))

    body = call(client, auth, READ, {"owner": "acme"}).json()

    message = body["error"]["message"]
    assert "personal token" in message
    assert "acting-for" in message
    assert "could not be reached" not in message
    assert read_audit() == []


def test_tools_list_omits_the_unreachable_account_quietly(
    client, auth, token, isolated_storage, monkeypatch
):
    """The non-strict half: the list still serves — one connector's problem must not
    hold the rest hostage — and the omission is a warning carrying the credential
    sentence rather than a vendor complaint. Asserted through the log because the
    protocol has no channel for 'omitted because'."""
    tools.save_connector(TEST_TENANT, connector(identity="user"), actor=TEST_ACTOR)
    row, _ = token
    grant(row, TRIAGE)
    monkeypatch.delenv("EXAMPLE_TOKEN")
    monkeypatch.setattr(mcp, "_transport_for", lambda t, c, cred: DemandsAuth(cred))

    response = rpc(client, auth, "tools/list")

    assert response.status_code == 200
    assert response.json()["result"]["tools"] == []


def test_a_mixed_identity_connector_keeps_the_generic_sentence(
    client, auth, token, isolated_storage, monkeypatch
):
    """The boundary, held on purpose. When even one wanted tool is `service`, the
    session is the tenant's business — a shared credential could have opened it — so
    a 401 there is genuinely a fact about the connector's configuration and the
    generic sentence is the honest one."""
    mixed = binding.Connector(
        id="example",
        launch=binding.HttpLaunch(
            url=f"https://{TEST_HOST}/mcp/", credential_env="EXAMPLE_TOKEN"
        ),
        vetted=[
            binding.Vetted("list_issues", effect="read", identity="user", resources=[REPO]),
            binding.Vetted("create_issue", effect="write", identity="service", resources=[REPO]),
        ],
    )
    tools.save_connector(TEST_TENANT, mixed, actor=TEST_ACTOR)
    row, _ = token
    grant(row, agent(name="both", tools_granted=[READ, WRITE],
                     scope={"github.repo": {"read": ["acme"], "write": ["acme"]}}))
    monkeypatch.delenv("EXAMPLE_TOKEN")
    monkeypatch.setattr(mcp, "_transport_for", lambda t, c, cred: DemandsAuth(cred))

    body = call(client, auth, READ, {"owner": "acme"}).json()

    assert "could not be reached" in body["error"]["message"]


def test_the_bound_path_refuses_with_the_same_sentence_and_a_record(
    client, auth, token, isolated_storage, monkeypatch
):
    """The other arm, found by the external harness the same evening the first fix
    landed: once anything binds the connector, the call reaches the broker — which
    audited the full reason and handed the model "unavailable (credential error)",
    a stub with no remedy in it. The two arms must hand the caller the same
    sentence; only the record differs, and here there is one."""
    tools.save_connector(TEST_TENANT, connector(identity="user"), actor=TEST_ACTOR)
    row, _ = token
    grant(row, TRIAGE)
    monkeypatch.delenv("EXAMPLE_TOKEN")
    rpc(client, auth, "tools/list")  # binds anonymously; EchoTransport permits it

    body = call(client, auth, READ, {"owner": "acme"}).json()

    assert body["result"]["isError"] is True
    text = body["result"]["structuredContent"]["error"]
    assert "personal token" in text
    assert "acting-for" in text
    record = read_audit()[-1]
    assert (record["decision"], record["outcome"]) == ("allow", "error")
    assert "personal token" in record["reason"]


def test_a_service_tokens_user_identity_refusal_names_the_three_remedies(
    principal, isolated_storage
):
    """The sentence itself, at its source. The old one told a machine to 'use the
    Connections page', which connects accounts for the signed-in person and can never
    help a machine — a true-sounding sentence pointing at the wrong fix, which is
    this family's founding defect shape."""
    from carnet.core import credentials

    with pytest.raises(credentials.CredentialError) as refused:
        credentials.for_connector("example", principal, identity="user")

    sentence = str(refused.value)
    assert "personal token" in sentence
    assert "--connect-account" in sentence
    assert "acting-for" in sentence
    assert "Connections page" not in sentence


# --- edges: what the record says when the tool misbehaves --------------------------


def test_an_oversize_response_is_refused_and_recorded_as_one(
    client, auth, vetted, token, monkeypatch
):
    """The per-response ceiling still applies through the door, and it is a *refusal*
    rather than a truncation: a clipped JSON payload is malformed JSON the caller has to
    guess at, where an explicit refusal is something it can act on by narrowing."""
    monkeypatch.setattr(config, "MAX_RESPONSE_BYTES", 50)
    row, _ = token
    grant(row, TRIAGE)

    class Big(EchoTransport):
        def send(self, message):
            if "id" in message and message["method"] == "tools/call":
                return {"jsonrpc": "2.0", "id": message["id"],
                        "result": {"content": [{"type": "text",
                                                "text": json.dumps({"x": "y" * 500})}]}}
            return super().send(message)

    monkeypatch.setattr(mcp, "_transport_for", lambda t, c, cred: Big(cred))
    body = call(client, auth, READ, {"owner": "acme"}).json()

    assert body["result"]["isError"] is True
    assert "exceeded the size limit" in body["result"]["structuredContent"]["error"]
    assert read_audit()[-1]["outcome"] == "oversize"


def test_a_write_that_may_have_landed_is_recorded_as_unknown(
    client, auth, vetted, token, monkeypatch
):
    """**The one lie the audit log must never tell**, at the door that will carry the
    most writes. A write that reached a server and never answered is not the same event
    as one that plainly did not, and only this record will ever remember which."""
    row, _ = token
    grant(row, FILER)

    class Hangs(EchoTransport):
        def send(self, message):
            if "id" in message and message["method"] == "tools/call":
                raise TransportError("no reply in time", delivered=True)
            return super().send(message)

    monkeypatch.setattr(mcp, "_transport_for", lambda t, c, cred: Hangs(cred))
    body = call(client, auth, WRITE, {"owner": "acme", "title": "t"}).json()

    assert body["result"]["isError"] is True
    assert read_audit()[-1]["outcome"] == "unknown"


def test_the_tools_redaction_policy_survives_the_door(client, auth, token, isolated_var_dir):
    """A tool naming an argument as sensitive has that honoured wherever the call came
    from. `post_message` redacts its message text, which through the door is somebody
    else's agent's content."""
    row, _ = token
    grant(row, agent("chatter", ["post_message"], {"chat.channel": {"write": ["#eng"]}}))

    call(client, auth, "post_message", {"channel": "#eng", "text": "secret plans"})

    logged = read_audit()[-1]["args"]
    assert logged["channel"] == "#eng"
    assert logged["text"].startswith("sha256:")


def test_a_name_that_could_not_be_a_tool_name_is_refused_without_a_row(
    client, auth, vetted, token
):
    """**An unmetered write into an append-only table, closed.**

    `make_denial_record` states as a structural fact that no user free text reaches it —
    true while its only producers were the two grant seams, which see constants,
    principal ids and agent names. The door is the first caller whose `resource_id`
    arrives off the wire from somebody else's agent, and the column is unbounded TEXT.

    The refusal happens *before* the broker, so the per-token ceiling never sees it: a
    token granted nothing at all could otherwise put a megabyte per request into the one
    table an operator reads during an incident, degrading the evidence as much as the
    disk. A name that cannot match the registry's own `TOOL_NAME_RE` is not an attempt on
    a named thing, so it is refused with no row at all.
    """
    row, _ = token
    grant(row, TRIAGE)
    before = len(storage.active().denial_records(TEST_TENANT))

    body = call(client, auth, "x" * 5000, {"owner": "acme"}).json()

    assert body["error"]["code"] == -32602
    assert len(storage.active().denial_records(TEST_TENANT)) == before
    # The sentence itself must not carry the payload back either.
    assert len(body["error"]["message"]) < 400


def test_a_plausible_but_ungranted_name_is_still_written_down(client, auth, vetted, token):
    """The other side of the guard: real probing stays recorded. Narrowing what the log
    accepts must not become a way to probe a tenant's tool names unobserved."""
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, "example_delete_repository", {"owner": "acme"})

    recorded = storage.active().denial_records(TEST_TENANT, resource_kind="tool")
    assert recorded[-1]["resource_id"] == "example_delete_repository"


def test_an_oversized_call_is_refused_before_anything_is_recorded(
    client, auth, vetted, token, monkeypatch
):
    """**The audit log's half of the amplification, closed the same way.**

    Every brokered call records its arguments, and through the door those arguments are
    composed by somebody else's agent rather than by a model inside our own loop. The
    per-token ceiling does not bound them: a *denied* call spends no budget — deliberately,
    so an agent fixing its own scope mistakes cannot exhaust its day doing so — and still
    writes a row. Left open, a token granted one tool could put megabytes per request into
    an append-only table, with nothing counting.

    Refused before the broker, so an oversized call costs a sentence rather than a row.
    """
    monkeypatch.setattr(config, "MCP_MAX_CALL_BYTES", 500)
    row, _ = token
    grant(row, TRIAGE)

    body = call(client, auth, READ, {"owner": "acme", "note": "z" * 5000}).json()

    assert body["error"]["code"] == -32602
    assert "limit is 500" in body["error"]["message"]
    assert read_audit() == []
    assert storage.active().mcp_calls_spent(TEST_TENANT, row["id"], today()) == 0


def test_a_denied_call_of_ordinary_size_is_still_recorded(client, auth, vetted, token):
    """The other side of that guard: bounding the size must not stop the log recording
    refusals, which is the whole reason a denial writes a row at all."""
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, READ, {"owner": "not-granted", "note": "ordinary"})

    assert read_audit()[-1]["decision"] == "deny"
    assert read_audit()[-1]["args"]["note"] == "ordinary"


def test_a_refusal_never_quotes_back_more_than_it_was_asked_to(client, auth, vetted, token):
    """A refusal that echoes a megabyte costs more to serve than the request did.

    The same shape as the two amplification defects one section up — unbounded input from
    somebody else's agent, repeated back somewhere it is kept or sent — and worth closing
    at the same time even though this one only reaches the caller who sent it.
    """
    row, _ = token
    grant(row, TRIAGE)

    unknown_method = rpc(client, auth, "y" * 9000).json()
    oversized = call(client, auth, "z" * 9000, {"owner": "acme"}).json()

    assert len(unknown_method["error"]["message"]) < 300
    assert len(oversized["error"]["message"]) < 400


# --- acting-for: whom a door call is made for (033c) ------------------------------
#
# The shared-service shape: one machine token, fifty people behind it. Acting-for is
# how a call says which one — verified (a forwarded IdP token) or asserted (an email
# the connector chose to believe) — and these tests hold the three rules that keep it
# from becoming something else: it never changes authorization, it never switches a
# `service` tool off the shared credential, and the audit log never collapses
# verified, asserted and none.

from carnet.access import oidc, providers  # noqa: E402
from carnet.access.oidc import JwksCache  # noqa: E402
from carnet.api import routes_mcp  # noqa: E402

from test_acting import Idp  # noqa: E402

TOM = "u-tom"
TOM_EMAIL = "tom@acme.com"

# The wire contract, pinned as a literal on purpose: renaming the key breaks every
# client that ever sent it, so a rename must fail a test rather than pass a refactor.
ACTING_FOR_KEY = "com.carnet/acting-for"


def test_the_wire_key_is_pinned():
    assert routes_mcp.ACTING_FOR_META_KEY == ACTING_FOR_KEY


def meta_call(client, auth, name, arguments, acting_for):
    """A `tools/call` carrying an acting-for identity, exactly as the SDK sends it:
    one namespaced key in the request's `_meta`."""
    return rpc(
        client,
        auth,
        "tools/call",
        {"name": name, "arguments": arguments, "_meta": {ACTING_FOR_KEY: acting_for}},
    )


@pytest.fixture
def idp(isolated_storage, monkeypatch):
    """This tenant's identity provider, its keys served without a network — through
    `providers.KEYS`, the one per-process cache both doors verify with since 033c."""
    provider = Idp()
    storage.active().save_tenant_idp(TEST_TENANT, provider.row())
    monkeypatch.setattr(
        providers,
        "KEYS",
        JwksCache(fetch=lambda uri: oidc.keys_from_jwks({"keys": [provider.jwk()]})),
    )
    return provider


@pytest.fixture
def tom(idp):
    """A person who has signed in once, as the verified path requires. Not the token's
    owner — the whole point is that the caller and the person differ."""
    storage.active().create_user(
        TEST_TENANT,
        {"id": TOM, "issuer": idp.issuer, "subject": "00u-tom", "email": TOM_EMAIL},
    )
    return TOM


def connect_tom():
    """Tom's own account for the connector — called after the connector row exists,
    because a credential cannot be sealed against a connector that does not."""
    connections.connect_account(
        Principal.user(TOM, TEST_TENANT), "example", "toms-own-token", actor=TEST_ACTOR
    )


def test_a_verified_acting_for_completes_the_tom_scenario(
    client, auth, token, idp, tom
):
    """**The scenario this plan was arranged around, finally allowed to succeed.**

    A `user`-identity tool called by a shared service *for Tom* — his own IdP token
    forwarded per call — reaches the upstream server as **Tom's** account, and the
    audit row says whom and how sure: `acting_for=tom@…, identity_source=verified,
    credential=delegated`. The vendor enforces what Tom may see, because the call went
    out as him; that is the whole mechanism.
    """
    tools.save_connector(TEST_TENANT, connector(identity="user"), actor=TEST_ACTOR)
    connect_tom()
    row, _ = token
    grant(row, TRIAGE)

    response = meta_call(client, auth, READ, {"owner": "acme"}, {"token": idp.token()})

    assert acted_as(response) == "toms-own-token"
    record = read_audit()[-1]
    assert record["acting_for"] == TOM_EMAIL
    assert record["identity_source"] == "verified"
    assert record["credential"] == "delegated"


def test_acting_for_never_switches_a_service_tool_off_the_shared_credential(
    client, auth, vetted, token, idp, tom
):
    """**The back-door test.** A `service`-identity tool with acting-for present still
    uses the shared credential — the vetting decided whose account, and acting-for only
    ever picks *which person* within a decision that already said "a person's". The
    acting-for is recorded; the resolution is untouched. Anything else makes acting-for
    a caller-controlled switch into the vetted identity.
    """
    connect_tom()
    row, _ = token
    grant(row, TRIAGE)

    response = meta_call(client, auth, READ, {"owner": "acme"}, {"token": idp.token()})

    assert acted_as(response) == SHARED
    record = read_audit()[-1]
    assert record["credential"] == "shared"
    assert record["acting_for"] == TOM_EMAIL
    assert record["identity_source"] == "verified"


def test_asserted_identity_needs_the_connector_opt_in(client, auth, token, idp, tom):
    """Off unless a connector turns it on — the resting posture is *verified or
    nothing*, and an assertion arriving where nobody opted in is refused before the
    broker with the same denial-log treatment an ungranted name gets."""
    tools.save_connector(TEST_TENANT, connector(identity="user"), actor=TEST_ACTOR)
    row, _ = token
    grant(row, TRIAGE)

    before = len(read_audit())
    body = meta_call(client, auth, READ, {"owner": "acme"}, {"email": TOM_EMAIL}).json()

    assert body["error"]["code"] == -32602
    assert "allow_asserted_identity" in body["error"]["message"]
    # No broker decision existed to audit; the attempt lands in the denial log.
    assert len(read_audit()) == before
    denials = storage.active().denial_records(TEST_TENANT, resource_kind="tool")
    assert denials[-1]["resource_id"] == READ
    assert denials[-1]["required"] == "acting-for"


def test_asserted_identity_with_the_opt_in_acts_as_the_person_named(
    client, auth, token, idp, tom
):
    """The trusted-subsystem pattern, working — and the audit row keeps `asserted`
    apart from `verified`, because the two are worth different amounts and a log that
    collapses them is actively untrue."""
    tools.save_connector(
        TEST_TENANT, connector(identity="user", allow_asserted=True), actor=TEST_ACTOR
    )
    connect_tom()
    row, _ = token
    grant(row, TRIAGE)

    response = meta_call(client, auth, READ, {"owner": "acme"}, {"email": TOM_EMAIL})

    assert acted_as(response) == "toms-own-token"
    record = read_audit()[-1]
    assert record["acting_for"] == TOM_EMAIL
    assert record["identity_source"] == "asserted"
    assert record["credential"] == "delegated"


def test_an_asserted_ghost_on_a_user_tool_is_the_brokers_answer(
    client, auth, token, isolated_storage
):
    """An address matching nobody is let through resolution deliberately — on a
    `service` tool it is only an audit fact — and a `user` tool then refuses it at
    credential time, through the broker, so the refusal is audited with the assertion
    it was refused under. 033b's lesson: whenever the tool is bound, the broker
    answers a credential problem, producing both the sentence and the record."""
    tools.save_connector(
        TEST_TENANT, connector(identity="user", allow_asserted=True), actor=TEST_ACTOR
    )
    row, _ = token
    grant(row, TRIAGE)

    body = meta_call(
        client, auth, READ, {"owner": "acme"}, {"email": "ghost@acme.com"}
    ).json()

    assert body["result"]["isError"] is True
    assert "unavailable" in body["result"]["structuredContent"]["error"]
    record = read_audit()[-1]
    assert (record["decision"], record["outcome"]) == ("allow", "error")
    assert record["acting_for"] == "ghost@acme.com"
    assert record["identity_source"] == "asserted"
    assert "matches nobody" in record["reason"]


def test_a_denial_carries_the_acting_for_it_was_denied_under(
    client, auth, vetted, token, idp, tom
):
    """The plan's log line `tom@… (verified) … DENIED` is real: a scope refusal made
    with acting-for present records whom the call was for. And it is a *broker* denial
    under the token's own grants — acting-for changed nothing about authorization,
    which is the first of the four rules this chunk must keep."""
    row, _ = token
    grant(row, TRIAGE)

    body = meta_call(client, auth, READ, {"owner": "secret"}, {"token": idp.token()}).json()

    assert body["result"]["isError"] is True
    record = read_audit()[-1]
    assert record["decision"] == "deny"
    assert record["acting_for"] == TOM_EMAIL
    assert record["identity_source"] == "verified"


def test_meta_without_our_key_is_no_acting_for(client, auth, vetted, token):
    """Absent, empty, and carrying only other people's keys all mean the same thing —
    the SDK sends `"_meta": {}` on a perfectly plain call — and the record says `none`,
    which is an answer rather than an absence."""
    row, _ = token
    grant(row, TRIAGE)

    plain = rpc(client, auth, "tools/call", {"name": READ, "arguments": {"owner": "acme"}, "_meta": {}})
    progress = rpc(
        client,
        auth,
        "tools/call",
        {"name": READ, "arguments": {"owner": "acme"}, "_meta": {"progressToken": 7}},
    )

    assert acted_as(plain) == SHARED
    assert acted_as(progress) == SHARED
    for record in read_audit()[-2:]:
        assert record["acting_for"] is None
        assert record["identity_source"] == "none"


def test_a_malformed_acting_for_refuses_rather_than_degrading(
    client, auth, vetted, token
):
    """A typo'd key must not silently become an unattributed call."""
    row, _ = token
    grant(row, TRIAGE)

    typo = meta_call(client, auth, READ, {"owner": "acme"}, {"emial": TOM_EMAIL}).json()
    both = meta_call(
        client, auth, READ, {"owner": "acme"}, {"token": "x", "email": TOM_EMAIL}
    ).json()

    assert typo["error"]["code"] == -32602
    assert "emial" in typo["error"]["message"]
    assert both["error"]["code"] == -32602
    assert "exactly one" in both["error"]["message"]


def test_an_expired_forwarded_token_names_the_fix(client, auth, vetted, token, idp, tom):
    import time as _time

    row, _ = token
    grant(row, TRIAGE)
    stale = idp.token(iat=int(_time.time()) - 900, exp=int(_time.time()) - 600)

    body = meta_call(client, auth, READ, {"owner": "acme"}, {"token": stale}).json()

    assert body["error"]["code"] == -32602
    assert "fresh" in body["error"]["message"]


def test_an_oversized_acting_for_costs_a_sentence_and_no_row(
    client, auth, vetted, token, monkeypatch
):
    """The bound the handoff demanded: acting-for rides beside the arguments the call
    cap measures, so it gets its own — refused at the route's edge, before the door,
    with nothing recorded anywhere and no budget spent."""
    monkeypatch.setattr(config, "MCP_MAX_ACTING_FOR_BYTES", 64)
    row, _ = token
    grant(row, TRIAGE)

    before_audit = len(read_audit())
    before_denials = len(storage.active().denial_records(TEST_TENANT, resource_kind="tool"))
    body = meta_call(
        client, auth, READ, {"owner": "acme"}, {"token": "x" * 200}
    ).json()

    assert body["error"]["code"] == -32602
    assert "64" in body["error"]["message"]
    assert len(read_audit()) == before_audit
    assert (
        len(storage.active().denial_records(TEST_TENANT, resource_kind="tool"))
        == before_denials
    )
    assert storage.active().mcp_calls_spent(TEST_TENANT, row["id"], today()) == 0


def test_no_acting_for_on_a_user_tool_stays_the_tom_refusal(
    client, auth, token, isolated_storage
):
    """The refusal 033a built is unchanged when nothing is claimed — and its audited
    reason now names acting-for as the shared-service remedy, so the operator reading
    the log learns the fix that did not exist when 033a wrote the sentence."""
    tools.save_connector(TEST_TENANT, connector(identity="user"), actor=TEST_ACTOR)
    row, _ = token
    grant(row, TRIAGE)

    body = call(client, auth, READ, {"owner": "acme"}).json()

    assert body["result"]["isError"] is True
    record = read_audit()[-1]
    assert (record["decision"], record["outcome"]) == ("allow", "error")
    assert record["identity_source"] == "none"
    assert "acting-for" in record["reason"]



# --- the door renews a delegated connection, the way a run does --------------------


def test_a_stale_oauth_connection_is_renewed_rather_than_refused(
    client, auth, token, idp, tom, monkeypatch
):
    """**The door had no equivalent of `runs.execute`'s pre-run refresh, and acting-for
    is what made that bite.**

    A person's OAuth connection lasts one access token. Through the door — where
    nothing ever called `oauth.refresh_for_run` — it then refused with *reconnect that
    account*, about a credential that was never broken and whose refresh token was
    sitting in the same row. 033b's edge-case defect at a new address: a true-sounding
    sentence sending somebody to the wrong fix.

    Reachable before this chunk (a machine token with its own connection) and
    unimportant then, because a machine's credential is pasted rather than consented.
    Acting-for makes it the mainline case: the account a door call acts as is now a
    *person's*, and a person's is the kind that arrives through a consent flow.
    """
    from test_oauth import ACCESS_TOKEN, FakeProvider  # noqa: PLC0415

    from carnet.access import oauth  # noqa: PLC0415

    fake = FakeProvider()
    monkeypatch.setattr(oauth, "_post_form", fake)

    tools.save_connector(TEST_TENANT, connector(identity="user"), actor=TEST_ACTOR)
    oauth.configure(
        TEST_TENANT,
        "example",
        authorize_endpoint=f"https://{TEST_HOST}/authorize",
        token_endpoint=f"https://{TEST_HOST}/token",
        revoke_endpoint="",
        client_id="client-abc",
        client_secret="shhh",
        scopes=("offline_access",),
        actor=TEST_ACTOR,
    )

    # Tom's account, through the whole consent flow, so the row is a real OAuth one.
    person = Principal.user(TOM, TEST_TENANT)
    url = oauth.begin(person, "example", redirect_uri="https://carnet.acme.com/cb")
    oauth.complete(url.split("state=")[1].split("&")[0], "the-authorization-code")

    # An hour passes.
    store = storage.active()
    row = store.find_connection(TEST_TENANT, "user", TOM, "example")
    store.update_connection_credential(
        TEST_TENANT, "user", TOM, "example",
        ciphertext=row["ciphertext"],
        key_id=row["key_id"],
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        refresh_expires_at=None,
        if_updated_at=row["updated_at"],
    )

    row_, _ = token
    grant(row_, TRIAGE)

    response = meta_call(client, auth, READ, {"owner": "acme"}, {"token": idp.token()})

    # Renewed and used, rather than refused. The upstream sees the *second* token the
    # provider issued, which is the one only a refresh could have produced.
    assert acted_as(response) == f"{ACCESS_TOKEN}-2"
    record = read_audit()[-1]
    assert (record["decision"], record["outcome"]) == ("allow", "ok")
    assert record["credential"] == "delegated"
    assert record["acting_for"] == TOM_EMAIL


def test_a_service_tool_does_not_pay_for_a_refresh_it_cannot_use(
    client, auth, vetted, token, principal, monkeypatch
):
    """The narrowing that keeps this off the hot path of every call: a `service` tool's
    credential is an environment variable, so there is nothing to renew and no lock to
    take. Asserted by counting what the door touched, because 'we skipped it' is not
    visible any other way."""
    from carnet.access import oauth  # noqa: PLC0415

    touched = []
    monkeypatch.setattr(
        oauth, "refresh_connection", lambda p, c, **k: touched.append((p, c))
    )
    row, _ = token
    grant(row, TRIAGE)

    assert acted_as(call(client, auth, READ, {"owner": "acme"})) == SHARED
    assert touched == []


# --- the edge-case pass: what probing found that reading did not ------------------


def add_ada(idp):
    """A second person with their own account, so the credential a call acts with can
    be shown to follow the identity rather than the connection opened first. A helper
    rather than a fixture, because the connector row has to exist before a credential
    can be sealed against it."""
    storage.active().create_user(
        TEST_TENANT,
        {"id": "u-ada", "issuer": idp.issuer, "subject": "00u-ada", "email": "ada@acme.com"},
    )
    connections.connect_account(
        Principal.user("u-ada", TEST_TENANT), "example", "adas-own-token", actor=TEST_ACTOR
    )


def test_two_people_through_one_token_do_not_share_a_session(
    client, auth, token, idp, tom
):
    """**The worst thing acting-for could do, asserted rather than reasoned about.**

    One machine token, one connector, two people back to back. The session pool is
    keyed by credential fingerprint, so each reaches the upstream as themselves — but
    "keyed by the credential" is a property of a module this one only calls, and the
    cost of it being coarser is Ada acting with Tom's authority at a vendor.
    """
    tools.save_connector(TEST_TENANT, connector(identity="user"), actor=TEST_ACTOR)
    connect_tom()
    add_ada(idp)
    row, _ = token
    grant(row, TRIAGE)

    first = meta_call(client, auth, READ, {"owner": "acme"}, {"token": idp.token()})
    second = meta_call(
        client, auth, READ, {"owner": "acme"},
        {"token": idp.token(sub="00u-ada", email="ada@acme.com")},
    )

    assert acted_as(first) == "toms-own-token"
    assert acted_as(second) == "adas-own-token", "the second person acted as the first"
    assert [r["acting_for"] for r in read_audit()[-2:]] == [TOM_EMAIL, "ada@acme.com"]


def test_acting_for_does_not_inherit_the_persons_own_grants(
    client, auth, vetted, token, idp, tom
):
    """**Acting-for is not impersonation, and this is the test that says so.**

    Tom is granted `security` (scope `secret`) in his own right; the token holds only
    `triage` (scope `acme`). Acting for Tom must not reach `secret`: what may be called
    is the token's grants, and what the call goes out *as* is the only thing acting-for
    changes.
    """
    row, _ = token
    grant(row, TRIAGE)
    agents.save(TEST_TENANT, SECURITY, actor=TEST_ACTOR)
    storage.active().grant_agent(
        TEST_TENANT, "security", "user", tom, role="user",
        granted_by=TEST_ACTOR, actor=TEST_ACTOR,
    )

    body = meta_call(
        client, auth, READ, {"owner": "secret"}, {"token": idp.token()}
    ).json()

    assert body["result"]["isError"] is True, "acting-for widened what may be called"
    assert read_audit()[-1]["decision"] == "deny"
    assert read_audit()[-1]["agent"] == "triage"


def test_attribution_is_unchanged_by_acting_for(client, auth, vetted, token, idp, tom):
    """The union rule names the same agent with and without an identity on the call."""
    row, _ = token
    grant(row, TRIAGE)
    grant(row, FILER)

    call(client, auth, READ, {"owner": "acme"})
    meta_call(client, auth, READ, {"owner": "acme"}, {"token": idp.token()})

    assert [r["agent"] for r in read_audit()[-2:]] == ["triage", "triage"]


def test_a_lying_email_claim_does_not_reach_the_audit_column(
    client, auth, vetted, token, idp, tom
):
    """The token is genuine and its `email` claim names somebody else. What lands in an
    append-only column is the address on **our** user row, never claim text."""
    row, _ = token
    grant(row, TRIAGE)

    meta_call(client, auth, READ, {"owner": "acme"}, {"token": idp.token(email="ceo@acme.com")})

    assert read_audit()[-1]["acting_for"] == TOM_EMAIL


def test_the_identity_does_not_persist_to_the_next_call(
    client, auth, vetted, token, idp, tom
):
    """Per call, not per session — the whole reason the shape is `_meta` rather than a
    header or a handshake. A following call that claims nothing records `none`, not
    whatever the previous call on the same connection claimed."""
    row, _ = token
    grant(row, TRIAGE)

    meta_call(client, auth, READ, {"owner": "acme"}, {"token": idp.token()})
    call(client, auth, READ, {"owner": "acme"})

    assert [r["identity_source"] for r in read_audit()[-2:]] == ["verified", "none"]
    assert [r["acting_for"] for r in read_audit()[-2:]] == [TOM_EMAIL, None]


def test_a_refusal_never_echoes_the_acting_for_object_back(client, auth, vetted, token):
    """`QUOTE_LIMIT`'s rule, at the field that arrived without it: an acting-for
    object's **keys** are caller text too, bounded only by `MCP_MAX_ACTING_FOR_BYTES`
    — so a 4 KB key came back inside a 4 KB refusal. Naming the misspelling is the
    actionable half, so they are trimmed rather than dropped."""
    row, _ = token
    grant(row, TRIAGE)

    body = meta_call(client, auth, READ, {"owner": "acme"}, {"k" * 4000: "x"}).json()

    assert body["error"]["code"] == -32602
    assert len(body["error"]["message"]) < 600


def test_an_address_over_the_wire_maximum_is_refused_without_being_quoted(
    client, auth, vetted, token
):
    row, _ = token
    grant(row, TRIAGE)

    body = meta_call(
        client, auth, READ, {"owner": "acme"}, {"email": "a" * 300 + "@acme.com"}
    ).json()

    assert body["error"]["code"] == -32602
    assert len(body["error"]["message"]) < 600


@pytest.mark.parametrize("value", ["tom@acme.com", ["tom@acme.com"], 42, True])
def test_an_acting_for_that_is_not_an_object_is_refused(client, auth, vetted, token, value):
    """A bare string where an object belongs is a caller that has misread the shape,
    not a caller with no identity to declare."""
    row, _ = token
    grant(row, TRIAGE)

    assert "error" in meta_call(client, auth, READ, {"owner": "acme"}, value).json()


@pytest.mark.parametrize("meta", ["nonsense", 7, ["a"], None, {}, {"progressToken": 3}])
def test_a_meta_this_server_does_not_use_is_ignored_rather_than_refused(
    client, auth, vetted, token, meta
):
    """The other half of the same judgment. Our own object is refused when malformed;
    somebody else's `_meta` is left alone, because a server that rejects metadata it
    does not consume breaks conformant clients — the SDK puts its own keys there."""
    row, _ = token
    grant(row, TRIAGE)

    response = rpc(
        client, auth, "tools/call",
        {"name": READ, "arguments": {"owner": "acme"}, "_meta": meta},
    )

    assert acted_as(response) == SHARED
    assert read_audit()[-1]["identity_source"] == "none"


def test_an_explicit_null_acting_for_is_no_acting_for(client, auth, vetted, token):
    """A client that always sets the key and nulls it when nobody is signed in. Absent
    and null are the same claim — none — and `none` is what the record says."""
    row, _ = token
    grant(row, TRIAGE)

    response = rpc(
        client, auth, "tools/call",
        {"name": READ, "arguments": {"owner": "acme"},
         "_meta": {routes_mcp.ACTING_FOR_META_KEY: None}},
    )

    assert acted_as(response) == SHARED
    assert read_audit()[-1]["identity_source"] == "none"


def test_an_ungranted_name_is_refused_before_the_identity_is_examined(
    client, auth, vetted, token
):
    """Ordering, so acting-for cannot become an oracle: a caller must not be able to
    tell a granted name from an ungranted one by which refusal it gets."""
    row, _ = token
    grant(row, TRIAGE)

    body = meta_call(
        client, auth, WRITE, {"owner": "acme", "title": "x"}, {"emial": "junk"}
    ).json()

    assert "no agent this token is granted" in body["error"]["message"]
    denials = storage.active().denial_records(TEST_TENANT, resource_kind="tool")
    assert denials[-1]["required"] == "grant"


def test_a_refused_acting_for_writes_one_bounded_row_and_spends_nothing(
    client, auth, vetted, token
):
    """The unmetered-write shape 033b closed twice, checked at the new field. A refusal
    before the broker spends no budget by design — so what it writes has to be bounded
    by construction instead. `resource_id` is a tool name that already matched a
    granted agent's list, and `required` is a constant; the caller's own text reaches
    neither."""
    row, _ = token
    grant(row, TRIAGE)
    before = len(storage.active().denial_records(TEST_TENANT, resource_kind="tool"))

    for _ in range(5):
        meta_call(client, auth, READ, {"owner": "acme"}, {"email": "tom@acme.com"})

    rows = storage.active().denial_records(TEST_TENANT, resource_kind="tool")
    assert len(rows) - before == 5
    assert all(len(r["resource_id"]) < 100 for r in rows[-5:])
    assert "tom@acme.com" not in json.dumps(rows[-5:], default=str)
    assert storage.active().mcp_calls_spent(TEST_TENANT, row["id"], today()) == 0


def test_asserted_is_refused_on_a_service_tool_too_without_the_opt_in(
    client, auth, vetted, token
):
    """On a `service` tool an assertion resolves nothing — it is only an audit fact —
    and it is still refused without the opt-in. That is the point: what the connector
    is opting into is an unverified name entering an append-only log."""
    row, _ = token
    grant(row, TRIAGE)

    body = meta_call(client, auth, READ, {"owner": "acme"}, {"email": "tom@acme.com"}).json()

    assert body["error"]["code"] == -32602
    assert "allow_asserted_identity" in body["error"]["message"]


def test_a_hand_written_tool_has_no_connector_to_enable_assertion(
    client, auth, vetted, token
):
    """Fail-closed at the one tool shape that can never opt in: `post_message` has no
    connector row, so there is nobody to have made the decision."""
    row, _ = token
    grant(row, agent(
        name="poster",
        tools_granted=["post_message"],
        scope={"chat.channel": {"write": ["#eng"]}},
    ))

    body = meta_call(
        client, auth, "post_message", {"channel": "#eng", "text": "hi"},
        {"email": "tom@acme.com"},
    ).json()

    assert body["error"]["code"] == -32602
    assert "asserted identity" in body["error"]["message"]


def test_a_disabled_person_cannot_be_acted_for_through_the_door(
    client, auth, vetted, token, idp, tom
):
    """The one thing that cuts somebody off before their token expires, honoured at
    the newest door — a person who was turned off must not keep acting through a bot."""
    row, _ = token
    grant(row, TRIAGE)
    forwarded = idp.token()
    storage.active().set_user_status(TEST_TENANT, tom, "disabled", actor="system:test")

    body = meta_call(client, auth, READ, {"owner": "acme"}, {"token": forwarded}).json()

    assert body["error"]["code"] == -32602
    assert "disabled" in body["error"]["message"]


# --- personal tokens (033d): the owner's access, through the door ------------------
#
# The resolution itself is test_grants.py's; what belongs here is the door-shaped
# half — the list is the owner's union, the call is charged to the token and audited
# as the machine, and a `user`-identity tool acts as the OWNER's connected account
# with no second credential pasted anywhere.


@pytest.fixture
def personal(owner):
    """A personal token owned by Priya. Beside `token` (service, same owner) so tests
    can hold both and watch them differ."""
    row, presented = tokens.mint(
        TEST_TENANT, "priya-editor", owner, actor="system:cli", acts_as_owner=True
    )
    return row, presented


@pytest.fixture
def personal_auth(personal):
    _, presented = personal
    return {"Authorization": f"Bearer {presented}"}


def grant_owner(config_):
    """Save an agent and share it with PRIYA — never with the token, which is the
    entire shape under test: the owner's access is the grant."""
    agents.save(TEST_TENANT, config_, actor=TEST_ACTOR)
    storage.active().grant_agent(
        TEST_TENANT,
        config_["name"],
        "user",
        OWNER,
        role="user",
        granted_by=TEST_ACTOR,
        actor=TEST_ACTOR,
    )


def test_a_personal_token_lists_its_owners_union(client, personal_auth, vetted, personal):
    """`tools/list` through a personal token is the union of the OWNER's agents'
    tools — the token itself is granted nothing, which is what makes the Cursor
    one-liner real: mint, paste, done."""
    grant_owner(TRIAGE)
    grant_owner(FILER)

    names = [
        t["name"]
        for t in rpc(client, personal_auth, "tools/list").json()["result"]["tools"]
    ]

    assert names == sorted([READ, WRITE])


def test_a_personal_call_is_charged_to_the_token_and_audited_as_the_machine(
    client, personal_auth, vetted, personal
):
    """Still a machine principal, everywhere: the budget is the token's (two of
    Priya's tokens are two ceilings), and the record names `machine:<id>` — whose
    token it was is the read-time join's business, never a second principal column."""
    row, _ = personal
    grant_owner(TRIAGE)

    response = call(client, personal_auth, READ, {"owner": "acme"})

    assert acted_as(response) == SHARED
    assert storage.active().mcp_calls_spent(TEST_TENANT, row["id"], today()) == 1
    record = read_audit()[-1]
    assert (record["principal_kind"], record["principal_id"]) == ("machine", row["id"])
    assert record["agent"] == TRIAGE["name"]
    assert record["identity_source"] == "none"


def test_a_user_tool_through_a_personal_token_acts_as_the_owner(
    client, personal_auth, personal, isolated_storage
):
    """The credential gap the plan called out: Priya's connection was made by consent
    as `user:u-priya`, her token has no row of its own, and the call must reach the
    upstream as HER account — `credential=delegated`, with `acting_for` staying None,
    because the owner is a per-token constant and not a per-call claim (the
    distinction 033c's columns exist to keep)."""
    tools.save_connector(TEST_TENANT, connector(identity="user"), actor=TEST_ACTOR)
    connections.connect_account(
        Principal.user(OWNER, TEST_TENANT), "example", "priyas-own-token", actor=TEST_ACTOR
    )
    grant_owner(TRIAGE)

    response = call(client, personal_auth, READ, {"owner": "acme"})

    assert acted_as(response) == "priyas-own-token"
    record = read_audit()[-1]
    assert record["credential"] == "delegated"
    assert record["acting_for"] is None
    assert record["identity_source"] == "none"


def test_the_tokens_own_connection_is_never_consulted(
    client, personal_auth, personal, isolated_storage
):
    """"The owner has no connection, so act as the machine's instead" is the Tom
    defect with the names changed — so a connection provisioned for the token itself
    is dead weight on a personal token. Missing owner: refused, with the audited
    reason naming HER, because she is the one who can fix it. Present owner: hers
    wins, however long the machine's row has been sitting there."""
    row, _ = personal
    tools.save_connector(TEST_TENANT, connector(identity="user"), actor=TEST_ACTOR)
    connections.connect_account(
        Principal.machine(row["id"], TEST_TENANT),
        "example",
        "the-machines-own-token",
        actor=TEST_ACTOR,
    )
    grant_owner(TRIAGE)

    refused = call(client, personal_auth, READ, {"owner": "acme"}).json()

    assert refused["result"]["isError"] is True
    record = read_audit()[-1]
    assert (record["decision"], record["outcome"]) == ("allow", "error")
    assert OWNER in record["reason"]

    connections.connect_account(
        Principal.user(OWNER, TEST_TENANT), "example", "priyas-own-token", actor=TEST_ACTOR
    )

    assert acted_as(call(client, personal_auth, READ, {"owner": "acme"})) == "priyas-own-token"


def test_acting_for_outranks_the_owner(
    client, personal_auth, personal, idp, tom
):
    """The two compose, and the per-call claim wins: a personal token carrying a
    verified acting-for uses THAT person's account, records them in the acting-for
    columns, and stays a machine principal in the same row."""
    row, _ = personal
    tools.save_connector(TEST_TENANT, connector(identity="user"), actor=TEST_ACTOR)
    connections.connect_account(
        Principal.user(OWNER, TEST_TENANT), "example", "priyas-own-token", actor=TEST_ACTOR
    )
    connect_tom()
    grant_owner(TRIAGE)

    response = meta_call(
        client, personal_auth, READ, {"owner": "acme"}, {"token": idp.token()}
    )

    assert acted_as(response) == "toms-own-token"
    record = read_audit()[-1]
    assert record["acting_for"] == TOM_EMAIL
    assert record["identity_source"] == "verified"
    assert record["principal_id"] == row["id"]


def test_revoking_the_owners_grant_closes_the_door_immediately(
    client, personal_auth, vetted, personal
):
    """Nothing cached, nothing to expire: the owner losing a grant loses it through
    every personal token they hold, at the very next request."""
    grant_owner(TRIAGE)
    assert rpc(client, personal_auth, "tools/list").json()["result"]["tools"]

    storage.active().revoke_agent(
        TEST_TENANT, TRIAGE["name"], "user", OWNER, actor=TEST_ACTOR
    )

    assert rpc(client, personal_auth, "tools/list").json()["result"]["tools"] == []
    assert "error" in call(client, personal_auth, READ, {"owner": "acme"}).json()


def test_a_disabled_owner_is_refused_at_the_door(
    client, personal_auth, vetted, personal
):
    """`check_row_is_live`'s fourth check, doing for a personal token exactly what it
    has done for every machine token since 020 — offboarding Priya offboards her
    editor at its next request, with the specific 403 an operator needs."""
    grant_owner(TRIAGE)
    storage.active().set_user_status(TEST_TENANT, OWNER, "disabled", actor="system:test")

    response = rpc(client, personal_auth, "tools/list")

    assert response.status_code == 403
    assert "no longer an active account" in response.json()["detail"]


def test_an_old_record_still_resolves_to_a_name_and_an_owner(
    client, personal_auth, vetted, personal
):
    """The decided question's contract, pinned. `acts_as_owner` is derived at read
    time — never stored per record — and that is only honest if the join always
    answers: token revoked, owner disabled, and the row a `machine:m_...` string
    resolves through is still there saying who and through what."""
    row, _ = personal
    grant_owner(TRIAGE)
    call(client, personal_auth, READ, {"owner": "acme"})

    storage.active().revoke_api_token(TEST_TENANT, row["id"], actor=TEST_ACTOR)
    storage.active().set_user_status(TEST_TENANT, OWNER, "disabled", actor="system:test")

    record = read_audit()[-1]
    resolved = storage.active().find_api_token(record["principal_id"])
    assert resolved["name"] == "priya-editor"
    assert resolved["acts_as_owner"] is True
    who = storage.active().get_user(TEST_TENANT, resolved["owner_id"])
    assert who["email"] == "priya@acme.com"


def test_a_stale_connection_of_the_owner_is_renewed_for_a_personal_token(
    client, personal_auth, personal, monkeypatch, isolated_storage
):
    """033c's edge-case defect #1, guarded at the principal this chunk adds: the
    refresh must aim at the row the credential read will consult — the OWNER's — or a
    personal token works for one access-token lifetime and then refuses with a
    true-sounding sentence about a connection that was never broken."""
    from test_oauth import ACCESS_TOKEN, FakeProvider  # noqa: PLC0415

    from carnet.access import oauth  # noqa: PLC0415

    fake = FakeProvider()
    monkeypatch.setattr(oauth, "_post_form", fake)

    tools.save_connector(TEST_TENANT, connector(identity="user"), actor=TEST_ACTOR)
    oauth.configure(
        TEST_TENANT,
        "example",
        authorize_endpoint=f"https://{TEST_HOST}/authorize",
        token_endpoint=f"https://{TEST_HOST}/token",
        revoke_endpoint="",
        client_id="client-abc",
        client_secret="shhh",
        scopes=("offline_access",),
        actor=TEST_ACTOR,
    )

    # Priya's account, through the whole consent flow, so the row is a real OAuth one.
    person = Principal.user(OWNER, TEST_TENANT)
    url = oauth.begin(person, "example", redirect_uri="https://carnet.acme.com/cb")
    oauth.complete(url.split("state=")[1].split("&")[0], "the-authorization-code")

    # An hour passes.
    store = storage.active()
    row = store.find_connection(TEST_TENANT, "user", OWNER, "example")
    store.update_connection_credential(
        TEST_TENANT, "user", OWNER, "example",
        ciphertext=row["ciphertext"],
        key_id=row["key_id"],
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        refresh_expires_at=None,
        if_updated_at=row["updated_at"],
    )

    grant_owner(TRIAGE)

    response = call(client, personal_auth, READ, {"owner": "acme"})

    assert acted_as(response) == f"{ACCESS_TOKEN}-2"
    record = read_audit()[-1]
    assert (record["decision"], record["outcome"]) == ("allow", "ok")
    assert record["credential"] == "delegated"
    assert record["acting_for"] is None


def test_attribution_is_unchanged_by_the_redirection(
    client, personal_auth, vetted, personal
):
    """The union rule runs on the same candidates and the same pure
    `permissions.check` whether the granted list came from the token's own rows or
    the owner's — a personal token calling into the scope only one of the owner's
    agents allows is attributed to that agent, exactly as a service token would be."""
    grant_owner(TRIAGE)  # read: acme
    grant_owner(SECURITY)  # read: secret

    call(client, personal_auth, READ, {"owner": "secret"})

    record = read_audit()[-1]
    assert record["agent"] == "security"
    assert record["decision"] == "allow"
    assert record["principal_kind"] == "machine"


# --- 035a: the door's traffic, readable at last -----------------------------------
#
# Four chunks of plan 033 deferred this with the same sentence, and the gap it left is
# the sharpest kind: the rows with the most to say — whom a shared service claimed to
# act for, and whether that claim was worth anything — were written correctly and could
# be reached by nothing. `GET /runs/{id}` is the only other route over `audit` and it
# resolves a run id, which a `door-<hex>` correlation id can never be.
#
# These live here rather than in `test_api.py` because this is the only file that can
# produce a *real* door call and then read it back over HTTP. A hand-built audit row
# would assert against a shape the door might not actually write.


@pytest.fixture
def door_admin(client, idp):
    """An administrator with a browser session — a *user*, which is what makes this the
    right caller for the route.

    Deliberately not the token's owner and not a machine: `split_actor` refuses a
    machine outright ("an API token runs agents; it administers nothing"), and the
    question this page answers is about everybody's traffic rather than the reader's
    own.
    """
    email = "boss@acme.com"
    headers = {"Authorization": f"Bearer {idp.token(sub='00u-boss', email=email)}"}
    # The request first, then the lookup: a user does not exist until they sign in — the
    # row is keyed `(issuer, subject)` and the subject only arrives inside a token — so
    # there is no id to grant the role to until one has been made.
    client.get("/agents", headers=headers)
    principal_id = storage.active().find_user_by_email(TEST_TENANT, email)["id"]
    storage.active().grant_platform_role(
        TEST_TENANT, "user", principal_id, "admin", actor="system:cli"
    )
    return headers


def door_calls(client, headers, **params):
    return client.get("/admin/door-calls", headers=headers, params=params)


def test_a_real_door_call_is_readable_over_http(client, auth, vetted, token, door_admin):
    """The whole chunk, end to end: a call goes through `/mcp`, and an administrator
    reads it back over a route that could not see it before."""
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, READ, {"owner": "acme"})

    (record,) = door_calls(client, door_admin).json()
    assert record["tool"] == READ
    assert record["agent"] == "triage"
    assert (record["decision"], record["outcome"]) == ("allow", "ok")
    assert record["principal_kind"] == "machine"
    assert record["principal_id"] == row["id"]
    assert record["run_id"].startswith(door.CALL_ID_PREFIX)


def test_the_response_shape_is_the_record_less_what_it_must_not_carry(
    client, auth, vetted, token, door_admin
):
    """The field set, asserted whole — so a field added to `DoorCallRecord` without a
    thought about this list fails here rather than shipping.

    `args` and `credential` are the two the model deliberately does not declare: one is
    caller-supplied free text in a record kept forever, the other a lookup key nobody
    asked to read in a browser. Both are still in the stored row, which the second half
    asserts — the redaction is the schema's, not the store's.
    """
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, READ, {"owner": "acme"})

    (record,) = door_calls(client, door_admin).json()
    assert set(record) == {
        "v", "ts", "run_id", "principal_kind", "principal_id", "agent", "tool",
        "effect", "decision", "reason", "outcome", "duration_ms", "response_bytes",
        "acting_for", "identity_source",
        # 045b. Declared rather than redacted, unlike `args` and `credential`: token
        # counts are the answer to *why is this credential being refused*, which is the
        # question somebody opens this listing with.
        "model", "input_tokens", "output_tokens",
        "cache_read_tokens", "cache_write_tokens",
    }

    stored = storage.active().door_call_records(TEST_TENANT)[-1]
    assert "args" in stored and "credential" in stored


def test_the_three_identity_sources_reach_the_reader_apart(
    client, auth, token, door_admin, idp, tom
):
    """033c stored three values rather than two, and this is the route that has to keep
    them apart: an asserted name is worth exactly what the calling app's honesty is
    worth, and a reader that collapsed it into "has an acting-for" would upgrade it.

    All three in one listing, in one order, because the distinction only means anything
    side by side.

    A `service` tool with the opt-in is what makes all three reachable in one setup: on
    it an assertion resolves no credential and is *only* an audit fact, which is exactly
    the case the badge on the page has to be honest about.
    """
    tools.save_connector(
        TEST_TENANT, connector(allow_asserted=True), actor=TEST_ACTOR
    )
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, READ, {"owner": "acme"})
    meta_call(client, auth, READ, {"owner": "acme"}, {"token": idp.token()})
    meta_call(client, auth, READ, {"owner": "acme"}, {"email": TOM_EMAIL})

    records = door_calls(client, door_admin).json()
    assert [(r["identity_source"], r["acting_for"]) for r in records] == [
        ("none", None),
        ("verified", TOM_EMAIL),
        ("asserted", TOM_EMAIL),
    ]


def test_a_denied_door_call_is_in_the_listing(client, auth, vetted, token, door_admin):
    """A refusal is the row this page exists for, so it must not be the one that goes
    missing — and it arrives with an empty outcome and null timings, which the response
    model has to permit rather than coerce."""
    row, _ = token
    grant(row, TRIAGE)

    call(client, auth, READ, {"owner": "secret"})

    (record,) = door_calls(client, door_admin).json()
    assert record["decision"] == "deny"
    assert record["outcome"] == ""
    assert record["duration_ms"] is None
    assert "scope" in record["reason"]


def test_runs_are_not_in_the_door_listing(client, auth, vetted, token, door_admin, owner):
    """The separation, over HTTP. One table, two questions — and a run appearing here
    would make the page lie about what came through the door."""
    row, _ = token
    grant(row, TRIAGE)
    call(client, auth, READ, {"owner": "acme"})

    from carnet.core import audit

    audit.record(
        run_id="r_0123456789ab",
        principal=Principal.user(owner, TEST_TENANT),
        agent="triage",
        tool=READ,
        tool_input={},
        decision="allow",
        outcome="ok",
    )

    (record,) = door_calls(client, door_admin).json()
    assert record["run_id"].startswith(door.CALL_ID_PREFIX)


def test_the_listing_is_empty_before_anything_comes_through(client, door_admin):
    """An empty answer is an answer. The page renders it as a sentence rather than a
    blank table, and the route's half of that is `[]` rather than a 404."""
    assert door_calls(client, door_admin).json() == []


def test_the_door_listing_needs_the_admin_role(client, auth, vetted, token):
    """403 with the sentence every admin route gives, and no list of who to ask. The
    machine token that made the calls cannot read them back — administering is not
    something an API token does."""
    from carnet.access.roles import NOT_AN_ADMINISTRATOR

    response = door_calls(client, auth)

    assert response.status_code == 403
    assert response.json()["detail"] == NOT_AN_ADMINISTRATOR


def test_the_door_listing_needs_authentication(client):
    assert client.get("/admin/door-calls").status_code == 401


def test_a_stranger_gets_401_before_422_whatever_they_send(client):
    """**Authentication is decided before the query string is validated**, so a caller
    with no bearer learns nothing about this route's shape — not even that it takes a
    `limit`, or what the bounds are.

    A 422 here would be a small enumeration oracle: it distinguishes a route that exists
    and parses from one that does not, and it hands over the parameter's name and range
    for free. That is the same anti-enumeration posture `/mcp` keeps with its 401 and the
    trigger door keeps with its byte-identical 404. Asserted because the ordering is a
    property of the dependency graph rather than of anything written in this route, and
    somebody could reverse it without noticing.
    """
    for query in (
        "?limit=abc",       # not a number
        "?limit=",          # empty
        "?limit=1.5",       # not an integer
        "?limit=0",         # below the floor
        "?limit=99999",     # above the ceiling
        "?bogus=1",         # a parameter that does not exist
    ):
        assert client.get(f"/admin/door-calls{query}").status_code == 401, query


def test_an_administrator_does_get_the_422(client, door_admin):
    """The other half: once authenticated, a bad `limit` is FastAPI's 422 naming the
    field. The refusal exists — it is just not shown to strangers."""
    assert door_calls(client, door_admin, limit="abc").status_code == 422
    assert door_calls(client, door_admin, limit="1.5").status_code == 422


def test_the_door_listing_limit_is_capped_by_the_signature(client, door_admin):
    """Silent truncation is the one behaviour a log route must not have — it reads as
    "that is everything". `/admin-audit`'s rule, on the fourth reader to inherit it."""
    assert door_calls(client, door_admin, limit=1).status_code == 200
    assert door_calls(client, door_admin, limit=0).status_code == 422
    assert door_calls(client, door_admin, limit=100000).status_code == 422


def test_the_door_listing_limit_takes_the_most_recent_oldest_first(
    client, auth, vetted, token, door_admin
):
    """The tail, still in the order it happened — `audit_records`' rule, all the way out
    to the wire."""
    row, _ = token
    grant(row, TRIAGE)

    for _ in range(3):
        call(client, auth, READ, {"owner": "acme"})

    everything = door_calls(client, door_admin).json()
    tail = door_calls(client, door_admin, limit=2).json()

    assert [r["run_id"] for r in tail] == [r["run_id"] for r in everything[-2:]]


def test_one_tenants_door_traffic_is_invisible_to_another(
    client, auth, vetted, token, door_admin
):
    """The scoping every read in this product carries, asserted on the new one rather
    than assumed from the method it calls."""
    row, _ = token
    grant(row, TRIAGE)
    call(client, auth, READ, {"owner": "acme"})

    store = storage.active()
    store.create_tenant("other-tenant", "Other")

    assert store.door_call_records("other-tenant") == []
    assert len(store.door_call_records(TEST_TENANT)) == 1


# --- 035d: what a token is granted, without presenting it -------------------------
#
# `door.reach` is `list_tools` with `require_machine` and the connector binding removed,
# and the property worth asserting is not that it works — it is that it **agrees**. A
# second implementation of decision 2 is how the screen and the door start disagreeing
# about what a token can do, which is 021's `role_of` defect at a new address, so several
# of these compare the two answers directly rather than asserting the new one against a
# literal that would still pass on the day somebody reimplemented the union in a route.
#
# They live here rather than in `test_api.py` for `door_calls`' reason: this is the only
# file that can produce a *real* `tools/list` and put it beside the reach of the same
# token.
#
# The fixtures below are their own rather than the file's, because this route's caller is
# a **person in a browser** — the principal `require_machine` refuses at the door by
# design, which is the first half of the gap. So the owner has to be somebody who has
# signed in, and `owner` above is a row created directly with a different issuer.


@pytest.fixture
def reader(client, idp):
    """Priya with a browser session, and the tokens below are hers.

    The request first, then the id: a user does not exist until they sign in — the row is
    keyed `(issuer, subject)` and the subject only arrives inside a token — so there is
    nothing to own a token until one has been made. `door_admin` above does the same
    thing for the same reason.
    """
    return {
        "Authorization": f"Bearer {idp.token(sub='00u-her', email='her@acme.com')}"
    }


@pytest.fixture
def her(client, reader):
    """Her principal id, which is what a token's `owner_id` has to be."""
    return client.get("/me", headers=reader).json()["principal"].split(":", 1)[1]


@pytest.fixture
def hers(her):
    """A service token she owns: grants of its own, nobody else's."""
    return tokens.mint(TEST_TENANT, "her-ci", her, actor="system:cli")


@pytest.fixture
def hers_auth(hers):
    _, presented = hers
    return {"Authorization": f"Bearer {presented}"}


@pytest.fixture
def her_personal(her):
    """A personal token she owns: her grants, live, capped at `user`."""
    return tokens.mint(
        TEST_TENANT, "her-editor", her, actor="system:cli", acts_as_owner=True
    )


@pytest.fixture
def stranger(client, idp):
    """Somebody else in the same customer, signed in, holding no role and owning
    nothing."""
    return {
        "Authorization": f"Bearer {idp.token(sub='00u-else', email='else@acme.com')}"
    }


def reach_of(client, headers, token_id):
    return client.get(f"/me/tokens/{token_id}/reach", headers=headers)


def listed_names(client, auth):
    return [t["name"] for t in rpc(client, auth, "tools/list").json()["result"]["tools"]]


def grant_her(her_id, config_):
    """Save an agent and share it with HER — never with a token, which is what a personal
    token's whole access is made of."""
    agents.save(TEST_TENANT, config_, actor=TEST_ACTOR)
    storage.active().grant_agent(
        TEST_TENANT,
        config_["name"],
        "user",
        her_id,
        role="user",
        granted_by=TEST_ACTOR,
        actor=TEST_ACTOR,
    )


def test_reach_and_tools_list_agree_about_the_names(
    client, reader, hers, hers_auth, vetted
):
    """**The assertion the whole chunk exists to make true.** Two surfaces, one
    credential, two entirely different paths into the answer — an MCP client presenting a
    secret over JSON-RPC, and a person's browser session asking about a row she owns —
    and the set of names has to be identical, or one of the two screens is lying about
    what a credential can do.

    Compared against each other rather than against a literal, on purpose.
    """
    row, _ = hers
    grant(row, TRIAGE)
    grant(row, FILER)

    answer = reach_of(client, reader, row["id"]).json()

    assert answer["tools"] == listed_names(client, hers_auth)
    assert answer["tools"] == sorted([READ, WRITE])


def test_one_tool_in_two_agents_is_one_name_and_two_scopes(
    client, reader, hers, vetted
):
    """**Decision 1, and the case a flat `Reachable` cannot express.**

    `triage` reads `acme` and `security` reads `secret`, and both grant `list_issues`.
    This module's own header says what a single flat answer would have to do with that:
    union the scopes, which invents a permission nobody wrote down, or pick one, which
    refuses calls the caller is plainly granted. So the *name* appears once — it is a
    union — and the *scope* appears twice, once per agent, each with its own bound.
    """
    row, _ = hers
    grant(row, TRIAGE)
    grant(row, SECURITY)

    answer = reach_of(client, reader, row["id"]).json()

    assert answer["tools"] == [READ]
    assert [(a["name"], a["scope"]) for a in answer["agents"]] == [
        ("security", {"github.repo": {"read": ["secret"]}}),
        ("triage", {"github.repo": {"read": ["acme"]}}),
    ]


def test_the_agents_come_back_ordered_by_name(client, reader, hers, vetted):
    """Ordered because `runnable_names` orders, in both stores.

    **And the names here are chosen so that they agree, which is a smaller claim than it
    looks — see the `DEFERRED.md` row.** 035c recorded a live split between the two
    stores (`memory` sorts by Python codepoint, `postgres` by the deployment's collation)
    and said agent names were *immune by accident*, being slugs. **That is false, and
    035d measured it through these very methods**: given `triage-bot`, `triageb`,
    `report-v2` and `reportv` — every one of them legal under migration 019 —
    `granted_agent_names` answers

        memory     report-v2  reportv  triage-bot  triageb
        postgres   reportv  report-v2  triageb  triage-bot

    because `en_US.utf8` ignores the hyphen at the primary level and `'-'` sorts below
    every letter in codepoint order. So the order this page renders is a property of the
    deployment's locale, exactly as it is for token names, and fixing it is the same
    cross-cutting decision that row already carries — a reach page must not be the reason
    twenty listings change their order any more than a token page was.

    What is asserted here is therefore that the list *is* ordered, on names the two
    stores agree about. The disagreement is the register's.
    """
    row, _ = hers
    for name in ("zeta-agent", "alpha-agent", "mid-agent"):
        grant(row, agent(name=name, tools_granted=[READ], scope={"github.repo": {"read": ["acme"]}}))

    answer = reach_of(client, reader, row["id"]).json()

    assert [a["name"] for a in answer["agents"]] == [
        "alpha-agent",
        "mid-agent",
        "zeta-agent",
    ]


def test_an_agent_granted_through_a_GROUP_reaches_too(client, reader, her, her_personal, vetted):
    """**The 033e path, which nothing in this chunk covered until the edge pass looked.**

    `runnable_names` resolves direct grants and group memberships in one statement, so a
    personal token reaches an agent shared with a *group its owner is in* — and that is
    the shape a real deployment mostly has, because sharing with a team is what people do.
    Every other test here grants directly, which would have passed just as well against a
    query that had lost its group half.

    Driven against real Postgres by 035d's edge probe too, where the `_VIA_GROUP` subquery
    is the thing actually being trusted; this is the same assertion at the tier that runs
    in CI.
    """
    row, _ = her_personal
    agents.save(TEST_TENANT, TRIAGE, actor=TEST_ACTOR)
    store = storage.active()
    store.create_group(TEST_TENANT, "g_eng", "Engineering", actor=TEST_ACTOR)
    store.add_group_member(TEST_TENANT, "g_eng", "user", her, actor=TEST_ACTOR)
    store.grant_agent(
        TEST_TENANT, "triage", "group", "g_eng", role="user",
        granted_by=TEST_ACTOR, actor=TEST_ACTOR,
    )

    answer = reach_of(client, reader, row["id"]).json()

    assert [a["name"] for a in answer["agents"]] == ["triage"]
    assert answer["tools"] == [READ]


def test_an_agent_granted_twice_over_is_listed_once(client, reader, her, her_personal, vetted):
    """Directly **and** through a group, which is not an error and must not be two rows.

    `granted_agent_names` is `DISTINCT` in Postgres and a set in the fake for exactly
    this; asserted through the route because a duplicate here would double-count in the
    page's *"N tools through M agents"* sentence, which is the one number somebody reads.
    """
    row, _ = her_personal
    grant_her(her, TRIAGE)
    store = storage.active()
    store.create_group(TEST_TENANT, "g_eng", "Engineering", actor=TEST_ACTOR)
    store.add_group_member(TEST_TENANT, "g_eng", "user", her, actor=TEST_ACTOR)
    store.grant_agent(
        TEST_TENANT, "triage", "group", "g_eng", role="editor",
        granted_by=TEST_ACTOR, actor=TEST_ACTOR,
    )

    answer = reach_of(client, reader, row["id"]).json()

    assert [a["name"] for a in answer["agents"]] == ["triage"]


def test_a_token_granted_nothing_reaches_nothing_and_that_is_an_answer(
    client, reader, hers, vetted
):
    """The empty-denies default, and it has to arrive as an **answer**. A 404 or a 403
    here would be a true-sounding sentence about a false cause: the token exists, the
    caller owns it, and *it is granted nothing* is the complete reply to what was asked.
    """
    row, _ = hers

    response = reach_of(client, reader, row["id"])

    assert response.status_code == 200
    assert response.json()["tools"] == []
    assert response.json()["agents"] == []


def test_a_personal_tokens_reach_is_its_owners_and_says_whose(
    client, reader, her, her_personal, vetted
):
    """Both token kinds out of one call, because `grants.runnable_names` already
    redirects a machine principal through `personal_owner`.

    `resolved_as` is what keeps this from being a lie by omission: the grants that
    answered are hers, no row names the token at all, and a response reporting somebody
    else's access without saying whose is describing the wrong person's blast radius.
    """
    row, presented = her_personal
    grant_her(her, TRIAGE)
    grant_her(her, FILER)
    her_auth = {"Authorization": f"Bearer {presented}"}

    answer = reach_of(client, reader, row["id"]).json()

    assert answer["acts_as_owner"] is True
    assert answer["resolved_as"] == f"user:{her}"
    assert answer["tools"] == listed_names(client, her_auth)
    assert (
        storage.active().agent_grant_role(TEST_TENANT, "triage", "machine", row["id"])
        is None
    )


def test_a_service_tokens_reach_resolves_as_the_token_itself(
    client, reader, hers, vetted
):
    """The other half of the pair, asserted because a test that checked only the personal
    case would pass on a route that hard-coded the owner."""
    row, _ = hers
    grant(row, TRIAGE)

    answer = reach_of(client, reader, row["id"]).json()

    assert answer["acts_as_owner"] is False
    assert answer["resolved_as"] == f"machine:{row['id']}"


def test_reading_a_tokens_reach_does_not_count_as_using_it(
    client, reader, hers, vetted
):
    """**Decision 3, and the one assertion that catches somebody "simplifying" this route
    onto `act_for`.**

    `tokens.act_for` stamps `last_used_at`, and an offboarding review that moved the stamp
    by being conducted would corrupt the single question that column exists to answer —
    which 035c's page renders as the word *never*. `require_owner_or_admin` touches
    nothing, which is why the non-touching variant plan 035 called for never had to be
    built.
    """
    row, _ = hers
    grant(row, TRIAGE)
    store = storage.active()
    assert store.find_api_token(row["id"])["last_used_at"] is None

    reach_of(client, reader, row["id"])
    reach_of(client, reader, row["id"])

    assert store.find_api_token(row["id"])["last_used_at"] is None


def test_a_revoked_token_still_reports_what_it_was_granted(client, reader, hers, vetted):
    """**Decision 4**, and it reads as a gap until the question is named.

    *What could this token reach before I killed it* is the offboarding question, asked
    most often about a credential that has just been revoked — and a reach page answering
    *"refused: this token was revoked"* would be useless to precisely the person who came
    to read it, in the **reassuring** direction: they would read the refusal as *it
    reaches nothing*. Reach follows the grant; the listing's four stamps say whether any
    of it can happen today.

    Asserted so that adding a liveness check later is a failing test rather than a silent
    narrowing of an offboarding tool.
    """
    row, _ = hers
    grant(row, TRIAGE)
    storage.active().revoke_api_token(TEST_TENANT, row["id"], actor=TEST_ACTOR)

    answer = reach_of(client, reader, row["id"])

    assert answer.status_code == 200
    assert answer.json()["tools"] == [READ]


def test_an_expired_tokens_reach_answers_too(client, reader, her, vetted):
    """The second of `act_for`'s four refusals, and the one 035c's edge pass found a
    *create* route should start applying — a different question about a different verb,
    which stays a register row. A read of what an expired credential was granted is
    exactly as useful as a read of a revoked one's."""
    row, _ = tokens.mint(
        TEST_TENANT,
        "lapsed",
        her,
        actor="system:cli",
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    grant(row, TRIAGE)

    assert reach_of(client, reader, row["id"]).json()["tools"] == [READ]


def test_a_disabled_owners_personal_token_still_reports_her_grants(
    client, door_admin, her, her_personal, vetted
):
    """The third refusal, one level down, and the corner where decision 4 is least
    obvious: `personal_owner` reads the token row without consulting the owner's status,
    so this answers while the door refuses the same token at authentication with a 403
    naming *no longer an active account*.

    That pair is the decision working rather than two surfaces disagreeing: one says what
    she is granted, the other says she can no longer present a credential. Both are true,
    and only the first is what somebody reviewing her offboarding is asking.

    **Read by the administrator and not by her**, which is not a convenience: a disabled
    person's own session is refused at `api/deps.py` long before this route, so once
    somebody is offboarded the admin half of `require_owner_or_admin` is the *only* way
    this answer can be read at all. That is the strongest argument the rule has, and it
    was found by writing this test as `reader` first and watching it 403.
    """
    row, _ = her_personal
    grant_her(her, TRIAGE)
    storage.active().set_user_status(TEST_TENANT, her, "disabled", actor="system:test")

    assert reach_of(client, door_admin, row["id"]).json()["tools"] == [READ]


def test_a_granted_agent_whose_config_is_broken_is_named_not_dropped(
    client, reader, hers, hers_auth, vetted
):
    """**Decision 7, in both directions.** `_granted_agents` skips an agent whose stored
    config no longer validates, because raising would let one broken agent remove every
    *other* agent's tools from a client's list. Silence is right for the door and wrong
    here: *your token reaches one agent*, about a token granted two, with no sentence
    saying where the second went, is an absence that reads as a fact — on the one page
    whose question is a count.

    The surviving agent's tools are asserted too, because that is the property the skip
    exists for and naming the casualty must not cost it. And the door's own list is
    asserted unchanged, because this chunk added an out-parameter to a function on its hot
    path.
    """
    row, _ = hers
    grant(row, TRIAGE)
    grant(row, FILER)
    # Withdrawn underneath a live agent, which is how this state actually arrives — and
    # written through storage rather than `agents.save`, which validates and would refuse.
    store = storage.active()
    broken = store.get_agent(TEST_TENANT, "filer")["config"]
    broken["permissions"] = {"tools": ["example_no_longer_vetted"], "scope": {}}
    store.save_agent(TEST_TENANT, broken, actor=TEST_ACTOR)

    answer = reach_of(client, reader, row["id"]).json()

    assert answer["invalid_agents"] == ["filer"]
    assert [a["name"] for a in answer["agents"]] == ["triage"]
    assert answer["tools"] == [READ]
    assert listed_names(client, hers_auth) == [READ]


def test_reach_is_a_superset_of_tools_list_when_a_connector_will_not_answer(
    client, reader, hers, hers_auth, vetted, monkeypatch
):
    """**Decision 5, and it is an honest difference rather than a defect.**

    `list_tools` binds and then looks the tool up, so a connector that will not answer
    drops its tools out of a client's list. `reach` reports the *grant*, which is still
    exactly what somebody wrote down. The two therefore differ in one direction only —
    reach ≥ `tools/list` — and a page that closed the gap by binding would be opening
    sessions to every connector a tenant has vetted in order to answer a question settled
    by rows in this database.
    """
    row, _ = hers
    grant(row, TRIAGE)

    def refuse(*args, **kwargs):
        raise TransportError("the server did not answer")

    monkeypatch.setattr(mcp, "_transport_for", refuse)

    assert listed_names(client, hers_auth) == []
    assert reach_of(client, reader, row["id"]).json()["tools"] == [READ]


def test_a_colleagues_token_is_refused_exactly_as_an_unknown_one_is(
    client, stranger, her, hers, vetted
):
    """**The in-tenant half of the same boundary the test below draws across tenants.**

    It asserted the opposite until 069: a 403 that named the owner, on 022b's argument
    that *"a token id is sixteen random hex the caller supplied inside their own tenant,
    and `--list-tokens` already answers the same question. There is nothing to
    enumerate."* Half of that survives — enumerating sixteen random hex is not a threat,
    and it is why this was a reasonable call at the time.

    The half that does not is that the sentence **named the owner**. `GET /me/tokens`
    returns only the tokens you own, so a stranger holding an id from anywhere else — a
    log, a screenshot, a pasted config — could turn it into a colleague's name, which is
    not something they could otherwise read and not something enumeration difficulty
    protects. 028's rule decides it: any difference between *not yours* and *not there*
    is a fact about somebody else, handed to a caller with no claim on the row.

    Asserted on the sentence rather than on the status, because both are 400 and the
    status proves nothing — the device the cross-tenant test below already uses.
    """
    row, _ = hers

    real = reach_of(client, stranger, row["id"])
    invented = reach_of(client, stranger, "m_000000000000")

    assert real.status_code == invented.status_code == 400
    assert real.json()["detail"].replace(row["id"], "X") == invented.json()[
        "detail"
    ].replace("m_000000000000", "X")
    assert her not in real.json()["detail"]


def test_an_unknown_token_id_is_a_400_about_a_typo(client, reader, vetted):
    """`ValueRefused` → 400, never `StorageError` → 503: a mistyped id is the caller's,
    and the wrong refusal family sends somebody to read logs about an outage that did not
    happen. 021's lesson, inherited rather than re-decided."""
    response = reach_of(client, reader, "m_notatoken")

    assert response.status_code == 400
    assert "m_notatoken" in response.json()["detail"]


def test_another_tenants_token_is_refused_exactly_as_an_unknown_one_is(
    client, reader, vetted
):
    """**The tenant boundary must not be an existence oracle.** A real id belonging to
    another customer and an id that was never minted anywhere have to come back
    byte-identical apart from the id itself, or somebody holding a list of ids can sort
    the real ones from the invented ones by reading which refusal arrived.

    Asserted on the sentence rather than on the status, because both are 400 and the
    status proves nothing.
    """
    store = storage.active()
    store.create_tenant("other-tenant", "Other")
    store.create_user(
        "other-tenant",
        {
            "id": "u-them",
            "issuer": "https://idp.example",
            "subject": "00u9",
            "email": "them@other.example",
        },
    )
    theirs, _ = tokens.mint("other-tenant", "theirs", "u-them", actor="system:cli")

    real = reach_of(client, reader, theirs["id"])
    invented = reach_of(client, reader, "m_000000000000")

    assert real.status_code == invented.status_code == 400
    assert real.json()["detail"].replace(theirs["id"], "X") == invented.json()[
        "detail"
    ].replace("m_000000000000", "X")


def test_an_administrator_may_read_a_token_that_is_not_theirs(
    client, door_admin, hers, vetted
):
    """The half of `require_owner_or_admin` that `/me/tokens` does not have, and it is
    fine *a fortiori*: the same function already lets an administrator **aim** this token
    at an agent on a clock, and reading what it is granted is strictly weaker than
    pointing it at something.

    Reachable by curl and by nothing in the browser — `/tokens/:id` renders from the
    caller's own listing, so an admin browsing to somebody else's id is told they own no
    such token before this route is ever called. A smaller surface than the rule permits,
    which is the safe direction.
    """
    row, _ = hers
    grant(row, TRIAGE)

    response = reach_of(client, door_admin, row["id"])

    assert response.status_code == 200
    assert response.json()["tools"] == [READ]


def test_the_reach_response_declares_the_whole_permission_model(
    client, reader, hers, vetted
):
    """**035c's register row, discharged at the boundary that matters** — the *drop*
    direction, where the failure is silent and a dropped field reads as a feature nobody
    built.

    `ReachableAgent` is built from `agents.get`'s dict, which is the whole stored config,
    and it declares three of its keys. That drop is a **policy**: `system`, `runtime` and
    `limits` are not what a permission is, and re-sending an agent's instructions to
    explain what a credential may call would be a different route's job done badly. So
    the walk is against `AgentPermissions` rather than against the config — `tools` and
    `scope` *are* the permission model, and a field added there and forgotten here is a
    capability that silently stopped being described.
    """
    from carnet.api.schemas import AgentPermissions

    row, _ = hers
    grant(row, TRIAGE)

    rendered = reach_of(client, reader, row["id"]).json()["agents"][0]

    assert set(rendered) - {"name"} == set(AgentPermissions.model_fields)


# --- 069: the same verdict, without the call ---------------------------------------
#
# Two halves of one question. `reach.by_tool` transposes the grant so a token holding
# three of them can be read tool-first; `simulate` answers one prospective call with the
# verdict the door would give and the rule that produced it.
#
# The load-bearing test in this section is the first one: everything else is detail if
# the simulator and the door can disagree.


def simulate_of(client, headers, token_id, tool, arguments=None):
    return client.post(
        f"/me/tokens/{token_id}/simulate",
        json={"tool": tool, "arguments": arguments or {}},
        headers=headers,
    )


NARROW = agent(
    name="narrow", tools_granted=[READ], scope={"github.repo": {"read": ["acme"]}}
)


@pytest.mark.parametrize(
    "owner_arg",
    ["acme", "secret", "other", "ACME"],
    ids=["granted-by-one", "granted-by-another", "granted-by-none", "case-differs"],
)
def test_the_simulator_and_the_door_agree_on_verdict_agent_and_reason(
    principal, token, vetted, owner_arg
):
    """**The claim the whole step rests on, checked against the door rather than against
    a second reading of the rules.**

    A simulator with its own copy of the matcher is a second opinion about permission,
    and the first time the two disagree the simulator is believed — so `simulate` runs
    `_granted_agents`, `_candidates` and `_adjudicate`, which is what `call_tool` runs.
    This asserts the consequence at the only place it can be observed: the audit row a
    real call writes.

    Three grants carrying the same tool at three bounds, which is the shape 033b's union
    rule makes hard and the shape nothing could read before this step. `secret` and
    `acme` are each granted by exactly one agent, `other` by none, and `ACME` by none
    because the matcher is case-sensitive — a fact stated in `core/patterns.py` and, until
    now, discoverable only by making the call.
    """
    row, _ = token
    for config_ in (TRIAGE, SECURITY, NARROW):
        grant(row, config_)

    arguments = {"owner": owner_arg}
    simulated = door.simulate(principal, READ, arguments)

    before = len(read_audit(TEST_TENANT))
    door.call_tool(principal, READ, dict(arguments))
    record = read_audit(TEST_TENANT)[before]

    assert (simulated["verdict"] == "allowed") == (record["decision"] == "allow")
    assert simulated["attributed_to"] == record["agent"]
    if record["decision"] == "deny":
        assert simulated["reason"] == record["reason"]


def test_a_refusal_names_every_agent_that_refused_and_why(principal, token, vetted):
    """**`considered` is the deliverable, not `verdict`.**

    A boolean is what somebody could have got by making the call. What they could not get
    is *all three of my grants said no, and here is each one's reason* — which is the
    question the union rule makes genuinely hard, because each tool keeps its own agent's
    scope and nothing composes them.
    """
    row, _ = token
    for config_ in (TRIAGE, SECURITY):
        grant(row, config_)

    answer = door.simulate(principal, READ, {"owner": "other"})

    assert answer["verdict"] == "refused"
    assert [c["agent"] for c in answer["considered"]] == ["security", "triage"]
    assert all(c["rule"] == "outside_scope" for c in answer["considered"])
    assert "secret" in answer["considered"][0]["reason"]
    assert "acme" in answer["considered"][1]["reason"]


def test_an_allow_still_says_what_the_other_grants_thought(principal, token, vetted):
    """Read the other way, the same list turns *it works, somehow* into *it works because
    `triage` grants acme* — which is the sentence somebody reviewing a token needs."""
    row, _ = token
    for config_ in (TRIAGE, SECURITY):
        grant(row, config_)

    answer = door.simulate(principal, READ, {"owner": "acme"})

    assert answer["verdict"] == "allowed"
    assert answer["attributed_to"] == "triage"
    assert answer["rule"] == answer["reason"] == ""
    refused = [c for c in answer["considered"] if not c["allowed"]]
    assert [c["agent"] for c in refused] == ["security"]


def test_a_vetted_but_unbound_tool_simulates_without_a_socket(principal, token, vetted):
    """**The case the design rests on, and the reason `describe` exists.**

    `tools.get` returns None for a connector tool nothing has bound, which is the ordinary
    state of every process that has not served a call yet. A simulator built on `get`
    would answer *"not a registered tool"* for a tenant's whole catalogue after every
    restart — a false verdict, in the reassuring direction, produced by a cold cache.

    No `connected` fixture here, and `reset_bound` makes the cold state explicit rather
    than incidental: nothing in this test can open a session, and the answer is still
    right.
    """
    row, _ = token
    grant(row, TRIAGE)
    tools.reset_bound(TEST_TENANT)

    assert tools.get(READ, TEST_TENANT) is None

    allowed = door.simulate(principal, READ, {"owner": "acme"})
    refused = door.simulate(principal, READ, {"owner": "other"})

    assert allowed["verdict"] == "allowed"
    assert refused["verdict"] == "refused"
    assert refused["rule"] == "outside_scope"


def test_a_simulation_opens_no_session_at_all(principal, token, vetted, monkeypatch):
    """Asserted by making the attempt impossible rather than by counting handshakes: any
    transport built during a simulation raises, so a future edit that reaches for one
    fails here instead of quietly costing a customer's server a round trip per page."""
    row, _ = token
    grant(row, TRIAGE)
    tools.reset_bound(TEST_TENANT)

    def refuse(*args, **kwargs):
        raise AssertionError("a simulation must not dial anything")

    monkeypatch.setattr(mcp, "ensure_session", refuse)
    monkeypatch.setattr(mcp, "connect", refuse)

    assert door.simulate(principal, READ, {"owner": "acme"})["verdict"] == "allowed"
    assert door.reach(principal)["by_tool"][0]["tool"] == READ


def test_a_simulation_writes_no_row_in_any_log(principal, token, vetted):
    """**The audit question, settled by assertion.**

    No `audit` row: there was no call, and every door-usage number in the product reads
    that table filtered on `door-`. No `access_denials` row: that log is *who tried and
    was refused*, and `denials.py` draws the line itself — `require` is somebody asking to
    act on a named thing, `check` is the system deciding what to show. A question is
    neither. No `admin_audit` row: records there ride the transaction of the write they
    describe, and this performs none.

    Counted over a hundred simulations because one of each would pass against a
    conditional write, and the register carries the trigger for when the argument behind
    this stops holding.
    """
    row, _ = token
    grant(row, TRIAGE)
    store = storage.active()
    before = (
        len(read_audit(TEST_TENANT)),
        len(store.denial_records(TEST_TENANT)),
        len(store.admin_audit_records(TEST_TENANT)),
    )

    for i in range(100):
        door.simulate(principal, READ, {"owner": "acme" if i % 2 else "other"})

    assert (
        len(read_audit(TEST_TENANT)),
        len(store.denial_records(TEST_TENANT)),
        len(store.admin_audit_records(TEST_TENANT)),
    ) == before


def test_a_tool_no_grant_carries_is_refused_in_the_doors_own_sentence(
    principal, token, vetted
):
    """Reused verbatim, and the reuse is the security property. That sentence conflates
    *not granted* with *no such tool* on purpose, so a simulator writing a more helpful
    one would reopen the existence oracle 026 closed — at a surface whose entire job is
    to be helpful about permission."""
    row, _ = token
    grant(row, TRIAGE)

    absent = door.simulate(principal, "no_such_tool_anywhere", {})
    unvetted = door.simulate(principal, WRITE, {"owner": "acme"})

    assert absent["verdict"] == unvetted["verdict"] == "refused"
    assert absent["rule"] == unvetted["rule"] == "not_granted"
    assert absent["considered"] == unvetted["considered"] == []
    # Byte-identical apart from the name the caller supplied — the device the token
    # refusals use, applied to tool names.
    assert absent["reason"].replace("no_such_tool_anywhere", "X") == unvetted[
        "reason"
    ].replace(WRITE, "X")


@pytest.mark.parametrize(
    "name",
    ["", "x" * 100_000, "not a tool name", "drop table tools;--", "a/b"],
    ids=["empty", "enormous", "spaces", "sql-ish", "slash"],
)
def test_a_name_that_could_not_be_a_tool_gets_the_doors_other_refusal(
    principal, token, vetted, name
):
    """**Found in the edge pass, and it was an agreement defect rather than a nicety.**

    `call_tool` has *two* refusals when nothing granted carries a name, and the simulator
    shipped with one. A name that cannot match `TOOL_NAME_RE` is not an attempt on a named
    thing — the door says so in its own sentence and cuts the name to 64 characters, which
    is the guard that keeps an unbounded string off the wire and out of `access_denials`.

    Without it the simulator answered *no agent this token is granted provides a tool
    called '<100,000 characters>'* — a different verdict from the door's, at the one
    surface whose whole claim is that it gives the same one, and an unbounded echo of
    caller input besides.
    """
    row, _ = token
    grant(row, TRIAGE)

    answer = door.simulate(principal, name, {})

    assert answer["verdict"] == "refused"
    assert answer["rule"] == permissions.RULE_NOT_GRANTED
    assert answer["considered"] == []
    assert "could not name one" in answer["reason"]
    assert len(answer["tool"]) <= 64
    assert len(answer["reason"]) < 1000

    # And the door refuses it in the same words, which is the actual assertion.
    with pytest.raises(door.DoorRefused) as refused:
        door.call_tool(principal, name, {})
    assert "could not name one" in str(refused.value)


def test_a_well_formed_name_nothing_grants_keeps_the_other_sentence(
    principal, token, vetted
):
    """The two refusals stay distinct: `search_issues` is a name a tool could have, so it
    gets the *not granted* sentence — the one that deliberately says nothing about whether
    such a tool exists."""
    row, _ = token
    grant(row, TRIAGE)

    answer = door.simulate(principal, "search_issues", {})

    assert "no agent this token is granted provides" in answer["reason"]
    assert "could not name one" not in answer["reason"]


def test_every_verdict_says_what_it_did_not_check(principal, token, vetted):
    """A verdict that implies more than it checked is worse than no verdict. Pinned as a
    list rather than a sentence so a fifth thing this stops short of has to be added here
    to be added at all."""
    row, _ = token
    grant(row, TRIAGE)

    for arguments in ({"owner": "acme"}, {"owner": "other"}, {}):
        answer = door.simulate(principal, READ, arguments)
        assert answer["not_checked"] == [
            "authentication",
            "binding",
            "acting-for",
            "credential",
            "budget",
        ]

    assert door.simulate(principal, "nothing", {})["not_checked"] == [
        "authentication",
        "binding",
        "acting-for",
        "credential",
        "budget",
    ]


def test_an_exhausted_budget_is_declared_rather_than_folded_into_the_verdict(
    principal, token, vetted, monkeypatch
):
    """**The designed divergence, pinned so nobody "fixes" it.**

    A token at its daily ceiling is *permitted* to make the call and is refused anyway —
    the broker's step 2, after step 1 passed. So `simulate` says allowed while the door
    denies, and the honest answer is `not_checked: budget` rather than a verdict that
    silently folds in a counter which moves on every call.

    Folding it in is the tempting change, and it would make the verdict expire while it
    was being read. `GET /me/tokens/{id}/budget` has answered this since 035e and the
    page renders it beside — two facts, two sources.
    """
    row, _ = token
    grant(row, TRIAGE)
    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 1)

    door.call_tool(principal, READ, {"owner": "acme"})  # spends the one

    simulated = door.simulate(principal, READ, {"owner": "acme"})
    before = len(read_audit(TEST_TENANT))
    door.call_tool(principal, READ, {"owner": "acme"})
    record = read_audit(TEST_TENANT)[before]

    assert simulated["verdict"] == "allowed"
    assert record["decision"] == "deny"
    assert "budget" in simulated["not_checked"]
    assert "calls through the MCP door today" in record["reason"]


def test_acting_for_is_a_gate_this_does_not_test_and_says_so(principal, token, vetted):
    """**Found in the edge pass, and it was a hole in the honest half rather than a bug.**

    `_resolve_acting_for` runs *before* the union rule and can refuse a call outright —
    an asserted identity on a connector that has not opted in is the case here. So a
    caller can simulate `allowed`, make the same call with an acting-for claim, and be
    refused for a reason the verdict never considered.

    The parameter stays off this function (see its docstring: acting-for does not decide
    permission). What changed is that `not_checked` now names the gate, which is the same
    sentence the other four keys make.
    """
    row, _ = token
    grant(row, TRIAGE)

    simulated = door.simulate(principal, READ, {"owner": "acme"})
    assert simulated["verdict"] == "allowed"
    assert "acting-for" in simulated["not_checked"]

    # And the door does refuse it, which is what makes the key worth having.
    with pytest.raises(door.DoorRefused, match="asserted identity"):
        door.call_tool(
            principal, READ, {"owner": "acme"}, acting_for_raw={"email": "tom@acme.com"}
        )


def test_a_revoked_token_still_answers_because_that_is_the_offboarding_question(
    principal, token, vetted
):
    """035d's decision, inherited rather than re-made: *what could this token reach before
    I killed it* is asked most often about a credential that has just been revoked, and a
    simulator answering *"refused: revoked"* would be useless to exactly the person who
    came to read it, in the reassuring direction. `not_checked` names it, and the token's
    own listing carries the four stamps."""
    row, _ = token
    grant(row, TRIAGE)
    storage.active().revoke_api_token(TEST_TENANT, row["id"], actor=TEST_ACTOR)

    answer = door.simulate(principal, READ, {"owner": "acme"})

    assert answer["verdict"] == "allowed"
    assert "authentication" in answer["not_checked"]


def test_by_tool_shows_only_the_patterns_that_can_decide(principal, token, vetted):
    """Not the agent's whole scope map — the ones this tool's effect and resource types
    select. A `write` grant beside a `read` one is not what a read call is measured
    against, and showing it would be a wall to read past on the page built to stop that.
    """
    row, _ = token
    grant(
        row,
        agent(
            name="broad",
            tools_granted=[READ, WRITE],
            scope={"github.repo": {"read": ["acme", "secret"], "write": ["acme"]}},
        ),
    )

    rows = {entry["tool"]: entry for entry in door.reach(principal)["by_tool"]}

    # One agent, one resource type, two effects — and each tool is measured against its
    # own. `agents.validate` refuses a grant no granted tool can use, which is why the
    # unused-effect case has to be built out of two tools rather than one wide scope.
    assert rows[READ]["effect"] == "read"
    assert rows[READ]["granted_by"] == [
        {"agent": "broad", "applies": {"github.repo": ["acme", "secret"]}}
    ]
    assert rows[WRITE]["effect"] == "write"
    assert rows[WRITE]["granted_by"] == [
        {"agent": "broad", "applies": {"github.repo": ["acme"]}}
    ]


def test_the_transpose_costs_one_connector_read_however_many_tools(
    principal, token, vetted, monkeypatch
):
    """**Found by measuring, in the edge pass, after the tests were already green.**

    `describe` resolves a connector tool by walking this tenant's connectors, which is a
    storage read. Called once per granted tool — the obvious loop — it made `reach` cost
    a read per tool: 61 for a token granted 30, on a page load. Nothing was wrong with
    the answers; the cost simply grew with the thing being described.

    Pinned as a *delta* rather than an absolute, because the absolute is somebody else's:
    `agents.get` validates a config against the catalogue and costs one read per granted
    tool all by itself, on every door call, which is a register row and not this step's
    to fix. What this asserts is that the transpose adds **one**, whatever it is added to.
    """
    row, _ = token
    grant(row, TRIAGE)

    reads = []
    store = storage.active()
    original = store.load_connectors
    monkeypatch.setattr(
        store,
        "load_connectors",
        lambda *a, **k: (reads.append(1), original(*a, **k))[1],
    )

    reads.clear()
    door._granted_agents(principal)
    baseline = len(reads)

    reads.clear()
    door.reach(principal)

    assert len(reads) == baseline + 1


def test_describing_many_names_reads_the_catalogue_once(vetted, monkeypatch):
    """`describe_all`'s whole reason, at the function rather than through the page."""
    reads = []
    store = storage.active()
    original = store.load_connectors
    monkeypatch.setattr(
        store,
        "load_connectors",
        lambda *a, **k: (reads.append(1), original(*a, **k))[1],
    )

    found = tools.describe_all([READ, WRITE, "post_message", "nope"], TEST_TENANT)

    assert len(reads) == 1
    assert found[READ].effect == "read"
    assert found[WRITE].effect == "write"
    assert found["post_message"].name == "post_message"
    # Every name asked for is a key, so a caller never has to tell *unknown* from
    # *forgot to ask*.
    assert found["nope"] is None


def test_describing_only_builtins_reads_no_storage_at_all(vetted, monkeypatch):
    reads = []
    store = storage.active()
    original = store.load_connectors
    monkeypatch.setattr(
        store,
        "load_connectors",
        lambda *a, **k: (reads.append(1), original(*a, **k))[1],
    )

    found = tools.describe_all(["post_message"], TEST_TENANT)

    assert reads == []
    assert found["post_message"].name == "post_message"


def test_by_tool_carries_no_attribution_because_attribution_needs_the_arguments(
    principal, token, vetted
):
    """**The defect the first build shipped and driving it found.**

    `ToolReach` had an `attributed_to` naming `granted_by[0]`, which is wrong in exactly
    the case this view exists for: the union rule is *first **allow** wins*, not first
    candidate. Here `security` sorts first and grants `secret`, so a call about `acme`
    attributes to `triage` — while the static field claimed `security` for every call, on
    the page built to explain attribution.

    What is true statically is the order, which `granted_by` carries. `simulate` answers
    the rest.
    """
    row, _ = token
    for config_ in (TRIAGE, SECURITY):
        grant(row, config_)

    entry = door.reach(principal)["by_tool"][0]

    assert "attributed_to" not in entry
    assert [g["agent"] for g in entry["granted_by"]] == ["security", "triage"]
    assert door.simulate(principal, READ, {"owner": "acme"})["attributed_to"] == "triage"
    assert (
        door.simulate(principal, READ, {"owner": "secret"})["attributed_to"] == "security"
    )


def test_a_granted_tool_nothing_describes_is_a_row_rather_than_a_crash(
    principal, token, vetted
):
    """**The fail-closed branch, tested where it is reachable and not pretended into an
    end-to-end path.**

    The first version of this test un-vetted a connector under a live grant and expected
    the row to survive. It cannot: `agents.validate` refuses both directions of the
    scope/tools cross-check — a grant no granted tool can use is as invalid as a tool with
    no grant — so un-vetting makes the *agent* invalid, `_granted_agents` skips it, and it
    is reported through `invalid_agents` instead. Which is the better answer, and is
    035d's, and means the null branch below is defensive rather than ordinary.

    It is still worth having and worth testing directly. A config reaches `_by_tool` after
    `agents.get` has validated it against *this* tenant's catalogue at *this* moment, and
    the thing a defensive branch buys is that the next gap between those two facts is a
    row saying *nothing describes this* rather than an `AttributeError` on a page.
    """
    row, _ = token
    grant(row, TRIAGE)

    invented = [
        {
            "name": "hand-made",
            "permissions": {"tools": ["a_name_no_registry_has"], "scope": {}},
        }
    ]

    assert door._by_tool(principal, invented) == [
        {
            "tool": "a_name_no_registry_has",
            "effect": None,
            "resource_types": [],
            "granted_by": [{"agent": "hand-made", "applies": {}}],
        }
    ]
    # And `permissions.check` says the same thing about it, which is the rule the door
    # would apply if one ever arrived: we cannot scope what we cannot describe.
    assert (
        door.simulate(principal, READ, {"owner": "acme"})["rule"] != "not_described"
    )


def test_a_caller_scope_on_a_door_grant_resolves_to_the_token_id(
    personal, vetted, client
):
    """**A finding, surfaced by building the simulator rather than by reading anything.**

    `permissions._resolve` substitutes `${principal.id}` from the principal it is handed,
    and on a door call that principal is the **machine token** — `RunContext.for_call`
    takes it, `broker.call` checks `ctx.principal`. So a `${principal.id}` scope on an
    agent reached through the door resolves to a token id, not to a person.

    That is sharpest on a *personal* token, whose whole purpose is to carry its owner's
    access and whose reach page says `resolved_as: user:<owner>` — while the scope
    underneath resolves to `machine:<token>`. Whether that is what anybody intended is
    not this step's question; it was previously observable only by making a call and
    reading a denial, and it is now on a screen.

    This test pins the **agreement**, not the design: the simulator says what the door
    does. If the resolution is later changed, both move together and this fails, which is
    the correct place for it to fail.

    `DEFERRED.md` carries the row.
    """
    row, _ = personal
    grant_owner(
        agent(
            name="mine",
            tools_granted=[READ],
            scope={"github.repo": {"read": ["${principal.id}"]}},
        )
    )
    principal = Principal.machine(row["id"], TEST_TENANT)

    as_token = door.simulate(principal, READ, {"owner": row["id"]})
    as_person = door.simulate(principal, READ, {"owner": OWNER})

    assert as_token["verdict"] == "allowed"
    assert as_person["verdict"] == "refused"
    assert row["id"] in as_person["reason"]

    # The reach page says the credential resolves as the owner, and it is right about
    # *whose grants answered*. The two facts are about different things and both are on
    # the page — which is the whole reason the transpose shows the raw pattern rather
    # than a resolved one it would have to pick a principal for.
    reach = door.reach(principal)
    assert reach["by_tool"][0]["granted_by"] == [
        {"agent": "mine", "applies": {"github.repo": ["${principal.id}"]}}
    ]

    # And the door agrees, which is the assertion that matters.
    before = len(read_audit(TEST_TENANT))
    door.call_tool(principal, READ, {"owner": OWNER})
    assert read_audit(TEST_TENANT)[before]["decision"] == "deny"


# --- 069 over the wire: the route, and what it refuses to tell anybody --------------


def test_the_route_gives_the_verdict_the_door_would_give(client, reader, her, hers, vetted):
    """The same three-grant shape, through HTTP, so the schema and the route are on the
    same claim as `door.simulate` rather than merely near it."""
    row, _ = hers
    for config_ in (TRIAGE, SECURITY):
        grant(row, config_)

    allowed = simulate_of(client, reader, row["id"], READ, {"owner": "acme"}).json()
    refused = simulate_of(client, reader, row["id"], READ, {"owner": "nope"}).json()

    assert allowed["verdict"] == "allowed"
    assert allowed["attributed_to"] == "triage"
    assert [c["agent"] for c in allowed["considered"]] == ["security", "triage"]

    assert refused["verdict"] == "refused"
    assert refused["rule"] == "outside_scope"
    assert all(not c["allowed"] for c in refused["considered"])


def test_simulating_a_colleagues_token_is_refused_as_a_missing_one(
    client, stranger, her, hers, vetted
):
    """**The done-when's second clause, and the reason `require_owner_or_admin` was
    changed rather than this route being given a rule of its own.**

    A token somebody does not administer refuses byte-identically to one that was never
    minted. Written here against the *simulate* route because it is the newest surface on
    that function and the one where a divergence would be introduced, not because the
    property belongs to it.
    """
    row, _ = hers
    grant(row, TRIAGE)

    real = simulate_of(client, stranger, row["id"], READ, {"owner": "acme"})
    invented = simulate_of(client, stranger, "m_000000000000", READ, {"owner": "acme"})

    assert real.status_code == invented.status_code == 400
    assert her not in real.json()["detail"]
    assert real.json()["detail"].replace(row["id"], "X") == invented.json()[
        "detail"
    ].replace("m_000000000000", "X")


def test_the_route_refuses_a_field_it_does_not_take(client, reader, her, hers, vetted):
    """**`acting_for` is the field a caller will try, and ignoring it is the wrong
    answer.** Found in the edge pass: pydantic's default drops unknown keys, so a body
    carrying an acting-for claim came back 200 with a verdict that had silently not
    considered it — a door call takes one, so a caller has every reason to send one here.

    `extra="forbid"` is what every other request body in `schemas.py` does, and
    `access/acting.py`'s own rule is the argument: *a typo'd `emial` must fail here, never
    quietly become a call with no acting-for.*
    """
    row, _ = hers
    grant(row, TRIAGE)

    refused = client.post(
        f"/me/tokens/{row['id']}/simulate",
        json={"tool": READ, "acting_for": {"email": "tom@acme.com"}},
        headers=reader,
    )

    assert refused.status_code == 422
    assert "acting_for" in str(refused.json()["detail"])

    # And an absent `arguments` is still a real state, not an error: *a call with no
    # arguments* is exactly what a default is for.
    assert (
        client.post(
            f"/me/tokens/{row['id']}/simulate", json={"tool": READ}, headers=reader
        ).status_code
        == 200
    )


def test_the_route_takes_the_doors_own_size_bound(client, reader, her, hers, vetted):
    """The refusal sentence quotes the value back, so an unbounded body is an unbounded
    reflection — 200KB in, 200KB out. `routes_mcp` bounds `arguments` against
    `MCP_MAX_CALL_BYTES` because what arrives lands in an append-only table; nothing here
    lands anywhere, and the same number is still the right one because this answers about
    that call."""
    row, _ = hers
    grant(row, TRIAGE)

    refused = client.post(
        f"/me/tokens/{row['id']}/simulate",
        json={"tool": READ, "arguments": {"owner": "x" * (config.MCP_MAX_CALL_BYTES + 1)}},
        headers=reader,
    )

    assert refused.status_code == 400
    assert str(config.MCP_MAX_CALL_BYTES) in refused.json()["detail"]
    # The whole response is short — which is the property, not the status.
    assert len(refused.content) < 1000


def test_an_administrator_may_simulate_somebody_elses_token(
    client, reader, door_admin, her, hers, vetted
):
    """`require_owner_or_admin`'s other arm. Reading is strictly weaker than aiming, and
    the same function already lets an administrator put this token on a clock."""
    row, _ = hers
    grant(row, TRIAGE)

    answer = simulate_of(client, door_admin, row["id"], READ, {"owner": "acme"})

    assert answer.status_code == 200
    assert answer.json()["verdict"] == "allowed"


def test_the_simulate_route_is_not_admin_surface(client):
    """035d decision 11, inherited. It authorizes on who owns a row rather than on a
    role, so `deps.ADMIN_SURFACE` must not carry it — and
    `test_every_admin_route_carries_the_dependency` fails in its second direction if
    somebody adds it, which is the point of asserting the absence here too."""
    from carnet.api import deps

    assert "/me/tokens/{token_id}/simulate" not in deps.ADMIN_SURFACE


def test_the_route_writes_nothing_either(client, reader, her, hers, vetted):
    """The same count as `door.simulate`'s test, over HTTP, because a route is where a
    convenience log would actually get added."""
    row, _ = hers
    grant(row, TRIAGE)
    store = storage.active()
    before = (
        len(read_audit(TEST_TENANT)),
        len(store.denial_records(TEST_TENANT)),
        len(store.admin_audit_records(TEST_TENANT)),
    )

    for owner_arg in ("acme", "other") * 10:
        assert (
            simulate_of(client, reader, row["id"], READ, {"owner": owner_arg}).status_code
            == 200
        )

    assert (
        len(read_audit(TEST_TENANT)),
        len(store.denial_records(TEST_TENANT)),
        len(store.admin_audit_records(TEST_TENANT)),
    ) == before


def test_the_reach_route_carries_the_transpose(client, reader, her, hers, vetted):
    """`by_tool` rides on the route 035d built rather than on one of its own: it answers
    the same question about the same token from the same read, and a second route would
    be a second `_granted_agents` call to render one page."""
    row, _ = hers
    for config_ in (TRIAGE, SECURITY):
        grant(row, config_)

    body = reach_of(client, reader, row["id"]).json()

    assert [entry["tool"] for entry in body["by_tool"]] == [READ]
    assert body["by_tool"][0]["granted_by"] == [
        {"agent": "security", "applies": {"github.repo": ["secret"]}},
        {"agent": "triage", "applies": {"github.repo": ["acme"]}},
    ]
    # And the flat union it is a transpose of is still there, unchanged.
    assert body["tools"] == [READ]


# --- the call id rides on the result — step 083, 080's E2 ---------------------------


def test_every_audited_call_hands_back_its_audit_rows_id(client, auth, vetted, token):
    """`_meta["com.carnet/call-id"]` on an allowed call and on a broker denial alike is
    the `run_id` of the audit row the call wrote — so an agent with forty calls and one
    denial can say which row is its, and an administrator can find it on
    `/admin/door-calls` by the same string."""
    from carnet.api.routes_mcp import CALL_ID_META_KEY

    row, _ = token
    grant(row, TRIAGE)

    allowed = call(client, auth, READ, {"owner": "acme"}).json()["result"]
    assert allowed["isError"] is False
    call_id = allowed["_meta"][CALL_ID_META_KEY]
    assert call_id.startswith(door.CALL_ID_PREFIX)
    assert read_audit()[-1]["run_id"] == call_id

    denied = call(client, auth, READ, {"owner": "somebody-else"}).json()["result"]
    assert denied["isError"] is True
    assert denied["_meta"][CALL_ID_META_KEY] == read_audit()[-1]["run_id"]
    assert denied["_meta"][CALL_ID_META_KEY] != call_id

    # And it is the administrator's string too: the door-traffic reader finds the row.
    records = storage.active().door_call_records(TEST_TENANT)
    assert {r["run_id"] for r in records} >= {call_id, denied["_meta"][CALL_ID_META_KEY]}


def test_a_refusal_that_wrote_no_row_carries_no_id(client, auth, vetted, token):
    """A `DoorRefused` is a JSON-RPC error and wrote no audit row, so there is nothing
    for an id to name — inventing one would point at a row that does not exist."""
    row, _ = token
    grant(row, TRIAGE)
    body = call(client, auth, "example_nothing", {}).json()
    assert "error" in body
    assert "_meta" not in body.get("error", {})
    assert "result" not in body


def test_call_tool_mints_its_own_id_when_nobody_hands_it_one(vetted, token, principal):
    """The four other callers of `door.call_tool` change nothing: absent, the id is
    minted inside exactly as before, with the same prefix."""
    row, _ = token
    grant(row, TRIAGE)
    door.call_tool(principal, READ, {"owner": "acme"})
    assert read_audit()[-1]["run_id"].startswith(door.CALL_ID_PREFIX)
    door.call_tool(principal, READ, {"owner": "acme"}, call_id="door-handedin0001")
    assert read_audit()[-1]["run_id"] == "door-handedin0001"
