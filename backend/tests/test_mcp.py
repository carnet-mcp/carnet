"""The MCP client, and the vetting boundary between a server and our registry.

Everything here runs against a fake transport. No subprocess, no Docker, no network —
the seam in tools/mcp/transport.py exists partly so this file can be honest about that.

The weight is on `bind()`. A protocol bug is a bug; a vetting bug is a tool nobody
approved becoming callable by every agent on the platform.
"""

import json

import pytest

from carnet import tools
from carnet.core import broker
from carnet.core.principal import Principal
from carnet.tools import mcp
from carnet.tools.base import MAY_HAVE_COMPLETED, REPORTED_USAGE, Resource, Tool
from carnet.tools.mcp import binding
from carnet.tools.mcp.connectors import github as github_connector
from carnet.tools.mcp.client import USAGE_META_KEY, Session, SessionPool, normalize
from carnet.tools.mcp.transport import TransportError

from conftest import Recording, TEST_ACTOR, read_audit, run_context

# Tenancy lives on the Principal, so every constructed principal carries one. A named
# constant rather than a literal: the tenant is routing here, not the thing under test.
TENANT = "t-test"

SYSTEM = Principal.system("test", TENANT)

# Taken from what github-mcp-server v1.8.0 actually advertises (issues toolset), not
# invented — the argument names and the `required` lists are the real ones. Plus one
# tool the server does not offer: the case this whole mechanism exists to keep out.
ADVERTISED = [
    {
        "name": "list_issues",
        "description": "List issues in a GitHub repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "state": {"type": "string"},
                "labels": {"type": "array"},
                "orderBy": {"type": "string"},
                "after": {"type": "string"},
                "perPage": {"type": "integer"},
            },
            "required": ["owner", "repo"],
        },
    },
    {
        "name": "issue_read",
        "description": "Get information about a specific issue in a GitHub repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "method": {"type": "string"},
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "issue_number": {"type": "integer"},
                "page": {"type": "integer"},
                "perPage": {"type": "integer"},
            },
            "required": ["method", "owner", "repo", "issue_number"],
        },
    },
    {
        "name": "search_issues",
        "description": "Search for issues using issues search syntax.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}, "owner": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "list_issue_types",
        "description": "List supported issue types.",
        "inputSchema": {
            "type": "object",
            "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}},
            "required": ["owner"],
        },
    },
    {"name": "get_label", "description": "Get a label.", "inputSchema": {"type": "object"}},
    # The three the server only advertises when NOT in read-only mode. One is vetted.
    {
        "name": "add_issue_comment",
        "description": "Add a comment to an issue.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "issue_number": {"type": "integer"},
                "body": {"type": "string"},
            },
            "required": ["owner", "repo", "issue_number", "body"],
        },
    },
    {
        "name": "issue_write",
        "description": "Create or update an issue.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "method": {"type": "string"},
                "owner": {"type": "string"},
                "repo": {"type": "string"},
            },
            "required": ["method", "owner", "repo"],
        },
    },
    {
        "name": "sub_issue_write",
        "description": "Restructure sub-issues.",
        "inputSchema": {"type": "object"},
    },
    # Not something v1.8.0 offers. It stands in for the version that does.
    {
        "name": "delete_repository",
        "description": "Delete a repository.",
        "inputSchema": {"type": "object"},
    },
]


class FakeTransport:
    """Scripted MCP server. Records what we sent so the handshake can be asserted."""

    def __init__(self, pages=None, call_result=None, call_error=None):
        self.pages = pages if pages is not None else [(ADVERTISED, None)]
        self.call_result = call_result or {"content": [{"type": "text", "text": "{}"}]}
        self.call_error = call_error
        self.sent = []
        self.closed = False
        self._page = 0

    def send(self, message):
        self.sent.append(message)
        if "id" not in message:
            return None

        method = message["method"]
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "github-mcp-server", "version": "0.9.0"},
            }
        elif method == "tools/list":
            advertised, cursor = self.pages[self._page]
            self._page += 1
            result = {"tools": advertised}
            if cursor:
                result["nextCursor"] = cursor
        elif method == "tools/call":
            if self.call_error:
                return {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "error": {"code": -32602, "message": self.call_error},
                }
            result = self.call_result
        else:
            return {"jsonrpc": "2.0", "id": message["id"], "error": {"message": "unknown method"}}

        return {"jsonrpc": "2.0", "id": message["id"], "result": result}

    def set_protocol_version(self, version):
        """Part of the transport interface: send / set_protocol_version / close."""

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def isolated_pool(monkeypatch):
    """A fresh session pool per test — a shared one would leak sessions between them."""
    monkeypatch.setattr(mcp, "POOL", SessionPool())


@pytest.fixture
def isolated_registry(monkeypatch):
    """Bound tools land in the real registry; give each test its own copy."""
    monkeypatch.setattr(tools, "REGISTRY", dict(tools.REGISTRY))


GITHUB = github_connector.CONNECTOR


def bound(transport=None, advertised=None):
    """Connect and bind the shipped GitHub connector against a fake server."""
    if transport is None:
        transport = FakeTransport(pages=[(advertised or ADVERTISED, None)])
    return mcp.connect(TENANT, GITHUB, None, transport=transport)


# --- protocol ------------------------------------------------------------------


def test_the_handshake_is_initialize_then_initialized():
    """Order is protocol, not preference: nothing else is legal before both."""
    transport = FakeTransport()
    session = Session(transport)
    session.initialize()

    methods = [m["method"] for m in transport.sent]
    assert methods == ["initialize", "notifications/initialized"]
    assert "id" not in transport.sent[1]  # a notification, not a request
    assert session.server_info["name"] == "github-mcp-server"


def test_list_tools_follows_the_cursor_to_the_end():
    """GitHub advertises far more tools than fit one page; a client that stopped at
    the first would silently vet against half an advertisement."""
    transport = FakeTransport(
        pages=[(ADVERTISED[:2], "page-2"), (ADVERTISED[2:], None)],
    )
    session = Session(transport)
    assert len(session.list_tools()) == len(ADVERTISED)


def test_a_jsonrpc_error_becomes_an_error_dict_not_an_exception():
    """The broker turns {"error": ...} into outcome="error" and hands it to the model,
    which can then explain itself instead of the run crashing."""
    session = Session(FakeTransport(call_error="unknown tool: nope"))
    result = session.call_tool("nope", {})
    assert "unknown tool: nope" in result["error"]


# --- result normalization ------------------------------------------------------


def test_structured_content_is_preferred():
    assert normalize({"structuredContent": {"count": 3}}) == {"count": 3}


def test_json_in_a_text_block_is_parsed():
    result = normalize({"content": [{"type": "text", "text": '{"count": 3}'}]})
    assert result == {"count": 3}


def test_a_json_array_is_wrapped_so_the_result_is_always_an_object():
    assert normalize({"content": [{"type": "text", "text": "[1, 2]"}]}) == {"items": [1, 2]}


def test_prose_survives_as_text():
    assert normalize({"content": [{"type": "text", "text": "no issues"}]}) == {"text": "no issues"}


def test_an_error_result_becomes_an_error_dict():
    result = normalize({"isError": True, "content": [{"type": "text", "text": "not found"}]})
    assert result == {"error": "not found"}


def test_non_text_blocks_are_counted_not_inlined():
    """An embedded image is base64 that would spend the whole size budget saying
    nothing the model asked for."""
    result = normalize(
        {
            "content": [
                {"type": "text", "text": '{"ok": true}'},
                {"type": "image", "data": "iVBORw0KGgo" * 5000},
            ]
        }
    )
    assert result == {"ok": True, "non_text_blocks": 1}
    assert "iVBOR" not in json.dumps(result)


# --- what a call spent, lifted out of `_meta` ------------------------------------
#
# Step 045b. `_meta` is the protocol's own extension point — the carrier 033c already
# used inbound — so a server that wants to say what a call cost has somewhere sanctioned
# to say it, and a server that does not is unaffected.


def test_a_server_can_report_what_a_call_spent():
    result = normalize(
        {
            "structuredContent": {"answer": "yes"},
            "_meta": {USAGE_META_KEY: {"model": "claude-opus-5", "input_tokens": 12}},
        }
    )

    assert result == {
        "answer": "yes",
        REPORTED_USAGE: {"model": "claude-opus-5", "input_tokens": 12},
    }


def test_an_errored_call_still_reports_what_it_spent():
    """A vendor that charged and then returned 500 has spent money, and money spent is
    money recorded. The error path lifts the report for that reason rather than as
    symmetry."""
    result = normalize(
        {
            "isError": True,
            "content": [{"type": "text", "text": "upstream 500"}],
            "_meta": {USAGE_META_KEY: {"input_tokens": 12}},
        }
    )

    assert result == {"error": "upstream 500", REPORTED_USAGE: {"input_tokens": 12}}


def test_a_server_that_says_nothing_leaves_no_key():
    """Which is every MCP server built before this existed, and most of them after. No
    key means the broker records NULL usage — *not applicable*, not zero."""
    assert REPORTED_USAGE not in normalize({"structuredContent": {"count": 3}})
    assert REPORTED_USAGE not in normalize({"structuredContent": {}, "_meta": {}})
    assert REPORTED_USAGE not in normalize({"structuredContent": {}, "_meta": "nonsense"})


def test_a_server_cannot_report_its_own_spend_in_the_body():
    """**The clear is unconditional, and this is why.** `structuredContent` is a mapping
    the *server* composed, so without it a server could meter itself by putting our
    reserved key in its result and skipping `_meta` entirely. The only route to the meter
    is the extension point this function reads."""
    result = normalize(
        {"structuredContent": {"count": 3, REPORTED_USAGE: {"input_tokens": 10**9}}}
    )

    assert result == {"count": 3}


def test_meta_wins_over_a_body_that_claims_the_same_key():
    """Cleared then set, in that order — a server that writes both is metered by the one
    it was supposed to use."""
    result = normalize(
        {
            "structuredContent": {REPORTED_USAGE: {"input_tokens": 10**9}},
            "_meta": {USAGE_META_KEY: {"input_tokens": 5}},
        }
    )

    assert result == {REPORTED_USAGE: {"input_tokens": 5}}


def test_nothing_here_validates_the_report():
    """One validator, in the broker. A report that is obvious nonsense is carried out of
    `_meta` unexamined and dropped by `core.usage.parse_report` — two validators would be
    two sets of rules free to disagree about the same number."""
    result = normalize({"structuredContent": {}, "_meta": {USAGE_META_KEY: "nonsense"}})

    assert result == {REPORTED_USAGE: "nonsense"}


# --- vetting: the allowlist ----------------------------------------------------


def test_only_vetted_tools_are_bound():
    tools_, excluded = bound()
    assert {t.name for t in tools_} == {
        "github_mcp_list_issues",
        "github_mcp_issue_read",
        "github_mcp_add_issue_comment",
    }
    assert "delete_repository" in excluded


def test_a_tool_the_server_adds_later_does_not_appear():
    """The brief's case. A server that grows `delete_repository` in a future version
    must not silently become callable — an allowlist, not a filter."""
    tools_, excluded = bound()
    names = {t.name for t in tools_}
    for unvetted in (
        "delete_repository",
        "search_issues",
        "list_issue_types",
        "get_label",
        "issue_write",       # creates and updates issues — scopeable, not vetted
        "sub_issue_write",
    ):
        assert not any(unvetted in name for name in names)
        assert unvetted in excluded


def test_a_vetted_tool_the_server_no_longer_advertises_raises():
    """Drift worth stopping for. Guessing which remaining tool replaced it is not
    a call this layer gets to make."""
    without_list_issues = [t for t in ADVERTISED if t["name"] != "list_issues"]
    with pytest.raises(RuntimeError, match="does not advertise"):
        bound(advertised=without_list_issues)


def test_a_renamed_argument_breaks_the_bind_rather_than_the_scoping():
    """The supply-chain case. If `repo` becomes `repository`, our resource declaration
    names an argument that never arrives — the tool would read as scoped and be
    completely open. tools.validation catches it here, loudly."""
    drifted = [dict(t) for t in ADVERTISED]
    drifted[0] = {
        **drifted[0],
        "inputSchema": {
            "type": "object",
            "properties": {"owner": {"type": "string"}, "repository": {"type": "string"}},
        },
    }
    with pytest.raises(RuntimeError, match="not in its input_schema"):
        bound(advertised=drifted)


def test_the_schema_and_description_come_from_the_server():
    """We copy rather than restate: a description we wrote would drift from the tool."""
    tools_, _ = bound()
    listing = next(t for t in tools_ if t.name == "github_mcp_list_issues")
    assert listing.description == "List issues in a GitHub repository."

    properties = set(listing.input_schema["properties"])
    # The arguments we scope on, and several the manifest never mentions — proof the
    # schema is the server's rather than something we restated.
    assert {"owner", "repo"} <= properties
    assert {"orderBy", "labels", "after"} <= properties


def test_the_effect_and_resources_come_from_us():
    """The row a server cannot author. It gives four argument names; it does not say
    which identify the thing worth scoping, nor whether the call mutates anything."""
    tools_, _ = bound()
    listing = next(t for t in tools_ if t.name == "github_mcp_list_issues")
    assert listing.effect == "read"
    assert listing.resources == (
        Resource("github.repo", ["owner", "repo"], template="{owner}/{repo}"),
    )
    assert listing.connector == "github-mcp"


# --- naming --------------------------------------------------------------------


def test_tool_names_are_namespaced_by_connector():
    """So two connectors may both offer `list_issues`, and so an audit record says
    which path a call took without a cross-reference."""
    assert GITHUB.local_name(GITHUB.vetted[0]) == "github_mcp_list_issues"


def test_a_name_that_would_be_illegal_is_refused_at_import():
    connector = binding.Connector(
        id="x",
        launch=binding.StdioLaunch(command=("true",)),
        vetted=[binding.Vetted("a" * 80)],
    )
    with pytest.raises(RuntimeError, match="not a legal tool name"):
        connector.validate()


def test_a_long_name_can_be_overridden():
    connector = binding.Connector(
        id="x",
        launch=binding.StdioLaunch(command=("true",)),
        vetted=[binding.Vetted("a" * 80, local_name="x_short")],
    )
    connector.validate()
    assert connector.declared_names() == {"x_short"}


def test_a_connector_cannot_shadow_a_hand_written_tool(vetted_github):
    """A grant naming a shadowed tool would be ambiguous, and the audit log would
    record one name for two different things."""
    assert not (set(tools.REGISTRY) & mcp.declared_names(TENANT))


def test_shadowing_a_hand_written_tool_is_refused_at_vetting_time():
    """The check moved from import to the moment the data arrives. A connector whose
    namespaced names would collide is refused when somebody tries to add it, rather
    than discovered at the first call."""
    colliding = binding.Connector(
        id="chat",
        launch=binding.StdioLaunch(command=("true",)),
        vetted=[binding.Vetted("message", local_name="post_message")],
    )

    with pytest.raises(RuntimeError, match="collide with hand-written tools"):
        tools.save_connector(TENANT, colliding, actor=TEST_ACTOR)


def test_vetted_names_are_known_before_anything_connects(vetted_github):
    """Which is what lets an agent granting an MCP tool be validated when saved."""
    assert tools.is_known("github_mcp_list_issues", TENANT)
    assert tools.get("github_mcp_list_issues", TENANT) is None  # known, not yet callable


# --- credentials and sessions --------------------------------------------------


def test_sessions_are_keyed_by_credential_not_by_connector():
    """The one that makes delegated credentials real rather than cosmetic. Two users
    with their own tokens must not share a session, or the second would silently act
    with the first one's authority."""
    pool = SessionPool()
    a, b = object(), object()
    pool.put(TENANT, "github-mcp", "token-priya", a)
    pool.put(TENANT, "github-mcp", "token-sam", b)

    assert pool.get(TENANT, "github-mcp", "token-priya") is a
    assert pool.get(TENANT, "github-mcp", "token-sam") is b
    assert pool.get(TENANT, "github-mcp", "token-nobody") is None


def test_a_shared_credential_shares_one_session():
    """Two principals on one service account should not spawn two containers."""
    pool = SessionPool()
    session = object()
    pool.put(TENANT, "github-mcp", "service-token", session)
    assert pool.get(TENANT, "github-mcp", "service-token") is session


def test_the_credential_is_not_used_as_a_dict_key():
    assert SessionPool.fingerprint("hunter2") != "hunter2"
    assert SessionPool.fingerprint(None) == "anonymous"


def test_the_launch_environment_carries_the_secret_and_nothing_else():
    """A server receives the credential it needs, not whatever else we happen to hold."""
    env = GITHUB.launch_env("ghp_example")
    assert env["GITHUB_PERSONAL_ACCESS_TOKEN"] == "ghp_example"
    # No GITHUB_READ_ONLY: a write is vetted, so the mode came off by itself.
    assert set(env) == {"GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_TOOLSETS"}


# --- through the broker --------------------------------------------------------

MCP_AGENT = {
    "name": "mcp-test-agent",
    "system": "irrelevant",
    "runtime": "simple",
    "permissions": {
        "tools": ["github_mcp_list_issues"],
        "scope": {"github.repo": {"read": ["anthropics/*"]}},
    },
}


@pytest.fixture(name="ctx")
def a_run_context():
    return run_context(SYSTEM)


def test_an_unbound_mcp_tool_is_denied_rather_than_improvised(ctx):
    """If a connector failed to start, the tool is not in REGISTRY and the broker
    refuses it. Fail-closed is the backstop; connect() raising is the plan."""
    result = broker.call(ctx, MCP_AGENT, "github_mcp_list_issues", {"owner": "a", "repo": "b"})
    assert result.get("denied_by") == "broker"
    assert "not a registered tool" in result["error"]


def test_a_bound_mcp_call_is_scoped_by_the_same_grant(ctx, isolated_registry):
    """The headline. The grant was written for a tool taking one `repo` argument;
    it constrains one taking `owner` and `repo` without knowing anything changed."""
    transport = FakeTransport(
        call_result={"content": [{"type": "text", "text": '{"count": 2}'}]}
    )
    for tool in bound(transport)[0]:
        tools.register(TENANT, tool)

    ok = broker.call(
        ctx, MCP_AGENT, "github_mcp_list_issues", {"owner": "anthropics", "repo": "sdk"}
    )
    assert ok == {"count": 2}

    denied = broker.call(
        ctx, MCP_AGENT, "github_mcp_list_issues", {"owner": "torvalds", "repo": "linux"}
    )
    assert denied.get("denied_by") == "broker"
    assert "torvalds/linux" in denied["error"]


def test_the_model_cannot_supply_its_own_token(ctx, isolated_registry):
    """The proxy takes its credential as `token`, which is in RESERVED_KWARGS — so a
    model supplying one is refused outright rather than overriding the broker."""
    for tool in bound()[0]:
        tools.register(TENANT, tool)

    result = broker.call(
        ctx,
        MCP_AGENT,
        "github_mcp_list_issues",
        {"owner": "anthropics", "repo": "sdk", "token": "ghp_attacker"},
    )
    assert result.get("denied_by") == "broker"


def test_a_denied_mcp_call_never_reaches_the_server(ctx, isolated_registry):
    """A refusal must cost nothing outbound — no request, no credential read."""
    transport = FakeTransport()
    for tool in bound(transport)[0]:
        tools.register(TENANT, tool)
    before = len(transport.sent)

    broker.call(ctx, MCP_AGENT, "github_mcp_list_issues", {"owner": "torvalds", "repo": "linux"})
    assert len(transport.sent) == before


# --- writes --------------------------------------------------------------------
# Nothing had ever constructed Vetted(effect="write"). These cover the half of the
# broker that cannot be undone by trying again.

WRITER_CONNECTOR = binding.Connector(
    id="wr",
    launch=binding.StdioLaunch(command=("true",), read_only_env="SERVER_READ_ONLY"),
    vetted=[
        binding.Vetted(
            "add_issue_comment",
            effect="write",
            resources=[Resource("github.repo", ["owner", "repo"], template="{owner}/{repo}")],
        )
    ],
)

WRITER_ADVERTISED = [
    {
        "name": "add_issue_comment",
        "description": "Comment on an issue.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "issue_number": {"type": "integer"},
                "body": {"type": "string"},
            },
            "required": ["owner", "repo", "issue_number", "body"],
        },
    }
]

WRITER_AGENT = {
    "name": "writer-agent",
    "system": "irrelevant",
    "permissions": {
        "tools": ["wr_add_issue_comment"],
        "scope": {"github.repo": {"write": ["anthropics/*"]}},
    },
    "limits": {"max_writes": 1},
}


def bind_writer():
    return binding.bind(WRITER_CONNECTOR, WRITER_ADVERTISED, lambda *a: {"ok": True})


def test_a_vetted_write_becomes_a_write_tool():
    """The effect is ours, not the server's — `readOnlyHint` is a claim by the thing
    being constrained, so nothing about the advertisement decides this."""
    tools_, _ = bind_writer()
    assert tools_[0].effect == "write"
    assert tools_[0].name == "wr_add_issue_comment"


def test_a_vetted_write_with_no_resources_is_refused_at_bind():
    """A write to something policy cannot name is unscopeable by construction, and
    for a connector tool that is caught here rather than at import."""
    connector = binding.Connector(
        id="wr2",
        launch=binding.StdioLaunch(command=("true",)),
        vetted=[binding.Vetted("add_issue_comment", effect="write")],
    )
    with pytest.raises(RuntimeError, match="declares no resources"):
        binding.bind(connector, WRITER_ADVERTISED, lambda *a: {})


def test_the_budget_seat_does_not_care_who_wrote_the_tool(isolated_registry):
    """A connector tool goes through the broker's step 2 exactly as a shipped one does.

    **This asserted `max_writes` biting until step 084.** `WRITER_AGENT` carries
    `limits: {"max_writes": 1}`, a real second call was refused, and the sentence came
    from `core.limits.Budget` — which 084 deleted, because its only caller had no caller
    (step 081, and the reason `max_writes: 0` refused nothing on a door deployment).

    What is left is the half that was ever this file's business: **a connector tool is
    reserved for, and refused, like any other.** The budget is a `conftest.Recording`, so
    the assertion is on the descriptor the broker hands over — a bound connector tool,
    `effect="write"` — and on the refusal reaching the caller. Whether four dials add up
    correctly was never an MCP question, and there are no longer four dials.
    """
    for tool in bind_writer()[0]:
        tools.register(TENANT, tool)
    args = {"owner": "anthropics", "repo": "sdk", "issue_number": 1, "body": "hi"}

    budget = Recording()
    assert broker.call(
        run_context(SYSTEM, budget), WRITER_AGENT, "wr_add_issue_comment", args
    ) == {"ok": True}
    assert [(t.name, t.effect) for t in budget.reserved] == [
        ("wr_add_issue_comment", "write")
    ]

    refusing = Recording(refuse="run write budget exhausted: 1 write already made")
    second = broker.call(
        run_context(SYSTEM, refusing), WRITER_AGENT, "wr_add_issue_comment", args
    )
    assert second.get("denied_by") == "broker"
    assert "write budget exhausted" in second["error"]
    # Refused before execution, which is the point of the dial and not of the counter.
    assert refusing.bytes == []


def test_a_read_grant_does_not_authorize_a_connector_write(isolated_registry):
    for tool in bind_writer()[0]:
        tools.register(TENANT, tool)
    agent = {**WRITER_AGENT, "permissions": {
        "tools": ["wr_add_issue_comment"],
        "scope": {"github.repo": {"read": ["anthropics/*"]}},
    }}
    ctx = run_context(SYSTEM)
    result = broker.call(
        ctx, agent, "wr_add_issue_comment",
        {"owner": "anthropics", "repo": "sdk", "issue_number": 1, "body": "hi"},
    )
    assert result.get("denied_by") == "broker"
    assert "no 'write' grant" in result["error"]


# --- ambiguous writes ----------------------------------------------------------


def test_an_undelivered_failure_says_nothing_happened():
    """Safe to retry, and the model should be told so."""
    class Dead:
        def send(self, message):
            raise TransportError("pipe closed", delivered=False)

        def set_protocol_version(self, version):
            pass

        def close(self):
            pass

    result = Session(Dead()).call_tool("add_issue_comment", {})
    assert "never reached the server" in result["error"]
    assert MAY_HAVE_COMPLETED not in result


def test_a_delivered_failure_says_it_may_have_landed():
    """The request was on the wire. Retrying might comment twice."""
    class Silent:
        def send(self, message):
            raise TransportError("no reply within 15s", delivered=True)

        def set_protocol_version(self, version):
            pass

        def close(self):
            pass

    result = Session(Silent()).call_tool("add_issue_comment", {})
    assert result[MAY_HAVE_COMPLETED] is True
    assert "MAY have taken effect" in result["error"]
    assert "Do not repeat it" in result["error"]


def test_an_ambiguous_write_is_audited_as_unknown(isolated_registry, isolated_var_dir):
    """The only place that will ever record "we do not know if this happened"."""
    tool = bind_writer()[0][0]
    ambiguous = Tool(
        **{**tool.__dict__, "impl": lambda **kw: {"error": "no reply", MAY_HAVE_COMPLETED: True}}
    )
    tools.register(TENANT, ambiguous)

    ctx = run_context(SYSTEM)
    broker.call(
        ctx, WRITER_AGENT, "wr_add_issue_comment",
        {"owner": "anthropics", "repo": "sdk", "issue_number": 1, "body": "hi"},
    )

    record = read_audit()[-1]
    assert record["outcome"] == "unknown"
    assert record["effect"] == "write"


def test_an_ambiguous_read_stays_a_plain_error(isolated_registry, isolated_var_dir):
    """An unanswered read changed nothing either way — there is nothing to go and look at."""
    reader = Tool(
        name="wr_peek",
        description="",
        input_schema={"type": "object", "properties": {"owner": {"type": "string"}}},
        impl=lambda **kw: {"error": "no reply", MAY_HAVE_COMPLETED: True},
        effect="read",
        resources=[Resource("github.repo", "owner")],
        connector="wr",
    )
    tools.register(TENANT, reader)
    agent = {"name": "r", "permissions": {
        "tools": ["wr_peek"], "scope": {"github.repo": {"read": ["anthropics"]}}}}

    ctx = run_context(SYSTEM)
    broker.call(ctx, agent, "wr_peek", {"owner": "anthropics"})

    record = read_audit()[-1]
    assert record["outcome"] == "error"


# --- read-only mode is derived, not written down -------------------------------


def test_a_read_only_connector_launches_the_server_read_only():
    """Defence in depth that cannot drift from the allowlist it is defending."""
    reads_only = binding.Connector(
        id="ro",
        launch=binding.StdioLaunch(command=("true",), read_only_env="SERVER_READ_ONLY"),
        vetted=[binding.Vetted("list_issues", effect="read",
                               resources=[Resource("github.repo", "owner")])],
    )
    assert reads_only.read_only is True
    assert reads_only.launch_env("tok")["SERVER_READ_ONLY"] == "1"


def test_vetting_a_write_turns_the_servers_read_only_mode_off():
    """Otherwise the vetted write could never run, and someone would have to
    remember to flip a constant — and remember to flip it back."""
    assert WRITER_CONNECTOR.read_only is False
    assert "SERVER_READ_ONLY" not in WRITER_CONNECTOR.launch_env("tok")


# --- two launch shapes ----------------------------------------------------------
#
# A stdio server takes its credential at process launch and holds it for that
# process's life; an HTTP server takes it per request. That difference is the whole
# reason per-user credentials need the second shape, so which one a connector uses
# must be explicit and must survive a round trip through the database.


def _http_connector(**overrides):
    launch = {
        "url": "https://api.example.com/mcp/",
        "credential_env": "EXAMPLE_TOKEN",
        **overrides,
    }
    return binding.Connector(
        id="example",
        launch=binding.HttpLaunch(**launch),
        vetted=[
            binding.Vetted(
                "list_issues", effect="read", resources=[Resource("github.repo", "owner")]
            )
        ],
    )


def test_a_stdio_launch_round_trips():
    connector = binding.Connector(
        id="local",
        launch=binding.StdioLaunch(
            command=("docker", "run"), credential_env="TOK", env={"A": "b"},
            read_only_env="RO",
        ),
        vetted=[binding.Vetted("list_issues", effect="read",
                               resources=[Resource("github.repo", "owner")])],
    )

    rebuilt = binding.from_manifest(binding.to_manifest(connector))

    assert rebuilt.launch == connector.launch
    assert rebuilt.transport_kind == "stdio"


def test_an_http_launch_round_trips():
    connector = _http_connector(headers={"X-Toolsets": "issues"})

    rebuilt = binding.from_manifest(binding.to_manifest(connector))

    assert rebuilt.launch == connector.launch
    assert rebuilt.transport_kind == "http"


def test_a_launch_row_without_a_kind_is_stdio():
    """Rows written before the HTTP transport existed have no `kind`. Defaulting is
    what lets them keep working — `connectors.launch` is JSONB precisely so the shape
    can grow without a migration."""
    legacy = {
        "id": "old",
        "description": "",
        "launch": {"command": ["true"], "credential_env": "TOK"},
        "vetted": [],
    }

    assert binding.from_manifest(legacy).transport_kind == "stdio"


def test_an_unknown_launch_kind_is_refused():
    """Fail closed rather than guess. stdio holds a credential for a process lifetime
    and HTTP does not, so picking one for the operator would be picking their security
    properties for them."""
    with pytest.raises(RuntimeError, match="unknown kind"):
        binding.from_manifest(
            {"id": "x", "launch": {"kind": "carrier-pigeon"}, "vetted": []}
        )


# --- whose account: the vetted identity in the manifest (033a) ---------------------


def test_the_identity_round_trips_through_the_manifest():
    connector = binding.Connector(
        id="gh",
        launch=binding.HttpLaunch(url="https://mcp.example/x"),
        vetted=[binding.Vetted("search_issues", effect="read", identity="user")],
    )

    rebuilt = binding.from_manifest(binding.to_manifest(connector))

    assert rebuilt.vetted[0].identity == "user"


def test_a_vetted_row_without_an_identity_reads_as_service():
    """A row written before 033a. `service` is the stated break in docs/UPGRADING.md:
    the shared credential, which is what every headless caller always got — and the
    one thing the missing key must never mean is the old try-delegated-first order,
    which was never part of any approval."""
    legacy = {
        "id": "old",
        "description": "",
        "launch": {"kind": "http", "url": "https://mcp.example/x"},
        "vetted": [{"remote_name": "search_issues", "effect": "read"}],
    }

    assert binding.from_manifest(legacy).vetted[0].identity == "service"


def test_an_unknown_identity_is_refused_at_load():
    """The same fail-closed moment an unknown launch kind gets: whose account a tool
    acts as is a security property, not something to guess."""
    with pytest.raises(RuntimeError, match="identity"):
        binding.from_manifest(
            {
                "id": "x",
                "launch": {"kind": "http", "url": "https://mcp.example/x"},
                "vetted": [
                    {"remote_name": "t", "effect": "read", "identity": "whichever"}
                ],
            }
        )


def test_bind_carries_the_identity_and_credential_env_onto_the_tool():
    """What the broker reads at step 3 comes off the Tool, so the descriptor's answer
    to "whose account?" and the manifest's answer to "which variable?" both have to
    survive binding."""
    connector = binding.Connector(
        id="gh",
        launch=binding.HttpLaunch(url="https://mcp.example/x", credential_env="GH_TOK"),
        vetted=[binding.Vetted("search_issues", effect="read", identity="user")],
    )
    advertised = [
        {"name": "search_issues", "inputSchema": {"type": "object", "properties": {}}}
    ]

    tools, _ = binding.bind(connector, advertised, lambda *a: {})

    assert tools[0].identity == "user"
    assert tools[0].credential_env == "GH_TOK"


def test_an_http_credential_goes_in_a_header_not_the_environment():
    connector = _http_connector()

    headers = connector.launch_headers("sekrit")

    assert headers["Authorization"] == "Bearer sekrit"


def test_the_credential_header_and_prefix_are_configurable():
    """Most servers want `Authorization: Bearer`; some vendors insist otherwise."""
    connector = _http_connector(credential_header="X-Api-Key", credential_prefix="")

    assert connector.launch_headers("sekrit")["X-Api-Key"] == "sekrit"


def test_no_credential_means_no_credential_header():
    """An absent credential must not become the literal string 'Bearer None'."""
    assert "Authorization" not in _http_connector().launch_headers(None)


def test_non_secret_headers_survive_without_a_credential():
    connector = _http_connector(headers={"X-Toolsets": "issues"})

    assert connector.launch_headers(None) == {"X-Toolsets": "issues"}


def test_an_http_launch_needs_an_absolute_http_url():
    """The value causes an outbound request, so it is checked rather than assumed."""
    for bad in ("", "file:///etc/passwd", "api.example.com/mcp"):
        with pytest.raises(RuntimeError, match="url"):
            binding.HttpLaunch(url=bad)


def test_a_stdio_server_is_found_through_the_parents_path(monkeypatch, tmp_path):
    """**The launch bug, and the reason no test caught it for a whole machine's lifetime.**

    `env_for` gives the child no `PATH` on purpose, and `Popen` with an explicit `env`
    then falls back to `os.defpath` — `/bin:/usr/bin`. A manifest naming a bare `docker`
    therefore starts on a machine whose toolchain is in `/usr/bin` and fails on one that
    keeps it anywhere else. Nothing noticed, because launching a stdio server is a thing
    no test does.

    So this asserts the resolution rather than the launch: the program is looked up in
    **this** process, and what reaches `Popen` is an absolute path. The child's
    environment is untouched, which is the property the fix had to preserve — see
    `StdioTransport._resolve`.
    """
    from carnet.tools.mcp.transport import StdioTransport, TransportError

    elsewhere = tmp_path / "not-on-the-default-path"
    elsewhere.mkdir()
    program = elsewhere / "pretend-mcp-server"
    program.write_text("#!/bin/sh\nexit 0\n")
    program.chmod(0o755)
    monkeypatch.setenv("PATH", str(elsewhere))

    spawned = {}

    def fake_popen(command, **kwargs):
        spawned["command"] = command
        spawned["env"] = kwargs.get("env")
        raise OSError("stopped before actually starting anything")

    monkeypatch.setattr("subprocess.Popen", fake_popen)

    with pytest.raises(TransportError):
        StdioTransport(["pretend-mcp-server", "--stdio"], env={"TOOLSETS": "issues"})

    assert spawned["command"][0] == str(program), "the bare name reached Popen"
    assert spawned["command"][1] == "--stdio", "the arguments must survive untouched"
    # The whole point of the fix: resolving in the parent means the child still gets
    # nothing it was not given.
    assert spawned["env"] == {"TOOLSETS": "issues"}
    assert "PATH" not in spawned["env"]


def test_a_stdio_server_that_is_not_on_the_path_says_so(monkeypatch, tmp_path):
    """A sentence naming whose PATH is being searched, because the answer is almost
    always "not the one in your shell" — the worker or the server is a different
    process with a different environment."""
    from carnet.tools.mcp.transport import StdioTransport, TransportError

    monkeypatch.setenv("PATH", str(tmp_path))

    with pytest.raises(TransportError, match="not on this process's PATH"):
        StdioTransport(["no-such-server"], env={})


def test_a_stdio_launch_needs_a_command():
    with pytest.raises(RuntimeError, match="command"):
        binding.StdioLaunch(command=())


def test_an_http_connector_survives_storage():
    """The round trip that matters: through `save_connector` and back out as a
    `Connector`, not just through `to_manifest`. No migration was needed for this —
    `connectors.launch` is JSONB."""
    tools.save_connector(TENANT, _http_connector(headers={"X-Toolsets": "issues"}), actor=TEST_ACTOR)

    loaded = mcp.get_connector(TENANT, "example")

    assert loaded.transport_kind == "http"
    assert loaded.launch.url == "https://api.example.com/mcp/"
    assert loaded.launch_headers("tok")["Authorization"] == "Bearer tok"


def test_storage_still_refuses_to_keep_read_only_for_either_shape():
    """The rule that survived the last step has to survive this one: `read_only` is
    derived, and there is no column for it whichever transport a connector speaks."""
    manifest = binding.to_manifest(_http_connector())

    assert "read_only" not in manifest
    assert "read_only" not in manifest["launch"]


def test_the_transport_is_chosen_by_the_manifest(monkeypatch):
    """Both branches asserted by recording which class was constructed — building a
    real StdioTransport would spawn a process, which this suite does not do."""
    built = []
    monkeypatch.setattr(mcp, "StdioTransport", lambda *a, **kw: built.append(("stdio", a, kw)))
    monkeypatch.setattr(mcp, "HttpTransport", lambda *a, **kw: built.append(("http", a, kw)))

    mcp._transport_for(TENANT, _http_connector(), "tok")
    assert built[-1][0] == "http"
    assert built[-1][1][0] == "https://api.example.com/mcp/"
    assert built[-1][2]["headers"]["Authorization"] == "Bearer tok"

    mcp._transport_for(TENANT, GITHUB, "tok")
    assert built[-1][0] == "stdio"


def test_an_http_connector_is_never_reached_over_stdio(monkeypatch):
    """No fallback between kinds, ever. stdio holds a credential for a process
    lifetime and HTTP does not, so substituting one for the other would substitute a
    security posture — a connector that cannot be reached the way it says it should be
    is a failure, not a hint."""
    monkeypatch.setattr(
        mcp, "StdioTransport", lambda *a, **kw: pytest.fail("built a stdio transport")
    )
    monkeypatch.setattr(mcp, "HttpTransport", lambda *a, **kw: "http-transport")

    assert mcp._transport_for(TENANT, _http_connector(), None) == "http-transport"


def test_an_http_connector_with_no_credential_still_connects():
    """An unauthenticated server is legitimate — the shipped GitHub read path ran
    against one for a while. It must not become 'Bearer None'."""
    transport = mcp._transport_for(TENANT, _http_connector(), None)

    assert "Authorization" not in transport._headers


def test_a_stale_pooled_session_is_retired_and_replaced(monkeypatch):
    """Pooled sessions outlive runs, so a subprocess that died between them leaves a
    handle that looks live and is not. `list_tools()` is the first thing that touches
    the server, so it is where that reveals itself — no probe needed."""
    dead = FakeTransport()
    dead.send = lambda message: (_ for _ in ()).throw(TransportError("server exited"))
    stale = Session(dead)
    mcp.POOL.put(TENANT, GITHUB.id, None, stale)

    fresh = FakeTransport()
    monkeypatch.setattr(mcp, "_transport_for", lambda tenant_id, connector, credential: fresh)

    tools_bound, _ = mcp.connect(TENANT, GITHUB, None)

    assert [t.name for t in tools_bound]
    assert mcp.POOL.get(TENANT, GITHUB.id, None) is not stale


def test_an_unreachable_server_is_reported_rather_than_dialled_twice(monkeypatch):
    """Retry only applies to a session we did not just create. A server that is simply
    down should be reported once."""
    attempts = []

    def failing(tenant_id, connector, credential):
        attempts.append(connector.id)
        transport = FakeTransport()
        transport.send = lambda message: (_ for _ in ()).throw(TransportError("refused"))
        return transport

    monkeypatch.setattr(mcp, "_transport_for", failing)

    with pytest.raises(TransportError):
        mcp.connect(TENANT, GITHUB, None)

    assert len(attempts) == 1


def test_the_credential_lookup_is_told_which_variable_the_manifest_names(monkeypatch):
    """The end of the chain the 401 exposed: `ensure_available` has the connector, so
    it passes the variable name down rather than making the credential store already
    know it. A name, not a connector — core/credentials.py still never learns what an
    MCP server is."""
    tools.save_connector(TENANT, _http_connector(), actor=TEST_ACTOR)
    agent = {
        "name": "x",
        "permissions": {
            "tools": ["example_list_issues"],
            "scope": {"github.repo": {"read": ["anthropics/*"]}},
        },
    }
    asked = []
    monkeypatch.setattr(mcp, "connect", lambda t, c, cred, **kw: ([], []))

    def credential_for(cid, env_var=None, ref=None):
        asked.append((cid, env_var))
        return None, False  # (credential, delegated) — see ensure_available

    tools.ensure_available(TENANT, agent, credential_for=credential_for)

    assert asked == [("example", "EXAMPLE_TOKEN")]


def test_read_only_is_still_derived_for_an_http_connector():
    """It is derived from the vetted effects and always will be. There is simply no
    launch-time switch to apply it to — the allowlist is unaffected, and the allowlist
    was always the actual control."""
    assert _http_connector().read_only is True
    assert not hasattr(binding.HttpLaunch(url="https://x.example/mcp"), "read_only_env")


def test_the_shipped_github_connector_vets_exactly_one_write():
    """Pinned by name. Vetting a write takes the server out of read-only mode, so a
    second one appearing should be a deliberate change someone had to edit this test
    for — not something that rides along in a manifest diff."""
    writes = {v.remote_name for v in GITHUB.vetted if v.effect == "write"}
    assert writes == {"add_issue_comment"}
    assert GITHUB.read_only is False  # follows from the above, and must
    assert "GITHUB_READ_ONLY" not in GITHUB.launch_env("tok")


def test_the_destructive_github_writes_stay_unvetted():
    """`issue_write` creates and updates issues; `sub_issue_write` restructures them.
    Both are scopeable and neither is vetted — a comment can be deleted."""
    vetted = {v.remote_name for v in GITHUB.vetted}
    assert "issue_write" not in vetted
    assert "sub_issue_write" not in vetted


def test_only_connectors_an_agent_needs_are_connected(monkeypatch, vetted_github):
    """A connector is a container. An agent touching no GitHub tool should not pay
    for a GitHub server."""
    connected = []
    monkeypatch.setattr(
        mcp, "connect", lambda t, c, cred, **kw: (connected.append(c.id), ([], []))[1]
    )

    tools.ensure_available(TENANT, {"name": "x", "permissions": {"tools": ["post_message"]}})
    assert connected == []

    tools.ensure_available(TENANT, {"name": "y", "permissions": {"tools": ["github_mcp_list_issues"]}})
    assert connected == ["github-mcp"]


# --- 069: the vetting's half of a tool, without a server ---------------------------


def test_a_described_tool_and_a_bound_one_agree_on_everything_the_check_reads():
    """**The one property that makes `tools.describe` safe, asserted field by field.**

    A simulator answers *would this be admitted* from `described`, and a real call is
    answered from `bind`. If those two ever disagree about `effect`, `resources` or the
    name, the simulator is a second opinion about permission wearing the door's clothes —
    which is the failure `_adjudicate` was extracted to prevent, arriving one layer down
    instead.

    They cannot disagree, because `bind` *is* `described` plus three fields. This pins
    that: everything except `description`, `input_schema` and `impl` compares equal.
    """
    from dataclasses import fields

    bound, _ = bind_writer()
    described = binding.described(WRITER_CONNECTOR, WRITER_CONNECTOR.vetted[0])

    from_the_server = {"description", "input_schema", "impl"}
    for field in fields(Tool):
        if field.name in from_the_server:
            continue
        assert getattr(bound[0], field.name) == getattr(described, field.name), field.name

    assert bound[0].effect == described.effect == "write"
    assert bound[0].resources == described.resources


def test_a_described_tool_cannot_be_called():
    """The rule is uniform on purpose. An accessor that hands back a live implementation
    for half the catalogue is one refactor away from being a second route to a tool, and
    `core.broker.call` is the only route to a tool."""
    described = binding.described(WRITER_CONNECTOR, WRITER_CONNECTOR.vetted[0])

    with pytest.raises(RuntimeError, match="descriptor, not an implementation"):
        described.impl(owner="anthropics", repo="sdk")


def test_describing_a_builtin_also_refuses_to_run():
    """`REGISTRY` holds the real thing, which is exactly what must not leave through
    here — so the builtin is replaced on the way past rather than passed along."""
    from carnet import tools as registry

    real = registry.REGISTRY["post_message"]
    described = registry.describe("post_message", TENANT)

    assert described.name == real.name
    assert described.effect == real.effect
    assert described.resources == real.resources
    assert described.impl is not real.impl
    with pytest.raises(RuntimeError, match="descriptor, not an implementation"):
        described.impl(channel="#eng", text="x")


def test_a_connector_cannot_shadow_a_hand_written_tool_through_describe(monkeypatch):
    """`get`'s backstop, at the second accessor. A connector must not be able to take a
    name we wrote — the name in a grant, and in an audit record, has to mean exactly one
    thing. The collision is refused when the connector is saved; checking static first is
    the backstop, and a second accessor that skipped it would be a way round the rule.
    """
    from carnet import storage, tools as registry

    shadow = binding.Connector(
        id="sh",
        launch=binding.StdioLaunch(command=("true",)),
        # `local_name` overridden so the name actually collides. Without it the prefix
        # makes it `sh_message` and the test passes for the wrong reason — which is how
        # the first version of it was written.
        vetted=[binding.Vetted("message", effect="read", local_name="post_message")],
    )
    # Saved past `check_no_collision` deliberately: the point is the backstop, not the
    # guard in front of it.
    monkeypatch.setattr(registry, "check_no_collision", lambda connector: None)
    storage.active().save_connector(TENANT, binding.to_manifest(shadow), actor=TEST_ACTOR)

    described = registry.describe("post_message", TENANT)

    assert described.connector is None
    assert described.effect == registry.REGISTRY["post_message"].effect
    # And in a batch, where the loop is a different one.
    assert registry.describe_all(["post_message"], TENANT)["post_message"].connector is None


def test_describe_answers_where_get_returns_nothing():
    """The distinction the pair exists for: `get` is *can this be called*, `describe` is
    *what would the check read*. A vetted connector tool nothing has bound answers the
    second and not the first, which is the ordinary state of a cold process."""
    from carnet import storage, tools as registry

    storage.active().save_connector(TENANT, binding.to_manifest(WRITER_CONNECTOR), actor=TEST_ACTOR)
    registry.reset_bound(TENANT)

    assert registry.get("wr_add_issue_comment", TENANT) is None
    described = registry.describe("wr_add_issue_comment", TENANT)
    assert described is not None
    assert described.effect == "write"
    assert [r.type for r in described.resources] == ["github.repo"]

    assert registry.describe("wr_no_such_tool", TENANT) is None
