"""Two people, one agent, two credentials — and never each other's.

This is the property step 007 exists for, and it is a *separation* property rather than
a feature one: nothing here asserts that a delegated credential works, only that one
user's call can never go out under another user's credential.

Everything in this file drives fake transports, so nothing spawns a container or
reaches a network. What each fake records is which credential it was built with, which
is the only question that matters here — a session is authenticated at handshake, so
"which session did this call land on" and "whose account did this act as" are the same
question asked twice.
"""

import pytest

from carnet import storage, tools
from carnet.tools import mcp
from carnet.tools.base import Resource
from carnet.tools.mcp import binding
from carnet.tools.mcp.client import SessionPool
from conftest import TEST_ACTOR

# The tenant `isolated_storage` creates. Matched by value, as every other test module
# does, rather than imported — conftest is a fixture file, not a constants module.
TENANT = "t-test"

ADVERTISED = [
    {
        "name": "list_issues",
        "description": "List issues.",
        "inputSchema": {
            "type": "object",
            "properties": {"owner": {"type": "string"}},
            "required": ["owner"],
        },
    }
]

AGENT = {
    "name": "reporter",
    "permissions": {"tools": ["example_list_issues"]},
}


class CredentialEchoTransport:
    """A server that answers every tool call with the credential it was handshaked on.

    Real servers do this implicitly — the account a call acts as is decided by the
    credential the session was opened with, and is invisible from inside the process.
    Making it visible is the whole trick that lets this file assert anything.
    """

    def __init__(self, credential):
        self.credential = credential
        self.closed = False

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
            result = {"content": [{"type": "text", "text": f"acted-as:{self.credential}"}]}
        else:  # pragma: no cover - the subset is three methods
            return {"jsonrpc": "2.0", "id": message["id"], "error": {"message": "?"}}

        return {"jsonrpc": "2.0", "id": message["id"], "result": result}

    def set_protocol_version(self, version):
        """send / set_protocol_version / close — the whole transport interface."""

    def close(self):
        self.closed = True


CONNECTOR = binding.Connector(
    id="example",
    launch=binding.HttpLaunch(
        url="https://api.example.com/mcp/", credential_env="EXAMPLE_TOKEN"
    ),
    vetted=[
        binding.Vetted(
            "list_issues", effect="read", resources=[Resource("github.repo", "owner")]
        )
    ],
)


@pytest.fixture(autouse=True)
def isolated_pool(monkeypatch):
    monkeypatch.setattr(mcp, "POOL", SessionPool())


@pytest.fixture(autouse=True)
def built_transports(monkeypatch):
    """Every session gets a transport tagged with the credential that built it."""
    built = []

    def transport_for(tenant_id, connector, credential):
        transport = CredentialEchoTransport(credential)
        built.append(transport)
        return transport

    monkeypatch.setattr(mcp, "_transport_for", transport_for)
    return built


@pytest.fixture
def vetted(isolated_storage):
    tools.save_connector(TENANT, CONNECTOR, actor=TEST_ACTOR)
    return CONNECTOR


def run_as(credential, delegated=True):
    """What one run does before the model sees a schema: connect what it needs.

    `delegated=True` throughout, because this file is about credentials that are
    somebody's own — and because it means every test here also passes through the
    transport check that refuses delegation on a connector which cannot carry it.
    """
    tools.ensure_available(
        TENANT,
        AGENT,
        credential_for=lambda connector_id, env_var=None, ref=None: (credential, delegated),
    )


def call_as(credential, owner="anthropics"):
    """One tool call, made with this credential. Returns whose account it reached."""
    tool = tools.get("example_list_issues", TENANT)
    assert tool is not None, "the connector's tool should be bound"
    return tool.impl(owner=owner, token=credential)


def acted_as(result):
    """Dig the echoed credential out of a normalized MCP result.

    A lone text block is flattened to `{"text": ...}` by the binding layer, which is
    what a tool result looks like by the time anything above `tools/` sees one.
    """
    return result["text"].removeprefix("acted-as:")


# --- the property -----------------------------------------------------------------


def test_one_user_alone_acts_as_themselves(vetted):
    run_as("priya-token")
    assert acted_as(call_as("priya-token")) == "priya-token"


def test_a_second_user_does_not_inherit_the_first_users_session(vetted):
    """The one that matters, and the one that failed before this step.

    The bound-tool registry is per tenant and shared across runs, so once anybody has
    run the agent its tools are registered — and `ensure_available` used to skip
    connecting entirely on that basis. The second user's credential therefore never got
    a session, and the proxy fell back to the session captured when the *first* user
    connected.

    Priya connects her own account, runs the agent, and reaches Sam's data, because Sam
    happened to run it first that morning. No error, and the audit record says Priya.
    """
    run_as("priya-token")
    call_as("priya-token")

    run_as("sam-token")

    assert acted_as(call_as("sam-token")) == "sam-token"


def test_each_credential_gets_its_own_session(vetted, built_transports):
    """Two credentials, two handshakes. One would mean they are sharing an account."""
    run_as("priya-token")
    run_as("sam-token")

    assert sorted(t.credential for t in built_transports) == ["priya-token", "sam-token"]


def test_a_third_user_arriving_later_still_gets_their_own(vetted):
    for credential in ("priya-token", "sam-token", "dev-token"):
        run_as(credential)

    for credential in ("priya-token", "sam-token", "dev-token"):
        assert acted_as(call_as(credential)) == credential


def test_an_evicted_session_is_rebuilt_under_the_right_credential(vetted):
    """Eviction must cost a handshake, never the truth.

    The pool evicts least-recently-used at a cap that is invented, and idle sessions
    expire on a TTL that is also invented. Both of those are latency decisions — and
    they were only latency decisions once a missing session stopped meaning "use
    somebody else's".
    """
    run_as("priya-token")
    run_as("sam-token")

    mcp.POOL.evict(TENANT, "example", "sam-token")

    assert acted_as(call_as("sam-token")) == "sam-token"


def test_an_evicted_session_is_rebuilt_for_the_first_user_too(vetted):
    """The same, for the credential the connect-time session was built with — the one
    the old fallback would have silently used."""
    run_as("priya-token")
    run_as("sam-token")

    mcp.POOL.evict(TENANT, "example", "priya-token")

    assert acted_as(call_as("priya-token")) == "priya-token"


def test_reconnecting_the_same_credential_reuses_its_session(vetted, built_transports):
    """Separation must not cost a handshake per run. A connector is a container."""
    run_as("priya-token")
    run_as("priya-token")
    run_as("priya-token")

    assert len(built_transports) == 1


# --- a transport that cannot carry a personal credential --------------------------


STDIO_CONNECTOR = binding.Connector(
    id="example",
    launch=binding.StdioLaunch(
        command=("docker", "run", "-i", "--rm", "example/mcp"),
        credential_env="EXAMPLE_TOKEN",
    ),
    vetted=[
        binding.Vetted(
            "list_issues", effect="read", resources=[Resource("github.repo", "owner")]
        )
    ],
)


@pytest.fixture
def vetted_stdio(isolated_storage):
    tools.save_connector(TENANT, STDIO_CONNECTOR, actor=TEST_ACTOR)
    return STDIO_CONNECTOR


def test_a_delegated_credential_on_a_stdio_connector_is_refused(vetted_stdio):
    """One subprocess, one environment, one credential for its whole life — so it
    cannot act as two people.

    The alternative is to ignore the connection and use the shared variable, which is
    the same lie the read path refuses to tell: acting as the operator while the person
    believes it is acting as them. Refused in both places, because it arrives by two
    different routes.
    """
    with pytest.raises(mcp.DelegationUnsupported) as caught:
        run_as("priyas-token", delegated=True)

    message = str(caught.value)
    assert "stdio" in message
    assert "--disconnect-account example" in message


def test_the_refusal_happens_before_anything_is_launched(vetted_stdio, built_transports):
    """Loudly, and before a subprocess exists. A container started under the operator's
    token and then refused would have already been the wrong thing."""
    with pytest.raises(mcp.DelegationUnsupported):
        run_as("priyas-token", delegated=True)

    assert built_transports == []


def test_a_shared_credential_on_a_stdio_connector_is_fine(vetted_stdio):
    """Unchanged behaviour for every deployment that has not connected an account —
    which is the shipped GitHub connector, today."""
    run_as("the-operators-token", delegated=False)

    assert acted_as(call_as("the-operators-token")) == "the-operators-token"


def test_a_delegated_credential_on_an_http_connector_is_allowed(vetted):
    """The other half of the same rule, so the test is about the transport rather than
    about delegation being refused generally."""
    run_as("priyas-token", delegated=True)

    assert acted_as(call_as("priyas-token")) == "priyas-token"


# --- a re-vetted tool rebinds, or the approval is a screen and not a control -------


def test_re_vetting_a_tool_takes_effect_without_a_restart(vetted):
    """`_BOUND` snapshots the descriptor at bind, and the broker reads whose account a
    call acts as off that snapshot. So an admin who re-vetted a tool used to watch
    storage and the admin screen agree with them while every run in the process kept
    the old descriptor until somebody restarted the API — the control stated in one
    place and enforced nowhere.

    Free to fix and therefore inexcusable to leave: `ensure_available` already re-reads
    the manifest every run, so this is a comparison against rows in hand — and it is
    correct across N API processes, where busting a process-local cache would not be.
    """
    run_as("the-operators-token", delegated=False)
    assert tools.get("example_list_issues", TENANT).identity == "service"

    tools.save_connector(
        TENANT,
        binding.Connector(
            id="example",
            launch=CONNECTOR.launch,
            vetted=[
                binding.Vetted(
                    "list_issues",
                    effect="read",
                    identity="user",
                    resources=[Resource("github.repo", "owner")],
                )
            ],
        ),
        actor=TEST_ACTOR,
    )

    run_as("priyas-token", delegated=True)

    assert tools.get("example_list_issues", TENANT).identity == "user"


def test_an_unchanged_vetting_does_not_rebind_on_every_run(vetted, built_transports):
    """The other half, and the reason `_descriptor` compares only fields `bind()`
    copies from the manifest: if a bound tool did not compare equal to the vetting it
    came from, every run would re-handshake forever, which is a worse bug than the one
    above and a quieter one."""
    run_as("the-operators-token", delegated=False)
    built = len(built_transports)

    run_as("the-operators-token", delegated=False)

    assert len(built_transports) == built


def test_a_user_identity_on_a_stdio_connector_cannot_even_be_stored(isolated_storage):
    """The same rule, one layer earlier and on every path.

    `tools.vet_tool` refuses this with a longer sentence, but it is one writer:
    `save_connector` replaces an allowlist wholesale without passing through it, and a
    direct storage write does not either. `Connector.validate()` runs inside
    `from_manifest`, so this is refused at every write **and** every read — which
    matters because the run-path guard below keys off the *session's* credential, and
    a `user` tool's credential is resolved per call, long after any session opened.
    """
    doomed = binding.Connector(
        id="example",
        launch=binding.StdioLaunch(command=("true",), credential_env="EXAMPLE_TOKEN"),
        vetted=[binding.Vetted("list_issues", effect="read", identity="user")],
    )

    with pytest.raises(RuntimeError, match="cannot act as two people"):
        tools.save_connector(TENANT, doomed, actor=TEST_ACTOR)


def test_two_tenants_with_the_same_credential_do_not_share_a_session(vetted):
    """Already true before this step, and asserted here because this file is where
    somebody will look. A session is bound to one tenant's manifest, and handing it to
    another would serve an allowlist that tenant never approved."""
    other = "t-other"
    storage.active().create_tenant(other, "Other")
    tools.save_connector(other, CONNECTOR, actor=TEST_ACTOR)

    run_as("shared-token")
    tools.ensure_available(
        other,
        AGENT,
        credential_for=lambda connector_id, env_var=None, ref=None: ("shared-token", True),
    )

    assert mcp.POOL.get(TENANT, "example", "shared-token") is not (
        mcp.POOL.get(other, "example", "shared-token")
    )
