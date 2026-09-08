"""Tenancy: one customer's data is not another's.

Isolation here is enforced by the *application*, not by the database — every load and
every write filters on a tenant the caller did not choose. That makes these tests the
enforcement record for the property, in the same way test_permissions.py is for scope.

Two halves. This file starts with the shape of tenancy (where it lives, that it cannot
be forged or defaulted) and grows into the isolation assertions as the registries
become loaders.
"""

import dataclasses

import pytest

from carnet import agents, storage, tools
from carnet.core import audit, broker
from carnet.core.context import RunContext
from carnet.core.principal import Principal
from carnet.tools import mcp
from carnet.tools.base import Resource, Tool
from carnet.tools.mcp import Connector, StdioLaunch, Vetted

from conftest import TEST_ACTOR, read_audit, run_context


ACME = "t-acme"
GLOBEX = "t-globex"

AGENT = {
    "name": "test-agent",
    "system": "irrelevant",
    "runtime": "simple",
    "permissions": {
        "tools": ["read_repo"],
        "scope": {"github.repo": {"read": ["octocat/*"]}},
    },
}

READER = Tool(
    name="read_repo",
    description="",
    input_schema={"type": "object", "properties": {"repo": {"type": "string"}}},
    impl=lambda repo: {"repo": repo},
    effect="read",
    resources=[Resource("github.repo", "repo")],
)





# --- where the tenant lives ------------------------------------------------------


def test_a_principal_cannot_be_built_without_a_tenant():
    """No default, deliberately.

    A defaulted tenant on a frozen security dataclass is how a construction site
    quietly ends up in the wrong customer's data. An argument the language demands is
    the only kind nobody forgets.
    """
    with pytest.raises(TypeError):
        Principal.system("cli")

    with pytest.raises(TypeError):
        Principal.user("priya@example.com")

    with pytest.raises(TypeError):
        Principal(kind="system", id="cli")


def test_the_run_derives_its_tenant_from_the_principal():
    ctx = run_context(Principal.user("priya@example.com", ACME))
    assert ctx.tenant_id == ACME


def test_the_run_does_not_store_its_own_tenant():
    """Derived, never stored — the same rule as Connector.read_only.

    A second copy is a value free to disagree with the first, and a disagreement
    about which tenant a run belongs to is a cross-tenant leak rather than an
    inconsistency. This asserts the field does not exist to be set.
    """
    fields = {f.name for f in dataclasses.fields(RunContext)}
    assert "tenant_id" not in fields


def test_two_principals_differ_only_by_tenant():
    acme = Principal.user("priya@example.com", ACME)
    globex = Principal.user("priya@example.com", GLOBEX)

    assert acme != globex
    assert acme.id == globex.id


def test_the_displayed_identity_does_not_include_the_tenant():
    """`str(principal)` is what a refusal message shows a person. The tenant is
    routing and has its own audit column; folding it in would change the wording of
    every denial for no one's benefit."""
    assert str(Principal.system("cli", ACME)) == "system:cli"


# --- the tenant reaches the audit log --------------------------------------------


@pytest.fixture
def stub_reader(monkeypatch):
    monkeypatch.setitem(tools.REGISTRY, READER.name, READER)


def test_audit_records_carry_the_tenant(isolated_storage, stub_reader):
    isolated_storage.create_tenant(ACME, "Acme")
    ctx = run_context(Principal.system("cli", ACME))

    broker.call(ctx, AGENT, "read_repo", {"repo": "octocat/Hello-World"})

    (record,) = read_audit(ACME)
    assert record["tenant_id"] == ACME


def test_a_denial_is_still_attributed_to_its_tenant(isolated_storage, stub_reader):
    """Denials are the records that matter most, and an unattributed one is a record
    nobody can act on."""
    isolated_storage.create_tenant(GLOBEX, "Globex")
    ctx = run_context(Principal.system("cli", GLOBEX))

    broker.call(ctx, AGENT, "read_repo", {"repo": "torvalds/linux"})

    (record,) = read_audit(GLOBEX)
    assert record["decision"] == "deny"
    assert record["tenant_id"] == GLOBEX


def test_one_tenants_audit_is_invisible_to_another(isolated_storage, stub_reader):
    """The read side of the same property. `--runs` for one customer must never show
    another customer's runs, and there is no call that returns all of them."""
    for tenant_id in (ACME, GLOBEX):
        isolated_storage.create_tenant(tenant_id, tenant_id)

    broker.call(
        run_context(Principal.system("cli", ACME)),
        AGENT,
        "read_repo",
        {"repo": "octocat/Hello-World"},
    )

    assert len(read_audit(ACME)) == 1
    assert read_audit(GLOBEX) == []


def test_the_audit_schema_version_records_the_added_field():
    """`v` is present from the first record so a later migration is a filter on a
    field rather than a guess from which keys happen to exist. Adding tenant_id was
    exactly the change it is there to mark; 6 marks `credential`.

    Pinned rather than compared loosely, so widening the record stays a line somebody
    changes on purpose — the table is append-only, and a field added without bumping
    this is a field no future reader can tell apart from a missing one.

    7 marks `acting_for` + `identity_source` (step 033c).
    """
    assert audit.SCHEMA_VERSION == 7


# --- the leak this step exists to close ------------------------------------------
#
# Two customers both run the official GitHub MCP server. One vets reads only; the
# other also vets a write. Nothing exotic — and with a process-global tool registry
# keyed by name, the second customer's vetting would decide what the first customer's
# agents can call.


ADVERTISED = [
    {
        "name": "list_issues",
        "description": "List issues in a GitHub repository.",
        "inputSchema": {
            "type": "object",
            "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}},
            "required": ["owner", "repo"],
        },
    },
    {
        "name": "add_issue_comment",
        "description": "Comment on an issue.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["owner", "repo", "body"],
        },
    },
]

REPO = Resource("github.repo", ["owner", "repo"], template="{owner}/{repo}")


class FakeTransport:
    """A scripted server, so these tests spawn nothing."""

    def __init__(self):
        self.closed = False

    def send(self, message):
        if "id" not in message:
            return None
        method = message["method"]
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "github-mcp-server", "version": "1.8.0"},
            }
        elif method == "tools/list":
            result = {"tools": ADVERTISED}
        else:
            result = {"content": [{"type": "text", "text": "{}"}]}
        return {"jsonrpc": "2.0", "id": message["id"], "result": result}

    def set_protocol_version(self, version):
        """Part of the transport interface: send / set_protocol_version / close."""

    def close(self):
        self.closed = True


def _github(*vetted) -> Connector:
    return Connector(
        id="github-mcp",
        launch=StdioLaunch(command=("true",), credential_env="GITHUB_TOKEN"),
        vetted=list(vetted),
    )


READ_ONLY = _github(Vetted("list_issues", effect="read", resources=[REPO]))

READ_AND_WRITE = _github(
    Vetted("list_issues", effect="read", resources=[REPO]),
    Vetted("add_issue_comment", effect="write", resources=[REPO]),
)


@pytest.fixture
def two_tenants(isolated_storage):
    """Acme vets reads only. Globex vets the same server, plus a write."""
    for tenant_id in (ACME, GLOBEX):
        isolated_storage.create_tenant(tenant_id, tenant_id)

    tools.save_connector(ACME, READ_ONLY, actor=TEST_ACTOR)
    tools.save_connector(GLOBEX, READ_AND_WRITE, actor=TEST_ACTOR)


def _bind(tenant_id, connector):
    bound, _ = mcp.connect(tenant_id, connector, None, transport=FakeTransport())
    for tool in bound:
        tools.register(tenant_id, tool)


def test_vetting_is_per_tenant_before_anything_connects(two_tenants):
    assert "github_mcp_add_issue_comment" not in tools.known_names(ACME)
    assert "github_mcp_add_issue_comment" in tools.known_names(GLOBEX)


def test_one_tenants_vetting_does_not_make_a_tool_callable_for_another(two_tenants):
    """The leak, stated directly.

    Globex vetted a write. Acme did not. After both have bound, the write must not be
    callable for Acme — not merely ungranted, but absent from its registry entirely.
    """
    _bind(GLOBEX, READ_AND_WRITE)
    _bind(ACME, READ_ONLY)

    assert tools.get("github_mcp_add_issue_comment", GLOBEX) is not None
    assert tools.get("github_mcp_add_issue_comment", ACME) is None


def test_the_broker_refuses_a_tool_the_calling_tenant_never_vetted(two_tenants):
    """And the refusal is the ordinary unregistered-tool one, because from Acme's
    side that is exactly what it is. A tool we cannot describe is a tool we cannot
    scope, so it is refused before any resource check runs."""
    _bind(GLOBEX, READ_AND_WRITE)
    _bind(ACME, READ_ONLY)

    agent = {
        "name": "over-reacher",
        "permissions": {
            # Granted in config, and still not callable: the grant names a tool this
            # tenant's connectors do not contribute.
            "tools": ["github_mcp_add_issue_comment"],
            "scope": {"github.repo": {"write": ["octocat/*"]}},
        },
    }
    ctx = run_context(Principal.system("cli", ACME))

    result = broker.call(
        ctx,
        agent,
        "github_mcp_add_issue_comment",
        {"owner": "octocat", "repo": "Hello-World", "body": "hi"},
    )

    assert result.get("denied_by") == "broker"
    assert "not a registered tool" in result["error"]

    (record,) = read_audit(ACME)
    assert record["decision"] == "deny"
    assert record["tenant_id"] == ACME


def test_the_same_tool_name_binds_independently_for_each_tenant(two_tenants):
    """`github_mcp_list_issues` exists for both, and they are not the same object —
    each was built from its own tenant's manifest."""
    _bind(ACME, READ_ONLY)
    _bind(GLOBEX, READ_AND_WRITE)

    acme = tools.get("github_mcp_list_issues", ACME)
    globex = tools.get("github_mcp_list_issues", GLOBEX)

    assert acme is not None and globex is not None
    assert acme is not globex


def test_read_only_mode_follows_each_tenants_own_vetting(two_tenants):
    """Derived per tenant, like everything else about a connector. Acme vetted no
    write, so its server is launched read-only; Globex's is not."""
    assert mcp.get_connector(ACME, "github-mcp").read_only is True
    assert mcp.get_connector(GLOBEX, "github-mcp").read_only is False


def test_a_connector_round_trips_without_read_only_being_stored(two_tenants):
    """`read_only` is derived and must stay derived. Nothing writes it down, and it
    still comes back correct — which is the whole argument for deriving it."""
    stored = storage.active().get_connector(ACME, "github-mcp")

    assert "read_only" not in stored
    assert mcp.from_manifest(stored).read_only is True


def test_sessions_are_not_shared_between_tenants(two_tenants):
    """Even with an identical credential. A live session is bound to the manifest it
    was bound against, and handing it to another tenant would serve them an allowlist
    they never approved."""
    mcp.connect(ACME, READ_ONLY, "same-token", transport=FakeTransport())
    mcp.connect(GLOBEX, READ_AND_WRITE, "same-token", transport=FakeTransport())

    assert mcp.POOL.get(ACME, "github-mcp", "same-token") is not None
    assert mcp.POOL.get(GLOBEX, "github-mcp", "same-token") is not None
    assert mcp.POOL.get(ACME, "github-mcp", "same-token") is not mcp.POOL.get(
        GLOBEX, "github-mcp", "same-token"
    )


def test_deleting_a_connector_invalidates_only_that_tenants_agents():
    """The load-time failure that write-time validation cannot prevent: the agent row
    never changed, the connector under it did."""
    store = storage.active()
    for tenant_id in (ACME, GLOBEX):
        store.create_tenant(tenant_id, tenant_id)
        tools.save_connector(tenant_id, READ_ONLY, actor=TEST_ACTOR)

    reader = {
        "name": "reader",
        "permissions": {
            "tools": ["github_mcp_list_issues"],
            "scope": {"github.repo": {"read": ["octocat/*"]}},
        },
    }
    for tenant_id in (ACME, GLOBEX):
        agents.save(tenant_id, reader, actor="system:cli")

    store.delete_connector(ACME, "github-mcp", actor=TEST_ACTOR)

    with pytest.raises(agents.InvalidAgentError, match="not a registered tool"):
        agents.get(ACME, "reader")

    assert agents.get(GLOBEX, "reader") is not None


# --- the retention window, step 018 --------------------------------------------------


def _retention(monkeypatch, value):
    from carnet import config

    if value is None:
        monkeypatch.delenv("CARNET_RETENTION_DAYS", raising=False)
    else:
        monkeypatch.setenv("CARNET_RETENTION_DAYS", value)
    return config._retention_days()


def test_no_retention_window_means_keep_everything(monkeypatch):
    """Today's behaviour is the default, so upgrading to 018 destroys nothing until
    somebody decides it should."""
    assert _retention(monkeypatch, None) is None
    assert _retention(monkeypatch, "") is None
    assert _retention(monkeypatch, "   ") is None


def test_a_retention_window_is_a_number_of_days(monkeypatch):
    assert _retention(monkeypatch, "30") == 30
    assert _retention(monkeypatch, " 90 ") == 90


def test_zero_days_is_refused_rather_than_read_as_off(monkeypatch):
    """The one input worth being strict about. `RETENTION_DAYS=0` reads to a person as
    "disabled" and means "everything older than right now", which is every record in
    the table — two plausible readings of one value, one of them irreversible."""
    import pytest as _pytest

    with _pytest.raises(ValueError, match="at least 1"):
        _retention(monkeypatch, "0")

    with _pytest.raises(ValueError, match="at least 1"):
        _retention(monkeypatch, "-7")


def test_a_retention_window_that_is_not_a_number_says_so(monkeypatch):
    import pytest as _pytest

    with _pytest.raises(ValueError, match="whole number of days"):
        _retention(monkeypatch, "thirty")


# --- the retired AGENT_RUNTIME_ prefix is refused, not ignored -----------------------


def test_a_retired_env_prefix_is_refused_with_its_replacement_named():
    """The rename (033's decision 10) broke `AGENT_RUNTIME_*` cleanly. A retired
    variable that is silently skipped is configuration that silently stops applying,
    so the import-time check names each offending variable and its replacement."""
    import pytest as _pytest

    from carnet import config

    config._refuse_retired_prefix({"CARNET_TENANT": "acme", "PATH": "/usr/bin"})

    with _pytest.raises(ValueError, match="AGENT_RUNTIME_TENANT is now CARNET_TENANT"):
        config._refuse_retired_prefix({"AGENT_RUNTIME_TENANT": "acme"})

    with _pytest.raises(ValueError, match="docs/UPGRADING.md"):
        config._refuse_retired_prefix({"AGENT_RUNTIME_DATABASE_URL": "postgresql://x"})
