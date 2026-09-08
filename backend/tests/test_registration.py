"""Connector registration — the step, not the methods.

The per-method behaviour is asserted where it belongs: storage in
`test_storage_contract.py` (both stores), the egress rules in `test_egress.py`, binding
in `test_mcp.py`. What is here is the five properties plan 012 named under
"Verification", each of which spans layers and none of which is a test of one function.

Everything runs against a fake transport. No subprocess, no Docker, no network — the
seam in `tools/mcp/transport.py` exists partly so this file can be honest about that.
"""

import pytest

from carnet import agents, storage, tools
from carnet.tools import mcp
from carnet.tools.base import Resource
from carnet.tools.mcp import discovery

from conftest import TEST_ACTOR, TEST_HOST, TEST_TENANT

ALICE = "user:u_alice"
URL = f"https://{TEST_HOST}/mcp"

# What a Jira MCP server advertises, near enough. `create_issue` is the write worth
# scoping, `search_issues` is the read, and `delete_project` is the one nobody vets —
# the case the whole allowlist exists for.
ADVERTISED = [
    {
        "name": "create_issue",
        "description": "Create an issue in a Jira project.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "projectKey": {"type": "string"},
                "summary": {"type": "string"},
                "description": {"type": "string"},
            },
            "required": ["projectKey", "summary"],
        },
    },
    {
        "name": "search_issues",
        "description": "Search issues with JQL.",
        "inputSchema": {
            "type": "object",
            "properties": {"jql": {"type": "string"}},
            "required": ["jql"],
        },
    },
    {
        "name": "delete_project",
        "description": "Delete a Jira project and everything in it.",
        "inputSchema": {
            "type": "object",
            "properties": {"projectKey": {"type": "string"}},
            "required": ["projectKey"],
        },
    },
]


class FakeServer:
    """A scripted MCP server, with a version it can be asked to change.

    Its own class rather than reusing `test_mcp.FakeTransport` because the properties
    here need the two things that one holds fixed: which tools are advertised, and what
    `serverInfo` says. Re-vetting against a server that has *moved* is the whole of
    decision 6, and it cannot be expressed against a transport whose advertisement is a
    constant.
    """

    def __init__(self, tools_=None, name="jira-mcp-server", version="2.3.0"):
        self.tools = ADVERTISED if tools_ is None else tools_
        self.name = name
        self.version = version
        self.closed = False

    def send(self, message):
        if "id" not in message:
            return None

        method = message["method"]
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": self.name, "version": self.version},
            }
        elif method == "tools/list":
            result = {"tools": self.tools}
        else:
            result = {"content": [{"type": "text", "text": "{}"}]}

        return {"jsonrpc": "2.0", "id": message["id"], "result": result}

    def set_protocol_version(self, version):
        pass

    def close(self):
        self.closed = True


@pytest.fixture
def registered(isolated_storage):
    """A connector registered and nothing vetted — the state `--add-connector` leaves.

    The intermediate state is worth having a fixture for, because it is the one plan
    012's decision 4 is *about*: registering a server and approving one of its tools are
    two commands because they are two judgments made at two times.
    """
    tools.register_connector(
        TEST_TENANT,
        "jira",
        url=URL,
        credential_env="JIRA_TOKEN",
        description="Jira, issues only",
        actor=ALICE,
    )
    return "jira"


def _vet(remote_name, effect="read", resources=(), server=None, **kwargs):
    return tools.vet_tool(
        TEST_TENANT,
        "jira",
        remote_name,
        effect=effect,
        resources=resources,
        actor=ALICE,
        transport=server or FakeServer(),
        **kwargs,
    )


PROJECT = Resource("jira.project", "projectKey")


# --- what a vetted tool keeps out of the audit log — step 045c ---------------------
#
# `--redact-arg` is deliberately **not** REST-only: an MCP tool whose argument is
# somebody's free text has exactly the problem a model connector's `messages` has, and
# the rule that a redaction must name a real argument is checked against whichever
# schema the connector kind has — discovered here, authored on a REST connector.


def test_an_mcp_tool_can_be_vetted_with_a_redaction(registered):
    """The discovered-schema half. `summary` is free text the vendor advertises, and a
    tenant that does not want it in an append-only log says so at the form."""
    _vet("create_issue", effect="write", resources=(PROJECT,),
         redact_args=("summary", "description"))

    (vetted,) = [
        v for v in mcp.get_connector(TEST_TENANT, "jira").vetted
        if v.remote_name == "create_issue"
    ]
    assert vetted.redact_args == ("summary", "description")


def test_a_redaction_is_checked_against_the_schema_the_server_advertises(registered):
    """Refused at the form, against the *server's* schema rather than a stored copy —
    which is what makes this the same check on both connector kinds. The failure it
    prevents is silent in the reassuring direction: the approval would read as hiding a
    value the log holds in the clear."""
    with pytest.raises(tools.RegistrationRefused, match="sumary"):
        _vet("create_issue", effect="write", resources=(PROJECT,),
             redact_args=("sumary",))


def test_a_vendor_renaming_a_redacted_argument_fails_at_bind(registered):
    """The drift half, which only the MCP path has: `resources` catches a renamed
    argument at bind and so must a redaction, or the rename quietly unhooks the
    redaction from the argument it was written against and the prompts start landing
    in the clear with nothing said."""
    _vet("search_issues", redact_args=("jql",))

    moved = [
        dict(spec, inputSchema={"type": "object", "properties": {"query": {"type": "string"}}})
        if spec["name"] == "search_issues" else spec
        for spec in ADVERTISED
    ]
    connector = mcp.get_connector(TEST_TENANT, "jira")
    with pytest.raises(RuntimeError, match="redacts argument 'jql'"):
        mcp.bind(connector, moved, lambda *a, **k: None)


# --- 1. a connector registered through the CLI reaches the form --------------------


def test_a_registered_connector_reaches_the_agent_form(registered):
    """The step's first verification, and the only one that spans the whole product.

    Register, vet one tool, then ask the two questions a form asks: *what may I grant*
    (the catalogue) and *is this config legal* (`agents.validate`). A tool that reaches
    the first and not the second is a tool the wizard offers and refuses to save.

    This is the property that makes the premise true. Before this step a tenant with no
    shipped connector got a wizard saying *"your organisation has not vetted any tools
    yet"* and could only create agents that reach nothing — self-serve agent creation is
    worth exactly what the connector onboarding behind it is worth, and that was zero.
    """
    _vet("create_issue", effect="write", resources=(PROJECT,))

    catalogue = tools.catalogue(TEST_TENANT)
    jira = next(group for group in catalogue if group["id"] == "jira")
    assert [entry["name"] for entry in jira["tools"]] == ["jira_create_issue"]

    entry = jira["tools"][0]
    assert entry["effect"] == "write"
    assert entry["resources"] == [{"type": "jira.project"}]
    # The vendor's words, copied at vetting time rather than restated by us.
    assert entry["description"] == "Create an issue in a Jira project."

    # The name is known to agent validation before anybody connects, which is what lets
    # a grant naming it be checked when the agent is saved rather than at the first run.
    assert "jira_create_issue" in tools.known_names(TEST_TENANT)

    # And the scope question the form derives. `agents.validate` cross-checks tools
    # against scope in both directions, so this passing means the wizard's derivation
    # has something real to derive from.
    agents.validate(
        TEST_TENANT,
        {
            "name": "ticket-filer",
            "system": "You file tickets.",
            "permissions": {
                "tools": ["jira_create_issue"],
                "scope": {"jira.project": {"write": ["ACME"]}},
            },
        },
    )


def test_an_agent_granting_an_unvetted_tool_is_still_refused(registered):
    """The other direction, and the one that says the allowlist is the control.

    `delete_project` is advertised by the same server, on the same connection, behind
    the same credential. Nobody vetted it, so no agent in this tenant can name it — and
    the refusal comes from `known_names`, which is built from the manifest rather than
    from anything the server said.
    """
    _vet("search_issues")

    assert "jira_delete_project" not in tools.known_names(TEST_TENANT)

    with pytest.raises(agents.InvalidAgentError):
        agents.validate(
            TEST_TENANT,
            {
                "name": "wrecker",
                "system": "…",
                "permissions": {"tools": ["jira_delete_project"], "scope": {}},
            },
        )


# --- 2. a vetted write with no resource is impossible -------------------------------


def test_a_write_with_no_resource_is_refused_at_the_storage_boundary(registered):
    """Not "the CLI asks for one" — **the row is refused**.

    Asserted against `storage.active()` directly, bypassing `tools.vet_tool` and every
    check it makes, because the property is that an interface which forgets *cannot*
    create the hole. A test that went through the CLI would only prove the CLI
    remembers.

    A write to something policy cannot name is unscopeable: the broker has nothing to
    check the call against, so the tool reads as constrained in review and is not.
    """
    with pytest.raises(storage.StorageError, match="unscopeable"):
        storage.active().vet_tool(
            TEST_TENANT,
            "jira",
            {"remote_name": "create_issue", "effect": "write", "resources": []},
            actor=ALICE,
        )

    assert storage.active().get_connector(TEST_TENANT, "jira")["vetted"] == []


def test_the_same_write_is_refused_through_the_wholesale_save(registered):
    """The other write path into the same table, refused the same way.

    Two paths reach `vetted_tools` — `save_connector` wholesale and `vet_tool` one at a
    time — and a rule enforced on one of them is a rule with a door beside it. Both call
    `normalize_vetted_tool`, which is why one check covers both.
    """
    with pytest.raises(storage.StorageError, match="unscopeable"):
        storage.active().save_connector(
            TEST_TENANT,
            {
                "id": "jira",
                "launch": {"kind": "http", "url": URL},
                "vetted": [{"remote_name": "create_issue", "effect": "write"}],
            },
            actor=ALICE,
        )


def test_a_read_with_no_resource_is_fine(registered):
    """A read that touches nothing policy needs to name is legal and correct.

    A PDF extractor takes bytes and returns text; it contributes no scope row and the
    form asks nothing about it. The rule is about writes precisely because the asymmetry
    is real — an unscoped read is bounded by what it can see, an unscoped write is not.
    """
    _vet("search_issues")

    entry = tools.catalogue(TEST_TENANT)[1]["tools"][0]
    assert entry["effect"] == "read"
    assert entry["resources"] == []


# --- 3. a renamed argument is caught, and says what changed -------------------------


def test_a_renamed_argument_names_the_version_and_the_argument(registered):
    """Vet against one advertisement, discover against a second, and read the refusal.

    `bind()` has raised on this since step 003 and `validate()` has raised on the
    argument half since then too — both fail closed, and neither could say what the tool
    had been vetted *against*. So an operator saw "this server does not advertise
    `create_issue`" with nothing anywhere answering "did the server change, or did
    somebody edit the manifest".

    Migration 023 is that answer, and this is the test that it arrives in the sentence a
    person actually reads.
    """
    _vet(
        "create_issue",
        effect="write",
        resources=(PROJECT,),
        server=FakeServer(version="2.3.0"),
    )

    # v3: `projectKey` became `project`.
    moved = [
        {
            **ADVERTISED[0],
            "inputSchema": {
                "type": "object",
                "properties": {"project": {"type": "string"}, "summary": {"type": "string"}},
                "required": ["project", "summary"],
            },
        },
        ADVERTISED[1],
    ]

    connector = mcp.get_connector(TEST_TENANT, "jira")
    findings = discovery.review(
        connector, moved, _vetting()
    )
    refusals = discovery.refusals(findings)

    assert len(refusals) == 1
    message = refusals[0]["message"]

    # The argument that moved…
    assert "'projectKey'" in message
    # …the version it was vetted against, which is the half that did not exist before…
    assert "jira-mcp-server v2.3.0" in message
    # …what the tool would silently stop constraining…
    assert "jira.project" in message
    # …and what it takes now, so the fix does not need a second command.
    assert "project" in message


def test_a_vanished_tool_is_refused_and_says_what_it_was_vetted_against(registered):
    _vet("search_issues", server=FakeServer(version="2.3.0"))

    connector = mcp.get_connector(TEST_TENANT, "jira")
    refusals = discovery.refusals(
        discovery.review(connector, [ADVERTISED[0]], _vetting())
    )

    assert len(refusals) == 1
    assert refusals[0]["kind"] == "gone"
    assert "jira-mcp-server v2.3.0" in refusals[0]["message"]


def test_a_new_optional_field_is_reported_and_not_refused(registered):
    """Decision 6's middle row. Servers add fields constantly, and a control that
    refused on every one is a control nobody can live with."""
    _vet("create_issue", effect="write", resources=(PROJECT,))

    grew = [
        {
            **ADVERTISED[0],
            "inputSchema": {
                "type": "object",
                "properties": {
                    **ADVERTISED[0]["inputSchema"]["properties"],
                    "labels": {"type": "array"},
                },
                "required": ["projectKey", "summary"],
            },
        }
    ]

    connector = mcp.get_connector(TEST_TENANT, "jira")
    findings = discovery.review(connector, grew, _vetting())

    assert discovery.refusals(findings) == []
    changed = next(f for f in findings if f["kind"] == "schema-changed")
    assert changed["arguments"] == ["labels"]
    assert "gained labels" in changed["message"]


def test_new_tools_are_reported_and_never_adopted(registered):
    """Decision 6's third row — the one an implementation gets wrong by being helpful.

    A discovery that added newly-advertised tools to the allowlist would mean a server
    could grant itself capabilities by shipping a release, which is the entire property
    the allowlist exists to deny.
    """
    _vet("search_issues")

    connector = mcp.get_connector(TEST_TENANT, "jira")
    findings = discovery.review(connector, ADVERTISED, _vetting())

    reported = next(f for f in findings if f["kind"] == "not-vetted")
    assert set(reported["arguments"]) == {"create_issue", "delete_project"}
    assert reported["severity"] == discovery.REPORT

    # And nothing was adopted.
    assert tools.known_names(TEST_TENANT) & {"jira_create_issue", "jira_delete_project"} == set()


def test_vetting_a_tenth_tool_is_refused_while_the_first_nine_have_drifted(registered):
    """Drift blocks new vetting, which is the part that is easy to leave out.

    Approving a new tool on a manifest that no longer binds would leave an operator
    finding out at the next run of an unrelated agent — and by then the command that
    would have told them has scrolled away.
    """
    _vet("create_issue", effect="write", resources=(PROJECT,))

    gone = FakeServer(tools_=[ADVERTISED[1]], version="3.0.0")
    with pytest.raises(tools.RegistrationRefused, match="no longer matches"):
        _vet("search_issues", server=gone)

    # And the tenth was not written.
    assert [v.remote_name for v in mcp.get_connector(TEST_TENANT, "jira").vetted] == [
        "create_issue"
    ]


# --- 4. a host not on the allowlist is never dialled --------------------------------


def test_an_unapproved_host_is_never_dialled(isolated_storage, monkeypatch):
    """Asserted by failing if **anything** reaches the transport.

    The same shape as `test_the_catalogue_needs_no_server`, which is the assertion that
    has held since 10b: a check that only asserts on the exception can pass while the
    connection was opened and then refused, and *whether we dialled* is the entire
    question an SSRF control answers.
    """
    for name in ("HttpTransport", "StdioTransport"):
        # `built=name` binds this iteration's value. A bare closure over `name` reads it
        # at call time, so whichever transport fired, the failure named the last one.
        monkeypatch.setattr(
            mcp,
            name,
            lambda *a, built=name, **kw: pytest.fail(
                f"built a {built} for an unapproved host"
            ),
        )

    storage.active().save_connector(
        TEST_TENANT,
        {
            "id": "elsewhere",
            "launch": {"kind": "http", "url": "https://not-approved.example.com/mcp"},
            "vetted": [{"remote_name": "search_issues", "effect": "read"}],
        },
        actor=TEST_ACTOR,
    )
    connector = mcp.get_connector(TEST_TENANT, "elsewhere")

    with pytest.raises(mcp.EgressRefused, match="not approved the host"):
        mcp._transport_for(TEST_TENANT, connector, None)


def test_registration_refuses_an_unapproved_host_before_the_row_exists(isolated_storage):
    """The cheaper refusal, at the moment a person still has the command in their shell.

    The dial-time check is the load-bearing one — a stored row outlives the moment it
    was written — but a refusal three days later at the first run is a mystery, and this
    one is not.
    """
    with pytest.raises(mcp.EgressRefused):
        tools.register_connector(
            TEST_TENANT,
            "elsewhere",
            url="https://not-approved.example.com/mcp",
            actor=ALICE,
        )

    assert storage.active().get_connector(TEST_TENANT, "elsewhere") is None


def test_revoking_a_host_stops_a_connector_that_was_already_registered(registered):
    """The reason the check is at dial time and not only at registration.

    The connector keeps its row and its vetting — deleting it would destroy the record
    of which tools somebody approved — and stops connecting.
    """
    _vet("search_issues")
    connector = mcp.get_connector(TEST_TENANT, "jira")

    storage.active().revoke_host(TEST_TENANT, TEST_HOST, actor=ALICE)

    with pytest.raises(mcp.EgressRefused):
        mcp._transport_for(TEST_TENANT, connector, None)

    # Still registered, still vetted, still in the catalogue.
    assert [v.remote_name for v in mcp.get_connector(TEST_TENANT, "jira").vetted] == [
        "search_issues"
    ]


# --- 5. nine vetted tools survive vetting a tenth ------------------------------------


def test_nine_vetted_tools_survive_vetting_a_tenth(registered):
    """The property `save_connector` cannot have, and the reason `vet_tool` exists.

    `save_connector` replaces the allowlist wholesale — right for `--seed`, where the
    module *is* the allowlist, and data loss here: an admin who has approved nine tools
    and is looking at the tenth must not lose nine by getting the command wrong.
    """
    advertised = [
        {
            "name": f"tool_{n}",
            "description": f"Tool {n}.",
            "inputSchema": {"type": "object", "properties": {"projectKey": {"type": "string"}}},
        }
        for n in range(10)
    ]
    server = FakeServer(tools_=advertised)

    for n in range(9):
        _vet(f"tool_{n}", server=server)

    assert len(mcp.get_connector(TEST_TENANT, "jira").vetted) == 9

    _vet("tool_9", effect="write", resources=(PROJECT,), server=server)

    vetted = mcp.get_connector(TEST_TENANT, "jira").vetted
    assert [v.remote_name for v in vetted] == [f"tool_{n}" for n in range(10)]
    # And each keeps its own review record rather than being re-stamped by the tenth.
    assert len(storage.active().load_vetting_record(TEST_TENANT)) == 10


def test_re_vetting_replaces_one_tool_and_leaves_the_rest(registered):
    """Editing an annotation in place is out of scope; re-vetting is how it is done.

    The review record is overwritten by a *new review* rather than edited underneath the
    old one's name — which is why `vetted_at` is refreshed rather than kept.
    """
    _vet("search_issues", note="first pass")
    _vet("create_issue", effect="write", resources=(PROJECT,))

    _vet("search_issues", note="reviewed again by security")

    vetted = {v.remote_name: v for v in mcp.get_connector(TEST_TENANT, "jira").vetted}
    assert len(vetted) == 2
    assert vetted["search_issues"].note == "reviewed again by security"
    assert vetted["create_issue"].effect == "write"


# --- whose account: the vetted identity (033a) ---------------------------------------


def test_vetting_records_the_identity_and_the_catalogue_shows_it(registered):
    """`identity` is the approval's third judgment, beside `effect` and `resources`,
    and it lands where they do: in the descriptor, readable with the server stopped."""
    recorded = _vet("search_issues", identity="user")

    assert recorded["identity"] == "user"
    connector = mcp.get_connector(TEST_TENANT, "jira")
    assert connector.vetted[0].identity == "user"

    entries = {
        tool["name"]: tool
        for group in tools.catalogue(TEST_TENANT)
        for tool in group["tools"]
    }
    assert entries["jira_search_issues"]["identity"] == "user"


def test_an_unstated_identity_is_service(registered):
    """The default is the break docs/UPGRADING.md states: the shared credential, which
    is what every headless caller always got."""
    assert _vet("search_issues")["identity"] == "service"


def test_a_user_identity_needs_a_transport_that_can_carry_one(isolated_storage):
    """`identity: user` on a stdio connector is refused at vet time — where the person
    deciding is still at the form — rather than surfacing at the first run. A stdio
    server takes its credential from the environment at launch and holds it for the
    process's life, so one server cannot act as two people."""
    tools.save_connector(
        TEST_TENANT,
        mcp.Connector(id="local", launch=mcp.StdioLaunch(command=("true",))),
        actor=ALICE,
    )

    with pytest.raises(tools.RegistrationRefused, match="cannot act as the person"):
        tools.vet_tool(
            TEST_TENANT,
            "local",
            "search_issues",
            effect="read",
            identity="user",
            actor=ALICE,
            transport=FakeServer(),
        )


# --- the review record, which finally has a writer -----------------------------------


def test_vetting_records_who_when_and_what_it_was_vetted_against(registered):
    """`vetted_by` has been `''` on every row since migration 018 because nothing vets.

    This is the thing that vets. All four columns are the database's — a caller cannot
    pass them in, because there is no key on a `Vetted` they would be read from.
    """
    _vet("search_issues", server=FakeServer(name="jira-mcp-server", version="2.3.0"))

    record = storage.active().load_vetting_record(TEST_TENANT)
    assert len(record) == 1
    assert record[0] == {
        "connector_id": "jira",
        "remote_name": "search_issues",
        "vetted_by": ALICE,
        "vetted_at": record[0]["vetted_at"],
        "server_name": "jira-mcp-server",
        "server_version": "2.3.0",
        # The baseline a later --discover diffs against. Names only.
        "vetted_arguments": ["jql"],
    }
    assert record[0]["vetted_at"]


def test_a_manifest_cannot_assert_who_vetted_a_tool(registered):
    """The 010b decision, still true with a writer in place.

    A `vetted_by` arriving inside a manifest is a claim that Alice approved this, made by
    code that is not Alice. The keys are simply not read — asserted by writing them and
    finding the actor unchanged rather than by asserting they raise, because dropping and
    refusing look the same from the outside and only one of them is what happens.

    **Two independent things enforce this and neither alone is load-bearing**, which was
    established by mutation rather than by reading: `normalize_vetted_tool` drops unknown
    keys, and both stores write `vetted_by` from the `actor` parameter without consulting
    the row. Breaking either one on its own leaves this test passing. That is defence in
    depth rather than redundancy, and it is worth knowing when changing either — the
    first regression here will be silent.
    """
    storage.active().save_connector(
        TEST_TENANT,
        {
            "id": "jira",
            "launch": {"kind": "http", "url": URL},
            "vetted": [
                {
                    "remote_name": "search_issues",
                    "effect": "read",
                    "vetted_by": "user:u_somebody_else",
                    "server_version": "99.0",
                }
            ],
        },
        actor=ALICE,
    )

    record = storage.active().load_vetting_record(TEST_TENANT)[0]
    assert record["vetted_by"] == ALICE
    assert record["server_version"] == ""


def test_the_catalogue_says_what_a_tool_was_vetted_against(registered):
    _vet("search_issues", server=FakeServer(version="2.3.0"))

    entry = tools.catalogue(TEST_TENANT)[1]["tools"][0]
    assert entry["vetted_by"] == ALICE
    assert entry["server_name"] == "jira-mcp-server"
    assert entry["server_version"] == "2.3.0"


# --- registration itself --------------------------------------------------------------


def test_registering_vets_nothing(registered):
    """Decision 4's shape: the row exists and contributes no tools.

    The correct intermediate state rather than a hole — `bind()` over an empty manifest
    yields no tools and excludes everything the server advertises.
    """
    connector = mcp.get_connector(TEST_TENANT, "jira")
    assert connector.vetted == ()
    assert connector.declared_names() == set()
    assert tools.known_names(TEST_TENANT) == frozenset(tools.REGISTRY)

    bound, excluded = mcp.bind(connector, ADVERTISED, lambda *a: None)
    assert bound == []
    assert excluded == ["create_issue", "delete_project", "search_issues"]


def test_registering_the_same_id_twice_is_refused_rather_than_replacing(registered):
    """The one line of SQL between `create_connector` and `save_connector`.

    An upsert here would let a mistyped second `--add-connector` wipe nine approved tools
    with a command whose entire visible effect is "the row exists".
    """
    _vet("search_issues")

    with pytest.raises(storage.ConnectorExistsError):
        tools.register_connector(
            TEST_TENANT, "jira", url=URL, actor=ALICE
        )

    assert len(mcp.get_connector(TEST_TENANT, "jira").vetted) == 1


def test_a_customer_connector_may_not_speak_stdio(isolated_storage):
    """Decision 2, and the refusal names the way out.

    A customer whose server speaks stdio does not have to rewrite it — they have to host
    it. A refusal that only says no would send somebody to the source.
    """
    with pytest.raises(tools.RegistrationRefused) as raised:
        tools.register_connector(TEST_TENANT, "jira", url="", actor=ALICE)

    message = str(raised.value)
    assert "cannot act as two people" in message
    assert "host it yourself" in message
    assert "mcp-proxy" in message
    # And the distinction that keeps the shipped connector working.
    assert "provenance" in message


def test_the_shipped_stdio_connector_still_works(isolated_storage, vetted_github):
    """`--seed`'s connectors keep stdio. The distinction is provenance, not transport.

    This is the other half of the decision above, and it is worth an assertion because
    "customer connectors are HTTP-only" is one sentence away from "connectors are
    HTTP-only", which would break the one worked example this repository ships.
    """
    connector = mcp.get_connector(TEST_TENANT, "github-mcp")
    assert connector.transport_kind == "stdio"
    assert connector.declared_names()


def test_vetting_a_tool_the_server_does_not_advertise_is_refused(registered):
    with pytest.raises(tools.RegistrationRefused, match="does not advertise"):
        _vet("invent_a_tool")


def test_vetting_names_an_argument_the_schema_does_not_have(registered):
    """`validation.py`'s rule, fired at the moment somebody typed the argument name.

    The difference between a typo and an outage: without discovery this is a guess that
    `bind()` rejects at the first run of whichever agent happens to need it.
    """
    with pytest.raises(RuntimeError, match="not in its input_schema"):
        _vet(
            "create_issue",
            effect="write",
            resources=(Resource("jira.project", "project_key"),),
        )

    assert mcp.get_connector(TEST_TENANT, "jira").vetted == ()


def test_a_vetted_tool_may_not_shadow_a_hand_written_one(registered):
    """The collision check, on the incremental path as well as the wholesale one.

    Extracted from `save_connector` in this step precisely so `--vet` is subject to it —
    a check that lived only in the wholesale save is one the one-at-a-time path silently
    skips, and `post_message` meaning two things is a grant nobody can read.
    """
    with pytest.raises(RuntimeError, match="collide with hand-written tools"):
        _vet("search_issues", local_name="post_message")


def _vetting():
    return {
        (row["connector_id"], row["remote_name"]): row
        for row in storage.active().load_vetting_record(TEST_TENANT)
    }
