"""The credential lookup, and the shape it has before it needs it.

Nothing here reaches a real secret store — the point is the *key*. A credential is
looked up by (tool, principal) because there are two kinds and only one of them is a
property of the tool alone: a shared organisational secret is the same for everyone,
while a delegated one is the caller's own account and differs per user.

Every principal is `system` today, so these tests mostly pin behaviour that must not
change while the second half of that story gets built.
"""

from datetime import datetime, timedelta, timezone

import pytest

from carnet import config, storage
from carnet.core import credentials, crypto
from carnet.core.principal import Principal
from conftest import TEST_ACTOR


@pytest.mark.parametrize(
    "name, platform",
    [
        # The platform's own surface — refused (step 050, B1).
        ("CARNET_SECRET_KEY", True),
        ("CARNET_SECRET_KEYS_OLD", True),
        ("CARNET_DATABASE_URL", True),
        ("DATABASE_URL", True),
        ("READONLY_DATABASE_URL", True),
        ("ANTHROPIC_API_KEY", True),
        ("AWS_SECRET_ACCESS_KEY", True),
        ("AWS_SESSION_TOKEN", True),
        ("carnet_secret_key", True),  # a lower-case spelling is refused too
        # A connector's own variable — legal, whatever its shape.
        ("GITHUB_PERSONAL_ACCESS_TOKEN", False),
        ("TRACKER_TOKEN", False),
        ("ANTHROPIC_BROKERED_KEY", False),  # not the platform's own ANTHROPIC_API_KEY
        ("OPENAI_BROKERED_KEY", False),
        ("CARNET_CONNECTOR_JIRA", False),  # the reserved connector sub-namespace
        ("", False),
    ],
)
def test_is_platform_env_refuses_only_the_platforms_surface(name, platform):
    assert config.is_platform_env(name) is platform

# Tenancy lives on the Principal, so every constructed principal carries one. A named
# constant rather than a literal: the tenant is routing here, not the thing under test.
TENANT = "t-test"

SYSTEM = Principal.system("cli", TENANT)


@pytest.fixture(autouse=True)
def vetted_connectors(isolated_storage):
    """Connector rows for the ids this file stores credentials against. Migration 021.

    See the twin fixture in `test_connections.py` for the reasoning. Note what is *not*
    seeded: `never-heard-of-it`, `any-connector`, `greedy` and `x` are used by the tests
    about the *environment-variable* path, which never writes a `connections` row and so
    never meets the foreign key.
    """
    store = storage.active()
    for connector_id in ("github-mcp", "jira"):
        store.save_connector(TENANT, {"id": connector_id, "launch": {}, "vetted": []}, actor=TEST_ACTOR)
PRIYA = Principal.user("priya@example.com", TENANT)
SAM = Principal.user("sam@example.com", TENANT)


# --- a connector names its own credential ---------------------------------------
#
# This was found by pointing the HTTP transport at a real server: a hardcoded map from
# connector id to environment variable could only answer for connectors somebody had
# edited `credentials.py` for, so every new one authenticated as nobody and got a 401.
# Connectors are rows now; the row says where its secret lives.


def test_a_connector_names_the_variable_its_credential_lives_in(monkeypatch):
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "sekrit")

    found = credentials.for_connector("any-connector", SYSTEM, "SOME_VENDOR_TOKEN")

    assert found.value == "sekrit"
    assert found.source == credentials.SHARED


def test_a_connector_with_no_named_variable_falls_back_to_the_map(monkeypatch):
    """Rows written before the manifest carried the field."""
    monkeypatch.setenv("GITHUB_PERSONAL_ACCESS_TOKEN", "from-the-map")

    assert credentials.for_connector("github-mcp", SYSTEM).value == "from-the-map"


def test_an_unknown_connector_with_no_named_variable_has_no_credential():
    assert credentials.for_connector("never-heard-of-it", SYSTEM) is None


def test_an_unset_variable_reads_as_no_credential(monkeypatch):
    """An unauthenticated server is legitimate; the empty string is not a token."""
    monkeypatch.delenv("SOME_VENDOR_TOKEN", raising=False)

    assert credentials.for_connector("x", SYSTEM, "SOME_VENDOR_TOKEN") is None


def test_a_connector_may_not_ask_for_the_platforms_own_credential(monkeypatch):
    """Step 050 (blocker B1): a connector naming any of the platform's own environment
    variables is refused at the credential read — the master key and the database DSN as
    much as the model key — not only `ANTHROPIC_API_KEY` as the first draft refused."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-do-not-send-this")
    monkeypatch.setenv("CARNET_SECRET_KEY", "the-deployments-master-key")

    with pytest.raises(credentials.CredentialError, match="platform's own"):
        credentials.for_connector("greedy", SYSTEM, "ANTHROPIC_API_KEY")

    with pytest.raises(credentials.CredentialError, match="CARNET_SECRET_KEY"):
        credentials.for_connector("greedy", SYSTEM, "CARNET_SECRET_KEY")


# --- the key ------------------------------------------------------------------


def test_for_tool_takes_a_principal():
    """The signature was the point of the step that added it: doing so later would have
    meant changing the broker's call site and every connector at once. It now reads it."""
    found = credentials.for_tool("some_hand_written_tool", {}, SYSTEM)

    assert found.kwargs == {}
    assert found.source is None  # no secret at all, which is not "shared"


def test_the_same_lookup_works_for_any_principal_kind():
    for principal in (SYSTEM, PRIYA, SAM):
        assert credentials.for_tool("some_hand_written_tool", {}, principal).kwargs == {}


# --- shared credentials -------------------------------------------------------


def test_a_shared_credential_does_not_vary_by_principal():
    """A channel's webhook belongs to the organisation. Who may post to it is the
    permission check's question, not the credential store's."""
    for_priya = credentials.for_tool("post_message", {"channel": "#eng"}, PRIYA)
    for_sam = credentials.for_tool("post_message", {"channel": "#eng"}, SAM)
    assert for_priya == for_sam


def test_an_unmapped_channel_has_no_secret_to_send_with():
    """The credential lookup is a second enforcement point: even if a channel somehow
    passed the permission check, there is nothing to deliver it with."""
    creds = credentials.for_tool("post_message", {"channel": "#nowhere"}, SYSTEM)
    assert creds.kwargs == {"webhook_url": None}


def test_a_channel_webhook_is_recorded_as_shared_however_it_resolves(monkeypatch):
    """A chat webhook is the organisation's and no amount of delegation changes that.
    Recorded as `shared` so the audit log does not imply otherwise."""
    monkeypatch.setenv("WEBHOOK_URL_ENG", "https://hooks.example/eng")

    assert credentials.for_tool("post_message", {"channel": "#eng"}, PRIYA).source == (
        credentials.SHARED
    )
    assert credentials.for_tool("post_message", {"channel": "#nope"}, PRIYA).source == (
        credentials.SHARED
    )


def test_a_mapped_channel_resolves_to_its_own_url(monkeypatch):
    """Per-channel, not per-workspace — one leaked grant cannot post everywhere."""
    monkeypatch.setenv("WEBHOOK_URL_ENG", "https://hooks.example/eng")
    monkeypatch.delenv("WEBHOOK_URL_GENERAL", raising=False)

    assert credentials.for_tool("post_message", {"channel": "#eng"}, SYSTEM).kwargs == {
        "webhook_url": "https://hooks.example/eng"
    }
    assert credentials.for_tool(
        "post_message", {"channel": "#general"}, SYSTEM
    ).kwargs == {"webhook_url": None}


def test_a_missing_channel_argument_does_not_raise():
    """The broker only reaches step 3 for an authorized call, so this shouldn't happen
    — but a KeyError here would surface as a crash rather than a refusal."""
    assert credentials.for_tool("post_message", {}, SYSTEM).kwargs == {
        "webhook_url": None
    }


# --- what the model never sees -------------------------------------------------


def test_every_injected_kwarg_name_is_reserved():
    """A credential kwarg the model could also supply would be an override, not an
    injection. RESERVED_KWARGS is what makes permissions.check() refuse the attempt
    and audit.py hash it — so any name we inject has to be in that set."""
    injected = set(credentials.for_tool("post_message", {"channel": "#eng"}, SYSTEM).kwargs)
    assert injected <= credentials.RESERVED_KWARGS


def test_the_delegated_kwarg_name_is_reserved_too():
    """The delegated path injects `token`, which the model must equally never supply."""
    injected = set(
        credentials.for_tool("x", {}, SYSTEM, connector="never-heard-of-it").kwargs
    )
    assert injected <= credentials.RESERVED_KWARGS


def test_the_model_api_key_is_not_reachable_through_the_tool_lookup():
    """The one credential the agent process legitimately holds is unrelated to tool
    credentials, and must not arrive as a tool kwarg."""
    creds = credentials.for_tool("post_message", {"channel": "#eng"}, SYSTEM).kwargs
    assert "ANTHROPIC_API_KEY" not in creds
    assert "api_key" not in creds


# --- delegated credentials: the `user` identity -----------------------------------
#
# The whole of the read path for a tool vetted `identity: user` — since 033a the only
# identity that reads `connections` at all. Two properties are the feature and the
# third is the reason it is written out rather than being a one-line lookup: an
# unreadable delegated credential must never quietly become the operator's, and since
# 033a an *absent* one must not either — the fallback itself was the defect (whose
# account a call used depended on whether the caller happened to have connected one).


def connect(principal, connector_id="github-mcp", credential="her-own-token", **extra):
    """Seal a credential into the store the way `--connect-account` will."""
    aad = crypto.connection_aad(
        principal.tenant_id, principal.kind, principal.id, connector_id
    )
    blob, key_id = crypto.seal(credential, tenant_id=principal.tenant_id, aad=aad)
    storage.active().save_connection(
        principal.tenant_id,
        principal.kind,
        principal.id,
        connector_id,
        ciphertext=blob,
        key_id=key_id,
        **extra,
        actor=TEST_ACTOR,
    )


def test_a_service_tool_reads_the_environment_variable(monkeypatch):
    """The `service` identity — and the default, so a tool vetted before 033a keeps
    the behaviour every headless caller always had."""
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")

    found = credentials.for_connector("github-mcp", PRIYA, "SOME_VENDOR_TOKEN")

    assert found.value == "the-operators"
    assert found.source == credentials.SHARED


def test_a_user_tool_uses_the_connected_account_and_never_the_variable(monkeypatch):
    """The sentence 7a existed to make true, sharpened by 033a: it is the vetting that
    says whose account, not the accident of who connected."""
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connect(PRIYA, credential="priyas-token")

    found = credentials.for_connector(
        "github-mcp", PRIYA, "SOME_VENDOR_TOKEN", identity=credentials.USER_IDENTITY
    )

    assert found.value == "priyas-token"
    assert found.source == credentials.DELEGATED


def test_a_user_tool_with_no_connection_is_refused_not_served_the_shared_one(
    monkeypatch,
):
    """**The Tom defect, closed.** The silent fallback was how somebody read data their
    own account cannot open: every check passed, the shared credential answered, and
    nothing recorded that the vetting never said `service`. The refusal names the
    connection to make; the operator's secret is provably not in the answer because
    there is no answer."""
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")

    with pytest.raises(credentials.CredentialError) as caught:
        credentials.for_connector(
            "github-mcp", PRIYA, "SOME_VENDOR_TOKEN", identity=credentials.USER_IDENTITY
        )

    assert "connect" in str(caught.value).lower()
    assert "the-operators" not in str(caught.value)


def test_a_service_tool_ignores_a_connected_account(monkeypatch):
    """The silent-widening half of the old fallback, closed from the other side: one
    person connecting an account no longer changes how a shared tool behaves for a run
    of theirs. The vetting said `service`, so the service answers."""
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connect(PRIYA, credential="priyas-token")

    found = credentials.for_connector(
        "github-mcp", PRIYA, "SOME_VENDOR_TOKEN", identity=credentials.SERVICE_IDENTITY
    )

    assert found.value == "the-operators"
    assert found.source == credentials.SHARED


def test_an_unknown_identity_is_refused_not_guessed(monkeypatch):
    """The backstop under `tools.validation`'s refusal: a caller that bypassed the
    descriptor check still cannot make this module guess whose account to use."""
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")

    with pytest.raises(credentials.CredentialError, match="unknown identity"):
        credentials.for_connector(
            "github-mcp", PRIYA, "SOME_VENDOR_TOKEN", identity="whichever"
        )


def test_the_identity_words_match_the_descriptor_vocabulary():
    """`core/credentials` duplicates the identity strings rather than importing them —
    that module knows no specific tool — so this is the drift pin, on
    `test_an_oauth_credential_round_trips_through_storage`'s pattern."""
    from carnet.tools.validation import VALID_IDENTITIES

    assert {credentials.SERVICE_IDENTITY, credentials.USER_IDENTITY} == VALID_IDENTITIES


def test_two_people_running_one_agent_get_two_credentials(monkeypatch):
    """*It acts on their data.* No policy of ours produces this — it is the credential
    that differs, which is why this lives here and not in permissions."""
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connect(PRIYA, credential="priyas-token")
    connect(SAM, credential="sams-token")

    assert credentials.for_connector(
        "github-mcp", PRIYA, "SOME_VENDOR_TOKEN", identity="user"
    ).value == ("priyas-token")
    assert credentials.for_connector(
        "github-mcp", SAM, "SOME_VENDOR_TOKEN", identity="user"
    ).value == ("sams-token")


def test_one_persons_connection_does_not_answer_for_another(monkeypatch):
    """Sam has connected nothing, so Sam is refused — never handed Priya's account,
    and since 033a never quietly handed the operator's either."""
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connect(PRIYA, credential="priyas-token")

    with pytest.raises(credentials.CredentialError) as caught:
        credentials.for_connector(
            "github-mcp", SAM, "SOME_VENDOR_TOKEN", identity="user"
        )

    assert "priyas-token" not in str(caught.value)


def test_a_connection_is_per_connector(monkeypatch):
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connect(PRIYA, connector_id="jira", credential="priyas-jira-token")

    assert credentials.for_connector(
        "jira", PRIYA, "SOME_VENDOR_TOKEN", identity="user"
    ).value == ("priyas-jira-token")
    # Her jira row is not a github row: a `user` tool on the other connector refuses.
    with pytest.raises(credentials.CredentialError):
        credentials.for_connector(
            "github-mcp", PRIYA, "SOME_VENDOR_TOKEN", identity="user"
        )


def test_an_unreadable_credential_raises_rather_than_using_the_shared_one(monkeypatch):
    """**The decision this step turns on.**

    Falling back here would mean the agent acting as the operator while the person
    believes it is acting as them — reaching data they have no access to, and
    attributing it to them in a log that is kept forever. A broken credential has to
    look broken.
    """
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connect(PRIYA, credential="priyas-token")

    # A rotation that dropped the old key before the rows were re-encrypted.
    crypto.configure(crypto.LocalKeyCipher(b"\x99" * crypto.KEY_BYTES))

    with pytest.raises(credentials.CredentialError) as caught:
        credentials.for_connector(
            "github-mcp", PRIYA, "SOME_VENDOR_TOKEN", identity="user"
        )

    assert "the-operators" not in str(caught.value)


def test_a_tampered_credential_raises(monkeypatch):
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connect(PRIYA, credential="priyas-token")

    row = storage.active().find_connection(TENANT, "user", PRIYA.id, "github-mcp")
    altered = bytearray(row["ciphertext"])
    altered[-1] ^= 0x01
    storage.active().save_connection(
        TENANT, "user", PRIYA.id, "github-mcp",
        ciphertext=bytes(altered), key_id=row["key_id"],
        actor=TEST_ACTOR,
    )

    with pytest.raises(credentials.CredentialError, match="could not be read"):
        credentials.for_connector(
            "github-mcp", PRIYA, "SOME_VENDOR_TOKEN", identity="user"
        )


def test_a_credential_lifted_into_another_persons_row_does_not_open(monkeypatch):
    """The binding, from the read path's side. Copying the ciphertext across is the
    move the database cannot refuse and the cipher can."""
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connect(PRIYA, credential="priyas-token")

    stolen = storage.active().find_connection(TENANT, "user", PRIYA.id, "github-mcp")
    storage.active().save_connection(
        TENANT, "user", SAM.id, "github-mcp",
        ciphertext=stolen["ciphertext"], key_id=stolen["key_id"],
        actor=TEST_ACTOR,
    )

    with pytest.raises(credentials.CredentialError, match="could not be read"):
        credentials.for_connector(
            "github-mcp", SAM, "SOME_VENDOR_TOKEN", identity="user"
        )


def test_an_expired_connection_says_so_rather_than_reading_as_unconnected(monkeypatch):
    """Never connected and connected-but-expired send a person to two different places.
    That is why `connections.expires_at` is nullable rather than absent."""
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connect(
        PRIYA,
        credential="priyas-token",
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )

    with pytest.raises(credentials.CredentialError, match="expired"):
        credentials.for_connector(
            "github-mcp", PRIYA, "SOME_VENDOR_TOKEN", identity="user"
        )


def test_a_connection_expiring_in_the_future_is_still_good(monkeypatch):
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connect(
        PRIYA,
        credential="priyas-token",
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    )

    assert credentials.for_connector(
        "github-mcp", PRIYA, "SOME_VENDOR_TOKEN", identity="user"
    ).value == ("priyas-token")


def test_a_system_principal_may_hold_its_own_connection(monkeypatch):
    """A scheduler running a customer's nightly job is that customer's scheduler, and
    may act with a service credential rather than the platform-wide one."""
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connect(SYSTEM, credential="the-schedulers-own")

    assert credentials.for_connector(
        "github-mcp", SYSTEM, "SOME_VENDOR_TOKEN", identity="user"
    ).value == ("the-schedulers-own")


def test_the_delegated_credential_reaches_the_tool_as_a_kwarg(monkeypatch):
    """End of the read path: what the broker will actually inject."""
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connect(PRIYA, credential="priyas-token")

    found = credentials.for_tool(
        "github_mcp_list_issues", {}, PRIYA, connector="github-mcp", identity="user"
    )

    assert found.kwargs == {"token": "priyas-token"}
    assert found.source == credentials.DELEGATED


def test_a_delegated_lookup_does_not_need_the_environment_at_all(monkeypatch):
    """A customer who has never set the shared variable is a normal deployment once
    everybody connects their own account."""
    monkeypatch.delenv("SOME_VENDOR_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_PERSONAL_ACCESS_TOKEN", raising=False)
    connect(PRIYA, credential="priyas-token")

    assert (
        credentials.for_connector("github-mcp", PRIYA, identity="user").value
        == "priyas-token"
    )


# --- the credential a SESSION is opened with, which is not a call's account --------
#
# `for_session` is the handshake's credential: what `tools/list` is asked with, never
# what a call acts as. Shared first — the inverse of `for_discovery`, and deliberate
# in both directions.


def test_a_session_prefers_the_shared_credential_over_the_callers_connection(
    monkeypatch,
):
    """Binding is a tenant fact. A caller's connection must not decide it — and must
    not be *read* to decide it, which is the half that matters below."""
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connect(PRIYA, credential="priyas-token")

    found = credentials.for_session("github-mcp", PRIYA, "SOME_VENDOR_TOKEN")

    assert found.value == "the-operators"
    assert found.source == credentials.SHARED


def test_a_broken_connection_does_not_break_a_session_that_has_a_shared_credential(
    monkeypatch,
):
    """033a's own complaint, one layer up. Priya's connection expired; every tool on
    this connector is `service` and would never read her row — so her expiry must not
    kill the handshake and take the run with it. Before this the session resolved
    delegated-first and raised here."""
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connect(
        PRIYA,
        credential="priyas-token",
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )

    assert credentials.for_session("github-mcp", PRIYA, "SOME_VENDOR_TOKEN").value == (
        "the-operators"
    )


def test_a_session_falls_back_to_the_caller_when_no_shared_credential_is_configured(
    monkeypatch,
):
    """The deployment shape the test above this section calls normal: everybody
    connects their own account and nobody ever set the variable. Binding with no
    credential at all meets a real server's 401 **before the model is shown a single
    tool**, which is the silent-degrade `ensure_available` raises rather than
    tolerates."""
    monkeypatch.delenv("SOME_VENDOR_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_PERSONAL_ACCESS_TOKEN", raising=False)
    connect(PRIYA, credential="priyas-token")

    found = credentials.for_session("github-mcp", PRIYA, "SOME_VENDOR_TOKEN")

    assert found.value == "priyas-token"
    assert found.source == credentials.DELEGATED


def test_a_session_with_neither_credential_is_none_rather_than_a_refusal(monkeypatch):
    """An unauthenticated MCP server is a real thing, and a server that wants auth
    answers 401 — which is its answer to give, not ours to guess."""
    monkeypatch.delenv("SOME_VENDOR_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_PERSONAL_ACCESS_TOKEN", raising=False)

    assert credentials.for_session("github-mcp", PRIYA, "SOME_VENDOR_TOKEN") is None


# --- acting-for: which person a `user` tool resolves (033c) -----------------------
#
# Acting-for substitutes a person, never a policy: the `user` branch resolves the
# acted-for person's connection instead of the caller's, the `service` branch never
# reads it, and every miss raises — by the time it runs, the vetting said "a person's
# account", the caller named which person, and the claim was already worth acting on.

MACHINE = Principal.machine("tok-1", TENANT)


def acting_for(user_id, email="tom@acme.com"):
    from carnet.core.principal import ASSERTED, ActingFor

    return ActingFor(user_id=user_id, email=email, source=ASSERTED)


def test_acting_for_resolves_the_acted_for_persons_connection(monkeypatch):
    """Both the caller and Tom have connections; Tom's is the one used, because the
    call is *for* him — and the caller's own is deliberately not a fallback."""
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connect(MACHINE, credential="the-callers-own")
    connect(Principal.user("u-tom", TENANT), credential="toms-token")

    found = credentials.for_connector(
        "github-mcp",
        MACHINE,
        "SOME_VENDOR_TOKEN",
        identity=credentials.USER_IDENTITY,
        acting_for=acting_for("u-tom"),
    )

    assert found.value == "toms-token"
    assert found.source == credentials.DELEGATED


def test_an_acted_for_person_with_no_connection_is_refused_naming_them(monkeypatch):
    """Nothing honest is left to fall back to: not the shared credential (the
    operator's account under Tom's name in the log) and not the caller's own connection
    (a different person's account under the same lie)."""
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connect(MACHINE, credential="the-callers-own")

    with pytest.raises(credentials.CredentialError) as refusal:
        credentials.for_connector(
            "github-mcp",
            MACHINE,
            "SOME_VENDOR_TOKEN",
            identity=credentials.USER_IDENTITY,
            acting_for=acting_for("u-tom"),
        )

    assert "tom@acme.com" in str(refusal.value)
    assert "the-operators" not in str(refusal.value)


def test_an_unresolved_assertion_on_a_user_tool_is_refused_at_credential_time():
    """`user_id=None` — an asserted address matching nobody — passes resolution so a
    `service` tool can record it, and lands here the moment an account is needed."""
    with pytest.raises(credentials.CredentialError, match="matches nobody"):
        credentials.for_connector(
            "github-mcp",
            MACHINE,
            identity=credentials.USER_IDENTITY,
            acting_for=acting_for(None, email="ghost@acme.com"),
        )


def test_the_service_branch_never_reads_acting_for(monkeypatch):
    """The rule that keeps acting-for from becoming a back door into the vetted
    identity: whose account a tool acts as stays the approval's decision."""
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connect(Principal.user("u-tom", TENANT), credential="toms-token")

    found = credentials.for_connector(
        "github-mcp",
        MACHINE,
        "SOME_VENDOR_TOKEN",
        identity=credentials.SERVICE_IDENTITY,
        acting_for=acting_for("u-tom"),
    )

    assert found.value == "the-operators"
    assert found.source == credentials.SHARED


# --- personal_owner: the one address for whom a machine credential answers as ------


def test_personal_owner_answers_only_for_a_live_match(isolated_storage):
    """Step 033d's one reader of the `acts_as_owner` row, at its four edges: a person
    is never redirected, a token id no row matches fails closed, a service token stays
    itself, and a personal token answers as its owner — a *user* principal, because
    the owner's grant rows and connection rows are keyed that way."""
    from carnet.access import tokens

    personal, _ = tokens.mint(
        TENANT, "priya-editor", "u-priya", actor="system:cli", acts_as_owner=True
    )
    service, _ = tokens.mint(TENANT, "nightly-ci", "u-priya", actor="system:cli")

    assert credentials.personal_owner(PRIYA) is None
    assert credentials.personal_owner(Principal.machine("m_missing", TENANT)) is None
    assert credentials.personal_owner(Principal.machine(service["id"], TENANT)) is None

    owner = credentials.personal_owner(Principal.machine(personal["id"], TENANT))
    assert (owner.kind, owner.id, owner.tenant_id) == ("user", "u-priya", TENANT)


def test_personal_owner_refuses_a_cross_tenant_costume(isolated_storage):
    """`find_api_token` is tenantless (it is what produces a tenant for `resolve`), so
    the redirect must check the row's tenant against the principal's — the same check
    `act_for` makes, for the same reason. A mismatch answers None: the machine's own
    empty rows, never an owner across the boundary."""
    from carnet.access import tokens

    storage.active().create_tenant("t-other", "Other")
    personal, _ = tokens.mint(
        "t-other", "priya-editor", "u-priya", actor="system:cli", acts_as_owner=True
    )

    assert credentials.personal_owner(Principal.machine(personal["id"], TENANT)) is None
