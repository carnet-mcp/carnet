"""Step 7b: the credential a person gives themselves.

Seven of the eight step-level verifications the plan names live here. The eighth —
**eight concurrent refreshes make one token-endpoint call** — is in
`test_storage_contract.py`, because it is Postgres-only: the in-memory store's refresh
lock is a `threading.Lock` in one process, which is a genuinely weaker guarantee than an
advisory lock and cannot demonstrate the property a deployment with two workers needs.

## The fake authorization server, and what it is allowed to be

`FakeProvider` below replaces `oauth._post_form` — the one function in `access/oauth.py`
that touches the network, isolated for exactly this reason and on `transport.py`'s
precedent. So no socket is opened and these tests cost nothing.

What that means the suite **cannot** show is that a real provider's token response parses,
that a real consent screen redirects the way this expects, or that refresh-token rotation
behaves at a vendor the way its documentation says. That is the gap the plan's one
non-test done-when names — *connect a real third-party account nobody here has connected
before* — and it is stated rather than papered over here.

What it **can** show, and what the fake is built to make visible, is every property that
is about our code: that the token never appears in a response body, that a forged or
replayed `state` seals nothing, that a rotating provider does not break the connection,
that an `invalid_grant` is terminal rather than retried, and that no secret reaches the
administrative log.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from carnet import storage, tools
from carnet.access import connections, oauth
from carnet.core import Principal, credentials, crypto

from conftest import TEST_ACTOR, TEST_HOST, TEST_TENANT

PRIYA = Principal.user("u_priya", TEST_TENANT)
SAM = Principal.user("u_sam", TEST_TENANT)

AUTHORIZE = f"https://{TEST_HOST}/authorize"
TOKEN = f"https://{TEST_HOST}/token"
REVOKE = f"https://{TEST_HOST}/revoke"
REDIRECT = "https://runtime.acme.com/connect/callback"

# Marker strings rather than plausible ones. Every secret in this flow is a value that
# would be unmistakable in a log, an audit record or a response body — which is what
# makes `test_no_secret_reaches_the_administrative_log` an assertion rather than an
# inspection. See decision 10.
CLIENT_SECRET = "MARKER-CLIENT-SECRET-e3f1"
ACCESS_TOKEN = "MARKER-ACCESS-TOKEN-a71c"
REFRESH_TOKEN = "MARKER-REFRESH-TOKEN-b92d"


class FakeProvider:
    """An authorization server that does what the awkward ones do.

    **Rotating by default**, because Atlassian, Google and Okta all rotate — a fake that
    returned the same refresh token forever would make every test here pass against a
    codebase with the lost-update bug decision 11 exists to prevent.
    """

    def __init__(self, *, rotate=True, expires_in=3600):
        self.rotate = rotate
        self.expires_in = expires_in
        self.calls = []
        self.issued = 0
        self.live_refresh = REFRESH_TOKEN
        self.revoked = []
        # Set to an `(error,)` to make the next exchange fail that way.
        self.fail_with = None

    def __call__(self, url, form, *, auth, want_body=False):
        self.calls.append({"url": url, "form": dict(form), "auth": auth})

        if url.endswith("/revoke"):
            self.revoked.append(form.get("token"))
            return 200, None

        if self.fail_with:
            return 400, {"error": self.fail_with}

        if form.get("grant_type") == "refresh_token":
            if form["refresh_token"] != self.live_refresh:
                # What a rotating provider actually does with a spent token. Atlassian
                # goes further and kills the grant; this is the mild version and is
                # still enough to break a connection permanently under a lost update.
                return 400, {"error": "invalid_grant"}

        self.issued += 1
        body = {
            "access_token": f"{ACCESS_TOKEN}-{self.issued}",
            "token_type": "Bearer",
            "expires_in": self.expires_in,
            "email": "priya@acme.com",
        }
        if self.rotate:
            self.live_refresh = f"{REFRESH_TOKEN}-{self.issued}"
            body["refresh_token"] = self.live_refresh
        return 200, body

    @property
    def token_calls(self):
        """Exchanges, by what they are rather than by which URL they went to.

        This filtered on `url == TOKEN` — this module's constant — and silently returned
        **zero** for `test_concurrency.py`, which configures the same fake against a
        different host. An assertion of `exchanges == 1` against a counter that is
        structurally zero is an assertion that can only fail, and the version before it
        (`exchanges == 0`) would have *passed with no lock at all*. Found by the count
        being 0 where it had to be at least 1.
        """
        return [c for c in self.calls if "grant_type" in c["form"]]


@pytest.fixture
def provider(monkeypatch):
    fake = FakeProvider()
    monkeypatch.setattr(oauth, "_post_form", fake)
    return fake


@pytest.fixture
def jira(isolated_storage):
    """A registered HTTP connector with a consent flow configured."""
    tools.register_connector(
        TEST_TENANT,
        "jira",
        url=f"https://{TEST_HOST}/mcp",
        actor=TEST_ACTOR,
    )
    oauth.configure(
        TEST_TENANT,
        "jira",
        authorize_endpoint=AUTHORIZE,
        token_endpoint=TOKEN,
        revoke_endpoint=REVOKE,
        client_id="client-abc",
        client_secret=CLIENT_SECRET,
        scopes=("read:jira-work", "offline_access"),
        actor=TEST_ACTOR,
    )
    return "jira"


def connect(principal, provider, connector="jira"):
    """Drive a whole consent flow. Returns what `complete` reported."""
    url = oauth.begin(principal, connector, redirect_uri=REDIRECT)
    state = url.split("state=")[1].split("&")[0]
    return oauth.complete(state, "the-authorization-code")


def stored(principal, connector="jira") -> dict:
    """The sealed credential, opened. Only a test may do this."""
    row = storage.active().find_connection(
        principal.tenant_id, principal.kind, principal.id, connector
    )
    plaintext = crypto.open_(
        row["ciphertext"],
        tenant_id=principal.tenant_id,
        aad=crypto.connection_aad(
            principal.tenant_id, principal.kind, principal.id, connector
        ),
        key_id=row["key_id"],
    )
    return {"row": row, "credential": json.loads(plaintext)}


# --- 1. the token never reaches the browser ------------------------------------------


def test_the_authorize_url_carries_no_secret(jira, provider):
    """What goes through the browser is a client id, a state and a hash. Decision 1."""
    url = oauth.begin(PRIYA, "jira", redirect_uri=REDIRECT)

    assert url.startswith(AUTHORIZE + "?")
    assert "client-abc" in url
    assert CLIENT_SECRET not in url
    # PKCE's whole point: the challenge travels, the verifier does not.
    assert "code_challenge=" in url and "code_challenge_method=S256" in url
    verifier_row = storage.active().consume_pending_authorization(
        url.split("state=")[1].split("&")[0]
    )
    verifier = crypto.open_(
        verifier_row["code_verifier"],
        tenant_id=TEST_TENANT,
        aad=crypto.pending_authorization_aad(TEST_TENANT, verifier_row["state"]),
        key_id=verifier_row["key_id"],
    )
    assert verifier not in url


def test_the_token_lands_in_storage_and_in_nothing_the_browser_sees(jira, provider):
    """Verification 1. The token is in `connections` and in no reported value."""
    outcome = connect(PRIYA, provider)

    held = stored(PRIYA)
    assert held["credential"]["access"] == f"{ACCESS_TOKEN}-1"
    assert held["credential"]["refresh"] == f"{REFRESH_TOKEN}-1"

    # Everything `complete` hands back to a route, flattened. The route turns this into
    # a redirect, so anything here can reach a browser.
    reported = json.dumps(outcome, default=str)
    assert ACCESS_TOKEN not in reported
    assert REFRESH_TOKEN not in reported
    assert CLIENT_SECRET not in reported
    assert outcome["connector_id"] == "jira"


def test_the_credential_is_marked_oauth_rather_than_sniffed(jira, provider):
    """Decision 4: the discriminator is a column, not the ciphertext's shape."""
    connect(PRIYA, provider)
    assert stored(PRIYA)["row"]["credential_kind"] == storage.OAUTH_CREDENTIAL


def test_the_read_path_hands_the_access_token_to_a_tool(jira, provider):
    """The whole point: what the broker injects is the access token, not the JSON."""
    connect(PRIYA, provider)

    credential = credentials.for_connector("jira", PRIYA, identity="user")

    assert credential.value == f"{ACCESS_TOKEN}-1"
    assert credential.source == credentials.DELEGATED
    assert REFRESH_TOKEN not in credential.value


# --- 2. a forged or replayed state is refused ------------------------------------------


def test_a_state_we_never_minted_is_refused(jira, provider):
    """Verification 2, first half. The CSRF defence, and it seals nothing."""
    with pytest.raises(oauth.OAuthRefused):
        oauth.complete("f" * 43, "some-code")

    assert provider.token_calls == []
    assert storage.active().find_connection(
        TEST_TENANT, "user", "u_priya", "jira"
    ) is None


def test_a_replayed_state_is_refused(jira, provider):
    """Verification 2, second half. Single-use, and it is one DELETE ... RETURNING."""
    url = oauth.begin(PRIYA, "jira", redirect_uri=REDIRECT)
    state = url.split("state=")[1].split("&")[0]

    oauth.complete(state, "code-1")
    calls_after_first = len(provider.token_calls)

    with pytest.raises(oauth.OAuthRefused):
        oauth.complete(state, "code-2")

    # Not merely refused — the second exchange never reached the provider at all.
    assert len(provider.token_calls) == calls_after_first


def test_a_states_row_names_the_principal_because_the_request_cannot(jira, provider):
    """Decision 2 stated as a property rather than as a comment.

    `complete` is handed a state and a code and nothing else — no principal, no tenant,
    no header — because a top-level redirect carries none of those. Everything it seals
    comes out of the row.
    """
    url = oauth.begin(SAM, "jira", redirect_uri=REDIRECT)
    state = url.split("state=")[1].split("&")[0]

    outcome = oauth.complete(state, "code")

    assert outcome["principal"].id == "u_sam"
    assert storage.active().find_connection(TEST_TENANT, "user", "u_sam", "jira")
    assert storage.active().find_connection(TEST_TENANT, "user", "u_priya", "jira") is None


def test_an_expired_flow_is_refused_and_is_also_spent(jira, provider, monkeypatch):
    """The TTL, and the ordering that makes an expired state unusable rather than stale."""
    url = oauth.begin(PRIYA, "jira", redirect_uri=REDIRECT)
    state = url.split("state=")[1].split("&")[0]

    monkeypatch.setattr(oauth, "PENDING_TTL_SECONDS", -1)

    with pytest.raises(oauth.OAuthRefused, match="too long"):
        oauth.complete(state, "code")

    # Consumed before the age check, so an expired flow cannot be retried by anybody who
    # merely waits for the clock to be wrong.
    assert storage.active().consume_pending_authorization(state) is None


# --- 3. the operator never sees the token ---------------------------------------------


def test_nothing_in_the_connection_listing_carries_a_secret(jira, provider):
    """Verification 3. `--list-connections` and `GET /connections` read this."""
    connect(PRIYA, provider)

    rows = json.dumps(connections.list_accounts(TEST_TENANT), default=str)

    assert ACCESS_TOKEN not in rows
    assert REFRESH_TOKEN not in rows
    assert CLIENT_SECRET not in rows
    assert "priya@acme.com" in rows  # the verified label, which is the point


def test_the_account_label_comes_from_the_provider(jira, provider):
    """Decision 6. 7a's README predicted this would be free, and it is."""
    connect(PRIYA, provider)
    assert stored(PRIYA)["row"]["account_label"] == "priya@acme.com"


# --- 4 and 5. refresh, and what a revoked consent does --------------------------------


def expire(principal, connector="jira", *, ago=timedelta(minutes=5)):
    """Backdate a connection's access token without going near the credential."""
    row = storage.active().find_connection(
        principal.tenant_id, principal.kind, principal.id, connector
    )
    storage.active().update_connection_credential(
        principal.tenant_id,
        principal.kind,
        principal.id,
        connector,
        ciphertext=row["ciphertext"],
        key_id=row["key_id"],
        expires_at=datetime.now(timezone.utc) - ago,
        refresh_expires_at=None,
        if_updated_at=row["updated_at"],
    )


def test_an_expired_access_token_is_renewed_before_a_run(jira, provider):
    """Verification 4. The new token is stored, and it is a different token."""
    connect(PRIYA, provider)
    expire(PRIYA)

    assert oauth.refresh_connection(PRIYA, "jira") is True

    held = stored(PRIYA)
    assert held["credential"]["access"] == f"{ACCESS_TOKEN}-2"
    assert (
        credentials.for_connector("jira", PRIYA, identity="user").value
        == f"{ACCESS_TOKEN}-2"
    )
    assert held["row"]["expires_at"] > datetime.now(timezone.utc)


def test_a_rotated_refresh_token_replaces_the_spent_one(jira, provider):
    """The failure decision 11 exists for, in its simplest form.

    A provider that rotates invalidates the old refresh token. Storing the response's
    *access* token and keeping the old refresh token would work exactly once and then
    break the connection permanently.
    """
    connect(PRIYA, provider)
    expire(PRIYA)
    oauth.refresh_connection(PRIYA, "jira")

    assert stored(PRIYA)["credential"]["refresh"] == f"{REFRESH_TOKEN}-2"

    # And it is still good the *second* time, which is the half a single refresh cannot
    # show and the half a real rotating provider punishes.
    expire(PRIYA)
    assert oauth.refresh_connection(PRIYA, "jira") is True
    assert stored(PRIYA)["credential"]["access"] == f"{ACCESS_TOKEN}-3"


def test_a_provider_that_does_not_rotate_keeps_its_refresh_token(jira, monkeypatch):
    """The other half. An omitted `refresh_token` means keep using the one you have.

    Dropping it would break the connection at the *next* refresh rather than this one,
    which is the kind of bug that gets blamed on the provider.
    """
    fake = FakeProvider(rotate=False)
    monkeypatch.setattr(oauth, "_post_form", fake)
    fake.live_refresh = REFRESH_TOKEN

    url = oauth.begin(PRIYA, "jira", redirect_uri=REDIRECT)
    # A non-rotating provider still issues one at the code exchange.
    fake.rotate = True
    oauth.complete(url.split("state=")[1].split("&")[0], "code")
    fake.rotate = False

    expire(PRIYA)
    oauth.refresh_connection(PRIYA, "jira")

    assert stored(PRIYA)["credential"]["refresh"] == f"{REFRESH_TOKEN}-1"


def test_a_fresh_token_is_not_refreshed_at_all(jira, provider):
    """The common path, and the reason the lock is cheap: no I/O for a live token."""
    connect(PRIYA, provider)
    before = len(provider.token_calls)

    assert oauth.refresh_connection(PRIYA, "jira") is False
    assert len(provider.token_calls) == before


def test_a_token_expiring_within_the_skew_is_refreshed_early(jira, provider):
    """A token with 30 seconds left expires mid-run. `EXPIRY_SKEW_SECONDS` is why."""
    connect(PRIYA, provider)
    expire(PRIYA, ago=timedelta(seconds=-30))  # 30 seconds in the FUTURE

    assert oauth.refresh_connection(PRIYA, "jira") is True


def test_a_revoked_consent_is_terminal_and_never_becomes_the_shared_credential(
    jira, provider, monkeypatch
):
    """Verification 5, and it is the most important test in this file.

    A refresh that fails must not fall back to the environment variable. Falling back
    would mean the agent acting as the **operator** while the person believes it is
    acting as them — reaching data they have no access to and attributing it to them in
    a log kept forever. 7a's third outcome, arriving through a new door.
    """
    connect(PRIYA, provider)
    expire(PRIYA)
    monkeypatch.setenv("JIRA_TOKEN", "the-operators-shared-token")
    provider.fail_with = "invalid_grant"

    with pytest.raises(oauth.ReconsentRequired):
        oauth.refresh_connection(PRIYA, "jira")

    # The row is kept, not deleted. Pre-033a, deleting it was what produced the
    # fallback; a `user` tool now refuses on no-row too, and the kept row is what
    # lets the refusal say *why* rather than "connect an account".
    row = storage.active().find_connection(TEST_TENANT, "user", "u_priya", "jira")
    assert row is not None
    assert "invalid_grant" in row["reconsent_reason"]

    with pytest.raises(credentials.CredentialError, match="set up again"):
        credentials.for_connector("jira", PRIYA, "JIRA_TOKEN", identity="user")


def test_an_invalid_grant_is_never_retried(jira, provider):
    """Decision 11's third rule. Retrying is how one dead connection becomes an incident."""
    connect(PRIYA, provider)
    expire(PRIYA)
    provider.fail_with = "invalid_grant"
    before = len(provider.token_calls)

    with pytest.raises(oauth.ReconsentRequired):
        oauth.refresh_connection(PRIYA, "jira")

    assert len(provider.token_calls) == before + 1

    # And a second attempt does not reach the provider at all: the row now says why.
    with pytest.raises(oauth.ReconsentRequired):
        oauth.refresh_connection(PRIYA, "jira")
    assert len(provider.token_calls) == before + 1


def test_reconnecting_clears_the_refusal(jira, provider):
    """The fix has to actually work, which is what `save_connection` resetting is for."""
    connect(PRIYA, provider)
    expire(PRIYA)
    provider.fail_with = "invalid_grant"
    with pytest.raises(oauth.ReconsentRequired):
        oauth.refresh_connection(PRIYA, "jira")

    provider.fail_with = None
    provider.live_refresh = REFRESH_TOKEN
    connect(PRIYA, provider)

    assert stored(PRIYA)["row"]["reconsent_reason"] == ""
    assert credentials.for_connector("jira", PRIYA, identity="user") is not None


def test_a_connection_with_no_refresh_token_asks_for_re_consent(jira, monkeypatch):
    """A provider given no `offline_access` issues none. Surfaced honestly, not fixed."""
    fake = FakeProvider(rotate=False)
    monkeypatch.setattr(oauth, "_post_form", fake)

    url = oauth.begin(PRIYA, "jira", redirect_uri=REDIRECT)
    oauth.complete(url.split("state=")[1].split("&")[0], "code")
    expire(PRIYA)

    with pytest.raises(oauth.ReconsentRequired, match="no refresh token"):
        oauth.refresh_connection(PRIYA, "jira")


def test_a_static_credential_is_never_refreshed(jira, provider):
    """A pasted token is somebody's PAT. Only they can rotate it, and this must not try."""
    connections.connect_account(PRIYA, "jira", "a-pasted-token", actor=TEST_ACTOR)
    before = len(provider.token_calls)

    assert oauth.refresh_connection(PRIYA, "jira") is False
    assert len(provider.token_calls) == before


# --- the entry point invokes it -------------------------------------------------------


def test_refresh_for_run_only_touches_this_agents_connectors(jira, provider):
    """Laziness, and the reason `connectors_for_agent` is one function with two callers."""
    connect(PRIYA, provider)
    expire(PRIYA)

    assert oauth.refresh_for_run(PRIYA, {"permissions": {"tools": []}}) == []
    assert provider.token_calls[-1]["form"]["grant_type"] == "authorization_code"


def test_a_provider_being_down_does_not_lose_the_run(jira, provider, monkeypatch):
    """Best-effort per connector. The run proceeds and fails at the credential, not here."""
    connect(PRIYA, provider)
    expire(PRIYA)

    def explode(*args, **kwargs):
        raise ConnectionError("the provider is down")

    monkeypatch.setattr(oauth, "_post_form", explode)

    # No exception. The connector's tools are what the run needs, and whether it needs
    # them at all is not this function's question.
    assert oauth.refresh_for_run(PRIYA, {"permissions": {"tools": ["jira_search"]}}) == []


# --- 7. no secret reaches the administrative log --------------------------------------


def test_no_secret_reaches_the_administrative_log(jira, provider):
    """Verification 7, on `test_no_record_carries_an_agents_system_prompt`'s precedent.

    Every secret in this flow is a marker string set at the top of this file. Running the
    whole thing — configure, consent, refresh, disconnect — and then requiring that none
    of them appears anywhere in `admin_audit` is an assertion; reading the `detail` dicts
    and agreeing that they look fine is not.
    """
    connect(PRIYA, provider)
    expire(PRIYA)
    oauth.refresh_connection(PRIYA, "jira")
    oauth.disconnect(PRIYA, "jira", actor=str(PRIYA))

    log = json.dumps(storage.active().admin_audit_records(TEST_TENANT), default=str)

    for secret in (CLIENT_SECRET, ACCESS_TOKEN, REFRESH_TOKEN):
        assert secret not in log, f"{secret} reached the administrative log"

    # And the things that SHOULD be there are, because a log that records nothing also
    # passes the assertion above.
    assert "connector.oauth.configure" in log
    assert "connection.create" in log
    assert "connection.delete" in log
    assert "read:jira-work" in log  # the scopes: what did we ask for


def test_connecting_records_the_person_as_their_own_actor(jira, provider):
    """Decision 10's last paragraph, and the difference 7b exists to create.

    `--connect-account` records an operator acting on somebody's behalf. A consent flow
    records the person acting on their own. That distinction is the whole step, and the
    administrative log is the only place it survives.
    """
    connect(PRIYA, provider)

    record = [
        r
        for r in storage.active().admin_audit_records(TEST_TENANT)
        if r["action"] == "connection.create"
    ][-1]

    assert record["actor_kind"] == "user"
    assert record["actor_id"] == "u_priya"
    assert record["detail"]["principal"] == "user:u_priya"
    assert record["detail"]["kind"] == "oauth"


def test_the_cli_path_records_the_operator_instead(jira):
    """The other side of the same assertion, so the pair means something."""
    connections.connect_account(PRIYA, "jira", "pasted", actor="user:u_operator")

    record = [
        r
        for r in storage.active().admin_audit_records(TEST_TENANT)
        if r["action"] == "connection.create"
    ][-1]

    assert record["actor_id"] == "u_operator"
    assert record["detail"]["principal"] == "user:u_priya"
    assert record["detail"]["kind"] == "static"


# --- 8. disconnecting revokes upstream, and deletes either way -------------------------


def test_disconnecting_revokes_upstream_then_deletes(jira, provider):
    """Verification 8, first half. Decision 12's ordering."""
    connect(PRIYA, provider)

    outcome = oauth.disconnect(PRIYA, "jira", actor=str(PRIYA))

    assert outcome == {"disconnected": True, "revoked_upstream": True}
    assert provider.revoked == [f"{REFRESH_TOKEN}-1"]
    assert storage.active().find_connection(
        TEST_TENANT, "user", "u_priya", "jira"
    ) is None


def test_disconnecting_deletes_even_when_revocation_fails(jira, provider, monkeypatch):
    """Verification 8, second half, and the half that matters to a person.

    A provider outage must not trap somebody in a connection they have asked to end.
    """
    connect(PRIYA, provider)

    def explode(*args, **kwargs):
        raise ConnectionError("the provider is down")

    monkeypatch.setattr(oauth, "_post_form", explode)

    outcome = oauth.disconnect(PRIYA, "jira", actor=str(PRIYA))

    assert outcome == {"disconnected": True, "revoked_upstream": False}
    assert storage.active().find_connection(
        TEST_TENANT, "user", "u_priya", "jira"
    ) is None

    # And the failure is recorded rather than swallowed, which is what makes "is that
    # token still live at Atlassian" answerable.
    record = [
        r
        for r in storage.active().admin_audit_records(TEST_TENANT)
        if r["action"] == "connection.delete"
    ][-1]
    assert record["detail"]["revoked_upstream"] is False


def test_disconnecting_a_static_credential_reports_nobody_to_tell(jira):
    """`null`, not `false`. A pasted PAT can be revoked by nobody but its owner."""
    connections.connect_account(PRIYA, "jira", "pasted", actor=TEST_ACTOR)

    outcome = oauth.disconnect(PRIYA, "jira", actor=str(PRIYA))

    assert outcome == {"disconnected": True, "revoked_upstream": None}


def test_disconnecting_something_unconnected_is_not_an_error(jira):
    outcome = oauth.disconnect(PRIYA, "jira", actor=str(PRIYA))
    assert outcome["disconnected"] is False


# --- egress, and the second kind of outbound connection --------------------------------


def test_a_token_endpoint_on_an_unapproved_host_cannot_be_configured(isolated_storage):
    """Finding 7. The token endpoint is an SSRF primitive with a friendly form in front."""
    tools.register_connector(
        TEST_TENANT, "jira", url=f"https://{TEST_HOST}/mcp", actor=TEST_ACTOR
    )

    with pytest.raises(tools.mcp.EgressRefused):
        oauth.configure(
            TEST_TENANT,
            "jira",
            authorize_endpoint="https://evil.example.com/authorize",
            token_endpoint="https://evil.example.com/token",
            client_id="c",
            client_secret="s",
            actor=TEST_ACTOR,
        )

    assert storage.active().get_connector_oauth(TEST_TENANT, "jira") is None


def test_revoking_the_host_stops_the_token_endpoint_being_dialled(jira, provider):
    """The dial-time check is the load-bearing one: a stored row outlives its approval."""
    connect(PRIYA, provider)
    expire(PRIYA)
    storage.active().revoke_host(TEST_TENANT, TEST_HOST, actor=TEST_ACTOR)
    before = len(provider.token_calls)

    with pytest.raises(tools.mcp.EgressRefused):
        oauth.refresh_connection(PRIYA, "jira")

    assert len(provider.token_calls) == before


def test_a_plain_http_authorization_server_is_refused(isolated_storage):
    """The client secret and the authorization code both travel over these.

    Two fences since 063, both asserted. Egress refuses the dial itself first (its
    https rule covers every connector URL); and even a host the operator has named
    internal — where egress lets plain http through for ordinary connectors — keeps
    the storage layer's own unconditional refusal for OAUTH endpoints, because a code
    exchange on a clear wire is not a thing an internal network makes acceptable.
    """
    from carnet.tools.mcp import egress

    tools.register_connector(
        TEST_TENANT, "jira", url=f"https://{TEST_HOST}/mcp", actor=TEST_ACTOR
    )

    with pytest.raises(egress.EgressRefused, match="https"):
        oauth.configure(
            TEST_TENANT,
            "jira",
            authorize_endpoint=f"http://{TEST_HOST}/authorize",
            token_endpoint=f"http://{TEST_HOST}/token",
            client_id="c",
            client_secret="s",
            actor=TEST_ACTOR,
        )


def test_even_an_internal_host_may_not_exchange_codes_over_http(
    isolated_storage, monkeypatch
):
    from carnet import config
    from carnet.tools.mcp import egress  # noqa: F401 - the fence under test is storage's

    monkeypatch.setattr(config, "EGRESS_INTERNAL_HOSTS", frozenset({TEST_HOST}))
    tools.register_connector(
        TEST_TENANT, "jira", url=f"https://{TEST_HOST}/mcp", actor=TEST_ACTOR
    )

    with pytest.raises(storage.StorageError, match="https"):
        oauth.configure(
            TEST_TENANT,
            "jira",
            authorize_endpoint=f"http://{TEST_HOST}/authorize",
            token_endpoint=f"http://{TEST_HOST}/token",
            client_id="c",
            client_secret="s",
            actor=TEST_ACTOR,
        )


def test_a_public_client_is_refused(isolated_storage):
    """Decision 1. No secret means the exchange could only happen in the browser."""
    tools.register_connector(
        TEST_TENANT, "jira", url=f"https://{TEST_HOST}/mcp", actor=TEST_ACTOR
    )

    with pytest.raises(oauth.OAuthRefused, match="client secret"):
        oauth.configure(
            TEST_TENANT,
            "jira",
            authorize_endpoint=AUTHORIZE,
            token_endpoint=TOKEN,
            client_id="c",
            client_secret="",
            actor=TEST_ACTOR,
        )


def test_a_consent_flow_needs_a_connector_that_exists(isolated_storage):
    """And the refusal is **not** a `StorageError`, which is the half that matters.

    `set_connector_oauth` raises `NoSuchConnectorError` for this, and that reached
    `configure` unwrapped until 12c gave it an HTTP caller. Every `StorageError` is a 503,
    so an administrator naming a connector they had not registered yet would have been
    told *"storage unavailable: try again later"* about a connector that will never exist
    until they create it — 011's `NoSuchGroupError` bug, arriving through a route that did
    not exist when that reasoning was written.

    So the class is asserted, and its *non*-membership of `StorageError` with it. The
    second assertion is the one that survives somebody making `OAuthRefused` a
    `StorageError` subclass for convenience.
    """
    with pytest.raises(oauth.OAuthRefused, match="--add-connector") as refusal:
        oauth.configure(
            TEST_TENANT,
            "ghost",
            authorize_endpoint=AUTHORIZE,
            token_endpoint=TOKEN,
            client_id="c",
            client_secret="s",
            actor=TEST_ACTOR,
        )

    assert not isinstance(refusal.value, storage.StorageError)


def test_a_stdio_connector_may_not_hold_a_consent_flow(isolated_storage, vetted_github):
    """Finding 3's guard, **at the seam rather than in the entry point**.

    This check spent 7b in `cli._set_oauth`, where it had no test at all — verified once
    by hand, and invisible to the suite for two whole steps. 12c gave `configure` a second
    caller and the guard had to come down with it, because a route calling `configure`
    directly would let an administrator configure a consent flow on a connector that can
    never use one: somebody completes a screen at a third party, granting real access, for
    a credential this platform could not present.

    `github-mcp` is the case, and it is the only case that can still occur — a connector a
    customer registers has been HTTP-only since 012, so this bites exactly the connectors
    that ship with the platform, which is where a half-configured state would be hardest
    to explain.

    **Nothing is written**, and that is asserted rather than assumed: the refusal comes
    before the secret is read and before the egress check, so a refused request is one in
    which no secret was handled at all.
    """
    with pytest.raises(oauth.OAuthRefused, match="speaks stdio") as refusal:
        oauth.configure(
            TEST_TENANT,
            vetted_github.id,
            authorize_endpoint=AUTHORIZE,
            token_endpoint=TOKEN,
            client_id="client-abc",
            client_secret=CLIENT_SECRET,
            actor=TEST_ACTOR,
        )

    assert not isinstance(refusal.value, storage.StorageError)
    assert oauth.configured(TEST_TENANT) == {}


def test_a_connector_with_no_consent_flow_says_what_to_do(isolated_storage):
    tools.register_connector(
        TEST_TENANT, "jira", url=f"https://{TEST_HOST}/mcp", actor=TEST_ACTOR
    )

    with pytest.raises(oauth.OAuthRefused, match="--set-oauth"):
        oauth.begin(PRIYA, "jira", redirect_uri=REDIRECT)


# --- the open redirect, which is the one thing return_to could be ----------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "https://evil.example.com",
        "//evil.example.com",
        "/\\evil.example.com",
        "http://evil.example.com/x",
    ],
)
def test_return_to_may_not_leave_this_application(jira, provider, hostile):
    """`return_to` becomes a Location header. An absolute URL there is a phishing primitive.

    The parametrised list is the list of things somebody would try, which is the shape
    `test_some_hosts_may_never_be_dialled_even_if_approved` uses and the reason the
    legacy-loopback bug in 012 was found at all. `//` and `/\\` are the two that get past
    a check for *"starts with a slash"*, and every browser treats both as absolute.
    """
    with pytest.raises(oauth.OAuthRefused, match="return_to"):
        oauth.begin(PRIYA, "jira", redirect_uri=REDIRECT, return_to=hostile)

    # And the storage layer refuses it independently, which is the half that is
    # load-bearing: `begin` raising `OAuthRefused` is so the route answers 400 instead of
    # 503, and a check that only lived there would be a check a second writer skips.
    with pytest.raises(storage.StorageError, match="return_to"):
        storage.active().create_pending_authorization(
            "s" * 43,
            TEST_TENANT,
            principal_kind="user",
            principal_id="u_priya",
            connector_id="jira",
            code_verifier=b"sealed",
            key_id="k1",
            redirect_uri=REDIRECT,
            return_to=hostile,
        )


def test_a_path_within_the_app_is_fine(jira, provider):
    url = oauth.begin(
        PRIYA, "jira", redirect_uri=REDIRECT, return_to="/agents/triage-bot"
    )
    row = storage.active().consume_pending_authorization(
        url.split("state=")[1].split("&")[0]
    )
    assert row["return_to"] == "/agents/triage-bot"


# --- the sealed client secret ----------------------------------------------------------


def test_the_client_secret_is_sealed_and_bound_to_its_connector(jira):
    """`crypto.oauth_app_aad`. A primary key has no opinion about a copied value."""
    row = storage.active().get_connector_oauth(TEST_TENANT, "jira")

    assert CLIENT_SECRET.encode() not in row["client_secret"]
    assert (
        crypto.open_(
            row["client_secret"],
            tenant_id=TEST_TENANT,
            aad=crypto.oauth_app_aad(TEST_TENANT, "jira"),
            key_id=row["key_id"],
        )
        == CLIENT_SECRET
    )

    # The same ciphertext under another connector's identity does not open.
    with pytest.raises(crypto.UndecryptableError):
        crypto.open_(
            row["client_secret"],
            tenant_id=TEST_TENANT,
            aad=crypto.oauth_app_aad(TEST_TENANT, "github-mcp"),
            key_id=row["key_id"],
        )


def test_listing_oauth_configuration_never_returns_the_secret(jira):
    """`OAUTH_APP_PUBLIC_FIELDS`, enforced by the method rather than by remembering."""
    rows = oauth.configured(TEST_TENANT)

    assert "client_secret" not in rows["jira"]
    assert rows["jira"]["client_id"] == "client-abc"
    assert rows["jira"]["scopes"] == ["read:jira-work", "offline_access"]


def test_removing_a_consent_flow_leaves_the_credentials_alone(jira, provider):
    """Migration 021's argument, applied to the other direction.

    Deleting configuration must not destroy evidence that somebody consented.
    """
    connect(PRIYA, provider)

    assert oauth.unconfigure(TEST_TENANT, "jira", actor=TEST_ACTOR) is True

    assert storage.active().find_connection(TEST_TENANT, "user", "u_priya", "jira")
    assert (
        credentials.for_connector("jira", PRIYA, identity="user").value
        == f"{ACCESS_TOKEN}-1"
    )


# --- a refresh token's expiry, which every provider spells differently -----------------


@pytest.mark.parametrize(
    "field,provider",
    [
        ("refresh_token_expires_in", "GitHub"),
        ("refresh_expires_in", "Keycloak / Okta"),
    ],
)
def test_a_refresh_tokens_expiry_is_read_whichever_way_it_is_spelled(
    jira, monkeypatch, field, provider
):
    """RFC 6749 defines `expires_in` and says nothing about the refresh token's lifetime.

    So every provider that volunteers it invented a field name, and reading only one of
    them is a **silent wrong answer** rather than a missing feature: the column stays
    NULL and "this connection needs reconnecting in six months" becomes unpredictable,
    with nothing recording that the provider actually told us.

    This read `refresh_expires_in` alone and would have stored NULL against **GitHub** —
    which is the most likely real provider this will meet, and the one whose refresh-token
    rotation makes it worth testing against at all. Parametrised over both spellings,
    which is the shape `test_some_hosts_may_never_be_dialled_even_if_approved` uses: the
    list is the list of things a real provider actually sends.
    """
    fake = FakeProvider()
    original = fake.__call__

    def with_refresh_expiry(url, form, *, auth, want_body=False):
        status, payload = original(url, form, auth=auth, want_body=want_body)
        if isinstance(payload, dict) and "access_token" in payload:
            payload[field] = 15897600  # six months, which is what GitHub sends
        return status, payload

    monkeypatch.setattr(oauth, "_post_form", with_refresh_expiry)

    connect(PRIYA, fake)

    row = stored(PRIYA)["row"]
    assert row["refresh_expires_at"] is not None, (
        f"{provider} sends '{field}' and it was dropped"
    )
    # Six months out, give or take the second this test took to run.
    assert row["refresh_expires_at"] > datetime.now(timezone.utc) + timedelta(days=180)


def _provider_that(monkeypatch, *, rotate, lifetime_on):
    """A fake whose refresh-token *lifetime* is volunteered on chosen exchanges only.

    `lifetime_on` is a set of 1-based exchange numbers. Real providers behave this way:
    the lifetime is part of the consent response and most servers do not repeat it on
    every renewal, because from their side nothing about the token changed.
    """
    fake = FakeProvider(rotate=rotate)
    original = fake.__call__
    seen = {"n": 0}

    def provider(url, form, *, auth, want_body=False):
        status, payload = original(url, form, auth=auth, want_body=want_body)
        if isinstance(payload, dict) and "access_token" in payload:
            seen["n"] += 1
            if not rotate and seen["n"] == 1:
                # A non-rotating provider still issues the first refresh token; what it
                # omits is a *new* one on every renewal afterwards.
                payload["refresh_token"] = REFRESH_TOKEN
            if seen["n"] in lifetime_on:
                payload["refresh_token_expires_in"] = 15897600  # six months, GitHub's
        return status, payload

    monkeypatch.setattr(oauth, "_post_form", provider)
    return fake


def test_a_refresh_that_keeps_the_token_keeps_its_expiry(jira, monkeypatch):
    """**A defect found by testing the field 035f had just put on a screen.**

    `update_connection_credential` writes `refresh_expires_at` unconditionally, and
    `_tokens_from` reads it from whatever the *current* response said. So a provider that
    answered *how long does this refresh token live* at consent time and stayed quiet on
    the renewal — which is what a non-rotating server does, because from its side nothing
    changed — had that answer erased on the first refresh, **while the refresh token
    itself was byte-identical**.

    Invisible until 035f, because nothing read the column. Visible immediately after it:
    the Connections page said *"this connection lapses on 26 February"* and the sentence
    disappeared after the next run, with no event behind its disappearance.

    The fix is `account_label`'s `COALESCE` and its argument — *"overwriting a verified
    label with '' because the provider stayed quiet would lose the only thing on this row
    a person recognises"* — applied to the branch where the credential did not change.
    """
    fake = _provider_that(monkeypatch, rotate=False, lifetime_on={1})

    connect(PRIYA, fake)
    before = stored(PRIYA)
    assert before["row"]["refresh_expires_at"] is not None

    refreshed = oauth.refresh_connection(PRIYA, "jira", force=True)
    after = stored(PRIYA)

    assert refreshed is True
    # The premise: this is the *same* credential, so the fact about it still holds.
    assert after["credential"]["refresh"] == before["credential"]["refresh"]
    assert after["row"]["refresh_expires_at"] == before["row"]["refresh_expires_at"]
    # And the access token really was renewed, so this is not a refresh that did nothing.
    assert after["credential"]["access"] != before["credential"]["access"]


def test_a_refresh_that_rotates_the_token_does_NOT_carry_the_old_expiry(jira, monkeypatch):
    """The other half, and it is why the fix above is one branch rather than a `COALESCE`.

    A rotating provider issues a **different** refresh token. The expiry the row held
    described the one that has just been spent, so carrying it forward would be a
    confident claim about a credential that no longer exists — worse than null, because
    null on this column already means the honest thing: *the provider did not say*.

    Atlassian, Google and Okta all rotate, so this is the common path and the one where
    a naive `COALESCE` would have shipped a wrong date to a screen.
    """
    fake = _provider_that(monkeypatch, rotate=True, lifetime_on={1})

    connect(PRIYA, fake)
    before = stored(PRIYA)
    assert before["row"]["refresh_expires_at"] is not None

    oauth.refresh_connection(PRIYA, "jira", force=True)
    after = stored(PRIYA)

    assert after["credential"]["refresh"] != before["credential"]["refresh"]
    assert after["row"]["refresh_expires_at"] is None


def test_a_provider_that_repeats_the_lifetime_gets_the_newer_one(jira, monkeypatch):
    """A fresh answer always wins over a kept one, whichever branch it arrives in.

    Asserted because the fix is an `or`, and an `or` that read the stored value first
    would pin a connection to the first lifetime it was ever told — a connection that
    could never learn its own extension.
    """
    fake = _provider_that(monkeypatch, rotate=False, lifetime_on={1, 2})

    connect(PRIYA, fake)
    before = stored(PRIYA)["row"]["refresh_expires_at"]

    oauth.refresh_connection(PRIYA, "jira", force=True)
    after = stored(PRIYA)["row"]["refresh_expires_at"]

    assert after is not None
    # Six months from *this* exchange rather than from the first, so it moved forward.
    assert after > before


def test_a_connection_that_never_knew_its_lifetime_still_does_not(jira, monkeypatch):
    """Null in, null out. The overwhelmingly common configuration — Atlassian's 90 days
    and Google's indefinite tokens are both silence — and the fix must not invent one."""
    fake = _provider_that(monkeypatch, rotate=False, lifetime_on=set())

    connect(PRIYA, fake)
    assert stored(PRIYA)["row"]["refresh_expires_at"] is None

    oauth.refresh_connection(PRIYA, "jira", force=True)

    assert stored(PRIYA)["row"]["refresh_expires_at"] is None


def test_reconnecting_replaces_the_lifetime_rather_than_keeping_it(jira, monkeypatch):
    """A **reconnection** is not a refresh, and the kept-expiry rule must not reach it.

    `save_connection` writes the row from the consent response outright — a new grant, a
    new refresh token, and whatever the provider said about it this time, including
    nothing. Keeping a lapse date across a re-consent would attach an old grant's
    lifetime to a new grant, which is the same wrong claim as the rotating branch above.
    """
    fake = _provider_that(monkeypatch, rotate=True, lifetime_on={1})

    connect(PRIYA, fake)
    assert stored(PRIYA)["row"]["refresh_expires_at"] is not None

    # A second consent flow, and this time the provider volunteers nothing.
    connect(PRIYA, fake)

    assert stored(PRIYA)["row"]["refresh_expires_at"] is None


def test_a_refresh_that_loses_the_race_changes_no_expiry(jira, monkeypatch):
    """The compare-and-set path, at the field 035f reads.

    A refresh whose `updated_at` precondition fails writes nothing and returns False —
    and must leave the winner's lapse date alone rather than half-applying its own.
    """
    fake = _provider_that(monkeypatch, rotate=False, lifetime_on={1})
    connect(PRIYA, fake)

    store = storage.active()
    row = store.find_connection(TEST_TENANT, PRIYA.kind, PRIYA.id, "jira")

    lost = store.update_connection_credential(
        TEST_TENANT, PRIYA.kind, PRIYA.id, "jira",
        ciphertext=b"someone-elses", key_id="k9",
        expires_at=None, refresh_expires_at=None,
        if_updated_at=row["updated_at"] - timedelta(seconds=1),
    )

    assert lost is None
    after = store.find_connection(TEST_TENANT, PRIYA.kind, PRIYA.id, "jira")
    assert after["refresh_expires_at"] == row["refresh_expires_at"]
    assert after["updated_at"] == row["updated_at"]


# --- provider-specific authorize parameters (migration 025) ---------------------------


def test_a_provider_that_needs_extra_parameters_gets_them(isolated_storage):
    """Atlassian mandates `audience` and `prompt`, and `begin` builds neither.

    The real consent flow in this step worked **only** because `begin` picks its separator
    based on whether the endpoint already has a query string, so an administrator could
    smuggle them onto the endpoint itself. That is a URL wearing an endpoint's name, and it
    survived validation by accident. The first real provider we pointed at needed it, so
    they get a column.
    """
    tools.register_connector(
        TEST_TENANT, "jira", url=f"https://{TEST_HOST}/mcp", actor=TEST_ACTOR
    )
    oauth.configure(
        TEST_TENANT, "jira",
        authorize_endpoint=AUTHORIZE, token_endpoint=TOKEN,
        client_id="client-abc", client_secret=CLIENT_SECRET,
        scopes=("read:jira-work",),
        authorize_params={"audience": "api.atlassian.com", "prompt": "consent"},
        actor=TEST_ACTOR,
    )

    url = oauth.begin(PRIYA, "jira", redirect_uri=REDIRECT)

    assert "audience=api.atlassian.com" in url
    assert "prompt=consent" in url
    # And still everything it always sent.
    assert "response_type=code" in url and "code_challenge_method=S256" in url


@pytest.mark.parametrize(
    "name",
    ["state", "redirect_uri", "client_id", "response_type", "code_challenge", "scope"],
)
def test_a_stored_row_may_not_supply_what_the_flow_builds_itself(isolated_storage, name):
    """The reason this is a validated mapping rather than a dict. Migration 025.

    Two of these are the security design rather than tidiness. **`state`** is the only
    thing binding a provider's callback to the person who started it — the callback is a
    top-level navigation carrying no token — so a row that could fix it to a known value
    would make every consent flow in the tenant forgeable. **`redirect_uri`** decides
    where somebody's authorization code is delivered, and a row that could redirect it is
    a stolen grant, held back only by the provider validating strictly on their side.
    """
    tools.register_connector(
        TEST_TENANT, "jira", url=f"https://{TEST_HOST}/mcp", actor=TEST_ACTOR
    )

    with pytest.raises(storage.StorageError, match=name):
        oauth.configure(
            TEST_TENANT, "jira",
            authorize_endpoint=AUTHORIZE, token_endpoint=TOKEN,
            client_id="client-abc", client_secret=CLIENT_SECRET,
            authorize_params={name: "hijacked"},
            actor=TEST_ACTOR,
        )

    assert storage.active().get_connector_oauth(TEST_TENANT, "jira") is None


def test_the_flows_own_parameters_win_even_if_a_row_carries_one(jira, provider):
    """The second lock on the same door, for a row some future path wrote unvalidated.

    `normalize_authorize_params` refuses these at the front door, so this can only happen
    through a write that skipped it. Asserted anyway, because the failure is silent: a
    consent flow whose `state` came from configuration would look completely normal right
    up until somebody else completed a connection with it.
    """
    row = storage.active().get_connector_oauth(TEST_TENANT, "jira")
    # Straight into the store, bypassing the validator, as a rogue writer would.
    row = dict(row, authorize_params={"state": "attacker-chosen", "redirect_uri": "https://evil"})
    monkey = lambda tenant_id, connector_id: row  # noqa: E731
    original = storage.active().get_connector_oauth
    storage.active().get_connector_oauth = monkey
    try:
        url = oauth.begin(PRIYA, "jira", redirect_uri=REDIRECT)
    finally:
        storage.active().get_connector_oauth = original

    assert "state=attacker-chosen" not in url
    assert "evil" not in url
    assert REDIRECT.replace(":", "%3A").replace("/", "%2F") in url


def test_the_parameters_are_recorded_in_the_administrative_log(jira):
    """Not a secret — they end up in an address bar — and this is where "what did we ask
    this provider for" should be answerable."""
    oauth.configure(
        TEST_TENANT, "jira",
        authorize_endpoint=AUTHORIZE, token_endpoint=TOKEN,
        client_id="client-abc", client_secret=CLIENT_SECRET,
        authorize_params={"audience": "api.atlassian.com"},
        actor=TEST_ACTOR,
    )

    record = [
        r for r in storage.active().admin_audit_records(TEST_TENANT)
        if r["action"] == "connector.oauth.configure"
    ][-1]
    assert record["detail"]["authorize_params"] == {"audience": "api.atlassian.com"}


def test_a_callback_with_no_code_is_refused_before_anything_is_spent(jira, provider):
    """A provider returns a code **or** an error. Neither means the redirect was mangled.

    Found by driving the callback at its edges: without this, `state` was consumed and an
    empty `code` was POSTed to the provider — an outbound request already known to be
    nonsense, whose refusal was then reported as though the provider had decided
    something.

    **And the state survives**, unlike an expired one. A truncated redirect is somebody
    else's accident; burning their pending row over it turns a recoverable problem into an
    unrecoverable one.
    """
    url = oauth.begin(PRIYA, "jira", redirect_uri=REDIRECT)
    state = url.split("state=")[1].split("&")[0]
    before = len(provider.token_calls)

    with pytest.raises(oauth.OAuthRefused, match="without an authorization code"):
        oauth.complete(state, "")

    assert len(provider.token_calls) == before, "it reached the provider anyway"
    assert storage.active().consume_pending_authorization(state) is not None
