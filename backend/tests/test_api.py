"""The HTTP entry point.

Three things here are worth more than the route coverage.

**Every endpoint is `def`, not `async def`** — asserted by walking the route table
rather than by trusting a docstring. An `async def` endpoint calling `broker.call`
blocks the event loop, and the symptom is not a slow request but a server that stops
answering under load while every individual piece looks correct.

**The tenant is never a parameter.** Every route takes it off the `Principal`, and
there is no path or query through which a caller can name one.

**Requests carry a real signed token.** Minted here against a locally generated key and
routed through the same `access/` code a production request goes through — there is no
test-only authentication path, because the fake would be the thing under test. The
`X-Dev-Principal` header that used to do this job is gone, and one test below fails if
it is ever honoured again.

The tests run against the app WITHOUT its lifespan, so the store stays the per-test
in-memory one from `conftest`.
"""

import inspect
import json
import pathlib
import time

import pytest

# Both are optional extras, like psycopg. CI installs them and fails if these skip.
pytest.importorskip("fastapi", reason="install the 'api' extra to run these")
pytest.importorskip("jwt", reason="install the 'access' extra to run these")

import jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from carnet import agents, bootstrap, config, door, storage, tools  # noqa: E402
from carnet.access import oidc, providers  # noqa: E402
from carnet.access.oidc import JwksCache  # noqa: E402
from carnet.api import create_app, deps  # noqa: E402
from carnet.api.schemas import AgentDraft  # noqa: E402
from carnet.tools import mcp  # noqa: E402

from carnet.access import grants
from carnet.core import Principal

from conftest import TEST_TENANT

OTHER_TENANT = "t-other"

ISSUER = "https://acme.okta.example"
AUDIENCE = "api://default"

AGENT = {
    "name": "demo",
    "system": "You are a demo agent.",
    "permissions": {
        "tools": ["post_message"],
        "scope": {"chat.channel": {"write": ["#eng"]}},
    },
}


class Idp:
    """One customer's identity provider, with a real signing key."""

    def __init__(self, issuer=ISSUER, audience=AUDIENCE, kid="k1"):
        self.issuer = issuer
        self.audience = audience
        self.kid = kid
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @property
    def jwks_uri(self):
        return f"{self.issuer}/v1/keys"

    def jwk(self):
        entry = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        entry.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return entry

    def token(self, **claims):
        now = int(time.time())
        payload = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": "00u-priya",
            "iat": now,
            "exp": now + 300,
            "email": "priya@acme.com",
        }
        payload.update(claims)
        return jwt.encode(payload, self.key, algorithm="RS256", headers={"kid": self.kid})

    def row(self, **overrides):
        return {
            "issuer": self.issuer,
            "jwks_uri": self.jwks_uri,
            "audience": self.audience,
            "allowed_domains": ("acme.com",),
            **overrides,
        }


@pytest.fixture
def idp():
    return Idp()


@pytest.fixture
def registered(idp, isolated_storage, monkeypatch):
    """`idp` registered for the test tenant, keys reachable without a network.

    The process-wide key cache is replaced per test rather than cleared: one carried
    between tests would serve one test's keys to another, which is the same class of
    mistake `isolated_storage` exists to prevent.
    """
    storage.active().save_tenant_idp(TEST_TENANT, idp.row())
    monkeypatch.setattr(
        providers,
        "KEYS",
        JwksCache(fetch=lambda uri: oidc.keys_from_jwks({"keys": [idp.jwk()]})),
    )
    return idp


@pytest.fixture
def auth(registered):
    """Headers for a genuine, signed request."""
    return {"Authorization": f"Bearer {registered.token()}"}


@pytest.fixture
def client():
    """A client that does NOT run the lifespan.

    Deliberate: the lifespan calls `bootstrap.configure`, which would replace the
    per-test store with a seeded one and make every assertion below depend on the
    shipped example agent.
    """
    return TestClient(create_app())


def logged_in_id(client, headers, tenant_id=TEST_TENANT):
    """The principal id these headers authenticate as, creating them if it is their
    first request.

    A user does not exist until they log in — the row is keyed `(issuer, subject)` and
    the subject only arrives inside a token — so there is no id to grant to until a
    request has been made. Hence the request first, then the lookup. That gap is what
    `pending_grants` exists to close for a real person sharing by address; here it is
    closed by logging in, because these tests know the token.

    Resolved by the token's own email rather than `list_users(...)[0]`, which was fine
    while every test had one user and silently grants to the wrong person the moment one
    has two.
    """
    client.get("/agents", headers=headers)
    email = jwt.decode(
        headers["Authorization"].removeprefix("Bearer "),
        options={"verify_signature": False},
    )["email"]
    return storage.active().find_user_by_email(tenant_id, email)["id"]


def submit(client, headers, agent="demo", task="x", json_extra=None, **kwargs):
    """`POST /runs`. Returns the response, which is now a 202 and holds no answer.

    `json_extra` merges into the body — step 028 added `file_id`, and threading a named
    parameter per field would mean editing this helper for every one.
    """
    body = {"agent": agent, "task": task, **(json_extra or {})}
    return client.post("/runs", json=body, headers=headers, **kwargs)


def share_with_caller(client, headers, agent_name, tenant_id=TEST_TENANT, role="owner"):
    """Grant `agent_name` to whoever `headers` authenticate as.

    A test that saves an agent and then asks for it needs this now. That is not
    ceremony — it is the same two steps a real person takes, and a test that forgets it
    gets a 404 rather than a pass, which is exactly the behaviour under test.
    """
    storage.active().grant_agent(
        tenant_id,
        agent_name,
        "user",
        logged_in_id(client, headers, tenant_id),
        role=role,
        actor="system:cli",
    )


@pytest.fixture
def unshared_agent():
    """An agent that exists and has been shared with nobody — the state every agent is
    in the moment it is created, and the one migration 011 moved existing rows out of."""
    agents.save(TEST_TENANT, AGENT, actor="system:cli")
    return AGENT


@pytest.fixture
def demo_agent(client, auth, unshared_agent):
    """The demo agent, owned by whoever `auth` authenticates as.

    Every test below that expects to see or run an agent needs this now, which is the
    visible cost of enforcement and the point of it: an agent shared with nobody is an
    agent nobody can reach, including in a test that forgot.
    """
    share_with_caller(client, auth, AGENT["name"])
    return unshared_agent


# --- the rules that make this work at all -----------------------------------------


def _flatten(routes):
    """Every route, through whatever wrappers `include_router` produced.

    **This was `app.routes` and that is a bug this file shipped with.** FastAPI 0.141
    keeps an included router as a single `_IncludedRouter` object in `app.routes` rather
    than splicing its routes in, and `_IncludedRouter` has no `.endpoint` — so the filter
    below dropped **every route this package defines** and kept `/health`. Three
    assertions about the route table were therefore checking one route each: that every
    endpoint is `def`, that no route takes a tenant from the caller, and (added in 10d)
    that there is no group-administration route.

    Found by printing the route table while checking 10d's URLs, not by a test — which is
    this project's eighth entry in that column, and the first where the thing that was
    quietly wrong was a test rather than the product.

    Recursive, and it looks for a nested route list by shape rather than by naming the
    wrapper class: which attribute holds it is a version detail, and the property being
    asserted is not. `test_the_route_table_assertions_can_see_the_route_table` below is
    what makes that safe — if a future version moves it again, that fails loudly instead of
    every route assertion going quiet.
    """
    out = []
    for route in routes:
        if hasattr(route, "endpoint"):
            out.append(route)
            continue
        nested = getattr(route, "routes", None)
        if nested is None:
            inner = getattr(route, "original_router", None)
            nested = getattr(inner, "routes", None)
        if nested:
            out.extend(_flatten(nested))
    return out


def _our_routes():
    """Routes this package defines.

    FastAPI adds `/docs`, `/redoc` and `/openapi.json` itself and they are `async` —
    correctly, since they serve static documentation and never touch the broker. The
    filter is "did we write it", not a hardcoded list of paths FastAPI adds today.
    """
    return [
        route
        for route in _flatten(create_app().routes)
        if getattr(route.endpoint, "__module__", "").startswith("carnet.api")
    ]


def test_the_route_table_assertions_can_see_the_route_table():
    """The guard on the guard, and it exists because the guards were empty.

    `_our_routes()` returned exactly one route — `/health` — on FastAPI 0.141, because an
    included router is one object in `app.routes` and has no `.endpoint`. Every assertion
    below iterates it, so all of them passed by finding nothing.

    A count with a floor rather than an exact number: adding a route must not be a test
    edit, and the failure this catches is the list collapsing rather than growing.
    """
    paths = {route.path for route in _our_routes()}

    assert len(paths) >= 10, f"the route table has collapsed: {sorted(paths)}"
    for expected in ("/agents", "/agents/{name}", "/mcp", "/tools", "/health"):
        assert expected in paths, f"{expected} is missing from {sorted(paths)}"


def test_every_endpoint_is_sync():
    """`def`, not `async def`, so FastAPI runs it in a threadpool and the synchronous
    broker stays synchronous."""
    offenders = [
        route.path
        for route in _our_routes()
        if inspect.iscoroutinefunction(route.endpoint)
    ]

    assert not offenders, (
        f"async def endpoints will block the event loop on broker.call: {offenders}"
    )


def test_no_route_accepts_a_tenant_from_the_caller():
    """The tenant comes off the Principal and nowhere else. A tenant in a path or a
    query is the caller asserting which customer's data to read."""
    for route in _our_routes():
        assert "tenant" not in route.path.lower(), route.path

        parameters = inspect.signature(route.endpoint).parameters
        named = [p for p in parameters if "tenant" in p.lower()]
        assert not named, f"{route.path} takes {named} from the caller"


# --- authentication ---------------------------------------------------------------


def test_the_dev_auth_header_is_gone(client, registered, demo_agent):
    """The bypass is **deleted**, not switched off.

    It was the entire authentication story for one step: any caller could name any
    principal in any tenant. This test fails if it is ever honoured again, and it also
    fails if somebody reintroduces the config flag it used to sit behind.
    """
    response = client.get(
        "/agents",
        headers={"X-Dev-Principal": "user:mallory", "X-Dev-Tenant": TEST_TENANT},
    )

    assert response.status_code == 401
    assert not hasattr(config, "INSECURE_DEV_AUTH")


def test_a_request_with_no_token_is_refused(client):
    response = client.get("/agents")

    assert response.status_code == 401
    assert "bearer" in response.headers.get("WWW-Authenticate", "").lower()


@pytest.mark.parametrize(
    "header", ["", "token abc", "Bearer", "Bearer   ", "Basic abc123"]
)
def test_a_malformed_authorization_header_is_refused(client, header):
    assert client.get("/agents", headers={"Authorization": header}).status_code == 401


def test_a_token_from_an_unregistered_issuer_is_refused(client, registered):
    stranger = Idp(issuer="https://evil.example")

    response = client.get(
        "/agents", headers={"Authorization": f"Bearer {stranger.token()}"}
    )

    assert response.status_code == 401


def test_a_forged_token_is_refused(client, registered):
    """Right issuer, right audience, right shape — wrong key."""
    impostor = Idp(issuer=ISSUER)

    response = client.get(
        "/agents", headers={"Authorization": f"Bearer {impostor.token()}"}
    )

    assert response.status_code == 401


def test_an_expired_token_says_so(client, registered):
    """The one distinction surfaced to a client, because it can act on it: refresh
    and retry, rather than prompting somebody who is already signed in."""
    expired = registered.token(exp=int(time.time()) - 3600)

    response = client.get("/agents", headers={"Authorization": f"Bearer {expired}"})

    assert response.status_code == 401
    assert "expired" in response.json()["detail"]


def test_a_token_for_another_application_is_refused(client, registered):
    """Genuine, unexpired, signed by the right provider — minted for a different app
    on the same Okta."""
    other_app = registered.token(aud="some-other-client-id")

    response = client.get("/agents", headers={"Authorization": f"Bearer {other_app}"})

    assert response.status_code == 401


def test_a_refusal_does_not_say_which_half_was_wrong(client, registered):
    """Telling an attacker whether the signature or the audience failed is free help.
    The reason goes to the log; the caller gets one sentence."""
    forged = Idp(issuer=ISSUER).token()

    detail = client.get(
        "/agents", headers={"Authorization": f"Bearer {forged}"}
    ).json()["detail"]

    assert detail == "not a valid token for this service"


def test_an_unlisted_domain_is_403_not_401(client, registered):
    """Genuinely authenticated and still not allowed. A 401 would send a UI round a
    login loop that cannot succeed."""
    contractor = registered.token(email="someone@elsewhere.example")

    response = client.get("/agents", headers={"Authorization": f"Bearer {contractor}"})

    assert response.status_code == 403
    assert "domain" in response.json()["detail"]


def test_health_needs_no_auth(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_health_says_what_version_is_running(client):
    """027. The one surface that answers "what are you running" from outside.

    Asserted against the module attribute rather than a literal, so bumping the version
    is one edit rather than two — the same reason `pyproject.toml` reads it too.
    """
    import carnet

    body = client.get("/health").json()

    assert body["version"] == carnet.__version__
    assert body["version"] != ""


def test_readiness_needs_no_auth_and_names_its_ground(client):
    """056. The readiness sibling of /health: one real round trip through the store.

    Against the in-memory store this suite runs on, ready is trivially true — the
    interesting half here is the shape: no auth, `status: ready`, and `storage`
    naming which ground the round trip touched.
    """
    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "storage": "memory"}


def test_readiness_goes_red_while_liveness_stays_green(client, monkeypatch):
    """056's pair, asserted as a pair against one broken store.

    Liveness answering through a storage outage is /health's one documented property;
    readiness 503ing with the store's own sentence is the property this step adds.
    Asserting them together is the point — two probes that cannot diverge would be
    one probe wearing two names.
    """
    from carnet import storage

    def refuse(self):
        raise storage.StorageError("the database did not answer: the test says so")

    monkeypatch.setattr(type(storage.active()), "ping", refuse)

    ready = client.get("/health/ready")
    live = client.get("/health")

    assert ready.status_code == 503
    assert "did not answer" in ready.json()["detail"]
    assert live.status_code == 200


# --- the tenant comes from our row ------------------------------------------------


def test_the_tenant_comes_from_the_provider_row(client, auth, demo_agent):
    """A token carrying a conflicting tenant claim reaches the tenant its **issuer**
    is registered to, and nowhere else."""
    storage.active().create_tenant(OTHER_TENANT, "Other")
    agents.save(OTHER_TENANT, {**AGENT, "name": "theirs"}, actor="system:cli")

    body = client.get("/agents", headers=auth).json()

    assert [a["name"] for a in body] == ["demo"]


def test_a_claim_cannot_move_somebody_to_another_tenant(client, registered, demo_agent):
    """The decision the whole design turns on: reading an organisation id out of the
    token would make a mis-mapped claim in somebody else's admin console a
    cross-tenant read here."""
    storage.active().create_tenant(OTHER_TENANT, "Other")
    agents.save(OTHER_TENANT, {**AGENT, "name": "theirs"}, actor="system:cli")

    token = registered.token(tid=OTHER_TENANT, org_id=OTHER_TENANT, tenant=OTHER_TENANT)
    body = client.get("/agents", headers={"Authorization": f"Bearer {token}"}).json()

    assert [a["name"] for a in body] == ["demo"]


def test_two_customers_on_one_issuer_see_their_own_agents(client, isolated_storage, monkeypatch):
    """Google Workspace: one issuer, one key, one audience, two customers."""
    store = storage.active()
    store.create_tenant(OTHER_TENANT, "Other")

    google = Idp(issuer="https://accounts.google.example", audience="123.apps.example")
    store.save_tenant_idp(
        TEST_TENANT, google.row(discriminator_claim="hd", discriminator_value="acme.com")
    )
    store.save_tenant_idp(
        OTHER_TENANT,
        google.row(
            discriminator_claim="hd",
            discriminator_value="globex.com",
            allowed_domains=("globex.com",),
        ),
    )
    monkeypatch.setattr(
        providers,
        "KEYS",
        JwksCache(fetch=lambda uri: oidc.keys_from_jwks({"keys": [google.jwk()]})),
    )

    agents.save(TEST_TENANT, AGENT, actor="system:cli")
    agents.save(OTHER_TENANT, {**AGENT, "name": "theirs"}, actor="system:cli")

    acme = {"Authorization": f"Bearer {google.token(hd='acme.com')}"}
    globex = {
        "Authorization": f"Bearer {google.token(hd='globex.com', sub='00u-bob', email='bob@globex.com')}"
    }
    share_with_caller(client, acme, "demo", TEST_TENANT)
    share_with_caller(client, globex, "theirs", OTHER_TENANT)

    ours = client.get("/agents", headers=acme).json()
    theirs = client.get("/agents", headers=globex).json()

    assert [a["name"] for a in ours] == ["demo"]
    assert [a["name"] for a in theirs] == ["theirs"]


# --- agents -----------------------------------------------------------------------


def test_agents_are_listed_for_the_principals_tenant(client, auth, demo_agent):
    response = client.get("/agents", headers=auth)

    assert response.status_code == 200
    body = response.json()
    assert [a["name"] for a in body] == ["demo"]
    assert body[0]["tools"] == ["post_message"]
    assert body[0]["valid"] is True


def test_a_broken_agent_is_listed_with_its_reason(client, auth):
    """Reported, not omitted. An agent that vanishes from the UI when it breaks is one
    somebody re-creates rather than fixes.

    Shared first: broken and ungranted are two different reasons to be absent, and only
    one of them is meant to be visible with an explanation attached.
    """
    storage.active().save_agent(
        TEST_TENANT,
        {**AGENT, "name": "broken", "permissions": {"tools": ["gone_away"]}},
        actor="system:cli",
    )
    share_with_caller(client, auth, "broken")

    body = client.get("/agents", headers=auth).json()

    broken = [a for a in body if a["name"] == "broken"]
    assert broken, "the broken agent was hidden"
    assert broken[0]["valid"] is False
    assert "gone_away" in broken[0]["error"]


def test_getting_one_agent_shows_capability_and_reach(client, auth, demo_agent):
    response = client.get("/agents/demo", headers=auth)

    assert response.status_code == 200
    body = response.json()
    assert body["tools"] == ["post_message"]
    assert body["scope"] == {"chat.channel": {"write": ["#eng"]}}


def test_an_unknown_agent_is_404(client, auth):
    assert client.get("/agents/nope", headers=auth).status_code == 404


# --- creating one, which is what 10c is -------------------------------------------

DRAFT = {
    "name": "triage-bot",
    "system": "You summarise open issues.",
    "runtime": "simple",
    "permissions": {
        "tools": ["post_message"],
        "scope": {"chat.channel": {"write": ["#eng"]}},
    },
    "limits": {"max_calls": 3, "max_writes": 1},
}


def test_creating_an_agent_is_201_with_its_url(client, auth):
    response = client.post("/agents", json=DRAFT, headers=auth)

    assert response.status_code == 201, response.text
    assert response.headers["Location"] == "/agents/triage-bot"
    assert response.json()["name"] == "triage-bot"


def test_the_creator_owns_it_and_can_use_it_immediately(client, auth):
    """The property four handoffs have warned about, asserted through HTTP rather than
    through the grant table — because "absence is denial" means the symptom of getting
    this wrong is a 404 on the agent you just made."""
    created = client.post("/agents", json=DRAFT, headers=auth).json()

    assert created["owner"] == f"user:{logged_in_id(client, auth)}"
    assert client.get("/agents/triage-bot", headers=auth).status_code == 200
    assert "triage-bot" in [a["name"] for a in client.get("/agents", headers=auth).json()]


def test_the_stored_config_is_the_request_body(client, auth):
    """Decision 1, at the one place it would be most tempting to break. A friendlier
    request shape would be a second definition of what an agent is, and the translator
    between them agrees with the validator only while somebody maintains it."""
    client.post("/agents", json=DRAFT, headers=auth)

    stored = storage.active().get_agent(TEST_TENANT, "triage-bot")
    assert stored["config"] == DRAFT


def test_a_name_that_exists_is_409_and_replaces_nothing(client, auth, registered):
    """`save_agent` is an upsert and is one line away from being what this route calls.

    The second caller is a **different person** on purpose: this is not "you already made
    that", it is "you cannot silently take somebody else's".
    """
    client.post("/agents", json=DRAFT, headers=auth)

    intruder = {"Authorization": f"Bearer {registered.token(sub='00u-mallory', email='mallory@acme.com')}"}
    response = client.post(
        "/agents",
        json={**DRAFT, "system": "Mine now.", "permissions": {"tools": [], "scope": {}}},
        headers=intruder,
    )

    assert response.status_code == 409, response.text
    assert storage.active().get_agent(TEST_TENANT, "triage-bot")["config"] == DRAFT
    # And the 409 did not hand them a foothold either.
    assert client.get("/agents/triage-bot", headers=intruder).status_code == 404


def test_a_name_collision_is_409_and_not_503(client, auth):
    """`AgentNameTaken` subclasses `StorageError`, whose handler answers 503. Starlette
    resolves handlers by walking the MRO, so the subclass wins — and this is the test
    that fails if that registration is ever dropped, because 503 tells a person to try
    again later about something that will never work."""
    client.post("/agents", json=DRAFT, headers=auth)

    assert client.post("/agents", json=DRAFT, headers=auth).status_code == 409


def test_an_invalid_scope_is_422_in_the_validators_own_words(client, auth):
    """The message is the one written to be read at 3am, and the person reading it is
    now at a form."""
    response = client.post(
        "/agents",
        json={**DRAFT, "permissions": {"tools": ["post_message"], "scope": {}}},
        headers=auth,
    )

    assert response.status_code == 422
    assert "chat.channel (write)" in response.json()["detail"]
    assert storage.active().get_agent(TEST_TENANT, "triage-bot") is None


def test_a_name_that_is_not_a_slug_is_422_with_a_sentence(client, auth):
    """Not FastAPI's list-shaped 422. The name rule is the error in this body most likely
    to be read by somebody non-technical, so it is refused by the validator rather than
    by a pattern on the pydantic field."""
    response = client.post("/agents", json={**DRAFT, "name": "Triage Bot"}, headers=auth)

    assert response.status_code == 422
    assert "triage-bot" in response.json()["detail"], "it should say what to type instead"


def test_creating_an_agent_needs_no_grant_but_does_need_a_token(client, auth):
    """Creation is not a permission — there is no platform role to hang one on, and 001
    says agent creation is self-serve. It is still not anonymous."""
    assert client.post("/agents", json=DRAFT).status_code == 401
    assert client.post("/agents", json=DRAFT, headers=auth).status_code == 201


def test_an_unknown_config_key_is_refused(client, auth):
    """`extra="forbid"`. A config with `systen` instead of `system` stores happily today
    and produces an agent that was told nothing — a typo in a key is silent in exactly the
    way a typo in a value is not."""
    response = client.post("/agents", json={**DRAFT, "systen": "oops"}, headers=auth)

    assert response.status_code == 422
    assert storage.active().get_agent(TEST_TENANT, "triage-bot") is None


# --- the dry run ------------------------------------------------------------------


def test_validating_a_draft_writes_nothing(client, auth):
    response = client.post("/agents/validate", json=DRAFT, headers=auth)

    assert response.status_code == 200
    assert response.json() == {"valid": True}
    assert storage.active().get_agent(TEST_TENANT, "triage-bot") is None


def test_an_invalid_draft_is_the_same_422_as_the_create(client, auth):
    """The reason there is no `valid: false` branch. A wizard that renders the dry run
    correctly renders the real thing correctly, and cannot develop a second opinion about
    what an error looks like."""
    bad = {**DRAFT, "permissions": {"tools": ["post_message"], "scope": {}}}

    dry = client.post("/agents/validate", json=bad, headers=auth)
    real = client.post("/agents", json=bad, headers=auth)

    assert dry.status_code == real.status_code == 422
    assert dry.json()["detail"] == real.json()["detail"]


def test_the_dry_run_refuses_the_reserved_name(client, auth):
    """It answers *would create accept this?*, so it has to know everything create knows
    except whether the name is free."""
    response = client.post("/agents/validate", json={**DRAFT, "name": "validate"}, headers=auth)

    assert response.status_code == 422
    assert "reserved" in response.json()["detail"]


def test_the_dry_run_does_not_answer_whether_a_name_is_free(client, auth):
    """Deliberate, and it is the one thing the wizard has to learn from the create.

    A name that is taken is a race whatever asks it and a different status code. Answering
    it here would also make agent-name enumeration a route rather than a side effect.
    """
    client.post("/agents", json=DRAFT, headers=auth)

    assert client.post("/agents/validate", json=DRAFT, headers=auth).status_code == 200
    assert client.post("/agents", json=DRAFT, headers=auth).status_code == 409


# --- the claim the whole chunk rests on --------------------------------------------
#
# *A form that derives its scope from the catalogue cannot violate
# `_validate_scope_matches_tools` in either direction.* That is 010b's finding and it is a
# claim of the form "correct by construction", which is worth exactly the test behind it.
#
# The form is TypeScript and the rule is here, so the assertion is split across the two.
# `frontend/src/lib/draft.test.ts` restates the rule as a set equality and checks every
# subset of the seeded tenant's tools against it, then writes the configs it produced to
# `draft.fixture.json`. This posts those exact bytes at the real validator.
#
# Neither half is sufficient alone: the TypeScript one asserts against a paraphrase of the
# rule, and this one would pass against a fixture somebody hand-wrote to pass. Together
# they say that what the form actually generates is what this server actually accepts.

FIXTURE = (
    pathlib.Path(__file__).resolve().parents[2]
    / "frontend" / "src" / "lib" / "draft.fixture.json"
)


def _fixture():
    if not FIXTURE.exists():  # pragma: no cover - only in a backend-only checkout
        pytest.skip(f"{FIXTURE} is missing — run the frontend suite to generate it")
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture
def seeded(client, auth, isolated_storage):
    """The tenant `--seed` produces, which is the catalogue the fixture was built from."""
    bootstrap.seed_tenant(TEST_TENANT)
    return auth


def test_the_form_and_the_catalogue_have_not_drifted_apart(seeded):
    """Checked before anything is validated, because it is the failure that would
    otherwise make the next test pass for the wrong reason.

    The fixture hardcodes the seeded tenant's tools. Add a tool to the shipped connector
    and every case below still passes — over a catalogue that no longer describes the
    product — until this line fails and says to regenerate.
    """
    assert sorted(_fixture()["tools"]) == sorted(tools.known_names(TEST_TENANT))


def test_the_unread_keys_the_detail_page_names_are_exactly_the_schemas_own(seeded):
    """Step 081, and it is the pin the plan's known limits ask for.

    `AgentDetailPage` renders *Stored, and not read here* over a hardcoded list of config
    keys. That list is a claim about **this** schema — the fields `AgentDraft` accepts
    that the door does not read — and only this side can check it. A seventh field added
    to `AgentDraft` and not added there is stored, unread and invisible in the browser,
    which is precisely the failure step 081 exists to end; this makes it a red build.

    `name` and `permissions` are the two the door does read. `name` is identity rather
    than configuration and `permissions` is the whole of what a config means here.
    """
    accepted = set(AgentDraft.model_fields) - {"name", "permissions"}
    assert sorted(_fixture()["unread"]) == sorted(accepted)


def test_the_list_row_still_promises_a_runtime_key_even_though_it_may_be_null(client):
    """Step 081, and the distinction is the one `ConnectionSummary`'s own test states:
    **required means the key is sent**, not that the value is non-null.

    `AgentSummary.runtime` became nullable here because a config that names no tier must
    not be reported as naming `"simple"`. Giving it a *default* as well would have taken
    it out of the OpenAPI document's `required` list while the server went on sending it
    on every row — a generated client would stop expecting a key it always gets, which is
    a spec that lies in the quiet direction. So it is nullable and required, and the
    request body is the opposite case: there, absence is what a caller sends.
    """
    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    assert "runtime" in schemas["AgentSummary"]["required"]
    assert "runtime" in schemas["AgentDetail"]["required"]
    assert schemas["AgentSummary"]["properties"]["runtime"]["anyOf"] == [
        {"type": "string"},
        {"type": "null"},
    ]
    # And the draft is optional on the way in, which is what stops the server minting one.
    assert "runtime" not in schemas["AgentDraft"]["required"]


def test_a_created_agent_stores_no_runtime_tier(client, seeded):
    """080 section B3. `AgentDraft.runtime` defaulted to `DEFAULT_RUNTIME`, so every agent
    created over HTTP stored `"runtime": "simple"` — a tier from a concept this tree
    deleted — while `bootstrap.py`'s seeded example stored none. The shipped example and
    an API-created agent therefore disagreed about the shape of a config, which is the
    drift 021's version history exists to make visible and 010d's merge exists to survive.

    Accepting one somebody sends is still right, and the second half asserts it: a config
    authored for a tree that has a runtime round-trips intact.
    """
    body = {"name": "no-tier", "permissions": {"tools": [], "scope": {}}}
    assert client.post("/agents", json=body, headers=seeded).status_code == 201

    stored = agents.get(TEST_TENANT, "no-tier")
    assert "runtime" not in stored

    # A list row does not invent one either — the same lie, read back out.
    rows = client.get("/agents", headers=seeded).json()
    assert next(a for a in rows if a["name"] == "no-tier")["runtime"] is None

    named = {**body, "name": "with-tier", "runtime": "simple"}
    assert client.post("/agents", json=named, headers=seeded).status_code == 201
    assert agents.get(TEST_TENANT, "with-tier")["runtime"] == "simple"


def test_every_draft_the_form_can_produce_is_accepted(client, seeded):
    """Every combination of ticked tools, both ways of answering every implied row.

    A failure here is not a broken test — it is a form that can build an agent the server
    refuses, which is the one thing 10c exists to make impossible.
    """
    cases = _fixture()["cases"]
    assert len(cases) == 32, "the fixture stopped covering every subset"

    refused = []
    for case in cases:
        response = client.post("/agents/validate", json=case["config"], headers=seeded)
        if response.status_code != 200:
            refused.append((case["tools"], case["reach"], response.json()["detail"]))

    assert not refused, "\n".join(f"{t} ({r}): {d}" for t, r, d in refused)


def test_a_draft_the_form_can_produce_actually_creates(client, seeded):
    """The dry run and the create are the same validator, so this is a spot check rather
    than a repeat — but "validates" and "creates" are different verbs and only one of them
    writes a row and a grant."""
    widest = max(_fixture()["cases"], key=lambda c: len(c["config"]["permissions"]["tools"]))

    response = client.post("/agents", json=widest["config"], headers=seeded)

    assert response.status_code == 201, response.text
    name = response.json()["name"]
    assert client.get(f"/agents/{name}", headers=seeded).status_code == 200


def test_validating_a_draft_needs_no_grant(client, auth):
    """Same reasoning as `GET /tools`: it discloses nothing but the shape of what the
    caller just typed, back to them. There is nothing to have a grant on."""
    assert client.post("/agents/validate", json=DRAFT, headers=auth).status_code == 200
    assert client.post("/agents/validate", json=DRAFT).status_code == 401


# --- sharing is enforced here ---------------------------------------------------------


def test_an_ungranted_agent_is_absent_from_the_list(client, auth, unshared_agent):
    """The state every agent is created in. Before this it was visible to everybody in
    the tenant, which is what the whole step is about."""
    assert client.get("/agents", headers=auth).json() == []


def test_an_ungranted_agent_is_the_same_404_as_a_missing_one(client, auth, unshared_agent):
    """Byte-identical, body and status. A 403 here would confirm that an agent by this
    name exists in a tenant the caller can see into — and a sweep over plausible names
    would enumerate the company's agents, which is worth more than the access."""
    ungranted = client.get("/agents/demo", headers=auth)
    missing = client.get("/agents/nope", headers=auth)

    assert ungranted.status_code == missing.status_code == 404
    assert ungranted.json()["detail"] == missing.json()["detail"].replace("nope", "demo")


def test_an_ungranted_broken_agent_is_404_and_not_422(client, auth):
    """The ordering test, and the reason the grant check is the first line of the route.

    A 422 says "this agent exists and its config is invalid". Checking access *after*
    loading the config would answer 404 for an agent that does not exist and 422 for an
    ungranted one that does — reopening the leak through a status code nobody thinks of
    as an authorization decision.
    """
    storage.active().save_agent(
        TEST_TENANT,
        {**AGENT, "name": "broken", "permissions": {"tools": ["gone_away"]}},
        actor="system:cli",
    )

    assert client.get("/agents/broken", headers=auth).status_code == 404


def test_an_ungranted_broken_agent_is_absent_from_the_list_too(client, auth):
    """Same ordering, on the other route. Filtering the summaries rather than the rows
    would mean fixing a config made somebody else's agent appear."""
    storage.active().save_agent(
        TEST_TENANT,
        {**AGENT, "name": "broken", "permissions": {"tools": ["gone_away"]}},
        actor="system:cli",
    )

    assert client.get("/agents", headers=auth).json() == []


def test_a_broken_agent_opens_and_says_why(client, auth):
    """**Decision 4, and it is a decision revisited rather than a bug patched.**

    This route answered 422 for four steps, argued in api/errors.py, on the grounds that
    `agents.get()` raises rather than returning None so a broken agent is never silently
    a missing one. That reasoning holds and the conclusion did not: `GET /agents` already
    lists broken agents *with their reason*, so refusing to open them meant the detail
    screen never rendered for exactly the agent somebody came to fix — and editing is the
    cure. Two representations of "this agent is broken" was the drift; one is the fix.

    Still only once it is shared. This is a disclosure — it says the agent exists and
    what is wrong with its config — so it is reachable exactly to the people who may see
    it at all, which is what the paired test below asserts.
    """
    storage.active().save_agent(
        TEST_TENANT,
        {**AGENT, "name": "broken", "permissions": {"tools": ["gone_away"]}},
        actor="system:cli",
    )
    share_with_caller(client, auth, "broken")

    response = client.get("/agents/broken", headers=auth)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["valid"] is False
    assert "gone_away" in body["error"]
    # The same shape the list route has used since 10a, and now literally the same
    # function — see `_why_invalid`.
    (listed,) = [a for a in client.get("/agents", headers=auth).json() if a["name"] == "broken"]
    assert (listed["valid"], listed["error"]) == (body["valid"], body["error"])


# --- editing, which is what 10d is ------------------------------------------------
#
# `editor` has had an editing half since migration 011 and nothing to edit. This is the
# first caller of the level — and the first moment two people can disagree about what an
# agent's config should be.


def _open(client, headers, name):
    """Read an agent the way an edit screen does: the config, and the ETag to send back."""
    response = client.get(f"/agents/{name}", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def _patch(client, headers, name, body, etag=None):
    """`PATCH`, conditional on the version this caller last read."""
    if etag is None:
        etag = _open(client, headers, name)["updated_at"]
    return client.patch(
        f"/agents/{name}", json=body, headers={**headers, "If-Match": f'"{etag}"'}
    )


# --- renaming, which is what 025 is -----------------------------------------------
#
# A separate verb from `PATCH` and a separate grant level, both argued at the route. Every
# test here is about a thing that was impossible before migration 035: `agents` was keyed
# by name, so changing one meant creating a second agent and deleting the first.


def test_renaming_an_agent_moves_its_url_and_keeps_everything(client, auth, demo_agent):
    """The whole feature, at the route: the new URL serves, the old one is gone, and the
    grant that made this caller the owner came along."""
    response = client.post(
        "/agents/demo/rename", json={"new_name": "triage"}, headers=auth
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["name"] == "triage"
    assert body["your_role"] == "owner"
    # A new ETag, and one that works: the rename changed the config.
    assert response.headers["ETag"] == f'"{body["updated_at"]}"'

    assert client.get("/agents/triage", headers=auth).status_code == 200
    assert client.get("/agents/demo", headers=auth).status_code == 404
    # And it is still this caller's agent, which is the point of re-keying the grants.
    assert [row["name"] for row in client.get("/agents", headers=auth).json()] == [
        "triage"
    ]


def test_renaming_to_a_taken_name_is_409(client, auth, demo_agent):
    """`create`'s refusal, at `create`'s constraint: two agents cannot answer one URL."""
    agents.save(TEST_TENANT, {**AGENT, "name": "billing"}, actor="system:cli")

    response = client.post(
        "/agents/demo/rename", json={"new_name": "billing"}, headers=auth
    )

    assert response.status_code == 409
    assert "already has an agent called 'billing'" in response.json()["detail"]
    assert client.get("/agents/demo", headers=auth).status_code == 200


def test_renaming_to_a_refused_name_is_422(client, auth, demo_agent):
    """The slug rules, the reserved names, and the name it already has — one family, and
    all three are the caller's to fix rather than the server's."""
    for target, expected in (
        ("Triage Bot", "not a usable agent name"),
        ("validate", "reserved"),
        ("new", "reserved"),
        ("demo", "already called that"),
    ):
        response = client.post(
            "/agents/demo/rename", json={"new_name": target}, headers=auth
        )
        assert response.status_code == 422, (target, response.text)
        assert expected in response.json()["detail"], target

    assert client.get("/agents/demo", headers=auth).status_code == 200


def test_renaming_needs_owner_and_an_editor_gets_the_same_404(
    client, auth, unshared_agent
):
    """**The access decision, asserted.** An editor changes what an agent does; a rename
    changes the URL somebody bookmarked, so it sits with `delete` and `transfer`.

    And a level too low is the same 404 an absent agent gives, for the reason every other
    route here gives it: anything else confirms that `demo` exists in a tenant this caller
    cannot fully see.
    """
    share_with_caller(client, auth, "demo", role="editor")

    refused = client.post(
        "/agents/demo/rename", json={"new_name": "triage"}, headers=auth
    )
    missing = client.post(
        "/agents/nope/rename", json={"new_name": "triage"}, headers=auth
    )

    assert refused.status_code == missing.status_code == 404
    assert storage.active().get_agent(TEST_TENANT, "demo") is not None


def test_a_rename_body_forbids_extra_keys(client, auth, demo_agent):
    """`extra="forbid"`, like every other body here: a rename carrying a `system` key
    somebody expected to be applied is a request half-honoured."""
    response = client.post(
        "/agents/demo/rename",
        json={"new_name": "triage", "system": "and this too"},
        headers=auth,
    )

    assert response.status_code == 422
    assert storage.active().get_agent(TEST_TENANT, "demo")["config"] == AGENT


def test_a_rename_takes_no_if_match(client, auth, demo_agent):
    """A deliberate asymmetry with `PATCH`, stated as a test so nobody adds one.

    An edit form races another edit form. A rename is one act from an owner, serialized on
    the row — and the loser of two concurrent renames gets a 404, which is true, rather
    than a 412 invented for the occasion.
    """
    response = client.post(
        "/agents/demo/rename", json={"new_name": "triage"}, headers=auth
    )
    assert response.status_code == 200, response.text

    # The second rename of the same agent, by the old name, from a caller who never saw
    # the first: a 404, because there is no `demo` any more.
    again = client.post(
        "/agents/demo/rename", json={"new_name": "other"}, headers=auth
    )
    assert again.status_code == 404


def test_an_agent_carries_an_id_a_rename_does_not_move(client, auth, demo_agent):
    """The additive field, and the reason it exists: a machine consumer that wants an
    identity a rename cannot change has one, without any URL learning about it."""
    before = client.get("/agents/demo", headers=auth).json()
    assert before["id"].startswith("a_")

    client.post("/agents/demo/rename", json={"new_name": "triage"}, headers=auth)
    after = client.get("/agents/triage", headers=auth).json()

    assert after["id"] == before["id"]
    assert after["name"] != before["name"]


def test_editing_an_agent_changes_only_what_was_sent(client, auth, demo_agent):
    response = _patch(client, auth, "demo", {"system": "You are a triage agent."})

    assert response.status_code == 200, response.text
    stored = storage.active().get_agent(TEST_TENANT, "demo")["config"]
    assert stored["system"] == "You are a triage agent."
    # Untouched, because it was not sent.
    assert stored["permissions"] == AGENT["permissions"]


def test_a_patch_that_omits_a_field_does_not_delete_it(client, auth, isolated_storage):
    """**The finding that decided decision 2.**

    `frontend/src/lib/draft.ts` has `toConfig` and no inverse, and `AgentDraft` forbids
    extra keys, so a form cannot send back a field it never asked about. An edit screen
    built from the create form and saving the whole config deletes such a field, and
    nothing anywhere reports it.

    A top-level merge makes that unreachable rather than guarded against: the field
    survives because the form never sent it. Asserted against a stored config carrying a
    key no wizard step knows, written the way a seed writes one.
    """
    owner = logged_in_id(client, auth)
    storage.active().create_agent(
        TEST_TENANT, {**AGENT, "name": "keeper", "note": "kept by the merge"}, "user", owner
    )
    before = storage.active().get_agent(TEST_TENANT, "keeper")["config"]
    assert before["note"] == "kept by the merge"

    response = _patch(client, auth, "keeper", {"system": "Rewritten."})

    assert response.status_code == 200, response.text
    after = storage.active().get_agent(TEST_TENANT, "keeper")["config"]
    assert after["note"] == before["note"]
    assert after["system"] == "Rewritten."


def test_permissions_are_replaced_as_a_unit_and_never_deep_merged(client, auth, demo_agent):
    """`tools` and `scope` are cross-checked in both directions by
    `_validate_scope_matches_tools`, so a merge that updated one and kept the other is the
    one way to produce a config the validator refuses through a route that looks like it
    is working."""
    response = _patch(
        client, auth, "demo", {"permissions": {"tools": [], "scope": {}}}
    )

    assert response.status_code == 200, response.text
    assert storage.active().get_agent(TEST_TENANT, "demo")["config"]["permissions"] == {
        "tools": [],
        "scope": {},
    }


def test_a_patch_the_validator_refuses_is_422_and_writes_nothing(client, auth, demo_agent):
    """The merged config is what is validated, not the patch — a patch that is fine on
    its own and breaks the agent when merged is the case that matters."""
    response = _patch(client, auth, "demo", {"permissions": {"tools": [], "scope": {
        "chat.channel": {"write": ["#eng"]}
    }}})

    assert response.status_code == 422
    assert "chat.channel (write)" in response.json()["detail"]
    assert storage.active().get_agent(TEST_TENANT, "demo")["config"] == AGENT


def test_editing_needs_editor_and_a_user_gets_the_same_404(client, auth, unshared_agent):
    """A level too low is the same 404 as an agent that does not exist. Anything else
    confirms that `demo` is an agent in a tenant this caller can see into."""
    share_with_caller(client, auth, "demo", role="user")

    refused = _patch(client, auth, "demo", {"system": "Mine now."})
    missing = client.patch(
        "/agents/nope", json={"system": "x"}, headers={**auth, "If-Match": '"x"'}
    )

    assert refused.status_code == missing.status_code == 404
    assert storage.active().get_agent(TEST_TENANT, "demo")["config"] == AGENT


def test_a_patch_with_no_if_match_is_428_and_changes_nothing(client, auth, demo_agent):
    """**Not a permissive default.** A PATCH with no precondition is last-write-wins,
    which is the single failure this step exists to refuse — and accepting it by default
    is how a system grows a concurrency guard most callers do not use."""
    response = client.patch("/agents/demo", json={"system": "x"}, headers=auth)

    assert response.status_code == 428
    assert "If-Match" in response.json()["detail"]
    assert storage.active().get_agent(TEST_TENANT, "demo")["config"] == AGENT


def test_a_stale_edit_is_409_and_says_which_keys_differ(client, auth, registered, unshared_agent):
    """**The question the step asks: what happens when two editors disagree?**

    Both open the agent. Priya narrows its scope and saves. Sam saves the version he
    loaded before that — and without the guard it lands, silently reverting a permission
    narrowing with nothing anywhere recording that it happened.
    """
    share_with_caller(client, auth, "demo", role="owner")
    sam = {"Authorization": f"Bearer {registered.token(sub='00u-sam', email='sam@acme.com')}"}
    share_with_caller(client, sam, "demo", role="editor")

    stale = _open(client, sam, "demo")["updated_at"]
    narrowed = _patch(
        client, auth, "demo",
        {"permissions": {"tools": [], "scope": {}}},
    )
    assert narrowed.status_code == 200, narrowed.text

    response = _patch(client, sam, "demo", {"permissions": AGENT["permissions"]}, etag=stale)

    assert response.status_code == 409, response.text
    body = response.json()
    assert body["changed"] == ["permissions"], "it has to say what it would have reverted"
    # The current version, so a client can reload and retry without a second request.
    assert body["updated_at"] == _open(client, auth, "demo")["updated_at"]
    # And Priya's narrowing survived.
    assert storage.active().get_agent(TEST_TENANT, "demo")["config"]["permissions"] == {
        "tools": [],
        "scope": {},
    }


def test_a_stale_edit_that_agrees_with_the_stored_version_says_so(client, auth, demo_agent):
    """`changed` is exact rather than "somebody edited this". An empty list means the save
    was a no-op against the current version, which is a thing a person can act on — reload
    and carry on — and is what stops the 409 reading as "your work is lost"."""
    stale = _open(client, auth, "demo")["updated_at"]
    _patch(client, auth, "demo", {"system": "First."})

    response = _patch(client, auth, "demo", {"system": "First."}, etag=stale)

    assert response.status_code == 409
    assert response.json()["changed"] == []


def test_a_patch_that_renames_is_400(client, auth, demo_agent):
    """Refused rather than silently ignored. The name is the URL, the storage key, the
    broker's identity and the string in every audit record; telling somebody their rename
    worked when it did not is the worse of the two failures."""
    response = _patch(client, auth, "demo", {"name": "renamed"})

    assert response.status_code == 400
    assert "renamed" in response.json()["detail"]
    assert storage.active().get_agent(TEST_TENANT, "renamed") is None


def test_a_patch_naming_its_own_agent_is_fine(client, auth, demo_agent):
    """A form that round-trips the config it was given sends `name` back. That is not a
    rename and must not be refused as one."""
    assert _patch(client, auth, "demo", {"name": "demo", "system": "x"}).status_code == 200


def test_an_unknown_key_in_a_patch_is_refused(client, auth, demo_agent):
    """`extra="forbid"`, for the reason `AgentDraft` has it: `systen` would merge happily
    and produce an agent that was told nothing."""
    assert _patch(client, auth, "demo", {"systen": "oops"}).status_code == 422


def test_the_detail_route_hands_back_what_an_edit_screen_needs(client, auth, demo_agent):
    """The whole config, and the ETag in both a header and a field.

    `system`, `scope` and `limits` are the same data spelled for a reader and are not the
    whole config — an edit form built from those alone reintroduces the deletion decision
    2 exists to prevent, through the response instead of the request.
    """
    response = client.get("/agents/demo", headers=auth)
    body = response.json()

    assert body["config"] == AGENT
    assert body["updated_at"]
    assert response.headers["ETag"] == f'"{body["updated_at"]}"'


@pytest.mark.parametrize("role", ["user", "editor", "owner"])
def test_the_detail_route_says_what_the_caller_may_do(
    client, auth, registered, unshared_agent, role
):
    """**Without this a screen renders buttons that 404 at the person they were rendered
    for.** `DELETE` is `owner` and `PATCH` is `editor`, and nothing else in this API tells
    a client who it is — so the level comes back on the read that precedes the write.

    The ladder's own word rather than a set of booleans per verb: what a level permits is
    policy, it lives in `access/grants.py`, and three flags is three things that can
    disagree with it.
    """
    sam = {"Authorization": f"Bearer {registered.token(sub='00u-sam', email='sam@acme.com')}"}
    share_with_caller(client, sam, "demo", role=role)

    assert client.get("/agents/demo", headers=sam).json()["your_role"] == role


def test_a_role_reached_through_a_group_is_the_one_reported(
    client, auth, registered, unshared_agent
):
    """Highest-wins is the ladder's rule and this is the first screen that shows it to a
    person. A sheet that reported the direct grant would tell an editor they may not
    edit."""
    store = storage.active()
    sam = {"Authorization": f"Bearer {registered.token(sub='00u-sam', email='sam@acme.com')}"}
    sam_id = logged_in_id(client, sam)
    share_with_caller(client, sam, "demo", role="user")
    store.create_group(TEST_TENANT, "g-1", "oncall", actor="system:cli")
    store.add_group_member(TEST_TENANT, "g-1", "user", sam_id, actor="system:cli")
    store.grant_agent(TEST_TENANT, "demo", "group", "g-1", role="editor", actor="system:cli")

    assert client.get("/agents/demo", headers=sam).json()["your_role"] == "editor"


# --- version history ---------------------------------------------------------------
#
# Step 021. Three routes: two reads at `user` and a restore at `editor`. The one to read
# first is `test_a_restore_removes_a_field_no_patch_could_have_removed`, which is the
# finding that makes the restore a route rather than something a client composes.


def _versions(client, headers, name="demo"):
    response = client.get(f"/agents/{name}/versions", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def _restore(client, headers, version, name="demo", etag=None):
    if etag is None:
        etag = _open(client, headers, name)["updated_at"]
    return client.post(
        f"/agents/{name}/versions/{version}/restore",
        headers={**headers, "If-Match": f'"{etag}"'},
    )


def test_the_history_starts_at_the_agents_first_configuration(client, auth, demo_agent):
    """One version, for an agent nobody has edited — and it is the config that is live.

    The fixture reaches `agents.save`, which is `--seed`'s path, so this also pins that
    a seeded agent arrives with its history already started rather than acquiring one at
    its first edit.
    """
    (version,) = _versions(client, auth)

    assert version["version"] == 1
    assert version["source"] == "save"
    assert version["created_by"] == "system:cli"
    assert version["restored_from"] is None
    assert version["valid"] is True
    assert "config" not in version


def test_an_edit_adds_a_version_and_the_older_one_still_says_what_it_said(
    client, auth, demo_agent
):
    """The property the whole step exists for, over HTTP: the prompt from before the
    edit is still readable afterwards."""
    _patch(client, auth, "demo", {"system": "Rewritten, badly."})

    history = _versions(client, auth)
    assert [row["version"] for row in history] == [2, 1]

    before = client.get("/agents/demo/versions/1", headers=auth).json()
    assert before["config"]["system"] == "You are a demo agent."
    assert client.get("/agents/demo", headers=auth).json()["config"]["system"] == (
        "Rewritten, badly."
    )


def test_a_restore_writes_a_new_version_rather_than_moving_a_pointer(
    client, auth, demo_agent
):
    """Restoring 1 while 2 is live writes **3**, and 2 stays exactly where it is.

    A pointer that moved back would make the timeline non-monotonic, so *what was live
    on Tuesday* would need a second log of every move — a history of the history — and a
    bad restore would have nothing to undo it.
    """
    _patch(client, auth, "demo", {"system": "Rewritten, badly."})

    restored = _restore(client, auth, 1)

    assert restored.status_code == 200, restored.text
    body = restored.json()
    assert body["version"] == 3
    assert body["config"]["system"] == "You are a demo agent."
    history = _versions(client, auth)
    assert [(r["version"], r["source"], r["restored_from"]) for r in history] == [
        (3, "restore", 1),
        (2, "update", None),
        (1, "save", None),
    ]
    # And the version that was restored *over* is still readable, which is what makes
    # the restore itself undoable.
    assert client.get("/agents/demo/versions/2", headers=auth).json()["config"][
        "system"
    ] == "Rewritten, badly."


def test_a_restore_removes_a_field_no_patch_could_have_removed(
    client, auth, demo_agent
):
    """**The finding that makes this a route rather than a client's two requests.**

    `PATCH` merges at the top level, so a key the old config does not carry survives from
    the live one. A client that fetched version 1 and patched it back would get neither
    version — it would get version 1 plus today's `model`, silently, while the screen
    said the restore worked. There is no way to remove a field over HTTP at all.

    Asserted both ways round, because the assertion is only meaningful next to the thing
    it is being contrasted with: the patch-composed restore keeps the field, and this
    route does not.
    """
    _patch(client, auth, "demo", {"model": "claude-haiku-4-5-20251001"})
    assert _open(client, auth, "demo")["config"]["model"] == "claude-haiku-4-5-20251001"

    # What a client would do without this route, and what it silently produces.
    version_one = client.get("/agents/demo/versions/1", headers=auth).json()["config"]
    composed = _patch(client, auth, "demo", version_one)
    assert composed.status_code == 200, composed.text
    assert composed.json()["config"]["model"] == "claude-haiku-4-5-20251001", (
        "a merge is supposed to keep the key — if this fails, the merge changed and this "
        "route's whole justification wants re-reading"
    )

    restored = _restore(client, auth, 1)

    assert restored.status_code == 200, restored.text
    assert "model" not in restored.json()["config"]


def test_reading_history_needs_only_user_and_restoring_needs_editor(
    client, auth, registered, demo_agent
):
    """The same bytes at a different age are not a second confidentiality level: a
    runner can already read today's system prompt, so they may read yesterday's.

    Writing is a write, and takes what every other write takes.
    """
    sam = {"Authorization": f"Bearer {registered.token(sub='00u-sam', email='sam@acme.com')}"}
    share_with_caller(client, sam, "demo", role="user")

    assert client.get("/agents/demo/versions", headers=sam).status_code == 200
    assert client.get("/agents/demo/versions/1", headers=sam).status_code == 200
    assert _restore(client, sam, 1).status_code == 404


def test_history_of_an_agent_you_may_not_see_is_the_same_404(
    client, auth, unshared_agent
):
    """`_require_agent`'s anti-enumeration rule, extended to two more URLs. An ungranted
    agent and an absent one must stay indistinguishable, and a new route is the easiest
    place to reopen that."""
    ungranted = client.get("/agents/demo/versions", headers=auth)
    missing = client.get("/agents/nope/versions", headers=auth)

    assert ungranted.status_code == missing.status_code == 404
    # The sentence names the agent, so equality is asserted through the substitution
    # `test_an_ungranted_agent_is_the_same_404_as_a_missing_one` already uses: what must
    # match is everything except the name the caller themselves supplied.
    assert ungranted.json()["detail"] == missing.json()["detail"].replace("nope", "demo")
    assert client.get("/agents/demo/versions/1", headers=auth).status_code == 404
    # A well-formed precondition rather than none, so what this asserts is the grant
    # check refusing — and that it runs **before** the header is parsed, which is what
    # keeps a 428 from confirming the agent exists.
    refused = _restore(client, auth, 1, etag="2026-08-13T00:00:00+00:00")
    assert refused.status_code == 404
    assert client.post("/agents/demo/versions/1/restore", headers=auth).status_code == 404


def test_a_version_that_was_never_written_is_404(client, auth, demo_agent):
    """And it is a 404 rather than a 422 for the same reason the agent's own is: the
    number is part of the address, and *"that agent exists and has no version 9"* is the
    enumeration leak through a number instead of a name."""
    assert client.get("/agents/demo/versions/9", headers=auth).status_code == 404
    assert client.get("/agents/demo/versions/0", headers=auth).status_code == 404
    assert _restore(client, auth, 9).status_code == 404


def test_a_restore_with_no_precondition_is_428(client, auth, demo_agent):
    """The same refusal `PATCH` makes, byte for byte. A restore is the widest write in
    the product — it replaces the whole config — so last-write-wins is worse here than
    anywhere else."""
    unconditional = client.post("/agents/demo/versions/1/restore", headers=auth)
    patched = client.patch("/agents/demo", json={"system": "x"}, headers=auth)

    assert unconditional.status_code == 428
    assert unconditional.json() == patched.json()


def test_a_restore_from_a_stale_read_is_409_and_names_what_it_would_have_written(
    client, auth, demo_agent
):
    """A restore is an edit, so it owes the same 409 — and the `changed` list is wider
    than an edit's because a restore writes every key rather than the ones a form sent."""
    stale = _open(client, auth, "demo")["updated_at"]
    _patch(client, auth, "demo", {"system": "Priya got here first."})

    refused = _restore(client, auth, 1, etag=stale)

    assert refused.status_code == 409, refused.text
    body = refused.json()
    assert "system" in body["changed"]
    assert body["updated_at"] == _open(client, auth, "demo")["updated_at"]
    # And nothing was written: the history is still the two versions it had.
    assert [row["version"] for row in _versions(client, auth)] == [2, 1]


def test_a_version_whose_tools_are_no_longer_vetted_says_so_before_the_click(
    client, auth, demo_agent
):
    """**Validity is evaluated when a version is read, never when it was written.**

    What may be live moves under stored configs, so a version can stop being restorable
    without anybody touching it. The list has to say so before somebody clicks restore,
    rather than answering 422 afterwards — and the restore does refuse, with the
    validator's own sentence rather than a paraphrase of it.
    """
    store = storage.active()

    def connector(vetted):
        store.save_connector(
            TEST_TENANT,
            {
                "id": "notes",
                "description": "",
                "launch": {"kind": "stdio", "command": ["/bin/true"]},
                "vetted": vetted,
            },
            actor="system:cli",
        )

    connector([
        {
            "remote_name": "read_page",
            "effect": "read",
            "resources": [],
            "local_name": None,
            "max_response_bytes": None,
        }
    ])
    # Whatever this tenant now calls that tool — read back rather than guessed at, since
    # the local name is derived and this test is not about how.
    granted = sorted(tools.known_names(TEST_TENANT) - {"post_message"})[0]

    # A version that uses it, then a version that does not, then the un-vetting.
    _patch(client, auth, "demo", {"permissions": {"tools": [granted], "scope": {}}})
    _patch(client, auth, "demo", {"permissions": {"tools": [], "scope": {}}})
    connector([])

    history = _versions(client, auth)
    stale = [row for row in history if row["version"] == 2][0]
    assert stale["valid"] is False
    assert stale["error"]
    # The versions that do not name the tool are unaffected, so "valid" is a fact about
    # each version rather than about the agent.
    assert [row["valid"] for row in history] == [True, False, True]

    refused = _restore(client, auth, 2)
    assert refused.status_code == 422
    assert refused.json()["detail"] == stale["error"]
    # The live agent is untouched and still runnable, which is the state that makes the
    # refusal survivable rather than a lockout.
    assert client.get("/agents/demo", headers=auth).json()["valid"] is True


def test_a_restore_of_what_is_already_live_changes_nothing(client, auth, demo_agent):
    """An ordinary no-change write: the ETag moves, the log records it, and the history
    does not grow. A restore that appended a copy of what is already live would make the
    history a log of clicks."""
    before = _open(client, auth, "demo")

    restored = _restore(client, auth, 1)

    assert restored.status_code == 200
    assert restored.json()["version"] == 1
    assert restored.json()["updated_at"] > before["updated_at"]
    assert [row["version"] for row in _versions(client, auth)] == [1]


def test_the_detail_route_carries_the_live_version_number(client, auth, demo_agent):
    """A screen says "v3", and a timestamp is not that. It is deliberately not a second
    ETag: `If-Match` still takes `updated_at`, and this number is what names a row in
    the history."""
    assert _open(client, auth, "demo")["version"] == 1

    _patch(client, auth, "demo", {"system": "Edited."})

    assert _open(client, auth, "demo")["version"] == 2
    # And a save that changes nothing moves the ETag without moving this, which is the
    # one place the two come apart.
    before = _open(client, auth, "demo")
    _patch(client, auth, "demo", {"system": "Edited."})
    after = _open(client, auth, "demo")
    assert after["version"] == before["version"]
    assert after["updated_at"] > before["updated_at"]


def test_the_history_of_a_broken_agent_opens_and_the_restore_is_the_fix(
    client, auth, demo_agent
):
    """10d decision 4 extended by one step. A broken agent is exactly the agent somebody
    has come to fix — and now the fix is one request rather than reconstructing a config
    from an administrative record that deliberately never held it."""
    storage.active().save_agent(
        TEST_TENANT,
        {**AGENT, "permissions": {"tools": ["not-a-real-tool"], "scope": {}}},
        actor="system:cli",
    )
    assert client.get("/agents/demo", headers=auth).json()["valid"] is False

    history = _versions(client, auth)
    assert [(row["version"], row["valid"]) for row in history] == [(2, False), (1, True)]

    restored = _restore(client, auth, 1)

    assert restored.status_code == 200, restored.text
    assert restored.json()["valid"] is True


# --- deleting --------------------------------------------------------------------


def test_deleting_an_agent_needs_owner(client, auth, registered, demo_agent):
    """**The one asymmetry worth arguing.** `unshare` already refuses to revoke the owner
    on the grounds that an editor who may orphan an agent may take it from the person who
    made it — and an editor who may *delete* it can do worse than orphan it."""
    sam = {"Authorization": f"Bearer {registered.token(sub='00u-sam', email='sam@acme.com')}"}
    share_with_caller(client, sam, "demo", role="editor")

    assert client.delete("/agents/demo", headers=sam).status_code == 404
    assert storage.active().get_agent(TEST_TENANT, "demo") is not None

    assert client.delete("/agents/demo", headers=auth).status_code == 204
    assert storage.active().get_agent(TEST_TENANT, "demo") is None


def test_deleting_an_agent_takes_its_grants_with_it(client, auth, demo_agent):
    """A real delete, not a flag. A disabled agent still holding grant rows is a row that
    grants nothing and looks like access — the artifact this codebase has refused three
    times."""
    client.delete("/agents/demo", headers=auth)

    assert client.get("/agents", headers=auth).json() == []
    assert storage.active().list_agent_grants(TEST_TENANT, "demo") == []


def test_deleting_the_same_agent_twice_is_404_not_204(client, auth, demo_agent):
    """`delete_agent` is idempotent in storage and this route is not, because it cannot
    be: 404 is also the answer for an agent you may not see, and answering 204 would tell
    a stranger that `payroll-bot` was there a moment ago."""
    assert client.delete("/agents/demo", headers=auth).status_code == 204
    assert client.delete("/agents/demo", headers=auth).status_code == 404


# --- the share sheet --------------------------------------------------------------


def test_the_access_sheet_says_how_each_person_has_access(client, auth, registered, demo_agent):
    """**`via` is the decision, not a nicety.** The moment unsharing exists in a UI,
    somebody revokes a grant, watches the agent stay visible through a group, and
    concludes the revoke failed. `unshare` already refuses that case loudly with a
    sentence naming the group; the sheet has to say the same thing *before* they try.
    """
    store = storage.active()
    sam = {"Authorization": f"Bearer {registered.token(sub='00u-sam', email='sam@acme.com')}"}
    sam_id = logged_in_id(client, sam)

    store.create_group(TEST_TENANT, "g-1", "oncall", actor="system:cli")
    store.add_group_member(TEST_TENANT, "g-1", "user", sam_id, actor="system:cli")
    store.grant_agent(TEST_TENANT, "demo", "group", "g-1", role="user", actor="system:cli")

    body = client.get("/agents/demo/access", headers=auth).json()
    rows = {(row["kind"], row["id"]): row for row in body["access"]}

    assert rows[("group", "g-1")]["direct"] == "user"
    assert rows[("user", sam_id)]["direct"] is None, "he has no grant of his own"
    assert rows[("user", sam_id)]["via"] == ["g-1"]
    assert rows[("user", logged_in_id(client, auth))]["role"] == "owner"


def test_the_access_sheet_lists_who_is_waiting_separately(client, auth, demo_agent):
    """A pending grant is a different kind of fact: nobody has that access, and somebody
    *will* if a person ever arrives at that address. Merging the two lists would report
    access that does not exist."""
    client.put(
        "/agents/demo/grants/email/newhire@acme.com", json={"role": "user"}, headers=auth
    )

    body = client.get("/agents/demo/access", headers=auth).json()

    assert [w["email"] for w in body["waiting"]] == ["newhire@acme.com"]
    assert "newhire@acme.com" not in [row["id"] for row in body["access"]]


def test_the_access_sheet_is_readable_at_user(client, auth, registered, demo_agent):
    """Deliberately the bottom of the ladder, matching `who_has_access`: somebody about to
    run an agent that acts on **their** data should see who else can reach it."""
    sam = {"Authorization": f"Bearer {registered.token(sub='00u-sam', email='sam@acme.com')}"}
    share_with_caller(client, sam, "demo", role="user")

    assert client.get("/agents/demo/access", headers=sam).status_code == 200


def test_the_access_sheet_of_an_ungranted_agent_is_the_same_404(client, auth, unshared_agent):
    assert client.get("/agents/demo/access", headers=auth).status_code == 404
    assert client.get("/agents/nope/access", headers=auth).status_code == 404


# --- sharing and unsharing over HTTP ----------------------------------------------


def test_sharing_with_a_person_who_has_logged_in_grants_immediately(
    client, auth, registered, demo_agent
):
    sam = {"Authorization": f"Bearer {registered.token(sub='00u-sam', email='sam@acme.com')}"}
    sam_id = logged_in_id(client, sam)

    response = client.put(
        f"/agents/demo/grants/user/{sam_id}", json={"role": "editor"}, headers=auth
    )

    assert response.status_code == 200, response.text
    assert response.json()["outcome"] == "granted"
    assert [a["name"] for a in client.get("/agents", headers=sam).json()] == ["demo"]


def test_sharing_by_email_reports_which_of_the_two_things_happened(
    client, auth, registered, demo_agent
):
    """**006 made this invisible to the sharer by design, and it stops being invisible
    here.** `granted` and `pending` look identical on a screen and only one of them means
    anybody actually has access — a sharer who cannot tell them apart finds out as "I
    shared that with her weeks ago"."""
    sam = {"Authorization": f"Bearer {registered.token(sub='00u-sam', email='sam@acme.com')}"}
    logged_in_id(client, sam)

    landed = client.put(
        "/agents/demo/grants/email/sam@acme.com", json={"role": "user"}, headers=auth
    )
    waiting = client.put(
        "/agents/demo/grants/email/newhire@acme.com", json={"role": "user"}, headers=auth
    )

    assert landed.json()["outcome"] == "granted"
    assert waiting.json()["outcome"] == "pending"


def test_sharing_with_an_address_no_provider_can_vouch_for_is_400(client, auth, demo_agent):
    """`ShareRefused`, not the 404 `NoAccess` becomes. The caller has already proved
    `editor`, so the agent's existence is not a secret from them — and collapsing the two
    once told an operator who owned an agent that it had not been shared with them."""
    response = client.put(
        "/agents/demo/grants/email/someone@elsewhere.example",
        json={"role": "user"},
        headers=auth,
    )

    assert response.status_code == 400
    assert "elsewhere.example" in response.json()["detail"]


def test_sharing_needs_editor(client, auth, registered, unshared_agent):
    share_with_caller(client, auth, "demo", role="user")
    sam_id = "u-sam"

    response = client.put(
        f"/agents/demo/grants/user/{sam_id}", json={"role": "user"}, headers=auth
    )

    assert response.status_code == 404


def test_unsharing_removes_the_grant(client, auth, registered, demo_agent):
    sam = {"Authorization": f"Bearer {registered.token(sub='00u-sam', email='sam@acme.com')}"}
    sam_id = logged_in_id(client, sam)
    client.put(f"/agents/demo/grants/user/{sam_id}", json={"role": "user"}, headers=auth)

    response = client.delete(f"/agents/demo/grants/user/{sam_id}", headers=auth)

    assert response.status_code == 204
    assert client.get("/agents", headers=sam).json() == []


def test_unsharing_somebody_whose_access_is_inherited_is_refused_by_name(
    client, auth, registered, demo_agent
):
    """**The refusal the share sheet exists to pre-empt.** Deleting nothing and reporting
    success is the worst available outcome: whoever pressed it believes the access is gone
    and stops looking."""
    store = storage.active()
    sam = {"Authorization": f"Bearer {registered.token(sub='00u-sam', email='sam@acme.com')}"}
    sam_id = logged_in_id(client, sam)
    store.create_group(TEST_TENANT, "g-1", "oncall", actor="system:cli")
    store.add_group_member(TEST_TENANT, "g-1", "user", sam_id, actor="system:cli")
    store.grant_agent(TEST_TENANT, "demo", "group", "g-1", actor="system:cli")

    response = client.delete(f"/agents/demo/grants/user/{sam_id}", headers=auth)

    assert response.status_code == 400
    assert "g-1" in response.json()["detail"]
    assert [a["name"] for a in client.get("/agents", headers=sam).json()] == ["demo"]


def test_nobody_may_unshare_the_owner(client, auth, demo_agent):
    """Revoking the owner leaves the agent orphaned, and an editor who may orphan an
    agent may take it from the person who made it."""
    owner_id = logged_in_id(client, auth)

    response = client.delete(f"/agents/demo/grants/user/{owner_id}", headers=auth)

    assert response.status_code == 404
    assert "owns" in response.json()["detail"]


@pytest.mark.parametrize("body,path,why", [
    ({"role": "admin"}, "/agents/demo/grants/user/u-sam", "a level that is not one"),
    ({"role": "user"}, "/agents/demo/grants/group/nope", "a group that does not exist"),
])
def test_a_caller_error_on_a_grant_is_400_and_not_503(client, auth, demo_agent, body, path, why):
    """**Both of these answered 503 until they were run.**

    "Storage unavailable" tells somebody to try again later about a word that will never
    be a level and an id that will never be a group — the exact mistake `AgentNameTaken`
    was given its own class to fix, arriving through routes that did not exist when that
    reasoning was written. Found by `scripts/e2e_edges.py`, not by a test.
    """
    response = client.put(path, json=body, headers=auth)

    assert response.status_code == 400, why
    assert "unavailable" not in response.json()["detail"]


def test_a_grantee_kind_that_is_not_one_is_400(client, auth, demo_agent):
    """A 400 rather than the 503 a storage refusal would arrive as — "the database is
    unavailable" is the wrong thing to tell somebody who typed a URL wrong."""
    response = client.put(
        "/agents/demo/grants/robot/r-1", json={"role": "user"}, headers=auth
    )

    assert response.status_code == 400
    assert "robot" in response.json()["detail"]


def test_every_group_route_is_behind_the_role_that_9a_waited_for():
    """9a's wall, asserted rather than remembered — and now asserted from the other side.

    This used to read `assert not [p for p in paths if "group" in p]`, because
    `access/groups.py` said an HTTP route before a tenant-admin role existed was the
    mistake it guarded against. The role exists, so the assertion inverts rather than
    disappearing: the routes are here, and **every one that mutates or enumerates is
    behind `admin_from_request`**.

    `GET /groups` is the deliberate exception and is named here rather than excluded by a
    pattern, so removing its openness — or opening one of the others — fails.
    """
    ours = {
        (method, route.path)
        for route in _our_routes()
        for method in (route.methods or set())
        if "/groups" in route.path
    }

    assert ("GET", "/groups") in ours, ours
    assert ours - {("GET", "/groups")} == {
        entry for entry in deps.ADMIN_SURFACE if "/groups" in entry[1]
    }


# --- every write route leaves a record naming the person who asked -----------------
#
# Step 11 asserts that storage writes one. This asserts that the *route* hands it a real
# principal — which is 9a's lesson in a new place: a guard that lives only on the path
# nobody takes is a guard nobody has. Parametrised so a fifth write route added later
# without a record is a failing test rather than a gap.


def _write_routes(client, auth, sam_id):
    return (
        ("agent.create", lambda: client.post("/agents", json=DRAFT, headers=auth)),
        ("agent.update", lambda: _patch(client, auth, "demo", {"system": "Edited."})),
        (
            "grant.create",
            lambda: client.put(
                f"/agents/demo/grants/user/{sam_id}", json={"role": "user"}, headers=auth
            ),
        ),
        (
            "grant.revoke",
            lambda: (
                client.put(
                    f"/agents/demo/grants/user/{sam_id}",
                    json={"role": "user"},
                    headers=auth,
                ),
                client.delete(f"/agents/demo/grants/user/{sam_id}", headers=auth),
            ),
        ),
        (
            "grant.pending.add",
            lambda: client.put(
                "/agents/demo/grants/email/newhire@acme.com",
                json={"role": "user"},
                headers=auth,
            ),
        ),
        ("agent.delete", lambda: client.delete("/agents/demo", headers=auth)),
    )


@pytest.mark.parametrize("action", [a for a, _ in _write_routes(None, None, None)])
def test_every_write_route_records_the_requests_principal(
    client, auth, registered, demo_agent, action
):
    caller = logged_in_id(client, auth)
    sam = {"Authorization": f"Bearer {registered.token(sub='00u-sam', email='sam@acme.com')}"}
    sam_id = logged_in_id(client, sam)

    # The fixtures share the agent through storage directly, as `system:cli`. Counting
    # first is what makes this an assertion about the *route* rather than about whatever
    # set the test up.
    before = len(storage.active().admin_audit_records(TEST_TENANT, action=action))

    dict(_write_routes(client, auth, sam_id))[action]()

    records = storage.active().admin_audit_records(TEST_TENANT, action=action)[before:]
    assert records, f"{action} left no administrative record"
    assert [(r["actor_kind"], r["actor_id"]) for r in records] == [("user", caller)] * len(
        records
    )




def test_running_an_unknown_agent_is_404(client, auth):
    response = client.post("/runs", json={"agent": "nope", "task": "x"}, headers=auth)
    assert response.status_code == 404


def test_an_unknown_run_is_404(client, auth):
    assert client.get("/runs/deadbeef", headers=auth).status_code == 404


# --- the wait (step 032) ----------------------------------------------------------
#
# `GET /runs/{id}?wait=…&cursor=…` holds the request until the run's state would render
# differently, then answers with the same full snapshot as ever. No second transport:
# `wait=0` is exactly the pre-032 route, and every degradation below — stale cursor,
# terminal run, exhausted slots — answers *immediately* rather than erroring, so the
# worst case is always the previous behaviour. The timing bounds here are deliberately
# loose: they distinguish "held" from "answered now", never measure the tick.


# --- cancelling a run -------------------------------------------------------------
#
# The one thing this endpoint must not do is lie. Python cannot interrupt a thread, so
# "cancelled" at the moment of asking would be a claim about somebody's real systems that
# is false for as long as the current tool call takes — and a person who believes it
# stops looking at what the run wrote.
#
# So: 202, the run's *actual* status in the body, and the guarantee written out where a
# client author reads it.


def test_cancelling_an_unknown_run_is_404(client, auth):
    assert client.post("/runs/deadbeef/cancel", headers=auth).status_code == 404


# --- sharing by email, end to end through a login --------------------------------------


def test_a_pending_grant_lands_at_a_real_first_login(client, registered, unshared_agent):
    """The whole of 6c, driven the way it happens: somebody is shared an agent before
    they have ever authenticated, and the grant attaches at the moment they do.

    Nothing here knows who the recipient is at share time. `users` is keyed
    `(issuer, subject)` and a subject only arrives inside a token, so all that exists is
    an address and the expectation that a person will one day carry it.
    """
    owner = {"Authorization": f"Bearer {registered.token(sub='00u-owner', email='owner@acme.com')}"}
    share_with_caller(client, owner, "demo")

    owner_principal = Principal.user(logged_in_id(client, owner), TEST_TENANT)
    assert grants.share_by_email(owner_principal, "demo", "newhire@acme.com") == "pending"

    # The new hire's very first request, with a genuinely signed token.
    newhire = {
        "Authorization": f"Bearer {registered.token(sub='00u-new', email='newhire@acme.com')}"
    }
    body = client.get("/agents", headers=newhire).json()

    assert [a["name"] for a in body] == ["demo"]
    assert client.get("/agents/demo", headers=newhire).status_code == 200
    assert grants.who_is_waiting(owner_principal, "demo") == []


def test_somebody_not_shared_with_still_gets_nothing_on_first_login(
    client, registered, unshared_agent
):
    """The other half: just-in-time user creation is not just-in-time access."""
    stranger = {
        "Authorization": f"Bearer {registered.token(sub='00u-str', email='stranger@acme.com')}"
    }

    assert client.get("/agents", headers=stranger).json() == []
    assert client.get("/agents/demo", headers=stranger).status_code == 404


def test_a_grant_waiting_on_a_new_address_lands_when_the_address_changes(
    client, registered, unshared_agent
):
    """People marry, companies migrate domains. Identity is `(issuer, subject)` and does
    not move, so their history stays theirs — and anything shared with the *new* address
    attaches at the login that first carries it."""
    owner = {"Authorization": f"Bearer {registered.token(sub='00u-owner', email='owner@acme.com')}"}
    share_with_caller(client, owner, "demo")
    owner_principal = Principal.user(logged_in_id(client, owner), TEST_TENANT)

    before = {"Authorization": f"Bearer {registered.token(sub='00u-p', email='priya@acme.com')}"}
    client.get("/agents", headers=before)
    priya_id = storage.active().find_user_by_email(TEST_TENANT, "priya@acme.com")["id"]

    grants.share_by_email(owner_principal, "demo", "priya.sharma@acme.com", role="editor")
    assert client.get("/agents", headers=before).json() == []

    after = {
        "Authorization": f"Bearer {registered.token(sub='00u-p', email='priya.sharma@acme.com')}"
    }
    assert [a["name"] for a in client.get("/agents", headers=after).json()] == ["demo"]

    # Same person, not a new one — the subject never moved.
    assert storage.active().find_user_by_email(TEST_TENANT, "priya.sharma@acme.com")["id"] == priya_id
    assert len(storage.active().list_users(TEST_TENANT)) == 2


# --- the catalogue ---------------------------------------------------------------


def test_the_catalogue_needs_no_grant(client, auth):
    """Decision 5, and it is a departure from every other route in this API.

    What it discloses is which connectors this customer vetted and which tools they
    approved — not what any agent may do, not what anybody has access to, and not a
    single resource identifier. It is the menu, not anybody's order.

    Requiring a grant fails the case it exists for: the person about to create their
    first agent has none. This caller has no grant on anything, and `GET /agents` for
    them is empty.
    """
    assert client.get("/agents", headers=auth).json() == []

    response = client.get("/tools", headers=auth)
    assert response.status_code == 200
    assert [tool["name"] for tool in response.json()[0]["tools"]] == ["post_message"]


def test_the_catalogue_still_needs_a_token(client):
    """No *grant*, which is not the same as no authentication. The tenant comes off the
    principal and there is nowhere else it could come from — `deps.py` refuses a tenant
    in the URL — so an unauthenticated catalogue would be a catalogue of nothing in
    particular."""
    assert client.get("/tools").status_code == 401


def test_the_catalogue_says_which_tools_write(client, auth, vetted_github):
    """The risk this chunk retires. `post_message` reaches a customer's chat and
    `github_mcp_list_issues` reads issues, and until now they were two names in a row."""
    groups = client.get("/tools", headers=auth).json()
    effects = {tool["name"]: tool["effect"] for g in groups for tool in g["tools"]}

    assert effects["post_message"] == "write"
    assert effects["github_mcp_list_issues"] == "read"
    assert effects["github_mcp_add_issue_comment"] == "write"


def test_the_catalogue_covers_the_grant_of_the_agent_this_repo_ships(client, auth, vetted_github):
    """`issue-reporter` grants one connector tool and one built-in. A catalogue that
    cannot describe both cannot describe the worked example, which is what made
    `GET /connectors` the wrong route."""
    from carnet.bootstrap import _ISSUE_REPORTER as AGENT

    named = {
        tool["name"]
        for group in client.get("/tools", headers=auth).json()
        for tool in group["tools"]
    }
    assert set(AGENT["permissions"]["tools"]) <= named


def test_the_catalogue_is_scoped_to_the_callers_tenant(
    client, auth, idp, vetted_github, monkeypatch
):
    """A second customer running the same GitHub server must not inherit this one's
    vetting — the cross-tenant authorization leak that produced the per-tenant registry,
    reached through a route instead of through a registry."""
    # A distinct `kid`, because a JWKS is keyed by it: two providers both calling their
    # key "k1" produce one key set where the second silently shadows the first, and the
    # symptom is a 401 on a perfectly good token.
    other = Idp(issuer="https://globex.okta.example", kid="k2")
    storage.active().create_tenant(OTHER_TENANT, "Globex")
    storage.active().save_tenant_idp(OTHER_TENANT, other.row(allowed_domains=("globex.com",)))
    monkeypatch.setattr(
        providers,
        "KEYS",
        JwksCache(fetch=lambda uri: oidc.keys_from_jwks({"keys": [idp.jwk(), other.jwk()]})),
    )
    headers = {"Authorization": f"Bearer {other.token(sub='00u-hank', email='hank@globex.com')}"}

    # This tenant sees the connector; the other must see only what ships with the code.
    assert [g["origin"] for g in client.get("/tools", headers=auth).json()] == [
        "builtin",
        "connector",
    ]

    response = client.get("/tools", headers=headers)
    assert response.status_code == 200, response.text
    assert [g["origin"] for g in response.json()] == ["builtin"]


def test_the_catalogue_never_returns_argument_names(client, auth, vetted_github):
    """Decision 2 over the wire. `github.repo` is composed from `owner` and `repo`, and
    a client that learned those two names could build a scope out of them — the coupling
    the resource type exists to prevent."""
    body = client.get("/tools", headers=auth).text
    assert '"args"' not in body
    assert "template" not in body


def test_the_catalogue_carries_the_review_record_shape_for_builtins(client, auth):
    """Empty, and present. A client rendering "vetted by" needs one shape, and
    inventing a reviewer for code nobody reviewed is the assurance this table exists to
    avoid."""
    builtin = client.get("/tools", headers=auth).json()[0]
    assert builtin["origin"] == "builtin"
    assert builtin["tools"][0]["vetted_by"] == ""
    assert builtin["tools"][0]["vetted_at"] == ""


# --- the connection routes (7b) -------------------------------------------------------
#
# The screen's server side, and the callback — which is the one route in this API with no
# authentication and cannot have any. See `api/routes_connections.py`.


@pytest.fixture
def oauth_jira(isolated_storage, monkeypatch):
    """A registered HTTP connector with a consent flow, and a fake provider behind it."""
    # Bare, like every `from conftest import ...` in this suite — pytest puts the test
    # directory itself on the path. `from tests.test_oauth import ...` worked locally
    # ONLY because `python -m pytest` puts the working directory on the path too, and CI
    # runs `pytest` bare, which does not. Both jobs failed on exactly this line while
    # 1593 tests passed locally: an import that depends on how the suite is invoked is a
    # suite that tests the invocation.
    from test_oauth import FakeProvider  # noqa: PLC0415

    from carnet.access import oauth
    from conftest import TEST_ACTOR, TEST_HOST

    tools.register_connector(
        TEST_TENANT, "jira", url=f"https://{TEST_HOST}/mcp", actor=TEST_ACTOR
    )
    oauth.configure(
        TEST_TENANT,
        "jira",
        authorize_endpoint=f"https://{TEST_HOST}/authorize",
        token_endpoint=f"https://{TEST_HOST}/token",
        revoke_endpoint=f"https://{TEST_HOST}/revoke",
        client_id="client-abc",
        client_secret="MARKER-CLIENT-SECRET-e3f1",
        scopes=("read:jira-work", "offline_access"),
        actor=TEST_ACTOR,
    )
    fake = FakeProvider()
    monkeypatch.setattr(oauth, "_post_form", fake)
    return fake


def test_the_connections_page_has_three_states(client, auth, oauth_jira, vetted_github):
    """Decision 8. The third one is why this is a field rather than an inference.

    `github-mcp` ships with the platform, speaks stdio, and can never have a consent
    flow — so its row must say *ask an administrator* rather than render a Connect button
    that leads nowhere. That is 10d's share sheet lesson: a control that exists and does
    nothing reads as a bug, where a sentence gets acted on.
    """
    rows = {r["connector_id"]: r for r in client.get("/connections", headers=auth).json()}

    assert rows["jira"]["state"] == "connectable"
    assert rows["jira"]["scopes"] == ["read:jira-work", "offline_access"]
    assert rows["github-mcp"]["state"] == "unavailable"
    assert rows["github-mcp"]["scopes"] == []


def test_the_connections_page_answers_only_for_the_caller(client, auth, oauth_jira, idp):
    """No `?user=`, and 12b's role does not change that: an admin is not a superuser, so
    whose account is connected where stays tenant data rather than tenant configuration."""
    priya = logged_in_id(client, auth)
    sam_headers = {"Authorization": f"Bearer {idp.token(sub='00u-sam', email='sam@acme.com')}"}
    logged_in_id(client, sam_headers)

    # Connect as Priya, through the real flow.
    start = client.post("/connectors/jira/connect", headers=auth).json()
    state = start["authorize_url"].split("state=")[1].split("&")[0]
    client.get("/connect/callback", params={"state": state, "code": "c"}, follow_redirects=False)

    mine = {r["connector_id"]: r for r in client.get("/connections", headers=auth).json()}
    theirs = {r["connector_id"]: r for r in client.get("/connections", headers=sam_headers).json()}

    assert mine["jira"]["state"] == "connected"
    assert mine["jira"]["account_label"] == "priya@acme.com"
    assert theirs["jira"]["state"] == "connectable"
    assert priya  # the connection is Priya's, and Sam's identical request cannot see it


def test_starting_a_flow_returns_a_url_rather_than_redirecting(client, auth, oauth_jira):
    """`fetch` follows a 302 transparently and would pull consent HTML into a promise.

    A top-level navigation is what the flow requires, so the route hands back the URL and
    the client assigns `window.location`.
    """
    response = client.post("/connectors/jira/connect", headers=auth)

    assert response.status_code == 200
    url = response.json()["authorize_url"]
    assert url.startswith("https://api.example.com/authorize?")
    assert "MARKER-CLIENT-SECRET" not in response.text


def test_starting_a_flow_needs_a_token(client, oauth_jira):
    assert client.post("/connectors/jira/connect").status_code == 401


def test_the_callback_needs_no_token_and_that_is_the_point(client, auth, oauth_jira):
    """Decision 2. A provider's redirect is a plain navigation carrying no bearer token,
    so the binding rides in `state` — minted where a principal existed."""
    start = client.post("/connectors/jira/connect", headers=auth).json()
    state = start["authorize_url"].split("state=")[1].split("&")[0]

    # No headers at all. This is a browser arriving from atlassian.com.
    response = client.get(
        "/connect/callback", params={"state": state, "code": "c"}, follow_redirects=False
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/connections?connected=jira"
    assert storage.active().find_connection(
        TEST_TENANT, "user", logged_in_id(client, auth), "jira"
    )


def test_the_callback_never_puts_a_token_in_the_redirect(client, auth, oauth_jira):
    """Verification 1, at the HTTP boundary. A query string lands in history and logs."""
    start = client.post("/connectors/jira/connect", headers=auth).json()
    state = start["authorize_url"].split("state=")[1].split("&")[0]

    response = client.get(
        "/connect/callback", params={"state": state, "code": "c"}, follow_redirects=False
    )

    everything = response.headers["location"] + response.text
    assert "MARKER-ACCESS-TOKEN" not in everything
    assert "MARKER-REFRESH-TOKEN" not in everything
    assert "MARKER-CLIENT-SECRET" not in everything


def test_a_forged_state_lands_on_the_page_with_a_reason(client, oauth_jira):
    """Refused, and reported where somebody is standing rather than as a stack trace."""
    response = client.get(
        "/connect/callback", params={"state": "f" * 43, "code": "c"}, follow_redirects=False
    )

    assert response.status_code == 303
    assert response.headers["location"].startswith("/connections?failed=")


def test_pressing_deny_is_not_an_error_page(client, auth, oauth_jira):
    """They made a choice. The Connections page is where they see the result of it."""
    response = client.get(
        "/connect/callback",
        params={"error": "access_denied", "error_description": "The user said no"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "The+user+said+no" in response.headers["location"]


def test_return_to_carries_somebody_back_where_they_started(client, auth, oauth_jira):
    """An agent's page is where somebody discovers they cannot run it. Decision 8."""
    start = client.post(
        "/connectors/jira/connect",
        params={"return_to": "/agents/triage-bot"},
        headers=auth,
    ).json()
    state = start["authorize_url"].split("state=")[1].split("&")[0]

    response = client.get(
        "/connect/callback", params={"state": state, "code": "c"}, follow_redirects=False
    )

    assert response.headers["location"] == "/agents/triage-bot?connected=jira"


def test_return_to_may_not_leave_this_application(client, auth, oauth_jira):
    """The open redirect, at the boundary a caller actually controls."""
    response = client.post(
        "/connectors/jira/connect",
        params={"return_to": "//evil.example.com"},
        headers=auth,
    )

    # **400, not 503.** It answered 503 "storage unavailable" first, because the check
    # lives in storage and `StorageError` had the only matching handler — a caller's typo
    # reported as a database outage. See `check_return_to` and `errors._oauth_refused`.
    assert response.status_code == 400
    assert "return_to" in response.json()["detail"]
    assert "evil.example.com" not in response.headers.get("location", "")


def test_connecting_to_a_connector_this_tenant_does_not_have(client, auth, oauth_jira):
    """Refused before minting anything, so nobody approves access at a third party for
    a connector that was a typo."""
    response = client.post("/connectors/ghost/connect", headers=auth)

    # 400 and a sentence. It was a **500** until `OAuthRefused` got a handler — an
    # unmapped exception from a route added after the handler table was written, which is
    # precisely how `NoSuchGroupError` arrived as a 503 in step 011.
    assert response.status_code == 400
    assert "ghost" in response.json()["detail"]


def test_disconnecting_says_whether_the_provider_was_told(client, auth, oauth_jira):
    """200 with a body rather than 204 — decision 12's ambiguity has to go somewhere."""
    start = client.post("/connectors/jira/connect", headers=auth).json()
    state = start["authorize_url"].split("state=")[1].split("&")[0]
    client.get("/connect/callback", params={"state": state, "code": "c"}, follow_redirects=False)

    response = client.delete("/connectors/jira/connection", headers=auth)

    assert response.status_code == 200
    assert response.json() == {"disconnected": True, "revoked_upstream": True}
    assert oauth_jira.revoked == ["MARKER-REFRESH-TOKEN-b92d-1"]


def test_disconnecting_twice_is_not_an_error(client, auth, oauth_jira):
    """Idempotent. A 404 would make the ordinary double-click read as a failure."""
    body = client.delete("/connectors/jira/connection", headers=auth).json()
    assert body["disconnected"] is False


def test_you_can_only_disconnect_yourself(client, auth, oauth_jira, idp):
    """There is no principal in this URL and there will not be one."""
    start = client.post("/connectors/jira/connect", headers=auth).json()
    state = start["authorize_url"].split("state=")[1].split("&")[0]
    client.get("/connect/callback", params={"state": state, "code": "c"}, follow_redirects=False)

    sam = {"Authorization": f"Bearer {idp.token(sub='00u-sam', email='sam@acme.com')}"}
    assert client.delete("/connectors/jira/connection", headers=sam).json() == {
        "disconnected": False,
        "revoked_upstream": None,
    }
    # Priya's connection is untouched.
    rows = {r["connector_id"]: r for r in client.get("/connections", headers=auth).json()}
    assert rows["jira"]["state"] == "connected"


def test_a_connection_needing_re_consent_says_so_on_the_page(client, auth, oauth_jira):
    """The state a run would otherwise be the first to report."""

    start = client.post("/connectors/jira/connect", headers=auth).json()
    state = start["authorize_url"].split("state=")[1].split("&")[0]
    client.get("/connect/callback", params={"state": state, "code": "c"}, follow_redirects=False)

    priya = logged_in_id(client, auth)
    storage.active().mark_connection_reconsent(
        TEST_TENANT, "user", priya, "jira", reason="Consent was withdrawn at Atlassian."
    )

    rows = {r["connector_id"]: r for r in client.get("/connections", headers=auth).json()}
    assert rows["jira"]["state"] == "reconnect"
    assert rows["jira"]["reconsent_reason"] == "Consent was withdrawn at Atlassian."


def _instant(wire: str):
    """Parse a stamp off `ConnectionSummary`, which spells UTC with a trailing `Z`.

    **A helper rather than `datetime.fromisoformat`, and the reason is a finding.** This
    model's three instants are typed `datetime` rather than `str` — 035f decision 11, and
    `expires_at` has been that way since 7b — so pydantic serialises them as
    `...582268Z`, where every other stamp in this API is a `str` built by a route's
    `_stamp` helper and spelled `...582268+00:00`.

    `datetime.fromisoformat` **cannot parse the `Z` form before Python 3.11**, which this
    project supports (`requires-python = ">=3.10"`). So the two tests below passed on
    3.12 and failed on 3.10 with `ValueError: Invalid isoformat string`, in CI, having
    been green locally — and that is not a fact about the tests. A Python client on 3.10
    reading `GET /connections` hits the same `ValueError` on these three fields and on no
    other stamp in the API.

    Not fixed here: normalising the spelling means touching every response model in
    `schemas.py` or changing a field that has shipped since 7b, which is the cross-cutting
    cost a connections chunk must not be the reason for. It is a `DEFERRED.md` row, and
    this docstring is the address the row points at.
    """
    from datetime import datetime

    return datetime.fromisoformat(wire.replace("Z", "+00:00"))


def test_a_connected_row_carries_the_two_stamps_the_route_never_passed(
    client, auth, oauth_jira
):
    """**Step 035f.** Both columns have been stored, projected by both stores and handed
    to this route for eleven steps, and the route named neither in the constructor.

    Not 035c's silent-drop class, and the difference is worth keeping straight:
    `OwnedToken` lost `acts_as_owner` because the route built it with `**row` and pydantic
    dropped a key the model had not declared. `ConnectionSummary` is built with explicit
    kwargs, so nothing was dropped — two facts were simply never passed. Same outcome for
    a reader, and only one of the two is a mechanism that recurs in silence.

    The consequence was migration 024's own prediction going unmade: *"Without the column,
    'this connection will need re-consenting' cannot be predicted at all, only discovered
    by a run failing."*
    """
    from datetime import datetime, timezone

    from conftest import TEST_ACTOR

    priya = logged_in_id(client, auth)
    lapse = datetime(2099, 3, 4, 10, tzinfo=timezone.utc)
    storage.active().save_connection(
        TEST_TENANT,
        "user",
        priya,
        "jira",
        ciphertext=b"sealed",
        key_id="k1",
        credential_kind="oauth",
        expires_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        refresh_expires_at=lapse,
        account_label="priya@acme.com",
        actor=TEST_ACTOR,
    )

    row = {r["connector_id"]: r for r in client.get("/connections", headers=auth).json()}[
        "jira"
    ]

    assert row["state"] == "connected"
    assert row["refresh_expires_at"].startswith("2099-03-04T10:00:00")
    # Not asserted to a value — `now()` is the store's — but it must be there and it must
    # be an instant a client can parse, which is the whole of what a reader needs.
    assert _instant(row["updated_at"]).year >= 2020


def test_an_unconnected_row_sends_all_three_stamps_as_null(client, auth, oauth_jira):
    """**Required is not the same as non-null, and this row is the proof.**

    A connector nobody has connected has no expiry, no lapse and no last-changed, because
    there is no row to have them. All three keys are still *sent* — 035f made every field
    required — because *there is no connection* and *the server did not say* are different
    answers and only the first can occur here.
    """
    row = {r["connector_id"]: r for r in client.get("/connections", headers=auth).json()}[
        "jira"
    ]

    assert row["state"] == "connectable"
    assert row["expires_at"] is None
    assert row["refresh_expires_at"] is None
    assert row["updated_at"] is None
    # And the keys are present rather than merely falsy, which is the half a `.get()`
    # would not have caught.
    assert {"expires_at", "refresh_expires_at", "updated_at"} <= set(row)


def test_reconnecting_moves_the_last_changed_stamp(client, auth, oauth_jira):
    """The stamp is *changed*, not *connected*, and this is why the word matters.

    `created_at` is preserved across a reconnection deliberately — migration 013: *"when
    did this person first connect" and "when did this credential last change" are two
    questions* — and `updated_at` is the one that moves. `--list-connections` printed this
    column under the heading `connected` until 035f corrected it, which it had not meant
    since the first refresh.
    """
    for _ in range(2):
        start = client.post("/connectors/jira/connect", headers=auth).json()
        state = start["authorize_url"].split("state=")[1].split("&")[0]
        client.get(
            "/connect/callback",
            params={"state": state, "code": "c"},
            follow_redirects=False,
        )

    priya = logged_in_id(client, auth)
    stored = storage.active().find_connection(TEST_TENANT, "user", priya, "jira")
    row = {r["connector_id"]: r for r in client.get("/connections", headers=auth).json()}[
        "jira"
    ]

    assert _instant(row["updated_at"]) == stored["updated_at"]
    assert stored["updated_at"] > stored["created_at"]


def test_a_connection_whose_consent_flow_was_removed_stays_connected_and_asks_nothing(
    client, auth, oauth_jira
):
    """Two independent rows, and the state machine reads both — 035f's fourth combination.

    `_state_of` returns `connected` on the strength of the *credential*, so removing the
    OAuth application leaves the connection working (migration 021's argument: a stored
    credential is evidence and an administrative action about configuration must not
    destroy it). What goes is the **ask**, because that lived on the application — which
    is the clearest available demonstration that `scopes` was never a property of the
    connection.
    """
    from carnet.access import oauth as oauth_access

    start = client.post("/connectors/jira/connect", headers=auth).json()
    state = start["authorize_url"].split("state=")[1].split("&")[0]
    client.get("/connect/callback", params={"state": state, "code": "c"}, follow_redirects=False)

    oauth_access.unconfigure(TEST_TENANT, "jira", actor="system:test")

    row = {r["connector_id"]: r for r in client.get("/connections", headers=auth).json()}["jira"]

    assert row["state"] == "connected"
    assert row["scopes"] == []
    # The credential is untouched, and the stamps that describe it are still sent.
    assert row["credential_kind"] == "oauth"
    assert row["updated_at"] is not None


def test_a_broken_connection_with_no_flow_left_is_unavailable_and_still_sends_its_stamps(
    client, auth, oauth_jira
):
    """The half-state's own half. `_state_of` collapses `reconnect` onto `unavailable`
    when there is nothing to reconnect *with* — saying "Reconnect" there would be the
    dead-button failure again — and the row's facts are sent either way.

    Worth pinning because it is the one path where a row exists, a reason exists, and the
    state names neither: a client that inferred *there is no connection* from
    `unavailable` would be wrong about a credential that is sitting in the database.
    """
    from carnet.access import oauth as oauth_access

    start = client.post("/connectors/jira/connect", headers=auth).json()
    state = start["authorize_url"].split("state=")[1].split("&")[0]
    client.get("/connect/callback", params={"state": state, "code": "c"}, follow_redirects=False)

    priya = logged_in_id(client, auth)
    storage.active().mark_connection_reconsent(
        TEST_TENANT, "user", priya, "jira", reason="The grant is gone."
    )
    oauth_access.unconfigure(TEST_TENANT, "jira", actor="system:test")

    row = {r["connector_id"]: r for r in client.get("/connections", headers=auth).json()}["jira"]

    assert row["state"] == "unavailable"
    assert row["reconsent_reason"] == "The grant is gone."
    assert row["credential_kind"] == "oauth"
    assert row["updated_at"] is not None


def test_the_wire_carries_combinations_the_screen_ignores(client, auth, oauth_jira):
    """**The route reports the row; it does not decide what a reader may see.**

    A *static* credential carrying a refresh lifetime is representable and meaningless —
    nothing renews a pasted token — and `ConnectionsPage` renders nothing for it. That is
    a rendering decision, and it must stay one: a route that started filtering
    combinations would be a second opinion about which facts are interesting, in the
    layer that cannot see the screen.
    """
    from datetime import datetime, timezone

    from conftest import TEST_ACTOR

    priya = logged_in_id(client, auth)
    storage.active().save_connection(
        TEST_TENANT, "user", priya, "jira",
        ciphertext=b"pasted", key_id="k1", credential_kind="static",
        refresh_expires_at=datetime(2030, 6, 1, tzinfo=timezone.utc),
        actor=TEST_ACTOR,
    )

    row = {r["connector_id"]: r for r in client.get("/connections", headers=auth).json()}["jira"]

    assert row["credential_kind"] == "static"
    assert row["refresh_expires_at"].startswith("2030-06-01")


def test_every_row_carries_every_field_whatever_its_state(client, auth, oauth_jira, vetted_github):
    """The key set is the same on all four states, which is what *required* means on the
    wire and what a generated client is entitled to assume.

    Asserted across states rather than on one row, because the route builds each summary
    in the same constructor and a conditional kwarg would break exactly one of them.
    """
    priya = logged_in_id(client, auth)
    storage.active().save_connection(
        TEST_TENANT, "user", priya, "jira", ciphertext=b"x", key_id="k1",
        actor="system:test",
    )

    rows = client.get("/connections", headers=auth).json()
    states = {r["connector_id"]: r["state"] for r in rows}

    assert states == {"jira": "connected", "github-mcp": "unavailable"}
    assert {frozenset(r) for r in rows} == {
        frozenset(
            {
                "connector_id", "description", "state", "account_label",
                "credential_kind", "expires_at", "refresh_expires_at", "updated_at",
                "reconsent_reason", "scopes",
                # Migration 051 — what those scopes permit, in words. Present on every
                # row whatever its state, like the rest: an empty object is what "this
                # connector's consent flow has no prose" looks like, and it is a
                # different fact from the key being absent.
                "scope_notes",
            }
        )
    }


def test_the_connections_response_declares_every_field_as_required(client, auth, oauth_jira):
    """035c's decision 1 at its fourth model, and the one plan 035 does not mention.

    The route supplies all ten kwargs unconditionally and the model defaulted six of
    them, so the document's `required` set was `['connector_id', 'state']` and a generated
    client typed a person's connection state — the account label, the credential kind, the
    expiry, the reason it stopped working — as possibly-absent. That is the reassuring
    direction: *this connector has no consent flow configured* and *the server did not
    say* are different answers, and only the first can occur.

    Asserted against the document rather than the model, because the document is what a
    client is generated from and is the artefact a default lies to. 035d broke the same
    rule on five fields and its edge pass caught it here rather than in `schemas.py`.

    Note what this does **not** assert: that any value is non-null. Three of these are
    null on a connector nobody has connected, and required means the key is sent.
    """
    client.get("/connections", headers=auth)

    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    assert sorted(schemas["ConnectionSummary"]["required"]) == [
        "account_label",
        "connector_id",
        "credential_kind",
        "description",
        "expires_at",
        "reconsent_reason",
        "refresh_expires_at",
        "scopes",
        "state",
        "updated_at",
    ]


def test_the_scopes_on_the_wire_are_the_application_s_ask(client, auth, oauth_jira):
    """**035f trap 1, pinned so nobody reads the field's name and believes it.**

    `scopes` comes from `connector_oauth`, not from the connection: it is the list
    `oauth.begin` builds the authorize query from, and it changes when an administrator
    reconfigures the application — including for somebody who connected under the old one.
    The scope a person actually granted is stored nowhere.

    So a connected row's `scopes` is *what this connector asks for now*, and any client
    rendering it beside a live credential has to say so. The register carries the fix,
    which is a column and a migration.
    """
    from carnet.access import oauth as oauth_access
    from conftest import TEST_ACTOR, TEST_HOST

    start = client.post("/connectors/jira/connect", headers=auth).json()
    state = start["authorize_url"].split("state=")[1].split("&")[0]
    client.get("/connect/callback", params={"state": state, "code": "c"}, follow_redirects=False)

    before = {r["connector_id"]: r for r in client.get("/connections", headers=auth).json()}
    assert before["jira"]["state"] == "connected"
    assert before["jira"]["scopes"] == ["read:jira-work", "offline_access"]

    # An administrator widens the ask. Nobody reconsented and no credential changed.
    oauth_access.configure(
        TEST_TENANT,
        "jira",
        authorize_endpoint=f"https://{TEST_HOST}/authorize",
        token_endpoint=f"https://{TEST_HOST}/token",
        revoke_endpoint=f"https://{TEST_HOST}/revoke",
        client_id="client-abc",
        client_secret="MARKER-CLIENT-SECRET-e3f1",
        scopes=("read:jira-work", "offline_access", "write:jira-work"),
        actor=TEST_ACTOR,
    )

    after = {r["connector_id"]: r for r in client.get("/connections", headers=auth).json()}

    assert after["jira"]["state"] == "connected"
    # The same credential, minted before any of this, now described by a wider list.
    assert after["jira"]["scopes"] == [
        "read:jira-work",
        "offline_access",
        "write:jira-work",
    ]


def test_a_revoked_host_answers_a_sentence_rather_than_a_500(client, auth, oauth_jira):
    """The **third** unmapped exception 7b found by driving routes at their edges.

    An administrator revoking a host between a consent flow starting and finishing raised
    `EgressRefused`, which had no handler and therefore no status code — so an in-flight
    callback answered *Internal Server Error*. `OAuthRefused` and `ConnectionRefused` were
    the first two, and 011's `NoSuchGroupError` was the same shape a step earlier. The
    table in `api/errors.py` now says so and is a checklist for the next route.
    """
    from conftest import TEST_HOST

    start = client.post("/connectors/jira/connect", headers=auth).json()
    state = start["authorize_url"].split("state=")[1].split("&")[0]
    storage.active().revoke_host(TEST_TENANT, TEST_HOST, actor="system:test")

    response = client.get(
        "/connect/callback", params={"state": state, "code": "c"}, follow_redirects=False
    )

    assert response.status_code == 303, response.text
    assert "failed=" in response.headers["location"]
    assert TEST_HOST in response.headers["location"]


def test_every_refusal_this_api_can_raise_has_a_status_code():
    """The guard on the handler table, and it exists because 7b filled three gaps in it.

    `OAuthRefused`, `ConnectionRefused` and `EgressRefused` all reach routes and none had a
    handler, so each was a **500** — or, worse, a 503 saying "storage unavailable" about a
    caller's typo. Step 011 hit the identical shape with `NoSuchGroupError`.

    Asserted by walking the registered handlers rather than by adding a fourth test that
    happens to exercise one path: the failure is a class that reaches a route with nobody
    having thought about its status code, and only the *table* can be checked for that.
    """
    from carnet.access.connections import ConnectionRefused
    from carnet.access.groups import GroupRefused
    from carnet.access.oauth import OAuthRefused
    from carnet.access.recipes import RecipeRefused
    from carnet.access.roles import RoleRequired
    from carnet.access.users import AccessDenied, UserRefused
    from carnet.core.credentials import CredentialError
    from carnet.storage.base import ConnectorExistsError
    from carnet.tools import RegistrationRefused
    from carnet.tools.mcp.egress import EgressRefused
    from carnet.tools.mcp.transport import TransportError

    handled = set(create_app().exception_handlers)

    # `RoleRequired` and `GroupRefused` join in 12b, in the same change as the routes that
    # raise them — which is the whole of what the four rows above taught.
    #
    # **Four more join in 12c**, and two of them were not in the plan. `RegistrationRefused`
    # and `TransportError` were; `ConnectorExistsError` and `CredentialError` were found by
    # reading this table against the new routes rather than by driving them, which is the
    # first time that has happened rather than the other way round. Unmapped they would
    # have been a **503** for a connector id that is taken and a **500** for an
    # administrator whose own OAuth token expired.
    # **`AccessDenied` joins in 022b, and it is the oldest gap this table has had.** The
    # class has existed since authentication did, and `deps.py` catches it there — so it
    # looked handled while nothing raised it from a *request body*. `schedules.create`
    # does: somebody else's token, and a machine with no grant on the agent. Both were
    # 500s from a route until the handler existed, which is this table's own failure mode
    # arriving through a class nobody would have thought to look at. (The route that
    # raised it left with step 078; the class still reaches routes.)
    # **`RecipeRefused` joins in 068, and it very nearly repeated the whole pattern.** The
    # route shipped before the handler, so a recipe file that would not parse was an
    # unhandled exception with no sentence and no filename — found by driving the route
    # with a broken file rather than by reading it. It is the one refusal here that maps
    # to **500 on purpose**: a recipe is a file in this repository, so the caller did
    # nothing wrong and a 4xx would be a lie about whose problem it is.
    for refusal in (
        OAuthRefused,
        ConnectionRefused,
        EgressRefused,
        RoleRequired,
        GroupRefused,
        RegistrationRefused,
        ConnectorExistsError,
        CredentialError,
        TransportError,
        AccessDenied,
        RecipeRefused,
        UserRefused,
    ):
        assert refusal in handled, (
            f"{refusal.__name__} reaches a route and has no handler, so it is a 500. "
            "See the table at the top of api/errors.py."
        )


# --- platform roles: the seam, from both sides -------------------------------------
#
# 12b. The four features stacked behind "which of many users may administer this tenant"
# are unblocked by one role, one dependency and one refusal — and the assertions that
# matter most are not the happy path. They are:
#
#   - `test_an_administrator_still_gets_404_from_an_agent_they_hold_no_grant_on`, which is
#     the boundary migration 026 states in the schema's voice: an admin is not a superuser
#   - `test_every_admin_route_carries_the_dependency`, because that rule fails **silently**
#   - `test_http_can_never_mint_a_system_principal`, which is the precondition the
#     always-admin rule for `system` rests on


@pytest.fixture
def admin(client, auth):
    """Whoever `auth` authenticates as, granted the `admin` platform role."""
    principal_id = logged_in_id(client, auth)
    storage.active().grant_platform_role(
        TEST_TENANT, "user", principal_id, "admin", actor="system:cli"
    )
    return principal_id


def test_every_admin_route_carries_the_dependency():
    """The rule that fails silently, asserted by walking the route table.

    A route added to the administrative surface without `admin_from_request` *works* —
    for the wrong person — and nothing about it looks wrong until an incident. So the list
    is written down in `deps.ADMIN_SURFACE` and compared **in both directions**: a route
    missing the dependency fails, and a route carrying it that nobody added to the list
    fails too, because the second means somebody closed a surface without recording it.

    `test_every_endpoint_is_sync`'s device, applied to authorization.
    """
    guarded = set()
    for route in _our_routes():
        names = {
            dependency.call
            for dependency in route.dependant.dependencies
        }
        if deps.admin_from_request in names:
            guarded |= {(method, route.path) for method in (route.methods or set())}

    assert guarded == deps.ADMIN_SURFACE


def test_http_can_never_mint_a_system_principal(registered, client, auth):
    """The precondition `access/roles.py` rests on, pinned rather than remembered.

    `require_admin` lets every `system` principal through, and that is only safe because
    no HTTP caller can be one: every path through `api/deps.py` ends at `users.resolve`,
    which returns `Principal.user(...)`. If a future entry point mints `system` principals
    from network input, this is the tripwire.
    """
    client.get("/agents", headers=auth)

    kinds = {row["id"]: "user" for row in storage.active().list_users(TEST_TENANT)}
    assert kinds, "nobody logged in, so this asserted nothing"

    source = pathlib.Path(deps.__file__).read_text()
    assert "Principal.system" not in source
    assert "users.resolve" in source


def test_an_unauthenticated_caller_on_an_admin_route_is_401_not_403(client, registered):
    """Decision 4's ordering, and it is cheap now and incoherent later. A 403 here would
    tell somebody who has not even proved a tenant that this route exists."""
    assert client.get("/admin-audit").status_code == 401
    assert client.post("/groups", json={"name": "x"}).status_code == 401


def test_an_authenticated_non_admin_is_403_with_an_actionable_sentence(client, auth):
    """403 rather than the 404 an agent route answers, and the inversion has a reason:
    the resource an admin route names is *the route*, whose existence is published in the
    OpenAPI document and is identical for every tenant."""
    response = client.get("/admin-audit", headers=auth)

    assert response.status_code == 403
    detail = response.json()["detail"]
    assert "administrator" in detail
    assert "grant" in detail


def test_metrics_needs_the_role(client, auth):
    """057. The scrape is admin surface: every caller's operational state, nobody's
    data — 401 before the route's existence is confirmed, 403 without the role."""
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers=auth).status_code == 403


def test_metrics_renders_the_numbers_somebody_can_watch(client, auth, admin):
    """057. Prometheus text: build info, the session-pool gauges, the broker counters.

    The broker counter is bumped directly here because the rendering seam is this
    route's own subject; that a real brokered call increments it is
    `test_broker.test_every_call_counts_itself`'s.
    """
    import carnet
    from carnet import metrics as metrics_module

    metrics_module.reset()
    metrics_module.bump("carnet_broker_calls_total", decision="allow", outcome="ok")
    try:
        response = client.get("/metrics", headers=auth)
    finally:
        metrics_module.reset()

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    body = response.text
    assert f'carnet_build_info{{version="{carnet.__version__}"}} 1' in body
    assert "carnet_mcp_sessions_max " in body
    assert 'carnet_broker_calls_total{decision="allow",outcome="ok"} 1' in body


def test_the_json_log_formatter_emits_one_parseable_object():
    """057. One line, valid JSON, level and message intact — and the newline the
    exception path would carry stays escaped inside the object, never raw in the
    stream, because a log pipeline reads lines."""
    import json as json_lib
    import logging as logging_module

    from carnet.api import JsonLogFormatter

    record = logging_module.LogRecord(
        "carnet.test", logging_module.WARNING, __file__, 1,
        "hello %s", ("world",), None,
    )
    line = JsonLogFormatter().format(record)

    entry = json_lib.loads(line)
    assert entry["level"] == "WARNING"
    assert entry["message"] == "hello world"
    assert "\n" not in line


def test_the_log_knobs_refuse_garbage_with_a_sentence(monkeypatch):
    """057. `_retention_days()`'s treatment: a typo'd level that silently means `info` is the
    "does nothing, silently" shape the knobs scene exists to kill."""
    from carnet import config as config_module

    monkeypatch.setenv("CARNET_LOG_LEVEL", "dbug")
    with pytest.raises(ValueError, match="CARNET_LOG_LEVEL"):
        config_module._log_level()

    monkeypatch.setenv("CARNET_LOG_FORMAT", "yaml")
    with pytest.raises(ValueError, match="CARNET_LOG_FORMAT"):
        config_module._log_format()

    monkeypatch.setenv("CARNET_LOG_LEVEL", " WARNING ")
    monkeypatch.setenv("CARNET_LOG_FORMAT", "JSON")
    assert config_module._log_level() == "warning"
    assert config_module._log_format() == "json"


def test_the_403_names_no_current_administrators(client, auth, idp, registered):
    """A directory of who to phish is not an error message's job. The cost is stated in
    the plan's known limits: a person asks a colleague rather than reading a screen."""
    sam = {"Authorization": f"Bearer {idp.token(sub='00u-sam', email='sam@acme.com')}"}
    sam_id = logged_in_id(client, sam)
    storage.active().grant_platform_role(
        TEST_TENANT, "user", sam_id, "admin", actor="system:cli"
    )

    detail = client.get("/admin-audit", headers=auth).json()["detail"]

    assert sam_id not in detail
    assert "sam@acme.com" not in detail


def test_the_administrative_log_becomes_readable_once_the_role_is_granted(
    client, auth, admin, demo_agent
):
    """011's most-argued deferral, retired. *A log nobody can read is a log nobody notices
    is broken* — and until 12b reading it meant `psql` or a shell."""
    response = client.get("/admin-audit", headers=auth)

    assert response.status_code == 200
    actions = [row["action"] for row in response.json()]
    assert "role.grant" in actions
    assert "grant.create" in actions

    first = response.json()[0]
    assert set(first) == {
        "v",
        "ts",
        "actor_kind",
        "actor_id",
        "action",
        "target_kind",
        "target_id",
        "detail",
    }


def test_the_administrative_log_is_refused_again_after_a_revoke(client, auth, admin):
    """The whole seam in one test: 403, grant, 200, revoke, 403."""
    assert client.get("/admin-audit", headers=auth).status_code == 200

    storage.active().revoke_platform_role(
        TEST_TENANT, "user", admin, "admin", actor="system:cli"
    )

    assert client.get("/admin-audit", headers=auth).status_code == 403


def test_reading_the_log_is_not_itself_recorded(client, auth, admin):
    """`ADMIN_ACTIONS` records changes to who-may-do-what, and a read changes nothing. An
    access log for reads is a different table with a different retention question, and it
    is deliberately not smuggled in here."""
    before = len(client.get("/admin-audit", headers=auth).json())

    client.get("/admin-audit", headers=auth)
    client.get("/admin-audit", headers=auth)

    assert len(client.get("/admin-audit", headers=auth).json()) == before


def test_the_log_limit_is_capped_by_the_signature(client, auth, admin):
    """A 422 naming the field rather than a silent truncation — which is the one behaviour
    a log route must not have, because it reads as "that is everything"."""
    assert client.get("/admin-audit?limit=1", headers=auth).status_code == 200
    assert client.get("/admin-audit?limit=0", headers=auth).status_code == 422
    assert client.get("/admin-audit?limit=100000", headers=auth).status_code == 422


def test_the_log_answers_only_for_the_callers_tenant(client, auth, admin):
    """The tenant comes off the principal, never the URL. `deps.py`'s standing rule."""
    storage.active().create_tenant("globex", "Globex")
    storage.active().grant_platform_role(
        "globex", "user", "u-elsewhere", "admin", actor="system:cli"
    )

    targets = {row["target_id"] for row in client.get("/admin-audit", headers=auth).json()}

    assert "user:u-elsewhere" not in targets


# --- the overview -------------------------------------------------------------------
#
# Step 041. The route's own assertions; the arithmetic is pinned in
# `test_storage_contract.py` against both stores.


def _door_call(**overrides):
    """One door call in the audit log — no run row, which is the whole point."""
    record = {
        "v": 7,
        "ts": f"{door.budget_window().isoformat()}T09:00:00.000+00:00",
        "run_id": "door-0123456789ab",
        "principal_kind": "machine",
        "principal_id": "tok_1",
        "agent": "triage",
        "tool": "search_issues",
        "effect": "read",
        "args": {},
        "decision": "allow",
        "reason": "",
        "outcome": "ok",
        "duration_ms": 12,
        "response_bytes": 100,
        "identity_source": "verified",
    }
    record.update(overrides)
    storage.active().append_audit(TEST_TENANT, record)


def test_the_overview_needs_the_admin_role(client, auth):
    """Tenant-wide governance data, so it sits on the administrative surface — and the
    refusal is itself recorded, which means it appears next month on the very page it
    was refused from."""
    assert client.get("/admin/overview", headers=auth).status_code == 403


def test_the_overview_series_are_dense(client, auth, admin):
    """Every series has exactly one entry per day of the window, whatever the data.

    The fill is the route's job — both stores return sparse rows on purpose, so that a
    fake cannot be kinder than Postgres. A sparse list reaching the page would make it
    guess whether a gap is *nothing happened* or *no answer*.
    """
    body = client.get("/admin/overview?days=7", headers=auth).json()

    assert body["window"]["days"] == 7
    for series in (
        "door_calls", "door_spend", "door_effects", "identity", "refusals"
    ):
        assert len(body[series]) == 7, series


def test_an_empty_tenant_answers_zeros_rather_than_nothing(client, auth, admin):
    """A deployment nobody has used yet renders a page of zeros, not a broken one."""
    body = client.get("/admin/overview", headers=auth).json()

    assert body["totals"]["door_calls"] == 0
    assert all(day["allowed"] == 0 for day in body["door_calls"])


def test_the_overview_counts_a_door_call(client, auth, admin):
    """**The product's usage figure comes from the door.** One door call is one call
    on the page, read from `audit` and nowhere else."""
    _door_call()

    body = client.get("/admin/overview", headers=auth).json()

    assert body["totals"]["door_calls"] == 1


def test_the_identity_split_reaches_the_wire_uncollapsed(client, auth, admin):
    """Three counts, no total. The governance chart, and the one whose whole value is
    that `asserted` is not quietly rendered as `verified`."""
    _door_call(identity_source="verified")
    _door_call(identity_source="asserted")
    _door_call(identity_source="none")

    today = client.get("/admin/overview", headers=auth).json()["identity"][-1]

    assert (today["verified"], today["asserted"], today["none"]) == (1, 1, 1)


# --- step 066: the hour window, the tails, and what the tiles compare against --------


def test_the_one_day_window_buckets_by_the_hour(client, auth, admin):
    """`days=1` is a new window and the only one that groups by the hour.

    It exists because a day's live traffic drawn as one column beside a backdated month
    is an eleven-pixel sliver — the walkthrough finding that made a working demo look
    broken. Twenty-four columns and not "up to now": a chart that ended at the current
    hour would redraw its own width every sixty minutes.
    """
    _door_call()

    body = client.get("/admin/overview?days=1", headers=auth).json()

    assert body["window"]["days"] == 1
    assert body["window"]["bucket"] == "hour"
    assert len(body["door_calls"]) == 24
    assert body["door_calls"][9]["day"].endswith("T09")


def test_every_other_window_still_buckets_by_the_day(client, auth, admin):
    """No client that never asks for a day sees a change — the flag says `day` and the
    labels are dates, exactly as they were before this step existed."""
    body = client.get("/admin/overview?days=7", headers=auth).json()

    assert body["window"]["bucket"] == "day"
    assert len(body["door_calls"][0]["day"]) == len("2026-08-31")


def test_the_window_echoes_dates_even_when_it_buckets_by_hours(client, auth, admin):
    """`since`/`until` are the window's **dates** and not its first and last label.

    With hour buckets the labels are `…T00` and `…T23`, and a footnote reading
    "2026-08-31T00 to 2026-08-31T23, in UTC days" would be two kinds of wrong in one
    sentence.
    """
    body = client.get("/admin/overview?days=1", headers=auth).json()

    assert body["window"]["since"] == body["window"]["until"]
    assert "T" not in body["window"]["since"]


def test_an_ask_below_a_week_now_lands_on_the_day(client, auth, admin):
    """The clamp is nearest, and 066 put a 1 in the offered set — so an ask for 2 lands
    on 1 where it used to land on 7, and still says the ask moved."""
    body = client.get("/admin/overview?days=2", headers=auth).json()

    assert (body["window"]["days"], body["window"]["clamped"]) == (1, True)


def test_a_capped_leaderboard_reaches_the_wire_with_its_tail(client, auth, admin):
    """The walkthrough's first finding, at the route: the response says how many rows
    there really were and what the cap left out.

    Before this the page received fifteen rows and no way to tell "these are all of them"
    from "these are most of them".
    """
    for index in range(18):
        for _ in range(18 - index):
            _door_call(tool=f"tool_{index:02d}")

    body = client.get("/admin/overview", headers=auth).json()

    assert len(body["door_tools"]) == 15
    assert body["tool_count"] == 18
    assert body["tool_tail"] == {"n": 3, "calls": 3 + 2 + 1, "denied": 0}


def test_the_tiles_carry_the_window_before_them(client, auth, admin):
    """`previous` is a denominator, not a dataset — totals only, and never a second set
    of series. "4,120 calls" is a number nobody can size; "4,120, up 18%" is a fact."""
    _door_call()

    body = client.get("/admin/overview?days=7", headers=auth).json()

    assert body["previous"]["door_calls"] == 0
    # Totals, and nothing shaped like a series anywhere in it.
    assert "door_calls" in body["previous"] and isinstance(
        body["previous"]["door_calls"], int
    )


def test_the_three_missing_dimensions_reach_the_page(client, auth, admin):
    """Which permission list admitted it, whose name it went out under, and what the
    refusal said — three columns every audit row has carried and no figure grouped by."""
    _door_call(agent="triage", acting_for="sam@example.com")
    _door_call(decision="deny", reason="tool not granted", outcome="")

    body = client.get("/admin/overview", headers=auth).json()

    assert [row["agent"] for row in body["door_agents"]] == ["triage"]
    assert body["acting_for"][0]["acting_for"] == "sam@example.com"
    assert body["refusal_reasons"] == [{"reason": "tool not granted", "count": 1}]


def test_the_hour_grid_is_window_wide_and_not_a_series(client, auth, admin):
    """`hourly` answers *when is the door busy*, which is about the shape of a week and
    not about any particular Tuesday — so it is not filled and is not per day."""
    _door_call()

    body = client.get("/admin/overview?days=7", headers=auth).json()

    assert len(body["hourly"]) == 1
    assert body["hourly"][0]["hour"] == 9


# --- step 066: the door log's filters ------------------------------------------------


def test_the_door_log_filters_by_every_axis_the_overview_draws(client, auth, admin):
    """Each link the Overview now emits is one of these queries.

    The incident argument the route's docstring asked for is that list: an aggregate that
    cannot point at the rows behind it leaves the reader with a number and no way down.
    """
    _door_call(tool="create_issue", effect="write", decision="allow")
    _door_call(tool="search_issues", effect="read")

    found = client.get(
        "/admin/door-calls?tool=create_issue&effect=write", headers=auth
    ).json()

    assert [row["tool"] for row in found] == ["create_issue"]


def test_a_closed_vocabulary_refuses_a_value_the_column_cannot_hold(client, auth, admin):
    """422 naming the field, never `[]` with a 200.

    `?decision=banana` is not a question with no answers — it is a question the server
    does not have, and an empty 200 would read as *"no refusals"*. That is `limit`'s lie
    in a different costume and it gets `limit`'s treatment.
    """
    assert client.get("/admin/door-calls?decision=banana", headers=auth).status_code == 422


def test_an_open_id_that_matches_nothing_is_an_honest_empty_answer(client, auth, admin):
    """The other half of the asymmetry. An id is whatever somebody was handed during an
    incident and this route has no opinion about its shape."""
    _door_call()

    response = client.get("/admin/door-calls?tool=nonesuch", headers=auth)

    assert response.status_code == 200
    assert response.json() == []


def test_the_door_log_window_covers_the_column_that_linked_to_it(client, auth, admin):
    """A chart column links here with `since`/`until` set to its own day, so the two
    have to mean the same day — inclusive, UTC, the boundary the ceiling charges on."""
    _door_call()
    today = door.budget_window().isoformat()

    found = client.get(
        f"/admin/door-calls?since={today}&until={today}", headers=auth
    ).json()

    assert len(found) == 1


def test_a_malformed_date_is_refused_by_the_signature(client, auth, admin):
    """`date` rather than `str`, so FastAPI answers a typo with a 422 naming the field
    instead of the store matching nothing and the page reading it as "quiet day"."""
    assert client.get("/admin/door-calls?since=yesterday", headers=auth).status_code == 422


def test_usage_does_not_depend_on_whether_the_ceiling_is_enforced(
    client, auth, admin, monkeypatch
):
    """**Plan 041, finding 3, as an assertion.**

    `TokenBudget.reserve` returns ALLOW *before touching storage* when the ceiling is not
    positive — so `mcp_budget` is empty on every deployment that measures without
    enforcing, which is the ordinary shape of a rollout. Sourcing the usage series from
    `audit` instead makes them independent of the dial; only `headroom.metered` moves.

    Turning the dial off and watching the traffic figure stay put is what proves it.
    """
    _door_call()
    _door_call()

    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 1000)
    metered = client.get("/admin/overview", headers=auth).json()

    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 0)
    unmetered = client.get("/admin/overview", headers=auth).json()

    assert metered["totals"]["door_calls"] == unmetered["totals"]["door_calls"] == 2
    assert metered["headroom"]["metered"] is True
    assert unmetered["headroom"]["metered"] is False


# A million Opus input tokens is $15.00 at `core/usage.RATES` — a round number somebody
# can check by hand rather than a float nobody can read.
_A_MILLION_OPUS = {
    "model": "claude-opus-5",
    "input_tokens": 1_000_000,
    "output_tokens": 0,
    "cache_read_tokens": 0,
    "cache_write_tokens": 0,
}


def test_the_overview_draws_what_the_door_cost(client, auth, admin):
    """Step 045b's series, and the first money on this page.

    Priced in the route from token counts the store returned, never stored — 045's
    Amendment 3 kept for the third time, so an operator who fixes their rate table can
    reprice this history.
    """
    _door_call(**_A_MILLION_OPUS)
    _door_call(**_A_MILLION_OPUS)

    body = client.get("/admin/overview", headers=auth).json()

    assert body["door_spend"][-1]["usd"] == 30.0
    assert body["door_spend"][-1]["tokens"] == 2_000_000
    assert body["totals"]["door_usd"] == 30.0
    assert body["totals"]["door_tokens"] == 2_000_000


def test_the_spend_tile_is_exactly_what_the_chart_adds_up_to(client, auth, admin):
    """Summed from the rounded days rather than re-priced over the window, because a tile
    that disagreed with the chart under it by a rounding step is the discrepancy a reader
    actually notices."""
    _door_call(**_A_MILLION_OPUS)

    body = client.get("/admin/overview?days=7", headers=auth).json()

    assert body["totals"]["door_usd"] == round(
        sum(day["usd"] for day in body["door_spend"]), 6
    )


def test_an_ordinary_tool_call_costs_nothing_and_is_still_counted(client, auth, admin):
    """The two series are measured differently, and a reader has to be able to see that:
    `door_calls` counts every call, `door_spend` counts only the ones whose tool reported
    what it spent. On a deployment brokering no model calls the money line is flat zero
    under a busy traffic chart — the truth, rather than a gap."""
    _door_call()

    body = client.get("/admin/overview", headers=auth).json()

    assert body["totals"]["door_calls"] == 1
    assert body["totals"]["door_usd"] == 0.0
    assert body["totals"]["door_unpriced_models"] == []


def test_an_unpriced_model_is_named_on_the_overview_rather_than_billed_at_zero(
    client, auth, admin
):
    """A total that excluded two of the three models in play and said nothing would be the
    wrong number on the one screen built to be trusted at a glance."""
    _door_call(**{**_A_MILLION_OPUS, "model": "llama-3-70b"})

    body = client.get("/admin/overview", headers=auth).json()

    assert body["totals"]["door_usd"] == 0.0
    assert body["totals"]["door_tokens"] == 1_000_000
    assert body["totals"]["door_unpriced_models"] == ["llama-3-70b"]


def test_a_money_refusal_has_its_own_line_on_the_refusals_chart(client, auth, admin):
    """The fourth band. *Too many calls* and *too much money* are answered differently, so
    a single line summing them would spike identically for either — and the one absorbed
    would read zero forever."""
    from carnet.storage import CEILING_REFUSAL_MARKER, SPEND_REFUSAL_MARKER

    _door_call(
        decision="deny",
        reason=f"machine:tok_1 has spent $15.00 {SPEND_REFUSAL_MARKER}, and the "
        "ceiling is $10.00.",
    )
    _door_call(
        decision="deny",
        reason=f"this token has made 1000 {CEILING_REFUSAL_MARKER}, which is its ceiling.",
    )
    _door_call(decision="deny", reason="agent 'triage' may not call 'delete_repo'")

    today = client.get("/admin/overview", headers=auth).json()["refusals"][-1]

    assert (today["door_spend"], today["ceiling"], today["policy"]) == (1, 1, 1)


def test_an_over_large_window_is_clamped_rather_than_refused(client, auth, admin):
    """A dashboard that will not load because somebody typed a big number into a URL is
    worse than one that loads the largest honest answer and says it did. Silent
    substitution would be worse still — a caller could draw a quarter and label it a
    year."""
    body = client.get("/admin/overview?days=365", headers=auth).json()

    assert body["window"]["days"] == 90
    assert body["window"]["clamped"] is True
    assert len(body["door_calls"]) == 90


def test_an_offered_window_is_not_reported_as_clamped(client, auth, admin):
    """The other direction, so `clamped` means something."""
    body = client.get("/admin/overview?days=30", headers=auth).json()

    assert (body["window"]["days"], body["window"]["clamped"]) == (30, False)


def test_a_day_with_no_timed_call_reports_null_latency_not_zero(client, auth, admin):
    """Zero would draw a chart claiming instant calls on a day when nothing ran."""
    body = client.get("/admin/overview?days=7", headers=auth).json()

    assert all(day["median_ms"] is None for day in body["door_latency"])


def test_the_overview_answers_only_for_the_callers_tenant(client, auth, admin):
    """The tenant comes off the principal, never the URL — `deps.py`'s standing rule,
    and on this route a leak would be one customer's whole activity profile."""
    storage.active().create_tenant("globex", "Globex")
    storage.active().append_audit(
        "globex",
        {
            "v": 7,
            "ts": f"{door.budget_window().isoformat()}T09:00:00.000+00:00",
            "run_id": "door-ffffffffffff",
            "principal_kind": "machine",
            "principal_id": "tok_elsewhere",
            "agent": "theirs",
            "tool": "search_issues",
            "decision": "allow",
            "identity_source": "none",
        },
    )

    body = client.get("/admin/overview", headers=auth).json()

    assert body["totals"]["door_calls"] == 0
    assert body["callers"] == []


# --- an admin is not a superuser ---------------------------------------------------


def test_an_administrator_still_gets_404_from_an_agent_they_hold_no_grant_on(
    client, auth, admin, unshared_agent
):
    """**Finding 6, over HTTP.** The ladder answers who may use an agent and the role
    answers who may administer the tenant; they never meet. 7b is why this must hold: an
    `admin` that implied agent access would rebuild the operator who holds everybody's
    credentials, one grant away.
    """
    assert client.get("/agents/demo", headers=auth).status_code == 404
    assert client.get("/agents", headers=auth).json() == []

    submitted = submit(client, auth, agent="demo")
    assert submitted.status_code == 404


def test_an_administrator_sees_no_extra_connections(client, auth, admin, oauth_jira, idp):
    """The credential half of the same boundary. Whose account is connected where is
    tenant *data*, and `GET /connections` answers for the caller alone."""
    sam = {"Authorization": f"Bearer {idp.token(sub='00u-sam', email='sam@acme.com')}"}
    start = client.post("/connectors/jira/connect", headers=sam).json()
    state = start["authorize_url"].split("state=")[1].split("&")[0]
    client.get("/connect/callback", params={"state": state, "code": "c"}, follow_redirects=False)

    mine = {row["connector_id"]: row for row in client.get("/connections", headers=auth).json()}

    assert mine["jira"]["state"] == "connectable"


# --- GET /me -----------------------------------------------------------------------


def test_me_says_who_you_are_and_that_you_are_not_an_administrator(client, auth):
    """No role required, and that is the point: a non-administrator needs this precisely
    in order to be told they are not one, so the app does not render a door that refuses
    them. `AgentDetail.your_role`'s problem, one level up."""
    body = client.get("/me", headers=auth).json()

    assert body["admin"] is False
    assert body["kind"] == "user"
    assert body["email"] == "priya@acme.com"
    assert body["principal"] == f"user:{logged_in_id(client, auth)}"


def test_me_says_admin_once_the_row_exists(client, auth, admin):
    assert client.get("/me", headers=auth).json()["admin"] is True


def test_me_needs_a_token(client, registered):
    assert client.get("/me").status_code == 401


def test_me_reads_our_row_rather_than_reaching_into_the_token(client, isolated_storage, monkeypatch):
    """**`email` is a per-provider claim** — see migration 010, which exists because of a
    real token rather than a spec — so a route that read `claims["email"]` would report
    nothing for a provider that puts the address somewhere else, while every other screen
    named the person correctly.

    Here the provider puts it in `preferred_username`, which is what Entra frequently
    does. `/me` answers from the `users` row, where `_email(provider, claims)` already
    resolved it.
    """
    idp = Idp()
    storage.active().save_tenant_idp(
        TEST_TENANT, idp.row(email_claim="preferred_username")
    )
    monkeypatch.setattr(
        providers,
        "KEYS",
        JwksCache(fetch=lambda uri: oidc.keys_from_jwks({"keys": [idp.jwk()]})),
    )
    headers = {
        "Authorization": "Bearer "
        + idp.token(email=None, preferred_username="priya@acme.com", name="Priya Patel")
    }

    body = client.get("/me", headers=headers).json()

    assert body["email"] == "priya@acme.com"
    assert body["display_name"] == "Priya Patel"


# --- the access-denial log: who tried, and was refused (015) ------------------------
#
# The assertions that matter most here are not the happy path. They are the two
# byte-identity checks — the refusal responses must be **unchanged** from before the
# log existed, asserted by equality with the exact sentences, because the
# anti-enumeration property lives in those bytes and this step must be invisible from
# outside — and `test_the_denial_log_records_its_own_door`, because the reader is
# guarded by the same seam it reads.


def read_denials(**filters):
    return storage.active().denial_records(TEST_TENANT, **filters)


def test_a_user_probing_an_editor_route_is_recorded_with_both_levels(
    client, auth, unshared_agent
):
    """Verification 3: today's 404, and a record saying `required='editor'`,
    `held='user'` — the too-low case incident review reads closest."""
    share_with_caller(client, auth, "demo", role="user")

    response = client.patch("/agents/demo", json={"system": "x"}, headers=auth)

    assert response.status_code == 404
    assert response.json()["detail"] == "no agent named 'demo'"

    (record,) = read_denials()
    assert (record["required"], record["held"]) == ("editor", "user")


def test_a_non_admin_on_an_admin_route_is_recorded_and_the_403_is_unchanged(
    client, auth
):
    """Verification 4 over HTTP. The detail is the exact sentence `require_admin` has
    always produced — equality, not substring, because byte-identity is the claim."""
    from carnet.access.roles import NOT_AN_ADMINISTRATOR

    caller = logged_in_id(client, auth)

    response = client.get("/admin-audit", headers=auth)

    assert response.status_code == 403
    assert response.json()["detail"] == NOT_AN_ADMINISTRATOR

    (record,) = read_denials()
    assert (record["principal_kind"], record["principal_id"]) == ("user", caller)
    assert record["resource_kind"] == "admin"
    assert (record["required"], record["held"]) == ("admin", "")


def test_the_denial_log_records_its_own_door(client, auth):
    """Verification 6: `GET /admin/denials` refuses a non-admin with the same 403 as
    every admin route, and that refusal appears in the log it was refused from — one
    row, not recursive, because the record is written where `require_admin` refuses
    and the reader is just another caller of it."""
    from carnet.access.roles import NOT_AN_ADMINISTRATOR

    response = client.get("/admin/denials", headers=auth)

    assert response.status_code == 403
    assert response.json()["detail"] == NOT_AN_ADMINISTRATOR

    (record,) = read_denials()
    assert record["resource_kind"] == "admin"


def test_an_unauthenticated_caller_gets_401_and_no_record(client, registered):
    """Decision 6's last row: a failed authentication has no principal to attribute
    and is the identity provider's log, not ours."""
    assert client.get("/admin/denials").status_code == 401

    assert read_denials() == []


def test_a_kind_the_log_cannot_hold_is_refused_rather_than_answered_empty(client, admin, auth):
    """The asymmetry with the two id filters, which is deliberate.

    An id that matches nothing is honestly an empty answer — an id is whatever somebody
    was handed during an incident, and this route has no opinion about its shape. A kind
    is a closed vocabulary with a CHECK behind it, so `?resource_kind=tools` is not a
    question with no answers; it is a question the server does not have. Answering `[]`
    with a 200 would read as *"no tool denials"*, which is `limit`'s lie in a different
    costume — so it gets `limit`'s treatment.
    """
    assert client.get("/admin/denials?resource_kind=tools", headers=auth).status_code == 422
    assert client.get("/admin/denials?resource_kind=", headers=auth).status_code == 422

    # And every kind the column admits is accepted, including the one migration 040 added
    # for the door — derived from the constant rather than listed here, so a fourth kind
    # widens this assertion by itself.
    from carnet.storage import DENIAL_RESOURCE_KINDS

    for kind in sorted(DENIAL_RESOURCE_KINDS):
        response = client.get(f"/admin/denials?resource_kind={kind}", headers=auth)
        assert response.status_code == 200, kind
        assert response.json() == []


def test_a_stranger_gets_401_before_422_on_the_denial_log(client):
    """**Authentication is decided before the query string is validated**, so a caller
    with no bearer learns nothing about this route's shape — not even that it takes a
    `resource_kind`, or which words it accepts.

    A 422 here would be a small enumeration oracle: it distinguishes a route that exists
    and parses from one that does not, and it hands over the parameter's name and its
    whole vocabulary for free. 035a pinned this for `/admin/door-calls`; it is asserted
    here too because the ordering is a property of the dependency graph rather than of
    anything written in this route, and adding a parameter is exactly when somebody would
    reverse it without noticing.
    """
    for query in (
        "?limit=abc",
        "?limit=0",
        "?limit=99999",
        "?resource_kind=tools",       # the new one, and the reason this test is here
        "?resource_kind=",
        "?bogus=1",
    ):
        assert client.get(f"/admin/denials{query}").status_code == 401, query


def test_the_denial_log_limit_is_capped_by_the_signature(client, auth, admin):
    """Silent truncation is the one behaviour a log route must not have — it reads as
    "that is everything". `/admin-audit`'s rule, on the third log's route."""
    assert client.get("/admin/denials?limit=1", headers=auth).status_code == 200
    assert client.get("/admin/denials?limit=0", headers=auth).status_code == 422
    assert client.get("/admin/denials?limit=100000", headers=auth).status_code == 422


# --- group administration over HTTP, 9a's oldest debt ------------------------------


def test_a_non_admin_may_read_the_group_menu_and_nothing_else(client, auth):
    """The line decision 6 draws: **listing is the menu, membership is the directory.**
    An `editor` sharing with a group has to pick one; who is in every group is a map of
    the company."""
    storage.active().create_group(
        TEST_TENANT, "g-1", "oncall", created_by="system:cli", actor="system:cli"
    )

    listed = client.get("/groups", headers=auth)
    assert listed.status_code == 200
    assert [row["name"] for row in listed.json()] == ["oncall"]
    assert "members" not in listed.json()[0]

    assert client.get("/groups/g-1", headers=auth).status_code == 403
    assert client.post("/groups", json={"name": "mine"}, headers=auth).status_code == 403
    assert client.delete("/groups/g-1", headers=auth).status_code == 403
    assert client.put("/groups/g-1/members/user/u-1", headers=auth).status_code == 403
    assert client.delete("/groups/g-1/members/user/u-1", headers=auth).status_code == 403


def test_an_administrator_creates_fills_reads_and_deletes_a_group(client, auth, admin):
    """9a's debt, paid. The whole arc, over HTTP, as one administrator."""
    created = client.post(
        "/groups", json={"name": "oncall", "description": "who carries the pager"},
        headers=auth,
    )
    assert created.status_code == 201, created.text
    group_id = created.json()["group_id"]
    assert created.json()["members"] == []

    added = client.put(f"/groups/{group_id}/members/user/u-sam", headers=auth)
    assert added.status_code == 200
    assert added.json()["changed"] is True

    detail = client.get(f"/groups/{group_id}", headers=auth).json()
    assert [(m["kind"], m["id"]) for m in detail["members"]] == [("user", "u-sam")]
    assert detail["created_by"] == f"user:{admin}"

    assert client.delete(f"/groups/{group_id}", headers=auth).status_code == 204
    assert client.get(f"/groups/{group_id}", headers=auth).status_code == 400


def test_a_group_is_linked_to_a_directory_and_hand_edits_are_refused(client, auth, admin):
    """Step 033e over HTTP: the write 017 left out, and the seam that keeps the two
    sources of membership from fighting once it exists."""
    # The seam refuses only while the directory is speaking — a provider that names no
    # groups claim leaves its groups the administrator's, which is what stops a group
    # linked in the wrong order from being editable by nobody.
    _idp_with_groups_claim()
    group_id = client.post("/groups", json={"name": "eng"}, headers=auth).json()[
        "group_id"
    ]
    client.put(f"/groups/{group_id}/members/system/nightly", headers=auth)

    linked = client.patch(
        f"/groups/{group_id}", json={"external_id": "dir-eng"}, headers=auth
    )
    assert linked.status_code == 200, linked.text
    assert linked.json()["external_id"] == "dir-eng"
    assert [(m["kind"], m["id"]) for m in linked.json()["members"]] == [
        ("system", "nightly")
    ], "linking removes nobody, and a system member is never the directory's anyway"

    refused = client.put(f"/groups/{group_id}/members/user/u-sam", headers=auth)
    assert refused.status_code == 400
    assert "follows your directory" in refused.json()["detail"]

    # ...and a `system` member is still the administrator's to add.
    assert client.put(f"/groups/{group_id}/members/system/other", headers=auth).status_code == 200

    unlinked = client.patch(f"/groups/{group_id}", json={"external_id": None}, headers=auth)
    assert unlinked.json()["external_id"] is None
    assert client.put(f"/groups/{group_id}/members/user/u-sam", headers=auth).status_code == 200


def test_a_patch_that_names_no_field_does_not_unlink_a_group(client, auth, admin):
    """The shape `groups.link`'s blank-value refusal cannot see. With a default on the
    field, `PATCH {}` — a probe — and `PATCH {"externalId": …}` — a camel-cased typo —
    both answered **200 having unlinked the group**, which is reported success for the
    opposite of what was asked."""
    group_id = client.post(
        "/groups", json={"name": "eng", "external_id": "dir-eng"}, headers=auth
    ).json()["group_id"]

    assert client.patch(f"/groups/{group_id}", json={}, headers=auth).status_code == 422
    assert (
        client.patch(
            f"/groups/{group_id}", json={"externalId": "dir-ops"}, headers=auth
        ).status_code
        == 422
    )
    assert (
        client.patch(
            f"/groups/{group_id}", json={"external_id": "   "}, headers=auth
        ).status_code
        == 400
    )
    assert client.get(f"/groups/{group_id}", headers=auth).json()["external_id"] == "dir-eng"

    # Unlinking is spelled one way, and it still works.
    unlinked = client.patch(
        f"/groups/{group_id}", json={"external_id": None}, headers=auth
    )
    assert unlinked.status_code == 200
    assert unlinked.json()["external_id"] is None


def test_a_directory_id_is_normalised_and_bounded_at_every_door(client, auth, admin):
    """`POST /groups` is a door `groups.link` does not stand in, and it used to store
    whatever it was handed: a padded id makes a group the directory can never fill, and
    the seam then refuses every hand edit — a group editable by nobody."""
    made = client.post(
        "/groups", json={"name": "eng", "external_id": "  dir-eng\t"}, headers=auth
    )
    assert made.status_code == 201
    assert made.json()["external_id"] == "dir-eng"

    for bad in ("", "   ", "dir\neng", "d" * 300):
        refused = client.post(
            "/groups", json={"name": f"g-{len(bad)}", "external_id": bad}, headers=auth
        )
        assert refused.status_code == 400, bad


def _idp_with_groups_claim():
    """Re-register the test provider with a groups claim. Step 033e."""
    row = storage.active().list_tenant_idps(TEST_TENANT)[0]
    storage.active().save_tenant_idp(TEST_TENANT, {**row, "groups_claim": "groups"})


def test_a_directory_id_another_group_holds_is_refused_over_http(client, auth, admin):
    first = client.post(
        "/groups", json={"name": "eng", "external_id": "dir-eng"}, headers=auth
    ).json()["group_id"]
    second = client.post("/groups", json={"name": "ops"}, headers=auth).json()["group_id"]

    clash = client.patch(
        f"/groups/{second}", json={"external_id": "dir-eng"}, headers=auth
    )

    assert clash.status_code == 400
    assert "already has a group linked to directory" in clash.json()["detail"]
    assert client.get(f"/groups/{first}", headers=auth).json()["external_id"] == "dir-eng"


def test_the_share_sheet_says_a_group_follows_the_directory(client, auth, admin):
    """The obligation 9b inherited: with membership coming from a claim this list is
    everybody who has signed in since being placed in the group, not everybody in it."""
    group_id = client.post(
        "/groups", json={"name": "eng", "external_id": "dir-eng"}, headers=auth
    ).json()["group_id"]
    hand = client.post("/groups", json={"name": "by-hand"}, headers=auth).json()["group_id"]

    storage.active().save_agent(TEST_TENANT, {"name": "reporter"}, actor="system:cli")
    storage.active().grant_agent(
        TEST_TENANT, "reporter", "user", admin, role="owner", actor="system:cli"
    )
    for target in (group_id, hand):
        storage.active().grant_agent(
            TEST_TENANT, "reporter", "group", target, role="user", actor="system:cli"
        )

    sheet = client.get("/agents/reporter/access", headers=auth).json()["access"]
    marked = {row["id"]: row["directory"] for row in sheet if row["kind"] == "group"}

    assert marked == {group_id: True, hand: False}
    assert all(row["directory"] is False for row in sheet if row["kind"] != "group")


def test_the_menu_marks_which_groups_follow_the_directory(client, auth, admin):
    """Step 035h. The menu an editor picks from says which kind each option is.

    The boolean and **not** the id: an editor is entitled to know that sharing with this
    group reaches whoever the directory names, and a customer's Entra object id is not
    theirs to read. `AgentAccessEntry` draws the same line one route over.
    """
    linked = client.post(
        "/groups", json={"name": "eng", "external_id": "dir-eng"}, headers=auth
    ).json()["group_id"]
    hand = client.post("/groups", json={"name": "by-hand"}, headers=auth).json()[
        "group_id"
    ]

    menu = {row["group_id"]: row for row in client.get("/groups", headers=auth).json()}

    assert menu[linked]["directory"] is True
    assert menu[hand]["directory"] is False
    # The id stays on `GroupDetail`. A summary that carried it would have moved a
    # customer's directory identifier onto a route open to every employee.
    assert "external_id" not in menu[linked]
    assert "members" not in menu[linked]


def test_a_non_admin_is_told_which_groups_follow_the_directory(client, auth):
    """On the open route, which is the whole point of the field.

    `GET /groups` is deliberately outside `deps.ADMIN_SURFACE` because it is the sharing
    menu, so the reader this field exists for holds no role at all. A test that only ever
    asked as an administrator would not notice if that stopped being true.
    """
    storage.active().create_group(
        TEST_TENANT,
        "g-dir",
        "eng",
        external_id="dir-eng",
        created_by="system:cli",
        actor="system:cli",
    )
    storage.active().create_group(
        TEST_TENANT, "g-hand", "by-hand", created_by="system:cli", actor="system:cli"
    )

    menu = {row["group_id"]: row for row in client.get("/groups", headers=auth).json()}

    assert menu["g-dir"]["directory"] is True
    assert menu["g-hand"]["directory"] is False
    assert client.get("/groups/g-dir", headers=auth).status_code == 403


def test_the_directory_flag_reads_null_and_not_falsiness(client, auth):
    """`GROUP_FIELDS`' rule, at the one place a truthiness test would break it.

    NULL and `''` are different states, and `''` is the worse one: `check_external_id`
    calls a group linked to it one that *"removes every person at each sign-in"*, because
    it is `IS NOT NULL` to the reconciliation and no claim value can ever match it. So it
    is the state most worth marking, and precisely the one `bool(external_id)` would report
    as *managed here*.

    **Asserted against the projection rather than through a route, and that is the honest
    address**: `check_external_id` refuses a blank at every door this codebase has —
    `POST /groups`, `PATCH`, `--group-link` and `create_group` in both stores — so there is
    no request that can produce such a row today. The rule still has to be written where the
    reading happens, because the reason it is unreachable is a guard four callers deep and
    a future path that forgets it is exactly what `groups.link`'s own comment expects.
    """
    from carnet.api.routes_groups import _summary

    assert _summary({"group_id": "g", "name": "eng", "external_id": ""})["directory"] is True
    assert _summary({"group_id": "g", "name": "eng", "external_id": None})["directory"] is False

    # And the doors that exist do refuse it, which is why the case above is a unit.
    from carnet.storage.base import ValueRefused

    with pytest.raises(ValueRefused, match="cannot be blank"):
        storage.active().create_group(
            TEST_TENANT, "g-blank", "eng", external_id="", actor="system:cli"
        )


def test_the_group_menu_declares_exactly_its_four_public_fields(client, auth, admin):
    """**The leak direction of the seam `DEFERRED.md` records, and 035h is the reason it
    now has a test.**

    `routes_groups._summary` hands `external_id` and `created_by` to `GroupSummary`, and
    they are dropped only because `extra="ignore"` is pydantic's default — the same
    mechanism that silently dropped `acts_as_owner` for three steps, running the other
    way. `GET /groups` is open to **every authenticated employee**, so if that default
    ever moved, or somebody added `model_config = ConfigDict(extra="allow")` to keep a
    sibling model honest, a customer's Entra object id would be on a public listing with
    nothing failing.

    So the key set is asserted rather than the presence of one field: a test that only
    said `"external_id" not in row` would pass while `created_by` leaked, and would say
    nothing at all about the next column somebody adds to `_summary`.
    """
    client.post(
        "/groups", json={"name": "eng", "external_id": "dir-eng"}, headers=auth
    )
    client.post("/groups", json={"name": "by-hand"}, headers=auth)

    menu = client.get("/groups", headers=auth).json()

    assert len(menu) == 2
    for row in menu:
        assert set(row) == {"group_id", "name", "description", "directory"}, row
        assert isinstance(row["directory"], bool)

    # And the model itself refuses to carry one, so the guard holds for any other caller
    # of this shape rather than only for this route.
    from carnet.api.schemas import GroupSummary

    assert "external_id" not in GroupSummary(
        group_id="g", name="eng", external_id="dir-eng", created_by="user:u_1"
    ).model_dump()


def test_the_menu_is_readable_by_a_machine_and_a_personal_token(
    client, auth, admin, machine_auth
):
    """`GET /groups` is the one group route with no role, so the tokens are part of its
    surface — and 035h is what gives that surface a consumer.

    The pair is asserted together because the interesting part is the asymmetry: both
    read the menu, **neither** opens a group. A personal token's owner here is an
    administrator and it still gets a 403, which is 033d's cap doing exactly what it
    says — its access is its owner's, capped at `user`, and a platform role is not
    something it inherits.
    """
    from carnet.access import tokens

    group_id = client.post(
        "/groups", json={"name": "eng", "external_id": "dir-eng"}, headers=auth
    ).json()["group_id"]

    _, personal = tokens.mint(
        TEST_TENANT,
        "priya-cursor",
        logged_in_id(client, auth),
        actor="system:cli",
        acts_as_owner=True,
    )
    personal_auth = {"Authorization": f"Bearer {personal}"}

    for who, headers in (("machine", machine_auth), ("personal", personal_auth)):
        menu = client.get("/groups", headers=headers)
        assert menu.status_code == 200, who
        assert {row["group_id"]: row["directory"] for row in menu.json()} == {
            group_id: True
        }, who
        assert client.get(f"/groups/{group_id}", headers=headers).status_code == 403, who


def test_a_group_detail_agrees_with_its_own_external_id(client, auth, admin):
    """`GroupDetail` inherits the field, so the two shapes cannot disagree — asserted
    rather than assumed, because a projection that dropped or contradicted a field it
    already carries is the silent-drop class `schemas.py`'s register row is about."""
    group_id = client.post(
        "/groups", json={"name": "eng", "external_id": "dir-eng"}, headers=auth
    ).json()["group_id"]

    linked = client.get(f"/groups/{group_id}", headers=auth).json()
    assert linked["external_id"] == "dir-eng"
    assert linked["directory"] is True

    unlinked = client.patch(
        f"/groups/{group_id}", json={"external_id": None}, headers=auth
    ).json()
    assert unlinked["external_id"] is None
    assert unlinked["directory"] is False

    # And the menu agrees with the detail, which is what makes the badge and the sheet
    # answer the same question rather than two questions that usually match.
    menu = {row["group_id"]: row for row in client.get("/groups", headers=auth).json()}
    assert menu[group_id]["directory"] is False


def test_membership_writes_say_whether_they_changed_anything(client, auth, admin):
    """`GrantOutcome`'s complaint, one noun over: "added" and "was already there" are
    different facts, and an administrator who cannot tell them apart cannot tell a working
    command from a no-op."""
    group_id = client.post("/groups", json={"name": "oncall"}, headers=auth).json()[
        "group_id"
    ]

    assert client.put(f"/groups/{group_id}/members/user/u-sam", headers=auth).json()[
        "changed"
    ] is True
    assert client.put(f"/groups/{group_id}/members/user/u-sam", headers=auth).json()[
        "changed"
    ] is False
    assert client.delete(f"/groups/{group_id}/members/user/u-sam", headers=auth).json()[
        "changed"
    ] is True
    assert client.delete(f"/groups/{group_id}/members/user/u-sam", headers=auth).json()[
        "changed"
    ] is False


def test_a_group_may_not_be_a_member_of_a_group(client, auth, admin):
    """Refused by `check_principal_kind`, which has permitted exactly `user` and `system`
    since 009 — so nesting is refused by a rule that predates this route, and it arrives
    as a 400 rather than a 503 or a 500."""
    group_id = client.post("/groups", json={"name": "oncall"}, headers=auth).json()[
        "group_id"
    ]

    response = client.put(f"/groups/{group_id}/members/group/g-other", headers=auth)

    assert response.status_code == 400
    assert "group" in response.json()["detail"]


def test_a_group_route_naming_a_group_that_does_not_exist_is_a_400(client, auth, admin):
    """Not a 503 and not a 500 — which is what an unmapped `GroupRefused` would have been,
    and is exactly how `NoSuchGroupError` arrived in step 011."""
    response = client.get("/groups/g-nope", headers=auth)

    assert response.status_code == 400
    assert "g-nope" in response.json()["detail"]

    added = client.put("/groups/g-nope/members/user/u-1", headers=auth)
    assert added.status_code == 400


def test_a_duplicate_group_name_is_refused_with_a_sentence(client, auth, admin):
    client.post("/groups", json={"name": "oncall"}, headers=auth)

    response = client.post("/groups", json={"name": "oncall"}, headers=auth)

    assert response.status_code == 400
    assert "oncall" in response.json()["detail"]


def test_every_group_write_leaves_a_record_naming_the_person(client, auth, admin):
    """The route hands storage a real principal, which is 9a's lesson in a new place: a
    guard that lives only on the path nobody takes is a guard nobody has."""
    group_id = client.post("/groups", json={"name": "oncall"}, headers=auth).json()[
        "group_id"
    ]
    client.put(f"/groups/{group_id}/members/user/u-sam", headers=auth)
    client.delete(f"/groups/{group_id}", headers=auth)

    records = [
        row
        for row in storage.active().admin_audit_records(TEST_TENANT)
        if row["target_kind"] == "group"
    ]

    assert [row["action"] for row in records] == [
        "group.create",
        "group.member.add",
        "group.delete",
    ]
    assert {row["actor_id"] for row in records} == {admin}


# --- the administration surface: connector onboarding over HTTP (12c) ----------------
#
# The three features 12b's role was still blocking. Every route here is a thin caller of
# a seam `--allow-host`, `--add-connector`, `--discover`, `--vet` and `--set-oauth`
# already use, so what is worth asserting is not that the seams work — they have their
# own tests, several against real Postgres — but the four things that are new:
#
#   - the dependency, on ten routes where for most of them it is the ONLY guard
#   - the two moved guards arriving through the route rather than being restated in it
#   - the client secret going in and never coming back
#   - the refusals, which are the half a screen is built to render


@pytest.fixture
def fake_server(monkeypatch):
    """A scripted MCP server behind every route that dials one.

    `discovery._transport_for` is the seam — the same one `test_registration.py` injects
    at, one level up, because these routes do not take a `transport` argument and must
    not: a body field naming a transport would be a caller choosing what this dials.
    """
    from test_registration import FakeServer  # noqa: PLC0415

    server = FakeServer()
    monkeypatch.setattr(
        mcp.discovery, "_transport_for", lambda tenant, connector, credential: server
    )
    return server


@pytest.fixture
def admin_host(admin):
    """An administrator, and `TEST_HOST` already approved by `isolated_storage`."""
    from conftest import TEST_HOST  # noqa: PLC0415

    return TEST_HOST


@pytest.fixture
def registered_jira(client, auth, admin, admin_host):
    """A connector registered through the route, and nothing vetted on it.

    Through `POST /admin/connectors` rather than through `tools.register_connector`, so
    the fixture every other test builds on is itself evidence the route works.
    """
    response = client.post(
        "/admin/connectors",
        json={
            "connector_id": "jira",
            "url": f"https://{admin_host}/mcp",
            "credential_env": "JIRA_TOKEN",
            "description": "Jira, issues only",
        },
        headers=auth,
    )
    assert response.status_code == 201, response.json()
    return "jira"


# --- the guard, which for most of these routes is the only one -----------------------


ADMIN_CONNECTOR_ROUTES = [
    ("get", "/admin/hosts", None),
    ("post", "/admin/hosts", {"host": "mcp.acme.com"}),
    ("delete", "/admin/hosts/mcp.acme.com", None),
    ("get", "/admin/connectors", None),
    ("post", "/admin/connectors", {"connector_id": "x", "url": "https://x.example/mcp"}),
    # 068. The content is identical for every tenant and is in the public repository, so
    # this is not secrecy — it is a control on the registration screen, and a route
    # answering any signed-in caller invites a client to render an administrative
    # affordance to somebody who cannot use it. `ADMIN_SURFACE` asserts the dependency is
    # *declared*; this asserts it *refuses*, and either alone passes while the surface is
    # open.
    ("get", "/admin/recipes", None),
    ("get", "/admin/connectors/jira", None),
    ("post", "/admin/connectors/jira/discovery", None),
    ("put", "/admin/connectors/jira/tools/create_issue", {"effect": "read"}),
    (
        "put",
        "/admin/connectors/jira/oauth",
        {
            "authorize_endpoint": "https://a.example/authorize",
            "token_endpoint": "https://a.example/token",
            "client_id": "c",
            "client_secret": "s",
        },
    ),
    ("delete", "/admin/connectors/jira/oauth", None),
]


@pytest.mark.parametrize("method,path,body", ADMIN_CONNECTOR_ROUTES)
def test_a_non_administrator_is_refused_every_connector_route(
    client, auth, registered, method, path, body
):
    """**The important one in this file**, and it is stronger than 12b's equivalent.

    12b's harder pass found that on the group routes `admin_from_request` is behaviourally
    invisible: every one of them goes through `access/groups.py`, which does its own
    `require_admin`, so removing either guard alone changes nothing observable. That is
    defence in depth and it made the route-table walk the only thing that could see the
    dependency at all.

    These are the other case, and it is worse. `storage.allow_host`,
    `tools.register_connector`, `mcp.discovery.discover` and `oauth.configure` check **no
    role whatsoever** — they were written for a CLI whose caller is `system` and therefore
    always an administrator. For these ten routes the dependency is not a second lock. It
    is the only thing between any authenticated employee and registering a connector that
    dials wherever they say.

    So this drives all ten as an ordinary colleague and requires 403 from each, and the
    route-table walk requires the dependency be present. Two tests, because either alone
    can pass while the surface is open.
    """
    response = getattr(client, method)(path, headers=auth, **({"json": body} if body else {}))

    assert response.status_code == 403, (
        f"{method.upper()} {path} answered {response.status_code} to somebody who is not "
        "an administrator"
    )
    assert "administrator" in response.json()["detail"]


@pytest.mark.parametrize("method,path,body", ADMIN_CONNECTOR_ROUTES)
def test_an_unauthenticated_caller_on_a_connector_route_is_401(
    client, registered, method, path, body
):
    """401 before 403, which comes free from the `Depends` chain and has to. A 403 to a
    caller who has not proved a tenant tells them this route exists."""
    response = getattr(client, method)(path, **({"json": body} if body else {}))

    assert response.status_code == 401


# --- hosts ---------------------------------------------------------------------------


def test_approving_a_host_records_it_and_names_who(client, auth, admin):
    response = client.post(
        "/admin/hosts", json={"host": "mcp.acme.com", "note": "Jira"}, headers=auth
    )

    assert response.status_code == 200
    assert response.json() == {"host": "mcp.acme.com", "note": "Jira", "warning": ""}

    (row,) = [
        r for r in storage.active().allowed_hosts(TEST_TENANT) if r["host"] == "mcp.acme.com"
    ]
    assert row["allowed_by"] == f"user:{admin}"


def test_approving_a_host_that_can_never_be_dialled_warns_in_the_body(
    client, auth, admin
):
    """Finding 3's second guard, arriving where there is no stderr.

    The row is written — a **warning and not a refusal**, because it records that somebody
    approved a host and the refusal belongs at dial time where it is load-bearing. What
    must not happen is a plain 200 that reads as *yes*, about a control that is not in
    force. Same sentence the terminal prints, from `egress.approval_warning`.
    """
    response = client.post("/admin/hosts", json={"host": "localhost"}, headers=auth)

    assert response.status_code == 200
    assert response.json()["warning"] == mcp.egress.approval_warning("localhost")
    assert "will NOT be dialled" in response.json()["warning"]
    assert "localhost" in {r["host"] for r in storage.active().allowed_hosts(TEST_TENANT)}


def test_a_pasted_url_where_a_host_belongs_is_a_400_that_says_what_to_strip(
    client, auth, admin
):
    """Decision 2, and the whole reason approval takes a body.

    12b's edge pass established that a `/` in a path segment is a routing 404 even
    percent-encoded, because uvicorn decodes before Starlette routes. Pasting a URL is
    exactly what people do when adding a host, so a path-segment route would answer a bare
    404 where `normalize_host` has a sentence naming what is wrong.
    """
    response = client.post(
        "/admin/hosts", json={"host": "https://mcp.acme.com/mcp"}, headers=auth
    )

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "scheme" in detail
    assert "just the hostname" in detail


def test_the_allowlist_reads_back_with_its_warnings(client, auth, admin):
    client.post("/admin/hosts", json={"host": "127.0.0.1"}, headers=auth)

    rows = {row["host"]: row for row in client.get("/admin/hosts", headers=auth).json()}

    assert rows["127.0.0.1"]["warning"]
    assert rows[admin_test_host()]["warning"] == ""


def admin_test_host():
    from conftest import TEST_HOST  # noqa: PLC0415

    return TEST_HOST


def test_revoking_a_host_says_which_connectors_it_stranded(
    client, auth, admin, registered_jira, admin_host
):
    """`revoke_host`'s behaviour, said in a body because a 204 has nowhere to say it.

    The connectors stay, keep their vetting, and stop connecting. The alternative reading
    — that revoking a host removed them — is the one somebody assumes, and assuming it
    means believing a customer's integration is gone when the row is waiting for the host
    to come back.
    """
    response = client.delete(f"/admin/hosts/{admin_host}", headers=auth)

    assert response.status_code == 200
    assert response.json() == {
        "host": admin_host,
        "removed": True,
        "stranded": ["jira"],
    }
    assert storage.active().get_connector(TEST_TENANT, "jira") is not None


def test_revoking_a_host_nobody_approved_is_a_no_op_that_says_so(client, auth, admin):
    """Idempotent, and `removed: false` rather than a 404 — an administrator who cannot
    tell a no-op from a change cannot tell a working control from a broken one."""
    response = client.delete("/admin/hosts/never.example.com", headers=auth)

    assert response.status_code == 200
    assert response.json()["removed"] is False


# --- registration --------------------------------------------------------------------


def test_registering_a_connector_vets_nothing(client, auth, registered_jira):
    """Decision 4 of plan 012, through a route: the row exists and reaches nothing.

    This is the state a wizard has to be able to render, because it is the one somebody is
    in for as long as it takes them to read a vendor's documentation.
    """
    body = client.get("/admin/connectors/jira", headers=auth).json()

    assert body["vetted"] == 0
    assert body["writes"] == 0
    assert body["tools"] == []
    assert body["transport"] == "http"
    assert body["host_allowed"] is True
    assert body["oauth"] is None
    assert tools.catalogue(TEST_TENANT) and not any(
        group["id"] == "jira" and group["tools"] for group in tools.catalogue(TEST_TENANT)
    )


def test_asserted_identity_toggles_through_its_own_route(client, auth, registered_jira):
    """033c. A security control being switched gets its own verb, its own URL and its
    own administrative record — never a field buried in a broader edit."""
    assert (
        client.get("/admin/connectors/jira", headers=auth).json()[
            "allow_asserted_identity"
        ]
        is False
    )

    flipped = client.put(
        "/admin/connectors/jira/asserted-identity",
        json={"allowed": True},
        headers=auth,
    )

    assert flipped.status_code == 200
    assert flipped.json()["allow_asserted_identity"] is True
    (record,) = storage.active().admin_audit_records(
        TEST_TENANT, action="connector.asserted_identity"
    )
    assert record["detail"]["allow_asserted_identity"] is True


def test_asserted_identity_on_an_unregistered_connector_is_a_400(client, auth, admin):
    response = client.put(
        "/admin/connectors/ghost/asserted-identity",
        json={"allowed": True},
        headers=auth,
    )

    assert response.status_code == 400
    assert "Register the connector first" in response.json()["detail"]


def test_registering_a_connector_id_that_exists_is_a_409(
    client, auth, registered_jira, admin_host
):
    """`AgentNameTaken`'s reasoning, and the alternative is worse here than there.

    The alternative to refusing is an upsert, and `save_connector`'s upsert replaces a
    vetted allowlist wholesale. An administrator who has approved nine tools and
    re-registers by mistake must not lose nine to a request whose only visible effect is
    *the row exists*.
    """
    response = client.post(
        "/admin/connectors",
        json={"connector_id": "jira", "url": f"https://{admin_host}/mcp"},
        headers=auth,
    )

    assert response.status_code == 409


def test_registering_a_connector_on_an_unapproved_host_is_a_400(client, auth, admin):
    """Checked at registration as well as at dial time, which is 012's redundancy: a
    refusal somebody gets on this screen is one they can act on, where the same refusal
    three days later at the first run is a mystery."""
    response = client.post(
        "/admin/connectors",
        json={"connector_id": "nope", "url": "https://elsewhere.example.com/mcp"},
        headers=auth,
    )

    assert response.status_code == 400
    assert "has not approved the host" in response.json()["detail"]


def test_registering_without_a_url_explains_the_transport_rule(client, auth, admin):
    """`tools.STDIO_REFUSED` in full, rather than a field name.

    A registered connector speaks HTTP because HTTP is the only transport that can carry a
    per-user credential — a stdio server takes its credential from the environment at
    launch and holds it for the process's life, so every user of every agent would share
    one service account. That is three paragraphs of explanation and it is all returned,
    because the remedy is *change your infrastructure* and a person needs to know why.
    """
    response = client.post(
        "/admin/connectors", json={"connector_id": "local"}, headers=auth
    )

    assert response.status_code == 400
    assert "must speak HTTP" in response.json()["detail"]


# --- discovery -----------------------------------------------------------------------


def test_discovery_returns_each_tools_arguments_and_requiredness(
    client, auth, registered_jira, fake_server
):
    """**The one thing a person cannot guess**, and the reason `--discover` exists at all.

    Everything else on a vetting screen is a judgment somebody makes. What they cannot
    guess is what *this* server calls the argument carrying the identifier, and whether it
    is optional — an optional argument that widens reach when absent is the case
    `validation.py` names, and it is invisible without the second field.
    """
    body = client.post("/admin/connectors/jira/discovery", headers=auth).json()

    assert body["server"] == "jira-mcp-server v2.3.0"

    by_name = {tool["name"]: tool for tool in body["tools"]}
    assert set(by_name) == {"create_issue", "search_issues", "delete_project"}

    create = by_name["create_issue"]
    assert create["vetted"] is False
    assert create["local_name"] == "jira_create_issue"
    assert create["arguments"] == [
        {"name": "description", "type": "string", "required": False},
        {"name": "projectKey", "type": "string", "required": True},
        {"name": "summary", "type": "string", "required": True},
    ]


def test_discovery_marks_what_is_already_vetted(
    client, auth, registered_jira, fake_server
):
    client.put(
        "/admin/connectors/jira/tools/search_issues",
        json={"effect": "read"},
        headers=auth,
    )

    body = client.post("/admin/connectors/jira/discovery", headers=auth).json()

    marked = {tool["name"] for tool in body["tools"] if tool["vetted"]}
    assert marked == {"search_issues"}


def test_discovery_reports_drift_rather_than_adopting_it(
    client, auth, registered_jira, fake_server
):
    """*You do not vet a server, you vet the tools you want.* A newly advertised tool is
    a `report` finding and never an addition — a discovery that adopted them would let a
    server grant itself capabilities by shipping a release, which is the whole property
    the allowlist exists to deny."""
    client.put(
        "/admin/connectors/jira/tools/search_issues",
        json={"effect": "read"},
        headers=auth,
    )
    fake_server.tools = [tool for tool in fake_server.tools if tool["name"] != "search_issues"]

    body = client.post("/admin/connectors/jira/discovery", headers=auth).json()

    by_severity = {}
    for finding in body["findings"]:
        by_severity.setdefault(finding["severity"], []).append(finding["message"])

    # A vetted tool that is **gone** is a refusal: nothing else may be approved on this
    # connector until somebody looks at it.
    assert any("search_issues" in message for message in by_severity["refuse"])
    # Newly advertised tools are a **report**, always, and never an addition — a discovery
    # that adopted them would let a server grant itself capabilities by shipping a
    # release. Both severities come back from one call, which is precisely why the screen
    # has to render the difference rather than listing findings in a row.
    assert by_severity["report"]


def test_a_server_that_does_not_answer_is_a_502(
    client, auth, registered_jira, monkeypatch
):
    """**Decision 3, and the only 502 in this API.**

    The customer's own server did not answer, which is what a gateway status means. None
    of the alternatives are honest: a 503 claims *our* storage is down and sends an
    administrator to check our status page, a 400 blames a request that was correct, and a
    500 — which is what an unmapped exception produces — says we have a bug.
    """
    from carnet.tools.mcp.transport import TransportError  # noqa: PLC0415

    def refuse(*_args, **_kwargs):
        raise TransportError("could not reach https://api.example.com/mcp: connection refused")

    monkeypatch.setattr(mcp.discovery, "_transport_for", refuse)

    response = client.post("/admin/connectors/jira/discovery", headers=auth)

    assert response.status_code == 502
    assert "connection refused" in response.json()["detail"]


def test_discovery_on_a_connector_that_is_not_registered_is_a_400(client, auth, admin):
    """400 rather than 404, and the same sentence `--vet` gives. The caller has proved
    they administer this tenant, so which connectors exist is not a secret from them."""
    response = client.post("/admin/connectors/ghost/discovery", headers=auth)

    assert response.status_code == 400
    assert "--add-connector" in response.json()["detail"]


# --- vetting -------------------------------------------------------------------------


# The scope `create_issue` needs to be vettable at all. A write with nothing to scope it
# to is refused by `tools.validate` — *a write to something policy cannot name is
# unscopeable* — so every test below that vets this tool as a write has to say what it
# touches, exactly as a person filling in the form would.
PROJECT_SCOPE = {"type": "jira.project", "args": ["projectKey"]}


def test_vetting_one_tool_puts_it_in_the_catalogue(
    client, auth, registered_jira, fake_server, admin
):
    """The arc this whole step exists for, ending where an agent creator can see it."""
    response = client.put(
        "/admin/connectors/jira/tools/create_issue",
        json={
            "effect": "write",
            "resources": [{"type": "jira.project", "args": ["projectKey"]}],
            "note": "Scope this to the projects a team owns.",
        },
        headers=auth,
    )

    assert response.status_code == 200
    assert response.json() == {
        "local_name": "jira_create_issue",
        "remote_name": "create_issue",
        "effect": "write",
        # Unstated in the request, so the default: the connector's shared credential,
        # which is what a missing key means everywhere else — see docs/UPGRADING.md.
        "identity": "service",
        "resources": ["jira.project"],
        "server": "jira-mcp-server v2.3.0",
        "actor": f"user:{admin}",
    }

    catalogue = {
        tool["name"]: tool
        for group in client.get("/tools", headers=auth).json()
        for tool in group["tools"]
    }
    assert catalogue["jira_create_issue"]["effect"] == "write"
    assert catalogue["jira_create_issue"]["identity"] == "service"
    assert catalogue["jira_create_issue"]["vetted_by"] == f"user:{admin}"


def test_a_composed_resource_is_structured_rather_than_a_string(
    client, auth, registered_jira, fake_server
):
    """`cli._parse_resource` owns `TYPE={a}/{b}:a,b` and its docstring says why it stays
    there: *"the moment `Resource` learns one, an HTTP route ends up accepting the same
    string."* So this route takes the parts, and never the spelling."""
    response = client.put(
        "/admin/connectors/jira/tools/create_issue",
        json={
            "effect": "write",
            "resources": [
                {
                    "type": "jira.thing",
                    "args": ["projectKey", "summary"],
                    "template": "{projectKey}/{summary}",
                }
            ],
        },
        headers=auth,
    )

    assert response.status_code == 200
    assert response.json()["resources"] == ["jira.thing"]


def test_a_family_is_structured_on_the_route_too(
    client, auth, registered_jira, fake_server
):
    """Step 086. Families reach the route as a list on the resource spec, never as a CLI
    spelling — `ResourceSpec`'s own rule, and the CLI's `--resource-family` is a terminal
    convenience that stops at `cli.py`."""
    response = client.put(
        "/admin/connectors/jira/tools/create_issue",
        json={
            "effect": "write",
            "resources": [
                {"type": "jira.project", "args": ["projectKey"], "families": ["acme"]}
            ],
        },
        headers=auth,
    )

    assert response.status_code == 200
    (vetted,) = [
        v for v in mcp.get_connector(TEST_TENANT, "jira").vetted if v.remote_name == "create_issue"
    ]
    (ref,) = vetted.resources
    assert ref.families == ("acme",)


def test_a_family_a_scope_line_could_never_name_is_a_400(
    client, auth, registered_jira, fake_server
):
    """The refusals in `tools/validation.py` reach a form as a sentence rather than a
    500, which is the wrong-refusal-family this repository has now found seven times."""
    response = client.put(
        "/admin/connectors/jira/tools/create_issue",
        json={
            "effect": "write",
            "resources": [
                {"type": "jira.project", "args": ["projectKey"], "families": ["a/b"]}
            ],
        },
        headers=auth,
    )

    assert response.status_code == 400
    assert "could never be named" in response.json()["detail"]


def test_vetting_a_tool_the_server_does_not_advertise_names_what_it_does(
    client, auth, registered_jira, fake_server
):
    """`vet_tool` check 2, already written — the screen inherits it rather than
    reimplementing it, which is finding 2 of the plan as a property."""
    response = client.put(
        "/admin/connectors/jira/tools/invent_issue",
        json={"effect": "read"},
        headers=auth,
    )

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "does not advertise" in detail
    assert "create_issue" in detail


def test_scoping_to_an_argument_that_does_not_exist_is_refused_at_vetting_time(
    client, auth, registered_jira, fake_server
):
    """Check 3, and the difference between a typo and an outage. The descriptor is
    validated against the schema the server just sent, so the refusal arrives at the
    moment somebody typed the argument name rather than at the first run."""
    response = client.put(
        "/admin/connectors/jira/tools/create_issue",
        json={
            "effect": "write",
            "resources": [{"type": "jira.project", "args": ["project"]}],
        },
        headers=auth,
    )

    assert response.status_code == 400
    assert "project" in response.json()["detail"]


def test_a_write_with_nothing_to_scope_it_to_is_a_400_and_not_a_500(
    client, auth, registered_jira, fake_server
):
    """**A defect found by driving this route, and the fifth of its family.**

    `tools.validate` raises a bare `RuntimeError` for the three commonest mistakes on a
    vetting form — a write declaring no resources, a resource naming an argument the
    schema does not have, a local name that shadows a hand-written tool. The CLI has
    always caught `RuntimeError` at the call site, which worked because a terminal has one
    caller; a route has no such catch-all, so each of these answered **500 Internal Server
    Error** to an administrator whose remedy was to change one field.

    Fixed one level below the entry point rather than in the route, so the CLI and the
    form refuse identically and the *next* caller inherits it: `tools.vet_tool` re-raises
    them as `RegistrationRefused`, which is a `RuntimeError` and therefore changes nothing
    about `--vet`.

    The sentence is `validation.py`'s own, and it is worth reading — it says what to do
    instead, which is the whole difference between this and a 500.
    """
    response = client.put(
        "/admin/connectors/jira/tools/create_issue",
        json={"effect": "write"},
        headers=auth,
    )

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "unscopeable" in detail
    assert "mark it read" in detail


def test_a_local_name_that_shadows_a_built_in_is_a_400(
    client, auth, registered_jira, fake_server
):
    """The same family, and the one with a real consequence: a grant naming
    `post_message` has to mean exactly one thing, in the config and in the audit log."""
    response = client.put(
        "/admin/connectors/jira/tools/search_issues",
        json={"effect": "read", "local_name": "post_message"},
        headers=auth,
    )

    assert response.status_code == 400
    assert "post_message" in response.json()["detail"]


def test_vetting_is_refused_entirely_on_a_connector_that_has_drifted(
    client, auth, registered_jira, fake_server
):
    """Check 5, the one that is easy to leave out and expensive to omit: approving a
    tenth tool on a manifest that no longer binds, with nobody finding out until an
    unrelated agent's next run."""
    client.put(
        "/admin/connectors/jira/tools/search_issues",
        json={"effect": "read"},
        headers=auth,
    )
    fake_server.tools = [t for t in fake_server.tools if t["name"] != "search_issues"]

    response = client.put(
        "/admin/connectors/jira/tools/create_issue",
        json={"effect": "write", "resources": [PROJECT_SCOPE]},
        headers=auth,
    )

    assert response.status_code == 400
    assert "nothing new was approved" in response.json()["detail"]


def test_re_vetting_replaces_that_row_and_leaves_the_others(
    client, auth, registered_jira, fake_server
):
    """Append semantics, which is `--vet`'s decision and matters more through a form: a
    form is where somebody works through a whole server's tool list in one sitting, and a
    failed tenth must not cost nine."""
    client.put(
        "/admin/connectors/jira/tools/search_issues",
        json={"effect": "read"},
        headers=auth,
    )
    client.put(
        "/admin/connectors/jira/tools/create_issue",
        json={"effect": "write", "resources": [PROJECT_SCOPE]},
        headers=auth,
    )
    client.put(
        "/admin/connectors/jira/tools/create_issue",
        json={"effect": "write", "resources": [PROJECT_SCOPE], "note": "second look"},
        headers=auth,
    )

    body = client.get("/admin/connectors/jira", headers=auth).json()

    assert body["vetted"] == 2
    assert body["writes"] == 1
    notes = {tool["remote_name"]: tool["note"] for tool in body["tools"]}
    assert notes == {"search_issues": "", "create_issue": "second look"}


def test_a_vetted_tool_carries_who_approved_it_and_against_what(
    client, auth, registered_jira, fake_server, admin
):
    """Migration 023: the server's own name and version at the moment of approval,
    recorded rather than trusted."""
    client.put(
        "/admin/connectors/jira/tools/search_issues",
        json={"effect": "read"},
        headers=auth,
    )

    (tool,) = client.get("/admin/connectors/jira", headers=auth).json()["tools"]

    assert tool["vetted_by"] == f"user:{admin}"
    assert (tool["server_name"], tool["server_version"]) == ("jira-mcp-server", "2.3.0")


def test_a_response_ceiling_the_column_or_the_broker_would_regret_is_a_422(
    client, auth, registered_jira, fake_server
):
    """035g, and the reason the field grew three constraints the moment a form grew a box.

    `broker._bound_response` uses this value as the cap outright, so a stored `0` refuses
    **every** response the tool will ever return — with a sentence about a size limit and
    nothing anywhere saying somebody typed a zero into a form. The agent is told to narrow
    a request that narrowing cannot fix.

    Refused by the schema rather than by a branch, on `OAuthRequest.client_secret`'s
    reasoning. `--max-response-bytes 0` does **not** come through this model and is still
    accepted; that is a register row, not an oversight.

    **Two of these were found by 035g's edge pass rather than by writing the bound**, and
    both are the same defect wearing a different type: a JSON `true` became `1` under
    pydantic's lax mode and stored a one-byte ceiling, and one past a BIGINT became a
    `StorageError` answered *503 — try again later* about a value no amount of later will
    accept. See the field's comment in `schemas.py`.
    """
    for refused in (
        0,
        -1,
        # **A boolean, and the edge pass is what found this one.** Pydantic's lax mode
        # reads `True` as `1`, which `gt=0` is perfectly happy with — so a JSON `true`
        # stored a one-byte ceiling, the same tool-killing row a zero would have been,
        # through the one door the bound left open. `False` was already refused, by
        # `gt=0`, which is how confusing the pair was. Two other places in this codebase
        # refuse a bool where an int goes for the same reason.
        True,
        False,
        # A string is not a byte count, and lax mode would have coerced it.
        "4096",
        1.5,
        # **One past the column.** `vetted_tools.max_response_bytes` is a BIGINT, and
        # without `le` this reached psycopg as a numeric-out-of-range, became a
        # `StorageError`, and was answered **503 — try again later** about a value no
        # amount of later will accept.
        2**63,
    ):
        response = client.put(
            "/admin/connectors/jira/tools/search_issues",
            json={"effect": "read", "max_response_bytes": refused},
            headers=auth,
        )

        assert response.status_code == 422
        assert any(
            "max_response_bytes" in part["loc"] for part in response.json()["detail"]
        )

    # And the top of the column itself is accepted, so the bound is the column's and not
    # a number somebody liked.
    assert (
        client.put(
            "/admin/connectors/jira/tools/search_issues",
            json={"effect": "read", "max_response_bytes": 2**63 - 1},
            headers=auth,
        ).status_code
        == 200
    )
    client.put(
        "/admin/connectors/jira/tools/search_issues",
        json={"effect": "read"},
        headers=auth,
    )

    assert client.get("/admin/connectors/jira", headers=auth).json()["tools"][0][
        "max_response_bytes"
    ] is None


def test_a_null_ceiling_is_the_right_answer_and_a_number_is_stored(
    client, auth, registered_jira, fake_server
):
    """**Null is not an omission being tolerated** — it means *use this deployment's
    `MAX_RESPONSE_BYTES`*, which is right for nearly every tool.

    The inverse of `DEFERRED.md`'s `max_tokens: null` row, where a stored null is the
    hazard and a number is safe. Same shape, opposite polarity, which is why the form says
    *leave it blank* rather than treating blank as a thing to be corrected.
    """
    client.put(
        "/admin/connectors/jira/tools/search_issues",
        json={"effect": "read", "max_response_bytes": None},
        headers=auth,
    )
    client.put(
        "/admin/connectors/jira/tools/create_issue",
        json={
            "effect": "write",
            "resources": [{"type": "jira.project", "args": ["projectKey"]}],
            "max_response_bytes": 200_000,
            "note": "Finance owns this project.",
        },
        headers=auth,
    )

    tools_by_name = {
        tool["remote_name"]: tool
        for tool in client.get("/admin/connectors/jira", headers=auth).json()["tools"]
    }

    assert tools_by_name["search_issues"]["max_response_bytes"] is None
    assert tools_by_name["create_issue"]["max_response_bytes"] == 200_000
    # The sentence a person wrote at approval time, on the wire here as well as on
    # `ToolSummary`. The catalogue has rendered it to a grantee since 12c; this is the
    # projection the *approvals* screen reads, which is where 035g put it.
    assert tools_by_name["create_issue"]["note"] == "Finance owns this project."


# --- the consent flow, and the secret ------------------------------------------------


OAUTH_BODY = {
    "authorize_endpoint": "https://api.example.com/authorize",
    "token_endpoint": "https://api.example.com/token",
    "revoke_endpoint": "https://api.example.com/revoke",
    "client_id": "client-abc",
    "client_secret": "MARKER-CLIENT-SECRET-e3f1",
    "scopes": ["read:jira-work", "offline_access"],
}


def test_configuring_a_consent_flow_answers_the_redirect_uri(
    client, auth, registered_jira
):
    """The one real onboarding ask in this flow, returned rather than documented: the
    person who must register it at the provider is looking at this response."""
    response = client.put(
        "/admin/connectors/jira/oauth", json=OAUTH_BODY, headers=auth
    )

    assert response.status_code == 200
    body = response.json()
    assert body["redirect_uri"].endswith("/connect/callback")
    assert body["warnings"] == []
    assert body["app"]["client_id"] == "client-abc"
    assert body["app"]["scopes"] == ["read:jira-work", "offline_access"]


def test_the_client_secret_never_comes_back(client, auth, registered_jira):
    """**Verification 3**, asserted against the marker rather than against a field name.

    `_read_secret`'s rule is *never argv*; the HTTP equivalent is *never a query string*,
    and the containment on the way out is `OAUTH_APP_PUBLIC_FIELDS` — a projection
    deliberately ordered so `client_secret` and `key_id` are the two columns after it. A
    reader asking for the public list is structurally unable to acquire the sealed value.

    Searched for as a **substring of the whole response**, in every response that touches
    an OAuth row, because a field name assertion would pass against a secret that leaked
    under a different key. The mutation check is adding `client_secret` to `OAuthApp` and
    watching this fail.
    """
    secret = OAUTH_BODY["client_secret"]

    configured = client.put("/admin/connectors/jira/oauth", json=OAUTH_BODY, headers=auth)
    detail = client.get("/admin/connectors/jira", headers=auth)
    listing = client.get("/admin/connectors", headers=auth)
    connections = client.get("/connections", headers=auth)

    for response in (configured, detail, listing, connections):
        assert secret not in response.text, f"the secret is in {response.url}"

    # And there is no masked echo either. `••••••` implies the value is retrievable and
    # nothing here can retrieve it; the screen renders the word "stored".
    assert "•" not in configured.text
    assert set(configured.json()["app"]) == set(storage.OAUTH_APP_PUBLIC_FIELDS)


def test_no_secret_reaches_the_administrative_log_through_the_route(
    client, auth, registered_jira
):
    client.put("/admin/connectors/jira/oauth", json=OAUTH_BODY, headers=auth)

    records = storage.active().admin_audit_records(TEST_TENANT)

    assert OAUTH_BODY["client_secret"] not in json.dumps(records, default=str)
    assert any(row["action"] == "connector.oauth.configure" for row in records)


def test_a_consent_flow_with_no_offline_scope_warns(client, auth, registered_jira):
    """A warning rather than a refusal, on `--allow-host localhost`'s precedent: every
    provider spells this differently and refusing on a guess about a vendor's vocabulary
    would block a correct setup."""
    body = {**OAUTH_BODY, "scopes": ["read:jira-work"]}

    warnings = client.put(
        "/admin/connectors/jira/oauth", json=body, headers=auth
    ).json()["warnings"]

    assert any("offline access" in warning for warning in warnings)


def test_a_consent_flow_with_no_revocation_endpoint_warns(client, auth, registered_jira):
    body = {**OAUTH_BODY, "revoke_endpoint": ""}

    warnings = client.put(
        "/admin/connectors/jira/oauth", json=body, headers=auth
    ).json()["warnings"]

    assert any("live at the provider" in warning for warning in warnings)


def test_an_empty_client_secret_is_a_422_naming_the_field(client, auth, registered_jira):
    """Refused by the schema rather than by a branch. A blank secret stored silently is a
    consent flow that works right up until the first token exchange, at which point it
    fails at a third party for a reason nothing here recorded."""
    response = client.put(
        "/admin/connectors/jira/oauth",
        json={**OAUTH_BODY, "client_secret": ""},
        headers=auth,
    )

    assert response.status_code == 422


def test_authorize_params_round_trip_onto_the_public_projection(
    client, auth, registered_jira
):
    """035g. Migration 025's field, over HTTP for the first time.

    Atlassian mandates `audience` and `prompt`, so a connector needing them was
    browser-unconfigurable — and, separately, a connector a CLI had configured with them
    showed an administrator nothing about it, because the detail page rendered seven pairs
    and this was not one.
    """
    response = client.put(
        "/admin/connectors/jira/oauth",
        json={
            **OAUTH_BODY,
            "authorize_params": {"audience": "api.atlassian.com", "prompt": "consent"},
        },
        headers=auth,
    )

    assert response.status_code == 200
    assert response.json()["app"]["authorize_params"] == {
        "audience": "api.atlassian.com",
        "prompt": "consent",
    }
    stored = client.get("/admin/connectors/jira", headers=auth).json()["oauth"]
    assert stored["authorize_params"] == {
        "audience": "api.atlassian.com",
        "prompt": "consent",
    }


def test_no_authorize_params_is_an_empty_mapping_rather_than_a_missing_key(
    client, auth, registered_jira
):
    """Required-but-empty, so a client never has to tell absent from unset. The screen
    renders it as *nothing extra*, which is a complete answer and a different fact from a
    connector with no consent flow at all."""
    response = client.put("/admin/connectors/jira/oauth", json=OAUTH_BODY, headers=auth)

    assert response.json()["app"]["authorize_params"] == {}


def test_a_reserved_authorize_param_is_a_400_with_its_own_sentence(
    client, auth, registered_jira
):
    """**The refusals are the security design, and they have to reach a person verbatim.**

    `normalize_authorize_params` writes a different sentence per name and two of the seven
    are paragraphs rather than bookkeeping — `state` is the only thing binding a callback
    to the person who started it, and `redirect_uri` decides where their authorization code
    is delivered. Asserted as **400s** and not 422s, because a 422 in this API is a list of
    field errors rather than a sentence, and the SPA collapses every one of them to *"the
    request was not in a shape the server accepts"* — a generic line where the platform has
    a paragraph explaining itself.
    """
    forgeable = client.put(
        "/admin/connectors/jira/oauth",
        json={**OAUTH_BODY, "authorize_params": {"state": "guessable"}},
        headers=auth,
    )

    assert forgeable.status_code == 400
    assert "forgeable" in forgeable.json()["detail"]

    redirected = client.put(
        "/admin/connectors/jira/oauth",
        json={**OAUTH_BODY, "authorize_params": {"redirect_uri": "https://evil"}},
        headers=auth,
    )

    assert redirected.status_code == 400
    assert "stolen grant" in redirected.json()["detail"]

    # The other five say what they are and list the set, which is a different sentence for
    # a different reason: not a security design, but a request that would differ from what
    # this platform believes it sent.
    scoped = client.put(
        "/admin/connectors/jira/oauth",
        json={**OAUTH_BODY, "authorize_params": {"scope": "everything"}},
        headers=auth,
    )

    assert scoped.status_code == 400
    assert "believes it sent" in scoped.json()["detail"]

    # And none of the three configured anything.
    assert client.get("/admin/connectors/jira", headers=auth).json()["oauth"] is None


def test_a_value_postgres_cannot_hold_is_a_400_rather_than_a_503(
    client, auth, registered_jira
):
    """035g's third pass. `authorize_params` is a JSONB column, and a NUL byte or a lone
    surrogate reaches it as *"unsupported Unicode escape sequence"* — a `StorageError`,
    and therefore a **503 about a request that will never work**.

    That is the exact sentence `check_config_is_storable` exists for, and it had never
    been applied to this column. Same rule, same helper, one call in the normalizer both
    stores share. A name gets it separately, because the helper walks a mapping's values
    and a JSONB *key* cannot hold a NUL either.
    """
    # A **lone surrogate** is not among these, and the reason this comment first gave —
    # *it cannot be sent over HTTP at all* — was wrong: `\ud800` is six ASCII bytes and
    # a legal JSON escape, and `json.loads` produces the surrogate from it (step 087,
    # `test_a_lone_surrogate_in_a_json_body_is_reachable_and_refused`). It is not
    # driven here because this client's `json=` refuses to encode one; the storage
    # half is asserted in the contract suite as before.
    for params, why in (
        ({"audience": "a\x00b"}, "a NUL in a value"),
        ({"a\x00b": "x"}, "a NUL in a name"),
    ):
        response = client.put(
            "/admin/connectors/jira/oauth",
            json={**OAUTH_BODY, "authorize_params": params},
            headers=auth,
        )

        assert response.status_code == 400, why
        assert "NUL" in response.json()["detail"]

    assert client.get("/admin/connectors/jira", headers=auth).json()["oauth"] is None


def test_two_parameter_names_that_differ_only_in_spacing_are_refused(
    client, auth, registered_jira
):
    """Names are stripped before they are stored, so these are one parameter — and the
    second used to win silently, throwing away a value somebody typed.

    Reachable the moment a form has a row per parameter, which is what 035g built.
    """
    response = client.put(
        "/admin/connectors/jira/oauth",
        json={**OAUTH_BODY, "authorize_params": {"audience": "first", "audience ": "second"}},
        headers=auth,
    )

    assert response.status_code == 400
    assert "given twice" in response.json()["detail"]
    assert client.get("/admin/connectors/jira", headers=auth).json()["oauth"] is None


def test_the_authorize_endpoint_may_not_carry_a_reserved_parameter_either(
    client, auth, registered_jira
):
    """**The second door into `RESERVED_AUTHORIZE_PARAMS`**, found by 035g's third pass
    driving a real consent start and counting what was on the link.

    `oauth.begin` appends its own parameters after the endpoint's own query string, so
    `https://auth/authorize?state=fixed` produced a sign-in link carrying `state` **twice**
    — and RFC 6749 does not say which one a provider reads. One that reads the first gets
    a `state` a stored row chose, which is the forgeable consent flow the reserved-name
    refusal exists to prevent, arriving through a field nothing checked.

    Non-reserved names stay legal: a query string on this endpoint predates the column and
    is why `?audience=x` works at all.
    """
    for name in ("state", "redirect_uri", "client_id", "scope"):
        refused = client.put(
            "/admin/connectors/jira/oauth",
            json={
                **OAUTH_BODY,
                "authorize_endpoint": f"https://api.example.com/authorize?{name}=fixed",
            },
            headers=auth,
        )

        assert refused.status_code == 400, name
        assert name in refused.json()["detail"]
        assert "twice" in refused.json()["detail"]

    allowed = client.put(
        "/admin/connectors/jira/oauth",
        json={
            **OAUTH_BODY,
            "authorize_endpoint": "https://api.example.com/authorize?audience=api.acme.com",
        },
        headers=auth,
    )

    assert allowed.status_code == 200


def test_reconfiguring_replaces_the_authorize_params_wholesale(
    client, auth, registered_jira
):
    """The `PUT` is an upsert and replaces, deliberately — that is how a rotated client
    secret is installed. Which makes a **blank form a data-loss control**, and is why the
    screen seeds every non-secret field from what is stored before letting somebody press
    Replace. Pinned here because the storage behaviour is what the screen's decision rests
    on."""
    client.put(
        "/admin/connectors/jira/oauth",
        json={**OAUTH_BODY, "authorize_params": {"audience": "api.atlassian.com"}},
        headers=auth,
    )

    client.put("/admin/connectors/jira/oauth", json=OAUTH_BODY, headers=auth)

    assert (
        client.get("/admin/connectors/jira", headers=auth).json()["oauth"][
            "authorize_params"
        ]
        == {}
    )


def test_configuring_oauth_on_a_stdio_connector_is_refused_from_the_access_layer(
    client, auth, admin, vetted_github
):
    """**Finding 3's guard, arriving through the door it was moved for.**

    This route calls `oauth.configure` directly. Before 12c the check lived in
    `cli._set_oauth`, so this exact request would have configured a consent flow on a
    connector that can never present the credential it produces — somebody completes a
    screen at a third party, granting real access, and finds out at their first run.

    Byte for byte the CLI's sentence, because there is one sentence.
    """
    from carnet.access import oauth as oauth_module  # noqa: PLC0415

    response = client.put(
        f"/admin/connectors/{vetted_github.id}/oauth", json=OAUTH_BODY, headers=auth
    )

    assert response.status_code == 400
    assert response.json()["detail"] == oauth_module.STDIO_CONSENT_REFUSED.format(
        connector=vetted_github.id
    )
    assert oauth_module.configured(TEST_TENANT) == {}


def test_a_token_endpoint_on_an_unapproved_host_is_refused(client, auth, registered_jira):
    """An inherited refusal, driven rather than trusted. The token endpoint receives this
    deployment's client secret in a server-side POST, which is the same risk class as
    dialling the MCP server — so it is subject to the same allowlist."""
    response = client.put(
        "/admin/connectors/jira/oauth",
        json={**OAUTH_BODY, "token_endpoint": "https://elsewhere.example.com/token"},
        headers=auth,
    )

    assert response.status_code == 400
    assert "has not approved the host" in response.json()["detail"]


def test_a_non_tls_authorization_server_is_refused(client, auth, registered_jira):
    """`check_oauth_app`'s rule, inherited. Over `http` the token endpoint's client
    secret and the authorize endpoint's authorization code are both readable by anything
    on the path."""
    response = client.put(
        "/admin/connectors/jira/oauth",
        json={**OAUTH_BODY, "token_endpoint": "http://api.example.com/token"},
        headers=auth,
    )

    assert response.status_code in (400, 422)


def test_reconfiguring_a_consent_flow_is_how_a_secret_is_rotated(
    client, auth, registered_jira
):
    """An upsert, deliberately. Refusing a second configure would make rotation a
    delete-then-create with a window in which nobody can connect."""
    client.put("/admin/connectors/jira/oauth", json=OAUTH_BODY, headers=auth)

    second = client.put(
        "/admin/connectors/jira/oauth",
        json={**OAUTH_BODY, "client_secret": "MARKER-ROTATED-9f21", "client_id": "client-xyz"},
        headers=auth,
    )

    assert second.status_code == 200
    assert second.json()["app"]["client_id"] == "client-xyz"
    assert "MARKER-ROTATED-9f21" not in second.text

    records = [
        row
        for row in storage.active().admin_audit_records(TEST_TENANT)
        if row["action"] == "connector.oauth.configure"
    ]
    assert len(records) == 2, "a rotation is a second record, not an edit of the first"


def test_removing_a_consent_flow_leaves_credentials_alone(
    client, auth, registered_jira
):
    """Migration 021's argument: destroying evidence that people consented, as a side
    effect of an administrative action about configuration, is what does not happen."""
    client.put("/admin/connectors/jira/oauth", json=OAUTH_BODY, headers=auth)

    response = client.delete("/admin/connectors/jira/oauth", headers=auth)

    assert response.status_code == 200
    assert response.json()["removed"] is True
    assert client.get("/admin/connectors/jira", headers=auth).json()["oauth"] is None

    # Idempotent, and it says so rather than 404ing on the second click.
    assert client.delete("/admin/connectors/jira/oauth", headers=auth).json()["removed"] is False


def test_a_configured_connector_becomes_connectable_on_the_connections_page(
    client, auth, registered_jira, fake_server
):
    """**The whole distance this step covers, in one assertion**: from a tenant with
    nothing to a person with a Connect button, without a shell.

    The Connections page's third state — *no consent flow yet, ask an administrator* — is
    exactly a connector absent from the OAuth rows, so this is the state change that
    matters and the one an administrator was previously unable to cause.
    """
    before = {row["connector_id"]: row for row in client.get("/connections", headers=auth).json()}
    assert before["jira"]["state"] == "unavailable"

    client.put("/admin/connectors/jira/oauth", json=OAUTH_BODY, headers=auth)

    after = {row["connector_id"]: row for row in client.get("/connections", headers=auth).json()}
    assert after["jira"]["state"] == "connectable"
    assert after["jira"]["scopes"] == ["read:jira-work", "offline_access"]


# --- the inherited refusals, driven rather than trusted -------------------------------


def test_a_suspended_customer_reaches_no_administration_route(
    client, auth, admin, registered
):
    """12b's rule, inherited through `admin_from_request` — asserted rather than assumed.

    Sign-in is refused at `users.resolve`, before the role is ever consulted, so a
    suspended customer's administrator gets the same 403 as everybody else in it. The CLI
    still works, which is the recovery path.
    """
    storage.active().set_tenant_status(TEST_TENANT, "suspended")

    for method, path, body in ADMIN_CONNECTOR_ROUTES:
        response = getattr(client, method)(
            path, headers=auth, **({"json": body} if body else {})
        )
        assert response.status_code == 403, f"{method.upper()} {path}"
        assert "suspended" in response.json()["detail"]


# --- follow-up turns (step 014) -------------------------------------------------------
#
# A follow-up is an ordinary run that arrives knowing what was said before: it re-enters
# the same grant check, the same 202, the same worker. What is under test here is the
# route's decided refusal order, the replay being byte-exact task/answer pairs, the
# thread permission model (private by default, shared by choice, `private_runs` above
# both), and the idempotency contract widened by one comparison. The row mechanics —
# roots, the live-child index, the freed slot — are the contract suite's.


# --- private_runs (decision 8's third layer) ------------------------------------------


def test_private_runs_must_be_a_boolean(client, auth):
    """`"true"` is not true. Over HTTP pydantic refuses what it cannot coerce; below
    it, the validator refuses any non-bool outright — a truthy string would make
    `"false"` private, which is a config that reads as open and is not."""
    response = client.post(
        "/agents",
        json={
            "name": "not-a-bool",
            "system": "x",
            "permissions": {"tools": [], "scope": {}},
            "private_runs": "banana",
        },
        headers=auth,
    )
    assert response.status_code == 422

    # The write paths that take a raw dict — `--seed`, the CLI — hit the validator's
    # own sentence, which pydantic's lax coercion never gets the chance to launder.
    with pytest.raises(agents.InvalidAgentError, match="true or false"):
        agents.save(
            TEST_TENANT, {**AGENT, "name": "raw", "private_runs": "yes"},
            actor="system:cli",
        )


# --- the machine caller, step 020 -------------------------------------------------
#
# The second door. What these hold is the escalation trap the whole step is arranged
# around — a token that resolved to a `system` principal would be a tenant administrator
# — plus the three gates and the one sentence.


@pytest.fixture
def machine(client, auth):
    """A live API token owned by whoever `auth` is, and the string it presents.

    Minted through `tokens.mint` rather than by writing a row, because the secret exists
    exactly once and only that function has it — which is the property under test as
    much as it is a fixture detail.
    """
    from carnet.access import tokens

    owner = logged_in_id(client, auth)
    row, presented = tokens.mint(
        TEST_TENANT, "nightly-ci", owner, actor="system:cli"
    )
    return row, presented, owner


@pytest.fixture
def machine_auth(machine):
    _, presented, _ = machine
    return {"Authorization": f"Bearer {presented}"}


def test_a_machine_token_never_resolves_to_a_system_principal(registered, machine):
    """**The trap this whole step is arranged around.**

    `access/roles.py` returns True for every `system` principal before touching storage,
    on the stated precondition that no HTTP caller can be one. A machine token minting a
    `system` principal would therefore make every API token a tenant administrator, with
    no row to revoke and nothing in the log calling it an escalation.

    Behavioural rather than a source grep, unlike its sibling below: what matters is the
    kind that comes *out*, not the spelling that goes in.
    """
    from carnet.access import roles, tokens

    _, presented, _ = machine
    principal = tokens.resolve(presented)

    assert principal.kind == "machine"
    assert principal.kind != "system"
    assert principal.tenant_id == TEST_TENANT
    assert roles.is_admin(principal) is False


def test_a_personal_token_resolves_to_the_same_machine_kind(registered, machine):
    """The 020 trap, re-armed for 033d. A personal token redirects whose GRANT ROWS
    answer — never the principal — so what comes out of `resolve` is byte-identical in
    kind to a service token's, and an owner who is an administrator hands the token
    none of it. The redirection edits `role_of`, which is exactly where 021 says an
    escalation would arrive, so the admin half is asserted here as well as there."""
    from carnet.access import roles, tokens

    _, _, owner = machine
    storage.active().grant_platform_role(
        TEST_TENANT, "user", owner, "admin", actor="system:cli"
    )
    _, presented = tokens.mint(
        TEST_TENANT, "priya-editor", owner, actor="system:cli", acts_as_owner=True
    )

    principal = tokens.resolve(presented)

    assert principal.kind == "machine"
    assert roles.is_admin(principal) is False


def test_the_token_module_can_never_mint_a_system_principal(registered, machine):
    """`test_http_can_never_mint_a_system_principal`'s pattern, aimed at the file that
    could actually have broken it. `deps.py` is now one of two doors, and this is the
    other one."""
    import pathlib

    from carnet.access import tokens

    source = pathlib.Path(tokens.__file__).read_text()
    assert "Principal.system" not in source
    assert "Principal.machine" in source


def test_a_machine_is_refused_every_admin_route(registered, client, machine_auth):
    """403 and a denial record naming the machine. The mutation that matters here is
    widening `roles.py`'s always-admin line to include `machine`, which this fails."""
    response = client.get("/admin-audit", headers=machine_auth)
    assert response.status_code == 403

    denials = storage.active().denial_records(TEST_TENANT)
    machine_denials = [d for d in denials if d["principal_kind"] == "machine"]
    assert machine_denials, f"no denial named a machine; log has {denials}"
    assert machine_denials[-1]["resource_kind"] == "admin"


def test_a_machine_may_read_history_and_may_never_restore(
    registered, client, auth, machine
):
    """Step 021 meeting step 020, and the answer costs no code — which is why it is
    worth a test rather than an assumption.

    `agent_grants_no_machine_above_user` caps a machine at `user`, so `editor` is not
    reachable for one and the restore is refused by the ladder that already exists. A
    machine reading the history is the same `user` read as a machine reading the agent.
    """
    row, presented, owner = machine
    headers = {"Authorization": f"Bearer {presented}"}

    storage.active().create_agent(TEST_TENANT, AGENT, "user", owner)
    storage.active().grant_agent(
        TEST_TENANT, AGENT["name"], "machine", row["id"], "user", actor="system:cli"
    )

    assert client.get(f"/agents/{AGENT['name']}/versions", headers=headers).json() == [
        {
            "version": 1,
            "created_at": _open(client, headers, AGENT["name"])["updated_at"],
            "created_by": f"user:{owner}",
            "source": "create",
            "restored_from": None,
            "valid": True,
            "error": None,
        }
    ]

    refused = client.post(
        f"/agents/{AGENT['name']}/versions/1/restore",
        headers={**headers, "If-Match": '"2026-08-13T00:00:00+00:00"'},
    )
    assert refused.status_code == 404


def test_a_group_cannot_make_a_machine_an_editor(registered, client, auth, machine):
    """**The ceiling 020 documented twice was reachable around both statements of it.**

    `MACHINE_ROLES` and `agent_grants_no_machine_above_user` each guard a *direct* grant.
    Neither can see a group — a machine may be a member (031 widened `group_members` on
    purpose), a group may be granted `editor`, and "highest of direct and inherited" then
    handed a machine the level both rules exist to withhold.

    What it produced, found by driving the request rather than by reading: `your_role`
    came back **`editor`**, so a screen would render Edit and Restore for a token — and
    the write then failed at the last guard, `ADMIN_ACTOR_KINDS`, as a bare
    `StorageError`, which becomes *"storage unavailable: try again later"* about a thing
    that will never work. Nothing was ever written, so this was a control in the wrong
    place and a refusal in the wrong family rather than a data defect.

    The cap now lives in `grants.role_of`, which is the one place every path goes
    through. Mutation check: remove it and this fails on `your_role` before it gets to
    the verbs.
    """
    row, presented, owner = machine
    headers = {"Authorization": f"Bearer {presented}"}
    store = storage.active()
    store.create_agent(TEST_TENANT, AGENT, "user", owner)
    store.create_group(TEST_TENANT, "g-ops", "ops", actor="system:cli")
    store.add_group_member(
        TEST_TENANT, "g-ops", "machine", row["id"], actor="system:cli"
    )
    store.grant_agent(
        TEST_TENANT, AGENT["name"], "group", "g-ops", role="editor", actor="system:cli"
    )

    detail = client.get(f"/agents/{AGENT['name']}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["your_role"] == "user", "a group cannot make a machine a person"

    etag = detail.json()["updated_at"]
    conditional = {**headers, "If-Match": f'"{etag}"'}
    restore = client.post(
        f"/agents/{AGENT['name']}/versions/1/restore", headers=conditional
    )
    patch = client.patch(
        f"/agents/{AGENT['name']}", json={"system": "a machine wrote this"},
        headers=conditional,
    )

    # The ladder's own 404, not a 503 — and identical to what an absent agent gives.
    assert restore.status_code == patch.status_code == 404
    assert restore.json()["detail"] == f"no agent named '{AGENT['name']}'"
    assert patch.json() == restore.json()


def test_the_share_sheet_reports_a_machines_capped_role(
    registered, client, auth, machine
):
    """**The sheet must agree with the enforcement**, which is the whole reason `via`
    exists — and it did not: `who_has_access` aggregated the group's `editor` onto the
    machine's row while `role_of` capped the same token at `user`. An auditor reading
    the one screen that answers "who can reach this agent" would have counted an editor
    that cannot edit — over-reporting, the safe direction, on exactly the screen where
    over-reporting causes the panic.

    The group's own row still says `editor`, because that is the group's fact: revoking
    it is one of the two things an owner can do about inherited access.
    """
    row, presented, owner = machine
    store = storage.active()
    store.create_agent(TEST_TENANT, AGENT, "user", owner)
    store.create_group(TEST_TENANT, "g-ops", "ops", actor="system:cli")
    store.add_group_member(
        TEST_TENANT, "g-ops", "machine", row["id"], actor="system:cli"
    )
    store.grant_agent(
        TEST_TENANT, AGENT["name"], "group", "g-ops", role="editor", actor="system:cli"
    )
    share_with_caller(client, auth, AGENT["name"], role="user")

    sheet = client.get(f"/agents/{AGENT['name']}/access", headers=auth).json()
    by_kind = {entry["kind"]: entry for entry in sheet["access"]}

    assert by_kind["machine"]["role"] == "user"
    assert by_kind["machine"]["via"] == ["g-ops"]
    assert by_kind["group"]["role"] == "editor"


def test_every_version_route_gives_an_ungranted_agent_the_absent_agents_bytes(
    client, auth, unshared_agent
):
    """Asserted as **byte equality against a name that does not exist**, which is the
    property that actually matters and the one status-code assertions miss.

    `test_history_of_an_agent_you_may_not_see_is_the_same_404` checked the list route's
    body and only the status of the other two, so a reordering inside either — the
    version lookup before the grant check — would reopen the leak with both tests green.
    """
    conditional = {**auth, "If-Match": '"2026-08-13T00:00:00+00:00"'}
    pairs = [
        (client.get("/agents/demo/versions", headers=auth),
         client.get("/agents/nope/versions", headers=auth)),
        (client.get("/agents/demo/versions/1", headers=auth),
         client.get("/agents/nope/versions/1", headers=auth)),
        (client.post("/agents/demo/versions/1/restore", headers=conditional),
         client.post("/agents/nope/versions/1/restore", headers=conditional)),
    ]

    for ungranted, missing in pairs:
        assert ungranted.status_code == missing.status_code == 404
        assert ungranted.json()["detail"] == missing.json()["detail"].replace(
            "nope", "demo"
        )


def test_the_share_sheet_can_describe_a_machine_grantee(registered, client, auth, machine):
    """**The response model has to know the kind exists**, or the sheet 500s.

    `AgentAccessEntry.kind` was `Literal["user", "system", "group"]` — a fourth copy of a
    vocabulary that already lived in a frozenset and a CHECK. Widening both left this one
    behind, so the first share sheet holding a machine answered 500: the grant correct,
    the storage correct, and the response model refusing to describe what it was handed.
    It is derived from `GRANTEE_KINDS` now, and this is what says so.

    Found by driving the e2e rather than by the suite, which is why it is also a test.
    """
    token_row, _, owner = machine
    storage.active().create_agent(TEST_TENANT, AGENT, "user", owner)
    storage.active().grant_agent(
        TEST_TENANT, AGENT["name"], "machine", token_row["id"], "user",
        actor="system:cli",
    )

    response = client.get(f"/agents/{AGENT['name']}/access", headers=auth)

    assert response.status_code == 200, response.text
    entries = {(e["kind"], e["id"]): e["role"] for e in response.json()["access"]}
    assert entries[("machine", token_row["id"])] == "user"
    assert entries[("user", owner)] == "owner"


def test_granting_a_machine_above_user_over_http_is_a_400(registered, client, auth, machine):
    """A caller error, not a server failure — `api/errors.py`'s family, which this is the
    eighth instance of. It answered **503** ("storage unavailable: try again later")
    about a grant that will never be accepted, because `check_grant` raised a bare
    `StorageError`. Found by driving the route."""
    token_row, _, owner = machine
    storage.active().create_agent(TEST_TENANT, AGENT, "user", owner)

    response = client.put(
        f"/agents/{AGENT['name']}/grants/machine/{token_row['id']}",
        json={"role": "editor"},
        headers=auth,
    )

    assert response.status_code == 400, response.text
    assert "a machine may be granted" in response.json()["detail"]


@pytest.mark.parametrize(
    "mangle,label",
    [
        (lambda t: "art_", "prefix alone"),
        (lambda t: "art_m_nosuchtoken.secret", "unknown id"),
        (lambda t: t.rsplit(".", 1)[0] + ".wrong-secret", "wrong secret"),
        (lambda t: t.replace("art_", "art_x"), "mangled id"),
        (lambda t: t.rsplit(".", 1)[0], "no separator"),
    ],
)
def test_every_bad_machine_token_gets_one_sentence(
    registered, client, machine, mangle, label
):
    """**Asserted by equality against the human door's refusal**, not by both being
    written carefully.

    Saying "revoked" or "expired" confirms to whoever holds a stolen token that it was
    real and once worked. The bytes are the anti-enumeration property, exactly as they
    are for the 404 an agent nobody shared with you returns.
    """
    _, presented, _ = machine
    forged_jwt = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.e30.x"}
    human = client.get("/agents", headers=forged_jwt)

    response = client.get("/agents", headers={"Authorization": f"Bearer {mangle(presented)}"})

    assert response.status_code == human.status_code == 401
    assert response.json() == human.json(), label
    assert response.headers["WWW-Authenticate"] == human.headers["WWW-Authenticate"]


def test_a_revoked_token_is_refused_with_the_same_sentence(registered, client, machine):
    row, presented, _ = machine
    headers = {"Authorization": f"Bearer {presented}"}
    assert client.get("/agents", headers=headers).status_code == 200

    storage.active().revoke_api_token(TEST_TENANT, row["id"], actor="system:cli")

    response = client.get("/agents", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "not a valid token for this service"


def test_an_expired_token_is_refused(registered, client, auth):
    """The coarse case: a token whose moment has passed does not work."""
    from datetime import datetime, timedelta, timezone

    from carnet.access import tokens

    owner = logged_in_id(client, auth)
    _, dead = tokens.mint(
        TEST_TENANT, "dead", owner, actor="system:cli",
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    _, live = tokens.mint(
        TEST_TENANT, "live", owner, actor="system:cli",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )

    assert client.get("/agents", headers={"Authorization": f"Bearer {dead}"}).status_code == 401
    assert client.get("/agents", headers={"Authorization": f"Bearer {live}"}).status_code == 200


def test_the_expiry_boundary_is_strict_at_the_exact_instant(
    registered, client, auth, monkeypatch
):
    """**Against a frozen clock, because otherwise this test asserts nothing.**

    The obvious version mints a token expiring at `now` and then makes a request — but
    time passes between those two lines, so the token is a millisecond stale by the time
    it is checked and `<` and `<=` both refuse it. Mutating the comparison leaves the
    whole suite and the e2e script green, which is how this was found: the mutation
    survived, and the assertion that looked like a boundary test was a test that an
    already-expired token fails.

    Freezing `now` is what makes the three cases actually distinct. A token *at* its
    expiry is refused: a boundary must have one answer, and the one that keeps a
    credential alive a moment longer than its owner asked is the wrong one to guess.
    """
    from datetime import datetime, timedelta, timezone

    from carnet.access import tokens
    from carnet.access.oidc import TokenError

    owner = logged_in_id(client, auth)
    instant = datetime(2030, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

    class FrozenClock:
        @staticmethod
        def now(tz=None):
            return instant

    monkeypatch.setattr(tokens, "datetime", FrozenClock)

    resolved = []
    for label, when in (
        ("before", instant - timedelta(seconds=1)),
        ("exactly", instant),
        ("after", instant + timedelta(seconds=1)),
    ):
        _, presented = tokens.mint(
            TEST_TENANT, f"boundary-{label}", owner, actor="system:cli", expires_at=when
        )
        try:
            tokens.resolve(presented)
            resolved.append(label)
        except TokenError:
            pass

    assert resolved == ["after"], "the token at its exact expiry must be refused"


def test_suspending_the_customer_closes_the_machine_door_too(
    registered, client, auth, machine_auth
):
    """**The third door.** Migration 020 named two — authentication and the claim loop —
    and this is a way work arrives that did not exist then. Asserted by equality with the
    sentence a person gets, because one shared function is the mechanism and two careful
    authors is not."""
    human_before = client.get("/agents", headers=auth)
    assert human_before.status_code == 200
    assert client.get("/agents", headers=machine_auth).status_code == 200

    storage.active().set_tenant_status(TEST_TENANT, "suspended")

    human = client.get("/agents", headers=auth)
    machine_response = client.get("/agents", headers=machine_auth)

    assert human.status_code == machine_response.status_code == 403
    assert machine_response.json() == human.json()
    assert "suspended" in machine_response.json()["detail"]


def test_disabling_the_owner_closes_their_machines(registered, client, machine, machine_auth):
    """What makes offboarding a person offboard their machines. `set_user_status` is
    documented as "the only thing that can cut somebody off immediately", and without the
    live owner read that sentence would have quietly stopped being true."""
    _, _, owner = machine
    assert client.get("/agents", headers=machine_auth).status_code == 200

    storage.active().set_user_status(TEST_TENANT, owner, "disabled", actor="system:test")

    response = client.get("/agents", headers=machine_auth)
    assert response.status_code == 403
    assert "owner of this API token" in response.json()["detail"]


def test_a_token_is_touched_on_use_and_the_secret_is_never_stored(registered, client, machine, machine_auth):
    """`last_used_at` is what an offboarding review reads. The second assertion is the
    one worth having: the presented secret appears nowhere in the row."""
    row, presented, _ = machine
    secret = presented.rsplit(".", 1)[1]

    assert storage.active().find_api_token(row["id"])["last_used_at"] is None
    client.get("/agents", headers=machine_auth)

    stored = storage.active().find_api_token(row["id"])
    assert stored["last_used_at"] is not None
    assert secret not in repr(stored)
    assert stored["secret_hash"] != secret


# --- 020 edge hunt: the edges the plan did not think of ----------------------------


def test_a_revoked_name_can_be_reused(registered, client, auth):
    """The edge hunt's first defect. `UNIQUE (tenant_id, name)` burned a name on
    revocation, so the replacement for a leaked token could not take the name the
    pipeline's configuration already referred to. `api_tokens_one_live_name` now."""
    from carnet.access import tokens

    owner = logged_in_id(client, auth)
    row, _ = tokens.mint(TEST_TENANT, "nightly-ci", owner, actor="system:cli")
    storage.active().revoke_api_token(TEST_TENANT, row["id"], actor="system:cli")

    replacement, _ = tokens.mint(TEST_TENANT, "nightly-ci", owner, actor="system:cli")
    assert replacement["id"] != row["id"]


def test_an_owner_from_another_tenant_is_refused(registered, client, auth):
    """An owner in another tenant is nobody. `get_user` is tenant-scoped, so the live
    owner read fails closed — which is what `owner_id` having no foreign key costs and
    where that cost is paid."""
    from carnet.access import tokens
    from carnet.access.users import AccessDenied

    store = storage.active()
    store.create_tenant("other-co", "Other Co")
    store.create_user("other-co", {"id": "u_stranger", "issuer": "https://x", "subject": "s"})

    _, presented = tokens.mint(TEST_TENANT, "cross", "u_stranger", actor="system:cli")

    with pytest.raises(AccessDenied):
        tokens.resolve(presented)


def test_a_credential_with_extra_separators_resolves_to_nothing(registered, client, auth):
    """The parser half of the id guard, tested without a bad row — because there can no
    longer be one: `normalize_api_token` refuses an id containing the separator.

    `_split` partitions on the **first** separator, so everything after it is the secret.
    A credential carrying extra ones therefore names a shorter id than it looks like and
    resolves to nothing, rather than matching a real token by accident.
    """
    from carnet.access import tokens
    from carnet.access.oidc import TokenError

    for presented in ("art_m_has.dot.s3cret", "art_m_x..", "art_.secret"):
        with pytest.raises(TokenError):
            tokens.resolve(presented)


def test_a_machine_cannot_claim_a_pending_grant(registered, client, auth, machine):
    """`check_claimant` already refused every kind but `user`, so this needed no new code
    — the shape of a rule that was already right, asserted because a widened
    `PRINCIPAL_KINDS` is exactly what would have loosened it."""
    from carnet.storage.base import StorageError

    token_row, _, owner = machine
    storage.active().create_agent(TEST_TENANT, AGENT, "user", owner)
    storage.active().add_pending_grant(
        TEST_TENANT, AGENT["name"], "newhire@acme.com", "user",
        granted_by=f"user:{owner}", actor=f"user:{owner}",
    )

    with pytest.raises(StorageError):
        storage.active().claim_pending_grants(
            TEST_TENANT, "newhire@acme.com", "machine", token_row["id"]
        )


def test_a_machine_is_refused_on_me_without_crashing(registered, client, machine_auth):
    """`profile()` returns {} for a non-user, and `GET /me` has to render that rather than
    raise: a client calling it on startup must not 500 because it is a machine."""
    response = client.get("/me", headers=machine_auth)
    assert response.status_code == 200, response.text
    assert response.json()["admin"] is False


def test_a_machine_reached_through_a_group_shows_in_the_share_sheet(
    registered, client, auth, machine
):
    """Group expansion is kind-agnostic, so a machine reached through a group appears in
    the sheet with its `via` — no machine-specific branch anywhere in `grants.py`."""
    token_row, _, owner = machine
    store = storage.active()
    store.create_agent(TEST_TENANT, AGENT, "user", owner)
    store.create_group(TEST_TENANT, "g_bots", "Bots", actor="system:cli")
    store.add_group_member(TEST_TENANT, "g_bots", "machine", token_row["id"], actor="system:cli")
    store.grant_agent(TEST_TENANT, AGENT["name"], "group", "g_bots", "user", actor="system:cli")

    response = client.get(f"/agents/{AGENT['name']}/access", headers=auth)

    assert response.status_code == 200, response.text
    entries = {(e["kind"], e["id"]): e for e in response.json()["access"]}
    assert ("machine", token_row["id"]) in entries


def test_a_revoked_tokens_grant_is_still_listed_and_that_is_a_known_gap(
    registered, client, auth, machine
):
    """**A gap, asserted so it stays visible** — the shape `test_a_name_that_would_
    resolve_to_a_private_address_is_not_caught` uses for the DNS-rebinding hole.

    Revocation kills the credential and leaves the grant, so the share sheet keeps
    listing a machine that can never authenticate again. It over-reports access rather
    than under-reporting it, which is the safe direction — but "who can reach this agent"
    is the one question that screen answers, and this answers it wrongly.

    Not fixed here: `who_has_access` would have to join `api_tokens`, and it is already
    N+1 behind a screen somebody reloads (the register carries that row). Filed rather
    than built, and pinned here so the next person finds it deliberately.
    """
    token_row, _, owner = machine
    store = storage.active()
    store.create_agent(TEST_TENANT, AGENT, "user", owner)
    store.grant_agent(TEST_TENANT, AGENT["name"], "machine", token_row["id"], "user",
                      actor="system:cli")
    store.revoke_api_token(TEST_TENANT, token_row["id"], actor="system:cli")

    entries = {
        (e["kind"], e["id"])
        for e in client.get(f"/agents/{AGENT['name']}/access", headers=auth).json()["access"]
    }
    assert ("machine", token_row["id"]) in entries


def test_a_refused_request_does_not_stamp_last_used(registered, client, machine):
    """`touch` is after every check, so a wrong secret does not look like use. It matters
    because `last_used_at` is what an offboarding review reads to decide what is dead."""
    token_row, presented, _ = machine
    bad = presented.rsplit(".", 1)[0] + ".wrong"

    client.get("/agents", headers={"Authorization": f"Bearer {bad}"})

    assert storage.active().find_api_token(token_row["id"])["last_used_at"] is None


def test_a_suspended_tenants_token_does_not_stamp_last_used(registered, client, machine):
    """The two 403 gates also sit before `touch`. A credential refused because its customer
    is suspended has not been used, and a review must not read it as alive."""
    token_row, _, _ = machine
    headers = {"Authorization": f"Bearer {_present(machine)}"}
    storage.active().set_tenant_status(TEST_TENANT, "suspended")

    client.get("/agents", headers=headers)

    assert storage.active().find_api_token(token_row["id"])["last_used_at"] is None


def _present(machine):
    return machine[1]


def test_a_machine_may_not_reach_another_tenants_agent(registered, client, auth, machine):
    """The tenant comes off the token row, never off the request — so a grant written in
    another customer's tenant naming this token id reaches nothing."""
    token_row, presented, owner = machine
    store = storage.active()
    store.create_tenant("other-co", "Other Co")
    store.create_user("other-co", {"id": "u_them", "issuer": "https://y", "subject": "s2"})
    store.create_agent("other-co", AGENT, "user", "u_them")
    store.grant_agent("other-co", AGENT["name"], "machine", token_row["id"], "user",
                      actor="system:cli")

    response = client.post(
        "/runs", json={"agent": AGENT["name"], "task": "go"},
        headers={"Authorization": f"Bearer {presented}"},
    )
    assert response.status_code == 404


def test_an_empty_or_absurd_token_name_is_refused(registered, client, auth):
    from carnet.access import tokens
    from carnet.storage.base import StorageError

    owner = logged_in_id(client, auth)
    with pytest.raises(StorageError):
        tokens.mint(TEST_TENANT, "", owner, actor="system:cli")


def test_a_gigantic_presented_token_is_refused_cheaply(registered, client):
    """`art_` plus a megabyte is refused like any other malformed credential, and nothing
    below it hashes or queries at that scale."""
    huge = "art_" + ("m_" + "a" * 500_000) + "." + "b" * 500_000
    response = client.get("/agents", headers={"Authorization": f"Bearer {huge}"})
    assert response.status_code == 401


def test_deleting_the_tenant_kills_the_token(registered, client, auth, machine):
    token_row, presented, _ = machine
    store = storage.active()
    store.set_tenant_status(TEST_TENANT, "suspended")
    store.delete_tenant(TEST_TENANT, actor="system:cli")

    response = client.get("/agents", headers={"Authorization": f"Bearer {presented}"})
    assert response.status_code == 401
    assert store.find_api_token(token_row["id"]) is None


def test_a_machine_may_hold_a_delegated_connection(registered, client, auth, machine):
    """`crypto.connection_aad` binds ciphertext to `(tenant, kind, id, connector)`, so the
    new kind has to survive a seal-and-open round trip or an operator could provision a
    machine credential that nothing can read."""
    from carnet.core import crypto

    token_row, _, _ = machine
    store = storage.active()
    store.save_connector(TEST_TENANT, {"id": "jira", "url": "https://mcp.example.com/mcp"},
                         actor="system:cli")
    aad = crypto.connection_aad(TEST_TENANT, "machine", token_row["id"], "jira")
    ciphertext, key_id = crypto.seal("s3cret", tenant_id=TEST_TENANT, aad=aad)
    store.save_connection(
        TEST_TENANT, "machine", token_row["id"], "jira",
        ciphertext=ciphertext, key_id=key_id, expires_at=None, actor="system:cli",
    )

    found = store.find_connection(TEST_TENANT, "machine", token_row["id"], "jira")
    assert crypto.open_(found["ciphertext"], tenant_id=TEST_TENANT, aad=aad,
                        key_id=found["key_id"]) == "s3cret"


def test_a_token_id_may_never_contain_the_separator(registered, client, auth):
    """Nothing mints such an id — `tokens.mint` builds `m_` plus hex — and it is refused
    anyway, on `check_prune_batch`'s reason: this is a public method on the storage
    protocol and the next caller will not know that. Found by an edge hunt."""
    from carnet.storage.base import StorageError

    owner = logged_in_id(client, auth)
    with pytest.raises(StorageError):
        storage.active().create_api_token(
            TEST_TENANT,
            {"id": "m_has.dot", "name": "dotted", "owner_id": owner,
             "secret_hash": "sha256$aa"},
            actor="system:cli",
        )


def test_a_machine_cannot_share_the_agent_it_can_run(registered, client, auth, machine):
    """Plan edge 10. A machine holds `user`, sharing needs `editor`, and the refusal is
    the same 404 a stranger gets — no machine-specific branch, just the existing ladder
    doing its job on a kind it had never seen.

    **Two guards, and removing either alone changes nothing observable** — 12b's finding
    about the group routes, arriving again: `put_grant` requires `editor` and so does
    `grants.share`. Mutation-checked in all three combinations, and only removing *both*
    fails this, which is worth recording so nobody reads this test as pinning one of
    them. What it pins is the outcome, which is the thing that matters.
    """
    token_row, presented, owner = machine
    store = storage.active()
    store.create_agent(TEST_TENANT, AGENT, "user", owner)
    store.grant_agent(TEST_TENANT, AGENT["name"], "machine", token_row["id"], "user",
                      actor="system:cli")
    headers = {"Authorization": f"Bearer {presented}"}

    # It can reach the agent...
    assert client.get(f"/agents/{AGENT['name']}", headers=headers).status_code == 200
    # ...and cannot pass that access on.
    onward = client.put(
        f"/agents/{AGENT['name']}/grants/user/u_somebody",
        json={"role": "user"}, headers=headers,
    )
    assert onward.status_code == 404
    assert client.delete(f"/agents/{AGENT['name']}", headers=headers).status_code == 404


def test_a_machine_with_no_connection_has_no_credential(registered, client, auth, machine):
    """Plan edge 15. A delegated credential is per principal, so a machine has its own or
    none — never its owner's. `None` means *not connected* and nothing else, which is what
    turns into the existing sentence at the tool call."""
    from carnet.core import credentials

    token_row, _, owner = machine
    storage.active().save_connector(
        TEST_TENANT, {"id": "jira", "url": "https://mcp.example.com/mcp"}, actor="system:cli"
    )
    machine_principal = Principal.machine(token_row["id"], TEST_TENANT)
    owner_principal = Principal.user(owner, TEST_TENANT)

    assert credentials._delegated_credential("jira", machine_principal) is None
    # And its owner's connection is not inherited: the whole point of 7a.
    assert credentials._delegated_credential("jira", owner_principal) is None


def test_a_jwt_never_enters_the_token_door(registered, client, auth):
    """Plan edge 18. Dispatch is on the credential's shape, before anything is verified,
    and a JWT is base64 of `{"alg"...` so it begins `eyJ`. Asserted rather than reasoned:
    the two doors produce the same 401 bytes, so a JWT quietly taking the machine path
    would be invisible from outside."""
    from carnet.access import tokens

    jwt_token = auth["Authorization"].removeprefix("Bearer ")

    assert jwt_token.startswith("eyJ")
    assert tokens.looks_like_api_token(jwt_token) is False
    # And the genuine article still works, so this is not passing because auth is broken.
    assert client.get("/agents", headers=auth).status_code == 200


# --- schedules over HTTP, step 022b ---------------------------------------------------
#
# The browser half of a machine caller with a clock. Two gates that are about different
# things — the agent's grant, and the token's owner — and the tests below are arranged
# around proving they are independent rather than one check written twice.

SCHEDULE_CADENCE = {"every": "day", "at": "07:30"}


def _post_schedule(client, headers, token_id, agent=AGENT["name"], **overrides):
    body = {
        "task": "summarize yesterday",
        "cadence": SCHEDULE_CADENCE,
        "timezone": "Europe/Berlin",
        "token_id": token_id,
    }
    body.update(overrides)
    return client.post(f"/agents/{agent}/schedules", json=body, headers=headers)


def test_scheduling_needs_a_grant_on_the_agent_and_an_absent_one_is_the_same_404(
    client, auth, unshared_agent, machine
):
    """The route's own gate, added on top of the module's rule.

    `schedules.create` deliberately requires the creator to hold no grant — a schedule
    should survive its author changing teams — and it can name an absent agent out loud
    because by then the caller is established as the token's owner. Over HTTP nobody is
    established as anything until the grant check runs, so the route adds the API's
    visibility floor and the two 404s must be indistinguishable.
    """
    row, _presented, _owner = machine

    ungranted = _post_schedule(client, auth, row["id"])
    # The same name, now genuinely absent — which is the comparison that matters. Two
    # different names would differ in the sentence for an innocent reason and prove
    # nothing about the leak.
    storage.active().delete_agent(TEST_TENANT, AGENT["name"], actor="system:cli")
    absent = _post_schedule(client, auth, row["id"])

    assert ungranted.status_code == 404
    assert absent.status_code == 404
    assert ungranted.json() == absent.json()


# --- GET /me/tokens, step 022b --------------------------------------------------------


def test_a_person_sees_the_tokens_they_own(client, auth, machine):
    row, _presented, owner = machine

    response = client.get("/me/tokens", headers=auth)

    assert response.status_code == 200
    listed = response.json()
    assert [t["id"] for t in listed] == [row["id"]]
    assert listed[0]["name"] == "nightly-ci"
    assert listed[0]["owner_id"] == owner


def test_the_token_listing_carries_no_hash_and_no_tenant(client, auth, machine):
    """Structural rather than filtered: `find_api_token` is the only storage method that
    returns the hash and this route does not call it."""
    listed = client.get("/me/tokens", headers=auth).json()

    assert "secret_hash" not in listed[0]
    assert "tenant_id" not in listed[0]
    assert "secret" not in str(listed).lower()


def test_a_colleagues_tokens_are_not_listed(client, auth, registered, machine):
    colleague = {
        "Authorization": f"Bearer {registered.token(sub='00u-c2', email='c2@acme.com')}"
    }

    assert client.get("/me/tokens", headers=colleague).json() == []


def test_a_revoked_token_is_still_listed_with_the_field_that_says_so(
    client, auth, machine
):
    """The listing is a record; the picker is what greys out what cannot be used. A route
    that filtered these would answer "you have no tokens" to somebody who has three dead
    ones, and hide the reason their schedule stopped."""
    row, _presented, _owner = machine
    storage.active().revoke_api_token(TEST_TENANT, row["id"], actor="system:cli")

    listed = client.get("/me/tokens", headers=auth).json()

    assert len(listed) == 1
    assert listed[0]["revoked_at"] is not None
    # The three nulls stay distinguishable: never expires, never used.
    assert listed[0]["expires_at"] is None
    assert listed[0]["last_used_at"] is None


def test_a_machine_owns_no_tokens_and_that_is_an_empty_list_not_a_refusal(
    client, machine_auth, machine
):
    """A token owns nothing — `owner_id` never names a machine — so "you own no tokens"
    is a true and complete answer rather than an error about the question."""
    response = client.get("/me/tokens", headers=machine_auth)

    assert response.status_code == 200
    assert response.json() == []


def test_the_listing_says_which_tokens_act_as_their_owner(client, auth, machine):
    """**Step 035c, and the assertion that failed at the wire for three steps.**

    `acts_as_owner` decides whether a credential resolves its owner's grants and groups —
    live, capped at `user` — or only the grants held by the token itself. It has been a
    column since migration 042, it is in `API_TOKEN_PUBLIC_FIELDS`, both stores return
    it, and the mint's administrative record carries it. It never reached a caller,
    because `OwnedToken` did not declare it and pydantic's default `extra="ignore"` drops
    what a model does not name — so the property deciding a token's blast radius was
    readable from `--list-tokens` and from nowhere else.

    Both values in one listing, deliberately: a test asserting only `True` would pass on a
    model that hard-coded it, and the distinction is the deliverable rather than the flag.
    """
    from carnet.access import tokens

    _service, _presented, owner = machine
    personal, _ = tokens.mint(
        TEST_TENANT, "priya-cursor", owner, actor="system:cli", acts_as_owner=True
    )

    listed = {row["name"]: row for row in client.get("/me/tokens", headers=auth).json()}

    assert listed["priya-cursor"]["acts_as_owner"] is True
    assert listed["nightly-ci"]["acts_as_owner"] is False
    assert listed["priya-cursor"]["id"] == personal["id"]


def test_the_token_listing_declares_every_public_field(client, auth, machine):
    """The mechanism, rather than the field — 035c decision 2.

    A docstring saying *declare the whole projection* would not have caught
    `acts_as_owner`: 033d added the column, both stores carried it, the contract suite
    pinned it in `create`, `find` **and** `list`, and the wire lost it anyway, silently,
    because the loss happens at the model and every test below the model was green.

    So the response's keys are walked against the projection they are built from. This is
    023b's device for `TRIGGER_FIELDS` one table over, and it is what makes the *next*
    column added to `api_tokens` and forgotten here a failing test rather than a field
    somebody notices in a shell three steps later.

    `tenant_id` is the one subtraction and it is `AdminRecord`'s: the caller already knows
    which workspace they are in, having authenticated into it.
    """
    from carnet.storage import API_TOKEN_PUBLIC_FIELDS

    listed = client.get("/me/tokens", headers=auth).json()

    assert set(listed[0]) == set(API_TOKEN_PUBLIC_FIELDS) - {"tenant_id"}


# --- POST /me/tokens and DELETE /me/tokens/{id}, step 044 -----------------------------
#
# The route `tokens.mint`'s docstring said would never exist, narrowed rather than
# repealed: a *session* mints for itself, a machine is refused before validation, and
# revocation — the direction that must never be the hard one — sits beside it.


def _door_row(agent_name: str, **overrides) -> dict:
    """One door-call audit row, the shape `core/audit.record` writes for the door."""
    from carnet.storage import DOOR_CALL_ID_PREFIX

    row = {
        "v": 7,
        "ts": "2026-08-02T10:00:00.000+00:00",
        "run_id": f"{DOOR_CALL_ID_PREFIX}0123456789ab",
        "principal_kind": "machine",
        "principal_id": "m_abc",
        "agent": agent_name,
        "tool": "post_message",
        "effect": "write",
        "args": {"channel": "#eng"},
        "decision": "allow",
        "reason": "",
        "outcome": "ok",
        "duration_ms": 3,
        "response_bytes": 147,
        "acting_for": None,
        "identity_source": "none",
    }
    row.update(overrides)
    return row


def test_a_session_mints_a_token_it_owns_and_the_secret_works(client, auth):
    owner = logged_in_id(client, auth)

    response = client.post("/me/tokens", headers=auth, json={"name": "my-assistant"})

    assert response.status_code == 201
    body = response.json()
    assert body["owner_id"] == owner
    # The self-serve default is the personal token — the connect-your-assistant shape.
    assert body["acts_as_owner"] is True
    assert body["token"].startswith("art_m_")
    assert "secret_hash" not in body

    # The minted string authenticates. Proved by presenting it, not by inspecting it.
    minted_auth = {"Authorization": f"Bearer {body['token']}"}
    assert client.get("/me/tokens", headers=minted_auth).status_code == 200

    # And the row is on the owner's own listing, exactly as the CLI's would be.
    listed = client.get("/me/tokens", headers=auth).json()
    assert body["id"] in [t["id"] for t in listed]


def test_a_token_name_a_column_cannot_hold_is_400_not_503(client, auth):
    """Step 087. `POST /me/tokens` with a NUL in the name reached `api_tokens.name`
    and answered **503 — storage unavailable** on Postgres, while the fake stored it.
    The rule is the row's now (`normalize_api_token`), so every writer — this route,
    the CLI, an OAuth exchange — answers 400 with the sentence."""
    for name in ("bad\x00name", "line\nbreak", "tab\tstop"):
        response = client.post("/me/tokens", headers=auth, json={"name": name})
        assert response.status_code == 400, repr(name)
        assert "control characters" in response.json()["detail"], repr(name)
    assert client.get("/me/tokens", headers=auth).json() == []


def test_a_lone_surrogate_in_a_json_body_is_reachable_and_refused(client, auth):
    """Step 087. Two register rows say a lone surrogate *cannot be sent over HTTP*.
    It can: `\\ud800` is six ASCII bytes and a legal JSON escape, and `json.loads`
    produces the surrogate from it. A bare `str` field lets it through to the store,
    which now refuses it as the caller's to fix; a constrained one is refused by
    Pydantic as `string_unicode`, whose 422 used to die rendering the offending
    `input` with `ensure_ascii=False` and answer **500** — the handler renders ASCII
    now, with the default's status and shape (`test_oauth_server` drives that half)."""
    response = client.post(
        "/me/tokens", headers={**auth, "Content-Type": "application/json"},
        content=b'{"name": "a\\ud800b"}',
    )
    assert response.status_code == 400
    assert "unpaired surrogate" in response.json()["detail"]
    assert response.text.isascii()
    assert client.get("/me/tokens", headers=auth).json() == []


def test_the_mint_response_is_the_listing_row_plus_the_secret_once(client, auth):
    """035c's walk-the-keys device, applied at mint: the response is `OwnedToken`'s
    projection exactly, plus `token` — the one deliberate secret exception, 023b's
    trigger-secret rule (*a create route may return the secret once*)."""
    from carnet.storage import API_TOKEN_PUBLIC_FIELDS

    body = client.post("/me/tokens", headers=auth, json={"name": "walked"}).json()

    assert set(body) == (set(API_TOKEN_PUBLIC_FIELDS) - {"tenant_id"}) | {"token"}


def test_a_machine_may_not_mint_a_machine(client, machine_auth):
    """12b decision 5's argument, kept where it bites: no credential that survives its
    presenter may create another."""
    response = client.post(
        "/me/tokens", headers=machine_auth, json={"name": "successor"}
    )

    assert response.status_code == 403
    assert "durable successor" in response.json()["detail"]


def test_the_mint_expiry_rules_are_the_clis(client, auth):
    zero = client.post(
        "/me/tokens", headers=auth, json={"name": "soon", "expires_days": 0}
    )
    assert zero.status_code == 422  # `ge=1` — there is no "expires immediately"

    absurd = client.post(
        "/me/tokens", headers=auth, json={"name": "soon", "expires_days": 10**9}
    )
    assert absurd.status_code == 400
    assert "further ahead than a date can be written" in absurd.json()["detail"]

    real = client.post(
        "/me/tokens", headers=auth, json={"name": "soon", "expires_days": 30}
    )
    assert real.status_code == 201
    assert real.json()["expires_at"] is not None


def test_a_blank_token_name_is_refused_about_the_field(client, auth):
    response = client.post("/me/tokens", headers=auth, json={"name": "   "})

    assert response.status_code == 400
    assert "name" in response.json()["detail"]


def test_a_duplicate_live_name_is_refused_and_revocation_frees_it(
    client, auth, machine
):
    """The storage constraint's own sentence surfaces, and the name-recycling index's
    behaviour — revoke frees the name — holds over HTTP as it does at the terminal."""
    row, _presented, _owner = machine  # 'nightly-ci' is live

    taken = client.post("/me/tokens", headers=auth, json={"name": "nightly-ci"})
    assert taken.status_code == 400
    assert "live API token" in taken.json()["detail"]

    assert client.delete(f"/me/tokens/{row['id']}", headers=auth).status_code == 200

    freed = client.post("/me/tokens", headers=auth, json={"name": "nightly-ci"})
    assert freed.status_code == 201


def test_revoking_your_own_token_ends_it_and_is_idempotent(
    client, auth, machine, machine_auth
):
    row, _presented, _owner = machine
    assert client.get("/me/tokens", headers=machine_auth).status_code == 200

    first = client.delete(f"/me/tokens/{row['id']}", headers=auth)
    assert first.status_code == 200
    assert first.json()["changed"] is True
    assert first.json()["revoked_at"] is not None

    # Idempotent, and the two outcomes stay distinguishable — `MemberOutcome`'s device.
    again = client.delete(f"/me/tokens/{row['id']}", headers=auth)
    assert again.status_code == 200
    assert again.json()["changed"] is False

    # The credential is dead, with the anti-enumeration sentence every dead token gets.
    assert client.get("/me/tokens", headers=machine_auth).status_code == 401


def test_you_may_not_revoke_a_colleagues_token(client, auth, registered, machine):
    row, _presented, _owner = machine
    colleague = {
        "Authorization": f"Bearer {registered.token(sub='00u-c9', email='c9@acme.com')}"
    }

    response = client.delete(f"/me/tokens/{row['id']}", headers=colleague)

    invented = client.delete("/me/tokens/m_000000000000", headers=colleague)

    # Indistinguishable from a token that never existed — 069. It matters most at
    # this verb: a caller learning *this id is real* from a failed revoke learns it
    # from the one request that would have destroyed the row had it worked.
    assert response.status_code == invented.status_code == 400
    assert response.json()["detail"].replace(row["id"], "X") == invented.json()[
        "detail"
    ].replace("m_000000000000", "X")
    # And nothing changed for the owner.
    assert client.get("/me/tokens", headers=auth).json()[0]["revoked_at"] is None


def test_revoking_a_token_that_never_existed_is_a_400_not_an_outage(client, auth):
    response = client.delete("/me/tokens/m_nosuchtoken", headers=auth)

    assert response.status_code == 400


def test_an_administrator_may_revoke_anybodys_token(client, registered, machine):
    """`require_owner_or_admin`'s other arm, over the wire — the same permission
    `--revoke-token` exercises at a terminal, for the admin who cannot reach one."""
    row, _presented, _owner = machine
    admin = {
        "Authorization": f"Bearer {registered.token(sub='00u-adm', email='adm@acme.com')}"
    }
    storage.active().grant_platform_role(
        TEST_TENANT, "user", logged_in_id(client, admin), "admin", actor="system:cli"
    )

    response = client.delete(f"/me/tokens/{row['id']}", headers=admin)

    assert response.status_code == 200
    assert response.json()["changed"] is True


# --- GET /agents/{name}/door-activity and Me.mcp_url, step 044 ------------------------


def test_me_names_the_door(client, auth):
    """The endpoint an assistant dials, from the same config the OAuth callback is
    built from — the one origin fact a bundle cannot know."""
    body = client.get("/me", headers=auth).json()

    assert body["mcp_url"].endswith("/mcp")


def test_door_activity_starts_at_zero_and_counts_knocks(client, auth):
    owner = logged_in_id(client, auth)
    storage.active().create_agent(TEST_TENANT, AGENT, "user", owner)

    before = client.get("/agents/demo/door-activity", headers=auth)
    assert before.status_code == 200
    assert before.json() == {"calls": 0, "last_call_at": None, "last_refusal": None}

    storage.active().append_audit(TEST_TENANT, _door_row("demo"))
    # A run row is not a knock — the prefix filter is the behaviour under test.
    storage.active().append_audit(
        TEST_TENANT, _door_row("demo", run_id="abc123", ts="2026-08-02T11:00:00.000+00:00")
    )

    after = client.get("/agents/demo/door-activity", headers=auth).json()
    assert after["calls"] == 1
    assert after["last_call_at"] == "2026-08-02T10:00:00.000+00:00"


def test_door_activity_is_indistinguishable_for_ungranted_and_absent(
    client, auth, registered
):
    """`_require_agent`'s rule, on this route as on its neighbours."""
    owner = logged_in_id(client, auth)
    storage.active().create_agent(TEST_TENANT, AGENT, "user", owner)

    colleague = {
        "Authorization": f"Bearer {registered.token(sub='00u-c9', email='c9@acme.com')}"
    }

    ungranted = client.get("/agents/demo/door-activity", headers=colleague)
    absent = client.get("/agents/no-such-agent/door-activity", headers=auth)

    assert ungranted.status_code == 404
    assert absent.status_code == 404


def test_door_activity_names_the_last_refusal_for_this_agents_tools(client, auth):
    """Step 074: a call the door refused at its own threshold is in neither `calls`
    nor the audit log — it is a denial row naming the tool — and the card needs it to
    tell *refused* from *idle*. Matched by the agent's own tool list; a denial naming
    a tool this agent does not carry is not its news."""
    from carnet.storage.base import make_denial_record

    owner = logged_in_id(client, auth)
    storage.active().create_agent(TEST_TENANT, AGENT, "user", owner)

    assert client.get("/agents/demo/door-activity", headers=auth).json() == {
        "calls": 0,
        "last_call_at": None,
        "last_refusal": None,
    }

    storage.active().record_denial(
        TEST_TENANT, make_denial_record("machine", "m_other", "tool", "elsewhere", "grant")
    )
    assert client.get("/agents/demo/door-activity", headers=auth).json()["last_refusal"] is None

    storage.active().record_denial(
        TEST_TENANT, make_denial_record("machine", "m_abc", "tool", "post_message", "grant")
    )
    body = client.get("/agents/demo/door-activity", headers=auth).json()
    assert body["calls"] == 0
    refusal = body["last_refusal"]
    assert refusal["tool"] == "post_message"
    assert refusal["token"] == "m_abc"
    assert refusal["reason"] == "grant"
    assert refusal["at"].endswith("+00:00")


def test_door_activity_keeps_the_refusal_behind_the_grant(client, auth, registered):
    """*The last thing refused here* is a reconnaissance answer at any address but
    this one: an ungranted viewer gets the same 404 as for an absent agent, with no
    refusal in it."""
    from carnet.storage.base import make_denial_record

    owner = logged_in_id(client, auth)
    storage.active().create_agent(TEST_TENANT, AGENT, "user", owner)
    storage.active().record_denial(
        TEST_TENANT, make_denial_record("machine", "m_abc", "tool", "post_message", "grant")
    )
    colleague = {
        "Authorization": f"Bearer {registered.token(sub='00u-c9', email='c9@acme.com')}"
    }

    response = client.get("/agents/demo/door-activity", headers=colleague)
    assert response.status_code == 404
    assert "post_message" not in response.text


# --- door-activity's evidence, step 074 ---------------------------------------------


def test_the_reach_response_declares_every_field_as_required(client, auth, machine):
    """**The OpenAPI half of the drop direction — found by the edge pass, in the very
    chunk that cited the rule it broke.**

    035c made `OwnedToken.acts_as_owner` required rather than `= False`, because a
    pydantic default is about *a key missing from the dict a model is built from* and
    that key can never be missing. `TokenReach` and `ReachableAgent` were then written
    with `default_factory` on all five list and dict fields, so the OpenAPI document
    described a token's granted tools as **optional** — and a client generated from it
    would type them as possibly-absent.

    That is the reassuring direction and the wrong one: *this token reaches nothing* and
    *the server did not say* are different answers, and only the first can ever occur.
    An empty list is the meaningful answer here, which is precisely why it has to be sent
    rather than defaulted.

    Asserted against the document rather than against the model, because the document is
    what a client is generated from and is the artefact the defaults were lying to.
    """
    row, _presented, _owner = machine
    client.get(f"/me/tokens/{row['id']}/reach", headers=auth)

    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    assert sorted(schemas["TokenReach"]["required"]) == [
        "acts_as_owner",
        "agents",
        "by_tool",
        "invalid_agents",
        "resolved_as",
        "token_id",
        "tools",
    ]
    assert sorted(schemas["ReachableAgent"]["required"]) == ["name", "scope", "tools"]

    # 069's four, held to the same rule. `SimulationRequest.arguments` is deliberately
    # not here: it is a *request* body where an absent key is a real state (*no
    # arguments*), which is the case a default is actually for.
    assert sorted(schemas["ToolReach"]["required"]) == [
        "effect",
        "granted_by",
        "resource_types",
        "tool",
    ]
    assert sorted(schemas["ToolReachGrant"]["required"]) == ["agent", "applies"]
    assert sorted(schemas["Simulation"]["required"]) == [
        "attributed_to",
        "considered",
        "not_checked",
        "reason",
        "rule",
        "tool",
        "verdict",
    ]
    assert sorted(schemas["ConsideredAgent"]["required"]) == [
        "agent",
        "allowed",
        "reason",
        "rule",
    ]


def test_reading_a_tokens_reach_needs_no_role_and_is_not_admin_surface(
    client, auth, registered, machine
):
    """**Step 035d decision 11, and it is a rule that fails silently in both directions.**

    `GET /me/tokens/{id}/reach` authorizes on `tokens.require_owner_or_admin` — *who owns
    this row* — which is deliberately not a role, for `GET /me/tokens`' reason: the person
    who needs it is a non-administrator looking at their own credential.

    So it must be **absent** from `deps.ADMIN_SURFACE`, and
    `test_every_admin_route_carries_the_dependency` would fail in its second direction if
    somebody added it there — a route carrying the dependency that nobody wrote down means
    a surface was closed without recording it. Asserted here from the outside too, because
    the set is a list a person edits and the behaviour is what a customer meets.
    """
    from carnet.api import deps

    row, _presented, _owner = machine

    assert client.get(f"/me/tokens/{row['id']}/reach", headers=auth).status_code == 200
    assert ("GET", "/me/tokens/{token_id}/reach") not in deps.ADMIN_SURFACE


# --- what a token has spent, step 035e ------------------------------------------------
#
# `GET /me/tokens/{id}/budget`. `mcp_budget` has been written on every admitted door call
# since migration 040 and read by nothing outside the suite; this is the reader.
#
# **These tests are memory-store only**, like every other route test in this file —
# `isolated_storage` is an `InMemoryStorage` and nothing parametrises it. The range read
# itself is pinned against real Postgres in `test_storage_contract.py`, and an edge pass
# over real HTTP is a separate step. Said here because 035d's edge pass found two things
# a green file like this one had never had the chance to see.


def _spend(token_id, count, *, day=None):
    """Admit `count` calls in a window, through the statement that enforces the ceiling."""
    from carnet import door, storage

    for _ in range(count):
        storage.active().spend_mcp_call(
            TEST_TENANT, token_id, day or door.budget_window(), ceiling=10_000
        )


def test_a_tokens_budget_reports_the_count_and_the_ceiling(
    client, auth, machine, monkeypatch
):
    """**A number without its limit is not an answer**, which is the whole reason the
    ceiling rides on the response rather than being something a browser is expected to
    know. It is also the one field here that is not a stored column: it is
    `config.MCP_CALLS_PER_DAY` on whichever replica answered."""
    from carnet import config

    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 1000)
    row, _presented, _owner = machine
    _spend(row["id"], 3)

    body = client.get(f"/me/tokens/{row['id']}/budget", headers=auth).json()

    assert body["token_id"] == row["id"]
    assert body["calls"] == 3
    assert body["ceiling"] == 1000
    assert body["metered"] is True


def test_the_ceiling_is_read_per_request_and_never_captured(
    client, auth, machine, monkeypatch
):
    """The dial is a knob an operator turns mid-incident — the contract suite's
    `test_a_lowered_ceiling_bites_immediately_and_a_raised_one_frees` is the same
    property one layer down. A page reporting a value captured at process start would
    disagree with the door within a minute of somebody turning it."""
    from carnet import config

    row, _presented, _owner = machine

    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 10)
    assert client.get(f"/me/tokens/{row['id']}/budget", headers=auth).json()["ceiling"] == 10

    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 25)
    assert client.get(f"/me/tokens/{row['id']}/budget", headers=auth).json()["ceiling"] == 25


def test_an_unmetered_deployment_says_so_rather_than_reporting_zero(
    client, auth, machine, monkeypatch
):
    """**Trap 1, and it is the one that makes a naive rendering actively wrong.**

    `TokenBudget.reserve` returns ALLOW *before touching storage* when the ceiling is not
    positive — an operator's explicit decision to run unmetered — so a token hammering
    the door all day on such a deployment has **no rows at all**. `calls: 0` there means
    *nothing was counted*, not *nothing happened*, and a page rendering `0 / 0` or a bar
    at 0% would say "this credential has barely been used" about the opposite.

    So `metered` is a field. The count is still reported honestly — the table is what it
    is — and this flag is what says whether today's entry in it is a measurement.
    """
    from carnet import config

    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 0)
    row, _presented, _owner = machine

    body = client.get(f"/me/tokens/{row['id']}/budget", headers=auth).json()

    assert body["metered"] is False
    assert body["ceiling"] == 0


def test_a_negative_ceiling_is_unmetered_too(client, auth, machine, monkeypatch):
    """`reserve` compares `<= 0`, not `== 0` — `RUNS_PER_HOUR`'s convention, and
    `test_door.py` already drives `-5` through the door itself. A second reader writing
    the obvious equality would report `metered: true` with a ceiling of -5 and render a
    count of nothing as a count of calls, so the predicate has one home
    (`TokenBudget.metered`) and this is it seen from outside."""
    from carnet import config

    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", -5)
    row, _presented, _owner = machine

    assert client.get(
        f"/me/tokens/{row['id']}/budget", headers=auth
    ).json()["metered"] is False


def test_turning_the_dial_off_does_not_delete_what_was_already_counted(
    client, auth, machine, monkeypatch
):
    """The second-order fact, and it decides how the page renders history: nothing is
    deleted when the meter stops. A deployment that ran metered until Tuesday keeps
    Monday's rows, so `history` can be genuinely non-empty while `metered` is false."""
    from datetime import timedelta

    from carnet import config, door

    row, _presented, _owner = machine
    _spend(row["id"], 4, day=door.budget_window() - timedelta(days=2))

    monkeypatch.setattr(config, "MCP_CALLS_PER_DAY", 0)
    body = client.get(f"/me/tokens/{row['id']}/budget", headers=auth).json()

    assert body["metered"] is False
    assert [w["calls"] for w in body["history"]] == [0, 0, 0, 0, 4, 0, 0]


def test_the_history_is_seven_dense_windows_ending_today(client, auth, machine):
    """**Dense, and the fill is a rule that already exists.**

    `mcp_call_windows` is sparse — it reports the table. A window with no row *is* zero
    by `mcp_calls_spent`'s own documented contract, so the route filling gaps applies a
    semantic with a home rather than inventing a fact; and the alternative is a browser
    doing the same fill, which would be a second implementation of it. A sparse list also
    makes a page guess whether a gap is *no calls* or *no answer*, and those differ.
    """
    from datetime import timedelta

    from carnet import door

    row, _presented, _owner = machine
    today = door.budget_window()
    _spend(row["id"], 2, day=today - timedelta(days=6))
    _spend(row["id"], 5, day=today - timedelta(days=3))
    _spend(row["id"], 1)

    body = client.get(f"/me/tokens/{row['id']}/budget", headers=auth).json()

    assert [w["calls"] for w in body["history"]] == [2, 0, 0, 5, 0, 0, 1]
    assert [w["window_start"] for w in body["history"]] == [
        (today - timedelta(days=offset)).isoformat() for offset in range(6, -1, -1)
    ]
    # Oldest first, and today is last — the ordering rule every log reader here shares.
    assert body["window"] == today.isoformat()


def test_the_window_and_the_last_history_entry_cannot_disagree(client, auth, machine):
    """One lookup, used twice. A page reads `calls` for its figure and `history` for its
    table, and a reader who saw 41 in one and 40 in the other would have no way to tell
    which was the answer."""
    row, _presented, _owner = machine
    _spend(row["id"], 6)

    body = client.get(f"/me/tokens/{row['id']}/budget", headers=auth).json()

    assert body["history"][-1] == {"window_start": body["window"], "calls": body["calls"]}


def test_a_window_older_than_the_history_is_not_reported(client, auth, machine):
    """The range is bounded and the row is left where it is. Migration 040 keeps past
    windows deliberately — *"the only record of what a credential has been doing"* — so
    this asserts the read is narrow, not that the table forgot."""
    from datetime import timedelta

    from carnet import door, storage

    row, _presented, _owner = machine
    old = door.budget_window() - timedelta(days=30)
    _spend(row["id"], 9, day=old)

    body = client.get(f"/me/tokens/{row['id']}/budget", headers=auth).json()

    assert [w["calls"] for w in body["history"]] == [0] * 7
    assert storage.active().mcp_calls_spent(TEST_TENANT, row["id"], old) == 9


def test_a_token_that_has_spent_nothing_answers_zeroes_rather_than_refusing(
    client, auth, machine
):
    """An answer, not an empty state. *This token has admitted no calls* is a true and
    complete answer — and it is the answer a freshly minted credential has, so a route
    that 404'd here would refuse the most common case."""
    row, _presented, _owner = machine

    body = client.get(f"/me/tokens/{row['id']}/budget", headers=auth).json()

    assert body["calls"] == 0
    assert [w["calls"] for w in body["history"]] == [0] * 7


def test_a_revoked_token_still_reports_what_it_spent(client, auth, machine):
    """Liveness is not this route's, exactly as it is not `reach`'s. *What was that
    credential spending before I killed it* is asked **after** a revocation, so a route
    that refused a revoked token would be empty for precisely the reader who came for
    it — and "refused" would read as "it spent nothing"."""
    from carnet import storage

    row, _presented, _owner = machine
    _spend(row["id"], 7)
    storage.active().revoke_api_token(TEST_TENANT, row["id"], actor="system:cli")

    body = client.get(f"/me/tokens/{row['id']}/budget", headers=auth)

    assert body.status_code == 200
    assert body.json()["calls"] == 7


def test_reading_a_budget_does_not_stamp_the_token_as_used(client, auth, machine):
    """035d's property at a new address, and it matters for the same reason: an
    offboarding review that moved `last_used_at` by being conducted would corrupt the one
    question only that column answers. `require_owner_or_admin` calls `find_api_token`
    and stops — it never resolves the credential — so this holds by omission and this
    test is what keeps it holding."""
    row, _presented, _owner = machine

    before = client.get("/me/tokens", headers=auth).json()[0]["last_used_at"]
    for _ in range(3):
        client.get(f"/me/tokens/{row['id']}/budget", headers=auth)

    assert client.get("/me/tokens", headers=auth).json()[0]["last_used_at"] == before


def test_a_budget_for_a_token_this_customer_does_not_have_is_400(client, auth, machine):
    """`ValueRefused` → 400, not 503 and not 404. A mistyped id is the caller's, and the
    wrong refusal family sends somebody to read logs about an outage that did not
    happen — 021's lesson, and `require_owner_or_admin`'s own sentence unmodified."""
    response = client.get("/me/tokens/m_nosuchtoken/budget", headers=auth)

    assert response.status_code == 400
    assert "m_nosuchtoken" in response.json()["detail"]


def test_a_colleagues_budget_is_refused_as_a_missing_token(
    client, auth, registered, machine
):
    """Somebody else's credential, refused in the sentence a token that does not exist
    gets — the same sentence the schedule, trigger and reach surfaces answer with,
    because it is the same function (069)."""
    row, _presented, owner = machine
    stranger = {
        "Authorization": f"Bearer {registered.token(sub='00u-p', email='p@acme.com')}"
    }

    response = client.get(f"/me/tokens/{row['id']}/budget", headers=stranger)
    invented = client.get("/me/tokens/m_000000000000/budget", headers=stranger)

    assert response.status_code == invented.status_code == 400
    assert owner not in response.json()["detail"]
    assert response.json()["detail"].replace(row["id"], "X") == invented.json()[
        "detail"
    ].replace("m_000000000000", "X")


def test_an_administrator_may_read_somebody_elses_budget(
    client, auth, registered, machine
):
    """The admin half of `require_owner_or_admin`, and 035d's build pass found the
    argument for keeping it: a disabled person's session is refused at `api/deps.py` long
    before this route, so once somebody is offboarded this is the **only** way the answer
    can be read at all — and *what was that credential spending* is an offboarding
    question by construction.

    A **different** person with the role, not `auth` granted it: the point is that the
    reader does not own the row.
    """
    row, _presented, _owner = machine
    _spend(row["id"], 2)
    boss = {
        "Authorization": f"Bearer {registered.token(sub='00u-adm', email='adm@acme.com')}"
    }
    storage.active().grant_platform_role(
        TEST_TENANT, "user", logged_in_id(client, boss), "admin", actor="system:cli"
    )

    body = client.get(f"/me/tokens/{row['id']}/budget", headers=boss)

    assert body.status_code == 200
    assert body.json()["calls"] == 2


def test_reading_a_budget_needs_no_role_and_is_not_admin_surface(
    client, auth, registered, machine
):
    """Decision 8, and `ADMIN_SURFACE` is **checked rather than edited**.

    This route authorizes on who owns the row, which is deliberately not a role — so it
    must be absent from the set, and `test_every_admin_route_carries_the_dependency`
    would fail in its second direction if somebody added it. That makes three routes
    under `/me/tokens` deliberately outside the administrative surface.
    """
    from carnet.api import deps

    row, _presented, _owner = machine

    assert client.get(f"/me/tokens/{row['id']}/budget", headers=auth).status_code == 200
    assert ("GET", "/me/tokens/{token_id}/budget") not in deps.ADMIN_SURFACE


def _door_spend_row(token_id, *, model="claude-opus-5", input_tokens=1_000_000):
    """One door call that reported usage, written straight into `audit`.

    Through `append_audit` rather than through the broker: what these tests are about is
    the *route's* arithmetic, and driving a real MCP call to get one row would make a
    failure here say "the door is broken" rather than "the budget page is wrong".
    """
    from datetime import datetime, timezone

    from carnet import storage
    from carnet.storage import DOOR_CALL_ID_PREFIX

    storage.active().append_audit(
        TEST_TENANT,
        {
            "v": 7,
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "run_id": f"{DOOR_CALL_ID_PREFIX}0123456789ab",
            "principal_kind": "machine",
            "principal_id": token_id,
            "agent": "triage",
            "tool": "example_answer",
            "effect": "read",
            "args": {},
            "decision": "allow",
            "outcome": "ok",
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": 0,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
        },
    )


def test_a_tokens_budget_reports_what_it_spent_beside_what_it_may(
    client, auth, machine, monkeypatch
):
    """Step 045b. **A number without its limit is not an answer**, applied to the money —
    the same rule that put `ceiling` beside `calls` when this route was built.

    A million Opus input tokens is $15.00 at the built-in rate table, which is what makes
    this a figure somebody can check by hand.
    """
    from carnet import config

    monkeypatch.setattr(config, "MCP_USD_PER_DAY", 100.0)
    monkeypatch.setattr(config, "MCP_TOKENS_PER_DAY", 5_000_000)
    row, _presented, _owner = machine
    _door_spend_row(row["id"])

    body = client.get(f"/me/tokens/{row['id']}/budget", headers=auth).json()

    assert body["usd"] == 15.0
    assert body["usd_ceiling"] == 100.0
    assert body["usd_metered"] is True
    assert body["tokens"] == 1_000_000
    assert body["tokens_ceiling"] == 5_000_000
    assert body["tokens_metered"] is True
    assert body["unpriced_models"] == []


def test_the_two_money_dials_are_metered_independently(client, auth, machine, monkeypatch):
    """Two flags rather than one, because the two dials are independent: a deployment that
    bounds tokens without pricing anything — which is every deployment brokering a
    provider `core/usage.RATES` has never heard of — has an honest $0 under a live token
    ceiling, and a single flag would have to lie about one of them."""
    from carnet import config

    monkeypatch.setattr(config, "MCP_USD_PER_DAY", 0.0)
    monkeypatch.setattr(config, "MCP_TOKENS_PER_DAY", 5_000_000)
    row, _presented, _owner = machine

    body = client.get(f"/me/tokens/{row['id']}/budget", headers=auth).json()

    assert body["usd_metered"] is False
    assert body["tokens_metered"] is True


def test_a_negative_money_dial_reads_as_unmetered(client, auth, machine, monkeypatch):
    """`<= 0`, not `== 0` — `metered`'s whole reason for being a named expression. A
    reader writing the obvious equality would render `-1` as a live ceiling of zero."""
    from carnet import config

    monkeypatch.setattr(config, "MCP_USD_PER_DAY", -1.0)
    row, _presented, _owner = machine

    assert client.get(
        f"/me/tokens/{row['id']}/budget", headers=auth
    ).json()["usd_metered"] is False


def test_an_unpriced_model_is_named_rather_than_counted_as_free(
    client, auth, machine, monkeypatch
):
    """`cost_of`'s honesty on the wire. `estimate_cost` returns None for a model with no
    rate, so its tokens cost `$0.00` however many there are — a figure that excluded two of
    three models in play and said nothing would be read as whole."""
    from carnet import config

    monkeypatch.setattr(config, "MCP_USD_PER_DAY", 100.0)
    row, _presented, _owner = machine
    _door_spend_row(row["id"], model="llama-3-70b")

    body = client.get(f"/me/tokens/{row['id']}/budget", headers=auth).json()

    assert body["usd"] == 0.0
    assert body["tokens"] == 1_000_000
    assert body["unpriced_models"] == ["llama-3-70b"]


def test_a_budget_page_reports_zero_money_rather_than_nothing(client, auth, machine):
    """The ordinary state of every deployment today: nothing reports usage. `$0` beside
    the ceiling is legible; an absent field would make a client guess whether the server
    had failed to answer."""
    row, _presented, _owner = machine

    body = client.get(f"/me/tokens/{row['id']}/budget", headers=auth).json()

    assert body["usd"] == 0.0
    assert body["tokens"] == 0
    assert body["unpriced_models"] == []


def test_a_tokens_money_is_its_own_and_not_a_colleagues(client, auth, machine, registered):
    """The scope clause the ceiling rests on, read from the route rather than the store: a
    figure that summed another credential's spend would refuse somebody for traffic they
    never made."""
    from carnet.access import tokens as tokens_module

    row, _presented, owner = machine
    other, _ = tokens_module.mint(TEST_TENANT, "other-bot", owner, actor="system:cli")

    _door_spend_row(row["id"], input_tokens=1_000_000)
    _door_spend_row(other["id"], input_tokens=9_000_000)

    mine = client.get(f"/me/tokens/{row['id']}/budget", headers=auth).json()
    theirs = client.get(f"/me/tokens/{other['id']}/budget", headers=auth).json()

    assert mine["tokens"] == 1_000_000
    assert theirs["tokens"] == 9_000_000


def test_the_budget_response_declares_every_field_as_required(client, auth, machine):
    """035c's rule, which 035d broke on five fields and its edge pass caught in the
    OpenAPI `required` set rather than in the model.

    Every key here is supplied unconditionally by the route, so a `default_factory` would
    describe a state that cannot arise and would type a generated client's `history` as
    possibly-absent. And the direction of that lie is the reassuring one: *this token
    spent nothing* and *the server did not say* are different answers, and only the first
    can occur — which is exactly why an empty week has to be **sent**.

    Asserted against the document, because the document is what a client is generated
    from and the artefact a default lies to.
    """
    row, _presented, _owner = machine
    client.get(f"/me/tokens/{row['id']}/budget", headers=auth)

    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    assert sorted(schemas["TokenSpend"]["required"]) == [
        "calls",
        "ceiling",
        "history",
        "metered",
        "token_id",
        # 045b's money fields, held to the same rule: the route supplies every one
        # unconditionally, so a default would describe a state that cannot arise.
        # `unpriced_models` most of all — an empty list is *nothing was unpriced*, and an
        # absent key would let a client read that as *the server did not say*.
        "tokens",
        "tokens_ceiling",
        "tokens_metered",
        "unpriced_models",
        "usd",
        "usd_ceiling",
        "usd_metered",
        "window",
    ]
    assert sorted(schemas["SpentWindow"]["required"]) == ["calls", "window_start"]


def test_listing_tokens_needs_no_role(client, auth, registered, machine):
    """**Deliberately not admin-gated**, which is `/me`'s reasoning: the person who needs
    this is a non-administrator picking among their own tokens, and an admin-gated route
    would be useless to exactly them. The register's `GET /admin/tokens` — everyone's
    tokens, for an operations team — stays open and unbuilt."""
    plain = {
        "Authorization": f"Bearer {registered.token(sub='00u-p', email='p@acme.com')}"
    }

    assert client.get("/me/tokens", headers=plain).status_code == 200
    assert client.get("/admin-audit", headers=plain).status_code == 403


def test_an_agent_config_a_column_cannot_hold_is_400_not_503(client, auth, demo_agent):
    """**Wider than schedules, and found while building them.**

    `check_config_is_storable` guards all six config write paths and raised the family
    that means *the database is broken*. A person pasting a prompt with a stray NUL was
    told to try again later, forever. Pinned here because the fix reaches a route that
    022b did not otherwise touch.
    """
    response = client.patch(
        f"/agents/{AGENT['name']}",
        json={"system": "you are\x00 a demo agent"},
        headers={**auth, "If-Match": client.get(
            f"/agents/{AGENT['name']}", headers=auth
        ).headers["ETag"]},
    )

    assert response.status_code == 400


def test_a_config_KEY_a_column_cannot_hold_is_400_not_503(client, auth, demo_agent):
    """**The same rule, at the half of the walk that never ran.** 035i's edge pass.

    `check_config_is_storable` says *a NUL, or a lone surrogate, in any string* and a dict
    key is a string — but the walk descended into values only, so a NUL in a **key** went
    straight to Postgres and came back a 503 about a request that will never work. The
    wrong refusal family, at the one function written to prevent exactly it.

    It was unreachable until 035i for a reason worth keeping: **no config key had ever come
    from a person.** Every key in every config was written by the code. `output.schema`'s
    `properties` are keys, the browser's schema control is a textarea, and `"\u0000"` is
    four characters somebody can paste out of a document they were given — so the hole
    stopped being theoretical the moment there was a box.
    """
    response = client.patch(
        f"/agents/{AGENT['name']}",
        json={
            "output": {
                "schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {"a\x00b": {"type": "string"}},
                }
            }
        },
        headers={**auth, "If-Match": client.get(
            f"/agents/{AGENT['name']}", headers=auth
        ).headers["ETag"]},
    )

    assert response.status_code == 400
    # The sentence names where, which is what makes it fixable rather than merely refused.
    assert "<key>" in response.json()["detail"]


def test_a_machine_whose_id_collides_with_a_persons_still_owns_nothing(
    client, machine_auth, machine
):
    """**Found by a mutation that survived**, and it is the case `_is_owner`'s comment
    names: ids are minted per population, so nothing guarantees a machine's can never
    equal a person's. Dropping the `kind` check looked harmless because no token is ever
    owned by a machine — until the two id spaces touch.
    """
    row, _presented, _owner = machine
    from carnet.access import tokens

    # A person whose id is this machine's id, owning a token of their own.
    storage.active().create_user(
        TEST_TENANT,
        {
            "id": row["id"],
            "issuer": ISSUER,
            "subject": "s-collide",
            "email": "collide@acme.com",
            "display_name": "Collide",
        },
    )
    tokens.mint(TEST_TENANT, "theirs", row["id"], actor="system:cli")

    assert client.get("/me/tokens", headers=machine_auth).json() == []


# --- triggers over HTTP, step 023b ----------------------------------------------------
#
# The browser half of the door. The same two gates as schedules — the agent's grant and
# the token's owner — plus the one thing no other surface in this app does: it returns a
# secret. The tests below are arranged around proving that the secret appears exactly
# once and that the *sealed* one never appears at all.


def _post_trigger(client, headers, token_id, agent=AGENT["name"], **overrides):
    body = {
        "name": "github-issues",
        "task": "triage the issue below",
        "token_id": token_id,
    }
    body.update(overrides)
    return client.post(f"/agents/{agent}/triggers", json=body, headers=headers)


def test_creating_a_trigger_needs_a_grant_and_an_absent_agent_is_the_same_404(
    client, auth, unshared_agent, machine
):
    """The route's visibility floor, 022b's argument at a second surface: the module can
    name an absent agent out loud because by then the caller is established as the
    token's owner, and over HTTP nobody is established as anything until the grant check
    runs."""
    row, _presented, _owner = machine

    ungranted = _post_trigger(client, auth, row["id"])
    storage.active().delete_agent(TEST_TENANT, AGENT["name"], actor="system:cli")
    absent = _post_trigger(client, auth, row["id"])

    assert ungranted.status_code == 404
    assert absent.status_code == 404
    assert ungranted.json() == absent.json()


# --- the sixth wrong refusal family, found by driving 023b's routes -------------------


# --- the reserved key namespace, found by driving POST /runs after 023b ---------------
#
# 023b made trigger ids readable over HTTP, which is what turned a collision the plan had
# already answered into an attack it had not. The plan's edge table says *"a person types
# a `trig:`-prefixed idempotency key → the existing 409"*, which is the right answer to
# the accident. Done on purpose by somebody who can read the id, the same act takes the
# key a delivery was going to use — and `runs_idempotency` never expires.


# --- the output section over HTTP (step 024) ---------------------------------------
#
# The schema's authoring surfaces are PATCH and `--seed`; the form is deliberately not
# one. What these pin: the section round-trips spelled `schema` (the pydantic field is
# aliased — an internal name leaking into a row would be a stored artifact of an
# implementation wrinkle), the validator's sentences arrive as 422s, and the type
# layer refuses shapes before policy is even asked.


OUTPUT_SECTION = {
    "schema": {
        "type": "object",
        "properties": {"n": {"type": "integer"}},
        "required": ["n"],
        "additionalProperties": False,
    }
}


def test_an_output_section_round_trips_spelled_schema(client, auth, demo_agent):
    response = _patch(client, auth, "demo", {"output": OUTPUT_SECTION})

    assert response.status_code == 200, response.text
    stored = storage.active().get_agent(TEST_TENANT, "demo")["config"]
    assert stored["output"] == OUTPUT_SECTION
    assert "json_schema" not in stored["output"], "the alias leaked"

    read = client.get("/agents/demo", headers=auth)
    assert read.json()["config"]["output"] == OUTPUT_SECTION


def test_a_bad_schema_is_422_with_the_validators_sentence(client, auth, demo_agent):
    response = _patch(
        client, auth, "demo",
        {"output": {"schema": {"type": "object", "properties": {}}}},
    )

    assert response.status_code == 422
    assert "additionalProperties" in response.json()["detail"]
    assert "output" not in storage.active().get_agent(TEST_TENANT, "demo")["config"]


def test_output_null_over_http_is_422_not_a_removal(client, auth, demo_agent):
    """The standing merge cost, refused loudly: a top-level key cannot be removed over
    HTTP, and a null that quietly stored would be a key that means nothing."""
    ok = _patch(client, auth, "demo", {"output": OUTPUT_SECTION})
    assert ok.status_code == 200, ok.text

    refused = _patch(client, auth, "demo", {"output": None})

    assert refused.status_code == 422
    assert "output is null" in refused.json()["detail"]
    stored = storage.active().get_agent(TEST_TENANT, "demo")["config"]
    assert stored["output"] == OUTPUT_SECTION, "the null must write nothing"


def test_an_unknown_key_inside_output_is_type_refused(client, auth, demo_agent):
    """`extra="forbid"`'s layer, not the validator's: a typo'd key is refused as a
    shape before policy is asked, `AgentDraft`'s own argument one model up."""
    response = _patch(client, auth, "demo", {"output": {"shcema": {}}})

    assert response.status_code == 422


def test_a_degenerately_deep_schema_is_a_caller_error_not_a_500(client, auth, demo_agent):
    """FastAPI's parser accepts bodies far deeper than Python's recursion limit, so
    the recursive schema checks used to blow up *after* type validation — a 500
    answered to caller-typed input, the wrong refusal family, found in 024's own new
    code before it shipped a copy.

    **Two depths, because "far deeper than the recursion limit" is interpreter-specific
    and the claim is not.** This was one case at depth 3000 and it was wrong twice on
    the oldest supported interpreter: `json.dumps` of a 3000-deep dict raises
    `RecursionError` in the *client*, so on 3.10 the request was never sent and the
    failure had nothing to do with the server; and had it been sent, 3.10's body parser
    refuses that depth itself with a 400 before the app sees it, where 3.12+ hands it
    straight through. Found by running CI, which had not run on this repository for
    long enough that the case had never executed on 3.10 at all.

    So the body is assembled as text rather than encoded from a dict, and the two
    halves are asserted separately: the guard is pinned at a depth every interpreter
    delivers to the app, and the degenerate depth is pinned to what the title actually
    claims — some caller error, never a 500.
    """
    def nested(depth: int) -> str:
        leaf = '{"type": "object", "additionalProperties": false}'
        opener = '{"type": "object", "additionalProperties": false, "properties": {"x": '
        return opener * depth + leaf + "}}" * depth

    def patch_schema(schema: str):
        etag = _open(client, auth, "demo")["updated_at"]
        return client.patch(
            "/agents/demo",
            content='{"output": {"schema": ' + schema + "}}",
            headers={**auth, "If-Match": f'"{etag}"', "Content-Type": "application/json"},
        )

    # Past the recursive checks — they spend several frames per level, so the limit is
    # reached long before the depth suggests — and shallow enough that every supported
    # interpreter's parser hands it to the app, which is where the guard lives.
    guarded = patch_schema(nested(100))
    assert guarded.status_code == 422
    assert "nested too deeply" in guarded.json()["detail"]

    # And the degenerate case the name is about. Whichever layer refuses it, the
    # refusal belongs to the caller: 422 from the guard where the parser passes it
    # along, 400 from the parser where it does not, and never a 5xx either way.
    degenerate = patch_schema(nested(3000))
    assert 400 <= degenerate.status_code < 500, degenerate.text

    assert "output" not in storage.active().get_agent(TEST_TENANT, "demo")["config"]


def test_an_outward_ref_is_422_with_the_fix_in_the_sentence(client, auth, demo_agent):
    response = _patch(client, auth, "demo", {"output": {"schema": {
        "type": "object", "additionalProperties": False,
        "properties": {"x": {"$ref": "https://nowhere.invalid/s.json"}},
    }}})

    assert response.status_code == 422
    assert "refers outside itself" in response.json()["detail"]


def test_the_internal_field_name_is_not_a_second_wire_spelling(client, auth, demo_agent):
    """Found by sending it: with `populate_by_name` the aliased field's internal name
    (`json_schema`) was quietly accepted as a synonym for `schema`. One key, one
    spelling — the extra-forbid layer now refuses it like any other unknown key."""
    response = _patch(
        client, auth, "demo",
        {"output": {"json_schema": {"type": "object", "additionalProperties": False}}},
    )

    assert response.status_code == 422


def test_creating_an_agent_with_an_output_section(client, auth):
    """The create route, not just PATCH: `AgentDraft` carries the field, the config
    stores it spelled `schema`, and the whole arc — create, read back — works before
    any edit exists."""
    draft = {
        "name": "born-structured",
        "system": "You extract fields.",
        "runtime": "simple",
        "permissions": {"tools": [], "scope": {}},
        "output": OUTPUT_SECTION,
    }

    created = client.post("/agents", json=draft, headers=auth)

    assert created.status_code == 201, created.text
    stored = storage.active().get_agent(TEST_TENANT, "born-structured")["config"]
    assert stored["output"] == OUTPUT_SECTION


def test_the_dry_run_answers_for_output_sections(client, auth):
    """`POST /agents/validate` runs the same validator, so the wizard's dry run and
    the create cannot develop two opinions about a schema — a good section is
    `valid: true`, a bad one is the same 422 sentence the create would give."""
    base = {
        "name": "dry-run",
        "system": "s",
        "runtime": "simple",
        "permissions": {"tools": [], "scope": {}},
    }

    good = client.post(
        "/agents/validate", json={**base, "output": OUTPUT_SECTION}, headers=auth
    )
    assert good.status_code == 200, good.text
    assert good.json()["valid"] is True

    bad = client.post(
        "/agents/validate",
        json={**base, "output": {"schema": {"type": "object", "properties": {}}}},
        headers=auth,
    )
    assert bad.status_code == 422
    assert "additionalProperties" in bad.json()["detail"]


def test_the_openapi_document_advertises_one_spelling(client):
    """The spec is what a client generator reads — if it advertised the aliased
    field's internal name, generated clients would send `json_schema` and meet 422s.
    The only place the internal name may appear is the prose description that
    explains the alias."""
    component = client.get("/openapi.json").json()["components"]["schemas"]["AgentOutput"]

    assert sorted(component["properties"]) == ["schema"]
    assert component["required"] == ["schema"]


# --- step 028: a file with a task -----------------------------------------------------
#
# Two requests. `POST /files` stores the bytes against whoever uploaded them and answers
# with an id; `POST /runs` names that id. The rejected alternative put the file on the run
# in one request — no id, and reuse across runs unrepresentable rather than refused. The
# id is what buys upload-once-retry-many, and its cost is that "who may use this file"
# becomes a check rather than a property of the schema. These are that check.

PDF_BYTES = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"


def upload(client, headers, *, filename="notes.txt", media_type="text/plain",
           content=b"hello world"):
    return client.post(
        "/files",
        files={"file": (filename, content, media_type)},
        headers=headers,
    )


# --- the ownership rule, which is what the id costs ----------------------------------


# --- what the upload door refuses ----------------------------------------------------


# --- idempotency, now keyed on the id ------------------------------------------------


# --- step 029: the tenant scope seam ---------------------------------------------


def test_an_authenticated_request_is_scoped_to_its_principals_tenant(
    client, auth, monkeypatch
):
    """The whole 029 seam in one request: the middleware installs the cell on the
    event loop, `principal_from_request` fills it in from one threadpool copy, and the
    endpoint's storage calls — a different threadpool copy — see it. Asserted inside a
    storage method, because that is where `_connection()` would read it; if this scope
    were None, Postgres would serve the request unscoped and nothing would say so."""
    from carnet.storage import InMemoryStorage, tenancy

    observed = []
    original = InMemoryStorage.load_agents

    def spy(self, tenant_id):
        observed.append((tenancy.current_tenant(), tenant_id))
        return original(self, tenant_id)

    monkeypatch.setattr(InMemoryStorage, "load_agents", spy)
    response = client.get("/agents", headers=auth)

    assert response.status_code == 200, response.text
    assert observed, "GET /agents stopped calling load_agents — spy on what it does call"
    for scope, asked in observed:
        assert scope == TEST_TENANT
        assert asked == TEST_TENANT




# --- 070: a credential the platform does not hold ------------------------------------


def test_a_connector_can_be_registered_with_a_vault_reference(
    client, auth, admin, admin_host
):
    """The form's half of step 070. The reference is a **location**, so unlike a header
    value there is nothing sealed on either side of it — it goes out on the detail
    response exactly as `credential_env` does."""
    created = client.post(
        "/admin/connectors",
        json={
            "connector_id": "vaulted",
            "url": f"https://{admin_host}/mcp",
            "credential_ref": "op://Engineering/Jira/credential",
            "description": "held in the customer's own vault",
        },
        headers=auth,
    )
    assert created.status_code == 201, created.json()

    detail = client.get("/admin/connectors/vaulted", headers=auth).json()
    assert detail["credential_ref"] == "op://Engineering/Jira/credential"
    assert detail["credential_env"] == ""

    listed = client.get("/admin/connectors", headers=auth).json()
    row = next(r for r in listed if r["connector_id"] == "vaulted")
    assert row["credential_ref"] == "op://Engineering/Jira/credential"


@pytest.fixture
def vaulted_jira(client, auth, admin, admin_host, monkeypatch):
    """A connector whose shared credential is a vault reference, with the vault answering
    a known value — `core/vault.resolve` patched rather than a Connect stub, because what
    these tests assert is that the *route* hands the reference on, and the resolver has
    its own suite."""
    from carnet.core import credentials  # noqa: PLC0415

    monkeypatch.setattr(credentials.vault, "resolve", lambda pointer: "from-the-vault")
    created = client.post(
        "/admin/connectors",
        json={
            "connector_id": "jira",
            "url": f"https://{admin_host}/mcp",
            "credential_ref": "op://Engineering/Jira/credential",
        },
        headers=auth,
    )
    assert created.status_code == 201, created.json()
    return "jira"


@pytest.fixture
def looking_with(monkeypatch):
    """`fake_server` with the credential it was handed kept, because that is the fact
    under test here and `fake_server` deliberately discards it."""
    from test_registration import FakeServer  # noqa: PLC0415

    seen = []
    server = FakeServer()

    def transport(tenant, connector, credential):
        seen.append(credential)
        return server

    monkeypatch.setattr(mcp.discovery, "_transport_for", transport)
    return seen


def test_discovery_looks_with_the_vault_credential(
    client, auth, vaulted_jira, looking_with
):
    """070's first draft passed only `credential_env` from this route, so a connector
    registered with a reference was discovered **unauthenticated** from the screen while
    `--discover` resolved the pointer — two answers for one connector, and the browser's
    was the empty one. The route now hands on both halves, as the CLI does."""
    response = client.post("/admin/connectors/jira/discovery", headers=auth)

    assert response.status_code == 200, response.json()
    assert looking_with == ["from-the-vault"]


def test_vetting_looks_with_the_vault_credential(
    client, auth, vaulted_jira, looking_with
):
    response = client.put(
        "/admin/connectors/jira/tools/search_issues",
        json={"effect": "read"},
        headers=auth,
    )

    assert response.status_code in (200, 201), response.json()
    assert looking_with == ["from-the-vault"]


def test_a_broken_recipe_file_cannot_fail_a_registration(
    client, auth, admin, admin_host, tmp_path, monkeypatch
):
    """Rule 1 of 068, at the one place the first draft broke it: `from_recipe` is a log
    line, and `recipes.load` raising on a malformed shipped file made that log line able
    to 500 a registration that was complete and correct. The hint is dropped, the row is
    written, and the audit record says nothing about a recipe."""
    from carnet.access import recipes  # noqa: PLC0415

    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(recipes, "RECIPES_DIR", tmp_path)

    created = client.post(
        "/admin/connectors",
        json={
            "connector_id": "jira",
            "url": f"https://{admin_host}/mcp",
            "credential_env": "JIRA_TOKEN",
            "from_recipe": "broken",
        },
        headers=auth,
    )

    assert created.status_code == 201, created.json()
    assert client.get("/admin/connectors/jira", headers=auth).status_code == 200


def test_a_malformed_reference_is_a_400_naming_the_syntax(client, auth, admin, admin_host):
    """Refused here as well as at the credential read. `core/vault` owns what a reference
    means and `tools/` may not import `core/`, so the friendly refusal lives at the entry
    points and the load-bearing one at the read."""
    refused = client.post(
        "/admin/connectors",
        json={
            "connector_id": "broken",
            "url": f"https://{admin_host}/mcp",
            "credential_ref": "op://Engineering/Jira",
        },
        headers=auth,
    )
    assert refused.status_code == 400
    assert "op://" in refused.json()["detail"]


def test_a_variable_and_a_reference_together_are_a_400(client, auth, admin, admin_host):
    refused = client.post(
        "/admin/connectors",
        json={
            "connector_id": "both",
            "url": f"https://{admin_host}/mcp",
            "credential_env": "JIRA_TOKEN",
            "credential_ref": "op://Engineering/Jira/credential",
        },
        headers=auth,
    )
    assert refused.status_code == 400
    assert "not both" in refused.json()["detail"]


def test_every_open_route_is_listed_and_argued():
    """Step 083. A route that authenticates nobody is a decision, and the list of them
    is `deps.OPEN_SURFACE` — compared in both directions, `ADMIN_SURFACE`'s device: an
    unlisted open route fails, and a listed route that grew a dependency fails too.

    The walk is recursive because a principal may arrive through a dependency of a
    dependency (`admin_from_request` depends on `principal_from_request`).
    """

    def calls(dependant):
        found = set()
        for dependency in dependant.dependencies:
            found.add(dependency.call)
            found |= calls(dependency)
        return found

    principals = {deps.principal_from_request, deps.admin_from_request}
    open_routes = set()
    for route in _our_routes():
        if not (calls(route.dependant) & principals):
            open_routes |= {(method, route.path) for method in (route.methods or set())}

    assert open_routes == deps.OPEN_SURFACE


def test_a_family_a_column_cannot_hold_is_400_not_503(
    client, auth, registered_jira, fake_server
):
    """**The oldest split in this register, checked at a position step 086 opened.**

    A NUL or a lone surrogate inside a family is a value a caller supplied and can fix,
    so it is a 400. Driven against both stores in 086's edge pass it was neither: the
    in-memory store took all three, and Postgres answered *"unsupported Unicode escape
    sequence"* as a `StorageError` — the 503 that means the database is broken, about a
    request that will never work. `check_config_is_storable` is the rule already written
    down one function away, and it now reaches the two caller-supplied string positions
    this step added inside a jsonb column.
    """
    response = client.put(
        "/admin/connectors/jira/tools/create_issue",
        json={
            "effect": "write",
            "resources": [
                {"type": "jira.project", "args": ["projectKey"], "families": ["hai\x00ku"]}
            ],
        },
        headers=auth,
    )

    assert response.status_code == 400
    assert "cannot be stored" in response.json()["detail"]

    # **The other half is asserted in-process**, and the sentence this comment first
    # carried — *unreachable over HTTP* — was wrong: `\ud800` is six ASCII bytes and a
    # legal JSON escape, and `json.loads` produces the surrogate from it (step 087). It
    # is not driven here because this client's `json=` refuses to encode one.
    from carnet.storage.base import ValueRefused

    with pytest.raises(ValueRefused, match="cannot be stored"):
        storage.active().vet_tool(
            TEST_TENANT,
            "jira",
            {
                "remote_name": "create_issue",
                "effect": "read",
                "resources": [
                    {"type": "jira.project", "args": ["projectKey"],
                     "families": ["hai\ud800ku"]}
                ],
            },
            actor="system:cli",
        )
