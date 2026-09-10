"""The door as an OAuth resource server, end to end through `TestClient`. Step 083.

The dance a real MCP client does — discover, register, be sent to consent, exchange —
driven against the in-memory store, and every refusal beside it. What this suite cannot
prove is the wire: `scripts/e2e_mcp_door.py` drives the same flow with the official
SDK's `OAuthClientProvider` against Postgres, and that is the ratification.

The tripwire is `test_the_only_grant_type_is_authorization_code`, on 020's pattern: the
plan argues that a PKCE-gated interactive mint is not the bearer-authenticated mint
`access/tokens.py` refuses, and the next person adding `client_credentials` should meet
a failing test rather than a docstring.
"""

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("fastapi", reason="install the 'api' extra to run these")
pytest.importorskip("jwt", reason="install the 'access' extra to run these")

from fastapi.testclient import TestClient  # noqa: E402

from carnet import config, storage  # noqa: E402
from carnet.storage import StorageError  # noqa: E402
from carnet.access import oauth_server  # noqa: E402
from carnet.api import create_app  # noqa: E402

from conftest import TEST_TENANT  # noqa: E402
from test_api import Idp, logged_in_id  # noqa: E402
from test_api import client as _client  # noqa: E402,F401
from test_api import registered as _registered  # noqa: E402,F401

PUBLIC = "https://carnet.acme.com/api"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"
LOOPBACK = "http://localhost:6274/oauth/callback"
CURSOR = "cursor://anysphere.cursor-retrieval/oauth/user-carnet/callback"

SDK_REGISTRATION = {
    "client_name": "Claude",
    "redirect_uris": [REDIRECT, LOOPBACK, CURSOR],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "client_uri": "https://claude.ai",
    "logo_uri": "https://claude.ai/logo.png",
}


@pytest.fixture(autouse=True)
def public_origin(monkeypatch):
    monkeypatch.setattr(config, "PUBLIC_ORIGIN", PUBLIC)


@pytest.fixture
def idp():
    return Idp()


registered = _registered
client = _client


@pytest.fixture
def auth(registered):
    return {"Authorization": f"Bearer {registered.token()}"}


@pytest.fixture
def sam(registered):
    return {"Authorization": f"Bearer {registered.token(sub='00u-sam', email='sam@acme.com')}"}


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


def register(client, **overrides):
    body = {**SDK_REGISTRATION, **overrides}
    response = client.post("/oauth/register", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def consent(client, headers, client_id, challenge, *, approve=True, **overrides):
    body = {
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "state": "xyz-123",
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": f"{PUBLIC}/mcp",
        "approve": approve,
    }
    body.update(overrides)
    return client.post("/oauth/consent", headers=headers, json=body)


def code_from(redirect_to):
    parts = urlsplit(redirect_to)
    query = parse_qs(parts.query)
    return query["code"][0], query


def exchange(client, client_id, code, verifier, **overrides):
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "resource": f"{PUBLIC}/mcp",
    }
    form.update(overrides)
    return client.post("/oauth/token", data=form)


def dance(client, headers, **registration):
    """Register, consent, exchange. Returns `(client_id, token_response)`."""
    reg = register(client, **registration)
    verifier, challenge = pkce()
    bounced = consent(client, headers, reg["client_id"], challenge)
    assert bounced.status_code == 200, bounced.text
    code, _ = code_from(bounced.json()["redirect_to"])
    return reg["client_id"], exchange(client, reg["client_id"], code, verifier)


# --- the documents and the challenge --------------------------------------------------


def test_the_two_documents_are_derived_from_the_public_origin(client):
    """RFC 9728 and RFC 8414, both open, both from the one setting this deployment
    already registers at every OAuth provider. The issuer is the bare origin, so the
    documents live at the origin root; the endpoints are under the API path."""
    resource = client.get("/.well-known/oauth-protected-resource")
    assert resource.status_code == 200
    assert resource.headers["cache-control"] == "no-store"
    assert resource.json() == {
        "resource": "https://carnet.acme.com/api/mcp",
        "authorization_servers": ["https://carnet.acme.com"],
        "bearer_methods_supported": ["header"],
        "resource_name": "Carnet MCP door",
    }
    # The path form the MCP specification has a client try first, and a stranger.
    assert client.get("/.well-known/oauth-protected-resource/api/mcp").json() == resource.json()
    assert client.get("/.well-known/oauth-protected-resource/somewhere/else").status_code == 404

    server = client.get("/.well-known/oauth-authorization-server")
    assert server.status_code == 200
    assert server.json() == {
        "issuer": "https://carnet.acme.com",
        "authorization_endpoint": "https://carnet.acme.com/oauth/authorize",
        "token_endpoint": "https://carnet.acme.com/api/oauth/token",
        "registration_endpoint": "https://carnet.acme.com/api/oauth/register",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }


def test_an_api_at_the_origin_root_puts_the_door_at_slash_mcp(client, monkeypatch):
    monkeypatch.setattr(config, "PUBLIC_ORIGIN", "https://door.example")
    assert client.get("/.well-known/oauth-protected-resource/mcp").status_code == 200
    assert client.get("/.well-known/oauth-protected-resource/api/mcp").status_code == 404
    assert oauth_server.endpoints()["resource"] == "https://door.example/mcp"
    assert oauth_server.endpoints()["token_endpoint"] == "https://door.example/oauth/token"


def test_an_unauthenticated_door_names_its_metadata(client, registered):
    """MCP 2025-06-18: a 401 from the resource **must** carry `WWW-Authenticate` naming
    the protected-resource metadata. Only at the door, only on a 401, and the
    `error=` the header already had is kept beside it."""
    where = 'resource_metadata="https://carnet.acme.com/.well-known/oauth-protected-resource/api/mcp"'

    nothing = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert nothing.status_code == 401
    assert nothing.headers["www-authenticate"] == f"Bearer {where}"

    garbage = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        headers={"Authorization": "Bearer art_m_nobody.nothing"},
    )
    assert garbage.status_code == 401
    assert garbage.headers["www-authenticate"] == f'Bearer error="invalid_token", {where}'

    # Every other route's 401 is exactly what it was.
    elsewhere = client.get("/agents")
    assert elsewhere.status_code == 401
    assert elsewhere.headers["www-authenticate"] == "Bearer"

    # And a person's own credential is still the 403 `require_machine` writes — a
    # client that followed the challenge and signed in as a person gets the sentence
    # that names the fix, not another challenge.
    person = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        headers={"Authorization": f"Bearer {registered.token()}"},
    )
    assert person.status_code == 403
    assert "www-authenticate" not in person.headers


def test_the_challenge_survives_a_root_path(registered):
    """The shipped front door runs uvicorn with `--root-path /api`, so the path a
    request carries is `/api/mcp`. Found red by `e2e_deploy.py`: the first version
    keyed the widening on `request.url.path == "/mcp"`."""
    deployed = TestClient(create_app(), root_path="/api")
    nothing = deployed.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert nothing.status_code == 401
    assert "resource_metadata=" in nothing.headers["www-authenticate"]
    elsewhere = deployed.get("/agents")
    assert elsewhere.headers["www-authenticate"] == "Bearer"


# --- registration ---------------------------------------------------------------------


def test_registration_is_public_clients_with_pkce_only(client):
    """RFC 7591, as the SDK sends it. What is recorded may differ from what was asked
    (§3.2.1): `refresh_token` is dropped and the response says so; a secret is never
    issued because none exists."""
    reg = register(client)
    assert reg["client_id"].startswith("oc_") and len(reg["client_id"]) == 19
    assert reg["client_name"] == "Claude"
    assert reg["redirect_uris"] == [REDIRECT, LOOPBACK, CURSOR]
    assert reg["grant_types"] == ["authorization_code"]
    assert reg["response_types"] == ["code"]
    assert reg["token_endpoint_auth_method"] == "none"
    assert reg["client_uri"] == "https://claude.ai"
    assert "client_secret" not in reg
    assert "logo_uri" not in reg, "a remote image on the consent page is a tracking pixel"
    assert isinstance(reg["client_id_issued_at"], int)

    # No credential is needed and the row is what the page will read.
    assert storage.active().find_oauth_client(reg["client_id"])["client_name"] == "Claude"


def test_a_registration_asking_for_a_bearer_shaped_grant_is_refused(client):
    """`client_credentials` is the mint for a bearer that 020 refused; a client secret is
    a second bearer-shaped credential. Both are refused at registration, so a client
    learns it there rather than at the exchange."""
    refused = client.post(
        "/oauth/register", json={**SDK_REGISTRATION, "grant_types": ["client_credentials"]}
    )
    assert refused.status_code == 400
    assert refused.json()["error"] == "invalid_client_metadata"
    assert "bearer" in refused.json()["error_description"]

    secret = client.post(
        "/oauth/register",
        json={**SDK_REGISTRATION, "token_endpoint_auth_method": "client_secret_basic"},
    )
    assert secret.status_code == 400
    assert secret.json()["error"] == "invalid_client_metadata"

    implicit = client.post("/oauth/register", json={**SDK_REGISTRATION, "response_types": ["token"]})
    assert implicit.status_code == 400


def test_a_redirect_uri_is_https_loopback_or_private_use(client):
    """RFC 8252's rule, and a short denylist for schemes a browser owns."""

    def attempt(uris):
        return client.post("/oauth/register", json={**SDK_REGISTRATION, "redirect_uris": uris})

    assert attempt(["http://evil.example/cb"]).json()["error"] == "invalid_redirect_uri"
    assert attempt(["http://127.0.0.1:9999/cb"]).status_code == 201
    assert attempt(["http://[::1]:9999/cb"]).status_code == 201
    assert attempt(["javascript:alert(1)"]).json()["error"] == "invalid_redirect_uri"
    assert attempt(["https://claude.ai/cb#frag"]).json()["error"] == "invalid_redirect_uri"
    assert attempt(["not a uri"]).json()["error"] == "invalid_redirect_uri"
    assert attempt([]).json()["error"] == "invalid_redirect_uri"
    assert attempt(["https://a.example/cb"] * 11).json()["error"] == "invalid_redirect_uri"
    assert attempt(["https://" + "a" * 3000]).json()["error"] == "invalid_redirect_uri"
    body = client.post("/oauth/register", json="nonsense")
    assert body.status_code in (400, 422)


def test_a_registration_body_is_bounded_before_it_is_parsed(client):
    """The one unauthenticated **write** this API has. The row it makes was bounded from
    the start; the request was not, so a stranger's script could post a hundred megabytes
    and have it parsed before a bound was consulted — the door's `MCP_MAX_CALL_BYTES`
    argument at a new address. Found in the testing pass."""
    from carnet.api.routes_oauth import MAX_REGISTRATION_BYTES

    huge = client.post(
        "/oauth/register",
        content=b'{"padding": "' + b"a" * (MAX_REGISTRATION_BYTES + 1) + b'"}',
        headers={"Content-Type": "application/json"},
    )
    assert huge.status_code == 400
    assert huge.json()["error"] == "invalid_client_metadata"
    assert "at most" in huge.json()["error_description"]

    # A legal registration is nowhere near the bound: ten 2 KiB URIs fit.
    legal = client.post(
        "/oauth/register",
        json={**SDK_REGISTRATION, "redirect_uris": [f"https://a.example/{'p' * 2000}/{n}" for n in range(10)]},
    )
    assert legal.status_code == 201


def test_a_malformed_registration_answers_in_the_rfcs_shape(client):
    """RFC 7591 §3.2.2, not FastAPI's 422 with a `detail` list — an OAuth client parses
    the former and has never read the latter."""
    for body in (b"not json", b"[]", b'"a string"', b"", b"null"):
        response = client.post(
            "/oauth/register", content=body, headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 400, body
        assert response.json()["error"] == "invalid_client_metadata", body


def test_a_lone_surrogate_in_a_registration_is_a_refusal_not_an_outage(client):
    """Step 087. The six ASCII bytes `\\ud800` are a legal JSON escape, and `json.loads`
    — which this route calls instead of a Pydantic model so it can answer in RFC 7591's
    shape — turns them into a string UTF-8 cannot encode. Driven against Postgres: in
    `client_name` the driver raised and the route answered **500**; in a `redirect_uri`
    or `client_uri` it was **503**. Both from an unauthenticated route. The register
    said this half of the storable rule was unreachable over HTTP; it was reachable
    from `curl`."""
    escape = '\\ud800'
    for body in (
        '{"client_name": "a%sb", "redirect_uris": ["https://a.example/cb"]}' % escape,
        '{"client_name": "ok", "redirect_uris": ["https://a.example/cb?q=%s"]}' % escape,
        '{"client_name": "ok", "redirect_uris": ["https://a.example/cb"], "client_uri": "https://x%s"}' % escape,
        '{"client_name": "ok", "redirect_uris": ["https://a.example/cb"], "%s": "x"}' % escape,
        '{"client_name": "ok", "redirect_uris": ["https://a.example/cb"], "software_id": ["%s"]}' % escape,
    ):
        response = client.post(
            "/oauth/register", content=body.encode("ascii"),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 400, body
        assert response.json()["error"] == "invalid_client_metadata", body
        assert "unpaired surrogate" in response.json()["error_description"], body
        assert response.text.isascii()

    # And the walk is the same one that refuses a NUL written as an escape.
    nul = client.post(
        "/oauth/register",
        content=b'{"client_name": "ok", "redirect_uris": ["https://a.example/cb\\u0000"]}',
        headers={"Content-Type": "application/json"},
    )
    assert nul.status_code == 400
    assert "NUL" in nul.json()["error_description"]


def test_a_lone_surrogate_at_the_token_endpoint_is_invalid_request(client, auth):
    """Step 087. The JSON form of the token request reaches `digest(code)` — which
    encodes the code before anything is looked up — and answered **500**. The form
    encoding was never affected: `parse_qsl` decodes with `errors="replace"`."""
    reg = register(client)
    verifier, challenge = pkce()
    code, _ = code_from(consent(client, auth, reg["client_id"], challenge).json()["redirect_to"])

    for field in ("code", "code_verifier", "client_id", "redirect_uri", "resource"):
        body = {
            "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
            "client_id": reg["client_id"], "redirect_uri": REDIRECT,
        }
        body[field] = "a\\ud800b"
        raw = "{" + ", ".join(f'"{k}": "{v}"' for k, v in body.items()) + "}"
        response = client.post(
            "/oauth/token", content=raw.encode("ascii"),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 400, field
        assert response.json()["error"] == "invalid_request", field
        assert "unpaired surrogate" in response.json()["error_description"], field

    # The code was never consumed by any of those: the honest exchange still works.
    assert exchange(client, reg["client_id"], code, verifier).status_code == 200

    # The form encoding of the same bytes is a plain mismatch, as it always was.
    formed = client.post(
        "/oauth/token",
        content=(
            f"grant_type=authorization_code&code=a%ED%A0%80b&code_verifier={verifier}"
            f"&client_id={reg['client_id']}"
        ).encode("ascii"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert formed.status_code == 400
    assert formed.json()["error"] == "invalid_grant"


def test_a_token_name_a_column_cannot_hold_is_refused_before_a_code_exists(client, auth):
    """Step 087. The other person-typed name in this flow. A NUL in `token_name` was a
    **503** from `oauth_codes` on Postgres, and the fake stored it; a line break stored
    fine and then broke the tokens page's list. Refused at consent — before the client
    is handed a code — with the RFC's error, which the page renders as the sentence.
    And the store refuses it on its own, so the fake is no more permissive than
    Postgres."""
    from carnet.storage import ValueRefused
    from carnet.storage.base import normalize_api_token, normalize_oauth_code

    reg = register(client)
    verifier, challenge = pkce()
    for name in ("bad\x00name", "line\nbreak", "bell\x07", "del\x7f"):
        response = consent(client, auth, reg["client_id"], challenge, token_name=name)
        assert response.status_code == 400, repr(name)
        assert response.json()["error"] == "invalid_request", repr(name)
        assert "control characters" in response.json()["error_description"], repr(name)
    # No code was issued and nothing was minted.
    assert client.get("/me/tokens", headers=auth).json() == []

    # The surrogate is refused one layer up, by Pydantic, and the 422 that says so is
    # a 422 — it used to die rendering the offending input and answer 500.
    surrogate = client.post(
        "/oauth/consent", headers={**auth, "Content-Type": "application/json"},
        content=(
            '{"client_id": "%s", "redirect_uri": "%s", "approve": true, "response_type": '
            '"code", "code_challenge": "%s", "code_challenge_method": "S256", '
            '"token_name": "a\\ud800b"}' % (reg["client_id"], REDIRECT, challenge)
        ).encode("ascii"),
    )
    assert surrogate.status_code == 422
    assert surrogate.text.isascii()

    # A name with ordinary Unicode is a name.
    named = consent(client, auth, reg["client_id"], challenge, token_name="Клод 助手 🤖")
    assert named.status_code == 200
    code, _ = code_from(named.json()["redirect_to"])
    assert exchange(client, reg["client_id"], code, verifier).status_code == 200
    assert [t["name"] for t in client.get("/me/tokens", headers=auth).json()] == ["Клод 助手 🤖"]

    # Both normalizers hold the rule, as `ValueRefused` — a 400, the caller's to fix.
    for bad in ("a\x00b", "a\ud800b", "a\nb"):
        with pytest.raises(ValueRefused):
            normalize_api_token(
                {"id": "m_x", "name": bad, "owner_id": "u", "secret_hash": "sha256$x"}
            )
        with pytest.raises(ValueRefused):
            normalize_oauth_code(
                {
                    "code_hash": "sha256$x", "client_id": "oc_x", "owner_id": "u",
                    "redirect_uri": REDIRECT, "code_challenge": "c" * 43,
                    "token_name": bad,
                    "expires_at": __import__("datetime").datetime.now(
                        __import__("datetime").timezone.utc
                    ),
                }
            )


def test_a_control_character_in_a_client_name_is_a_refusal_not_an_outage(client):
    """A NUL cannot live in a Postgres text column at all, so an unauthenticated
    registration carrying one came back **503** — the status that says *this server is
    broken* about a request that was merely wrong. The rest of C0 stores fine and then
    renders as a line break or a bell on the consent page."""
    for name in ("bad\x00name", "line\nbreak", "bell\x07", "tab\tstop", "del\x7f"):
        response = client.post("/oauth/register", json={**SDK_REGISTRATION, "client_name": name})
        assert response.status_code == 400, name
        assert response.json()["error"] == "invalid_client_metadata", name
        assert "control characters" in response.json()["error_description"]

    # And the store refuses a NUL on its own, so the fake is not more permissive than
    # Postgres — which is the drift direction the contract suite exists to catch.
    from carnet.storage.base import normalize_oauth_client

    with pytest.raises(StorageError, match="NUL"):
        normalize_oauth_client(
            {"id": "oc_x", "client_name": "a\x00b", "redirect_uris": ["https://a/"], "metadata": {}}
        )
    with pytest.raises(StorageError, match="NUL"):
        normalize_oauth_client(
            {"id": "oc_x", "client_name": "ok", "redirect_uris": ["https://a/\x00"], "metadata": {}}
        )

    # A name with ordinary Unicode is not a control character and is kept whole.
    named = register(client, client_name="Клод — Ассистент 助手 🤖")
    assert named["client_name"] == "Клод — Ассистент 🤖".replace(" 🤖", " 助手 🤖")


def test_a_redirect_uri_may_not_carry_credentials(client):
    """`https://claude.ai@evil.example/cb` has host `evil.example` and reads, to a person
    scanning it, as `claude.ai`. The consent page renders the *parsed* host so it is
    honest either way; refusing costs a legitimate client nothing, because no MCP
    client's callback has ever needed userinfo."""
    for uri in (
        "https://claude.ai@evil.example/cb",
        "https://user:pw@claude.ai/cb",
        "http://localhost@evil.example/cb",
    ):
        response = client.post("/oauth/register", json={**SDK_REGISTRATION, "redirect_uris": [uri]})
        assert response.status_code == 400, uri
        assert response.json()["error"] == "invalid_redirect_uri", uri
        assert "credentials" in response.json()["error_description"]


def test_a_hostname_that_merely_starts_with_localhost_is_not_the_loopback(client):
    """The loopback exception is RFC 8252 §7.3 and is about *the* loopback. A check on
    a prefix rather than the whole hostname would make `http://localhost.evil.example/`
    a plain-http redirect target on somebody else's domain."""
    for uri in (
        "http://localhost.evil.example/cb",
        "http://127.0.0.1.evil.example/cb",
        "http://notlocalhost/cb",
        "http://[::1].evil.example/cb",
    ):
        response = client.post("/oauth/register", json={**SDK_REGISTRATION, "redirect_uris": [uri]})
        assert response.status_code == 400, uri
        assert response.json()["error"] == "invalid_redirect_uri", uri

    # And the real loopback, in all its spellings, on any port.
    for uri in ("http://localhost:6274/cb", "http://127.0.0.1:1/cb", "http://[::1]:65535/cb",
                "HTTPS://claude.ai/CB"):
        assert client.post(
            "/oauth/register", json={**SDK_REGISTRATION, "redirect_uris": [uri]}
        ).status_code == 201, uri


def test_a_registrations_metadata_is_truncated_rather_than_refused(client):
    """A bound that refuses what its own truncation produced is not a bound. The first
    version capped each field at 2048 and then refused the *total* over 4096, so three
    individually legal fields were rejected as "too large"."""
    from carnet.access.oauth_server import MAX_METADATA_FIELD_LENGTH

    reg = register(
        client,
        client_uri="https://" + "a" * 2000,
        software_id="b" * 2000,
        software_version="c" * 2000,
    )
    assert len(reg["client_uri"]) == MAX_METADATA_FIELD_LENGTH
    assert len(reg["software_id"]) == MAX_METADATA_FIELD_LENGTH
    assert len(reg["software_version"]) == MAX_METADATA_FIELD_LENGTH


def test_a_nameless_registration_is_named_by_where_it_goes_back_to(client):
    reg = register(client, client_name=None)
    assert reg["client_name"] == "claude.ai"
    reg = register(client, client_name="  ", redirect_uris=[CURSOR])
    assert reg["client_name"] == "anysphere.cursor-retrieval"


# --- the dance -------------------------------------------------------------------------


def test_the_whole_dance_ends_in_a_personal_token_the_person_owns(client, auth):
    """Register, consent, exchange, and then the thing that matters: the access token is
    an `art_` token — on the person's own tokens page, personal, named for the client,
    admitted at the door as a machine, and recorded as a mint via this client."""
    reg = register(client)
    verifier, challenge = pkce()

    described = client.get(f"/oauth/clients/{reg['client_id']}", headers=auth)
    assert described.status_code == 200
    assert described.json() == {
        "client_id": reg["client_id"],
        "client_name": "Claude",
        "client_uri": "https://claude.ai",
        "redirect_uris": [REDIRECT, LOOPBACK, CURSOR],
    }

    bounced = consent(client, auth, reg["client_id"], challenge)
    assert bounced.status_code == 200, bounced.text
    redirect_to = bounced.json()["redirect_to"]
    assert redirect_to.startswith(REDIRECT + "?")
    code, query = code_from(redirect_to)
    assert query["state"] == ["xyz-123"]
    assert "error" not in query

    minted = exchange(client, reg["client_id"], code, verifier)
    assert minted.status_code == 200, minted.text
    assert minted.headers["cache-control"] == "no-store"
    assert minted.headers["pragma"] == "no-cache"
    body = minted.json()
    assert body["token_type"] == "Bearer"
    assert body["access_token"].startswith("art_m_")
    assert 29 * 86400 < body["expires_in"] <= 30 * 86400
    assert "refresh_token" not in body

    # The door admits it as a machine and the handshake answers.
    handshake = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        headers={"Authorization": f"Bearer {body['access_token']}"},
    )
    assert handshake.status_code == 200
    assert handshake.json()["result"]["serverInfo"]["name"] == "carnet"

    # And it is the person's: on their page, personal, named for the client.
    mine = client.get("/me/tokens", headers=auth).json()
    assert len(mine) == 1
    assert mine[0]["name"] == "Claude"
    assert mine[0]["acts_as_owner"] is True
    assert mine[0]["owner_id"] == logged_in_id(client, auth)
    assert mine[0]["expires_at"] is not None

    # The mint is recorded as such, by the person, via this client.
    records = storage.active().admin_audit_records(TEST_TENANT)
    mint = [r for r in records if r["action"] == "token.mint"][-1]
    assert mint["actor_kind"] == "user"
    assert mint["detail"]["via"] == f"oauth:{reg['client_id']}"
    assert mint["detail"]["acts_as_owner"] is True

    # The client is now one somebody consented to, so the sweep leaves it alone.
    assert storage.active().find_oauth_client(reg["client_id"])["last_consented_at"] is not None


def test_the_token_request_is_a_form_and_json_is_tolerated(client, auth):
    reg = register(client)
    verifier, challenge = pkce()
    code, _ = code_from(consent(client, auth, reg["client_id"], challenge).json()["redirect_to"])
    as_json = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "client_id": reg["client_id"],
        },
    )
    assert as_json.status_code == 200, as_json.text
    assert as_json.json()["access_token"].startswith("art_")


def test_a_second_person_connecting_the_same_client_gets_the_same_name(client, auth, sam):
    """Two colleagues connecting Claude Desktop each get `Claude`: since migration 054 a
    personal token's name is unique per owner, so the second person is not the
    collision the suffix loop exists for. Before 054 this test expected `Claude (2)`."""
    client_id, first = dance(client, auth)
    assert first.status_code == 200
    reg_again = storage.active().find_oauth_client(client_id)
    verifier, challenge = pkce()
    code, _ = code_from(consent(client, sam, client_id, challenge).json()["redirect_to"])
    second = exchange(client, client_id, code, verifier)
    assert second.status_code == 200, second.text
    assert reg_again["client_name"] == "Claude"
    assert [t["name"] for t in client.get("/me/tokens", headers=sam).json()] == ["Claude"]
    assert [t["name"] for t in client.get("/me/tokens", headers=auth).json()] == ["Claude"]


def test_the_same_person_connecting_the_same_client_twice_gets_a_suffixed_name(client, auth):
    """The collision the loop is for: one person, a second machine, the same client.
    Their own page would show two live `Claude` rows and revocation would be a guess,
    so the second is `Claude (2)`."""
    client_id, first = dance(client, auth)
    assert first.status_code == 200
    verifier, challenge = pkce()
    code, _ = code_from(consent(client, auth, client_id, challenge).json()["redirect_to"])
    second = exchange(client, client_id, code, verifier)
    assert second.status_code == 200, second.text
    assert sorted(t["name"] for t in client.get("/me/tokens", headers=auth).json()) == [
        "Claude", "Claude (2)"
    ]


def test_the_person_may_name_the_token_on_the_page(client, auth):
    reg = register(client)
    verifier, challenge = pkce()
    code, _ = code_from(
        consent(client, auth, reg["client_id"], challenge, token_name="  laptop  ").json()["redirect_to"]
    )
    assert exchange(client, reg["client_id"], code, verifier).status_code == 200
    assert [t["name"] for t in client.get("/me/tokens", headers=auth).json()] == ["laptop"]


def test_no_expiry_when_the_deployment_says_so(client, auth, monkeypatch):
    monkeypatch.setattr(config, "OAUTH_TOKEN_DAYS", 0)
    _, minted = dance(client, auth)
    assert minted.status_code == 200
    assert "expires_in" not in minted.json()
    assert client.get("/me/tokens", headers=auth).json()[0]["expires_at"] is None


# --- consent's gate and its refusals ------------------------------------------------


def test_consent_is_a_persons_and_refuses_a_machine_before_reading_the_body(client, auth):
    """The mint's only gate, and 044's guard on `POST /me/tokens` word for word: no
    credential that survives its presenter can create another."""
    _, minted = dance(client, auth)
    machine = {"Authorization": f"Bearer {minted.json()['access_token']}"}
    reg = register(client)
    _, challenge = pkce()

    refused = consent(client, machine, reg["client_id"], challenge)
    assert refused.status_code == 403
    assert "person" in refused.json()["detail"]

    nobody = consent(client, {}, reg["client_id"], challenge)
    assert nobody.status_code == 401

    # And the page's read is behind a principal too — a registration is not a
    # directory.
    assert client.get(f"/oauth/clients/{reg['client_id']}").status_code == 401


def test_consent_never_redirects_to_an_unregistered_uri(client, auth):
    """RFC 6749 §4.1.2.1: an unknown client or an unregistered `redirect_uri` is
    answered with a 400 and no redirect, or the page would be an open redirect."""
    reg = register(client)
    _, challenge = pkce()

    unknown = consent(client, auth, "oc_0000000000000000", challenge)
    assert unknown.status_code == 400
    assert unknown.json()["error"] == "invalid_client"

    off_by_one = consent(client, auth, reg["client_id"], challenge, redirect_uri=REDIRECT + "/")
    assert off_by_one.status_code == 400
    assert off_by_one.json()["error"] == "invalid_request"
    assert "open redirect" in off_by_one.json()["error_description"]

    elsewhere = consent(client, auth, reg["client_id"], challenge, redirect_uri="https://evil.example/")
    assert elsewhere.status_code == 400

    assert client.get("/oauth/clients/oc_0000000000000000", headers=auth).status_code == 400


def test_a_declined_consent_and_a_bad_request_bounce_with_the_rfcs_error(client, auth):
    """Once the target is trusted, everything answers by redirecting — the RFC's error
    for a request that is wrong, `access_denied` for a person who said no — with the
    state echoed and no code anywhere."""
    reg = register(client)
    _, challenge = pkce()

    def bounced(**overrides):
        response = consent(client, auth, reg["client_id"], challenge, **overrides)
        assert response.status_code == 200, response.text
        parts = urlsplit(response.json()["redirect_to"])
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == REDIRECT
        query = parse_qs(parts.query)
        assert "code" not in query
        assert query["state"] == ["xyz-123"]
        return query["error"][0], query["error_description"][0]

    assert bounced(approve=False)[0] == "access_denied"
    assert bounced(response_type="token")[0] == "unsupported_response_type"
    assert bounced(code_challenge_method="plain")[0] == "invalid_request"
    assert bounced(code_challenge="short")[0] == "invalid_request"
    assert bounced(code_challenge=None)[0] == "invalid_request"
    error, description = bounced(resource="https://other.example/mcp")
    assert error == "invalid_target"
    assert "https://carnet.acme.com/api/mcp" in description

    # No state in, no state out.
    response = consent(client, auth, reg["client_id"], challenge, approve=False, state=None)
    assert "state" not in parse_qs(urlsplit(response.json()["redirect_to"]).query)


def test_a_registered_uri_with_its_own_query_keeps_it(client, auth):
    """RFC 6749 §3.1.2: the redirect URI may carry a query, and the response's
    parameters are added to it rather than replacing it."""
    with_query = "https://client.example/cb?app=carnet"
    reg = register(client, redirect_uris=[with_query])
    _, challenge = pkce()
    response = consent(client, auth, reg["client_id"], challenge, redirect_uri=with_query)
    query = parse_qs(urlsplit(response.json()["redirect_to"]).query)
    assert query["app"] == ["carnet"]
    assert "code" in query


# --- the exchange's refusals ---------------------------------------------------------


def test_a_code_is_single_use_and_a_replay_revokes_what_it_minted(client, auth):
    """RFC 6749 §4.1.2's *should*, done: the second presentation is the signal that the
    first was intercepted, so the token it minted dies and the door refuses it."""
    reg = register(client)
    verifier, challenge = pkce()
    code, _ = code_from(consent(client, auth, reg["client_id"], challenge).json()["redirect_to"])

    first = exchange(client, reg["client_id"], code, verifier)
    assert first.status_code == 200
    token = first.json()["access_token"]
    assert client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        headers={"Authorization": f"Bearer {token}"},
    ).status_code == 200

    replay = exchange(client, reg["client_id"], code, verifier)
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"

    mine = client.get("/me/tokens", headers=auth).json()
    assert mine[0]["revoked_at"] is not None
    assert mine[0]["revoked_by"] == "system:oauth"
    assert client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        headers={"Authorization": f"Bearer {token}"},
    ).status_code == 401


def test_every_wrong_exchange_gets_one_sentence(client, auth):
    """Unknown, wrong verifier, wrong client, wrong redirect: one `invalid_grant`, byte
    for byte, on `tokens._refuse`'s reasoning — and none of them consumes the code."""
    reg = register(client)
    other = register(client, client_name="Other")
    verifier, challenge = pkce()
    code, _ = code_from(consent(client, auth, reg["client_id"], challenge).json()["redirect_to"])

    wrong = [
        exchange(client, reg["client_id"], "not-a-code", verifier),
        exchange(client, reg["client_id"], code, secrets.token_urlsafe(48)),
        exchange(client, reg["client_id"], code, "short"),
        exchange(client, other["client_id"], code, verifier),
        exchange(client, reg["client_id"], code, verifier, redirect_uri=LOOPBACK),
    ]
    assert {r.status_code for r in wrong} == {400}
    assert len({r.text for r in wrong}) == 1
    assert wrong[0].json()["error"] == "invalid_grant"

    # A wrong `resource` is the one refusal that is its own error: the client asked for
    # a token for something this server is not.
    target = exchange(client, reg["client_id"], code, verifier, resource="https://other.example/mcp")
    assert target.json()["error"] == "invalid_target"

    # The right one still works: nothing above consumed the code.
    assert exchange(client, reg["client_id"], code, verifier).status_code == 200


def test_a_verifier_that_is_not_a_verifier_is_a_refusal_not_a_crash(client, auth):
    """RFC 7636 §4.1's charset is part of the rule. `S256` is defined over ASCII octets,
    so encoding a non-ASCII verifier **raised** — a 500 at the token endpoint, which
    tells an operator the server is broken about a request that was merely wrong. Found
    in the testing pass by sending one."""
    from carnet.access.oauth_server import _looks_like_challenge, _pkce_matches

    reg = register(client)
    verifier, challenge = pkce()
    code, _ = code_from(consent(client, auth, reg["client_id"], challenge).json()["redirect_to"])

    for bad in ("é" * 50, "ünïcödé" * 8, "verifier with spaces" * 3, "🔑" * 45, "a" * 42, "a" * 129):
        response = exchange(client, reg["client_id"], code, bad)
        assert response.status_code == 400, bad
        assert response.json()["error"] == "invalid_grant", bad

    # Nothing above consumed the code: the right verifier still works.
    assert exchange(client, reg["client_id"], code, verifier).status_code == 200

    # The two shape checks, directly. `str.isalnum()` is Unicode-aware and answers True
    # for `é` and `１`, so a challenge of 43 accented letters passed a check whose
    # docstring said base64url.
    assert _looks_like_challenge("A" * 43) is True
    assert _looks_like_challenge("é" * 43) is False
    assert _looks_like_challenge("１" * 43) is False
    assert _looks_like_challenge("A" * 42) is False
    assert _looks_like_challenge("A" * 42 + "=") is False
    assert _pkce_matches("é" * 50, "x" * 43) is False
    assert _pkce_matches("a" * 43, "x" * 43) is False


def test_a_challenge_that_is_not_base64url_never_reaches_the_database(client, auth):
    """Bounced at consent, so no code row is written for a challenge nothing could ever
    match. The `=` case is the real one: a client that base64-encodes *with* padding
    produces 44 characters."""
    import base64 as b64

    reg = register(client)
    padded = b64.urlsafe_b64encode(hashlib.sha256(b"x").digest()).decode()
    assert padded.endswith("=")

    for bad in (padded, "é" * 43, "A" * 42, "A/B+" + "c" * 39, ""):
        response = consent(client, auth, reg["client_id"], bad)
        assert response.status_code == 200, bad
        query = parse_qs(urlsplit(response.json()["redirect_to"]).query)
        assert query["error"] == ["invalid_request"], bad
        assert "code" not in query, bad
    assert storage.active().list_api_tokens(TEST_TENANT) == []


def test_a_missing_parameter_is_invalid_request(client):
    response = client.post("/oauth/token", data={"grant_type": "authorization_code"})
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    huge = client.post("/oauth/token", data={"grant_type": "authorization_code", "code": "x" * 9000})
    assert huge.json()["error"] == "invalid_request"


def test_an_expired_code_is_refused(client, auth, monkeypatch):
    monkeypatch.setattr(config, "OAUTH_CODE_TTL_SECONDS", -1)
    reg = register(client)
    verifier, challenge = pkce()
    code, _ = code_from(consent(client, auth, reg["client_id"], challenge).json()["redirect_to"])
    assert exchange(client, reg["client_id"], code, verifier).json()["error"] == "invalid_grant"


def test_a_person_disabled_after_consenting_gets_no_token(client, auth):
    """`check_row_is_live` would refuse the token at its first use; minting it at all
    for somebody who has gone is wrong for the seconds it would exist."""
    reg = register(client)
    verifier, challenge = pkce()
    code, _ = code_from(consent(client, auth, reg["client_id"], challenge).json()["redirect_to"])
    owner = logged_in_id(client, auth)
    storage.active().set_user_status(TEST_TENANT, owner, "disabled", actor="system:cli")

    assert exchange(client, reg["client_id"], code, verifier).json()["error"] == "invalid_grant"
    assert storage.active().list_api_tokens(TEST_TENANT) == []


def test_the_only_grant_type_is_authorization_code(client, auth):
    """**The tripwire.** 020 refused a mint for a bearer. The exchange is a mint route,
    and what keeps 020 intact is that its only grant is gated on a person's interactive
    sign-in with PKCE. `client_credentials` is exactly the mint 020 refused and
    `refresh_token` is a mint of a successor for a bearer. Both refused, and the
    metadata advertises exactly one grant, so the next person adding one meets this."""
    assert oauth_server.GRANT_TYPES == ("authorization_code",)
    assert client.get("/.well-known/oauth-authorization-server").json()["grant_types_supported"] == [
        "authorization_code"
    ]

    for grant in ("client_credentials", "refresh_token", "password", "implicit", ""):
        response = client.post(
            "/oauth/token",
            data={"grant_type": grant, "client_id": "oc_x", "client_secret": "s", "refresh_token": "r"},
        )
        assert response.status_code == 400, grant
        assert response.json()["error"] == "unsupported_grant_type", grant
        assert "bearer" in response.json()["error_description"]

    # And a token minted this way is admitted at the door and nowhere near a mint:
    # `POST /me/tokens` refuses it as it refuses every machine.
    _, minted = dance(client, auth)
    machine = {"Authorization": f"Bearer {minted.json()['access_token']}"}
    assert client.post("/me/tokens", headers=machine, json={"name": "successor"}).status_code == 403

    # Source-text half, on 020's device: the exchange dispatches on exactly this string
    # and the module spells no other grant as a branch.
    import inspect

    source = inspect.getsource(oauth_server)
    assert 'grant_type != "authorization_code"' in source
    assert 'grant_type == "client_credentials"' not in source
    assert 'grant_type == "refresh_token"' not in source


def test_the_minted_token_is_personal_and_cannot_be_granted(client, auth):
    """033d's rule holds for a token minted here: its reach is its owner's, and
    `grants.share` refuses it as a grantee — consent cannot widen anything."""
    from carnet import agents
    from carnet.access import grants
    from carnet.core import Principal

    _, minted = dance(client, auth)
    row = client.get("/me/tokens", headers=auth).json()[0]
    owner = logged_in_id(client, auth)
    agents.save(
        TEST_TENANT,
        {"name": "triage", "permissions": {"tools": [], "scope": {}}},
        actor="system:cli",
    )
    storage.active().grant_agent(
        TEST_TENANT, "triage", "user", owner, role="editor", granted_by="system:cli", actor="system:cli"
    )
    with pytest.raises(grants.ShareRefused, match="personal token"):
        grants.share(
            Principal.user(owner, TEST_TENANT), "triage", "machine", row["id"], role="user"
        )


# --- housekeeping ---------------------------------------------------------------------


def test_the_sweep_takes_unconsented_clients_and_expired_codes(client, auth, monkeypatch):
    idle = register(client, client_name="Idle")
    used_id, _ = dance(client, auth)
    monkeypatch.setattr(config, "OAUTH_CLIENT_UNUSED_DAYS", 0)
    monkeypatch.setattr(config, "OAUTH_CODE_SWEEP_SECONDS", -1000)

    swept = oauth_server.sweep()
    assert swept["clients"] >= 1
    assert storage.active().find_oauth_client(idle["client_id"]) is None
    assert storage.active().find_oauth_client(used_id) is not None
    # The consented code had a five-minute life; a negative window sweeps it.
    assert swept["codes"] >= 1


def test_the_maintainer_runs_the_sweep(monkeypatch):
    from carnet.api import LogMaintainer

    calls = []
    monkeypatch.setattr(oauth_server, "sweep", lambda: calls.append(1) or {"codes": 0, "clients": 0})
    swept = LogMaintainer(60).sweep_once()
    assert calls == [1]
    assert swept["oauth"] == {"codes": 0, "clients": 0}


def test_a_test_client_can_be_built_without_the_documents_touching_storage(monkeypatch):
    """Both documents are configuration and read nothing — a client that holds nothing
    reads them, and they must answer when storage is down."""
    monkeypatch.setattr(storage, "active", lambda: (_ for _ in ()).throw(storage.StorageError("down")))
    app = TestClient(create_app())
    assert app.get("/.well-known/oauth-protected-resource").status_code == 200
    assert app.get("/.well-known/oauth-authorization-server").status_code == 200
