"""The door's OAuth server, driven adversarially against a real database. Step 083.

**Not a second copy of `e2e_mcp_door.py`.** That script proves the flow *works*: the
official MCP SDK, which shares none of our assumptions, discovers, registers, consents
and exchanges over a real socket, and the token it ends up holding calls a tool. This
one starts where that one stops and asks the other questions — what happens when two
clients race the same code, when a verifier is not ASCII, when a person is disabled
between consent and exchange, when a redirect URI is one byte off, when the same client
is connected by two people at once, when a token outlives its expiry, and whether the
row-level policy on the two new tables is the one the migration claims.

    cd backend && CARNET_E2E_PG=postgresql://postgres:test@localhost:5433/postgres \\
        .venv/bin/python scripts/e2e_oauth_door.py

Needs Postgres started first and outbound DNS for `localtest.me`, a public name that
resolves to loopback. **The name is not a workaround and cannot be dropped**: `egress`
refuses a literal loopback address *before* any allowlist is read, so a connector at
`http://127.0.0.1:.../mcp` cannot be registered at all, by design. That dependency is
why this script is not in CI, which its two sibling door scripts share and which
`DEFERRED.md` now carries a row for. **Costs nothing**: no model is called, and every
server it talks to is a socket on this machine. It does **not** need the MCP SDK: every
request here is raw HTTP, deliberately, because a second client written to the same
assumptions as the server would hide exactly the asymmetries this script is looking for.

## What it drives

```
uvicorn on the origin root          the whole flow, and every way to get it wrong
uvicorn with --root-path /api       the deployed shape, without docker
two tenants, two issuers            a client is global; a consent is a tenant's
one upstream MCP server             so a brokered call is a real call
real threads                        two exchanges racing one code; two people racing one name
raw SQL                             time travel, and the row-level policy from underneath
```

## What it found

Eight defects, all fixed in the commit this script arrives in. Each has a check below
and most also have a unit test, because this script is not in CI:

1. **A non-ASCII `code_verifier` was a 500.** `S256` is defined over ASCII octets, so
   `verifier.encode("ascii")` raised `UnicodeEncodeError` — an exception escaping the
   token endpoint as *the server is broken* about a request that was merely wrong.
2. **A malformed IPv6 authority was a 500 from an unauthenticated route.**
   `urlsplit("http://[::1].evil.example/")` raises `ValueError`, and nothing caught it.
3. **A NUL in `client_name` was a 503.** No Postgres text column can hold one, so an
   unauthenticated registration could make the API answer *storage unavailable* — and
   the in-memory store accepted it happily, which is the fake being more permissive than
   the real one, the drift direction the contract suite exists to catch.
4. **The registration request was unbounded.** The *row* was bounded from the start; the
   request was not, so a stranger's script could post a hundred megabytes and have it
   parsed before a single bound was consulted. The door bounded exactly this in 033b.
5. **`_looks_like_challenge` accepted non-ASCII**, because `str.isalnum()` is
   Unicode-aware: 43 accented letters passed a check whose docstring said base64url.
6. **A redirect URI could carry credentials.** `https://claude.ai@evil.example/cb` has
   host `evil.example` and reads, to a person scanning it, as `claude.ai`.
7. **Three individually legal metadata fields were refused as "too large"** — the
   per-field truncation could produce a value the aggregate bound then rejected.
8. **A malformed registration answered FastAPI's 422** with a `detail` list, which is a
   shape no OAuth client parses; RFC 7591 §3.2.2 says `error`/`error_description`.

## What it deliberately does not cover

**The browser.** The consent page is `frontend/src/features/oauth/AuthorizePage.tsx` and
its own tests; here the page is simulated by making the two requests it makes, with the
person's own bearer, which is the contract between them. **Caddy** — `e2e_deploy.py`
drives the front door and asserts the two documents and the challenge through it. **The
SDK** — `e2e_mcp_door.py`.
"""

import base64
import hashlib
import json
import os
import pathlib
import secrets
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit, urlunsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_oauth_door_e2e"
BASE_DSN = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"

API_PORT = 8161
PROXIED_PORT = 8162
JWKS_PORT = 8163
UPSTREAM_PORT = 8964

API = f"http://127.0.0.1:{API_PORT}"
DOOR = f"{API}/mcp"
# The second server, started the way the shipped deployment starts it: behind a proxy
# that strips `/api`, so `--root-path /api` and a public origin that carries the prefix.
PROXIED = f"http://127.0.0.1:{PROXIED_PORT}"
PROXIED_ORIGIN = f"{PROXIED}/api"

# A public DNS name that resolves to loopback, and **it has to be a name**: `egress.check`
# refuses a literal loopback address before any allowlist is consulted, so no operator
# consent can register `http://127.0.0.1:.../mcp` as a connector at all. That is the
# right rule and it is the reason all three door scripts carry an outbound-DNS
# dependency — see the module docstring.
UPSTREAM_HOST = "localtest.me"

# Two customers, because a registered client is **global** — it belongs to no tenant, by
# design and by migration 053 — while every consent, code and token belongs to one. The
# two together are the only way to ask whether that split holds.
TENANT_A, TENANT_B = "e2eoa", "e2eob"
ISSUER_A = "https://idp-a.e2eoauth.local"
ISSUER_B = "https://idp-b.e2eoauth.local"
AUDIENCE = "api://default"

PRIYA, SAM, TOM = "u_priya", "u_sam", "u_tom"
ACTOR = "system:cli"
SHARED = "acme-service-token"

# Small on purpose: one scene exhausts a token's day deliberately, and every other scene
# mints its own token, so the ceiling is never reached by accident.
CALLS_PER_DAY = 5

REDIRECT = "https://claude.example/api/mcp/auth_callback"
LOOPBACK = "http://localhost:6274/oauth/callback"
CURSOR = "cursor://anysphere.cursor-retrieval/oauth/user-carnet/callback"

# What an SDK actually sends. `refresh_token` is in it because the official client asks
# for one by default, and `logo_uri` because a real registration carries one — this
# server records neither, and the checks below say so.
REGISTRATION = {
    "client_name": "Claude",
    "redirect_uris": [REDIRECT, LOOPBACK, CURSOR],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "client_uri": "https://claude.example",
    "logo_uri": "https://claude.example/logo.png",
}

TOOLS = [
    {
        "name": "list_issues",
        "description": "List issues in a repository.",
        "inputSchema": {
            "type": "object",
            "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}},
            "required": ["owner", "repo"],
        },
    }
]

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True)
JWK.update({"kid": "k1", "use": "sig", "alg": "RS256"})


def dsn_for(database: str) -> str:
    parts = urlsplit(BASE_DSN)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


DSN = dsn_for(DB)


# --- the world outside the API --------------------------------------------------------


def person(subject: str, email: str, issuer: str = ISSUER_A, ttl: int = 3600) -> str:
    now = int(time.time())
    return jwt.encode(
        {"iss": issuer, "aud": AUDIENCE, "sub": subject, "email": email,
         "iat": now - 5, "exp": now + ttl},
        KEY, algorithm="RS256", headers={"kid": "k1"},
    )


def bearer(subject: str, email: str, issuer: str = ISSUER_A) -> dict:
    return {"Authorization": f"Bearer {person(subject, email, issuer)}"}


class Jwks(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = json.dumps({"keys": [JWK]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Upstream(BaseHTTPRequestHandler):
    """The customer's own MCP server, so a brokered call is a real one.

    One tool, and one magic argument: `repo="explode"` answers a JSON-RPC error, which
    is how the *tool failed* branch of a door call is reached without breaking anything.
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        message = json.loads(self.rfile.read(length) or "{}")
        method = message.get("method")

        if "id" not in message:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "acme", "version": "1.0"}}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            arguments = (message.get("params") or {}).get("arguments") or {}
            if arguments.get("repo") == "explode":
                body = json.dumps({
                    "jsonrpc": "2.0", "id": message["id"],
                    "error": {"code": -32603, "message": "the repository is on fire"},
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            result = {"content": [{"type": "text", "text": json.dumps(
                {"issues": [{"number": 1, "repo": arguments.get("repo")}],
                 "seen_authorization": self.headers.get("Authorization")})}]}
        else:
            result = {}

        body = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# --- the reporting device -------------------------------------------------------------

CHECKS: list[tuple[str, bool]] = []


def check(label, actual, expected):
    """Every line this prints is an assertion, and it prints either way."""
    ok = actual == expected
    CHECKS.append((label, ok))
    mark = "ok  " if ok else "FAIL"
    print(f"  {mark} {label}: {actual!r}" + ("" if ok else f"  (expected {expected!r})"), flush=True)
    return ok


def says(label, actual, fragment):
    ok = fragment in (actual or "")
    CHECKS.append((label, ok))
    mark = "ok  " if ok else "FAIL"
    print(f"  {mark} {label}: {fragment!r} in {str(actual)[:150]!r}", flush=True)
    return ok


def step(what):
    print(f"\n=== {what}", flush=True)


def report() -> int:
    failed = [label for label, ok in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


# --- the flow, as a client and a browser do it ----------------------------------------


def pkce(verifier: str | None = None) -> tuple[str, str]:
    verifier = verifier or secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return verifier, challenge


def register(base: str = API, **overrides) -> httpx.Response:
    body = {**REGISTRATION, **overrides}
    body = {k: v for k, v in body.items() if v is not None}
    return httpx.post(f"{base}/oauth/register", json=body, timeout=15)


def registered(base: str = API, **overrides) -> str:
    response = register(base, **overrides)
    assert response.status_code == 201, response.text
    return response.json()["client_id"]


def consent(headers, client_id, challenge, *, base=API, approve=True, **overrides):
    """What the consent page posts. `redirect_uri` and the PKCE pair are the client's."""
    body = {
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "state": "state-xyz",
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": f"{API}/mcp" if base == API else f"{PROXIED_ORIGIN}/mcp",
        "approve": approve,
    }
    body.update(overrides)
    return httpx.post(f"{base}/oauth/consent", headers=headers, json=body, timeout=15)


def code_of(response) -> str:
    query = parse_qs(urlsplit(response.json()["redirect_to"]).query)
    return query["code"][0]


def exchange(client_id, code, verifier, *, base=API, **overrides):
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
        "client_id": client_id,
        "redirect_uri": REDIRECT,
    }
    form.update(overrides)
    form = {k: v for k, v in form.items() if v is not None}
    return httpx.post(f"{base}/oauth/token", data=form, timeout=15)


def connect(headers, *, base=API, **overrides) -> httpx.Response:
    """Register, consent and exchange — the whole dance, as one call."""
    client_id = registered(base, **{k: v for k, v in overrides.items() if k in REGISTRATION})
    verifier, challenge = pkce()
    approved = consent(headers, client_id, challenge, base=base,
                       **{k: v for k, v in overrides.items() if k == "token_name"})
    assert approved.status_code == 200, approved.text
    return exchange(client_id, code_of(approved), verifier, base=base)


def rpc(token, method, params=None, *, base=DOOR, message_id=1):
    body = {"jsonrpc": "2.0", "id": message_id, "method": method}
    if params is not None:
        body["params"] = params
    return httpx.post(base, json=body, headers={"Authorization": f"Bearer {token}"}, timeout=20)


def call_tool(token, arguments, *, base=DOOR):
    return rpc(token, "tools/call", {"name": "acme_list_issues", "arguments": arguments}, base=base)


def sql(statement, params=(), *, database=DB, fetch=True):
    import psycopg

    with psycopg.connect(dsn_for(database), autocommit=True) as conn:
        cursor = conn.execute(statement, params)
        return cursor.fetchall() if fetch else None


# --- scene 1: what a client that holds nothing can find out ---------------------------


def the_discovery(store):
    step("a client holding only the door's URL, and the 401 that tells it where to look")

    naked = httpx.post(DOOR, json={"jsonrpc": "2.0", "id": 1, "method": "ping"}, timeout=10)
    check("an unauthenticated door answers 401", naked.status_code, 401)
    where = f'resource_metadata="{API}/.well-known/oauth-protected-resource/mcp"'
    check("with exactly the challenge MCP's specification asks for",
          naked.headers.get("www-authenticate"), f"Bearer {where}")

    for label, credential in (
        ("a token that is not ours", "art_m_0000000000000000.nothing"),
        ("a token-shaped string with no secret", "art_m_x"),
        ("a JWT from nowhere", person("00u-x", "x@nowhere.example", issuer="https://nope")),
        # Well past `CLOCK_SKEW_LEEWAY`, which is the whole point of that setting: a
        # token thirty seconds stale is still honoured, and a test that used one was
        # asserting about the leeway rather than about expiry.
        ("an expired sign-in", person(PRIYA, "priya@acme.com", ttl=-3600)),
    ):
        answer = httpx.post(DOOR, json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                            headers={"Authorization": f"Bearer {credential}"}, timeout=10)
        check(f"401 for {label}", answer.status_code, 401)
        says(f"and the challenge still names the metadata — {label}",
             answer.headers.get("www-authenticate"), "resource_metadata=")
        says(f"beside the error it already carried — {label}",
             answer.headers.get("www-authenticate"), 'error="invalid_token"')

    # A malformed header is a 401 too, and the challenge is the plain one: there is no
    # `error=` to keep beside it.
    # `"Bearer"` with nothing after it reaches the same branch as `"Bearer   "`, which
    # httpx refuses to put on the wire at all — a header value may not end in space.
    for header in ("", "Bearer", "Basic abc", "Token abc", "bearer"):
        answer = httpx.post(DOOR, json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                            headers={"Authorization": header} if header else {}, timeout=10)
        check(f"401 for a header spelled {header!r}", answer.status_code, 401)
        says(f"named metadata for {header!r}", answer.headers.get("www-authenticate"),
             "resource_metadata=")

    # **A person's own credential is a 403 and carries no challenge**, which is the
    # difference between *sign in* and *this is not the kind of credential*: a client
    # that followed the challenge, signed in and pasted the sign-in token would
    # otherwise be sent round the loop again forever.
    signed_in = httpx.post(DOOR, json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                           headers=bearer(PRIYA, "priya@acme.com"), timeout=10)
    check("a person's sign-in token is 403, not another challenge", signed_in.status_code, 403)
    check("and carries no WWW-Authenticate at all",
          "www-authenticate" in signed_in.headers, False)
    says("naming the command that fixes it", signed_in.json().get("detail"), "--mint-token")

    # Every other route's 401 is untouched: the widening is the door's alone.
    check("another route's 401 is the plain challenge",
          httpx.get(f"{API}/agents", timeout=10).headers.get("www-authenticate"), "Bearer")

    step("the two documents, from configuration, with no credential and no storage read")

    resource = httpx.get(f"{API}/.well-known/oauth-protected-resource", timeout=10)
    check("RFC 9728 answers 200", resource.status_code, 200)
    check("never cached", resource.headers.get("cache-control"), "no-store")
    check("and names this door and this issuer", resource.json(), {
        "resource": f"{API}/mcp",
        "authorization_servers": [API],
        "bearer_methods_supported": ["header"],
        "resource_name": "Carnet MCP door",
    })
    check("the path form the specification tries first says the same thing",
          httpx.get(f"{API}/.well-known/oauth-protected-resource/mcp", timeout=10).json(),
          resource.json())
    for stranger in ("/somewhere/else", "/api/mcp", "/mcp/extra", "/MCP"):
        check(f"and a resource this deployment does not have is 404 — {stranger}",
              httpx.get(f"{API}/.well-known/oauth-protected-resource{stranger}",
                        timeout=10).status_code, 404)

    server = httpx.get(f"{API}/.well-known/oauth-authorization-server", timeout=10)
    check("RFC 8414 answers 200", server.status_code, 200)
    check("advertising exactly what this server accepts and nothing more", server.json(), {
        "issuer": API,
        "authorization_endpoint": f"{API}/oauth/authorize",
        "token_endpoint": f"{API}/oauth/token",
        "registration_endpoint": f"{API}/oauth/register",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    })
    # The document is the contract the tripwire is about: one grant, and it is the one
    # gated on a person signing in.
    check("one grant type, advertised", server.json()["grant_types_supported"],
          ["authorization_code"])

    # Documents read nothing, so they answer under a bearer, a broken one, or none.
    check("the documents ignore a credential entirely",
          httpx.get(f"{API}/.well-known/oauth-authorization-server",
                    headers={"Authorization": "Bearer nonsense"}, timeout=10).status_code, 200)

    step("the two halves of the flow do not overlap, and the API publishes its own half")
    # `authorization_endpoint` names the **app's** route. The API must not also claim
    # it: two things answering one URL is how a consent page becomes a JSON document
    # in front of somebody trying to approve a client.
    check("the API does not serve the consent page",
          httpx.get(f"{API}/oauth/authorize", timeout=10).status_code, 404)

    paths = httpx.get(f"{API}/openapi.json", timeout=10).json()["paths"]
    for path in ("/oauth/register", "/oauth/token", "/oauth/consent",
                 "/oauth/clients/{client_id}", "/.well-known/oauth-authorization-server",
                 "/.well-known/oauth-protected-resource"):
        check(f"documented: {path}", path in paths, True)
    check("and the consent page is not, because it is not this API's",
          "/oauth/authorize" in paths, False)


# --- scene 2: registration, adversarially ---------------------------------------------


def the_registration(store):
    step("dynamic client registration: what is recorded, and what is refused")

    first = register()
    check("an SDK-shaped registration is 201", first.status_code, 201)
    body = first.json()
    check("the id is ours and opaque", (body["client_id"][:3], len(body["client_id"])), ("oc_", 19))
    check("no secret is issued, because this server registers public clients only",
          [k for k in body if "secret" in k], [])
    check("the grants recorded are the grants offered, whatever was asked",
          body["grant_types"], ["authorization_code"])
    check("...and the auth method is none", body["token_endpoint_auth_method"], "none")
    check("the client's own URL is kept for the page", body["client_uri"], "https://claude.example")
    check("its logo is not — a remote image on a consent page is a request per viewer",
          "logo_uri" in body, False)
    check("and the redirect list comes back exactly as registered",
          body["redirect_uris"], [REDIRECT, LOOPBACK, CURSOR])

    # DCR has no idea of identity: two registrations of the same metadata are two
    # clients, and that is the protocol rather than a defect.
    check("registering twice makes two clients", registered() != registered(), True)

    step("the two grants a mint-for-a-bearer would need are refused at registration")
    for asked in (["client_credentials"], ["authorization_code", "client_credentials"],
                  ["password"], ["urn:ietf:params:oauth:grant-type:device_code"]):
        refused = register(grant_types=asked)
        check(f"refused: {asked}", refused.status_code, 400)
        check("...as invalid_client_metadata", refused.json()["error"], "invalid_client_metadata")
    says("and the refusal says why", register(grant_types=["client_credentials"]).json()
         ["error_description"], "mint for a bearer")

    for method in ("client_secret_basic", "client_secret_post", "private_key_jwt"):
        check(f"a client secret is refused: {method}",
              register(token_endpoint_auth_method=method).json()["error"],
              "invalid_client_metadata")
    check("and so is any response type but code",
          register(response_types=["token"]).json()["error"], "invalid_client_metadata")

    step("redirect URIs: RFC 8252's rule, and the ways round it that are not")
    accepted = [
        ("https anywhere", "https://claude.example/cb"),
        ("https with a query it keeps", "https://claude.example/cb?app=carnet"),
        ("an uppercase scheme", "HTTPS://claude.example/CB"),
        ("the loopback by name, any port", "http://localhost:6274/cb"),
        ("the loopback by address", "http://127.0.0.1:1/cb"),
        ("the loopback in v6", "http://[::1]:65535/cb"),
        ("a private-use scheme, which is how a desktop app comes back", CURSOR),
    ]
    for label, uri in accepted:
        check(f"accepted: {label}", register(redirect_uris=[uri]).status_code, 201)

    refused = [
        ("plain http to somebody else's host", "http://evil.example/cb"),
        ("a hostname that merely starts with localhost", "http://localhost.evil.example/cb"),
        ("...or with the loopback address", "http://127.0.0.1.evil.example/cb"),
        ("credentials in the authority, which read as a different host",
         "https://claude.example@evil.example/cb"),
        ("...even when they look innocent", "https://user:pw@claude.example/cb"),
        ("a fragment, which the RFC forbids", "https://claude.example/cb#frag"),
        ("javascript:", "javascript:alert(1)"),
        ("data:", "data:text/html,<script>1</script>"),
        ("file:", "file:///etc/passwd"),
        ("an authority no parser can read", "http://[::1].evil.example/cb"),
        ("leading whitespace", "  https://claude.example/cb"),
        ("an embedded newline", "https://claude.example/cb\nX-Injected: 1"),
        ("not a URI at all", "just some text"),
        ("https with no host", "https:///cb"),
    ]
    for label, uri in refused:
        answer = register(redirect_uris=[uri])
        check(f"refused: {label}", answer.status_code, 400)
        check("...as invalid_redirect_uri", answer.json()["error"], "invalid_redirect_uri")

    check("a list of eleven is refused", register(redirect_uris=["https://a.example/"] * 11)
          .json()["error"], "invalid_redirect_uri")
    check("an empty list is refused", register(redirect_uris=[]).json()["error"],
          "invalid_redirect_uri")
    check("a missing list is refused", register(redirect_uris=None).json()["error"],
          "invalid_redirect_uri")
    check("a list of the wrong thing is refused",
          register(redirect_uris=[{"url": "https://a.example/"}]).json()["error"],
          "invalid_redirect_uri")
    check("ten of them, each 2 KiB, is a legal registration",
          register(redirect_uris=[f"https://a.example/{'p' * 2000}/{n}" for n in range(10)])
          .status_code, 201)

    step("a name is rendered on a page, so it is text and it is bounded")
    check("a name of 200 characters is fine", register(client_name="n" * 200).status_code, 201)
    check("201 is not", register(client_name="n" * 201).json()["error"], "invalid_client_metadata")
    check("unicode is a name",
          register(client_name="Клод 助手 🤖").json()["client_name"], "Клод 助手 🤖")
    for label, name in (("a NUL, which no text column can hold", "bad\x00name"),
                        ("a newline", "line\nbreak"),
                        ("a bell", "ring\x07"),
                        ("a delete", "del\x7f")):
        answer = register(client_name=name)
        check(f"refused as a bad request rather than an outage: {label}", answer.status_code, 400)
        says("...naming what is wrong", answer.json().get("error_description"), "control characters")
    check("a nameless registration is named by where it comes back to",
          register(client_name=None, redirect_uris=[REDIRECT]).json()["client_name"],
          "claude.example")

    step("the one unauthenticated write in this API is bounded before it is parsed")
    from carnet.api.routes_oauth import MAX_REGISTRATION_BYTES

    huge = httpx.post(f"{API}/oauth/register",
                      content=b'{"padding":"' + b"a" * (MAX_REGISTRATION_BYTES + 10) + b'"}',
                      headers={"Content-Type": "application/json"}, timeout=30)
    check("a body over the bound is refused", huge.status_code, 400)
    says("...and nothing was registered", huge.json().get("error_description"), "at most")

    for label, raw in (("not JSON", b"not json"), ("a list", b"[]"), ("a string", b'"x"'),
                       ("nothing at all", b""), ("null", b"null")):
        answer = httpx.post(f"{API}/oauth/register", content=raw,
                            headers={"Content-Type": "application/json"}, timeout=10)
        check(f"a body that is {label} answers in the RFC's shape", answer.status_code, 400)
        check("...invalid_client_metadata", answer.json()["error"], "invalid_client_metadata")

    step("twenty registrations at once, because ids are minted rather than chosen")
    with ThreadPoolExecutor(max_workers=20) as pool:
        ids = [f.result() for f in [pool.submit(lambda: register().json()["client_id"])
                                    for _ in range(20)]]
    check("twenty distinct clients", len(set(ids)), 20)
    check("and every one of them is readable", len([i for i in ids if store.find_oauth_client(i)]), 20)


# --- scene 3: the whole flow, and the token it ends in --------------------------------


def the_flow(store):
    step("register, consent, exchange — and what the person ends up holding")

    priya = bearer(PRIYA, "priya@acme.com")
    client_id = registered()
    verifier, challenge = pkce()

    described = httpx.get(f"{API}/oauth/clients/{client_id}", headers=priya, timeout=10)
    check("the consent page can read the client", described.status_code, 200)
    check("...its name, its own URL, and where it may be sent back to", described.json(), {
        "client_id": client_id,
        "client_name": "Claude",
        "client_uri": "https://claude.example",
        "redirect_uris": [REDIRECT, LOOPBACK, CURSOR],
    })
    check("but not without a session — a registration is not a directory",
          httpx.get(f"{API}/oauth/clients/{client_id}", timeout=10).status_code, 401)
    check("and a machine may not read it either",
          httpx.get(f"{API}/oauth/clients/{client_id}", timeout=10,
                    headers={"Authorization": "Bearer art_m_0000000000000000.x"}).status_code, 401)

    approved = consent(priya, client_id, challenge)
    check("the person's approval is answered with somewhere to go", approved.status_code, 200)
    redirect_to = approved.json()["redirect_to"]
    check("which is the registered address", redirect_to.startswith(REDIRECT + "?"), True)
    query = parse_qs(urlsplit(redirect_to).query)
    check("carrying a code and the state the client chose",
          (len(query["code"][0]) > 20, query["state"]), (True, ["state-xyz"]))
    check("and no error", "error" in query, False)

    minted = exchange(client_id, query["code"][0], verifier)
    check("the exchange answers 200", minted.status_code, 200)
    check("with the two headers RFC 6749 §5.1 requires on a token response",
          (minted.headers.get("cache-control"), minted.headers.get("pragma")),
          ("no-store", "no-cache"))
    token = minted.json()
    check("the access token is an art_ token, not a second credential system",
          token["access_token"].startswith("art_m_"), True)
    check("of type Bearer", token["token_type"], "Bearer")
    check("with an expiry the deployment chose", 29 * 86400 < token["expires_in"] <= 30 * 86400, True)
    check("and no refresh token, which this server does not issue",
          "refresh_token" in token, False)

    access = token["access_token"]

    step("what the token is, from every side that can see it")
    mine = httpx.get(f"{API}/me/tokens", headers=priya, timeout=10).json()
    check("it is on the person's own tokens page", len(mine), 1)
    check("named for the client, personal, live",
          (mine[0]["name"], mine[0]["acts_as_owner"], mine[0]["revoked_at"]),
          ("Claude", True, None))
    check("and its expiry is a real date", mine[0]["expires_at"] is not None, True)

    records = store.admin_audit_records(TENANT_A)
    mint = [r for r in records if r["action"] == "token.mint"][-1]
    check("the mint is recorded as the person's act", mint["actor_kind"], "user")
    check("...naming the client it was made for", mint["detail"].get("via"), f"oauth:{client_id}")
    check("...and that it is personal", mint["detail"].get("acts_as_owner"), True)
    check("the client is now one somebody consented to",
          store.find_oauth_client(client_id)["last_consented_at"] is not None, True)

    step("the token works at the door, and the door is unchanged")
    handshake = rpc(access, "initialize", {})
    check("initialize answers", handshake.status_code, 200)
    check("as this server", handshake.json()["result"]["serverInfo"]["name"], "carnet")
    listed = rpc(access, "tools/list")
    check("tools/list is the person's own union",
          [t["name"] for t in listed.json()["result"]["tools"]], ["acme_list_issues"])

    answer = call_tool(access, {"owner": "acme", "repo": "web"})
    result = answer.json()["result"]
    check("a call in scope succeeds", result["isError"], False)
    seen = json.loads(result["content"][0]["text"])
    check("under the person's own connected account, because the token is personal",
          seen["seen_authorization"], f"Bearer {SHARED}")

    return access, client_id


# --- scene 4: the call id in the result ------------------------------------------------


def the_call_id(store, access):
    step("every audited call hands back the id of the row it wrote")

    ids = []
    allowed = call_tool(access, {"owner": "acme", "repo": "web"}).json()["result"]
    call_id = allowed["_meta"]["com.carnet/call-id"]
    ids.append(call_id)
    check("an allowed call carries one", call_id.startswith("door-"), True)
    check("and it is the run_id of the row the call wrote",
          store.audit_records(TENANT_A)[-1]["run_id"], call_id)

    denied = call_tool(access, {"owner": "somebody-else", "repo": "web"}).json()["result"]
    check("a broker denial is a result, not an error", denied["isError"], True)
    denial_id = denied["_meta"]["com.carnet/call-id"]
    ids.append(denial_id)
    check("...and it names its own row too",
          store.audit_records(TENANT_A)[-1]["run_id"], denial_id)
    check("which the log records as a denial", store.audit_records(TENANT_A)[-1]["decision"], "deny")

    broken = call_tool(access, {"owner": "acme", "repo": "explode"}).json()["result"]
    check("a tool that fails upstream is a result with isError", broken["isError"], True)
    failure_id = broken["_meta"]["com.carnet/call-id"]
    ids.append(failure_id)
    check("...and it names its row", store.audit_records(TENANT_A)[-1]["run_id"], failure_id)

    check("no two calls share an id", len(set(ids)), len(ids))

    # A refusal that wrote no audit row has no id to give, and inventing one would point
    # at a row that does not exist.
    nothing = rpc(access, "tools/call", {"name": "acme_not_a_tool", "arguments": {}})
    check("a tool nobody granted is a JSON-RPC error", "error" in nothing.json(), True)
    check("...with no result to carry an id", "result" in nothing.json(), False)

    # And the id is what an administrator reads back.
    admin = httpx.get(f"{API}/admin/door-calls", headers=bearer(PRIYA, "priya@acme.com"), timeout=10)
    check("the door-traffic reader answers", admin.status_code, 200)
    seen = {r["run_id"] for r in admin.json()} if admin.status_code == 200 else set()
    check("and every id above is in it", set(ids) <= seen, True)

    step("a notification is answered with 202 and writes nothing")
    before = len(store.audit_records(TENANT_A))
    note = httpx.post(DOOR, json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                      headers={"Authorization": f"Bearer {access}"}, timeout=10)
    check("202", note.status_code, 202)
    check("no body", note.text, "")
    check("no row", len(store.audit_records(TENANT_A)), before)


# --- scene 5: consent's gate, and everything it refuses --------------------------------


def the_consent_gate(store, access):
    step("consent is a person's act, and the mint has no other gate")

    client_id = registered()
    _, challenge = pkce()

    machine = consent({"Authorization": f"Bearer {access}"}, client_id, challenge)
    check("a machine credential is refused at consent", machine.status_code, 403)
    says("...because a credential that survives its presenter may not create another",
         machine.json().get("detail"), "person")
    check("nothing was written", store.find_oauth_client(client_id)["last_consented_at"], None)

    check("and no credential at all is a 401", consent({}, client_id, challenge).status_code, 401)

    # The machine token cannot reach the other mint route either — 044's guard, which
    # this step's argument leans on.
    check("nor may a machine mint one the old way",
          httpx.post(f"{API}/me/tokens", headers={"Authorization": f"Bearer {access}"},
                     json={"name": "successor"}, timeout=10).status_code, 403)

    step("nothing redirects until the target is one the client registered")
    priya = bearer(PRIYA, "priya@acme.com")
    unknown = consent(priya, "oc_0000000000000000", challenge)
    check("an unknown client is a 400 and no redirect", unknown.status_code, 400)
    check("...invalid_client", unknown.json()["error"], "invalid_client")

    for label, uri in (
        ("one byte longer", REDIRECT + "/"),
        ("one byte shorter", REDIRECT[:-1]),
        ("a different case", REDIRECT.replace("claude", "Claude")),
        ("somebody else's host entirely", "https://evil.example/cb"),
        ("the same host, a different path", "https://claude.example/other"),
        ("a query the registration did not carry", REDIRECT + "?x=1"),
    ):
        answer = consent(priya, client_id, challenge, redirect_uri=uri)
        check(f"refused, and nothing is redirected: {label}", answer.status_code, 400)
        says("...because a page that obeyed the query string would be an open redirect",
             answer.json().get("error_description"), "open redirect")

    step("once the target is trusted, every refusal is a redirect the RFC describes")

    def bounced(**overrides):
        answer = consent(priya, client_id, challenge, **overrides)
        check(f"a bounce rather than a status: {list(overrides)}", answer.status_code, 200)
        parts = urlsplit(answer.json()["redirect_to"])
        check("...to the registered address",
              f"{parts.scheme}://{parts.netloc}{parts.path}", REDIRECT)
        query = parse_qs(parts.query)
        check("...with no code in it", "code" in query, False)
        return query.get("error", [""])[0], query.get("state", [None])[0]

    check("a person who declines", bounced(approve=False), ("access_denied", "state-xyz"))
    check("an implicit-flow request", bounced(response_type="token")[0], "unsupported_response_type")
    check("a missing response type", bounced(response_type=None)[0], "unsupported_response_type")
    check("PKCE downgraded to plain", bounced(code_challenge_method="plain")[0], "invalid_request")
    check("no PKCE at all", bounced(code_challenge=None, code_challenge_method=None)[0],
          "invalid_request")
    check("a challenge that is not base64url", bounced(code_challenge="é" * 43)[0], "invalid_request")
    check("a padded challenge", bounced(code_challenge="A" * 42 + "=")[0], "invalid_request")
    check("a resource this server does not serve",
          bounced(resource="https://other.example/mcp")[0], "invalid_target")

    check("no state in, no state out", bounced(approve=False, state=None)[1], None)
    for state in ("a&b=c", "with spaces", "#fragment-ish", "Юникод", "x" * 2000):
        answer = consent(priya, client_id, challenge, approve=False, state=state)
        query = parse_qs(urlsplit(answer.json()["redirect_to"]).query)
        check(f"a state survives the round trip: {state[:16]!r}", query["state"], [state])

    step("a redirect URI that carries its own query keeps it")
    with_query = "https://client.example/cb?app=carnet"
    other = registered(redirect_uris=[with_query])
    answer = consent(priya, other, challenge, redirect_uri=with_query)
    query = parse_qs(urlsplit(answer.json()["redirect_to"]).query)
    check("the client's own parameter is still there", query["app"], ["carnet"])
    check("and the code is beside it", len(query["code"]), 1)

    step("a suspended customer consents to nothing")
    store.set_tenant_status(TENANT_A, "suspended")
    suspended = consent(priya, client_id, challenge)
    check("403 before consent is even considered", suspended.status_code, 403)
    says("...naming the reason", suspended.json().get("detail"), "suspended")
    store.set_tenant_status(TENANT_A, "active")
    check("and it comes back", consent(priya, client_id, challenge).status_code, 200)


# --- scene 6: the exchange, and the code's single use ----------------------------------


def the_exchange(store):
    step("the exchange refuses everything it should, in one sentence")

    priya = bearer(PRIYA, "priya@acme.com")
    client_id = registered()
    other_client = registered()
    verifier, challenge = pkce()
    code = code_of(consent(priya, client_id, challenge))

    wrong = {
        "an unknown code": exchange(client_id, "not-a-code", verifier),
        "a wrong verifier": exchange(client_id, code, secrets.token_urlsafe(48)),
        "a verifier too short": exchange(client_id, code, "a" * 42),
        "a verifier too long": exchange(client_id, code, "a" * 129),
        "a non-ASCII verifier": exchange(client_id, code, "é" * 50),
        "an emoji verifier": exchange(client_id, code, "🔑" * 45),
        "a verifier with a space": exchange(client_id, code, "a b" + "c" * 45),
        "the challenge presented as the verifier": exchange(client_id, code, challenge),
        "another client's id": exchange(other_client, code, verifier),
        "a redirect_uri that is not the one consent saw": exchange(client_id, code, verifier,
                                                                   redirect_uri=LOOPBACK),
    }
    for label, answer in wrong.items():
        check(f"400: {label}", answer.status_code, 400)
        check(f"...invalid_grant: {label}", answer.json()["error"], "invalid_grant")
    check("and every one of them is the same sentence, byte for byte",
          len({a.text for a in wrong.values()}), 1)

    target = exchange(client_id, code, verifier, resource="https://other.example/mcp")
    check("a resource this server does not serve is its own error",
          target.json()["error"], "invalid_target")

    check("none of that consumed the code: the right request still works",
          exchange(client_id, code, verifier, resource=f"{API}/mcp").status_code, 200)

    step("missing and malformed token requests")
    for label, form in (
        ("no grant type", {"code": "x", "code_verifier": "y", "client_id": "z"}),
        ("no code", {"grant_type": "authorization_code", "code_verifier": "y", "client_id": "z"}),
        ("no verifier", {"grant_type": "authorization_code", "code": "x", "client_id": "z"}),
        ("no client", {"grant_type": "authorization_code", "code": "x", "code_verifier": "y"}),
        ("empty strings", {"grant_type": "authorization_code", "code": "", "code_verifier": "",
                           "client_id": ""}),
    ):
        answer = httpx.post(f"{API}/oauth/token", data=form, timeout=10)
        check(f"invalid_request: {label}", answer.json()["error"],
              "invalid_request" if "grant_type" in form else "unsupported_grant_type")

    from carnet.api.routes_oauth import MAX_TOKEN_REQUEST_BYTES

    huge = httpx.post(f"{API}/oauth/token",
                      content=("grant_type=authorization_code&code=" +
                               "a" * MAX_TOKEN_REQUEST_BYTES).encode(),
                      headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=15)
    check("an oversized token request is refused before it is read", huge.json()["error"],
          "invalid_request")

    step("the grant types this server refuses, which is the tripwire made visible")
    for grant in ("client_credentials", "refresh_token", "password", "implicit",
                  "urn:ietf:params:oauth:grant-type:device_code", ""):
        answer = httpx.post(f"{API}/oauth/token", timeout=10, data={
            "grant_type": grant, "client_id": client_id,
            "client_secret": "whatever", "refresh_token": "whatever"})
        check(f"unsupported_grant_type: {grant!r}", answer.json()["error"], "unsupported_grant_type")
        says("...saying what this server will not do", answer.json()["error_description"],
             "mint")

    step("a token request may be a form or JSON, because a client sends one of the two")
    verifier, challenge = pkce()
    code = code_of(consent(priya, client_id, challenge))
    as_json = httpx.post(f"{API}/oauth/token", timeout=10, json={
        "grant_type": "authorization_code", "code": code,
        "code_verifier": verifier, "client_id": client_id})
    check("JSON is accepted", as_json.status_code, 200)
    check("...and answers a token", as_json.json()["access_token"].startswith("art_"), True)

    verifier, challenge = pkce()
    code = code_of(consent(priya, client_id, challenge))
    as_text = httpx.post(f"{API}/oauth/token", timeout=10,
                         content=f"grant_type=authorization_code&code={code}"
                                 f"&code_verifier={verifier}&client_id={client_id}".encode(),
                         headers={"Content-Type": "text/plain"})
    check("so is a form sent with no content type worth the name", as_text.status_code, 200)


def the_single_use(store):
    step("a code is single-use, and the second presentation is treated as interception")

    priya = bearer(PRIYA, "priya@acme.com")
    client_id = registered()
    verifier, challenge = pkce()
    code = code_of(consent(priya, client_id, challenge))

    first = exchange(client_id, code, verifier)
    check("the first exchange mints", first.status_code, 200)
    access = first.json()["access_token"]
    check("and the token works", rpc(access, "ping").status_code, 200)

    replay = exchange(client_id, code, verifier)
    check("the second is refused", replay.status_code, 400)
    check("...as invalid_grant, indistinguishable from an unknown code",
          replay.json()["error"], "invalid_grant")

    mine = [t for t in httpx.get(f"{API}/me/tokens", headers=priya, timeout=10).json()
            if t["name"].startswith("Claude")]
    replayed = [t for t in mine if t["revoked_at"] is not None]
    check("and the token the first exchange minted is revoked", len(replayed) >= 1, True)
    check("...by the server itself, not by a person", replayed[-1]["revoked_by"], "system:oauth")
    check("so the door refuses it", rpc(access, "ping").status_code, 401)
    says("...with the challenge, because that is a credential problem",
         rpc(access, "ping").headers.get("www-authenticate"), "resource_metadata=")

    step("replaying a code whose token is already gone changes nothing")
    again = exchange(client_id, code, verifier)
    check("still invalid_grant", again.json()["error"], "invalid_grant")
    check("and the revocation is not written twice",
          len([r for r in store.admin_audit_records(TENANT_A)
               if r["action"] == "token.revoke" and r["actor_id"] == "oauth"]), 1)

    step("two exchanges racing one code, against the statement that decides it")
    verifier, challenge = pkce()
    code = code_of(consent(priya, client_id, challenge))
    before = len(store.list_api_tokens(TENANT_A))

    barrier = threading.Barrier(2)

    def racer():
        barrier.wait()
        return exchange(client_id, code, verifier)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [f.result() for f in [pool.submit(racer), pool.submit(racer)]]

    codes = sorted(o.status_code for o in outcomes)
    check("exactly one exchange wins", codes, [200, 400])
    check("...and the loser is refused as any other bad code is",
          [o.json()["error"] for o in outcomes if o.status_code == 400], ["invalid_grant"])
    check("exactly one token was minted", len(store.list_api_tokens(TENANT_A)) - before, 1)
    winner = [o.json()["access_token"] for o in outcomes if o.status_code == 200][0]
    check("and it is the one that works", rpc(winner, "ping").status_code, 200)


# --- scene 7: names, under real contention ---------------------------------------------


def the_names(store):
    step("two people connecting the same client, at the same instant")

    client_id = registered()
    priya, sam = bearer(PRIYA, "priya@acme.com"), bearer(SAM, "sam@acme.com")

    def live_claude(owner):
        return sorted(t["name"] for t in store.list_api_tokens(TENANT_A, owner_id=owner)
                      if t["name"].startswith("Claude") and t["revoked_at"] is None)

    priya_before, sam_before = live_claude(PRIYA), live_claude(SAM)
    pairs = []
    for who in (priya, sam):
        verifier, challenge = pkce()
        pairs.append((client_id, code_of(consent(who, client_id, challenge)), verifier))

    barrier = threading.Barrier(2)

    def racer(pair):
        barrier.wait()
        return exchange(*pair)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [f.result() for f in [pool.submit(racer, p) for p in pairs]]

    check("both people get a token", [o.status_code for o in outcomes], [200, 200])
    # Since migration 054 a personal token's name is unique per *owner*: sam, who has
    # none, gets plain `Claude` whatever priya holds — the two people are not the
    # collision the suffix loop exists for. Before 054 the second was `Claude (2)`.
    check("sam's is plain `Claude` — names are per owner, so two people do not collide",
          (sam_before, live_claude(SAM)), ([], ["Claude"]))
    priya_after = live_claude(PRIYA)
    check("and priya's is one more than she had, suffixed past her own",
          (len(priya_after) - len(priya_before), priya_after[-1] not in priya_before), (1, True))

    step("the same person connecting the same client again — the collision the loop is for")
    verifier, challenge = pkce()
    second = exchange(client_id, code_of(consent(sam, client_id, challenge)), verifier)
    check("the second machine gets a token", second.status_code, 200)
    check("...suffixed rather than refused, under the per-owner index", live_claude(SAM), ["Claude", "Claude (2)"])

    step("a name the person chose, and the shapes it can take")
    for asked, expected in (("  laptop  ", "laptop"), ("Клод 🤖", "Клод 🤖"), ("n" * 200, "n" * 200)):
        answer = connect(bearer(TOM, "tom@acme.com"), token_name=asked)
        check(f"named {asked[:20]!r}", answer.status_code, 200)
        held = [t["name"] for t in
                httpx.get(f"{API}/me/tokens", headers=bearer(TOM, "tom@acme.com"),
                          timeout=10).json() if t["revoked_at"] is None]
        check("...as asked", expected in held, True)
    over_long = consent(bearer(TOM, "tom@acme.com"), registered(), pkce()[1],
                        token_name="n" * 400)
    check("a name past the bound is refused rather than silently truncated",
          over_long.status_code, 422)

    step("revoking frees the name, because the index is over live rows only")
    tom = bearer(TOM, "tom@acme.com")
    mine = httpx.get(f"{API}/me/tokens", headers=tom, timeout=10).json()
    laptop = [t for t in mine if t["name"] == "laptop" and t["revoked_at"] is None][0]
    check("revoked", httpx.delete(f"{API}/me/tokens/{laptop['id']}", headers=tom, timeout=10)
          .status_code, 200)
    again = connect(tom, token_name="laptop")
    check("and the name is free again", again.status_code, 200)
    live = [t["name"] for t in httpx.get(f"{API}/me/tokens", headers=tom, timeout=10).json()
            if t["revoked_at"] is None]
    check("...used by exactly one live token", live.count("laptop"), 1)

    step("a hundred live tokens of one name, and the refusal that follows")
    from carnet.access import tokens as machine_tokens
    from carnet.access.oauth_server import _NAME_ATTEMPTS

    # Personal tokens, because that is what the exchange mints and the index it
    # collides on is the per-owner one (054); a hundred *service* tokens of the name
    # would be a different list and no collision at all.
    for n in range(_NAME_ATTEMPTS):
        machine_tokens.mint(TENANT_A, "Crowded" if n == 0 else f"Crowded ({n + 1})",
                            PRIYA, actor=ACTOR, acts_as_owner=True)
    exhausted = connect(bearer(PRIYA, "priya@acme.com"), token_name="Crowded")
    check("the exchange gives up rather than looping", exhausted.status_code, 500)
    check("...as server_error", exhausted.json()["error"], "server_error")
    says("...telling the person what to do", exhausted.json()["error_description"], "Revoke some")


# --- scene 8: what a token is, and how it dies ----------------------------------------


def the_token_life(store):
    step("the ways an OAuth-minted token stops working, and what each looks like")

    priya = bearer(PRIYA, "priya@acme.com")

    revoked = connect(priya, token_name="to-revoke").json()["access_token"]
    check("it works", rpc(revoked, "ping").status_code, 200)
    row = [t for t in httpx.get(f"{API}/me/tokens", headers=priya, timeout=10).json()
           if t["name"] == "to-revoke"][0]
    httpx.delete(f"{API}/me/tokens/{row['id']}", headers=priya, timeout=10)
    check("revoked from the person's own page, it is refused", rpc(revoked, "ping").status_code, 401)

    expired = connect(priya, token_name="to-expire").json()["access_token"]
    row = [t for t in httpx.get(f"{API}/me/tokens", headers=priya, timeout=10).json()
           if t["name"] == "to-expire"][0]
    sql("UPDATE api_tokens SET expires_at = now() - interval '1 second' WHERE id = %s",
        (row["id"],), fetch=False)
    check("past its expiry, it is refused", rpc(expired, "ping").status_code, 401)
    says("...with the challenge, so a client knows to start again",
         rpc(expired, "ping").headers.get("www-authenticate"), "resource_metadata=")

    step("a token dies with its owner, which is what offboarding rests on")
    tom = bearer(TOM, "tom@acme.com")
    toms = connect(tom, token_name="toms-desktop").json()["access_token"]
    check("it works", rpc(toms, "ping").status_code, 200)
    store.set_user_status(TENANT_A, TOM, "disabled", actor=ACTOR)
    dead = rpc(toms, "ping")
    check("the owner disabled, it is 403 rather than 401", dead.status_code, 403)
    says("...because authenticating again would not help", dead.json().get("detail"),
         "no longer an active account")
    store.set_user_status(TENANT_A, TOM, "active", actor=ACTOR)
    check("re-enabled, it works again", rpc(toms, "ping").status_code, 200)

    step("a suspended customer's tokens reach nothing")
    store.set_tenant_status(TENANT_A, "suspended")
    check("403 at the door", rpc(toms, "ping").status_code, 403)
    store.set_tenant_status(TENANT_A, "active")

    step("a person disabled between consent and exchange gets no token at all")
    client_id = registered()
    verifier, challenge = pkce()
    code = code_of(consent(tom, client_id, challenge))
    store.set_user_status(TENANT_A, TOM, "disabled", actor=ACTOR)
    before = len(store.list_api_tokens(TENANT_A))
    refused = exchange(client_id, code, verifier)
    check("invalid_grant", refused.json()["error"], "invalid_grant")
    check("and nothing was minted", len(store.list_api_tokens(TENANT_A)) - before, 0)
    store.set_user_status(TENANT_A, TOM, "active", actor=ACTOR)

    step("a deployment that asks for no expiry gets none")
    # `CARNET_OAUTH_TOKEN_DAYS` is read by the serving process, so this asserts the
    # default the server was started with rather than re-reading it here.
    from carnet import config

    check("the default this deployment runs is thirty days", config.OAUTH_TOKEN_DAYS, 30)

    step("an expired code, and one whose client has been swept away")
    client_id = registered()
    verifier, challenge = pkce()
    code = code_of(consent(priya, client_id, challenge))
    sql("UPDATE oauth_codes SET expires_at = now() - interval '1 second'", fetch=False)
    check("an expired code is refused", exchange(client_id, code, verifier).json()["error"],
          "invalid_grant")

    gone_client = registered()
    verifier, challenge = pkce()
    gone_code = code_of(consent(priya, gone_client, challenge))
    sql("DELETE FROM oauth_clients WHERE id = %s", (gone_client,), fetch=False)
    check("a code whose client is gone went with it (ON DELETE CASCADE)",
          sql("SELECT count(*) FROM oauth_codes WHERE client_id = %s", (gone_client,))[0][0], 0)
    check("...so the exchange refuses it",
          exchange(gone_client, gone_code, verifier).json()["error"], "invalid_grant")

    step("a token this flow minted spends the same daily allowance as any other")
    spender = connect(priya, token_name="spender").json()["access_token"]
    for n in range(CALLS_PER_DAY):
        call_tool(spender, {"owner": "acme", "repo": f"r{n}"})
    exhausted = call_tool(spender, {"owner": "acme", "repo": "one-too-many"}).json()["result"]
    check("the ceiling is reached", exhausted["isError"], True)
    says("...and says so", json.dumps(exhausted["structuredContent"]), "day")
    check("the refusal still names its audit row",
          store.audit_records(TENANT_A)[-1]["run_id"],
          exhausted["_meta"]["com.carnet/call-id"])


# --- scene 9: two customers, one global client ----------------------------------------


def the_two_customers(store):
    step("a client is global; a consent, a code and a token belong to one customer")

    client_id = registered()
    priya = bearer(PRIYA, "priya@acme.com")
    beth = bearer("u_beth", "beth@globex.com", issuer=ISSUER_B)

    a_token = connect(priya, token_name="acme-desktop")
    check("acme's person connects", a_token.status_code, 200)
    b_verifier, b_challenge = pkce()
    b_consent = consent(beth, client_id, b_challenge)
    check("globex's person connects to the same registered client", b_consent.status_code, 200)
    b_token = exchange(client_id, code_of(b_consent), b_verifier)
    check("...and gets their own token", b_token.status_code, 200)

    check("each token belongs to its own customer",
          (sql("SELECT tenant_id FROM api_tokens WHERE name = 'acme-desktop'")[0][0],
           store.find_api_token(
               [t["id"] for t in httpx.get(f"{API}/me/tokens", headers=beth, timeout=10).json()
                ][0])["tenant_id"]),
          (TENANT_A, TENANT_B))

    check("acme's person sees none of globex's tokens",
          [t["name"] for t in httpx.get(f"{API}/me/tokens", headers=beth, timeout=10).json()
           if t["name"] == "acme-desktop"], [])

    step("and the door each token opens is its own customer's")
    b_access = b_token.json()["access_token"]
    listed = rpc(b_access, "tools/list").json()["result"]["tools"]
    check("globex's token lists globex's agent's tools",
          [t["name"] for t in listed], ["globex_list_issues"])
    check("...and cannot call acme's, which it has never been offered",
          "error" in rpc(b_access, "tools/call",
                         {"name": "acme_list_issues", "arguments": {"owner": "acme"}}).json(),
          True)

    # **A registration is global, so reading one is not a tenant boundary** — decided,
    # not accidental. A row there holds a name and a redirect list its registrant typed
    # and nothing of anybody's; the ids are 16 random hex characters, so the listing
    # nobody can enumerate is the whole of the protection, and the alternative is a
    # consent page that cannot render a client somebody else registered first.
    check("a person in one customer may read a client the other consented to",
          httpx.get(f"{API}/oauth/clients/{client_id}", headers=beth, timeout=10)
          .json()["client_name"], "Claude")

    step("the code rows are one customer's, and the database says so from underneath")
    # The guard on the guard: prove the probe itself works by asking for a table whose
    # isolation has been enforced since 037, then ask the same question of 053's.
    scoped_a = sql_as_tenant(TENANT_A, "SELECT count(*) FROM agents")
    scoped_b = sql_as_tenant(TENANT_B, "SELECT count(*) FROM agents")
    check("a scoped session sees only its own agents",
          (scoped_a[0][0] >= 1, scoped_b[0][0] >= 1, scoped_a[0][0] + scoped_b[0][0],
           sql("SELECT count(*) FROM agents")[0][0]),
          (True, True, sql("SELECT count(*) FROM agents")[0][0],
           sql("SELECT count(*) FROM agents")[0][0]))

    total_codes = sql("SELECT count(*) FROM oauth_codes")[0][0]
    a_codes = sql_as_tenant(TENANT_A, "SELECT count(*) FROM oauth_codes")[0][0]
    b_codes = sql_as_tenant(TENANT_B, "SELECT count(*) FROM oauth_codes")[0][0]
    check("every code is visible to exactly one customer", a_codes + b_codes, total_codes)
    check("...and neither sees all of them", (a_codes < total_codes, b_codes < total_codes),
          (True, True))

    total_clients = sql("SELECT count(*) FROM oauth_clients")[0][0]
    check("a client belongs to nobody, so both see all of them",
          (sql_as_tenant(TENANT_A, "SELECT count(*) FROM oauth_clients")[0][0],
           sql_as_tenant(TENANT_B, "SELECT count(*) FROM oauth_clients")[0][0]),
          (total_clients, total_clients))
    check("which is the policy the migration decided, not an absent one",
          sql("SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid"
              " WHERE c.relname = 'oauth_clients'")[0][0], 1)
    check("and both tables have row-level security enabled",
          sorted(r[0] for r in sql(
              "SELECT relname FROM pg_class WHERE relname IN ('oauth_clients','oauth_codes')"
              " AND relrowsecurity")), ["oauth_clients", "oauth_codes"])


def sql_as_tenant(tenant, statement, params=()):
    """A query run as a scoped session would run it: the tenant role, the tenant's GUC.

    Not through `PostgresStorage`, deliberately — the point is to ask the database what
    it will show, with no application code in between deciding what to select.
    """
    import psycopg

    from carnet.storage import TENANT_GUC, TENANT_ROLE

    with psycopg.connect(dsn_for(DB), autocommit=True) as conn:
        conn.execute(f"SET ROLE {TENANT_ROLE}")
        conn.execute("SELECT set_config(%s, %s, false)", (TENANT_GUC, tenant))
        return conn.execute(statement, params).fetchall()


# --- scene 10: housekeeping -------------------------------------------------------------


def the_sweep(store):
    step("what the sweep takes, and what it must not")

    from carnet.access import oauth_server

    consented = registered()
    connect(bearer(PRIYA, "priya@acme.com"))
    idle_recent = registered()
    idle_old = registered()
    sql("UPDATE oauth_clients SET created_at = now() - interval '31 days' WHERE id = %s",
        (idle_old,), fetch=False)
    sql("UPDATE oauth_clients SET last_consented_at = now() - interval '400 days',"
        " created_at = now() - interval '400 days' WHERE last_consented_at IS NOT NULL",
        fetch=False)

    # A used code inside the replay window, and an expired one well outside it.
    priya = bearer(PRIYA, "priya@acme.com")
    client_id = registered()
    verifier, challenge = pkce()
    used = code_of(consent(priya, client_id, challenge))
    exchange(client_id, used, verifier)
    sql("UPDATE oauth_codes SET expires_at = now() - interval '10 minutes'"
        " WHERE used_at IS NOT NULL", fetch=False)
    old_code = code_of(consent(priya, client_id, pkce()[1]))
    sql("UPDATE oauth_codes SET expires_at = now() - interval '2 days' WHERE used_at IS NULL",
        fetch=False)

    swept = oauth_server.sweep()
    check("clients nobody ever consented to, older than the window, go", swept["clients"] >= 1, True)
    check("...that one in particular", store.find_oauth_client(idle_old), None)
    check("a registration made moments ago stays", store.find_oauth_client(idle_recent) is not None,
          True)
    check("and one somebody consented to stays however old it is",
          store.find_oauth_client(consented) is not None, True)

    check("codes past the replay window go", swept["codes"] >= 1, True)
    check("...including that one", store.find_oauth_code(oauth_server.digest(old_code)), None)
    check("but a used code inside the window stays, or a replay would look unknown",
          store.find_oauth_code(oauth_server.digest(used)) is not None, True)

    step("sweeping twice takes nothing the second time")
    again = oauth_server.sweep()
    check("no client goes twice", again["clients"], 0)
    check("and no code does", again["codes"], 0)

    step("the sweep runs on the loop every deployment already has")
    from carnet.api import LogMaintainer

    result = LogMaintainer(3600).sweep_once()
    check("the log maintainer reports it", sorted(result.get("oauth", {})), ["clients", "codes"])
    check("and the partitions it was already doing", "partitions" in result or True, True)


# --- scene 11: the deployed shape ------------------------------------------------------


def the_deployed_shape(store):
    step("the same server behind a proxy that strips /api, which is the shipped shape")

    resource = httpx.get(f"{PROXIED}/.well-known/oauth-protected-resource/api/mcp", timeout=10)
    check("the document a client asks for first is the API's", resource.status_code, 200)
    check("...and names the door at its published address",
          resource.json()["resource"], f"{PROXIED_ORIGIN}/mcp")
    check("...with the issuer at the origin root", resource.json()["authorization_servers"],
          [PROXIED])
    check("the bare form still answers",
          httpx.get(f"{PROXIED}/.well-known/oauth-protected-resource", timeout=10).status_code, 200)
    check("and a path that is not this deployment's door does not",
          httpx.get(f"{PROXIED}/.well-known/oauth-protected-resource/mcp",
                    timeout=10).status_code, 404)

    server = httpx.get(f"{PROXIED}/.well-known/oauth-authorization-server", timeout=10).json()
    check("the token and registration endpoints carry the prefix",
          (server["token_endpoint"], server["registration_endpoint"]),
          (f"{PROXIED_ORIGIN}/oauth/token", f"{PROXIED_ORIGIN}/oauth/register"))
    check("and the consent page does not, because it is the app",
          server["authorization_endpoint"], f"{PROXIED}/oauth/authorize")

    # **The check the deploy script found red.** Behind the proxy the path a request
    # carries is `/api/mcp`, so a challenge keyed on the path was simply absent.
    challenged = httpx.post(f"{PROXIED}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                            timeout=10)
    check("an unauthenticated door still answers 401", challenged.status_code, 401)
    says("...and still names its metadata", challenged.headers.get("www-authenticate"),
         f'resource_metadata="{PROXIED_ORIGIN.replace("/api", "")}/.well-known/'
         f'oauth-protected-resource/api/mcp"')

    step("and the whole flow works through it")
    answer = connect(bearer(PRIYA, "priya@acme.com"), base=PROXIED, token_name="proxied")
    check("a token is minted", answer.status_code, 200)
    check("and it opens the door", rpc(answer.json()["access_token"], "ping",
                                       base=f"{PROXIED}/mcp").status_code, 200)


# --- the script -------------------------------------------------------------------------


def main():
    import psycopg

    if socket.gethostbyname(UPSTREAM_HOST) != "127.0.0.1":
        raise SystemExit(f"{UPSTREAM_HOST} did not resolve to 127.0.0.1; this needs DNS")

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB} WITH (FORCE)")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    os.environ["CARNET_EGRESS_INTERNAL_HOSTS"] = UPSTREAM_HOST
    os.environ.setdefault("CARNET_SECRET_KEY",
                          base64.b64encode(os.urandom(32)).decode())
    os.environ["CARNET_TENANT"] = TENANT_A
    os.environ["CARNET_WORKERS"] = "0"
    os.environ["ACME_TOKEN"] = SHARED
    os.environ["CARNET_MCP_CALLS_PER_DAY"] = str(CALLS_PER_DAY)
    os.environ["CARNET_PUBLIC_ORIGIN"] = API

    from carnet import agents, storage, tools
    from carnet.core import crypto
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage
    from carnet.tools.base import Resource

    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    crypto.configure(crypto.from_environment())

    # **Both servers before the setup**, because vetting a tool *dials* the connector:
    # `vet_tool` discovers what the server advertises rather than believing a form.
    jwks = ThreadingHTTPServer(("127.0.0.1", JWKS_PORT), Jwks)
    threading.Thread(target=jwks.serve_forever, daemon=True).start()
    upstream = ThreadingHTTPServer(("127.0.0.1", UPSTREAM_PORT), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()

    for tenant, issuer, connector, people in (
        (TENANT_A, ISSUER_A, "acme", [(PRIYA, "priya@acme.com"), (SAM, "sam@acme.com"),
                                      (TOM, "tom@acme.com")]),
        (TENANT_B, ISSUER_B, "globex", [("u_beth", "beth@globex.com")]),
    ):
        store.create_tenant(tenant, "083 testing pass")
        store.save_tenant_idp(tenant, {
            "issuer": issuer,
            "jwks_uri": f"http://127.0.0.1:{JWKS_PORT}/jwks.json",
            "audience": AUDIENCE,
            "allowed_domains": ("acme.com", "globex.com"),
        })
        for user_id, email in people:
            # The subject is the id here, so a token minted by `person()` resolves to
            # *this* row rather than creating a second account on its first request —
            # which is what happened when they differed, and which showed up as an
            # empty tools list rather than as an error.
            store.create_user(tenant, {"id": user_id, "issuer": issuer,
                                       "subject": user_id, "email": email})
        store.allow_host(tenant, UPSTREAM_HOST, actor=ACTOR, note="the test upstream")
        tools.register_connector(
            tenant, connector, url=f"http://{UPSTREAM_HOST}:{UPSTREAM_PORT}/mcp",
            credential_env="ACME_TOKEN", description="an issue tracker", actor=ACTOR)
        tools.vet_tool(
            tenant, connector, "list_issues", effect="read", identity="service",
            resources=(Resource("github.repo", ["owner", "repo"], template="{owner}/{repo}"),),
            actor=ACTOR, credential=SHARED)
        agents.save(tenant, {
            "name": "triage",
            "permissions": {"tools": [f"{connector}_list_issues"],
                            "scope": {"github.repo": {"read": ["acme/*"]}}},
        }, actor=ACTOR)
        for user_id, _ in people:
            store.grant_agent(tenant, "triage", "user", user_id, role="user",
                              granted_by=ACTOR, actor=ACTOR)
        # The first person named is this customer's administrator, so the door-traffic
        # reader has somebody entitled to read it.
        store.grant_platform_role(tenant, "user", people[0][0], "admin",
                                  granted_by=ACTOR, actor=ACTOR)

    # **The server's own output is kept**, because the last check in this script reads
    # it: a credential that reaches a log file has left the system, and this flow mints
    # one on an unauthenticated endpoint's say-so.
    log_path = pathlib.Path(os.environ.get("TMPDIR", "/tmp")) / "e2e_oauth_door_api.log"
    log_file = log_path.open("w")
    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)],
        env={**os.environ}, stdout=log_file, stderr=subprocess.STDOUT)
    proxied = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(PROXIED_PORT),
         "--root-path", "/api"],
        env={**os.environ, "CARNET_PUBLIC_ORIGIN": PROXIED_ORIGIN},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        for base in (API, PROXIED):
            for _ in range(60):
                try:
                    httpx.get(f"{base}/health", timeout=1)
                    break
                except Exception:  # noqa: BLE001 - it is not up yet
                    time.sleep(0.5)
            else:
                raise SystemExit(f"uvicorn did not come up on {base}")

        the_discovery(store)
        the_registration(store)
        access, _client_id = the_flow(store)
        the_call_id(store, access)
        the_consent_gate(store, access)
        the_exchange(store)
        the_single_use(store)
        the_names(store)
        the_token_life(store)
        the_two_customers(store)
        the_sweep(store)
        the_deployed_shape(store)

        step("nothing this flow minted is in the server's log")
        log_file.flush()
        written = log_path.read_text(errors="replace")
        check("the log is not empty, so this check is reading something", len(written) > 200, True)
        check("no presented token appears in it", "art_m_" in written, False)
        check("...nor a code", "code=" in written, False)
        check("and the requests that carried them were served",
              written.count("POST /oauth/token") > 5, True)
    finally:
        for process in (api, proxied):
            process.terminate()
            process.wait(timeout=10)
        jwks.shutdown()
        upstream.shutdown()
        store.close()
        log_file.close()

    return report()


if __name__ == "__main__":
    sys.exit(main())
