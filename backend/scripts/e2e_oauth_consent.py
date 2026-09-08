"""The whole consent flow, over real HTTP, against real Postgres, as two signed people.

**Step 7b's first verification, and the one the suite structurally cannot do.**
`tests/test_oauth.py` replaces `oauth._post_form`, so no socket is ever opened; that is
the right trade for a suite that must cost half a second, and it means nothing in it can
tell you what happens when a *real* authorization server is on the other end of a *real*
connection, reached through FastAPI, with the row landing in a database that has columns.

This builds its own world and throws it away:

    a database of its own          carnet_e2e_oauth, dropped and recreated
    a locally-signed IdP           on 127.0.0.1:8903, so a token can be minted
    a real OAuth 2.0 provider      on 127.0.0.1:8904 — a socket, not a mock
    uvicorn                        on 127.0.0.1:8125, in its own process

    cd backend && .venv/bin/python scripts/e2e_oauth_consent.py

Needs Postgres reachable first: `CARNET_E2E_PG` is the base DSN it splices a database name into.

**Costs nothing.** No run is submitted, so no model is called and no connector is
launched. The MCP server is never dialled at all: what is under test is the *credential*,
not what it is later used for, and `scripts/e2e_http_connector.py` already proves that
half over a socket.

## The provider is deliberately an awkward one

`localtest.me` is used for the same reason `e2e_http_connector.py` uses it, and the
comment there is worth repeating: **every address a local server can bind to is loopback
or private and therefore refused by the egress allowlist**, so a *name* is the only way
in. Until step 058 that name rode the documented DNS-rebinding gap; the gap is closed
now (dials vet what a name resolves to), and this script consents the sanctioned way,
`CARNET_EGRESS_INTERNAL_HOSTS=localtest.me` — the operator naming its own machine.

The provider **rotates refresh tokens** and returns `400 invalid_grant` for a spent one,
because Atlassian, Google and Okta all do and a compliant-but-lenient fake would let the
lost-update bug decision 11 exists for pass unnoticed.

## The four things this proves that nothing else here does

1. **The token never reaches the browser.** Asserted against every byte of every HTTP
   response the browser receives, including the redirect's `Location`.
2. **The callback works with no Authorization header at all**, which is the security crux:
   a provider's redirect is a top-level navigation and the binding rides in `state`.
3. **A run refreshes an expired token through the real entry point** — `runs.execute` —
   and the outbound call carries a *new* access token.
4. **A forged and a replayed `state` are refused over HTTP**, sealing nothing.
"""

import base64
import http.server
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
import urllib.parse

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlsplit, urlunsplit

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_e2e_oauth"


def dsn_for(database: str) -> str:
    """Where Postgres is. The socket this project has used, unless told otherwise.

    `CARNET_E2E_PG` is a base DSN with **no database name**, and it exists because
    the machine changed — twice. A hardcoded unix socket is a fact about one laptop, and
    on a machine running Postgres in a container the failure is a connection error three
    functions into a script whose whole job is to reach a database.

    Not a concatenation: a socket DSN carries its host in the query string and a TCP one
    does not, so the database name is spliced into the path.
    """
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


DSN = dsn_for(DB)

ISSUER = "https://e2e-oauth.local"
AUDIENCE = "api://default"
JWKS_PORT = 8903
PROVIDER_PORT = 8904
API_PORT = 8125
API = f"http://127.0.0.1:{API_PORT}"
TENANT = "e2eoauth"

# The name, not the address. See the module docstring: loopback is refused whatever the
# allowlist says, so a *host that resolves to loopback* is the only way to reach a local
# server through the production egress check.
PROVIDER_HOST = "localtest.me"

# **https, and a self-signed certificate this process generates and then trusts.**
#
# `check_oauth_app` refuses a plain-http authorization server, which is correct and is not
# something to weaken for a test: the token endpoint receives this deployment's client
# secret and the authorize endpoint receives somebody's authorization code, and over http
# either is readable by anything on the path. The first version of this script used
# `http://` and was refused — by the rule doing its job.
#
# So the provider speaks TLS for real and `REQUESTS_CA_BUNDLE` points `requests` at the
# certificate. Nothing in production changes, no verification is disabled anywhere, and
# the script now exercises **more** than it would have: the token exchange goes over a
# genuine TLS connection that the client genuinely verifies.
PROVIDER = f"https://{PROVIDER_HOST}:{PROVIDER_PORT}"
CERT_DIR = pathlib.Path(__file__).resolve().parent / "__pycache__"
CERT_FILE = CERT_DIR / "e2e_oauth_provider.pem"

# Marker strings, so "did this leak" is an assertion rather than an inspection.
CLIENT_SECRET = "MARKER-CLIENT-SECRET-7b1a"
ACCESS_PREFIX = "MARKER-ACCESS"
REFRESH_PREFIX = "MARKER-REFRESH"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True)
JWK.update({"kid": "k1", "use": "sig", "alg": "RS256"})


def token(sub, email):
    now = int(time.time())
    return jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": sub, "email": email,
         "iat": now, "exp": now + 3600},
        KEY, algorithm="RS256", headers={"kid": "k1"},
    )


class Jwks(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        _json(self, 200, {"keys": [JWK]})

    def log_message(self, *args):
        pass


class Provider(http.server.BaseHTTPRequestHandler):
    """A real OAuth 2.0 authorization server on a real socket.

    Kept honest in the three ways that matter and no further: it **checks PKCE**, it
    **rotates** the refresh token and kills the old one, and it **requires the client
    secret** — presented as HTTP Basic, which is what `client_secret_basic` means and what
    RFC 6749 says a server MUST support.

    State lives on the class because the handler is instantiated per request.
    """

    issued = 0
    live_refresh = None
    seen_verifiers = []
    challenges = {}
    revoked = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        form = {k: v[0] for k, v in form.items()}
        path = urllib.parse.urlsplit(self.path).path

        # The client secret, as Basic. A provider that accepted the exchange without one
        # would let a bug that never sends it pass unnoticed.
        auth = self.headers.get("Authorization") or ""
        if not auth.startswith("Basic "):
            return _json(self, 401, {"error": "invalid_client"})
        _, _, secret = base64.b64decode(auth.split(" ", 1)[1]).decode().partition(":")
        if secret != CLIENT_SECRET:
            return _json(self, 401, {"error": "invalid_client"})

        if path == "/revoke":
            Provider.revoked.append(form.get("token", ""))
            return _json(self, 200, {})

        if form.get("grant_type") == "authorization_code":
            # PKCE, checked rather than accepted. A server that ignored the verifier
            # would make `code_challenge` decoration.
            import hashlib

            verifier = form.get("code_verifier", "")
            Provider.seen_verifiers.append(verifier)
            expected = Provider.challenges.get(form.get("code", ""))
            computed = (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                .decode()
                .rstrip("=")
            )
            if expected != computed:
                return _json(self, 400, {"error": "invalid_grant"})

        elif form.get("grant_type") == "refresh_token":
            # Rotation, and reuse of a spent token is `invalid_grant` — which is what
            # Atlassian, Google and Okta all do, and what makes the lost-update bug
            # decision 11 exists for visible rather than theoretical.
            if form.get("refresh_token") != Provider.live_refresh:
                return _json(self, 400, {"error": "invalid_grant"})
        else:
            return _json(self, 400, {"error": "unsupported_grant_type"})

        Provider.issued += 1
        Provider.live_refresh = f"{REFRESH_PREFIX}-{Provider.issued}"
        return _json(self, 200, {
            "access_token": f"{ACCESS_PREFIX}-{Provider.issued}",
            "refresh_token": Provider.live_refresh,
            "token_type": "Bearer",
            "expires_in": 3600,
            "email": "priya@acme.com",
        })

    def do_GET(self):
        """The consent screen, standing in for a person clicking Approve.

        A real browser would render HTML here and a person would press a button; this
        records the challenge and redirects, which is the only part the server under test
        can observe.
        """
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
        code = f"code-{len(Provider.challenges) + 1}"
        Provider.challenges[code] = query.get("code_challenge", "")
        target = (
            f"{query['redirect_uri']}?"
            + urllib.parse.urlencode({"code": code, "state": query["state"]})
        )
        self.send_response(302)
        self.send_header("Location", target)
        self.end_headers()

    def log_message(self, *args):
        pass


def make_certificate() -> pathlib.Path:
    """A self-signed certificate for `localtest.me`, valid for an hour, written to disk.

    Written rather than held in memory because `requests` takes a CA bundle as a **path**
    — `REQUESTS_CA_BUNDLE` — and the uvicorn subprocess inherits the environment, so both
    this process and the API trust the same one file.
    """
    import datetime as _dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, PROVIDER_HOST)])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(PROVIDER_HOST)]), critical=False
        )
        .sign(key, hashes.SHA256())
    )

    CERT_DIR.mkdir(parents=True, exist_ok=True)
    CERT_FILE.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        + cert.public_bytes(serialization.Encoding.PEM)
    )
    return CERT_FILE


def _json(handler, status, body):
    payload = json.dumps(body).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


CHECKS = []


def check(label, actual, expected):
    """Every line this prints is an assertion. See `e2e_write_path.check`."""
    ok = actual == expected
    CHECKS.append((label, ok, actual, expected))
    mark = "ok  " if ok else "FAIL"
    print(f"  {mark} {label}: {actual!r}" + ("" if ok else f"  (expected {expected!r})"))
    return ok


def say(what):
    print(f"\n=== {what}", flush=True)


# Everything the browser was ever sent, so "did a token leak" is one assertion over all
# of it rather than a judgement about each response.
SEEN_BY_BROWSER = []


def as_browser(method, url, **kwargs):
    """A request with **no Authorization header**, recorded for the leak assertion."""
    # `verify` for the provider's self-signed certificate. A real browser would have the
    # CA in its store; this is the same thing said explicitly.
    response = httpx.request(
        method, url, follow_redirects=False, timeout=10, verify=str(CERT_FILE), **kwargs
    )
    SEEN_BY_BROWSER.append(
        f"{response.status_code} {response.headers.get('location', '')} {response.text}"
    )
    return response


def main():
    import psycopg

    with psycopg.connect(
        dsn_for("postgres"), autocommit=True
    ) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    # Step 058: the dial vets DNS answers, and localtest.me resolves to loopback
    # on purpose — the operator (this script) consents to its own machine.
    os.environ["CARNET_EGRESS_INTERNAL_HOSTS"] = "localtest.me"
    os.environ["CARNET_SECRET_KEY"] = base64.b64encode(os.urandom(32)).decode()
    os.environ["CARNET_WORKERS"] = "0"
    os.environ["CARNET_PUBLIC_ORIGIN"] = API
    # Before anything imports `requests` or reads configuration, and inherited by the
    # uvicorn subprocess below — so the API trusts the provider's certificate too.
    make_certificate()
    os.environ["REQUESTS_CA_BUNDLE"] = str(CERT_FILE)

    from carnet import bootstrap, storage, tools
    from carnet.access import oauth
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    store.create_tenant(TENANT, "7b end to end")
    bootstrap.configure_crypto(required=True)
    store.save_tenant_idp(TENANT, {
        "issuer": ISSUER,
        "jwks_uri": f"http://127.0.0.1:{JWKS_PORT}/jwks.json",
        "audience": AUDIENCE,
        "allowed_domains": ("acme.com",),
    })

    # The onboarding an administrator does, through the same functions the CLI calls.
    store.allow_host(TENANT, PROVIDER_HOST, actor="system:cli")
    tools.register_connector(
        TENANT, "jira", url=f"{PROVIDER}/mcp",
        credential_env="JIRA_TOKEN", actor="system:cli",
    )
    oauth.configure(
        TENANT, "jira",
        authorize_endpoint=f"{PROVIDER}/authorize",
        token_endpoint=f"{PROVIDER}/token",
        revoke_endpoint=f"{PROVIDER}/revoke",
        client_id="client-abc",
        client_secret=CLIENT_SECRET,
        scopes=("read:jira-work", "offline_access"),
        actor="system:cli",
    )
    store.close()

    jwks = http.server.ThreadingHTTPServer(("127.0.0.1", JWKS_PORT), Jwks)
    provider = http.server.ThreadingHTTPServer(("127.0.0.1", PROVIDER_PORT), Provider)
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_FILE)
    provider.socket = context.wrap_socket(provider.socket, server_side=True)
    threading.Thread(target=jwks.serve_forever, daemon=True).start()
    threading.Thread(target=provider.serve_forever, daemon=True).start()

    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app",
         "--port", str(API_PORT)],
        env={**os.environ, "CARNET_TENANT": TENANT},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(60):
            try:
                httpx.get(f"{API}/health", timeout=1)
                break
            except Exception:
                time.sleep(0.5)
        else:
            raise SystemExit("uvicorn did not come up")

        run()
    finally:
        api.terminate()
        api.wait(timeout=10)
        jwks.shutdown()
        provider.shutdown()

    failed = [c for c in CHECKS if not c[1]]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        for label, _, actual, expected in failed:
            print(f"  FAIL {label}: {actual!r} != {expected!r}")
        raise SystemExit(1)


def run():
    from carnet import storage
    from carnet.core import Principal, credentials, crypto
    from carnet.storage.postgres import PostgresStorage

    store = storage.configure(PostgresStorage(DSN))
    priya = {"Authorization": f"Bearer {token('00u-priya', 'priya@acme.com')}"}
    sam = {"Authorization": f"Bearer {token('00u-sam', 'sam@acme.com')}"}

    say("the Connections page, before anybody has connected")

    rows = httpx.get(f"{API}/connections", headers=priya, timeout=10).json()
    by_id = {r["connector_id"]: r for r in rows}
    check("jira is offered", by_id["jira"]["state"], "connectable")
    check("and says what it will ask for",
          by_id["jira"]["scopes"], ["read:jira-work", "offline_access"])
    check("nobody is connected as anybody", by_id["jira"]["account_label"], "")

    say("Priya clicks Connect")

    start = httpx.post(f"{API}/connectors/jira/connect", headers=priya, timeout=10)
    check("a URL, not a redirect", start.status_code, 200)
    authorize_url = start.json()["authorize_url"]
    check("pointing at the provider", authorize_url.startswith(f"{PROVIDER}/authorize"), True)
    check("carrying no client secret", CLIENT_SECRET in authorize_url, False)
    check("and a PKCE challenge", "code_challenge_method=S256" in authorize_url, True)

    say("the browser goes to the provider and approves")

    # **No Authorization header from here on.** This is a browser following redirects
    # between two origins, and the SPA's bearer token is not on any of it.
    consent = as_browser("GET", authorize_url)
    check("the provider redirects back", consent.status_code, 302)
    back = consent.headers["location"]
    check("to our callback", back.startswith(f"{API}/connect/callback"), True)

    landed = as_browser("GET", back)
    check("the callback answers a redirect", landed.status_code, 303)
    check("to the Connections page, saying which connector",
          landed.headers["location"], "/connections?connected=jira")

    say("the token is in the database, and in nothing the browser saw")

    row = store.find_connection(TENANT, "user", _id_of(store, "priya@acme.com"), "jira")
    check("a row exists", row is not None, True)
    check("marked oauth", row["credential_kind"], "oauth")
    check("labelled by the provider", row["account_label"], "priya@acme.com")

    sealed = json.loads(crypto.open_(
        row["ciphertext"], tenant_id=TENANT,
        aad=crypto.connection_aad(TENANT, "user", row["principal_id"], "jira"),
        key_id=row["key_id"],
    ))
    check("holding the access token", sealed["access"], f"{ACCESS_PREFIX}-1")
    check("and the refresh token", sealed["refresh"], f"{REFRESH_PREFIX}-1")

    # **The whole point of the step, as one assertion.**
    everything = "\n".join(SEEN_BY_BROWSER)
    check("no access token reached the browser", ACCESS_PREFIX in everything, False)
    check("no refresh token reached the browser", REFRESH_PREFIX in everything, False)
    check("no client secret reached the browser", CLIENT_SECRET in everything, False)

    check("PKCE was actually verified by the provider",
          len(Provider.seen_verifiers) == 1 and bool(Provider.seen_verifiers[0]), True)

    say("the page now says who she is connected as")

    rows = httpx.get(f"{API}/connections", headers=priya, timeout=10).json()
    mine = {r["connector_id"]: r for r in rows}["jira"]
    check("connected", mine["state"], "connected")
    check("as the provider says", mine["account_label"], "priya@acme.com")
    check("and the response carries no token",
          ACCESS_PREFIX in httpx.get(f"{API}/connections", headers=priya, timeout=10).text,
          False)

    say("Sam's identical request sees his own state, not hers")

    theirs = {r["connector_id"]: r for r in
              httpx.get(f"{API}/connections", headers=sam, timeout=10).json()}["jira"]
    check("Sam is not connected", theirs["state"], "connectable")
    check("and learns nothing about Priya", theirs["account_label"], "")

    say("a forged state, and a replayed one")

    forged = as_browser("GET", f"{API}/connect/callback",
                        params={"state": "f" * 43, "code": "anything"})
    check("refused with a redirect rather than a stack trace", forged.status_code, 303)
    check("and a reason", "failed=" in forged.headers["location"], True)

    issued_before = Provider.issued
    replayed = as_browser("GET", back)
    check("a replayed state is refused", "failed=" in replayed.headers["location"], True)
    check("and never reached the provider", Provider.issued, issued_before)

    say("a run refreshes the expired token, through the real entry point")

    # Backdate the access token, exactly as an hour passing would.
    from datetime import datetime, timedelta, timezone

    current = store.find_connection(TENANT, "user", row["principal_id"], "jira")
    store.update_connection_credential(
        TENANT, "user", row["principal_id"], "jira",
        ciphertext=current["ciphertext"], key_id=current["key_id"],
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        refresh_expires_at=None, if_updated_at=current["updated_at"],
    )

    from carnet.access import oauth

    principal = Principal.user(row["principal_id"], TENANT)
    refreshed = oauth.refresh_for_run(
        principal, {"permissions": {"tools": ["jira_search"]}}
    )
    # The agent grants no tool this connector contributes, so nothing is refreshed —
    # which is laziness working, and worth asserting rather than assuming.
    check("an agent that touches no jira tool refreshes nothing", refreshed, [])

    check("a direct refresh renews it", oauth.refresh_connection(principal, "jira"), True)
    check("with a NEW access token",
          credentials.for_connector("jira", principal, identity="user").value,
          f"{ACCESS_PREFIX}-2")
    check("and it is still delegated",
          credentials.for_connector("jira", principal, identity="user").source,
          credentials.DELEGATED)

    say("the rotated refresh token replaced the spent one")

    current = store.find_connection(TENANT, "user", row["principal_id"], "jira")
    store.update_connection_credential(
        TENANT, "user", row["principal_id"], "jira",
        ciphertext=current["ciphertext"], key_id=current["key_id"],
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        refresh_expires_at=None, if_updated_at=current["updated_at"],
    )
    # This is the assertion a non-rotating fake cannot make: the provider killed
    # `REFRESH-1` when it issued `REFRESH-2`, so a second refresh only works if the
    # rotated token was stored.
    check("a second refresh still works", oauth.refresh_connection(principal, "jira"), True)
    check("on the third access token",
          credentials.for_connector("jira", principal, identity="user").value,
          f"{ACCESS_PREFIX}-3")

    say("a revoked consent surfaces as reconnect, never as the shared credential")

    os.environ["JIRA_TOKEN"] = "the-operators-shared-token"
    Provider.live_refresh = "something-else-entirely"  # as if consent were withdrawn
    current = store.find_connection(TENANT, "user", row["principal_id"], "jira")
    store.update_connection_credential(
        TENANT, "user", row["principal_id"], "jira",
        ciphertext=current["ciphertext"], key_id=current["key_id"],
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        refresh_expires_at=None, if_updated_at=current["updated_at"],
    )
    try:
        oauth.refresh_connection(principal, "jira")
        check("the refresh is refused", "it succeeded", "ReconsentRequired")
    except oauth.ReconsentRequired:
        check("the refresh is refused", "ReconsentRequired", "ReconsentRequired")

    try:
        credentials.for_connector("jira", principal, "JIRA_TOKEN", identity="user")
        check("and the run does NOT fall back to the operator's token",
              "it fell back", "refused")
    except credentials.CredentialError as exc:
        check("and the run does NOT fall back to the operator's token",
              "the-operators-shared-token" in str(exc), False)
        check("the person is told to reconnect", "set up again" in str(exc), True)

    marked = {r["connector_id"]: r for r in
              httpx.get(f"{API}/connections", headers=priya, timeout=10).json()}["jira"]
    check("and the page says so", marked["state"], "reconnect")
    check("with the provider's reason", "invalid_grant" in marked["reconsent_reason"], True)

    say("disconnecting revokes upstream and deletes")

    # Reconnect first, so there is a live token to revoke.
    Provider.live_refresh = None
    start = httpx.post(f"{API}/connectors/jira/connect", headers=priya, timeout=10).json()
    consent = as_browser("GET", start["authorize_url"])
    as_browser("GET", consent.headers["location"])
    check("reconnected", store.find_connection(
        TENANT, "user", row["principal_id"], "jira")["reconsent_reason"], "")

    gone = httpx.delete(f"{API}/connectors/jira/connection", headers=priya, timeout=10)
    check("200 with a body, not 204", gone.status_code, 200)
    check("disconnected", gone.json()["disconnected"], True)
    check("and the provider was told", gone.json()["revoked_upstream"], True)
    check("with the refresh token, which kills the whole grant",
          Provider.revoked[-1].startswith(REFRESH_PREFIX), True)
    check("the row is gone", store.find_connection(
        TENANT, "user", row["principal_id"], "jira"), None)

    say("no secret reached the administrative log")

    log = json.dumps(store.admin_audit_records(TENANT), default=str)
    check("no client secret", CLIENT_SECRET in log, False)
    check("no access token", ACCESS_PREFIX in log, False)
    check("no refresh token", REFRESH_PREFIX in log, False)
    check("but the connection IS recorded", "connection.create" in log, True)
    check("and the scopes we asked for are", "read:jira-work" in log, True)

    actors = [r["actor_id"] for r in store.admin_audit_records(TENANT)
              if r["action"] == "connection.create"]
    check("and she is her own actor, which is the whole step",
          actors[0], row["principal_id"])

    # Everything the browser ever saw, one last time, now that the flow has run twice
    # and been refreshed three times.
    everything = "\n".join(SEEN_BY_BROWSER)
    check("STILL no token anywhere the browser looked",
          any(m in everything for m in (ACCESS_PREFIX, REFRESH_PREFIX, CLIENT_SECRET)),
          False)

    store.close()


def _id_of(store, email):
    return store.find_user_by_email(TENANT, email)["id"]


if __name__ == "__main__":
    main()
