"""The edges of the consent flow, against real Postgres and a real TLS provider.

`e2e_oauth_consent.py` walks the **happy path** — connect, refresh, revoke, disconnect —
and proves the properties the step exists for. This one is the opposite: everything that
goes wrong, races, is abandoned, is tampered with, or is asked in the wrong order.

    cd backend && .venv/bin/python scripts/e2e_oauth_edges.py

Needs Postgres started first. Costs nothing — no model, no MCP server, no money.

Same shape as its sibling: its own database, a locally-signed IdP, a real OAuth server on
a real socket over real TLS, and uvicorn in its own process. The provider here is built to
misbehave on demand, which is the whole point.

**Why so much of this is concurrency.** Three of the failures 7b is designed against are
invisible single-threaded and ordinary in production: two runs refreshing one connection
at once, two callbacks carrying one `state`, and a disconnect landing mid-refresh. A
suite that only ever does one thing at a time cannot distinguish a system that handles
them from one that does not.
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
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlsplit, urlunsplit

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_e2e_edges"


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

ISSUER = "https://e2e-edges.local"
AUDIENCE = "api://default"
JWKS_PORT = 8905
PROVIDER_PORT = 8906
API_PORT = 8127
API = f"http://127.0.0.1:{API_PORT}"
TENANT = "e2eedges"
OTHER = "e2eedges2"

PROVIDER_HOST = "localtest.me"
PROVIDER = f"https://{PROVIDER_HOST}:{PROVIDER_PORT}"
CERT_DIR = pathlib.Path(__file__).resolve().parent / "__pycache__"
CERT_FILE = CERT_DIR / "e2e_edges_provider.pem"

CLIENT_SECRET = "MARKER-CLIENT-SECRET-edges"
ACCESS = "MARKER-ACCESS"
REFRESH = "MARKER-REFRESH"

# Atlassian's real access token was 2619 characters. A fake that returns `token-1` would
# never notice a column, a header or a log line that cannot hold one.
BIG = "x" * 2600

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True)
JWK.update({"kid": "k1", "use": "sig", "alg": "RS256"})

CHECKS = []


def _short(value, limit=80):
    """Long values are summarised. A 2.6KB ciphertext blob is not a check result — it is
    a page of noise that hides the twenty checks around it."""
    text = repr(value)
    return text if len(text) <= limit else f"{text[:40]}…<{len(text)} chars>"


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok, _short(actual), _short(expected)))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {_short(actual)}"
          + ("" if ok else f"  (expected {_short(expected)})"))
    return ok


def raises(label, expected_type, fn):
    """A refusal is the assertion. Records what happened either way."""
    try:
        fn()
    except expected_type as exc:
        # `isinstance`, not a name comparison — `UndecryptableError` **is** a
        # `CryptoError`, and a helper that insisted on the exact class would report the
        # correct, more specific exception as a failure.
        return check(label, f"raised {expected_type.__name__}",
                     f"raised {expected_type.__name__}") and str(exc)
    except Exception as exc:  # noqa: BLE001
        check(label, f"{type(exc).__name__}: {exc}", expected_type.__name__)
        return ""
    check(label, "no exception", expected_type.__name__)
    return ""


def say(what):
    print(f"\n=== {what}", flush=True)


def token(sub, email):
    now = int(time.time())
    return jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": sub, "email": email,
                       "iat": now, "exp": now + 3600},
                      KEY, algorithm="RS256", headers={"kid": "k1"})


class Jwks(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        _json(self, 200, {"keys": [JWK]})

    def log_message(self, *args):
        pass


class Provider(http.server.BaseHTTPRequestHandler):
    """An authorization server that can be told to misbehave. State on the class."""

    issued = 0
    # **A set, not one value.** The first version held a single `live_refresh`, so Sam
    # connecting invalidated Priya's token — a property of the fake, not of anything under
    # test, and it made the eight-refresh race fail for the wrong reason. A real provider
    # tracks refresh tokens per grant; rotation removes the spent one and adds its
    # replacement.
    live = set()
    challenges = {}
    revoked = []
    # Set to make the next exchange do something awful.
    mode = "ok"          # ok | error | garbage | no_token | slow | http_500
    exchanges = []
    lock = threading.Lock()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        form = {k: v[0] for k, v in
                urllib.parse.parse_qs(self.rfile.read(length).decode()).items()}
        path = urllib.parse.urlsplit(self.path).path

        auth = self.headers.get("Authorization") or ""
        if not auth.startswith("Basic "):
            return _json(self, 401, {"error": "invalid_client"})
        _, _, secret = base64.b64decode(auth.split(" ", 1)[1]).decode().partition(":")
        if secret != CLIENT_SECRET:
            return _json(self, 401, {"error": "invalid_client"})

        if path == "/revoke":
            Provider.revoked.append(form.get("token", ""))
            return _json(self, 200, {})

        with Provider.lock:
            Provider.exchanges.append(form)

        if Provider.mode == "error":
            return _json(self, 400, {"error": "invalid_grant"})
        if Provider.mode == "http_500":
            return _json(self, 500, {"oops": True})
        if Provider.mode == "garbage":
            body = b"<html>not json at all</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        if Provider.mode == "no_token":
            return _json(self, 200, {"token_type": "Bearer", "expires_in": 3600})
        if Provider.mode == "slow":
            time.sleep(1.5)

        if form.get("grant_type") == "authorization_code":
            # **PKCE, checked.** This was missing, so the edges script accepted any code —
            # including an empty one, which is how the malformed-callback finding surfaced
            # as a passing exchange rather than a refusal. A fake that does not verify the
            # challenge makes `code_challenge` decoration.
            import hashlib

            expected = Provider.challenges.get(form.get("code", ""))
            computed = (base64.urlsafe_b64encode(
                hashlib.sha256(form.get("code_verifier", "").encode()).digest())
                .decode().rstrip("="))
            if expected is None or expected != computed:
                return _json(self, 400, {"error": "invalid_grant"})

        with Provider.lock:
            if form.get("grant_type") == "refresh_token":
                # Rotation: spending a refresh token kills it. Reuse is `invalid_grant`,
                # which is what Atlassian, Google and Okta all do.
                if form.get("refresh_token") not in Provider.live:
                    return _json(self, 400, {"error": "invalid_grant"})
                Provider.live.discard(form.get("refresh_token"))

            Provider.issued += 1
            n = Provider.issued
            issued_refresh = f"{REFRESH}-{n}"
            Provider.live.add(issued_refresh)

        return _json(self, 200, {
            "access_token": f"{ACCESS}-{n}-{BIG}",
            "refresh_token": issued_refresh,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token_expires_in": 15897600,   # GitHub's spelling
        })

    def do_GET(self):
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
        code = f"code-{len(Provider.challenges) + 1}"
        Provider.challenges[code] = query.get("code_challenge", "")
        target = f"{query['redirect_uri']}?" + urllib.parse.urlencode(
            {"code": code, "state": query["state"]})
        self.send_response(302)
        self.send_header("Location", target)
        self.end_headers()

    def log_message(self, *args):
        pass


def _json(handler, status, body):
    payload = json.dumps(body).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def make_certificate():
    import datetime as _dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, PROVIDER_HOST)])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(now + _dt.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(PROVIDER_HOST)]),
                           critical=False)
            .sign(key, hashes.SHA256()))
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    CERT_FILE.write_bytes(
        key.private_bytes(serialization.Encoding.PEM,
                          serialization.PrivateFormat.TraditionalOpenSSL,
                          serialization.NoEncryption())
        + cert.public_bytes(serialization.Encoding.PEM))


def browser(method, url, **kwargs):
    """A request with no Authorization header, like a provider's redirect."""
    return httpx.request(method, url, follow_redirects=False, timeout=20,
                         verify=str(CERT_FILE), **kwargs)


def main():
    import psycopg

    with psycopg.connect(dsn_for("postgres"),
                         autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    # Step 058: the dial vets DNS answers, and localtest.me resolves to loopback
    # on purpose — the operator (this script) consents to its own machine.
    os.environ["CARNET_EGRESS_INTERNAL_HOSTS"] = "localtest.me"
    os.environ["CARNET_SECRET_KEY"] = base64.b64encode(os.urandom(32)).decode()
    os.environ["CARNET_WORKERS"] = "0"
    os.environ["CARNET_PUBLIC_ORIGIN"] = API
    make_certificate()
    os.environ["REQUESTS_CA_BUNDLE"] = str(CERT_FILE)

    from carnet import bootstrap, storage, tools
    from carnet.access import oauth
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN, min_size=2, max_size=10))
    bootstrap.configure_crypto(required=True)

    for tenant in (TENANT, OTHER):
        store.create_tenant(tenant, "edges")

    # Only the first tenant gets an identity provider — one issuer speaks for one
    # customer, and `save_tenant_idp` refuses a second registration precisely so that one
    # cannot read the other's data. `OTHER` exists here only to be the tenant a
    # credential is *not* readable in, which needs no login at all.
    store.save_tenant_idp(TENANT, {
        "issuer": ISSUER, "jwks_uri": f"http://127.0.0.1:{JWKS_PORT}/jwks.json",
        "audience": AUDIENCE, "allowed_domains": ("acme.com",)})

    for tenant in (TENANT, OTHER):
        store.allow_host(tenant, PROVIDER_HOST, actor="system:cli")
        tools.register_connector(tenant, "jira", url=f"{PROVIDER}/mcp",
                                 credential_env="JIRA_TOKEN", actor="system:cli")
        oauth.configure(tenant, "jira",
                        authorize_endpoint=f"{PROVIDER}/authorize",
                        token_endpoint=f"{PROVIDER}/token",
                        revoke_endpoint=f"{PROVIDER}/revoke",
                        client_id="client-abc", client_secret=CLIENT_SECRET,
                        scopes=("read:jira-work", "offline_access"),
                        authorize_params={"audience": "api.atlassian.com",
                                          "prompt": "consent"},
                        actor="system:cli")

    jwks = http.server.ThreadingHTTPServer(("127.0.0.1", JWKS_PORT), Jwks)
    provider = http.server.ThreadingHTTPServer(("127.0.0.1", PROVIDER_PORT), Provider)
    import ssl

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE)
    provider.socket = ctx.wrap_socket(provider.socket, server_side=True)
    threading.Thread(target=jwks.serve_forever, daemon=True).start()
    threading.Thread(target=provider.serve_forever, daemon=True).start()

    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)],
        env={**os.environ, "CARNET_TENANT": TENANT},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            try:
                httpx.get(f"{API}/health", timeout=1)
                break
            except Exception:
                time.sleep(0.5)
        else:
            raise SystemExit("uvicorn did not come up")
        run(store)
    finally:
        api.terminate(); api.wait(timeout=10)
        jwks.shutdown(); provider.shutdown()

    failed = [c for c in CHECKS if not c[1]]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        for label, _, actual, expected in failed:
            print(f"  FAIL {label}: {actual!r} != {expected!r}")
        raise SystemExit(1)


def run(store):
    from carnet import storage
    from carnet.access import connections, oauth
    from carnet.core import Principal, credentials, crypto

    priya_h = {"Authorization": f"Bearer {token('00u-priya', 'priya@acme.com')}"}
    sam_h = {"Authorization": f"Bearer {token('00u-sam', 'sam@acme.com')}"}
    httpx.get(f"{API}/connections", headers=priya_h, timeout=10)
    httpx.get(f"{API}/connections", headers=sam_h, timeout=10)
    priya = Principal.user(store.find_user_by_email(TENANT, "priya@acme.com")["id"], TENANT)
    sam = Principal.user(store.find_user_by_email(TENANT, "sam@acme.com")["id"], TENANT)

    def start(headers=priya_h, **params):
        body = httpx.post(f"{API}/connectors/jira/connect", headers=headers,
                          params=params, timeout=10)
        return body

    def consent(url):
        """Follow the provider's redirect back to our callback. No bearer token."""
        hop = browser("GET", url)
        return browser("GET", hop.headers["location"])

    def state_of(url):
        return url.split("state=")[1].split("&")[0]

    def expire(who, connector="jira", seconds=300):
        row = store.find_connection(TENANT, "user", who.id, connector)
        store.update_connection_credential(
            TENANT, "user", who.id, connector,
            ciphertext=row["ciphertext"], key_id=row["key_id"],
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=seconds),
            refresh_expires_at=row["refresh_expires_at"],
            if_updated_at=row["updated_at"])

    # ---------------------------------------------------------------- the callback
    say("the callback, at its edges")

    r = browser("GET", f"{API}/connect/callback")
    check("no state at all is refused, not a crash", r.status_code, 303)
    check("  and says so", "failed=" in r.headers["location"], True)

    r = browser("GET", f"{API}/connect/callback", params={"state": "short"})
    check("a state too short to be one of ours", "failed=" in r.headers["location"], True)

    r = browser("GET", f"{API}/connect/callback", params={"state": "q" * 43})
    check("a well-formed state we never minted", "failed=" in r.headers["location"], True)

    started = start().json()["authorize_url"]
    r = browser("GET", f"{API}/connect/callback", params={"state": state_of(started)})
    check("a real state with NO code is refused", "failed=" in r.headers["location"], True)
    check("  and it never reached the provider", len(Provider.exchanges), 0)
    # **The state survives, unlike an expired one**, and the asymmetry is the decision: a
    # truncated redirect is somebody else's accident, and burning their pending row over
    # it turns a recoverable problem into an unrecoverable one. An expired state is a flow
    # that genuinely happened and must never be replayable.
    check("  and a mangled redirect does NOT burn the flow",
          bool(store.consume_pending_authorization(state_of(started))), True)

    r = browser("GET", f"{API}/connect/callback",
                params={"error": "access_denied", "error_description": "user said no"})
    check("pressing Deny is a redirect, not an error", r.status_code, 303)
    check("  carrying the provider's words",
          "user+said+no" in r.headers["location"], True)

    # ---------------------------------------------------------- concurrency on state
    say("two callbacks carrying one state, at the same instant")

    url = start().json()["authorize_url"]
    hop = browser("GET", url)
    back = hop.headers["location"]
    before = len(Provider.exchanges)

    with ThreadPoolExecutor(max_workers=2) as pool:
        both = [f.result() for f in [pool.submit(browser, "GET", back) for _ in range(2)]]

    outcomes = ["connected" if "connected=" in r.headers["location"] else "failed"
                for r in both]
    check("exactly one callback wins", sorted(outcomes), ["connected", "failed"])
    check("  and the code was exchanged exactly once",
          len(Provider.exchanges) - before, 1)
    check("  leaving one connection", bool(
        store.find_connection(TENANT, "user", priya.id, "jira")), True)

    # ------------------------------------------------------------- two people at once
    say("two people connecting the same connector at the same time")

    with ThreadPoolExecutor(max_workers=2) as pool:
        urls = [f.result() for f in [
            pool.submit(lambda h=h: start(h).json()["authorize_url"])
            for h in (priya_h, sam_h)]]
    check("two distinct states", len(set(state_of(u) for u in urls)), 2)
    for u in urls:
        consent(u)
    check("Priya has one", bool(store.find_connection(TENANT, "user", priya.id, "jira")), True)
    check("Sam has his own", bool(store.find_connection(TENANT, "user", sam.id, "jira")), True)
    a = store.find_connection(TENANT, "user", priya.id, "jira")["ciphertext"]
    b = store.find_connection(TENANT, "user", sam.id, "jira")["ciphertext"]
    check("and they are different credentials", a != b, True)

    # ------------------------------------------------------------------ big tokens
    say("a provider whose tokens are the size of Atlassian's")

    sealed = json.loads(crypto.open_(
        store.find_connection(TENANT, "user", priya.id, "jira")["ciphertext"],
        tenant_id=TENANT, aad=crypto.connection_aad(TENANT, "user", priya.id, "jira"),
        key_id=store.find_connection(TENANT, "user", priya.id, "jira")["key_id"]))
    check("a 2.6KB access token round-trips", len(sealed["access"]) > 2600, True)
    check("and the read path returns it whole",
          credentials.for_connector("jira", priya, identity="user").value
          == sealed["access"], True)

    # --------------------------------------------------------- eight refreshes at once
    say("eight concurrent refreshes of one connection, over a real socket")

    expire(priya)
    before = len(Provider.exchanges)
    ready = threading.Barrier(8)

    def refresh_once(_):
        ready.wait(timeout=20)
        return oauth.refresh_connection(priya, "jira")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = [f.result() for f in [pool.submit(refresh_once, i) for i in range(8)]]

    check("exactly one exchange reached the provider", len(Provider.exchanges) - before, 1)
    check("exactly one thread refreshed", sum(1 for r in results if r), 1)
    check("nobody errored", len(results), 8)
    fresh = credentials.for_connector("jira", priya, identity="user").value
    check("and every loser uses the winner's token", fresh == sealed["access"], False)

    # Still refreshable — a lost update stores a token the provider already killed.
    expire(priya)
    check("the connection survives the race", oauth.refresh_connection(priya, "jira"), True)

    # ------------------------------------------------------ the provider misbehaving
    say("a provider that misbehaves")

    for mode, label in [("http_500", "a 500"), ("garbage", "HTML instead of JSON"),
                        ("no_token", "a 200 with no access token")]:
        # Read the stored credential **before** backdating it: an expired connection
        # correctly refuses to be read at all, which is 7a's rule and not what is under
        # test here. Comparing ciphertext rather than plaintext for the same reason.
        good = store.find_connection(TENANT, "user", priya.id, "jira")["ciphertext"]
        Provider.mode = mode
        expire(priya)
        raises(f"{label} is refused", oauth.OAuthRefused,
               lambda: oauth.refresh_connection(priya, "jira"))
        check(f"  and {label} changed nothing",
              store.find_connection(TENANT, "user", priya.id, "jira")["ciphertext"], good)
        Provider.mode = "ok"

    say("a provider that says the grant is gone")

    os.environ["JIRA_TOKEN"] = "the-operators-shared-token"
    Provider.mode = "error"
    expire(priya)
    raises("invalid_grant is terminal", oauth.ReconsentRequired,
           lambda: oauth.refresh_connection(priya, "jira"))
    before = len(Provider.exchanges)
    raises("  and is not retried", oauth.ReconsentRequired,
           lambda: oauth.refresh_connection(priya, "jira"))
    check("  nothing reached the provider the second time",
          len(Provider.exchanges) - before, 0)
    message = raises("  the read path refuses too", credentials.CredentialError,
                     lambda: credentials.for_connector(
                         "jira", priya, "JIRA_TOKEN", identity="user"))
    check("  and NEVER falls back to the operator's token",
          "the-operators-shared-token" in (message or ""), False)
    rows = httpx.get(f"{API}/connections", headers=priya_h, timeout=10).json()
    check("  the page says reconnect",
          {r["connector_id"]: r for r in rows}["jira"]["state"], "reconnect")
    Provider.mode = "ok"
    Provider.live.clear()

    consent(start().json()["authorize_url"])
    check("reconnecting clears it",
          store.find_connection(TENANT, "user", priya.id, "jira")["reconsent_reason"], "")
    check("  and the credential works again",
          credentials.for_connector("jira", priya, identity="user").source,
          credentials.DELEGATED)

    # --------------------------------------------------- configuration changing under it
    say("configuration changing underneath a flow in progress")

    url = start().json()["authorize_url"]
    oauth.unconfigure(TENANT, "jira", actor="system:cli")
    r = consent(url)
    check("a flow whose consent config vanished is refused",
          "failed=" in r.headers["location"], True)

    # ...and the credentials it already issued are untouched. Migration 021's argument.
    check("  but existing credentials survive",
          bool(store.find_connection(TENANT, "user", sam.id, "jira")), True)
    raises("  they simply cannot be refreshed", oauth.OAuthRefused,
           lambda: oauth.refresh_connection(sam, "jira", force=True))

    oauth.configure(TENANT, "jira", authorize_endpoint=f"{PROVIDER}/authorize",
                    token_endpoint=f"{PROVIDER}/token", revoke_endpoint=f"{PROVIDER}/revoke",
                    client_id="client-abc", client_secret=CLIENT_SECRET,
                    scopes=("read:jira-work", "offline_access"), actor="system:cli")

    say("a host revoked between minting a link and using it")

    url = start().json()["authorize_url"]
    store.revoke_host(TENANT, PROVIDER_HOST, actor="system:cli")
    before = len(Provider.exchanges)
    r = consent(url)
    check("the exchange is refused at dial time", "failed=" in r.headers["location"], True)
    check("  and nothing reached the provider", len(Provider.exchanges) - before, 0)
    store.allow_host(TENANT, PROVIDER_HOST, actor="system:cli")

    # ------------------------------------------------------------------ tenancy
    say("tenancy")

    other_h = {"Authorization": f"Bearer {token('00u-priya', 'priya@acme.com')}"}
    rows = httpx.get(f"{API}/connections", headers=other_h, timeout=10).json()
    check("a connection is not visible to another tenant's row",
          store.find_connection(OTHER, "user", priya.id, "jira"), None)
    ciphertext = store.find_connection(TENANT, "user", priya.id, "jira")["ciphertext"]
    key_id = store.find_connection(TENANT, "user", priya.id, "jira")["key_id"]
    raises("a credential lifted into another tenant does not open", crypto.CryptoError,
           lambda: crypto.open_(ciphertext, tenant_id=OTHER,
                                aad=crypto.connection_aad(OTHER, "user", priya.id, "jira"),
                                key_id=key_id))
    raises("nor into another person's row", crypto.CryptoError,
           lambda: crypto.open_(ciphertext, tenant_id=TENANT,
                                aad=crypto.connection_aad(TENANT, "user", sam.id, "jira"),
                                key_id=key_id))

    # ------------------------------------------------------------- the open redirect
    say("return_to, which becomes a Location header")

    for hostile in ("https://evil.example.com", "//evil.example.com",
                    "/\\evil.example.com", "http://evil.example.com/x"):
        r = start(return_to=hostile)
        check(f"{hostile!r} is a 400", r.status_code, 400)
        check("  and nothing was minted", "evil" in r.text.replace("evil.example.com", ""), False)

    r = start(return_to="/agents/triage-bot")
    landed = consent(r.json()["authorize_url"])
    check("a path inside the app is honoured",
          landed.headers["location"], "/agents/triage-bot?connected=jira")

    # ------------------------------------------------------------ static credentials
    say("a pasted credential beside a consent flow")

    connections.connect_account(sam, "jira", "a-pasted-token",
                                account_label="sam-pat", actor="user:u_operator")
    row = store.find_connection(TENANT, "user", sam.id, "jira")
    check("it overwrites the oauth one and is marked static", row["credential_kind"], "static")
    check("  the read path hands back the bare token",
          credentials.for_connector("jira", sam, identity="user").value, "a-pasted-token")
    before = len(Provider.exchanges)
    check("  and it is never refreshed", oauth.refresh_connection(sam, "jira", force=True), False)
    check("  nothing reached the provider", len(Provider.exchanges) - before, 0)
    record = [r for r in store.admin_audit_records(TENANT)
              if r["action"] == "connection.create"][-1]
    check("  the operator is recorded as the actor, not Sam", record["actor_id"], "u_operator")

    # ---------------------------------------------------------------- disconnecting
    say("disconnecting, at its edges")

    body = httpx.delete(f"{API}/connectors/jira/connection", headers=sam_h, timeout=10).json()
    check("a static credential reports nobody to revoke to", body["revoked_upstream"], None)
    body = httpx.delete(f"{API}/connectors/jira/connection", headers=sam_h, timeout=10).json()
    check("disconnecting twice is not an error", body["disconnected"], False)

    Provider.mode = "error"   # revocation still answers 200; this proves ordering
    out = oauth.disconnect(priya, "jira", actor=str(priya))
    check("an oauth connection revokes upstream", out["revoked_upstream"], True)
    check("  and is deleted", store.find_connection(TENANT, "user", priya.id, "jira"), None)
    Provider.mode = "ok"

    # --------------------------------------------------------------- sweeping
    say("abandoned flows")

    for _ in range(3):
        start()
    pending = store.sweep_pending_authorizations(older_than_seconds=3600)
    check("fresh flows are not swept", pending, 0)
    swept = store.sweep_pending_authorizations(older_than_seconds=-1)
    check("abandoned ones are", swept >= 3, True)
    check("  and the table is empty", store.sweep_pending_authorizations(older_than_seconds=-1), 0)

    # ------------------------------------------------------------ authorize params
    say("provider-specific parameters (migration 025)")

    url = start().json()["authorize_url"]
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    check("the flow's own state survives", len(query["state"]) >= 32, True)
    oauth.configure(TENANT, "jira", authorize_endpoint=f"{PROVIDER}/authorize",
                    token_endpoint=f"{PROVIDER}/token", client_id="client-abc",
                    client_secret=CLIENT_SECRET, scopes=("read:jira-work",),
                    authorize_params={"audience": "api.atlassian.com"}, actor="system:cli")
    url = start().json()["authorize_url"]
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    check("a provider's own parameter is sent", query["audience"], "api.atlassian.com")
    for reserved in ("state", "redirect_uri", "client_id"):
        raises(f"a row may not supply {reserved}", storage.StorageError,
               lambda r=reserved: oauth.configure(
                   TENANT, "jira", authorize_endpoint=f"{PROVIDER}/authorize",
                   token_endpoint=f"{PROVIDER}/token", client_id="c",
                   client_secret=CLIENT_SECRET, authorize_params={r: "hijacked"},
                   actor="system:cli"))

    # -------------------------------------------------------------- the audit trail
    say("nothing anywhere carries a secret")

    log = json.dumps(store.admin_audit_records(TENANT), default=str)
    for name, value in [("client secret", CLIENT_SECRET), ("access token", ACCESS),
                        ("refresh token", REFRESH)]:
        check(f"no {name} in the administrative log", value in log, False)
    listing = json.dumps(connections.list_accounts(TENANT), default=str)
    check("no ciphertext in the connection listing", "ciphertext" in listing, False)
    page = httpx.get(f"{API}/connections", headers=priya_h, timeout=10).text
    for name, value in [("access token", ACCESS), ("client secret", CLIENT_SECRET)]:
        check(f"no {name} in the Connections response", value in page, False)


if __name__ == "__main__":
    main()
