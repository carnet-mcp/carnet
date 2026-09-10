"""The team journey: one admin and three colleagues, from an empty database to four people
calling through the door **as themselves**. Step 099, the C-series spine.

This is the product's one differentiating claim, walked in one narrative rather than
proven a seam at a time. `e2e_admin_onboarding` proves the administrator's hour;
`e2e_oauth_consent` proves consent; `e2e_http_connector` proves two credentials travel
per request; `e2e_created_to_connected` proves a person can go from nothing to a
connected assistant. Each is a piece. Nobody had sat down as a four-person team and
done the whole thing in order, through the real interfaces, and read the log at the end.

    cd backend && CARNET_E2E_PG=postgresql://postgres:test@localhost:55432 \\
        .venv/bin/python scripts/e2e_team_journey.py

The people, and what each one does:

  priya   the first to sign in, so the administrator (B2). Approves the host, registers
          the connector, discovers it, vets two tools **for the caller's own identity**,
          configures the consent flow, builds the agent, shares it with three colleagues
          (B4, B6, D1). Later reads the door log (D4) and revokes one share.
  sam     signs in, sees the one agent shared with him and nothing else (C1). Connects
          his own account by OAuth — the consent screen, the redirect, the callback (C3).
          Mints a token, calls through the door: the upstream sees **his** access token
          (C4, C5).
  tom     connects by handing his own credential to the terminal — the pasted-token path,
          `--connect-account`, secret on stdin (C2). His call goes out under **his**
          token, which is not sam's (C5).
  lee     is granted the agent but never connects. Their call is refused with the sentence
          that says what to do, while sam's and tom's work (C6).

The upstream is a tiny MCP server in this process that records the `Authorization`
header of every call, because *whose credential went out* is the whole claim. The
consent provider is a real OAuth 2.0 authorization server on a real TLS socket, checking
PKCE and the client secret, at `localtest.me`. Costs nothing.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from urllib.parse import urlsplit, urlunsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from e2e_file_door import TinyMcp  # noqa: E402

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_team_journey"
BASE_DSN = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"

ISSUER = "https://e2e-team.local"
AUDIENCE = "api://default"
JWKS_PORT = 8912
PROVIDER_PORT = 8913
API_PORT = 8143
MCP_PORT = 8938
API = f"http://127.0.0.1:{API_PORT}"
TENANT = "e2eteam"
HOST = "localtest.me"
PROVIDER = f"https://{HOST}:{PROVIDER_PORT}"
MCP_URL = f"http://{HOST}:{MCP_PORT}/mcp/"
CERT_DIR = HERE.parent / "var" / "e2e_team_journey"
CERT_FILE = CERT_DIR / "provider.pem"

CLIENT_SECRET = "MARKER-CLIENT-SECRET-3e77"
ACCESS_PREFIX = "sam-access"
REFRESH_PREFIX = "sam-refresh"
TOM_TOKEN = "tom-pasted-credential-9b0a"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True)
JWK.update({"kid": "k1", "use": "sig", "alg": "RS256"})


def dsn_for(database: str) -> str:
    parts = urlsplit(BASE_DSN)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


def token(sub, email):
    now = int(time.time())
    return jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": sub, "email": email, "iat": now, "exp": now + 3600},
        KEY, algorithm="RS256", headers={"kid": "k1"},
    )


class Jwks(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"keys": [JWK]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _json(handler, status, body):
    payload = json.dumps(body).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


class Provider(http.server.BaseHTTPRequestHandler):
    """`e2e_oauth_consent`'s authorization server, with the consenting account a variable:
    PKCE checked, the client secret required as Basic, one access token per consent."""

    issued = 0
    challenges: dict = {}
    consenting = "nobody@acme.com"

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        form = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(length).decode()).items()}
        auth = self.headers.get("Authorization") or ""
        if not auth.startswith("Basic "):
            return _json(self, 401, {"error": "invalid_client"})
        _, _, secret = base64.b64decode(auth.split(" ", 1)[1]).decode().partition(":")
        if secret != CLIENT_SECRET:
            return _json(self, 401, {"error": "invalid_client"})
        if form.get("grant_type") != "authorization_code":
            return _json(self, 400, {"error": "unsupported_grant_type"})
        verifier = form.get("code_verifier", "")
        computed = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        if Provider.challenges.get(form.get("code", "")) != computed:
            return _json(self, 400, {"error": "invalid_grant"})
        Provider.issued += 1
        return _json(self, 200, {
            "access_token": f"{ACCESS_PREFIX}-{Provider.issued}",
            "refresh_token": f"{REFRESH_PREFIX}-{Provider.issued}",
            "token_type": "Bearer", "expires_in": 3600,
            "email": Provider.consenting,
        })

    def do_GET(self):
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
        code = f"code-{len(Provider.challenges) + 1}"
        Provider.challenges[code] = query.get("code_challenge", "")
        target = f"{query['redirect_uri']}?" + urllib.parse.urlencode({"code": code, "state": query["state"]})
        self.send_response(302)
        self.send_header("Location", target)
        self.end_headers()

    def log_message(self, *args):
        pass


def make_certificate() -> pathlib.Path:
    import datetime as _dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5)).not_valid_after(now + _dt.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    CERT_FILE.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                          serialization.NoEncryption())
        + cert.public_bytes(serialization.Encoding.PEM)
    )
    return CERT_FILE


CHECKS: list = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok, actual, expected))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}" + ("" if ok else f"  (expected {expected!r})"))
    return ok


def says(label, text, fragment):
    ok = fragment in str(text)
    CHECKS.append((label, ok, text, fragment))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f"\n        wanted {fragment!r} in {str(text)[:400]!r}"))
    return ok


def say(what):
    print(f"\n=== {what}", flush=True)


def cli(*args, stdin: str | None = None):
    result = subprocess.run(
        [sys.executable, "-m", "carnet.cli", *args],
        env={**os.environ}, input=stdin, capture_output=True, text=True,
    )
    print("      $ carnet " + " ".join(args) + ("   < (stdin)" if stdin else ""))
    for line in (result.stdout + result.stderr).strip().splitlines()[:8]:
        print(f"        {line}")
    return result


def rpc(bearer: str, method: str, params=None, id_=1):
    r = httpx.post(f"{API}/mcp", headers={"Authorization": f"Bearer {bearer}"},
                   json={"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}},
                   timeout=30)
    return r.status_code, r.json()


def as_browser(method, url, **kwargs):
    return httpx.request(method, url, follow_redirects=False, timeout=10, verify=str(CERT_FILE), **kwargs)


def consent(c: httpx.Client, who: dict, email: str) -> dict:
    """Connect, the way the Connections page does it: a URL, the provider, the callback."""
    Provider.consenting = email
    start = c.post("/connectors/acme/connect", headers=who)
    check(f"{email}: Connect answers a URL", start.status_code, 200)
    authorize_url = start.json()["authorize_url"]
    check("  at the provider, with PKCE", authorize_url.startswith(f"{PROVIDER}/authorize") and "code_challenge_method=S256" in authorize_url, True)
    approved = as_browser("GET", authorize_url)
    check("  the provider redirects back", approved.status_code, 302)
    landed = as_browser("GET", approved.headers["location"])
    check("  the callback lands on the Connections page", (landed.status_code, landed.headers.get("location")),
          (303, "/connections?connected=acme"))
    rows = {r["connector_id"]: r for r in c.get("/connections", headers=who).json()}
    return rows["acme"]


def main() -> int:
    import psycopg

    if socket.gethostbyname(HOST) != "127.0.0.1":
        print(f"SKIPPED: {HOST} did not resolve to 127.0.0.1; this needs outbound DNS")
        return 0

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")
    dsn = dsn_for(DB)
    os.environ["CARNET_DATABASE_URL"] = dsn
    os.environ["CARNET_SECRET_KEY"] = base64.b64encode(os.urandom(32)).decode()
    os.environ["CARNET_TENANT"] = TENANT
    os.environ["CARNET_EGRESS_INTERNAL_HOSTS"] = HOST
    os.environ["CARNET_PUBLIC_ORIGIN"] = API
    os.environ["REQUESTS_CA_BUNDLE"] = str(make_certificate())
    os.environ["SSL_CERT_FILE"] = str(CERT_FILE)

    from carnet import storage
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    migrate.apply(dsn)
    store = storage.configure(PostgresStorage(dsn))
    store.create_tenant(TENANT, "The team, week one")
    store.save_tenant_idp(TENANT, {
        "issuer": ISSUER, "jwks_uri": f"http://127.0.0.1:{JWKS_PORT}/jwks.json",
        "audience": AUDIENCE, "allowed_domains": ("acme.com",),
    })
    store.close()

    jwks = http.server.ThreadingHTTPServer(("127.0.0.1", JWKS_PORT), Jwks)
    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", MCP_PORT), TinyMcp)
    provider = http.server.ThreadingHTTPServer(("127.0.0.1", PROVIDER_PORT), Provider)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_FILE)
    provider.socket = context.wrap_socket(provider.socket, server_side=True)
    for server in (jwks, upstream, provider):
        threading.Thread(target=server.serve_forever, daemon=True).start()

    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)],
        env={**os.environ, "CARNET_BOOTSTRAP_ADMIN": "priya@acme.com"},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(60):
            try:
                httpx.get(f"{API}/health", timeout=1)
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.5)
        else:
            raise SystemExit("uvicorn did not come up")
        run()
    finally:
        api.terminate()
        api.wait(timeout=10)
        for server in (jwks, upstream, provider):
            server.shutdown()

    failed = [label for label, ok, *_ in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


def run() -> None:
    c = httpx.Client(base_url=API, timeout=30)
    priya = {"Authorization": f"Bearer {token('00u-priya', 'priya@acme.com')}"}
    sam = {"Authorization": f"Bearer {token('00u-sam', 'sam@acme.com')}"}
    tom = {"Authorization": f"Bearer {token('00u-tom', 'tom@acme.com')}"}
    lee = {"Authorization": f"Bearer {token('00u-lee', 'lee@acme.com')}"}

    say("B2: priya signs in first and is the administrator; sam signs in second and is not")
    me = c.get("/me", headers=priya).json()
    check("priya is an administrator", me["admin"], True)
    check("and /me hands her the door's address", me["mcp_url"], f"{API}/mcp")
    check("sam is not", c.get("/me", headers=sam).json()["admin"], False)
    check("nor tom", c.get("/me", headers=tom).json()["admin"], False)
    check("nor lee", c.get("/me", headers=lee).json()["admin"], False)
    check("sam is refused the administrative surface", c.get("/admin/connectors", headers=sam).status_code, 403)

    say("B4: priya approves the host, registers the connector and looks at what it offers")
    check("host approved", c.post("/admin/hosts", headers=priya, json={"host": HOST, "note": "our Jira's MCP server"}).status_code, 200)
    registered = c.post("/admin/connectors", headers=priya, json={
        "connector_id": "acme", "url": MCP_URL, "credential_env": "", "description": "Jira, over its MCP server",
    })
    check("connector registered, vetting nothing", (registered.status_code, registered.json()["vetted"]), (201, 0))
    seen = c.post("/admin/connectors/acme/discovery", headers=priya)
    check("discovery dialled the real server", seen.status_code, 200)
    check("and it advertises two tools", sorted(t["name"] for t in seen.json()["tools"]), ["create_issue", "search_issues"])

    say("B4: she vets both tools for the CALLER'S OWN identity — nobody's token is shared")
    for name, effect in (("search_issues", "read"), ("create_issue", "write")):
        vetted = c.put(f"/admin/connectors/acme/tools/{name}", headers=priya, json={
            "effect": effect, "identity": "user",
            "resources": [{"type": "jira.project", "args": ["project"]}],
        })
        check(f"{name} vetted as {effect}, identity user", (vetted.status_code, vetted.json().get("identity")), (200, "user"))

    say("B4: she configures the consent flow, and the secret does not come back")
    flow = c.put("/admin/connectors/acme/oauth", headers=priya, json={
        "authorize_endpoint": f"{PROVIDER}/authorize", "token_endpoint": f"{PROVIDER}/token",
        "client_id": "client-abc", "client_secret": CLIENT_SECRET,
        "scopes": ["read:jira-work", "offline_access"],
    })
    check("configured", flow.status_code, 200)
    check("and the client secret is in nothing the browser saw", CLIENT_SECRET in flow.text, False)

    say("B6: she builds the agent in the wizard's shape, and a second one she keeps to herself")
    made = c.post("/agents", headers=priya, json={
        "name": "triage",
        "permissions": {"tools": ["acme_search_issues"], "scope": {"jira.project": {"read": ["ACME"]}}},
    })
    check("triage created", made.status_code, 201)
    check("and valid", c.get("/agents/triage", headers=priya).json()["valid"], True)
    private = c.post("/agents", headers=priya, json={
        "name": "payroll",
        "permissions": {"tools": ["acme_create_issue"], "scope": {"jira.project": {"write": ["HR"]}}},
    })
    check("payroll created", private.status_code, 201)

    say("D1: she shares triage with each colleague, and the outcome says they exist")
    for email in ("sam@acme.com", "tom@acme.com", "lee@acme.com"):
        shared = c.put(f"/agents/triage/grants/email/{email}", headers=priya, json={"role": "user"})
        check(f"shared with {email}", (shared.status_code, shared.json()["outcome"]), (200, "granted"))
    sheet = c.get("/agents/triage/access", headers=priya).json()
    check("the share sheet lists four people", len(sheet["access"]), 4)

    say("C1: sam signs in and sees the one agent shared with him — and nothing else")
    listed = c.get("/agents", headers=sam).json()
    names = sorted(a["name"] for a in (listed if isinstance(listed, list) else listed.get("agents", [])))
    check("sam's list is triage alone", names, ["triage"])
    check("payroll by URL is a 404 he cannot tell from absence", c.get("/agents/payroll", headers=sam).status_code, 404)
    connections = {r["connector_id"]: r for r in c.get("/connections", headers=sam).json()}
    check("the Connections page offers acme, connectable", connections["acme"]["state"], "connectable")
    check("and says what it will ask for", connections["acme"]["scopes"], ["read:jira-work", "offline_access"])

    say("C3: sam connects his own account by consent")
    row = consent(c, sam, "sam@acme.com")
    check("sam is connected", row["state"], "connected")
    check("as the provider said he is", row["account_label"], "sam@acme.com")
    check("the provider verified PKCE and issued one token", Provider.issued, 1)

    say("C2: tom hands his own credential to the terminal — pasted, never on argv")
    done = cli("--connect-account", "acme", "tom@acme.com", stdin=TOM_TOKEN + "\n")
    check("stored", done.returncode, 0)
    says("for the right person", done.stdout, "Connected 'acme' for user:")
    check("the credential is not in the command's output", TOM_TOKEN in done.stdout + done.stderr, False)
    theirs = {r["connector_id"]: r for r in c.get("/connections", headers=tom).json()}["acme"]
    check("tom's Connections page says connected", theirs["state"], "connected")
    check("lee's says connectable — connections are per person",
          {r["connector_id"]: r for r in c.get("/connections", headers=lee).json()}["acme"]["state"], "connectable")

    say("C4: each colleague mints their own token and pastes it into their assistant")
    assistants = {}
    minted = c.post("/me/tokens", headers=sam, json={"name": "claude-code"})
    check("sam minted a personal token", (minted.status_code, minted.json().get("acts_as_owner")), (201, True))
    assistants["sam"] = minted.json()["token"]
    # Found by this harness on 2026-09-07: token names were unique per *customer*, so the
    # second colleague to call theirs "claude-code" — the obvious name — was refused with
    # a sentence about "this customer". Migration 054 (step 108, scenario S2) made a
    # personal token's name the owner's: the obvious name works for everybody, and what
    # is refused is one person holding two live tokens by one name.
    for who, headers in (("tom", tom), ("lee", lee)):
        minted = c.post("/me/tokens", headers=headers, json={"name": "claude-code"})
        if not check(f"{who} minted a personal token under the same name as sam's — names are per owner",
                     (minted.status_code, minted.json().get("acts_as_owner")), (201, True)):
            print(f"        the server said: {minted.text[:300]}")
            return
        assistants[who] = minted.json()["token"]
    clash = c.post("/me/tokens", headers=sam, json={"name": "claude-code"})
    check("sam minting a second live token by the same name is refused", clash.status_code, 400)
    says("with the constraint's own words, about the owner rather than the customer",
         clash.json().get("detail"), "this owner already has a live personal token called")
    for who in ("sam", "tom", "lee"):
        status, answer = rpc(assistants[who], "tools/list")
        check(f"{who}'s assistant lists the shared agent's tool", [t["name"] for t in answer["result"]["tools"]], ["acme_search_issues"])

    say("C5: sam's and tom's calls go out as THEM — two people, two credentials, one door")
    TinyMcp.seen.clear()
    status, answer = rpc(assistants["sam"], "tools/call", {"name": "acme_search_issues", "arguments": {"project": "ACME"}})
    sam_saw = json.loads(answer["result"]["content"][0]["text"])["authorization"]
    check("sam's call went out under the token the provider issued to sam", sam_saw, f"Bearer {ACCESS_PREFIX}-1")
    status, answer = rpc(assistants["tom"], "tools/call", {"name": "acme_search_issues", "arguments": {"project": "ACME"}}, id_=2)
    tom_saw = json.loads(answer["result"]["content"][0]["text"])["authorization"]
    check("tom's went out under the credential tom pasted", tom_saw, f"Bearer {TOM_TOKEN}")
    check("and the two are different", sam_saw != tom_saw, True)
    check("the upstream saw exactly two calls", len(TinyMcp.seen), 2)

    say("C6: lee never connected — refused with the remedy, while the others work")
    status, refused = rpc(assistants["lee"], "tools/call", {"name": "acme_search_issues", "arguments": {"project": "ACME"}}, id_=3)
    check("a result the assistant can read, not a crash", (status, refused["result"].get("isError")), (200, True))
    sentence = refused["result"]["content"][0]["text"]
    print(f"        lee was told: {sentence[:220]!r}")
    says("naming the connector", sentence, "acme")
    check("nothing went upstream for lee", len(TinyMcp.seen), 2)
    status, answer = rpc(assistants["sam"], "tools/call", {"name": "acme_search_issues", "arguments": {"project": "ACME"}}, id_=4)
    check("sam still works", answer["result"].get("isError", False), False)

    say("F: the scope holds per person too — sam outside ACME is refused, upstream untouched")
    status, denied = rpc(assistants["sam"], "tools/call", {"name": "acme_search_issues", "arguments": {"project": "HR"}}, id_=5)
    check("a broker denial", denied["result"].get("isError"), True)
    check("the upstream saw no third call for sam", len(TinyMcp.seen), 3)

    say("D4: priya reads the door log — who called what, as whom, and what was refused")
    log = c.get("/admin/door-calls", headers=priya)
    check("the log answers the administrator", log.status_code, 200)
    rows = log.json()
    print(f"        {len(rows)} rows; the first: { {k: rows[0][k] for k in list(rows[0])[:8]} if rows else None }")
    principals = {r.get("principal_id") or r.get("principal") for r in rows}
    check("at least three distinct callers appear", len(principals) >= 3, True)
    decisions = sorted({r.get("decision") for r in rows})
    check("both decisions are on the page", decisions, ["allow", "deny"])
    check("sam cannot read it", c.get("/admin/door-calls", headers=sam).status_code, 403)

    say("D1: priya revokes tom's share; his token is still valid but reaches nothing")
    removed = c.delete("/agents/triage/grants/email/tom@acme.com", headers=priya)
    check("revoked", removed.status_code in (200, 204), True)
    status, answer = rpc(assistants["tom"], "tools/list", id_=6)
    check("tom's assistant now lists nothing", (status, answer["result"]["tools"]), (200, []))
    status, refused = rpc(assistants["tom"], "tools/call", {"name": "acme_search_issues", "arguments": {"project": "ACME"}}, id_=7)
    says("and a call is refused by name", (refused.get("error") or {}).get("message", ""), "acme_search_issues")
    check("tom's own connection is untouched — the share moved, not the credential",
          {r["connector_id"]: r for r in c.get("/connections", headers=tom).json()}["acme"]["state"], "connected")


if __name__ == "__main__":
    sys.exit(main())
