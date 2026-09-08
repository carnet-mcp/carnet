"""From an empty database to a person with a Connect button, **with no shell after boot**.

That sentence is the whole of step 12c, and this script is the only thing that can check
it. Every other verification in this step asserts a piece: a route refuses the right
person, a guard moved to the right layer, a secret does not come back. This asserts the
*distance* — that a customer's own engineer, given a deployment and a browser, can get
from nothing to a working self-serve connector without anybody running a command for them.

Until 12c they could not, and the evidence was not hypothetical: in one working session
the operator hit it twice, once asking where the CLI even runs from and once asking how a
customer is supposed to configure a GitHub consent flow *"if I keep doing it through
you"*. The person the product is for could not do the thing without the person the product
is by.

    cd backend && .venv/bin/python scripts/e2e_admin_onboarding.py

## What it drives

```
uvicorn, started with CARNET_BOOTSTRAP_ADMIN=priya@acme.com
    priya's first login              -> she is the first administrator
    sam's first login                -> he is not, and the table is no longer empty
    POST /admin/hosts                -> localtest.me
    POST /admin/connectors           -> registered, vetting nothing
    POST .../discovery               -> a REAL socket to a REAL MCP server
    PUT  .../tools/list_issues       -> approved, scoped to github.repo
    PUT  .../oauth                   -> a consent flow, secret in, nothing out
    GET  /tools                      -> the agent form can now offer it
    GET  /connections                -> "connectable": a Connect button, for sam too
```

**The only subprocess after `uvicorn` starts is `uvicorn`.** There is deliberately no
`cli(...)` helper in the arc, unlike `e2e_platform_roles.py`, and its absence is the
assertion — this script would still pass if `carnet` were not on the PATH. The CLI
appears exactly once, at the end, to check that its refusal and the route's are the same
string.

## Two things it does not do, said rather than implied

**It does not complete a consent flow.** `oauth.configure` checks the token endpoint's
scheme and its host and stores a sealed secret; it dials nothing. Driving consent to a
token needs an authorization server with real TLS and a browser-shaped redirect, which is
`scripts/e2e_oauth_consent.py`'s whole job and is not repeated here. What this asserts is
the administrative half — that the flow can be configured through the product, which is
the half that needed a shell yesterday.

**It does not open a browser.** The nav item, the wizard and the forms are verification 8
and are a thing somebody has to look at.

## The host is `localtest.me`, and that is not a workaround

The egress check refuses loopback, link-local and private addresses whatever a tenant
approves, so no locally-hosted server is reachable by its address. `localtest.me` is a
public DNS name resolving to `127.0.0.1`. Until step 058 that passed on the name alone
— the DNS-rebinding gap, used deliberately, with a note that closing it must break this
script "which is the correct alarm". The alarm fired: 058 vets what a name resolves to
at dial time, and this script now consents the sanctioned way, by naming the host in
`CARNET_EGRESS_INTERNAL_HOSTS` — the operator (here, this script) consenting to its
own machine.

Needs Postgres started first and outbound DNS for `localtest.me`. **Costs nothing**: no
run is submitted, so no model is called, and the MCP server is a local socket.
"""

import http.server
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_admin_onboarding_e2e"
BASE_DSN = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"

ISSUER = "https://e2e-admin-onboarding.local"
AUDIENCE = "api://default"
JWKS_PORT = 8908
API_PORT = 8131
MCP_PORT = 8932
API = f"http://127.0.0.1:{API_PORT}"
TENANT = "e2eadmin"

# Resolves to 127.0.0.1 and is not a literal IP. See the module docstring.
HOST = "localtest.me"
MCP_URL = f"http://{HOST}:{MCP_PORT}/mcp"

BOOTSTRAP_EMAIL = "priya@acme.com"

# A marker rather than a plausible value, so "the secret never comes back" is an assertion
# over the whole response text rather than an inspection of one field.
CLIENT_SECRET = "MARKER-CLIENT-SECRET-0c4f"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True)
JWK.update({"kid": "k1", "use": "sig", "alg": "RS256"})

# What the customer's server advertises. `delete_repository` is here and is never vetted —
# the case the allowlist exists for, and the thing a discovery must report without
# adopting.
TOOLS = [
    {
        "name": "list_issues",
        "description": "List issues in a repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "state": {"type": "string"},
            },
            "required": ["owner", "repo"],
        },
    },
    {
        "name": "delete_repository",
        "description": "Delete a repository and everything in it.",
        "inputSchema": {
            "type": "object",
            "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}},
            "required": ["owner", "repo"],
        },
    },
]


def dsn_for(database: str) -> str:
    """`BASE_DSN` with a database name spliced in, for both DSN spellings this runs under.

    Not a concatenation: a socket DSN carries its host in the query string and a TCP one
    does not, which is how an earlier version of this helper silently connected to the
    `postgres` database and reported that the migration had already been applied.
    """
    parts = urlsplit(BASE_DSN)
    return urlunsplit(
        (parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment)
    )


def token(sub, email):
    now = int(time.time())
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": sub,
            "email": email,
            "iat": now,
            "exp": now + 3600,
        },
        KEY,
        algorithm="RS256",
        headers={"kid": "k1"},
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


class MCPServer(BaseHTTPRequestHandler):
    """A conformant-enough Streamable HTTP MCP server, on a real socket.

    `e2e_http_connector.py`'s, near enough, and the duplication is deliberate rather than
    lazy: importing it would make this script depend on that one's module-level database
    setup, and a shared fake that two scripts configure differently is how one of them
    starts passing for the wrong reason.

    What matters here is that discovery is a **real HTTP round trip**. Every other test of
    the vetting path in this repository injects a transport, which is exactly right for a
    unit test and means `POST /admin/connectors/{id}/discovery` — a route whose defining
    property is that it dials a third party from a request thread — had no live evidence
    behind it.
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        message = json.loads(self.rfile.read(length) or "{}")

        if "id" not in message:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        method = message["method"]
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "acme-mcp-server", "version": "4.1.0"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        else:
            result = {}

        body = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Mcp-Session-Id", "sess-1")
        self.end_headers()
        self.wfile.write(body)


CHECKS = []


def check(label, actual, expected):
    """**Every line this prints is an assertion**, and it prints either way.

    `e2e_write_path.py`'s device and its reason: a script that printed without asserting
    would go on looking correct while quietly reporting a 500. It also never raises — a
    broken thing should tell you everything that is broken, which is a lesson 12b's edge
    script learned by crashing three checks into a mutation run and reporting one failure
    where twenty followed.
    """
    ok = actual == expected
    CHECKS.append((label, ok))
    mark = "ok  " if ok else "FAIL"
    print(f"  {mark} {label}: {actual!r}" + ("" if ok else f"  (expected {expected!r})"))
    return ok


def says(label, actual, fragment):
    """The same, for a sentence we care about the substance of rather than the wording."""
    ok = fragment in (actual or "")
    CHECKS.append((label, ok))
    mark = "ok  " if ok else "FAIL"
    print(f"  {mark} {label}: {fragment!r} in {str(actual)[:160]!r}")
    return ok


def detail(response) -> str:
    """A response's `detail`, or a description of why there is not one.

    **Never raises**, and that is the point rather than defensiveness. `check()`'s whole
    doctrine is that a broken thing tells you everything that is broken, and
    `detail(response)` breaks that at the first failure: under a mutation that
    turns a refusal into a 200 the body has no `detail`, the KeyError kills the run, and
    twenty checks that would also have failed are never reported as one failure.

    12b's edge script learned this by crashing three checks into a mutation run. This one
    learned it by crashing during **its own** mutation check, which is the cheaper of the
    two ways.
    """
    try:
        body = response.json()
    except Exception:  # noqa: BLE001 - a non-JSON body is a finding, not a crash
        return f"<not JSON: {response.text[:120]}>"
    if isinstance(body, dict) and "detail" in body:
        return str(body["detail"])
    return f"<no detail, status {response.status_code}: {str(body)[:120]}>"


def say(what):
    print(f"\n=== {what}", flush=True)


def main():
    import psycopg

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    dsn = dsn_for(DB)
    os.environ["CARNET_DATABASE_URL"] = dsn
    # Step 058: the dial vets DNS answers, and localtest.me resolves to loopback
    # on purpose — the operator (this script) consents to its own machine.
    os.environ["CARNET_EGRESS_INTERNAL_HOSTS"] = "localtest.me"
    os.environ["CARNET_SECRET_KEY"] = (
        os.environ.get("CARNET_SECRET_KEY") or _generate_key()
    )
    os.environ["CARNET_WORKERS"] = "0"
    os.environ["CARNET_TENANT"] = TENANT

    from carnet import storage
    from carnet.storage import migrate

    migrate.apply(dsn)

    from carnet.storage.postgres import PostgresStorage

    store = storage.configure(PostgresStorage(dsn))

    # The two rows a deployment creates by hand during onboarding, and **nothing else**.
    # No seed, no connector, no allowlist entry, no role: this is the state a new customer
    # is in on the day they are handed a URL, and everything after this point happens
    # through the product.
    store.create_tenant(TENANT, "12c end to end")
    store.save_tenant_idp(
        TENANT,
        {
            "issuer": ISSUER,
            "jwks_uri": f"http://127.0.0.1:{JWKS_PORT}/jwks.json",
            "audience": AUDIENCE,
            "allowed_domains": ("acme.com",),
        },
    )

    jwks = http.server.ThreadingHTTPServer(("127.0.0.1", JWKS_PORT), Jwks)
    threading.Thread(target=jwks.serve_forever, daemon=True).start()

    mcp = ThreadingHTTPServer(("127.0.0.1", MCP_PORT), MCPServer)
    threading.Thread(target=mcp.serve_forever, daemon=True).start()

    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)],
        # **The variable that makes the whole script possible**, set the way a deployment
        # sets it: in the server's environment, at boot, by whoever could have run the CLI.
        env={**os.environ, "CARNET_BOOTSTRAP_ADMIN": BOOTSTRAP_EMAIL},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
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

        run(store)
    finally:
        api.terminate()
        api.wait(timeout=10)
        jwks.shutdown()
        mcp.shutdown()
        store.close()

    failed = [label for label, ok in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print(f"  FAILED  {label}")
    raise SystemExit(1 if failed else 0)


def _generate_key():
    import base64
    import os as _os

    return base64.b64encode(_os.urandom(32)).decode()


def roles(store):
    return [
        (row["principal_kind"], row["principal_id"])
        for row in store.list_platform_roles(TENANT)
    ]


def run(store):
    priya = {"Authorization": f"Bearer {token('00u-priya', BOOTSTRAP_EMAIL)}"}
    sam = {"Authorization": f"Bearer {token('00u-sam', 'sam@acme.com')}"}

    # --- the first administrator, from configuration ----------------------------------

    say("nobody administers this workspace yet")
    check("platform_roles is empty", roles(store), [])

    say("priya signs in for the first time, and two requests race")
    # **Two concurrent first logins**, which is the edge the plan calls out: both pass the
    # empty-table check because it is deliberately not atomic, and the grant is an upsert.
    # The worst case is a duplicate line in the log; the thing that must not happen is two
    # rows or a failed login. A lock on the login path would cost every request in the
    # product to deduplicate one line on one day of a deployment's life.
    answers = []
    threads = [
        threading.Thread(
            target=lambda: answers.append(httpx.get(f"{API}/me", headers=priya, timeout=10))
        )
        for _ in range(2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    check("both requests answered 200", sorted(a.status_code for a in answers), [200, 200])
    check("both say she is an administrator", [a.json()["admin"] for a in answers], [True, True])

    appointed = roles(store)
    check("exactly one role row, from a race", len(appointed), 1)
    check("and it is a person, not a system principal", appointed[0][0], "user")

    grants = [
        row
        for row in store.admin_audit_records(TENANT)
        if row["action"] == "role.grant"
    ]
    check("the log says who appointed her", grants[0]["actor_kind"] + ":" + grants[0]["actor_id"], "system:bootstrap")
    # **The race's whole cost, measured rather than predicted.** The plan says the
    # empty-table check is deliberately not atomic and that the worst case is a duplicate
    # log entry. This run produces one — the two threads both saw an empty table — and
    # that is the entire consequence: one row, one administrator, and a log line somebody
    # reads twice. A lock on the login path would cost every request in the product to
    # prevent it.
    from_the_race = len(grants)
    check("at most one duplicate record, and no more", from_the_race <= 2, True)

    say("sam signs in, and the variable is now inert")
    me = httpx.get(f"{API}/me", headers=sam, timeout=10).json()
    check("sam is not an administrator", me["admin"], False)
    check("and no second row appeared", len(roles(store)), 1)

    say("and priya signing in again appoints nobody a second time")
    # **The assertion that catches a missing empty-table check**, and the first version of
    # this script did not have it — the mutation went straight through 104 green checks.
    # Without that condition the grant is still an upsert, so the *row* count never moves
    # and nothing else here would notice. What does move is the log: `grant_platform_role`
    # records every time it is called, so every authenticated request she ever makes would
    # write an administrative record. A log that grows by a line per page view is a log
    # nobody can read, and it is the actual consequence of getting this wrong.
    #
    # Measured against what the race already produced rather than against 1, because the
    # race legitimately writes a duplicate — see above. What must not happen is *growth*.
    for _ in range(3):
        httpx.get(f"{API}/me", headers=priya, timeout=10)
    check("still one role row", len(roles(store)), 1)
    check(
        "and three more logins wrote no further grants",
        len([r for r in store.admin_audit_records(TENANT) if r["action"] == "role.grant"]),
        from_the_race,
    )

    say("sam is refused the whole administrative surface, in the server's own words")
    # **Every route, driven as an ordinary colleague.** For most of these the dependency is
    # the *only* guard — `register_connector`, `allow_host` and `discover` check no role at
    # all, having been written for a CLI whose caller is always an administrator — so this
    # is not belt-and-braces over `access/groups.py`'s own check. It is the check.
    for label, response in (
        ("GET /admin/hosts", httpx.get(f"{API}/admin/hosts", headers=sam)),
        ("POST /admin/hosts", httpx.post(f"{API}/admin/hosts", headers=sam, json={"host": "x.example"})),
        ("DELETE /admin/hosts/{h}", httpx.delete(f"{API}/admin/hosts/x.example", headers=sam)),
        ("GET /admin/connectors", httpx.get(f"{API}/admin/connectors", headers=sam)),
        (
            "POST /admin/connectors",
            httpx.post(f"{API}/admin/connectors", headers=sam, json={"connector_id": "x", "url": MCP_URL}),
        ),
        ("GET /admin/connectors/{id}", httpx.get(f"{API}/admin/connectors/acme", headers=sam)),
        ("POST .../discovery", httpx.post(f"{API}/admin/connectors/acme/discovery", headers=sam)),
        (
            "PUT .../tools/{n}",
            httpx.put(f"{API}/admin/connectors/acme/tools/list_issues", headers=sam, json={"effect": "read"}),
        ),
        (
            "PUT .../oauth",
            httpx.put(
                f"{API}/admin/connectors/acme/oauth",
                headers=sam,
                json={
                    "authorize_endpoint": f"https://{HOST}/a",
                    "token_endpoint": f"https://{HOST}/t",
                    "client_id": "c",
                    "client_secret": "s",
                },
            ),
        ),
        ("DELETE .../oauth", httpx.delete(f"{API}/admin/connectors/acme/oauth", headers=sam)),
        ("GET /admin-audit", httpx.get(f"{API}/admin-audit", headers=sam)),
    ):
        check(f"403 on {label}", response.status_code, 403)

    says(
        "with a sentence he can act on",
        httpx.get(f"{API}/admin/connectors", headers=sam).json()["detail"],
        "administrator",
    )
    check("and he changed nothing", store.allowed_hosts(TENANT), [])

    # --- the arc, entirely over HTTP --------------------------------------------------

    say("she approves the host her server lives on")
    pasted = httpx.post(
        f"{API}/admin/hosts", headers=priya, json={"host": MCP_URL}, timeout=10
    )
    check("a pasted URL is a 400, not a 404", pasted.status_code, 400)
    says("naming what to strip", detail(pasted), "just the hostname")

    approved = httpx.post(
        f"{API}/admin/hosts",
        headers=priya,
        json={"host": HOST, "note": "our own MCP server"},
        timeout=10,
    )
    check("the host is approved", approved.status_code, 200)
    check("and normalized in the answer", approved.json()["host"], HOST)
    check("with no warning, because it can be dialled", approved.json()["warning"], "")

    say("a host that can never be dialled is recorded and warned about")
    never = httpx.post(
        f"{API}/admin/hosts", headers=priya, json={"host": "localhost"}, timeout=10
    )
    check("still a 200 — the row records that somebody asked", never.status_code, 200)
    says("and the body says it will not be dialled", never.json()["warning"], "will NOT be dialled")

    listed = {row["host"]: row for row in httpx.get(f"{API}/admin/hosts", headers=priya).json()}
    check("both rows are in the allowlist", sorted(listed), ["localhost", HOST])
    says("and the warning is on the row, not only on the answer", listed["localhost"]["warning"], "localhost")
    check("the allowlist names who approved it", listed[HOST]["allowed_by"].startswith("user:"), True)

    say("she registers the connector, and it vets nothing")
    elsewhere = httpx.post(
        f"{API}/admin/connectors",
        headers=priya,
        json={"connector_id": "acme", "url": "https://not-approved.example.com/mcp"},
        timeout=10,
    )
    check("an unapproved host is refused at registration", elsewhere.status_code, 400)
    says("naming what is approved", detail(elsewhere), "has not approved the host")

    registered = httpx.post(
        f"{API}/admin/connectors",
        headers=priya,
        json={
            "connector_id": "acme",
            "url": MCP_URL,
            "credential_env": "",
            "description": "Acme's own issue tracker",
        },
        timeout=10,
    )
    check("201", registered.status_code, 201)
    check("nothing is vetted", registered.json()["vetted"], 0)
    check("and its host is approved", registered.json()["host_allowed"], True)

    again = httpx.post(
        f"{API}/admin/connectors",
        headers=priya,
        json={"connector_id": "acme", "url": MCP_URL},
        timeout=10,
    )
    check("registering it twice is a 409, not a silent replace", again.status_code, 409)

    say("the catalogue is still empty, because registration approves nothing")
    catalogue = httpx.get(f"{API}/tools", headers=priya, timeout=10).json()
    groups = [group for group in catalogue if group["id"] == "acme"]
    check("acme contributes no tools yet", [t for g in groups for t in g["tools"]], [])

    say("she looks at the server — a real socket, from a request thread")
    seen = httpx.post(f"{API}/admin/connectors/acme/discovery", headers=priya, timeout=30)
    check("200", seen.status_code, 200)
    body = seen.json()
    check("the server identified itself", body["server"], "acme-mcp-server v4.1.0")
    check(
        "and advertises both tools",
        sorted(tool["name"] for tool in body["tools"]),
        ["delete_repository", "list_issues"],
    )

    issues = next(tool for tool in body["tools"] if tool["name"] == "list_issues")
    check("nothing is vetted yet", issues["vetted"], False)
    check("the local name is shown before anybody commits to it", issues["local_name"], "acme_list_issues")
    # **The one thing a person cannot guess**, and the reason discovery exists at all.
    check(
        "each argument, with its requiredness",
        [(a["name"], a["type"], a["required"]) for a in issues["arguments"]],
        [("owner", "string", True), ("repo", "string", True), ("state", "string", False)],
    )

    say("she approves one tool, scoped to a resource composed from two arguments")
    invented = httpx.put(
        f"{API}/admin/connectors/acme/tools/invent_issues",
        headers=priya,
        json={"effect": "read", "resources": []},
        timeout=30,
    )
    check("a tool the server does not advertise is a 400", invented.status_code, 400)
    says("naming what it does offer", detail(invented), "list_issues")

    mistyped = httpx.put(
        f"{API}/admin/connectors/acme/tools/list_issues",
        headers=priya,
        json={"effect": "read", "resources": [{"type": "github.repo", "args": ["repository"]}]},
        timeout=30,
    )
    check("an argument the schema does not have is a 400", mistyped.status_code, 400)
    says("and it says why that matters", detail(mistyped), "never applies")

    vetted = httpx.put(
        f"{API}/admin/connectors/acme/tools/list_issues",
        headers=priya,
        json={
            "effect": "read",
            "resources": [
                {"type": "github.repo", "args": ["owner", "repo"], "template": "{owner}/{repo}"}
            ],
            "note": "Reads only. Scope this to the repositories a team owns.",
        },
        timeout=30,
    )
    check("200", vetted.status_code, 200)
    check("recorded under its local name", vetted.json()["local_name"], "acme_list_issues")
    check("against the server it was approved from", vetted.json()["server"], "acme-mcp-server v4.1.0")

    say("a write with nothing to scope it to is refused, not stored")
    unscopeable = httpx.put(
        f"{API}/admin/connectors/acme/tools/delete_repository",
        headers=priya,
        json={"effect": "write", "resources": []},
        timeout=30,
    )
    # Until 12c this was a bare `RuntimeError` out of `tools.validate` and therefore a
    # **500** — "the server broke", to somebody whose remedy was to fill in one more field.
    check("400, and not a 500", unscopeable.status_code, 400)
    says("saying what to do instead", detail(unscopeable), "mark it read")

    say("the vetting record names a person and a server version")
    acme = httpx.get(f"{API}/admin/connectors/acme", headers=priya, timeout=10).json()
    check("one tool is approved", acme["vetted"], 1)
    check("and none of them writes", acme["writes"], 0)
    tool = acme["tools"][0]
    check("scoped to the resource type, not to argument names", [r["type"] for r in tool["resources"]], ["github.repo"])
    check("approved by a person", tool["vetted_by"].startswith("user:"), True)
    check("against a recorded version", (tool["server_name"], tool["server_version"]), ("acme-mcp-server", "4.1.0"))

    say("re-vetting restamps that row and writes a second record")
    httpx.put(
        f"{API}/admin/connectors/acme/tools/list_issues",
        headers=priya,
        json={
            "effect": "read",
            "resources": [
                {"type": "github.repo", "args": ["owner", "repo"], "template": "{owner}/{repo}"}
            ],
            "note": "Second look: still reads only.",
        },
        timeout=30,
    )
    acme = httpx.get(f"{API}/admin/connectors/acme", headers=priya, timeout=10).json()
    check("still exactly one tool — an upsert, not an append", acme["vetted"], 1)
    check("and the new note replaced the old", acme["tools"][0]["note"], "Second look: still reads only.")
    vet_records = [r for r in store.admin_audit_records(TENANT) if r["action"] == "connector.vet"]
    check("two records, because a new review is not an edit", len(vet_records), 2)

    say("the discovery now marks what is vetted, and reports what is not")
    body = httpx.post(f"{API}/admin/connectors/acme/discovery", headers=priya, timeout=30).json()
    marked = {tool["name"]: tool["vetted"] for tool in body["tools"]}
    check("list_issues is marked", marked["list_issues"], True)
    check("delete_repository is not", marked["delete_repository"], False)
    check(
        "and the unvetted tool is reported rather than adopted",
        any("delete_repository" in f["message"] for f in body["findings"]),
        True,
    )
    check("with nothing blocking", [f for f in body["findings"] if f["severity"] == "refuse"], [])

    # --- the tool reaches the agent form ----------------------------------------------

    say("the agent form can now offer it — to sam, who administers nothing")
    catalogue = httpx.get(f"{API}/tools", headers=sam, timeout=10).json()
    offered = {
        tool["name"]: tool for group in catalogue for tool in group["tools"]
    }
    check("acme_list_issues is in the catalogue", "acme_list_issues" in offered, True)
    check("marked as a read", offered["acme_list_issues"]["effect"], "read")
    check("with the vendor's own description", offered["acme_list_issues"]["description"], "List issues in a repository.")
    check("delete_repository is not offered to anybody", "acme_delete_repository" in offered, False)

    # --- the consent flow --------------------------------------------------------------

    say("before a consent flow, nobody can connect their own account")
    rows = {r["connector_id"]: r for r in httpx.get(f"{API}/connections", headers=sam).json()}
    check("acme is unavailable to sam", rows["acme"]["state"], "unavailable")

    say("she configures one, and the secret goes in and does not come back")
    plaintext = httpx.put(
        f"{API}/admin/connectors/acme/oauth",
        headers=priya,
        json={
            "authorize_endpoint": f"http://{HOST}/authorize",
            "token_endpoint": f"http://{HOST}/token",
            "client_id": "client-abc",
            "client_secret": CLIENT_SECRET,
            "scopes": ["read:issues"],
        },
        timeout=10,
    )
    # The plan's edge table claimed this was "already mapped". It was not: `check_oauth_app`
    # raises a bare `StorageError`, so an `http://` endpoint answered **503 storage
    # unavailable** until `ValueRefused` was split out in 12c.
    check("a non-TLS authorization server is a 400, not a 503", plaintext.status_code, 400)
    says("and says why over http is unacceptable", detail(plaintext), "https")

    unapproved = httpx.put(
        f"{API}/admin/connectors/acme/oauth",
        headers=priya,
        json={
            "authorize_endpoint": f"https://{HOST}/authorize",
            "token_endpoint": "https://not-approved.example.com/token",
            "client_id": "client-abc",
            "client_secret": CLIENT_SECRET,
            "scopes": ["read:issues"],
        },
        timeout=10,
    )
    check("a token endpoint off the allowlist is refused", unapproved.status_code, 400)
    says("because that is where the client secret is posted", detail(unapproved), "has not approved the host")

    configured = httpx.put(
        f"{API}/admin/connectors/acme/oauth",
        headers=priya,
        json={
            "authorize_endpoint": f"https://{HOST}/authorize",
            "token_endpoint": f"https://{HOST}/token",
            "revoke_endpoint": f"https://{HOST}/revoke",
            "client_id": "client-abc",
            "client_secret": CLIENT_SECRET,
            "scopes": ["read:issues", "offline_access"],
        },
        timeout=10,
    )
    check("200", configured.status_code, 200)
    check("the secret is not in the response", CLIENT_SECRET in configured.text, False)
    check(
        "the response carries exactly the public fields",
        sorted(configured.json()["app"]),
        sorted(
            [
                "authorize_endpoint",
                "authorize_params",
                "client_id",
                "configured_at",
                "configured_by",
                "connector_id",
                "revoke_endpoint",
                "scope_notes",
                "scopes",
                "token_endpoint",
            ]
        ),
    )
    says(
        "and the redirect URI to register at the provider",
        configured.json()["redirect_uri"],
        "/connect/callback",
    )
    check("with no warnings, because offline access was asked for", configured.json()["warnings"], [])

    say("the secret is nowhere else either")
    for label, response in (
        ("the connector detail", httpx.get(f"{API}/admin/connectors/acme", headers=priya)),
        ("the connector list", httpx.get(f"{API}/admin/connectors", headers=priya)),
        ("the connections page", httpx.get(f"{API}/connections", headers=priya)),
        ("the administrative log", httpx.get(f"{API}/admin-audit", headers=priya)),
    ):
        check(f"not in {label}", CLIENT_SECRET in response.text, False)

    say("and sam now has a Connect button")
    rows = {r["connector_id"]: r for r in httpx.get(f"{API}/connections", headers=sam).json()}
    check("acme is connectable", rows["acme"]["state"], "connectable")
    check("and he is told what it will ask for", rows["acme"]["scopes"], ["read:issues", "offline_access"])

    say("removing it leaves credentials alone and says nothing was stranded")
    removed = httpx.delete(f"{API}/admin/connectors/acme/oauth", headers=priya, timeout=10)
    check("200", removed.status_code, 200)
    check("it was there", removed.json()["removed"], True)
    check("removing it twice is a no-op that says so", httpx.delete(f"{API}/admin/connectors/acme/oauth", headers=priya).json()["removed"], False)

    # Put it back: everything after this is about the finished state.
    httpx.put(
        f"{API}/admin/connectors/acme/oauth",
        headers=priya,
        json={
            "authorize_endpoint": f"https://{HOST}/authorize",
            "token_endpoint": f"https://{HOST}/token",
            "client_id": "client-abc",
            "client_secret": CLIENT_SECRET,
            "scopes": ["read:issues"],
        },
        timeout=10,
    )

    say("a consent flow with no offline scope warns rather than refusing")
    warned = httpx.put(
        f"{API}/admin/connectors/acme/oauth",
        headers=priya,
        json={
            "authorize_endpoint": f"https://{HOST}/authorize",
            "token_endpoint": f"https://{HOST}/token",
            "client_id": "client-abc",
            "client_secret": CLIENT_SECRET,
            "scopes": ["read:issues"],
        },
        timeout=10,
    )
    check("200 — every provider spells this differently", warned.status_code, 200)
    check("with two warnings", len(warned.json()["warnings"]), 2)
    says("about refresh tokens", " ".join(warned.json()["warnings"]), "offline access")
    says("and about revocation", " ".join(warned.json()["warnings"]), "live at the provider")

    # --- revoking the host underneath it ------------------------------------------------

    say("revoking the host strands the connector and destroys nothing")
    stranded = httpx.delete(f"{API}/admin/hosts/{HOST}", headers=priya, timeout=10)
    check("200 with a body", stranded.status_code, 200)
    check("it names the connector", stranded.json()["stranded"], ["acme"])
    acme = httpx.get(f"{API}/admin/connectors/acme", headers=priya, timeout=10).json()
    check("which still exists", acme["connector_id"], "acme")
    check("and still knows what was approved on it", acme["vetted"], 1)
    check("but will no longer connect", acme["host_allowed"], False)

    down = httpx.post(f"{API}/admin/connectors/acme/discovery", headers=priya, timeout=30)
    check("discovery against a revoked host is refused before it dials", down.status_code, 400)
    says("by the allowlist", detail(down), "has not approved the host")

    httpx.post(f"{API}/admin/hosts", headers=priya, json={"host": HOST}, timeout=10)
    check(
        "and re-approving it brings the connector back",
        httpx.get(f"{API}/admin/connectors/acme", headers=priya).json()["host_allowed"],
        True,
    )

    # --- the seam parity the moved guards rest on -----------------------------------------

    say("the stdio refusal is the same sentence from the CLI and from the route")
    from carnet.access import oauth

    # The shipped stdio connector, put in this tenant directly — there is deliberately no
    # route that can create one, which is the point of `STDIO_REFUSED`.
    from carnet import tools as tools_module
    from carnet.tools.mcp.connectors.github import CONNECTOR as GITHUB

    tools_module.save_connector(TENANT, GITHUB, actor="system:e2e")

    expected = oauth.STDIO_CONSENT_REFUSED.format(connector=GITHUB.id)
    via_route = httpx.put(
        f"{API}/admin/connectors/{GITHUB.id}/oauth",
        headers=priya,
        json={
            "authorize_endpoint": f"https://{HOST}/authorize",
            "token_endpoint": f"https://{HOST}/token",
            "client_id": "client-abc",
            "client_secret": CLIENT_SECRET,
            "scopes": [],
        },
        timeout=10,
    )
    check("the route refuses it", via_route.status_code, 400)
    check("in the seam's exact words", detail(via_route), expected)

    # **The only subprocess in this file other than uvicorn**, and it is here to compare a
    # string rather than to do any of the work. Everything above happened over HTTP.
    result = subprocess.run(
        [
            sys.executable, "-m", "carnet.cli",
            "--set-oauth", GITHUB.id,
            "--auth-server", f"https://{HOST}",
            "--client-id", "client-abc",
        ],
        env={**os.environ, "CARNET_TENANT": TENANT},
        input=CLIENT_SECRET,
        capture_output=True,
        text=True,
    )
    check("the CLI refuses it too", result.returncode != 0, True)
    check("byte for byte the same sentence", expected in result.stderr, True)

    say("and the never-dialled warning is the same from both")
    from carnet.tools.mcp import egress

    cli_warning = subprocess.run(
        [sys.executable, "-m", "carnet.cli", "--allow-host", "127.0.0.1"],
        env={**os.environ, "CARNET_TENANT": TENANT},
        capture_output=True,
        text=True,
    )
    route_warning = httpx.post(
        f"{API}/admin/hosts", headers=priya, json={"host": "127.0.0.2"}, timeout=10
    ).json()["warning"]
    check("the CLI prints it on stderr", egress.approval_warning("127.0.0.1") in cli_warning.stderr, True)
    check("the route puts it in the body", route_warning, egress.approval_warning("127.0.0.2"))

    # --- what a suspended customer reaches -------------------------------------------

    say("a suspended customer's administrator reaches none of it")
    store.set_tenant_status(TENANT, "suspended")
    for label, response in (
        ("hosts", httpx.get(f"{API}/admin/hosts", headers=priya)),
        ("connectors", httpx.get(f"{API}/admin/connectors", headers=priya)),
        ("discovery", httpx.post(f"{API}/admin/connectors/acme/discovery", headers=priya)),
        ("the log", httpx.get(f"{API}/admin-audit", headers=priya)),
    ):
        check(f"403 on {label}", response.status_code, 403)
        says(f"because the customer is suspended, not because of a role — {label}", detail(response), "suspended")

    store.set_tenant_status(TENANT, "active")
    check(
        "and it all comes back",
        httpx.get(f"{API}/admin/hosts", headers=priya).status_code,
        200,
    )


if __name__ == "__main__":
    main()
