"""The MCP door, driven by somebody else's MCP client, against a real database.

**Not a test, and it is here for the thing `tests/test_door.py` structurally cannot do.**
That suite drives the door through FastAPI's `TestClient` against the in-memory store
with a fake transport — which proves the logic and proves nothing about the wire. Two
gaps, and this script exists for both:

**The client is the official `mcp` SDK.** This repository hand-wrote its MCP *client*
(`tools/mcp/client.py`) for reasons that file states, and the door's own tests use it —
so until now every byte on both sides of this protocol was produced by code that shares
all of its assumptions. An asymmetric reading of the specification is invisible to that
arrangement by construction. Here a client written by other people, parsing with its own
Pydantic models, does the initialize / list / call sequence over a real socket. It is the
same argument `e2e_http_connector.py` makes about the transport, aimed the other way
round: that script proves we can *speak* to a real server, this one proves a real client
can speak to *us*.

**And it runs against Postgres.** The per-token budget is one
`INSERT ... ON CONFLICT DO UPDATE ... WHERE` (migration 040), and the whole reason it is
a table rather than a counter is that the API has to be able to run replicated. The
in-memory store answers that with a comparison under a lock, which is the shape that
agrees until it does not — so the ceiling is exercised here against the statement that
actually enforces it.

    cd backend && .venv/bin/python scripts/e2e_mcp_door.py

Needs Postgres started first, outbound DNS for `localtest.me` (see below), and the MCP
SDK, which is **not** a dependency of this project and is deliberately not in `dev`:

    uv pip install -e ".[mcpclient]"

`playwright` and the browser scripts are the precedent — a dependency somebody installs
when they want the check that finds a class of bug nothing else can, kept out of the
suite so `pytest` still starts nothing and calls nothing.

Costs nothing: no model is called, and the upstream MCP server is a local socket.

## What this does NOT cover, stated plainly

- **Caddy.** This drives uvicorn directly. The front door's ingress contract already
  tolerates the `/api/*` shapes this uses, and nothing here is a new HTTP shape — but a
  deployment-shaped run of the door through `deploy/` is not in this script.
- **Agent mode**, which does not exist yet. Acting-for (033c) IS covered: verified
  against a real dev IdP the API fetches JWKS from over a socket, asserted behind the
  connector opt-in, and the back-door case (a `service` tool with acting-for present
  stays on the shared credential) — each asserted by reading whose credential the
  upstream actually saw. Personal tokens (033d) are covered too: minted `--as-owner`
  by the real CLI, listing the owner's union with zero grants of their own, refused
  as a grantee at the real share command, acting as the owner's connected account on
  a `user`-identity tool, and dying with the owner's grant and then with the owner.
- **Two API replicas.** The budget is asserted against the statement in Postgres, which
  is what makes N replicas safe; two processes actually racing it is `test_concurrency`'s
  shape and is not driven here.

## Why the upstream host is `localtest.me`

`e2e_http_connector.py`'s reason: the egress check refuses loopback by address whatever
a tenant approves, and `localtest.me` is a public name resolving to 127.0.0.1. Until
step 058 that rode the DNS-rebinding gap, with a note that closing it must break this
script — the correct alarm. It fired: dials vet what a name resolves to now, and this
script consents the sanctioned way, `CARNET_EGRESS_INTERNAL_HOSTS=localtest.me`.
"""

import asyncio
import base64
import json
import os
import pathlib
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_mcp_door_e2e"
TENANT = "e2edoor"

# The upstream MCP server this tenant has vetted — the thing the door brokers *to*.
UPSTREAM_HOST = "localtest.me"
UPSTREAM_PORT = 8942

# Carnet's own API, which is what the SDK client dials.
API_PORT = 8143
API = f"http://127.0.0.1:{API_PORT}"
DOOR = f"{API}/mcp"

# The tenant's identity provider — `scripts/dev_idp.py`, in a thread. The acting-for
# scenes forward its tokens, and the API verifies them through exactly the production
# path: JWKS over HTTP, signature, issuer, audience.
IDP_PORT = 8944

# The wire key an acting-for identity rides under, spelled as a literal on purpose:
# this script exists to prove the contract against a client that shares none of our
# constants, so importing the constant would prove nothing.
ACTING_FOR_KEY = "com.carnet/acting-for"

# Tom's own account at the upstream, sealed by a consent flow's write. Every acting-for
# call that succeeds should reach the server as this, never as SHARED.
TOM_GITHUB = "toms-github-token"

OWNER = "u_priya"
ACTOR = "system:cli"

# The connector's shared credential. Every door call in this script should reach the
# upstream server as this, because every tool here is vetted `identity: service` — and
# the script asserts that by reading what the server saw.
SHARED = "acme-service-token"

TOOLS = [
    {
        "name": "list_issues",
        "description": "List issues in a repository.",
        "inputSchema": {
            "type": "object",
            "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}},
            "required": ["owner", "repo"],
        },
    },
    {
        "name": "delete_repository",
        "description": "Delete a repository and everything in it.",
        "inputSchema": {
            "type": "object",
            "properties": {"owner": {"type": "string"}},
            "required": ["owner"],
        },
    },
]

SEEN = []
SEEN_LOCK = threading.Lock()


def dsn_for(database):
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


DSN = dsn_for(DB)


class Upstream(BaseHTTPRequestHandler):
    """The customer's own MCP server. `e2e_http_connector.py`'s, trimmed."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        message = json.loads(self.rfile.read(length) or "{}")

        with SEEN_LOCK:
            SEEN.append(
                {
                    "method": message.get("method"),
                    "authorization": self.headers.get("Authorization"),
                    "arguments": (message.get("params") or {}).get("arguments"),
                }
            )

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
        elif method == "tools/call":
            arguments = (message.get("params") or {}).get("arguments") or {}
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "issues": [{"number": 1, "repo": arguments.get("repo")}],
                                "seen_authorization": self.headers.get("Authorization"),
                            }
                        ),
                    }
                ]
            }
        else:
            result = {}

        body = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


CHECKS = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((ok, label))
    print(f"{'  ok' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        expected: {expected!r}")
        print(f"        actual:   {actual!r}")
    return ok


def says(label, actual, fragment):
    ok = fragment in str(actual)
    CHECKS.append((ok, label))
    print(f"{'  ok' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        wanted {fragment!r} in: {actual!r}")
    return ok


def step(what):
    print(f"\n=== {what}", flush=True)


def _generate_key():
    return base64.b64encode(os.urandom(32)).decode()


# --- the SDK client ----------------------------------------------------------------


async def _with_session(token, body):
    """Run `body(session)` against the door, as the official SDK client sees it."""
    import httpx2
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=30)
    async with http:
        async with streamable_http_client(DOOR, http_client=http) as streams:
            read, write = streams[0], streams[1]
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                return await body(session, initialized)


def with_session(token, body):
    return asyncio.run(_with_session(token, body))


async def _with_oauth_session(redirect_handler, callback_handler, body):
    """Step 083: the SDK's own `OAuthClientProvider` does discovery, registration,
    the PKCE dance and the exchange; this script only plays the browser."""
    import httpx2
    from mcp import ClientSession
    from mcp.client.auth import OAuthClientProvider
    from mcp.client.streamable_http import streamable_http_client
    from mcp.shared.auth import OAuthClientMetadata
    from pydantic import AnyUrl

    class Memory:
        tokens = None
        client_info = None

        async def get_tokens(self):
            return self.tokens

        async def set_tokens(self, tokens):
            self.tokens = tokens

        async def get_client_info(self):
            return self.client_info

        async def set_client_info(self, client_info):
            self.client_info = client_info

    storage = Memory()
    provider = OAuthClientProvider(
        server_url=DOOR,
        client_metadata=OAuthClientMetadata(
            client_name="e2e assistant",
            redirect_uris=[AnyUrl("http://localhost:6274/callback")],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        ),
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )
    http = httpx2.AsyncClient(auth=provider, timeout=30)
    async with http:
        async with streamable_http_client(DOOR, http_client=http) as streams:
            read, write = streams[0], streams[1]
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                result = await body(session, initialized)
    held = storage.tokens.access_token if storage.tokens else ""
    return (*result, held)


def with_oauth_session(redirect_handler, callback_handler, body):
    return asyncio.run(_with_oauth_session(redirect_handler, callback_handler, body))


async def _oauth_body(session, _initialized):
    listed = await session.list_tools()
    answer = await session.call_tool("acme_list_issues", {"owner": "acme", "repo": "web"})
    return answer, [t.name for t in listed.tools]


def text_of(result):
    """The first text block of a `tools/call` result, parsed."""
    for block in result.content:
        if getattr(block, "type", None) == "text":
            return json.loads(block.text)
    return {}


# --- the script --------------------------------------------------------------------


def main():
    import psycopg

    try:
        import mcp  # noqa: F401
    except ImportError:
        raise SystemExit(
            "this script drives the official MCP SDK, which is deliberately not a "
            "dependency of this project. Install it:\n"
            "    uv pip install -e \".[mcpclient]\""
        ) from None

    if socket.gethostbyname(UPSTREAM_HOST) != "127.0.0.1":
        raise SystemExit(f"{UPSTREAM_HOST} did not resolve to 127.0.0.1; this needs DNS")

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    # Step 058: the dial vets DNS answers, and localtest.me resolves to loopback
    # on purpose — the operator (this script) consents to its own machine.
    os.environ["CARNET_EGRESS_INTERNAL_HOSTS"] = "localtest.me"
    os.environ.setdefault("CARNET_SECRET_KEY", _generate_key())
    os.environ["CARNET_TENANT"] = TENANT
    # No worker: nothing here submits a run, and a door call must not become one.
    os.environ["CARNET_WORKERS"] = "0"
    os.environ["ACME_TOKEN"] = SHARED
    # Small enough to exhaust deliberately, in the same process the door serves from —
    # which is the point: the ceiling has to come from the row, not from this variable
    # being read once at import.
    os.environ["CARNET_MCP_CALLS_PER_DAY"] = "3"
    # Step 083. The OAuth documents derive every URL from this, and the SDK client
    # follows them: the API here is at the origin root, no `/api` prefix.
    os.environ["CARNET_PUBLIC_ORIGIN"] = API

    from carnet import agents, storage, tools
    from carnet.core import crypto
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage
    from carnet.tools.base import Resource

    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    crypto.configure(crypto.from_environment())
    store.create_tenant(TENANT, "033b end to end")
    store.create_user(
        TENANT,
        {
            "id": OWNER,
            "issuer": "https://idp.e2edoor.local",
            "subject": "00u1",
            "email": "priya@acme.com",
        },
    )

    upstream = ThreadingHTTPServer(("127.0.0.1", UPSTREAM_PORT), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()

    api = None
    try:
        # --- what an administrator sets up, before any client exists --------------

        step("an administrator registers the server and approves ONE of its two tools")

        store.allow_host(TENANT, UPSTREAM_HOST, actor=ACTOR, note="Acme's issue tracker")
        tools.register_connector(
            TENANT,
            "acme",
            url=f"http://{UPSTREAM_HOST}:{UPSTREAM_PORT}/mcp",
            credential_env="ACME_TOKEN",
            description="Acme's internal issue tracker",
            actor=ACTOR,
        )
        tools.vet_tool(
            TENANT,
            "acme",
            "list_issues",
            effect="read",
            identity="service",
            resources=(Resource("github.repo", ["owner", "repo"], template="{owner}/{repo}"),),
            actor=ACTOR,
            credential=SHARED,
        )
        vetted = [v.remote_name for v in tools.mcp.get_connector(TENANT, "acme").vetted]
        check("one tool approved, one deliberately not", vetted, ["list_issues"])

        step("somebody builds an agent out of it and shares it with a token")

        agents.save(
            TENANT,
            {
                "name": "triage",
                "runtime": "simple",
                "system": "You triage issues.",
                "permissions": {
                    "tools": ["acme_list_issues"],
                    "scope": {"github.repo": {"read": ["acme/*"]}},
                },
            },
            actor=ACTOR,
        )

        # Minted by a real subprocess, read off its stdout — the only place the secret
        # ever exists, and the arc a deployment actually performs.
        minted = subprocess.run(
            [sys.executable, "-m", "carnet.cli", "--mint-token", "priya-cursor", OWNER],
            capture_output=True,
            text=True,
            env={**os.environ},
        )
        token = _token_from(minted)
        check("a token was minted by the CLI", bool(token), True)

        token_id = store.list_api_tokens(TENANT)[0]["id"]
        store.grant_agent(
            TENANT, "triage", "machine", token_id, role="user",
            granted_by=ACTOR, actor=ACTOR,
        )

        # --- the API, and somebody else's client ----------------------------------

        step("the API comes up and the official MCP SDK dials /mcp")

        api = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)],
            env={**os.environ},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _wait_for_api()

        seen_before = len(SEEN)

        initialized, listed, _ = with_session(token, _list_body)
        check("the SDK completed the handshake",
              initialized.server_info.name, "carnet")
        check("and negotiated the version it asked for",
              initialized.protocol_version, "2025-06-18")
        check("tools advertises a capability and nothing this server cannot do",
              initialized.capabilities.resources, None)

        check("tools/list is the grant list", [t[0] for t in listed], ["acme_list_issues"])
        says("the schema came from the customer's own server", listed[0][2], "owner")
        check("the un-vetted tool is nowhere near the door",
              any("delete" in name for name, *_ in listed), False)

        handshake = [m["method"] for m in SEEN[seen_before:]]
        check("binding dialled the upstream server exactly once",
              handshake, ["initialize", "notifications/initialized", "tools/list"])
        check("as the connector's shared account",
              {m["authorization"] for m in SEEN[seen_before:]}, {f"Bearer {SHARED}"})

        # --- a call, through the broker -------------------------------------------

        step("a tool call in scope: brokered, credentialled, audited")

        seen_before = len(SEEN)
        answer = with_session(token, _call_body("acme_list_issues", {"owner": "acme", "repo": "web"}))
        check("the call succeeded", answer.is_error, False)
        body = text_of(answer)
        check("and reached the real server", body["issues"][0]["repo"], "web")
        check("under the organisation's credential, never the caller's",
              body["seen_authorization"], f"Bearer {SHARED}")
        check("the upstream saw exactly one call",
              [m["method"] for m in SEEN[seen_before:]], ["tools/call"])

        records = store.audit_records(TENANT)
        check("one audit record, allowed", (records[-1]["decision"], records[-1]["outcome"]),
              ("allow", "ok"))
        check("attributed to the agent whose grant carried it", records[-1]["agent"], "triage")
        check("naming the machine, never a person or the system",
              records[-1]["principal_kind"], "machine")
        says("with a correlation id that is not a run id", records[-1]["run_id"], "door-")
        check("and NO run was created", store.list_runs(TENANT), [])

        step("a tool call out of scope: refused by the broker, and nothing is sent")

        seen_before = len(SEEN)
        refused = with_session(
            token, _call_body("acme_list_issues", {"owner": "other", "repo": "secrets"})
        )
        check("the SDK sees a tool error, not a protocol error", refused.is_error, True)
        says("carrying the broker's own sentence", text_of(refused).get("error"), "Denied by broker")
        check("and nothing reached the customer's server", len(SEEN), seen_before)
        check("the denial is in the log",
              store.audit_records(TENANT)[-1]["decision"], "deny")

        step("a tool the token was never granted: a protocol error and a denial row")

        ungranted = with_session(token, _raw_call_body("acme_delete_repository", {"owner": "acme"}))
        says("refused by name", ungranted, "acme_delete_repository")
        denials = store.denial_records(TENANT, resource_kind="tool")
        check("written down where refusals go", denials[-1]["resource_id"],
              "acme_delete_repository")

        step("a name that could not be a tool name: refused, and NOT written down")

        # `access_denials.resource_id` is unbounded TEXT in an append-only table, and this
        # refusal happens before the broker — so `MCP_CALLS_PER_DAY` never bounds it. Left
        # open, a token granted nothing could put a megabyte per request into the one
        # table an operator reads during an incident. Driven here as well as in the suite
        # because the payload has to survive a real HTTP body and a real client to prove
        # nothing downstream is doing the truncating for us.
        before_rows = len(store.denial_records(TENANT))
        junk = with_session(token, _raw_call_body("x" * 5000, {"owner": "acme"}))
        says("refused as a name that cannot be one", junk, "must match")
        check("and no row was written", len(store.denial_records(TENANT)), before_rows)
        check("nor did the sentence carry the payload back", len(str(junk)) < 600, True)
        check("and it cost no budget", _spent(store, token_id), 1)

        step("arguments larger than the cap: refused before the audit log sees them")

        # The same amplification through the *audit* log rather than the denial log, and
        # the reason the ceiling does not close it: a denied call spends no budget and
        # still records its arguments. Driven over real HTTP because the point is what
        # survives a real body — a cap the framework happened to enforce for us would be
        # a cap that moves when the framework does.
        before_audit = len(store.audit_records(TENANT))
        oversized = with_session(
            token, _raw_call_body("acme_list_issues", {"owner": "acme", "note": "z" * 90_000})
        )
        says("refused by size", oversized, "the limit is")
        check("nothing was recorded", len(store.audit_records(TENANT)), before_audit)
        check("and nothing was spent", _spent(store, token_id), 1)

        # --- the budget, against the statement that enforces it -------------------

        step("the per-token ceiling, counted in Postgres (CARNET_MCP_CALLS_PER_DAY=3)")

        # **One admitted call so far**, out of three attempts. The other two were
        # refused — one at the broker's scope check, one before it ever reached the
        # broker — and neither spent anything, which is the ordering the ceiling depends
        # on: a caller fixing its own scope mistakes must not exhaust its day doing so.
        check("only the admitted call was charged", _spent(store, token_id), 1)

        in_scope = {"owner": "acme", "repo": "web"}
        with_session(token, _call_body("acme_list_issues", in_scope))
        with_session(token, _call_body("acme_list_issues", in_scope))
        check("three admitted, which is the ceiling", _spent(store, token_id), 3)

        exhausted = with_session(token, _call_body("acme_list_issues", in_scope))
        check("the fourth call is refused", exhausted.is_error, True)
        says("naming the ceiling", text_of(exhausted).get("error"), "ceiling")
        check("and the refusal wrote nothing", _spent(store, token_id), 3)
        check("the refusal is an ordinary broker denial in the log",
              store.audit_records(TENANT)[-1]["decision"], "deny")
        check("still no runs, however many calls", store.list_runs(TENANT), [])

        # --- revocation ------------------------------------------------------------

        step("revoking the token closes the door, with no URL to change")

        store.revoke_api_token(TENANT, token_id, actor=ACTOR)

        # Asserted twice, because the two halves are different facts and the SDK hides
        # one of them. The server's answer is a **401** — checked with a plain HTTP POST,
        # since the SDK wraps a transport failure in an ExceptionGroup whose text says
        # nothing about status. The client's answer is that it cannot open a session at
        # all, which is what a person pointing Cursor at a revoked token actually sees.
        import httpx

        raw = httpx.post(
            DOOR,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=10,
        )
        check("the door answers 401", raw.status_code, 401)
        says("with the one sentence every bad token gets",
             raw.json()["detail"], "not a valid token for this service")
        says("and the SDK cannot open a session at all",
             _expect_failure(token), "unhandled errors in a TaskGroup")

        # --- acting-for (033c): whom a door call is made for -----------------------

        step("acting-for setup: an IdP, a person who signed in, and their connection")

        import dev_idp
        from carnet.access import connections
        from carnet.access import tokens as machine_tokens
        from carnet.core import Principal

        idp = dev_idp.Provider(f"http://127.0.0.1:{IDP_PORT}")
        idp_server = ThreadingHTTPServer(("127.0.0.1", IDP_PORT), dev_idp.handler_for(idp))
        threading.Thread(target=idp_server.serve_forever, daemon=True).start()
        store.save_tenant_idp(
            TENANT,
            {
                "issuer": idp.issuer,
                "jwks_uri": f"{idp.issuer}/v1/keys",
                "audience": dev_idp.AUDIENCE,
                # The real org's mapping, not the spec's — see migration 010.
                "subject_claim": "uid",
                "email_claim": "sub",
                "allowed_domains": ("acme.com",),
            },
        )
        # A verified acting-for names somebody who has signed in at least once — a tool
        # call creates nobody — so Tom's row exists the way a login writes it.
        store.create_user(
            TENANT,
            {
                "id": "u_tom",
                "issuer": idp.issuer,
                "subject": "u_tom",
                "email": "tom@acme.com",
            },
        )
        connections.connect_account(
            Principal.user("u_tom", TENANT), "acme", TOM_GITHUB, actor=ACTOR
        )

        # A fresh token for the chatbot: the revoked one is gone, and each token has
        # its own daily ceiling, which these scenes spend exactly to.
        bot_row, bot = machine_tokens.mint(TENANT, "acme-chatbot", OWNER, actor=ACTOR)
        store.grant_agent(
            TENANT, "triage", "machine", bot_row["id"], role="user",
            granted_by=ACTOR, actor=ACTOR,
        )
        forwarded = idp.token_for("tom@acme.com")

        step("a service tool with acting-for present still uses the shared credential")

        # The back-door test, over the real wire: the vetting decided whose account,
        # and acting-for only ever picks which person within a decision that already
        # said "a person's". The identity is recorded; the resolution is untouched.
        answer = with_session(
            bot, _meta_call_body("acme_list_issues", {"owner": "acme", "repo": "web"},
                                 {"token": forwarded})
        )
        check("the call succeeded", answer.is_error, False)
        check("as the service, never Tom",
              text_of(answer)["seen_authorization"], f"Bearer {SHARED}")
        record = store.audit_records(TENANT)[-1]
        check("with the person and the proof recorded anyway",
              (record["acting_for"], record["identity_source"], record["credential"]),
              ("tom@acme.com", "verified", "shared"))

        step("the tool is re-vetted to act as a person — and now needs one")

        tools.vet_tool(
            TENANT,
            "acme",
            "list_issues",
            effect="read",
            identity="user",
            resources=(Resource("github.repo", ["owner", "repo"], template="{owner}/{repo}"),),
            actor=ACTOR,
            credential=SHARED,
        )

        nobody = with_session(
            bot, _call_body("acme_list_issues", {"owner": "acme", "repo": "web"})
        )
        check("without acting-for it is refused (033a, unchanged)", nobody.is_error, True)
        says("as unavailable, not served from the shared account",
             text_of(nobody).get("error"), "unavailable")
        record = store.audit_records(TENANT)[-1]
        check("audited, with nothing claimed",
              (record["decision"], record["outcome"], record["identity_source"]),
              ("allow", "error", "none"))

        step("a forwarded IdP token: verified like a login, and the call goes out as Tom")

        answer = with_session(
            bot, _meta_call_body("acme_list_issues", {"owner": "acme", "repo": "web"},
                                 {"token": forwarded})
        )
        check("the call succeeded", answer.is_error, False)
        check("as Tom's own account, never the service's",
              text_of(answer)["seen_authorization"], f"Bearer {TOM_GITHUB}")
        record = store.audit_records(TENANT)[-1]
        check("and the log says whom, how sure, and whose credential",
              (record["acting_for"], record["identity_source"], record["credential"]),
              ("tom@acme.com", "verified", "delegated"))

        step("an asserted email before the connector opts in: refused, and written down")

        asserted = with_session(
            bot, _raw_meta_call_body("acme_list_issues", {"owner": "acme", "repo": "web"},
                                      {"email": "tom@acme.com"})
        )
        says("with the switch named", asserted, "allow_asserted_identity")
        denials = store.denial_records(TENANT, resource_kind="tool")
        check("as an acting-for denial on the tool it was about",
              (denials[-1]["resource_id"], denials[-1]["required"]),
              ("acme_list_issues", "acting-for"))

        step("the administrator enables assertion by name, and the log records it")

        flipped = subprocess.run(
            [sys.executable, "-m", "carnet.cli", "--set-asserted-identity", "acme", "on"],
            capture_output=True,
            text=True,
            env={**os.environ},
        )
        check("the CLI succeeded", flipped.returncode, 0)
        says("and said what was just trusted", flipped.stdout, "asserted")
        admin_rows = store.admin_audit_records(
            TENANT, action="connector.asserted_identity"
        )
        check("one administrative record, naming the new state",
              admin_rows[-1]["detail"]["allow_asserted_identity"], True)

        # A second service holds its own token — and its own ceiling, which is why the
        # asserted scene runs under a fresh principal rather than the chatbot's.
        rag_row, rag = machine_tokens.mint(TENANT, "acme-rag", OWNER, actor=ACTOR)
        store.grant_agent(
            TENANT, "triage", "machine", rag_row["id"], role="user",
            granted_by=ACTOR, actor=ACTOR,
        )

        answer = with_session(
            rag, _meta_call_body("acme_list_issues", {"owner": "acme", "repo": "web"},
                                  {"email": "tom@acme.com"})
        )
        check("believed, and acting as Tom",
              text_of(answer)["seen_authorization"], f"Bearer {TOM_GITHUB}")
        record = store.audit_records(TENANT)[-1]
        check("kept apart from verified in the log",
              (record["acting_for"], record["identity_source"]),
              ("tom@acme.com", "asserted"))

        step("a token from nobody's IdP: refused before anything resolves")

        # A well-formed JWT whose issuer nobody registered. Really encoded, so the
        # refusal exercised is the tenant boundary rather than a parse error.
        import jwt as pyjwt

        stranger = pyjwt.encode(
            {"iss": "https://evil.example"}, "s" * 32, algorithm="HS256"
        )
        refused_token = with_session(
            rag, _raw_meta_call_body("acme_list_issues", {"owner": "acme", "repo": "web"},
                                      {"token": stranger})
        )
        says("with the remedy, not the reason", refused_token, "identity provider")

        # --- personal tokens (033d): the owner's access, through the door ----------

        step("a personal token is minted for Priya, and granted NOTHING")

        store.grant_agent(
            TENANT, "triage", "user", OWNER, role="user",
            granted_by=ACTOR, actor=ACTOR,
        )
        minted = subprocess.run(
            [sys.executable, "-m", "carnet.cli",
             "--mint-token", "priya-editor", OWNER, "--as-owner"],
            capture_output=True,
            text=True,
            env={**os.environ},
        )
        personal = _token_from(minted)
        check("minted by the CLI", bool(personal), True)
        says("which says what it made", minted.stdout, "personal")
        check("and does not suggest the grant command the seam refuses",
              "--share-agent" in minted.stdout, False)
        personal_id = next(
            row["id"] for row in store.list_api_tokens(TENANT)
            if row["name"] == "priya-editor"
        )

        _, listed, _ = with_session(personal, _list_body)
        check("tools/list is the OWNER's union", [t[0] for t in listed],
              ["acme_list_issues"])
        check("with no grant row naming the token anywhere",
              store.agent_grant_role(TENANT, "triage", "machine", personal_id), None)

        # --- 035d: the same answer, read without presenting the token ---------------
        #
        # **The one thing about this chunk only this script can answer.** `tests/test_door.py`
        # can put `reach` beside `list_tools`, but both sides of that comparison are
        # computed by one process out of one fake store. Here the left-hand side is a real
        # `tools/list` — the official MCP SDK, over a socket, after real connector binding
        # — and the right-hand side is an HTTP GET by a person's browser session, with
        # Postgres underneath resolving the grants. If the screen and the door were ever
        # going to disagree about what a credential can do, it would be across that gap.
        #
        # The administrator is created here rather than in the 035a scene below (which now
        # reuses this one): a *disabled* person cannot read her own tokens, and Priya is
        # disabled forty lines from here — so the admin half of `require_owner_or_admin`
        # is the only thing that can read this answer once somebody has been offboarded,
        # which is the strongest argument that rule has.

        step("the same reach, read over HTTP without the secret")

        store.create_user(
            TENANT,
            {"id": "u_boss", "issuer": idp.issuer, "subject": "u_boss",
             "email": "boss@acme.com"},
        )
        store.grant_platform_role(TENANT, "user", "u_boss", "admin", actor=ACTOR)
        boss = {"Authorization": f"Bearer {idp.token_for('boss@acme.com')}"}

        seen = httpx.get(
            f"{API}/me/tokens/{personal_id}/reach", headers=boss, timeout=10
        )
        check("the route answers", seen.status_code, 200)
        check("and its union is exactly what the MCP client was just shown",
              seen.json()["tools"], [t[0] for t in listed])
        check("through the owner's agent, carrying that agent's own scope",
              [(a["name"], a["scope"]) for a in seen.json()["agents"]],
              [("triage", {"github.repo": {"read": ["acme/*"]}})])
        check("saying whose grants answered, which for a personal token is a person",
              seen.json()["resolved_as"], f"user:{OWNER}")
        # On the bytes, not on the parsed value: 035c's edge pass found `check(..., True)`
        # passing on `1`, which is exactly the coercion the question is about.
        says("with acts_as_owner as a JSON literal", seen.text, '"acts_as_owner":true')
        check("and nothing granted that cannot be read",
              seen.json()["invalid_agents"], [])

        before = store.find_api_token(personal_id)["last_used_at"]
        httpx.get(f"{API}/me/tokens/{personal_id}/reach", headers=boss, timeout=10)
        check("reading a token's reach is not using it — the stamp does not move",
              store.find_api_token(personal_id)["last_used_at"], before)

        # --- 035e: the ceiling scene above, read back over HTTP --------------------
        #
        # **This is the falsifiable form of the chunk, and `_spent()` is why it is not
        # already covered.** Every budget assertion in the ceiling scene calls the store
        # directly, so it proves the *table* is right and says nothing about whether a
        # browser agrees with it. The failure this chunk can actually produce is not a
        # wrong count — it is a page reporting a different number than the door is
        # enforcing against, and only a read through the route, over the same window, at
        # the same instant, can catch that.
        #
        # The token being read is the bot from the ceiling scene: **at its ceiling and
        # revoked**, which is exactly the credential somebody opens this page about.

        step("what that ceiling looks like from a browser, without the secret (035e)")

        spent = httpx.get(f"{API}/me/tokens/{token_id}/budget", headers=boss, timeout=10)
        check("a revoked token at its ceiling still answers", spent.status_code, 200)
        body = spent.json()

        check("and the route's count is the store's, against the statement that wrote it",
              body["calls"], _spent(store, token_id))
        check("which is the ceiling it stopped at", body["calls"], 3)
        # The dial this script actually set in the environment, read back through the
        # response. A route that captured `MCP_CALLS_PER_DAY` at import instead of per
        # request would answer 1000 here and be wrong on every deployment that moved it.
        check("carrying the ceiling, because a number without its limit is not an answer",
              body["ceiling"], 3)
        check("and saying the dial is on, which is what makes the figure mean anything",
              body["metered"], True)

        # Asserted against `door.budget_window()` — the **one** definition of which day a
        # call is charged to, which `TokenBudget` freezes at construction. Not against a
        # date computed here, which would be the second definition this chunk exists to
        # avoid. `_spent()` above computes the day independently, so the pair pins both
        # halves: the route uses the door's window, and the door's window is really today.
        from carnet import door

        today = door.budget_window().isoformat()
        check("the window is the door's own UTC day, not a second definition of today",
              body["window"], today)
        check("seven dense windows, oldest first, ending at today",
              (len(body["history"]), body["history"][-1]["window_start"]),
              (7, today))
        # A page reads `calls` for its figure and `history` for its table; a reader who
        # saw 3 in one and 2 in the other would have no way to tell which was the answer.
        check("today's row and the figure are the same number",
              body["history"][-1]["calls"], body["calls"])
        check("and the quiet days are present rather than missing",
              [w["calls"] for w in body["history"][:-1]], [0] * 6)

        stamp = store.find_api_token(token_id)["last_used_at"]
        httpx.get(f"{API}/me/tokens/{token_id}/budget", headers=boss, timeout=10)
        check("reading what a token spent is not spending — the stamp does not move",
              store.find_api_token(token_id)["last_used_at"], stamp)
        check("nor does reading it cost budget",
              _spent(store, token_id), 3)

        # A credential that has never reached the door: zeros, not a refusal. It is the
        # state every freshly minted token is in, so a route that 404'd here would refuse
        # the commonest case on the page.
        fresh = httpx.get(
            f"{API}/me/tokens/{personal_id}/budget", headers=boss, timeout=10
        ).json()
        check("a token that has spent nothing answers zeros rather than refusing",
              (fresh["calls"], [w["calls"] for w in fresh["history"]]), (0, [0] * 7))

        missing = httpx.get(f"{API}/me/tokens/m_nosuch/budget", headers=boss, timeout=10)
        check("an id this customer does not have is 400, never a 503 about an outage",
              missing.status_code, 400)

        step("granting an agent to a personal token is refused, naming the owner")

        # An owner for `triage`, so the CLI principal may share at all — the refusal
        # under test is the one AFTER that gate.
        store.grant_agent(
            TENANT, "triage", "system", "cli", role="owner",
            granted_by=ACTOR, actor=ACTOR,
        )
        shared_at = subprocess.run(
            [sys.executable, "-m", "carnet.cli",
             "--share-agent", "triage", f"machine:{personal_id}", "--role", "user"],
            capture_output=True,
            text=True,
            env={**os.environ},
        )
        check("the CLI refused", shared_at.returncode != 0, True)
        says("as a personal token", shared_at.stderr, "personal token")
        says("naming the owner instead", shared_at.stderr, OWNER)

        step("a user-identity tool acts as the OWNER's account — hers, or refused")

        nobody = with_session(
            personal, _call_body("acme_list_issues", {"owner": "acme", "repo": "web"})
        )
        check("no connection of Priya's yet: refused, never the shared account",
              nobody.is_error, True)
        record = store.audit_records(TENANT)[-1]
        says("with the audited remedy naming HER", record["reason"], OWNER)

        connections.connect_account(
            Principal.user(OWNER, TENANT), "acme", "priyas-github-token", actor=ACTOR
        )
        answer = with_session(
            personal, _call_body("acme_list_issues", {"owner": "acme", "repo": "web"})
        )
        check("connected: the upstream sees Priya's own account",
              text_of(answer)["seen_authorization"], "Bearer priyas-github-token")
        record = store.audit_records(TENANT)[-1]
        check("delegated credential, machine principal, and NO acting-for — the owner "
              "is a per-token constant, not a per-call claim",
              (record["credential"], record["principal_kind"],
               record["acting_for"], record["identity_source"]),
              ("delegated", "machine", None, "none"))

        step("Priya loses the grant, and every token she holds loses it with her")

        store.revoke_agent(TENANT, "triage", "user", OWNER, actor=ACTOR)
        _, listed, _ = with_session(personal, _list_body)
        check("the next tools/list is empty", listed, [])
        # 035d: and so is the reach, which is the case both surfaces must agree on —
        # access going away is the one change a stale answer here would hide.
        gone = httpx.get(
            f"{API}/me/tokens/{personal_id}/reach", headers=boss, timeout=10
        ).json()
        check("and so is the reach, from the other side",
              (gone["tools"], gone["agents"]), ([], []))

        step("Priya is disabled, and her editor stops at its next request")

        store.set_user_status(TENANT, OWNER, "disabled", actor="system:cli")
        raw = httpx.post(
            DOOR,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {personal}", "Accept": "application/json"},
            timeout=10,
        )
        check("a specific 403, not the anti-enumeration 401", raw.status_code, 403)
        says("saying why", raw.json()["detail"], "no longer an active account")

        step("an old record still resolves to a name and an owner — the derived 'via'")

        store.revoke_api_token(TENANT, personal_id, actor=ACTOR)
        # 035d, and it is the decision rather than an accident: reach follows the
        # **grant** and ignores the **credential**. *What could this token reach before I
        # killed it* is the offboarding question, asked about a credential somebody has
        # just revoked — and a page answering "refused: this token was revoked" would read
        # as "it reaches nothing" to the one person who needs the opposite. Asserted at the
        # only tier where the token is genuinely dead in a real database.
        after = httpx.get(
            f"{API}/me/tokens/{personal_id}/reach", headers=boss, timeout=10
        )
        check("a revoked token still answers about what it was granted",
              after.status_code, 200)
        check("and about whose access that was, its owner being disabled notwithstanding",
              after.json()["resolved_as"], f"user:{OWNER}")

        old = next(
            r for r in reversed(store.audit_records(TENANT))
            if r["principal_id"] == personal_id
        )
        resolved = store.find_api_token(old["principal_id"])
        check("the token row answers, revoked and owner-disabled notwithstanding",
              (resolved["name"], resolved["acts_as_owner"]),
              ("priya-editor", True))
        check("and the owner still resolves to a person",
              store.get_user(TENANT, resolved["owner_id"])["email"], "priya@acme.com")

        # 035e at the other credential, and the one that matters most for an offboarding
        # review: what a *personal* token spent, read after its owner was disabled and the
        # token revoked. `_spent()` is the enforcing statement; the route is the browser.
        # Under the owner's key since migration 054 — a personal token's day is its
        # owner's, and the page says so.
        her = httpx.get(
            f"{API}/me/tokens/{personal_id}/budget", headers=boss, timeout=10
        )
        check("a disabled owner's revoked token still reports what it spent",
              her.status_code, 200)
        check("and the number is the store's, not a second count",
              her.json()["calls"], _spent(store, OWNER))
        check("and it says whose day that is", her.json()["keyed_by"], "owner")

        # --- 035a: the traffic above, read back by an administrator ----------------
        #
        # Everything before this point proved the door *writes* correctly. This proves
        # somebody can read it — the half four chunks of plan 033 deferred, and the one
        # `pytest` structurally cannot check here: the filter is a `LIKE` over a
        # partitioned table, and the fake answers it with `str.startswith`. A prefix
        # scan that agrees with a Python loop is exactly the shape that agrees until it
        # does not.

        step("an administrator reads the door's whole traffic back over HTTP")

        # `boss` was created in the 035d scene above, which needed an administrator first —
        # a disabled person cannot read her own tokens, so that half of
        # `require_owner_or_admin` is the only thing that can read an offboarded
        # credential's reach at all. One administrator for both scenes rather than two.

        listed = httpx.get(f"{API}/admin/door-calls", headers=boss, timeout=10).json()
        stored = store.door_call_records(TENANT)

        check("the route and the store agree, against the real statement",
              [r["run_id"] for r in listed], [r["run_id"] for r in stored])
        check("every row is a door call and no run is among them",
              {r["run_id"][:5] for r in listed}, {"door-"})
        check("and there is real traffic to read, not an empty pass",
              len(listed) > 0, True)

        # The whole reason 033c kept three values instead of two. If the `LIKE` were
        # wrong these would be missing rather than incorrect, so this is the assertion
        # that fails loudly on a filter that quietly matches nothing.
        check("the acting-for rows are reachable at last",
              sorted({r["identity_source"] for r in listed}),
              ["asserted", "none", "verified"])
        check("naming the person a shared service acted for",
              "tom@acme.com" in {r["acting_for"] for r in listed}, True)

        check("the wire drops the args and the credential",
              [k for k in ("args", "credential") if k in listed[0]], [])
        check("and the stored record still has both, for an incident query",
              all(k in stored[0] for k in ("args", "credential")), True)

        capped = httpx.get(f"{API}/admin/door-calls?limit=2", headers=boss, timeout=10)
        check("the tail is the most recent, still oldest-first",
              [r["run_id"] for r in capped.json()],
              [r["run_id"] for r in stored[-2:]])
        check("an over-large limit is a 422 naming the field, never a silent truncation",
              httpx.get(f"{API}/admin/door-calls?limit=100000", headers=boss,
                        timeout=10).status_code, 422)

        # The machine that made every call above cannot read them back: administering
        # is not something an API token does.
        check("the door's own token is refused at the reader",
              httpx.get(f"{API}/admin/door-calls",
                        headers={"Authorization": f"Bearer {bot}"},
                        timeout=10).status_code, 403)

        # --- the door as an OAuth resource server (083) ----------------------------

        step("an OAuth client holding only the door's URL: discover, register, consent, exchange")

        # Tom holds `triage` as a person, so the personal token the flow mints — which
        # resolves its access through him — sees exactly triage's tools.
        store.grant_agent(
            TENANT, "triage", "user", "u_tom", role="user", granted_by=ACTOR, actor=ACTOR
        )
        tom = {"Authorization": f"Bearer {idp.token_for('tom@acme.com')}"}

        # The very first thing a client sees, before any of the SDK's machinery: a 401
        # that says where to look. Spelled raw so the header is asserted as bytes.
        challenged = httpx.post(DOOR, json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                                timeout=10)
        check("an unauthenticated door answers 401", challenged.status_code, 401)
        says("naming its protected-resource metadata", challenged.headers.get("www-authenticate", ""),
             f'resource_metadata="{API}/.well-known/oauth-protected-resource/mcp"')
        document = httpx.get(f"{API}/.well-known/oauth-protected-resource/mcp", timeout=10).json()
        check("which names this door and this issuer",
              (document.get("resource"), document.get("authorization_servers")),
              (DOOR, [API]))

        seen = {}

        async def browser(url):
            """The SDK hands over the authorize URL; this plays the browser and Tom.

            The real page is the SPA at `/oauth/authorize`; its two calls are made
            here with Tom's JWT, exactly as the page makes them."""
            from urllib.parse import parse_qs

            seen["authorize_url"] = url
            query = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
            seen["query"] = query
            seen["described"] = httpx.get(
                f"{API}/oauth/clients/{query['client_id']}", headers=tom, timeout=10
            )
            decision = httpx.post(
                f"{API}/oauth/consent", headers=tom, timeout=10,
                json={
                    "client_id": query["client_id"],
                    "redirect_uri": query["redirect_uri"],
                    "state": query.get("state"),
                    "response_type": query.get("response_type"),
                    "code_challenge": query.get("code_challenge"),
                    "code_challenge_method": query.get("code_challenge_method"),
                    "resource": query.get("resource"),
                    "approve": True,
                },
            )
            seen["consent"] = decision
            seen["redirect_to"] = decision.json().get("redirect_to", "") if decision.status_code == 200 else ""

        async def callback():
            from urllib.parse import parse_qs

            from mcp.shared.auth import AuthorizationCodeResult

            query = {k: v[0] for k, v in parse_qs(urlsplit(seen["redirect_to"]).query).items()}
            return AuthorizationCodeResult(code=query["code"], state=query.get("state"))

        answer, listed_tools, held = with_oauth_session(browser, callback, _oauth_body)

        says("the SDK built the authorize URL at this origin's consent page",
             seen.get("authorize_url", ""), f"{API}/oauth/authorize?")
        check("with PKCE S256 and a registered client id",
              (seen.get("query", {}).get("code_challenge_method"),
               seen.get("query", {}).get("client_id", "")[:3]),
              ("S256", "oc_"))
        check("the consent page could read the client the SDK registered",
              seen["described"].json().get("client_name") if seen["described"].status_code == 200 else None,
              "e2e assistant")
        check("and Tom's approval was answered with a redirect carrying a code",
              "code=" in seen.get("redirect_to", ""), True)
        check("the token the SDK holds is an art_ token",
              held.startswith("art_m_"), True)
        check("the session lists exactly the tools Tom holds",
              sorted(listed_tools), ["acme_list_issues"])
        check("and a call through it succeeds", answer.is_error, False)
        # 033d holds for a token minted this way: it is *personal*, so the user-identity
        # tool acts as Tom's own connected account — never the shared credential, and
        # never anybody else's.
        check("acting as Tom's own connected account, because the token is personal",
              text_of(answer).get("seen_authorization"), f"Bearer {TOM_GITHUB}")

        # E2: the result names its audit row.
        newest = store.audit_records(TENANT)[-1]
        call_id = (answer.meta or {}).get("com.carnet/call-id")
        says("the result's _meta carries the call id", call_id or "", "door-")
        check("and it is the run_id of the audit row the call wrote", newest["run_id"], call_id)

        # The token is Tom's: on his page, personal, named for the client.
        mine = httpx.get(f"{API}/me/tokens", headers=tom, timeout=10).json()
        check("the token is on Tom's own tokens page, personal, named for the client",
              [(t["name"], t["acts_as_owner"]) for t in mine], [("e2e assistant", True)])
        check("and the audit row names that machine",
              newest["principal_id"], mine[0]["id"] if mine else None)

        idp_server.shutdown()

    finally:
        if api is not None:
            api.terminate()
            api.wait(timeout=10)
        upstream.shutdown()
        store.close()

    failed = [label for ok, label in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        for label in failed:
            print(f"  FAILED: {label}")
        return 1
    return 0


# --- the bodies the SDK session runs ------------------------------------------------


async def _list_body(session, initialized):
    listed = await session.list_tools()
    return (
        initialized,
        [
            # `input_schema` is the SDK's Python spelling of the wire's `inputSchema`.
            (t.name, t.description, sorted((t.input_schema or {}).get("properties") or {}))
            for t in listed.tools
        ],
        listed,
    )


def _call_body(name, arguments):
    async def body(session, _initialized):
        return await session.call_tool(name, arguments)

    return body


def _raw_call_body(name, arguments):
    """A call the server answers with a JSON-RPC *error*, which the SDK raises on.

    Returned as text rather than as a result, because that is what the caller sees: an
    ungranted name is the request being wrong, not the tool failing.
    """

    async def body(session, _initialized):
        try:
            return str(await session.call_tool(name, arguments))
        except Exception as exc:  # noqa: BLE001 - the SDK's error type is what we want to read
            return f"{type(exc).__name__}: {exc}"

    return body


def _meta_call_body(name, arguments, acting_for):
    """A call carrying an acting-for identity, exactly as a real caller sends one: the
    SDK's own `meta=` kwarg, one namespaced key, per call. This riding through the
    official client untouched is the wire shape 033c was ratified against."""

    async def body(session, _initialized):
        return await session.call_tool(
            name, arguments, meta={ACTING_FOR_KEY: acting_for}
        )

    return body


def _raw_meta_call_body(name, arguments, acting_for):
    """`_raw_call_body` with an acting-for: for the claims the door refuses as
    protocol errors — asserted where nobody opted in, a token from nobody's IdP."""

    async def body(session, _initialized):
        try:
            return str(
                await session.call_tool(
                    name, arguments, meta={ACTING_FOR_KEY: acting_for}
                )
            )
        except Exception as exc:  # noqa: BLE001 - the SDK's error type is what we want to read
            return f"{type(exc).__name__}: {exc}"

    return body


def _expect_failure(token):
    try:
        with_session(token, _list_body)
        return "the door answered a revoked token"
    except Exception as exc:  # noqa: BLE001 - any refusal is the point; the text is asserted
        return f"{type(exc).__name__}: {exc}"


def _spent(store, token_id):
    from datetime import datetime, timezone

    return store.mcp_calls_spent(TENANT, token_id, datetime.now(timezone.utc).date())


def _token_from(completed):
    """The `art_...` string out of `--mint-token`'s stdout."""
    for word in (completed.stdout or "").split():
        if word.startswith("art_"):
            return word.strip()
    print(completed.stdout)
    print(completed.stderr)
    return ""


def _wait_for_api():
    import httpx

    for _ in range(60):
        try:
            httpx.get(f"{API}/health", timeout=1)
            return
        except Exception:  # noqa: BLE001 - it is not up yet; that is what we are waiting for
            time.sleep(0.5)
    raise SystemExit("uvicorn did not come up")


if __name__ == "__main__":
    sys.exit(main())
