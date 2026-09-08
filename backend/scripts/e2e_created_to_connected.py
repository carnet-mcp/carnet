"""Step 044's claim, driven end to end: **created to connected without a terminal.**

`e2e_mcp_door.py` proves the door itself against a real socket and a real Postgres.
What it does not prove — because until 044 it was not true — is that the *person* can
get from nothing to a connected assistant entirely over HTTP: the routes the browser
uses, in the order the browser uses them. This script is that arc, plus the refusals
that bound it.

The person's half, all over HTTP with their session JWT:

    GET  /me                              the door's address arrives with identity
    POST /agents                          the wizard's body — NO system, model or tier
    GET  /agents/{name}/door-activity     zero: nothing has knocked
    POST /me/tokens                       a personal token, secret shown once
    POST /mcp                             initialize / tools/list / tools/call, as their assistant
    GET  /agents/{name}/door-activity     nonzero: the card would flip

The refusals, each asserted on its sentence:

    a machine calling POST /me/tokens     403 — no durable successors
    expires_days: 0                       422 — no spelling of "expires immediately"
    a duplicate live name                 400 — the storage constraint's own words
    a colleague revoking your token       403, and nothing changed
    the revoked token at the door         401 — and DELETE is idempotent, changed: false

What stays store-level is the *administrator's* half that 044 left where it was:
`allow_host`, connector registration and vetting have their own HTTP arc
(`e2e_admin_onboarding.py`) and their own script; re-driving them here would test the
same routes twice.

    cd backend && .venv/bin/python scripts/e2e_created_to_connected.py

Needs Postgres (CARNET_E2E_PG or the dev socket) and outbound DNS for
`localtest.me` — `e2e_mcp_door.py`'s reasons, unchanged. **No model key**: the whole
point is that this deployment is only the door, and the arc completes anyway.
"""

import json
import os
import pathlib
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_created_to_connected_e2e"
TENANT = "e2econnect"

UPSTREAM_HOST = "localtest.me"
UPSTREAM_PORT = 8946
IDP_PORT = 8947
API_PORT = 8148
API = f"http://127.0.0.1:{API_PORT}"

ACTOR = "system:cli"
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
    }
]

SEEN = []
SEEN_LOCK = threading.Lock()


def dsn_for(database):
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


DSN = dsn_for(DB)


class Upstream(BaseHTTPRequestHandler):
    """The customer's own MCP server — `e2e_mcp_door.py`'s, trimmed to one tool."""

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


# --- HTTP, the way a browser or an assistant makes it -------------------------------


def http(method, path, token, body=None):
    """One request; returns (status, parsed-or-text body)."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"{API}{path}",
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            **({"Content-Type": "application/json"} if data else {}),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as refused:
        raw = refused.read()
        try:
            return refused.code, json.loads(raw)
        except (ValueError, TypeError):
            return refused.code, raw.decode(errors="replace")


def rpc(token, message):
    """One JSON-RPC message at the door, plain urllib — no SDK, no shared client code."""
    return http("POST", "/mcp", token, message)


def _generate_key():
    import base64

    return base64.b64encode(os.urandom(32)).decode()


def _wait_for_api():
    for _ in range(60):
        try:
            urllib.request.urlopen(f"{API}/health", timeout=1)
            return
        except Exception:  # noqa: BLE001 - not up yet; that is what we are waiting for
            time.sleep(0.5)
    raise SystemExit("uvicorn did not come up")


def main():
    import psycopg

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
    os.environ["ACME_TOKEN"] = SHARED
    # What `/me` will hand the connect card as the door's address.
    os.environ["CARNET_PUBLIC_ORIGIN"] = API

    from carnet import storage, tools
    from carnet.core import crypto
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage
    from carnet.tools.base import Resource

    import dev_idp

    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    crypto.configure(crypto.from_environment())
    store.create_tenant(TENANT, "044 end to end")

    # The tenant's IdP — a real one the API fetches JWKS from over a socket, so the
    # session tokens below verify through exactly the production path.
    idp = dev_idp.Provider(f"http://127.0.0.1:{IDP_PORT}")
    idp_server = ThreadingHTTPServer(("127.0.0.1", IDP_PORT), dev_idp.handler_for(idp))
    threading.Thread(target=idp_server.serve_forever, daemon=True).start()
    store.save_tenant_idp(
        TENANT,
        {
            "issuer": idp.issuer,
            "jwks_uri": f"{idp.issuer}/v1/keys",
            "audience": dev_idp.AUDIENCE,
            "subject_claim": "uid",
            "email_claim": "sub",
            "allowed_domains": ("acme.com",),
        },
    )

    upstream = ThreadingHTTPServer(("127.0.0.1", UPSTREAM_PORT), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()

    api = None
    try:
        # --- the administrator's half, already covered elsewhere, seeded here ------

        step("the tenant has one vetted tool (the admin arc has its own script)")

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

        api = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)],
            env={**os.environ},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _wait_for_api()

        priya = idp.token_for("priya@acme.com")

        # --- the person's arc, entirely over HTTP ----------------------------------

        step("GET /me: the door's address arrives with identity")

        status, me = http("GET", "/me", priya)
        check("who they are", (status, me["kind"]), (200, "user"))
        check("and /me names the door", me["mcp_url"], f"{API}/mcp")

        step("POST /agents: the wizard's body — no system, no model, no tier")

        status, made = http(
            "POST",
            "/agents",
            priya,
            {
                "name": "triage",
                "permissions": {
                    "tools": ["acme_list_issues"],
                    "scope": {"github.repo": {"read": ["acme/*"]}},
                },
            },
        )
        check("created, owned by whoever asked", status, 201)

        status, detail = http("GET", "/agents/triage", priya)
        check("and it is valid without a briefing or a model",
              (status, detail["valid"]), (200, True))
        check("nothing invented a system prompt", detail["config"].get("system"), None)
        check("nothing invented a model", detail["config"].get("model"), None)
        # Step 081. `AgentDraft.runtime` defaulted to `DEFAULT_RUNTIME` until now, so this
        # body — which is exactly what the wizard sends — stored a tier from a concept the
        # tree deleted, while the seeded example stored none. The two disagreed about the
        # shape of a config, over HTTP, on the most ordinary create there is.
        check("nothing invented a runtime tier", detail["config"].get("runtime"), None)
        check("and the list row does not invent one either", detail["runtime"], None)

        step("door-activity starts at zero — the connect card's waiting state")

        status, activity = http("GET", "/agents/triage/door-activity", priya)
        check("no calls yet", (status, activity), (200, {"calls": 0, "last_call_at": None, "last_refusal": None}))

        step("POST /me/tokens: a personal token, secret shown once")

        status, minted = http("POST", "/me/tokens", priya, {"name": "my-assistant"})
        check("minted", status, 201)
        check("personal by default — the connect-your-assistant shape",
              minted["acts_as_owner"], True)
        check("the secret is a presentable token", minted["token"].startswith("art_m_"), True)
        check("owned by the caller, not by a field",
              minted["owner_id"], me["principal"].split(":", 1)[1])
        assistant = minted["token"]

        status, listed = http("GET", "/me/tokens", priya)
        check("and it is on their own listing, hash-free",
              (status, [t["name"] for t in listed], "secret_hash" in json.dumps(listed)),
              (200, ["my-assistant"], False))

        step("their assistant dials /mcp with that token — no terminal was involved")

        status, answer = rpc(assistant, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "somebody's assistant", "version": "1.0"}},
        })
        check("the handshake completed",
              (status, answer["result"]["serverInfo"]["name"]), (200, "carnet"))

        status, answer = rpc(assistant, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = [t["name"] for t in answer["result"]["tools"]]
        check("tools/list is the grant list — the personal token reaches the owner's agent",
              names, ["acme_list_issues"])

        seen_before = len(SEEN)
        status, answer = rpc(assistant, {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "acme_list_issues",
                       "arguments": {"owner": "acme", "repo": "web"}},
        })
        body = json.loads(answer["result"]["content"][0]["text"])
        check("the call reached the customer's real server", body["issues"][0]["repo"], "web")
        check("under the organisation's credential, never the caller's",
              body["seen_authorization"], f"Bearer {SHARED}")
        check("the upstream saw exactly the brokered call",
              [m["method"] for m in SEEN[seen_before:]], ["tools/call"])

        step("door-activity flips — what the connect card's poll would see")

        status, activity = http("GET", "/agents/triage/door-activity", priya)
        check("one knock, timestamped",
              (status, activity["calls"], activity["last_call_at"] is not None),
              (200, 1, True))

        # An out-of-scope call is refused by the broker AND still counts as a knock —
        # a refused call arrived, and arrival is the question.
        status, answer = rpc(assistant, {
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "acme_list_issues",
                       "arguments": {"owner": "torvalds", "repo": "linux"}},
        })
        check("an out-of-scope call is a result, not a crash",
              answer["result"]["isError"], True)
        status, activity = http("GET", "/agents/triage/door-activity", priya)
        check("and the denial counted as an arrival", activity["calls"], 2)

        step("the refusals, each on its sentence")

        status, refused = http("POST", "/me/tokens", assistant, {"name": "successor"})
        check("a machine may not mint a machine", status, 403)
        says("and the sentence names the rule", refused["detail"], "durable successor")

        status, refused = http("POST", "/me/tokens", priya,
                               {"name": "soon", "expires_days": 0})
        check("expires_days 0 is refused by the schema", status, 422)

        status, refused = http("POST", "/me/tokens", priya, {"name": "my-assistant"})
        check("a duplicate live name is refused", status, 400)
        says("with the storage constraint's own words", refused["detail"],
             "live API token")

        # **This asserted a 403 until step 069 collapsed it, and the collapse is the
        # point.** Within a tenant, a 403 that says *only its owner may* alongside a 400
        # that says *no such token* is an existence oracle: a colleague learns which ids
        # are real, and the sentence named the owner as well. 028 had already decided this
        # shape for a different id — *any difference between "not yours" and "not there"
        # turns the id into a way to enumerate colleagues' uploads* — so 069 applied the
        # decided rule at `require_owner_or_admin`, where five surfaces inherit it.
        #
        # The check asserts the property rather than the status, because a status alone
        # cannot say whether the two answers are the same answer — and being the same is
        # the whole control. **069 shipped without running this script**, so the stale
        # 403 stood green in a file nobody executed; found in step 070's review.
        tom = idp.token_for("tom@acme.com")
        status, refused = http("DELETE", f"/me/tokens/{minted['id']}", tom)
        absent_status, absent = http("DELETE", "/me/tokens/m_000000000000000f", tom)
        check("a colleague may not revoke it", status, 400)
        # The id each sentence echoes is the one the **caller supplied**, so it is
        # substituted out before comparing: what must be identical is everything the
        # server chose to say, and an id somebody typed is not that.
        check(
            "and is told exactly what a token that never existed is told",
            (status, refused["detail"].replace(minted["id"], "<id>")),
            (absent_status, absent["detail"].replace("m_000000000000000f", "<id>")),
        )
        says("...which names no owner", refused["detail"], "no API token")
        check("the owner is not named", "priya" in refused["detail"].lower(), False)
        status, answer = rpc(assistant, {"jsonrpc": "2.0", "id": 5, "method": "tools/list"})
        check("and it still works", status, 200)

        step("DELETE /me/tokens: revocation ends it, idempotently")

        status, revoked = http("DELETE", f"/me/tokens/{minted['id']}", priya)
        check("revoked by its owner", (status, revoked["changed"]), (200, True))
        status, again = http("DELETE", f"/me/tokens/{minted['id']}", priya)
        check("a second revoke is a no-op that says so",
              (status, again["changed"]), (200, False))

        status, _ = rpc(assistant, {"jsonrpc": "2.0", "id": 6, "method": "tools/list"})
        check("the credential is dead at the door", status, 401)

        step("the name is freed — mint, revoke, mint again is a whole lifecycle")

        status, second = http("POST", "/me/tokens", priya,
                              {"name": "my-assistant", "expires_days": 30})
        check("the freed name minted again, with an expiry this time",
              (status, second["expires_at"] is not None), (201, True))

        # And no run-submission surface exists to have been touched: the deployment
        # has no /runs at all, which this arc rests on.
        status, _ = http("GET", "/runs", priya)
        check("there is no run surface", status, 404)

    finally:
        if api is not None:
            api.terminate()
            api.wait(timeout=10)
        upstream.shutdown()
        idp_server.shutdown()

    failed = [label for ok, label in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        for label in failed:
            print(f"  FAILED: {label}")
        return 1
    print("\ncreated to connected, and no terminal was involved.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
