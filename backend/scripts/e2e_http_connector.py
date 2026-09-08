"""A customer-registered HTTP connector, over a real socket, end to end.

**This closes the gap step 012 shipped with.** Every other test of the HTTP path in this
project uses a fake transport or an injected one, which means the transport step 012
makes *mandatory* for customer connectors was the one with no live evidence behind it.
Here a real Streamable HTTP MCP server runs on a real socket, and everything from
`--allow-host` to a brokered tool call goes through the production code path:

    registration -> egress check -> HttpTransport -> HTTP -> a server -> bind -> broker

Two things it proves that nothing else in this repository does.

**The credential travels per request, in a header, and two people get two different
ones.** That is the entire surviving reason decision 2 refuses stdio for a customer's
connector — a stdio server takes its credential once at launch and holds it, so it cannot
act as two people. This asserts the opposite property directly by reading the
`Authorization` header the server actually received, per call, per person.

**The scope is enforced against a live server.** The same tool, the same session, the same
credential — one repository allowed and one refused — with nothing reaching the server on
the refused call.

## Why the host is `localtest.me`

The egress check refuses loopback, link-local and private addresses whatever a tenant
approves, so **no locally-hosted server can be reached by its address**. `localtest.me` is
a public DNS name that resolves to `127.0.0.1`; it is not a literal IP, so `_as_ip`
returns None and the *name* check passes.

Until step 058 that was the whole story — the documented DNS-rebinding gap, reachable on
purpose, with this docstring promising that closing it "by resolving at connect time and
pinning the socket" must break this script, the correct alarm. The alarm fired: 058 did
exactly that (`egress.pinned`, in the two functions that touch the network), the old
`test_a_name_that_would_resolve_to_a_private_address_is_not_caught` inverted into the
closure's own test, and this script now consents the sanctioned way — the operator (here,
this script) names its own machine's host in `CARNET_EGRESS_INTERNAL_HOSTS`.

    cd backend && .venv/bin/python scripts/e2e_http_connector.py

Needs Postgres started first, and outbound DNS for `localtest.me`. Costs nothing: no model
is called and the MCP server is local.
"""

import json
import os
import pathlib
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_e2e_http"


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
TENANT = "e2ehttp"

# Resolves to 127.0.0.1 and is not a literal IP. See the module docstring.
HOST = "localtest.me"
PORT = 8931

PRIYA = "user:u_priya"
SAM = "user:u_sam"

# What the server advertises. Deliberately includes a tool nobody vets.
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

# Every Authorization header the server saw, in order, with the method it arrived on.
# This is the evidence for the per-request-credential property.
SEEN = []
SEEN_LOCK = threading.Lock()


class MCPServer(BaseHTTPRequestHandler):
    """A conformant-enough Streamable HTTP MCP server.

    Answers `initialize`, `tools/list` and `tools/call` with `application/json`, and
    notifications with 202 and no body — which is what `HttpTransport` requires and what
    a fake transport can never actually be wrong about.
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass  # the transcript is the assertions, not the access log

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        message = json.loads(self.rfile.read(length) or "{}")

        with SEEN_LOCK:
            SEEN.append(
                {
                    "method": message.get("method"),
                    "authorization": self.headers.get("Authorization"),
                    "accept": self.headers.get("Accept"),
                    "protocol_version": self.headers.get("MCP-Protocol-Version"),
                    "arguments": (message.get("params") or {}).get("arguments"),
                }
            )

        # A notification. The spec says 202 and no body, and the transport refuses
        # anything else — which is a real thing to get wrong and a real thing to assert.
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
                                "issues": [
                                    {"number": 1, "title": f"an issue in {arguments.get('repo')}"}
                                ],
                                # Echoed so a call can be attributed to a credential.
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
        self.send_header("Mcp-Session-Id", "sess-1")
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


def main():
    import psycopg

    if socket.gethostbyname(HOST) != "127.0.0.1":
        raise SystemExit(f"{HOST} did not resolve to 127.0.0.1; this script needs DNS")

    with psycopg.connect(
        dsn_for("postgres"), autocommit=True
    ) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    # Step 058: the dial vets DNS answers, and localtest.me resolves to loopback
    # on purpose — the operator (this script) consents to its own machine.
    os.environ["CARNET_EGRESS_INTERNAL_HOSTS"] = "localtest.me"
    os.environ.setdefault("CARNET_SECRET_KEY", _generate_key())

    from carnet import agents, storage, tools
    from carnet.access import connections
    from carnet.core import broker, crypto
    from carnet.core.context import RunContext
    from carnet.core.credentials import DELEGATED, for_connector
    from carnet.core.principal import Principal
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage
    from carnet.tools import mcp
    from carnet.tools.base import Resource

    migrate.apply(DSN)
    store = storage.configure(PostgresStorage(DSN))
    crypto.configure(crypto.from_environment())
    store.create_tenant(TENANT, "012 HTTP end to end")

    server = ThreadingHTTPServer(("127.0.0.1", PORT), MCPServer)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://{HOST}:{PORT}/mcp"

    try:
        # --- the egress check, against a real socket -----------------------------

        step("a real server is listening and will NOT be dialled until its host is approved")

        try:
            tools.register_connector(TENANT, "acme", url=url, actor=PRIYA)
            check("unapproved host refused", "registered", "refused")
        except mcp.EgressRefused as exc:
            says("unapproved host refused", exc, "has not approved the host")
        check("nothing reached the server", len(SEEN), 0)

        step("loopback is refused by address even when approved, which is why this uses a name")

        store.allow_host(TENANT, "127.0.0.1", actor=PRIYA)
        try:
            tools.register_connector(
                TENANT, "byaddress", url=f"http://127.0.0.1:{PORT}/mcp", actor=PRIYA
            )
            check("approved loopback still refused", "registered", "refused")
        except mcp.EgressRefused as exc:
            says("approved loopback still refused", exc, "loopback")
        check("still nothing reached the server", len(SEEN), 0)

        step("--allow-host, and the connector registers")

        store.allow_host(TENANT, HOST, actor=PRIYA, note="Acme's internal MCP")
        tools.register_connector(
            TENANT,
            "acme",
            url=url,
            credential_env="ACME_TOKEN",
            description="Acme's internal issue tracker",
            actor=PRIYA,
        )
        connector = mcp.get_connector(TENANT, "acme")
        check("registered over HTTP", connector.transport_kind, "http")
        check("and still vets nothing", list(connector.vetted), [])
        check("registration contacted no server", len(SEEN), 0)

        # --- per-user credentials, which is decision 2's surviving reason ----------

        step("two people connect their own accounts")

        priya = Principal.user("u_priya", TENANT)
        sam = Principal.user("u_sam", TENANT)
        # `actor` is required as of 7b — the operator who ran the command, which for a
        # pasted credential is a different principal from the one it is for. That
        # distinction is the whole of `connection.create`'s record.
        connections.connect_account(
            priya, "acme", "priya-token",
            account_label="priya@acme.com", actor="system:cli",
        )
        connections.connect_account(
            sam, "acme", "sam-token",
            account_label="sam@acme.com", actor="system:cli",
        )
        check("two connections stored", len(store.list_connections(TENANT)), 2)

        step("--discover, over a real socket, with priya's credential")

        seen_before = len(SEEN)
        discovered = mcp.discovery.discover(TENANT, connector, "priya-token")
        check("server identified itself over HTTP",
              mcp.discovery.server_label(discovered["server"]), "acme-mcp-server v4.1.0")
        check("two tools advertised", sorted(t["name"] for t in discovered["tools"]),
              ["delete_repository", "list_issues"])

        handshake = SEEN[seen_before:]
        check("initialize, initialized, tools/list — three messages",
              [m["method"] for m in handshake],
              ["initialize", "notifications/initialized", "tools/list"])
        check("every one carried priya's credential",
              {m["authorization"] for m in handshake}, {"Bearer priya-token"})
        says("Accept lists both content types the spec requires",
             handshake[0]["accept"], "text/event-stream")
        check("and the negotiated protocol version is stamped after initialize",
              handshake[-1]["protocol_version"], "2025-06-18")

        # --- vetting -----------------------------------------------------------------

        step("--vet, against the live advertisement")

        recorded = tools.vet_tool(
            TENANT,
            "acme",
            "list_issues",
            effect="read",
            # 033a: the two-people-two-credentials story below IS the `user` identity.
            # Unstated, the default is `service` and every brokered call would use the
            # shared credential — which is exactly what this scene proves must not
            # happen once the vetting says whose account.
            identity="user",
            resources=(Resource("github.repo", ["owner", "repo"], template="{owner}/{repo}"),),
            note="Read-only. Scope to the repos a team owns.",
            actor=PRIYA,
            credential="priya-token",
        )
        check("vetted", recorded["local_name"], "acme_list_issues")
        check("against the version the server just reported", recorded["server"],
              "acme-mcp-server v4.1.0")

        review = store.load_vetting_record(TENANT)[0]
        check("vetted_by names a person", review["vetted_by"], PRIYA)
        check("server_version recorded", review["server_version"], "4.1.0")
        check("and the observed arguments are the baseline",
              review["vetted_arguments"], ["owner", "repo", "state"])

        step("a write with no resource is refused even though the server advertises it")

        try:
            tools.vet_tool(
                TENANT, "acme", "delete_repository", effect="write",
                actor=PRIYA, credential="priya-token",
            )
            check("unscopeable write refused", "vetted", "refused")
        except RuntimeError as exc:
            says("unscopeable write refused", exc, "unscopeable")

        check(
            "delete_repository is advertised and invisible to every agent",
            "acme_delete_repository" in tools.known_names(TENANT),
            False,
        )

        # --- the agent -------------------------------------------------------------

        step("an agent granting it, validated and saved")

        config = {
            "name": "issue-reader",
            "system": "You read issues.",
            "runtime": "simple",
            "permissions": {
                "tools": ["acme_list_issues"],
                "scope": {"github.repo": {"read": ["acme/platform"]}},
            },
        }
        agents.validate(TENANT, config)
        store.create_agent(TENANT, config, "user", "u_priya")
        check("agent created", store.get_agent(TENANT, "issue-reader")["config"]["name"],
              "issue-reader")

        # --- a real brokered call over real HTTP --------------------------------------

        step("a brokered call, as priya, over the real socket")

        # The same resolver `core/runtimes` builds, rather than a simplification —
        # the point of this script is that the production path works, and a bespoke
        # credential lookup here would be testing a lookup nothing uses.
        def credential_for(principal):
            def resolve(connector_id, env_var=None, ref=None):
                credential = for_connector(connector_id, principal, env_var, ref=ref)
                if credential is None:
                    return None, False
                return credential.value, credential.source == DELEGATED

            return resolve

        tools.ensure_available(TENANT, config, credential_for=credential_for(priya))
        ctx = RunContext(run_id="r-priya", principal=priya, budget=_budget())
        seen_before = len(SEEN)
        result = broker.call(ctx, config, "acme_list_issues",
                             {"owner": "acme", "repo": "platform"})

        check("the call succeeded", "error" not in result, True)
        calls = [m for m in SEEN[seen_before:] if m["method"] == "tools/call"]
        check("one tool call reached the server", len(calls), 1)
        check("carrying PRIYA's own credential", calls[0]["authorization"], "Bearer priya-token")
        check("with the arguments the model supplied",
              calls[0]["arguments"], {"owner": "acme", "repo": "platform"})
        says("and the server's answer came back", json.dumps(result), "an issue in platform")

        step("the same tool, as sam, gets SAM's credential — not priya's")

        tools.ensure_available(TENANT, config, credential_for=credential_for(sam))
        ctx_sam = RunContext(run_id="r-sam", principal=sam, budget=_budget())
        seen_before = len(SEEN)
        broker.call(ctx_sam, config, "acme_list_issues", {"owner": "acme", "repo": "platform"})

        calls = [m for m in SEEN[seen_before:] if m["method"] == "tools/call"]
        check("one call", len(calls), 1)
        check("carrying SAM's credential", calls[0]["authorization"], "Bearer sam-token")
        check(
            "two people, two credentials, one connector — which stdio cannot do",
            len({m["authorization"] for m in SEEN if m["method"] == "tools/call"}),
            2,
        )

        step("the scope is enforced against the live server")

        seen_before = len(SEEN)
        refused = broker.call(ctx, config, "acme_list_issues",
                              {"owner": "acme", "repo": "secrets"})
        says("out-of-scope repo refused", json.dumps(refused), "outside this agent's")
        check("and NOTHING reached the server", len(SEEN) - seen_before, 0)

        step("the audit trail")

        records = store.audit_records(TENANT)
        check("three brokered calls recorded", len(records), 3)
        check("two allowed, one denied",
              sorted(r["decision"] for r in records), ["allow", "allow", "deny"])
        check("every call says the credential was delegated",
              {r["credential"] for r in records if r["decision"] == "allow"}, {"delegated"})

        step("re-discovery against a server that has moved")

        TOOLS[0]["inputSchema"]["properties"].pop("state")
        TOOLS[0]["inputSchema"]["properties"]["repository"] = {"type": "string"}
        TOOLS[0]["inputSchema"]["properties"].pop("repo")

        vetting = {
            (r["connector_id"], r["remote_name"]): r for r in store.load_vetting_record(TENANT)
        }
        moved = mcp.discovery.discover(TENANT, mcp.get_connector(TENANT, "acme"), "priya-token")
        refusals = mcp.discovery.refusals(
            mcp.discovery.review(mcp.get_connector(TENANT, "acme"), moved["tools"], vetting)
        )
        check("one refusal", len(refusals), 1)
        if refusals:
            says("names the argument that moved", refusals[0]["message"], "'repo'")
            says("names what it was vetted against", refusals[0]["message"],
                 "acme-mcp-server v4.1.0")

        step("revoking the host stops it and keeps the vetting")

        store.revoke_host(TENANT, HOST, actor=PRIYA)
        mcp.POOL.reset()
        try:
            mcp.discovery.discover(TENANT, mcp.get_connector(TENANT, "acme"), "priya-token")
            check("dialling a revoked host refused", "dialled", "refused")
        except mcp.EgressRefused as exc:
            says("dialling a revoked host refused", exc, "has not approved the host")
        check("the vetting survived",
              [v.remote_name for v in mcp.get_connector(TENANT, "acme").vetted], ["list_issues"])

        store.close()
    finally:
        server.shutdown()

    failed = [label for ok, label in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        print("\nFAILED:")
        for label in failed:
            print(f"  - {label}")
        raise SystemExit(1)


class _Unmetered:
    """A `core.limits.Spending` that never refuses. Step 084.

    The broker consumes a budget at step 2 of every call, so anything driving
    `broker.call` directly has to hand it one. This script used a permissive
    `core.limits.Budget` until 084 deleted it — a real enforcer, borrowed for its side
    effect by a script that is about a connector and not about a ceiling. Six lines that
    say so beat an import for its side effect, and `door.TokenBudget` would drag in
    storage and a spend ceiling this script has no opinion about.
    """

    def reserve(self, tool):
        from carnet.core.permissions import ALLOW

        return ALLOW

    def add_bytes(self, count):
        """Nothing. `door.TokenBudget.add_bytes` does the same and says why."""


def _budget():
    return _Unmetered()


def _generate_key():
    import base64
    import os as _os

    return base64.b64encode(_os.urandom(32)).decode()


if __name__ == "__main__":
    sys.exit(main())
