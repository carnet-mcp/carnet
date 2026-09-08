"""A world to click through by hand: 12c's administration surface, end to end.

    cd backend && .venv/bin/python scripts/admin_world.py

Starts four things on **dedicated ports** and blocks until you stop it:

    127.0.0.1:8904   a dev identity provider     signs you in with no password
    127.0.0.1:8934   a fake MCP server           something real to discover and vet
    127.0.0.1:8005   uvicorn                     with CARNET_BOOTSTRAP_ADMIN set
    localhost:8086   the SPA                     `npm run dev`, pointed at both

Its own ports rather than the usual 8000/8080, and `--strictPort`, because a dev server
left running from another session is a thing that happens — and one configured against a
different identity provider will send you to a real password form while every health check
says the world is up. This refuses to start rather than attach to somebody else's server.

**The database is created fresh and dropped on the way in**, so it does not touch
`carnet_demo`. The tenant holds exactly two rows to begin with: itself, and an
identity provider. No admin, no allowlist, no connector — which is the state a new
customer is in, and the whole point of clicking through it.

**Costs nothing.** No run is submitted, so no model is called, and the MCP server is a
local socket.

## Switching who you are

The dev provider signs in whoever `/_be/<email>` last named:

    curl http://127.0.0.1:8904/_be/priya@example.com
    curl http://127.0.0.1:8904/_be/sam@example.org

Then sign out in the app and sign in again. Anybody on an allowed domain is created on
first login, exactly as they would be through a real provider.
"""

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

ROOT = pathlib.Path(__file__).resolve().parent.parent
FRONTEND = ROOT.parent / "frontend"

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_admin_world"
BASE_DSN = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"

TENANT = "acme"
IDP_PORT = 8904
API_PORT = 8005
MCP_PORT = 8934
APP_PORT = 8086

APP = f"http://localhost:{APP_PORT}"

# Resolves to 127.0.0.1 and is not a literal IP, so the egress check passes on the name —
# a locally-hosted server cannot be reached by its address whatever the allowlist says.
# See `e2e_http_connector.py`.
HOST = "localtest.me"
MCP_URL = f"http://{HOST}:{MCP_PORT}/mcp"

# Whoever this is becomes the first administrator at their first login. Override it:
#   BOOTSTRAP_ADMIN=someone@example.com .venv/bin/python scripts/admin_world.py
BOOTSTRAP = os.environ.get("BOOTSTRAP_ADMIN") or "priya@example.com"
DOMAINS = ("example.com", "example.org")

# A tool worth scoping, and one nobody should vet. `delete_repository` is here so the
# discovery screen has something to show you that you would refuse.
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
        "name": "create_issue",
        "description": "Open a new issue in a repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "title": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["owner", "repo", "title"],
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
    parts = urlsplit(BASE_DSN)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


class MCPServer(BaseHTTPRequestHandler):
    """A conformant-enough Streamable HTTP MCP server, standing in for a customer's own."""

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

        if message["method"] == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "acme-issues-mcp", "version": "2.1.0"},
            }
        elif message["method"] == "tools/list":
            result = {"tools": TOOLS}
        else:
            result = {"content": [{"type": "text", "text": "{}"}]}

        body = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Mcp-Session-Id", "sess-1")
        self.end_headers()
        self.wfile.write(body)


def refuse_if_taken(*ports):
    for port in ports:
        with socket.socket() as probe:
            probe.settimeout(0.5)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                raise SystemExit(
                    f"something is already listening on 127.0.0.1:{port}. This script "
                    "starts its own provider, API, MCP server and dev server; attaching "
                    "to somebody else's would point the browser somewhere else entirely. "
                    "Stop it, or edit the port constants at the top of this file."
                )


def wait_for(url, seconds=120):
    import httpx

    for _ in range(seconds * 2):
        try:
            httpx.get(url, timeout=1)
            return
        except Exception:
            time.sleep(0.5)
    raise SystemExit(f"{url} never answered")


def main():
    import psycopg

    refuse_if_taken(IDP_PORT, API_PORT, MCP_PORT, APP_PORT)

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import dev_idp

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB}")
        conn.execute(f"CREATE DATABASE {DB}")

    dsn = dsn_for(DB)
    os.environ["CARNET_DATABASE_URL"] = dsn
    # Step 058: the dial vets DNS answers, and localtest.me resolves to loopback
    # on purpose — the operator (this script) consents to its own machine.
    os.environ["CARNET_EGRESS_INTERNAL_HOSTS"] = "localtest.me"
    os.environ.setdefault("CARNET_SECRET_KEY", base64.b64encode(os.urandom(32)).decode())
    os.environ["CARNET_WORKERS"] = "0"
    os.environ["CARNET_TENANT"] = TENANT
    # So the redirect URI the consent-flow screen tells you to register is the one this
    # deployment would actually receive a callback on.
    os.environ["CARNET_PUBLIC_ORIGIN"] = f"{APP}/api"

    _, provider = dev_idp.serve(IDP_PORT)

    from carnet import storage
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    migrate.apply(dsn)
    store = storage.configure(PostgresStorage(dsn))

    # **A tenant and a provider, and nothing else.** No seed: a seeded tenant already has
    # a connector and an allowlist entry, which is precisely the state this exists to let
    # you create by hand.
    store.create_tenant(TENANT, "Acme Corp")
    store.save_tenant_idp(
        TENANT,
        {
            "issuer": provider.issuer,
            "jwks_uri": f"{provider.issuer}/v1/keys",
            "audience": dev_idp.AUDIENCE,
            "subject_claim": "uid",
            "email_claim": "sub",
            "allowed_domains": DOMAINS,
        },
    )
    store.close()

    mcp = ThreadingHTTPServer(("127.0.0.1", MCP_PORT), MCPServer)
    threading.Thread(target=mcp.serve_forever, daemon=True).start()

    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)],
        env={**os.environ, "CARNET_BOOTSTRAP_ADMIN": BOOTSTRAP},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    vite = subprocess.Popen(
        ["npm", "run", "dev", "--", "--port", str(APP_PORT), "--strictPort"],
        cwd=str(FRONTEND),
        env={
            **os.environ,
            "VITE_OIDC_ISSUER": provider.issuer,
            "VITE_OIDC_CLIENT_ID": "dev",
            "VITE_OIDC_SCOPES": "openid",
            "VITE_API_ORIGIN": f"http://127.0.0.1:{API_PORT}",
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        wait_for(f"http://127.0.0.1:{API_PORT}/health")
        wait_for(APP)
        banner(provider)
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        api.terminate()
        vite.terminate()
        mcp.shutdown()


def banner(provider):
    print(f"""
================================================================================
  OPEN THIS:   {APP}
================================================================================

  You are         {BOOTSTRAP}
  Tenant          '{TENANT}', with NO administrator, NO approved hosts and NO
                  connectors — the state a new customer starts in.

  Sign in. Silent renewal will fail (it always does outside a real org — third
  party cookies), so press the Sign in button; there is no password.

  1. ADDING THE ADMIN — already done, by logging in.
     `CARNET_BOOTSTRAP_ADMIN={BOOTSTRAP}` was set on the server, the
     platform_roles table was empty, so signing in appointed you. You should see
     an **Administration** item in the top bar that nobody else gets.

     Check it worked: Administration -> Log. The first row is your own
     appointment, with actor `system:bootstrap`.

  2. APPROVING A CONNECTOR — Administration -> Connectors.

     a) Try pasting a URL into the host box first, to see the refusal:
            {MCP_URL}
        It should say what to strip rather than 404.

     b) Approve the host:
            {HOST}
        Try `localhost` too — it is recorded, marked "never dialled", and does
        NOT unlock registration.

     c) Register:
            identifier   acme-issues
            url          {MCP_URL}

     d) Open it -> Discover. A real socket to a real MCP server. You should get
        three tools with their argument names and requiredness.

     e) Approve `list_issues`:
            effect       read
            resource     github.repo  ->  repo
        Then try `create_issue` as a **write with no resource** — it should be
        refused with a sentence, not a 500.

     f) Consent flow (optional): any https URLs on {HOST} will be accepted,
        e.g. https://{HOST}/authorize and https://{HOST}/token. The secret is
        write-only — the saved state says "stored", never a masked echo.

  3. THE OTHER PERSON. Switch identity, then sign out and back in:
         curl {provider.issuer}/_be/sam@example.org

     Sam should see NO Administration item, get a sentence (not a blank page) at
     {APP}/admin/connectors, and — if you configured a consent flow —
     a Connect button on Connections. Your vetted tool should be in his agent
     form at Create MCP -> New MCP, step 2 (Tools).

  Ctrl-C here stops everything. The database is dropped and rebuilt next run.
================================================================================
""", flush=True)


if __name__ == "__main__":
    main()
