"""Run the product against **your own database**, with the bootstrap admin armed.

    cd backend && source .env && .venv/bin/python scripts/demo_world.py

The sibling of `admin_world.py`, and the difference is the whole point:

    admin_world.py   creates and drops its own database, and a dev identity provider.
                     An empty tenant, for walking through onboarding from nothing.
    this             uses `CARNET_DATABASE_URL` as it stands, and whatever
                     identity provider that tenant already has — your real Okta org,
                     your real connectors, your real connected accounts.

**It creates no database and drops none.** The only thing it changes about your data is
what you do in the browser, plus one thing it may do at your first login: if
`platform_roles` is empty for the tenant, signing in as `BOOTSTRAP_ADMIN` appoints you.
That is additive, recorded in the administrative log, and revocable with
`carnet --revoke-role admin <you>`.

It starts two things:

    127.0.0.1:8934   a fake MCP server     something real to discover and vet
    127.0.0.1:8000   uvicorn               against your DSN, with the bootstrap var set

The **frontend is not started here**, deliberately: the redirect URI registered at a real
Okta org names a specific origin, so the dev server has to stay on the port that org
expects. Run it the way you always have, with the provider named — the app learns it at
runtime and there is no hardcoded default, so a dev server started without these two
renders the sign-in screen's *"no identity provider is configured"* and nothing else:

    cd frontend && VITE_OIDC_ISSUER=https://your-org.okta.com/oauth2/default \
        VITE_OIDC_CLIENT_ID=your-spa-client-id npm run dev

`VITE_OIDC_ISSUER` is the **issuer URL**, not an endpoint base: the app fetches
`{issuer}/.well-known/openid-configuration` to find the endpoints (plan 031), which is
why the same variable now works against any OIDC provider rather than Okta's URL shape
alone.

## Why there is a fake MCP server in a script about real data

Your `jira` connector points at `https://mcp.acme-internal.com/mcp`, which does not
resolve — it came from an end-to-end script — and `github-mcp` speaks stdio, so it can
never hold a consent flow. Neither is something you can press Discover on and get an
answer from. This gives you one that answers, on `localtest.me`, so the vetting screen has
real output to render. Register it as a *new* connector; nothing about the two you have
changes.
"""

import json
import os
import pathlib
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API_PORT = 8000
MCP_PORT = 8934

# Resolves to 127.0.0.1 and is not a literal IP, so the egress check passes on the name.
HOST = "localtest.me"
MCP_URL = f"http://{HOST}:{MCP_PORT}/mcp"

BOOTSTRAP = os.environ.get("BOOTSTRAP_ADMIN") or "priya@example.com"

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


class MCPServer(BaseHTTPRequestHandler):
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


def main():
    dsn = os.environ.get("CARNET_DATABASE_URL")
    if not dsn:
        raise SystemExit(
            "CARNET_DATABASE_URL is not set. `source backend/.env` first — this "
            "script deliberately does not invent a database."
        )
    if not os.environ.get("CARNET_SECRET_KEY"):
        raise SystemExit(
            "CARNET_SECRET_KEY is not set, and a wrong one cannot read the "
            "credentials already in that database. `source backend/.env` first."
        )

    for port in (API_PORT, MCP_PORT):
        with socket.socket() as probe:
            probe.settimeout(0.5)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                raise SystemExit(
                    f"something is already listening on 127.0.0.1:{port} — probably an "
                    "older uvicorn. Stop it first; a stale one serves stale code, which "
                    "is how you end up looking at a screen that has not been rebuilt."
                )

    mcp = ThreadingHTTPServer(("127.0.0.1", MCP_PORT), MCPServer)
    threading.Thread(target=mcp.serve_forever, daemon=True).start()

    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port", str(API_PORT)],
        # Step 058: the dial vets DNS answers, and localtest.me resolves to loopback
        # on purpose — the operator (whoever runs this script) consents to their own
        # machine.
        env={**os.environ, "CARNET_BOOTSTRAP_ADMIN": BOOTSTRAP,
             "CARNET_EGRESS_INTERNAL_HOSTS": "localtest.me"},
        cwd=str(pathlib.Path(__file__).resolve().parent.parent),
    )

    database = dsn.rsplit("/", 1)[-1].split("?")[0]
    print(f"""
================================================================================
  API on http://127.0.0.1:{API_PORT}, against '{database}' — your real data.
  A fake MCP server on {MCP_URL}

  Start the frontend yourself, on the port your Okta org expects, and NAME THE
  PROVIDER — there is no hardcoded default, so without these two the app can only
  say "no identity provider is configured":
      cd frontend && VITE_OIDC_ISSUER=https://your-org.okta.com/oauth2/default \\
          VITE_OIDC_CLIENT_ID=your-spa-client-id npm run dev

  Then open http://localhost:8080 and sign in with your real Okta account.

  CARNET_BOOTSTRAP_ADMIN={BOOTSTRAP}
  That tenant has no platform roles, so signing in appoints you — additive,
  recorded in the log, and undone with:
      carnet --revoke-role admin {BOOTSTRAP}

  Your github-mcp and jira connectors are untouched. To exercise the vetting
  screen on something that actually answers, register a THIRD connector:
      host         {HOST}
      identifier   acme-issues
      url          {MCP_URL}

  Ctrl-C stops the API and the MCP server. Nothing is dropped.
================================================================================
""", flush=True)

    try:
        api.wait()
    except KeyboardInterrupt:
        pass
    finally:
        api.terminate()
        mcp.shutdown()


if __name__ == "__main__":
    main()
