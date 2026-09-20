"""The `carnet-mcp` client, LangChain adapter, against a real door. Plan 111, step (b2).

**Not a test, and here for what `client/tests/` structurally cannot do.** That suite
proves the adapter against a stub door over `httpx.MockTransport`. What it cannot prove
is the wire: that a real door on a real socket, loaded from a `carnet.yaml`, answers the
adapter's handshake, list and call; that the upstream server saw the *broker's*
credential and not anything the agent held; that a denial arrives inside LangChain as a
`ToolMessage` with an error status and the door's own sentence; and — the one that
proves decision 8 — that a grant revoked *while the agent is up* leaves the tool in the
cached list and the next call refused by name, with the refusal on the model's side of
the conversation rather than as a crash.

    cd backend && uv pip install -e "../client[langchain]"
    .venv/bin/python scripts/e2e_client_langchain.py

Needs nothing running and no database: the door is this process's own uvicorn, on a
thread, over the in-memory store a `carnet.yaml` fills at startup — which is the reason
the revocation half is possible at all, because `storage.active()` is then in reach of
this script the way it is in reach of `tests/test_door.py`. Outbound DNS for
`localtest.me`, because the door refuses a loopback *name* whatever the allowlist says
(`e2e_http_connector.py`'s reason) and that public name resolves to 127.0.0.1.

## The model half

`--yes-this-spends-money` builds a real LangChain agent over a real Claude
(`langchain-anthropic`, `ANTHROPIC_API_KEY`) and asks it a question only the tool can
answer, then one outside the scope, and reads what the model *said* about the denial.
Everything before that flag drives the tools through LangChain's own `invoke` and
`ainvoke` with no model, which is the mechanics the plan's verification names and costs
nothing. **The model half has not been run from here** — no key on this machine — and
the summary says which half ran.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import pathlib
import socket
import sys
import threading
import time
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
SCRATCH = HERE.parent / "var" / "e2e_client_langchain"
UPSTREAM_HOST = "localtest.me"
SHARED = "the-shared-jira-secret"
TENANT = os.environ.get("CARNET_TENANT") or "default"

CHECKS: list[tuple[str, bool, object, object]] = []


def check(label, actual, expected=True):
    ok = actual == expected
    CHECKS.append((label, ok, actual, expected))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}" + ("" if ok else f"  (expected {expected!r})"))
    return ok


def say(what):
    print(f"\n=== {what}", flush=True)


def report() -> int:
    say("summary")
    failed = [label for label, ok, *_ in CHECKS if not ok]
    print(f"  {len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --- the upstream the door dials ------------------------------------------------------

ADVERTISED = [
    {
        "name": "search_issues",
        "description": "Search issues in a project.",
        "inputSchema": {
            "type": "object",
            "properties": {"project": {"type": "string"}, "jql": {"type": "string"}},
            "required": ["project"],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "create_issue",
        "description": "Open an issue.",
        "inputSchema": {
            "type": "object",
            "properties": {"project": {"type": "string"}, "title": {"type": "string"}},
            "required": ["project", "title"],
        },
    },
]


class TinyMcp(http.server.BaseHTTPRequestHandler):
    """The subset the door's transport speaks; echoes the Authorization it saw."""

    seen: list = []

    def log_message(self, *args):
        pass

    def do_DELETE(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        message = json.loads(self.rfile.read(length) or b"{}")
        if "id" not in message:
            self.send_response(202)
            self.end_headers()
            return
        method = message.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "tiny-jira", "version": "0.1"}}
        elif method == "tools/list":
            result = {"tools": ADVERTISED}
        elif method == "tools/call":
            TinyMcp.seen.append((message["params"], self.headers.get("Authorization") or ""))
            project = (message["params"].get("arguments") or {}).get("project")
            result = {"content": [{"type": "text", "text": json.dumps(
                {"issues": [f"{project}-1", f"{project}-2"], "count": 2})}]}
        else:
            result = {}
        body = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# --- the door, in this process --------------------------------------------------------


def the_file(upstream_port: int) -> str:
    return f"""
connectors:
  jira:
    url: http://{UPSTREAM_HOST}:{upstream_port}/mcp/
    credential: ${{JIRA_TOKEN}}
    tools:
      - name: search_issues
        effect: read
        resources: [{{type: jira.project, args: [project]}}]
      - name: create_issue
        effect: write
        resources: [{{type: jira.project, args: [project]}}]
agents:
  triage:
    tools: [jira_search_issues]
    scope:
      jira.project: {{read: [ACME]}}
tokens:
  laptop:
    secret: ${{CARNET_TOKEN_LAPTOP}}
    agents: [triage]
"""


FILE = SCRATCH / "carnet.yaml"


def point_the_environment_at_the_file() -> None:
    """Before anything imports `carnet`: `carnet.config` reads the environment at import,
    and the first `from carnet... import` anywhere in this script pulls it in. The file's
    *contents* can be written later — the door reads them at startup, not at import —
    but the variables naming the mode must already be there."""
    SCRATCH.mkdir(parents=True, exist_ok=True)
    os.environ.pop("CARNET_DATABASE_URL", None)
    os.environ["CARNET_FILE"] = str(FILE)
    os.environ["JIRA_TOKEN"] = SHARED
    os.environ["CARNET_EGRESS_INTERNAL_HOSTS"] = UPSTREAM_HOST


def start_door(upstream_port: int, presented: str) -> tuple[str, threading.Thread]:
    """uvicorn on a thread, over the in-memory store the file fills."""
    FILE.write_text(the_file(upstream_port), encoding="utf-8")
    os.environ["CARNET_TOKEN_LAPTOP"] = presented

    import uvicorn

    from carnet.api import app

    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2)
            break
        except Exception:  # noqa: BLE001 - not up yet
            time.sleep(0.2)
    else:
        raise SystemExit("the door did not come up")
    return f"http://127.0.0.1:{port}/mcp", thread


# --- the scenes -----------------------------------------------------------------------


def the_mechanics(url: str, presented: str):
    """LangChain's own `invoke`/`ainvoke` over the adapter: list, call, denial, revoke."""
    import asyncio

    from carnet import storage
    from carnet.access import tokens
    from carnet_mcp import Door, DoorRefused
    from carnet_mcp.langchain import tools

    say("the three lines: tools(url, token)")
    made = tools(url, presented)
    names = [t.name for t in made]
    check("the tool list is the grant list — one tool, the granted one", names, ["jira_search_issues"])
    search = made[0]
    check("the schema is the connector's", search.args_schema.get("required"), ["project"])
    check("both slots are filled (sync and async)", search.func is not None and search.coroutine is not None)

    say("a call in scope, through LangChain's invoke")
    before = len(TinyMcp.seen)
    out = search.invoke({"project": "ACME"})
    check("the tool answered", "ACME-1" in out)
    check("the upstream was called once", len(TinyMcp.seen) - before, 1)
    check("and saw the broker's credential, which the agent never held",
          TinyMcp.seen[-1][1], f"Bearer {SHARED}")
    check("the process holding the agent holds no upstream credential",
          SHARED in presented or SHARED in url, False)

    say("the same through ainvoke — the coroutine slot, not the sync one in a thread")
    out = asyncio.run(search.ainvoke({"project": "ACME"}))
    check("the async call answered", "ACME-1" in out)

    say("a call outside scope: the model reads the door's sentence, the turn continues")
    before = len(TinyMcp.seen)
    message = search.invoke({"name": "jira_search_issues", "args": {"project": "OTHER"},
                             "id": "call_1", "type": "tool_call"})
    check("it is a ToolMessage with an error status", getattr(message, "status", None), "error")
    check("in the door's words", "outside this agent's 'read' scope" in message.content)
    check("with the audit row's id appended", "(carnet call door-" in message.content)
    check("and the upstream was not dialled", len(TinyMcp.seen) - before, 0)
    print(f"      the model reads: {message.content}")

    say("the grant is revoked while the agent is up (decision 8)")
    token_id, _ = tokens.digest_presented(presented)
    storage.active().revoke_agent(TENANT, "triage", "machine", token_id, actor="system:cli")
    check("the tool is still in the agent's list — visibility goes stale", [t.name for t in made], ["jira_search_issues"])
    before = len(TinyMcp.seen)
    message = search.invoke({"name": "jira_search_issues", "args": {"project": "ACME"},
                             "id": "call_2", "type": "tool_call"})
    check("the next call is refused — enforcement does not", getattr(message, "status", None), "error")
    check("by name, in the door's words", "provides a tool called 'jira_search_issues'" in message.content)
    check("no call id, because no audit row: the door turned it away at its own threshold",
          "(carnet call" in message.content, False)
    check("and the upstream was not dialled", len(TinyMcp.seen) - before, 0)
    print(f"      the model reads: {message.content}")
    with Door(url, presented) as fresh:
        check("a fresh client sees the grant list as it is now: empty", fresh.tools(), [])

    say("a token the door does not know fails at the handshake")
    try:
        tools(url, "art_m_0000000000000000.not-a-token")
        check("refused", False)
    except DoorRefused as exc:
        check("refused with 401 before any method ran", exc.status, 401)


def the_model(url: str, presented: str, model: str):
    """A real agent over a real model. Spends money; not run from here."""
    say("a real agent, a real model")
    try:
        from langchain.agents import create_agent
        from langchain_anthropic import ChatAnthropic
    except ImportError as exc:
        raise SystemExit(
            f"the model half needs `uv pip install langchain langchain-anthropic`: {exc}"
        ) from exc
    from carnet_mcp.langchain import tools

    agent = create_agent(ChatAnthropic(model=model, max_tokens=400), tools(url, presented))
    before = len(TinyMcp.seen)
    result = agent.invoke({"messages": [("user", "How many open issues are in the ACME project? Use the tool.")]})
    check("the model used the tool", len(TinyMcp.seen) - before, 1)
    final = result["messages"][-1].content
    print(f"      the model said: {final!r}")
    result = agent.invoke({"messages": [("user", "Now do the same for the OTHER project.")]})
    said = str(result["messages"][-1].content).lower()
    check("the model said it was denied, rather than crashing", any(w in said for w in ("denied", "not allowed", "outside", "scope", "permission")))
    print(f"      the model said: {result['messages'][-1].content!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--yes-this-spends-money", action="store_true", help="also run a real LangChain agent over a real Claude")
    parser.add_argument("--model", default=os.environ.get("USE_PRODUCT_MODEL", "claude-haiku-4-5-20251001"))
    args = parser.parse_args()

    sys.path.insert(0, str(HERE.parent / "src"))
    point_the_environment_at_the_file()
    from carnet.access import tokens

    upstream = http.server.ThreadingHTTPServer(("0.0.0.0", 0), TinyMcp)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    upstream_port = upstream.server_address[1]

    # The same call `carnet --new-token` makes: a fresh `art_m_<id>.<secret>` string, held
    # by nothing but this process's environment, which is exactly a customer's situation.
    presented = tokens.new_presented()

    say(f"a fileborne door in this process, upstream on {UPSTREAM_HOST}:{upstream_port}")
    url, _ = start_door(upstream_port, presented)
    print(f"  door: {url}")

    try:
        the_mechanics(url, presented)
        if args.yes_this_spends_money:
            if not os.environ.get("ANTHROPIC_API_KEY"):
                raise SystemExit("--yes-this-spends-money needs ANTHROPIC_API_KEY")
            the_model(url, presented, args.model)
        else:
            print("\n  (the model half was not run: pass --yes-this-spends-money with ANTHROPIC_API_KEY set)")
    finally:
        upstream.shutdown()
    return report()


if __name__ == "__main__":
    raise SystemExit(main())
