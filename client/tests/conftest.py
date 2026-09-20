"""A stub door over `httpx.MockTransport`, reproducing the answers that matter.

The real door's shapes, copied rather than imagined — from `routes_mcp.py` and one
session against a fileborne door on 2026-09-19:

    a result           `content` text block + `structuredContent` + `_meta` call id
    a denial           the same shape with `isError: true` and `{"error": ..., "denied_by": "broker"}`
    an ungranted tool  JSON-RPC `-32602`, no `_meta`
    a bad token        HTTP 401 `{"detail": ...}` with `WWW-Authenticate`, before any method
    a notification     HTTP 202, empty
    a dead door        a connection error; a gateway in front of one, 502

`MockTransport` takes a sync handler for both `httpx.Client` and `httpx.AsyncClient`, so
one stub serves both doors, and it records every request so the one-host and token tests
can read what actually went on the wire.
"""

from __future__ import annotations

import json

import httpx
import pytest

URL = "https://carnet.example.com/api/mcp"
TOKEN = "art_m_stub1234567890.SECRET-FOR-THE-STUB-ONLY"
CALL_ID = "door-0123456789abcdef"

TOOLS = [
    {
        "name": "jira_search_issues",
        "description": "Search issues in a project.",
        "inputSchema": {
            "type": "object",
            "properties": {"project": {"type": "string"}, "jql": {"type": "string"}},
            "required": ["project"],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "jira_create_issue",
        "description": "Open an issue.",
        "inputSchema": {
            "type": "object",
            "properties": {"project": {"type": "string"}, "title": {"type": "string"}},
            "required": ["project", "title"],
        },
    },
]

DENIAL = "Denied by broker: jira.project 'OTHER' is outside this agent's 'read' scope. Allowed: ACME"


def _rpc(message_id, result=None, error=None):
    body = {"jsonrpc": "2.0", "id": message_id}
    if error is not None:
        body["error"] = error
    else:
        body["result"] = result
    return httpx.Response(200, json=body)


class StubDoor:
    def __init__(self, *, protocol: str = "2025-06-18", token: str = TOKEN):
        self.protocol = protocol
        self.token = token
        self.mode = "ok"  # ok | denied | ungranted | down | gateway | garbage
        self.requests: list[httpx.Request] = []
        self.bodies: list[dict] = []
        self.initializes = 0
        self.lists = 0
        self.calls = 0

    def handle(self, request: httpx.Request) -> httpx.Response:
        if self.mode == "down":
            raise httpx.ConnectError("connection refused", request=request)
        self.requests.append(request)
        body = json.loads(request.content) if request.content else {}
        self.bodies.append(body)
        if request.headers.get("authorization") != f"Bearer {self.token}":
            return httpx.Response(
                401, json={"detail": "not a live token"}, headers={"WWW-Authenticate": "Bearer"}
            )
        if "id" not in body:
            return httpx.Response(202)
        message_id, method, params = body["id"], body["method"], body.get("params") or {}
        if method == "initialize":
            self.initializes += 1
            asked = params.get("protocolVersion")
            return _rpc(message_id, {
                "protocolVersion": asked if asked == self.protocol else self.protocol,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "carnet", "version": "0.11.0"},
            })
        if method == "tools/list":
            self.lists += 1
            return _rpc(message_id, {"tools": TOOLS})
        if method == "tools/call":
            self.calls += 1
            if self.mode == "gateway":
                return httpx.Response(502, text="Bad Gateway")
            if self.mode == "garbage":
                return httpx.Response(200, text="<html>not a door</html>")
            name = params.get("name")
            if self.mode == "ungranted" or name not in {t["name"] for t in TOOLS}:
                return _rpc(message_id, error={
                    "code": -32602,
                    "message": f"no agent granted to this token provides a tool called '{name}'.",
                })
            if self.mode == "denied":
                said = {"error": DENIAL, "denied_by": "broker"}
                return _rpc(message_id, {
                    "content": [{"type": "text", "text": json.dumps(said)}],
                    "structuredContent": said,
                    "isError": True,
                    "_meta": {"com.carnet/call-id": CALL_ID},
                })
            answer = {"issues": ["ACME-1", "ACME-2"], "arguments": params.get("arguments")}
            return _rpc(message_id, {
                "content": [{"type": "text", "text": json.dumps(answer)}],
                "structuredContent": answer,
                "isError": False,
                "_meta": {"com.carnet/call-id": CALL_ID},
            })
        return _rpc(message_id, error={"code": -32601, "message": f"unknown method {method}"})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handle))

    def async_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handle))


@pytest.fixture
def stub() -> StubDoor:
    return StubDoor()
