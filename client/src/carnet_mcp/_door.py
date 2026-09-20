"""The protocol: `initialize`, `tools/list`, `tools/call`, over `httpx`.

## Why this is forty lines and not the official SDK

The door answers five JSON-RPC methods and sends one JSON body per message — no SSE, no
session id, no server-initiated request. A client for that is a POST, a header and a
parser, which is what this file is. Depending on the `mcp` package instead would pull in
a session lifecycle, an anyio task group and an SSE reader for a transport the door does
not serve, and couple this package's release to a fast-moving package's minor versions.
Plan 111, decision 3. The counter-argument is recorded there: if the door ever grows a
streaming `tools/call`, this file reimplements what the SDK would have given us. That is
accepted, because the door's answer shape is a decision, not an accident, and changing it
is a plan of its own that would revisit this line.

## What the door answers, and how each answer is read

    HTTP 401 / 403             the token — `DoorRefused(status=…)`, on the first call
                               whatever that call is, because the door checks it before
                               dispatch so the handshake is a real check
    HTTP 5xx, not JSON,        `DoorUnavailable`: the door did not answer
      connection error
    HTTP 3xx, 404, 405         `DoorUnavailable`, naming the address: nothing answers
                               MCP here, or the door wants a different URL (`/mcp/`
                               redirects to `/mcp`). Redirects are not followed — one
                               address is the whole of decision 10
    JSON-RPC `error`           `DoorRefused(code=…)`: an ungranted tool name, an argument
                               the door will not record. No audit row was written, so
                               there is no call id
    `tools/call` result with   `CallResult.is_error`: a brokered denial or a failed tool,
      `isError: true`          with the sentence in `structuredContent.error` and the
                               audit row's id in `_meta`. Not raised — see `errors.py`
    `tools/call` result        `CallResult`, with the id

## Sync and async are two classes, and neither wraps the other

LangChain's tool takes a `func` and a `coroutine`; an async agent calling a sync function
blocks its event loop, and a sync agent given only a coroutine cannot call it at all. So
`Door` is over `httpx.Client` and `AsyncDoor` over `httpx.AsyncClient`, and everything
that is not the I/O — the message shapes, the answer parsing, the handshake check — is a
module-level function both call. Doing this at the start is cheap; retrofitting async
onto a sync client is a rewrite.

## The handshake runs once, before the first request

`initialize` is where a protocol version disagreement surfaces, and it should surface at
construction rather than as a confusing failure at the tenth call. It is run lazily —
before the first `tools()` or `call()`, under a lock — rather than in `__init__`, so that
constructing a `Door` costs nothing and an `AsyncDoor` needs no `await` to build. In
every framework the first request *is* construction: the tool list is fetched when the
agent is built. An unknown protocol version **warns and continues** (`ProtocolVersionWarning`).

## One host

Every request this module sends goes to `self.url`. There is no other address in this
package, and `tests/test_one_host.py` holds that in place by reading the source.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import threading
import warnings
from dataclasses import dataclass
from typing import Any, Mapping

import httpx

from ._version import __version__
from .errors import DoorRefused, DoorUnavailable, ProtocolVersionWarning

# The newest revision the door speaks, and what this client asks for. The door echoes a
# revision it knows and answers with its own otherwise; anything outside this set is the
# warning above, not a refusal.
PROTOCOL_VERSION = "2025-06-18"
KNOWN_PROTOCOL_VERSIONS = frozenset({"2024-11-05", "2025-03-26", "2025-06-18"})

# The door's response-side extension point (step 083): every `tools/call` result that
# wrote an audit row carries the row's correlation id here — the `door-<hex>` string an
# administrator finds on the door-calls page. It is the one string a support conversation
# needs, so the adapters append it to every refusal a model reads.
CALL_ID_META_KEY = "com.carnet/call-id"

# What this client calls itself in the handshake, and so in a door's logs.
CLIENT_NAME = "carnet-mcp"


@dataclass(frozen=True)
class Tool:
    """One entry of `tools/list`: what the token may call, with the schema the door
    forwards from the vetted connector."""

    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class CallResult:
    """One `tools/call` answer, as the door sent it.

    `is_error` is MCP's `isError`: the tool did not do what was asked, and `sentence` says
    why in the door's words. A brokered denial and a failed tool both arrive this way,
    which is the door's decision (a denial is the same sentence a model would have
    received in the product's own chat) and is why the adapters relay rather than raise.
    """

    content: tuple[dict[str, Any], ...]
    structured: Any
    is_error: bool
    call_id: str | None

    @property
    def text(self) -> str:
        """What a framework hands the model on success.

        The door sends two halves of the same document — `structuredContent`, and a
        text block that is that object serialised with ASCII escapes. Preferring the
        structured half and serialising it here without escapes is the difference
        between a model reading *café* and reading `caf\\u00e9`. A result with only text
        blocks (not something the door produces, but the shape is legal) is joined.
        """
        if self.structured is not None:
            return json.dumps(self.structured, ensure_ascii=False, default=str)
        return "\n".join(block.get("text", "") for block in self.content if block.get("type") == "text")

    @property
    def sentence(self) -> str:
        """The door's sentence for an error result, with the call id appended.

        The door puts a denial's reason in `structuredContent.error` and serialises the
        same object into the text block; the sentence is the reason alone, which is what
        a model should read, followed by the id that turns *the agent said it was denied*
        into a row on the door-calls page. It is the door's sentence relayed, not a
        second opinion about it: a wrapper that paraphrased would drift.
        """
        said = None
        if isinstance(self.structured, dict) and isinstance(self.structured.get("error"), str):
            said = self.structured["error"]
        if not said:
            said = self.text or "the tool did not complete, and the door gave no reason"
        return f"{said} (carnet call {self.call_id})" if self.call_id else said

    @property
    def relay(self) -> str:
        """What to hand a framework whose only channel is the returned string: the text
        on success, the sentence on an error."""
        return self.sentence if self.is_error else self.text


# --- the messages, and how an answer is read (shared by both doors) --------------------


def _headers(token: str, protocol: str | None) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if protocol:
        # 2025-06-18 asks a client to name the negotiated revision on every request
        # after the handshake. The door does not require it; a proxy in front of one may.
        headers["MCP-Protocol-Version"] = protocol
    return headers


def _request_body(message_id: int, method: str, params: Mapping[str, Any]) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": message_id, "method": method, "params": dict(params)}).encode()


def _notification_body(method: str) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "method": method}).encode()


def _initialize_params() -> dict[str, Any]:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": CLIENT_NAME, "version": __version__},
    }


def _checked(url: str, token: str, who: str) -> tuple[str, str]:
    """Both present; the token trimmed. A token pasted with a trailing newline is the
    commonest paste error, and untrimmed it reaches httpx as an illegal header value —
    a transport failure about the wrong thing. Whitespace *inside* a token is refused
    with a sentence, because no token has any."""
    if not url or not isinstance(url, str):
        raise ValueError(f"{who} needs the door's URL")
    if not token or not isinstance(token, str):
        raise ValueError(f"{who} needs an access token")
    token = token.strip()
    # A whole `Bearer art_…` header pasted as the token is the second commonest paste
    # error; the prefix is this client's to add, so it is taken off rather than sent twice.
    if token[:7].lower() == "bearer ":
        token = token[7:].strip()
    if not token or any(ch.isspace() for ch in token):
        raise ValueError(f"{who}: the access token contains whitespace — check the paste")
    return url, token


def _detail(response: httpx.Response) -> str | None:
    """The door's own sentence out of an HTTP-level refusal, when it sent one."""
    try:
        body = response.json()
    except ValueError:
        return None
    if isinstance(body, dict):
        for key in ("detail", "message", "error"):
            value = body.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def _answer(response: httpx.Response, method: str, url: str) -> Any:
    """An HTTP response to a JSON-RPC result, or the exception the table above names."""
    status = response.status_code
    if status in (401, 403):
        raise DoorRefused(
            _detail(response) or f"the door at {url} refused the token ({status})",
            status=status,
        )
    if 300 <= status < 400:
        # Not followed, on purpose: this client sends requests to one address, and a
        # redirect is a second one. The door redirects `/mcp/` to `/mcp`; the fix is
        # the address, and the sentence says which.
        where = response.headers.get("location") or "somewhere it did not say"
        raise DoorUnavailable(
            f"the door at {url} redirected {method} ({status}) to {where}. "
            "This client does not follow redirects; use that address."
        )
    if status in (404, 405):
        raise DoorUnavailable(
            f"nothing answers MCP at {url} ({status} to {method}) — is this the /mcp address? "
            "It is the MCP server URL on the agent's connect card."
        )
    if status >= 500:
        raise DoorUnavailable(f"the door at {url} answered {status} to {method}")
    if status >= 400:
        raise DoorRefused(_detail(response) or f"the door refused {method} with {status}", status=status)
    try:
        body = response.json()
    except ValueError:
        raise DoorUnavailable(
            f"the door at {url} answered {method} with something that is not JSON — "
            "is this the /mcp address?"
        ) from None
    if not isinstance(body, dict):
        raise DoorUnavailable(f"the door at {url} answered {method} with a JSON {type(body).__name__}, not a message")
    if "error" in body:
        error = body.get("error") or {}
        message = error.get("message") if isinstance(error, dict) else None
        code = error.get("code") if isinstance(error, dict) else None
        raise DoorRefused(str(message or error), code=code)
    return body.get("result")


def _tools_from(result: Any) -> list[Tool]:
    entries = result.get("tools", []) if isinstance(result, dict) else []
    return [
        Tool(
            name=str(entry["name"]),
            description=str(entry.get("description") or ""),
            input_schema=dict(entry.get("inputSchema") or {"type": "object", "properties": {}}),
        )
        for entry in entries
        if isinstance(entry, dict) and entry.get("name")
    ]


def _call_from(result: Any) -> CallResult:
    if not isinstance(result, dict):
        result = {}
    content = tuple(block for block in result.get("content") or () if isinstance(block, dict))
    meta = result.get("_meta")
    call_id = meta.get(CALL_ID_META_KEY) if isinstance(meta, dict) else None
    return CallResult(
        content=content,
        structured=result.get("structuredContent"),
        is_error=bool(result.get("isError")),
        call_id=str(call_id) if call_id else None,
    )


def _handshake_from(result: Any, url: str) -> tuple[str, dict[str, Any]]:
    if not isinstance(result, dict):
        raise DoorUnavailable(f"the door at {url} answered initialize with no result — is this the /mcp address?")
    protocol = str(result.get("protocolVersion") or "")
    if protocol not in KNOWN_PROTOCOL_VERSIONS:
        warnings.warn(
            f"the door at {url} speaks MCP {protocol or '(unstated)'}, which this version of "
            f"{CLIENT_NAME} ({__version__}) does not know. Continuing: the methods this "
            "client uses have not changed across revisions. Upgrade whichever is older.",
            ProtocolVersionWarning,
            stacklevel=4,
        )
    server = result.get("serverInfo")
    return protocol, dict(server) if isinstance(server, dict) else {}


def _transport_failure(exc: Exception, url: str) -> DoorUnavailable:
    return DoorUnavailable(f"could not reach the door at {url}: {type(exc).__name__}: {exc}")


# --- sync ------------------------------------------------------------------------------


class Door:
    """The door, synchronously. `tools()` once, `call()` per tool use.

    `client` is for a caller with their own `httpx.Client` — a proxy, a private CA, a
    pool; it is not closed by this object. Without one, a client is made and closed by
    `close()` or the context manager.
    """

    def __init__(
        self,
        url: str,
        token: str,
        *,
        timeout: float = 30.0,
        client: httpx.Client | None = None,
    ):
        self.url, self._token = _checked(url, token, "Door")
        self._client = client if client is not None else httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._protocol: str | None = None
        self._tools: list[Tool] | None = None
        self.server_info: dict[str, Any] = {}

    def __repr__(self) -> str:
        # Never the token.
        return f"Door({self.url!r})"

    def _post(self, body: bytes, method: str) -> httpx.Response:
        try:
            return self._client.post(self.url, content=body, headers=_headers(self._token, self._protocol))
        except (httpx.HTTPError, RuntimeError) as exc:
            # RuntimeError is httpx's own for a client that has been closed.
            raise _transport_failure(exc, self.url) from exc

    def _request(self, method: str, params: Mapping[str, Any]) -> Any:
        return _answer(self._post(_request_body(next(self._ids), method, params), method), method, self.url)

    def handshake(self) -> None:
        """`initialize`, once. Safe to call more than once; every other method calls it."""
        with self._lock:
            if self._protocol is not None:
                return
            protocol, server = _handshake_from(self._request("initialize", _initialize_params()), self.url)
            self._protocol, self.server_info = protocol, server
            # The door answers a notification with 202 and no body; a failure here is a
            # transport failure and raises as one. Its content is not read.
            self._post(_notification_body("notifications/initialized"), "notifications/initialized")

    def tools(self) -> list[Tool]:
        """What this token may call. Fetched once and cached for the life of the object
        — the module docstring says why that is safe."""
        self.handshake()
        if self._tools is None:
            self._tools = _tools_from(self._request("tools/list", {}))
        return list(self._tools)

    def call(self, name: str, arguments: Mapping[str, Any] | None = None) -> CallResult:
        """One brokered call. Raises `DoorRefused` for a tool this token is not granted
        and `DoorUnavailable` when the door did not answer; a brokered denial is a
        `CallResult` with `is_error`."""
        self.handshake()
        return _call_from(self._request("tools/call", {"name": name, "arguments": dict(arguments or {})}))

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "Door":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# --- async -----------------------------------------------------------------------------


class AsyncDoor:
    """The door, asynchronously. The same three methods, awaited."""

    def __init__(
        self,
        url: str,
        token: str,
        *,
        timeout: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ):
        self.url, self._token = _checked(url, token, "AsyncDoor")
        self._timeout = timeout
        self._client = client if client is not None else httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None
        # The loop the client was made under. `httpx.AsyncClient` holds connections that
        # belong to one loop; a sync agent that calls `asyncio.run` per tool use closes a
        # loop every call, and the second call would die with "Event loop is closed".
        # `_client_for_this_loop` swaps in a fresh client when the loop has changed.
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ids = itertools.count(1)
        self._lock = asyncio.Lock()
        self._protocol: str | None = None
        self._tools: list[Tool] | None = None
        self.server_info: dict[str, Any] = {}

    def __repr__(self) -> str:
        return f"AsyncDoor({self.url!r})"

    async def _client_for_this_loop(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        elif loop is not self._loop:
            if not self._owns_client:
                raise DoorUnavailable(
                    f"the AsyncDoor for {self.url} was given an httpx.AsyncClient on one event "
                    "loop and is being used on another; make a new AsyncDoor per loop"
                )
            # The old client's connections belong to a loop that may be closed; closing
            # it there is not possible from here, so it is dropped and collected.
            self._client = httpx.AsyncClient(timeout=self._timeout)
            self._lock = asyncio.Lock()
            self._loop = loop
        return self._client

    async def _post(self, body: bytes, method: str) -> httpx.Response:
        try:
            client = await self._client_for_this_loop()
            return await client.post(self.url, content=body, headers=_headers(self._token, self._protocol))
        except (httpx.HTTPError, RuntimeError) as exc:
            raise _transport_failure(exc, self.url) from exc

    async def _request(self, method: str, params: Mapping[str, Any]) -> Any:
        return _answer(await self._post(_request_body(next(self._ids), method, params), method), method, self.url)

    async def handshake(self) -> None:
        await self._client_for_this_loop()
        async with self._lock:
            if self._protocol is not None:
                return
            protocol, server = _handshake_from(await self._request("initialize", _initialize_params()), self.url)
            self._protocol, self.server_info = protocol, server
            await self._post(_notification_body("notifications/initialized"), "notifications/initialized")

    async def tools(self) -> list[Tool]:
        await self.handshake()
        if self._tools is None:
            self._tools = _tools_from(await self._request("tools/list", {}))
        return list(self._tools)

    async def call(self, name: str, arguments: Mapping[str, Any] | None = None) -> CallResult:
        await self.handshake()
        return _call_from(await self._request("tools/call", {"name": name, "arguments": dict(arguments or {})}))

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> "AsyncDoor":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()
