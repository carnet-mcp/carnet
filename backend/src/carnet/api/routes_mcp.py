"""`POST /mcp` — Carnet as an MCP server. Step 033b, decisions 1 through 4.

This module is **JSON-RPC framing and nothing else**. What a token may see and call is
`carnet/door.py`, on the same split every other router here has: this file owns HTTP
and `door.py` owns what a door call is, and the reason is that a second entry point onto
the same tier must not be able to enforce anything differently.

## The shape of the server, and what it deliberately does not implement

The client half of this protocol has been in the tree since step 012 (`tools/mcp/`), and
it is deliberately small — handshake, list, call — for reasons its own docstring states.
The server half is smaller still, and the omissions are decisions:

    implemented    initialize, notifications/*, ping, tools/list, tools/call
    not            resources, prompts, sampling, roots, completions, subscriptions,
                   server-initiated requests, SSE streams, session ids, batching

**Stateless, and that is decision 9 arriving early.** No `Mcp-Session-Id` is ever issued,
which the specification permits. Every request re-resolves token → grants → tools, so a
revoked grant is refused at the *next request* rather than at the next session — and the
half of the door that sits in a customer's production path scales by adding replicas,
with nothing held between calls that two processes could disagree about.

**JSON, never SSE.** A server may answer either, and there is nothing here to stream: a
`tools/call` is one synchronous brokered call, already bounded by `MAX_RESPONSE_BYTES`.
Progress notifications would have been the concern of a mode where a call can take
minutes — plan 033 called that agent mode, and it is **withdrawn permanently**
(`docs/PREMISE.md`). Tool mode is the only mode, so this decision is settled rather than
provisional: nothing that reaches this route can outlive one request.

**`GET` and `DELETE` answer 405**, and they do it by not existing — Starlette answers a
known path with an unknown method that way already. Both are optional in the
specification and both are about a session this server does not have: `GET` opens a
server-initiated stream, `DELETE` terminates a session id.

## Errors: which failures are JSON-RPC and which are HTTP

The rule, and it is the same one `api/errors.py` states for the rest of this API — the
status has to describe *whose* problem it is:

    a broker denial            a **result** with isError, never an error at all. The
                               enforcement worked; the calling agent is told and carries
                               on, exactly as a model does. See `api/errors.py`'s
                               "a brokered denial is not an HTTP error".
    an ungranted tool name     JSON-RPC -32602. The caller asked for something outside
                               the list it was handed; that is its request being wrong.
    an unknown method          JSON-RPC -32601.
    a connector that is down   JSON-RPC -32603, naming it. Not an HTTP 502 — the request
                               reached us and we answered it; what failed is one of the
                               tools it asked about.
    a person's credential      HTTP 403, through `errors.py`. Authentication-level, and
                               MCP puts authentication at the HTTP layer.
    an unreadable database     HTTP 503, through `errors.py`, unchanged and deliberate:
                               that is not something to bury in a JSON-RPC envelope a
                               client will report as a tool error.

A body that is not a JSON-RPC request at all is FastAPI's 422. JSON-RPC would have this
be a `-32700` with `"id": null`, and the honest reading is that there is nothing a client
does with that which it does not do with a 422 — there is no id to answer against, and
the caller is not speaking the protocol.
"""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from .. import __version__, config, door
from ..access import oauth_server
from ..core import Principal
from .deps import principal_from_request
from .responses import AsciiJSONResponse

log = logging.getLogger(__name__)

router = APIRouter(tags=["mcp"])

# The protocol revisions this subset is stable across. We echo the client's when it is
# one of these and answer with our own otherwise, which is what the specification asks
# for — negotiation, not insistence. Kept in step with `tools/mcp/client.py`'s
# `PROTOCOL_VERSION`, which is the newest of them and what the client half sends.
SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")
LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[-1]

# JSON-RPC 2.0's reserved codes, spelled out rather than written as literals at the four
# call sites. `-32602` is "invalid params", which is what an ungranted tool name is: the
# method exists, the argument naming the tool does not name anything this caller has.
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# Where an acting-for identity rides on a `tools/call`: one key in the request's
# `_meta`, per call. Step 033c, and the shape was ratified against the official SDK on
# a real socket rather than guessed: `_meta` is the protocol's own extension point (an
# open map, first-class in every SDK's `call_tool`), it arrives on exactly the request
# it describes, and it is the only per-call channel a client actually has — custom
# headers bind to the transport at construction, per *connection*, and the caller this
# exists for multiplexes fifty people over one connection. The prefix is ours by the
# spec's naming rule (`io.modelcontextprotocol/*` is reserved; applications use a name
# they control), so no client or future revision can collide with it.
#
# Every other `_meta` key is ignored, not refused — `progressToken` and the
# SDK-managed reserved keys legitimately appear there, and a server that rejects
# metadata it does not consume breaks conformant clients. Unknown keys *inside* our
# own object are the opposite case and refuse loudly; see `access/acting.py`.
ACTING_FOR_META_KEY = "com.carnet/acting-for"

# The response side of the same extension point — step 083, 080's E2. Every
# `tools/call` result that wrote an audit row carries the row's correlation id here:
# the `door-<hex>` string that is `run_id` on `/admin/door-calls`, minted by
# `door.new_call_id` and handed to `door.call_tool` so the two cannot differ. An agent
# with forty calls and one denial can now say which row is its. A `DoorRefused`
# (JSON-RPC `-32602`) wrote no audit row and gets no id: there is nothing to name.
CALL_ID_META_KEY = "com.carnet/call-id"


class JsonRpcRequest(BaseModel):
    """One JSON-RPC message. A request has an `id`; a notification does not.

    Batching (a JSON array) is not accepted, and that is the current specification's
    position rather than ours: 2025-06-18 removed it. A client that sends one gets
    FastAPI's 422, which is a clear enough answer to a message shape the protocol no
    longer has.
    """

    jsonrpc: str = "2.0"
    # `str | int | None`. Null and absent are treated identically — as a notification —
    # which is a small liberty: JSON-RPC calls an explicit null id a request with a null
    # id. Nothing in MCP sends one, and answering a null id is indistinguishable from
    # answering nobody.
    id: str | int | None = None
    method: str
    params: dict | None = Field(default=None)


# How much caller-supplied text an error sentence may quote back. Long enough that every
# real method and tool name survives whole — the registry caps a tool name at 64 — and
# short enough that a refusal cannot be made to echo a payload.
#
# Small, but the same shape as two defects this step already fixed: unbounded input from
# somebody else's agent, repeated back somewhere it is kept or sent. A refusal that quotes
# a megabyte is a refusal that costs more to serve than the request did.
QUOTE_LIMIT = 80


def _short(value: str) -> str:
    """Caller-supplied text, safe to put in a sentence."""
    text = str(value)
    return text if len(text) <= QUOTE_LIMIT else f"{text[:QUOTE_LIMIT]}…"


def _result(message_id, result: dict) -> JSONResponse:
    # **`AsciiJSONResponse`, because this body is not ours.** A `tools/call` result is
    # the connector's own answer, forwarded — so a vendor that puts a lone surrogate
    # anywhere in it (an echoed filename, a model id, a snippet of somebody's file)
    # used to kill Starlette's `render` and turn a completed call into a 500. Escaping
    # non-ASCII costs nothing a JSON parser can see and makes the door's answer
    # renderable whatever a vendor sends. Found by step 108's edge pass.
    return AsciiJSONResponse({"jsonrpc": "2.0", "id": message_id, "result": result})


def _error(message_id, code: int, message: str) -> JSONResponse:
    # **200, with the error inside the envelope.** A JSON-RPC error is a well-formed
    # answer to a well-formed question, and clients read the body. Using an HTTP status
    # instead would mean an MCP client reporting "the server is unreachable" about a
    # server that answered precisely.
    # Ascii-safe for `_result`'s reason: a refusal quotes the caller's own tool name and
    # arguments back at them, bounded but not re-encodable.
    return AsciiJSONResponse(
        {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": message}})


def widen_challenge(exc: HTTPException) -> HTTPException:
    """A 401 at the door, with `resource_metadata` added to its `WWW-Authenticate`.

    MCP's authorization specification (2025-06-18) says a server **must** answer an
    unauthenticated request with `WWW-Authenticate` naming where its protected-resource
    metadata is, because that header is how a client that was handed only a URL finds
    out where to sign in. So on a 401 at the door — and only there, and only a 401 —
    the header is widened to carry `resource_metadata="…"` beside whatever `error=` it
    already had. Every other outcome, including the 403 a person's own credential gets
    from `require_machine`, is exactly `principal_from_request`'s. Step 083.

    Scoped to this route by the endpoint the router matched (`scope["endpoint"]`),
    not by path: behind the shipped front door uvicorn runs with `--root-path /api`
    and the path the request carries is `/api/mcp`. Found by `e2e_deploy.py`.

    Applied by `api/errors.py`'s `HTTPException` handler rather than by a wrapping
    dependency, so a test that overrides `principal_from_request` still overrides the
    door, and so the widening happens where a 401 becomes bytes.
    """
    challenge = (exc.headers or {}).get("WWW-Authenticate", "Bearer")
    metadata = oauth_server.endpoints()["resource_metadata"]
    if challenge == "Bearer":
        widened = f'Bearer resource_metadata="{metadata}"'
    else:
        widened = f'{challenge}, resource_metadata="{metadata}"'
    return HTTPException(
        status_code=401,
        detail=exc.detail,
        headers={**(exc.headers or {}), "WWW-Authenticate": widened},
    )


@router.post("/mcp")
def mcp(
    message: JsonRpcRequest,
    principal: Principal = Depends(principal_from_request),
) -> Response:
    """The door. One JSON-RPC message in, one answer or a 202 out.

    `def`, not `async def`, like every endpoint here: `broker.call` is synchronous end to
    end and an `async` endpoint calling it would block the event loop — the failure that
    is not a slow request but the whole server stopping under load while every individual
    piece looks fine. `tests/test_api.py` walks the route table for this.

    Authentication is `principal_from_request`, unchanged and deliberately not a door of
    its own. The machine half of it has existed since step 020, the tenant binds to the
    request's scope in the one place every route gets it, and **HTTP structurally cannot
    produce a `system` principal** — which is the property `access/tokens.py` was written
    around and which this route inherits rather than re-earns. The 020 tripwire family
    has a sibling asserting it for exactly this door.
    """
    # **Before dispatch, so the handshake itself is refused.** A person's sign-in token
    # is not a credential for this endpoint (decision 1), and checking it per method
    # would let `initialize` succeed and `tools/list` fail — a client that connects and
    # then breaks, which is the confusing half of the failure rather than the honest one.
    # `door.list_tools` and `door.call_tool` check it again, and that is not belt and
    # braces: the tier is the boundary if anything else ever calls it, and this is the
    # endpoint saying who may knock. `tools.vet_tool` keeps its own guard beside
    # `Connector.validate` for the same reason.
    door.require_machine(principal)

    method = message.method
    params = message.params or {}

    # A notification is answered with 202 and no body — the specification says so, and
    # `HttpTransport` on the client side of this repository asserts exactly that. Handled
    # before dispatch because there is nothing to dispatch: the two we receive
    # (`notifications/initialized`, `notifications/cancelled`) require no work from a
    # stateless server, and one we do not recognise is still a message that wants no
    # answer.
    if message.id is None:
        if not method.startswith("notifications/"):
            log.info("mcp door: ignoring a message with no id: %s", method)
        return Response(status_code=202)

    if method == "initialize":
        return _result(message.id, _initialize(params))

    if method == "ping":
        # An empty result is the whole of it. Cheap on purpose: this is what a client
        # uses to find out whether the endpoint is alive, and it costs no storage read.
        return _result(message.id, {})

    if method == "tools/list":
        # A `cursor` parameter is ignored rather than refused. This server never issues a
        # `nextCursor`, so a client sending one is echoing something it did not get from
        # us; the list is complete in one page and answering it completely is the honest
        # response to a confused request.
        return _result(message.id, {"tools": door.list_tools(principal)})

    if method == "tools/call":
        return _call(message.id, principal, params)

    return _error(
        message.id,
        METHOD_NOT_FOUND,
        f"this server implements initialize, ping, tools/list and tools/call. "
        f"'{_short(method)}' is not one of them.",
    )


def _initialize(params: dict) -> dict:
    """The handshake answer.

    `capabilities` advertises tools and nothing else, with no `listChanged`: this server
    sends no notifications, and claiming a capability it does not have would leave a
    client waiting for an event that is never coming.
    """
    asked = params.get("protocolVersion")
    return {
        "protocolVersion": asked if asked in SUPPORTED_PROTOCOL_VERSIONS else LATEST_PROTOCOL_VERSION,
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "carnet", "version": __version__},
    }


def _call(message_id, principal: Principal, params: dict) -> JSONResponse:
    """`tools/call` — one brokered call, and the mapping of its outcome onto MCP.

    The mapping is the part worth reading. A brokered result is a dict the model would
    have received, and MCP's `isError` means *the tool did not do what was asked*, which
    is exactly what a broker denial and a failed tool both are from the caller's side. So
    both become a result with `isError: true` rather than a JSON-RPC error, and the
    calling agent gets the same sentence a model would have — which is the whole of
    decision 4's "no new enforcement path", visible at the wire.
    """
    name = params.get("name")
    if not isinstance(name, str) or not name:
        return _error(message_id, INVALID_PARAMS, "tools/call needs a 'name'.")

    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        return _error(message_id, INVALID_PARAMS, "'arguments' must be an object.")

    # **Bounded before anything is recorded**, because the broker writes these arguments
    # to an append-only table and the per-token ceiling does not reach this far: a denied
    # call spends no budget by design, and would still write its row. See
    # `config.MCP_MAX_CALL_BYTES`.
    #
    # Measured against the serialized form for `_bound_response`'s reason: that, not the
    # Python object, is what crosses the wire and what lands in a column.
    size = len(json.dumps(arguments, default=str).encode("utf-8"))
    if size > config.MCP_MAX_CALL_BYTES:
        return _error(
            message_id,
            INVALID_PARAMS,
            f"the arguments for '{_short(name)}' are {size} bytes, and the limit is "
            f"{config.MCP_MAX_CALL_BYTES}. Nothing was called. Send less — a tool call "
            "this large is a document, and a document belongs behind a reference the "
            "tool can fetch.",
        )

    # The acting-for identity, off `_meta`, **bounded before anything reads it** — it
    # rides beside the arguments the cap above measures, so without its own bound it
    # would be this door's third unmetered write. What the object *means* is not this
    # module's business: the door and `access/acting.py` decide that, and they see the
    # value only once it has fit through here. `_meta` that is absent, null, empty, or
    # not an object all mean the same thing — no acting-for — because the SDK sends
    # `"_meta": {}` on a perfectly plain call.
    meta = params.get("_meta")
    acting_raw = meta.get(ACTING_FOR_META_KEY) if isinstance(meta, dict) else None

    # **The third bound on what a caller may write into the log, beside the two sizes.**
    # A `\ud800` — legal JSON syntax, and what any file read with
    # `errors="surrogateescape"` produces — is a value Postgres refuses in the columns
    # this call is about to land in. Driven against a real database it *executed*: the
    # vendor was dialled and paid, and the audit insert then failed and was diverted to
    # the degraded-mode file, leaving a gap a caller could open at will. Refused here,
    # before anything is dialled, so an unwritable call costs a sentence rather than a
    # row — `MCP_MAX_CALL_BYTES`' own argument, one property over.
    #
    # `door.unstorable_call` checks the **recorded** form, so an argument the vetting
    # redacts stays free to hold anything: it is a digest by the time it reaches a
    # column, and a coding agent's prompt legitimately carries undecodable bytes.
    unstorable = door.unstorable_call(principal, name, arguments, acting_raw)
    if unstorable is not None:
        return _error(message_id, INVALID_PARAMS, f"{unstorable} Nothing was called.")
    if acting_raw is not None:
        size = len(json.dumps(acting_raw, default=str).encode("utf-8"))
        if size > config.MCP_MAX_ACTING_FOR_BYTES:
            return _error(
                message_id,
                INVALID_PARAMS,
                f"the acting-for identity on '{_short(name)}' is {size} bytes, and "
                f"the limit is {config.MCP_MAX_ACTING_FOR_BYTES}. Nothing was called. "
                "A forwarded IdP token fits well inside this; anything larger is not "
                "an identity.",
            )

    # Minted here so it can be handed back: the door writes the audit row under it,
    # and the result below names it. See `CALL_ID_META_KEY`.
    call_id = door.new_call_id()
    try:
        result = door.call_tool(
            principal, name, arguments, acting_for_raw=acting_raw, call_id=call_id
        )
    except door.DoorRefused as exc:
        return _error(message_id, INVALID_PARAMS, str(exc))
    except door.ToolUnavailable as exc:
        return _error(message_id, INTERNAL_ERROR, str(exc))

    return _result(message_id, _as_content(result, call_id))


def _as_content(result: dict, call_id: str | None = None) -> dict:
    """A brokered result, in the shape MCP returns tool output.

    Both halves are sent, and neither is redundant. `structuredContent` is what a client
    that understands it should read; the text block is the same document serialized, for
    the many clients that only render content blocks. That is the mirror image of
    `client.normalize` on the other side of this repository, which prefers
    `structuredContent` and falls back to parsing text — so our own client reading our
    own server exercises the preferred path, and a plainer client still gets everything.
    """
    failed = isinstance(result, dict) and "error" in result
    content = {
        "content": [{"type": "text", "text": json.dumps(result, default=str)}],
        "structuredContent": result,
        "isError": failed,
    }
    if call_id:
        content["_meta"] = {CALL_ID_META_KEY: call_id}
    return content
