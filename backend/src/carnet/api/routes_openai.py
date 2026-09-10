"""The OpenAI-compatible surface: a company's own coding agent, brokered by the door.

Step 108. The case is precise: an enterprise built a coding agent that calls Azure AI
Foundry's OpenAI-compatible endpoint, every engineer runs it on their own machine, and
the company wants per-engineer usage, per-engineer limits, and the Azure key off every
laptop — with the engineer changing nothing. The agent's author changes two values,
once:

    client = AzureOpenAI(azure_endpoint="https://carnet.acme.com", api_key=token)

and every `resp.choices[0].message.content`, every stream loop and every tool-call
delta in the agent is untouched, because what comes back is the vendor's answer, byte
for byte. That sentence is the whole of what this module has to protect, and it is why
nothing here parses a response for the caller.

## It goes through the broker, and the broker learned to stream for it

The one invariant the layout has protected since the first commit: **nothing outside
`core/` may call a tool implementation directly.** So a request here becomes a call on a
vetted REST tool — `door.stream_tool`, which runs every door step `/mcp` runs and then
`broker.stream`, which runs every broker step `broker.call` runs — grant, scope, ceiling,
credential, audit — before the first byte goes upstream. What this module adds is a
translation on each side of that call: the request's shape in, OpenAI's error dialect
out. It does not decide anything the door and the broker do not already decide.

## Two dialects on the wire, because the case is Azure

`OpenAI(base_url=…)` posts `/v1/chat/completions` with `Authorization: Bearer` and the
model in the body. `AzureOpenAI(azure_endpoint=…)` posts
`/openai/deployments/{deployment}/chat/completions?api-version=…` with an `api-key`
header and no model in the body. Both are accepted; the token is taken from either
header; the deployment is the path segment or `body.model`; `api-version` is forwarded
as the query carried it, never pinned here. Telling Azure users to reconfigure the plain
client with a default query was rejected in the plan as the kind of "small" change that
is not small in a company with forty call sites.

## Which tool, decided by what a tool *does*

A token reaches whatever tools its grants carry. Among them, the chat-completions tool is
the REST tool whose binding path ends in `/chat/completions`, and the embeddings tool the
one ending in `/embeddings` — the recipe vets them so, and a vetter naming them anything
else changes nothing here, because the role is a fact about the request the tool makes
rather than about its name. Where a token reaches more than one such tool (two
connectors, two regions), the first whose scope admits the deployment is the one called:
the union rule `door._adjudicate` applies within one tool, applied across the tools that
share a role, in name order so attribution is deterministic.

## What the caller's SDK sees, and never sees

Every refusal is `{"error": {"message", "type", "code"}}` with the status an SDK expects
for it, so `openai.PermissionDeniedError` carries Carnet's own sentence instead of a parse
failure hiding it. A vendor's own refusal — a 429, a content-filter 400 — is relayed whole
with its `Retry-After`, because the SDK's backoff and its error classes work only on the
vendor's body. A vendor's refusal of *Carnet's* credential is a 502 that names the
connector and quotes nothing, because that body tends to quote the key.

Every route is sync `def`, like every route here: one open stream is one thread for the
life of the completion, which is what `CARNET_THREADS` sizes.
"""

import json
import logging
from typing import Any, AsyncIterator, Generator, Iterator

import anyio
from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from .. import config, door, tools
from ..access.users import AccessDenied
from ..core import Principal
from ..storage import SPEND_REFUSAL_MARKER
from .deps import principal_from_request

log = logging.getLogger(__name__)

router = APIRouter(tags=["openai"])

# What a role looks like on the wire. The recipe's bindings end in these; the route
# recognises the tool by them rather than by a name a vetter may have changed.
CHAT_SUFFIX = "/chat/completions"
EMBEDDINGS_SUFFIX = "/embeddings"

# The argument that names the deployment on every binding this surface calls: the path
# placeholder on the Azure shape and the body key on OpenAI's, and the resource argument
# the scope is written against (`azure.deployment`, `openai.model`).
DEPLOYMENT_ARG = "model"

# Never on the audit row, whatever the tool's own redaction says. Decision 10: a prompt
# on an append-only table is not a mis-vetting anybody can undo. The broker unions this
# with the tool's `redact_args`; it cannot narrow them.
NEVER_RECORDED = frozenset({"messages", "input", "tools", "functions", "prediction"})

# The query parameter Azure requires and this surface forwards untouched (S24). Carried
# as a tool argument under its own name; the recipe's binding maps it into the query.
API_VERSION = "api-version"


class ModelRefused(Exception):
    """A refusal in OpenAI's error dialect. `install` renders it.

    One class for every refusal this surface decides itself, so the route table has one
    handler and the shape cannot drift between routes. `headers` is for the one refusal
    that needs one — a relayed 429's `Retry-After`.
    """

    def __init__(
        self, status: int, type_: str, code: str, message: str, headers: dict | None = None
    ):
        super().__init__(message)
        self.status = status
        self.type = type_
        self.code = code
        self.message = message
        self.headers = headers or {}

    def body(self) -> dict:
        return {
            "error": {
                "message": self.message,
                "type": self.type,
                "code": self.code,
                "param": None,
            }
        }


def install(app) -> None:
    """Attach the dialect's handler. Called once, from the app factory, beside `errors`."""

    @app.exception_handler(ModelRefused)
    def _refused(_request: Request, exc: ModelRefused):
        return JSONResponse(exc.body(), status_code=exc.status, headers=exc.headers)


# --- authentication: either header, one door ---------------------------------------


def model_principal(
    authorization: str | None = Header(default=None),
    api_key: str | None = Header(default=None, alias="api-key"),
) -> Principal:
    """`principal_from_request`, reached from either header, refused in the dialect.

    The Azure SDK sends `api-key: <key>`; the OpenAI SDK sends `Authorization: Bearer
    <key>`. Both carry the same `art_` token and both land on the one dependency every
    other route uses — this synthesises the bearer header from `api-key` and calls it,
    so the machine door's three refusals, the tenant binding and the offboarding checks
    are inherited rather than copied. `Authorization` wins when both are present, because
    it is the one a proxy in the path is likelier to have touched deliberately.

    The dialect's mapping of those refusals: a token that does not resolve is 401
    `invalid_api_key`, a person or tenant that is disabled is 403 `account_deactivated`,
    and a person's own sign-in token — a JWT, which `door.require_machine` refuses — is
    401 `invalid_api_key` with the door's sentence, because to an SDK it is a key that
    does not work and to its author the sentence says why.
    """
    header = authorization
    if not header and api_key:
        header = f"Bearer {api_key.strip()}"
    try:
        principal = principal_from_request(authorization=header)
        door.require_machine(principal)
    except HTTPException as exc:
        status = 403 if exc.status_code == 403 else 401
        raise ModelRefused(
            status,
            "permission_error" if status == 403 else "authentication_error",
            "account_deactivated" if status == 403 else "invalid_api_key",
            str(exc.detail),
        ) from exc
    except AccessDenied as exc:
        raise ModelRefused(401, "authentication_error", "invalid_api_key", str(exc)) from exc
    return principal


# --- the tool, decided by its role -------------------------------------------------


def _tools_with_role(principal: Principal, suffix: str) -> list:
    """The granted REST tools whose binding path ends in `suffix`, in name order."""
    granted = sorted(door._granted_tool_names(door._granted_agents(principal)))
    described = tools.describe_all(granted, principal.tenant_id)
    return [
        described[name]
        for name in granted
        if described[name] is not None
        and described[name].binding
        and str(described[name].binding.get("path", "")).endswith(suffix)
    ]


def _choose(principal: Principal, suffix: str, deployment: str, what: str):
    """The tool this call goes to: the first with the role whose scope admits the
    deployment, by `door.simulate` — which executes nothing and writes nothing.

    **When none admits, the first candidate is returned anyway**, and the call goes to
    the door, whose broker refuses it with the same sentence `simulate` gave and
    **writes the denial row** (S12: *denial recorded*). A refusal decided here would
    be a refusal the log never saw, on a surface whose whole claim is the log. Only
    the case with nothing to send the call to is decided here, because there is no
    tool for the door to refuse under.
    """
    candidates = _tools_with_role(principal, suffix)
    if not candidates:
        raise ModelRefused(
            403,
            "permission_error",
            "insufficient_scope",
            f"this token is granted no {what} tool. An administrator registers a model "
            "connector from a recipe (`carnet --add-connector <name> --from-recipe "
            "azure-openai`), puts its tools in a permission list and shares that list "
            "with you.",
        )
    for tool in candidates:
        verdict = door.simulate(principal, tool.name, {DEPLOYMENT_ARG: deployment})
        if verdict["verdict"] == "allowed":
            return tool
    return candidates[0]


# --- the request --------------------------------------------------------------------


def _check_size(request: Request, payload) -> None:
    """413 in the dialect, before anything is dialled or charged (S9)."""
    cap = config.MODEL_MAX_REQUEST_BYTES
    declared = request.headers.get("content-length")
    size = int(declared) if declared and declared.isdigit() else None
    if size is None:
        size = len(json.dumps(payload, default=str).encode("utf-8"))
    if size > cap:
        raise ModelRefused(
            413,
            "invalid_request_error",
            "request_too_large",
            f"this request is {size} bytes, and the limit is {cap} "
            "(CARNET_MODEL_MAX_REQUEST_BYTES). Nothing was called. A prompt this large "
            "is a document; send less of it, or an operator raises the limit.",
        )


def _object(payload) -> dict:
    if not isinstance(payload, dict):
        raise ModelRefused(
            400, "invalid_request_error", "invalid_body",
            "the request body must be a JSON object.",
        )
    return payload


def _deployment(payload: dict, from_path: str | None) -> str:
    """The deployment: the Azure path segment, or `body.model` on OpenAI's shape."""
    if from_path:
        return from_path
    model = payload.get(DEPLOYMENT_ARG)
    if not isinstance(model, str) or not model.strip():
        raise ModelRefused(
            400, "invalid_request_error", "missing_model",
            "'model' is required: the deployment this call goes to.",
        )
    return model.strip()


def _arguments(payload: dict, deployment: str, request: Request) -> dict:
    """The tool's arguments: the body as sent, the deployment under `model`, and the
    `api-version` the SDK chose when it chose one. Nothing else is added or removed
    here — the tool's own schema decides what it accepts, and an argument outside it is
    refused by the tool with a sentence naming it, never silently dropped."""
    arguments = dict(payload)
    arguments[DEPLOYMENT_ARG] = deployment
    version = request.query_params.get(API_VERSION)
    if version:
        arguments[API_VERSION] = version
    return arguments


def _wants_stream(payload: dict) -> bool:
    return payload.get("stream") is True


def _inject_usage(arguments: dict) -> None:
    """`stream_options.include_usage`, on every streamed request that did not set it.

    Without it Azure and OpenAI omit the usage object from the stream entirely and every
    streamed call would meter as zero. Invisible to the client: the extra final chunk it
    produces is one the SDK already knows how to skip. A client that set its own
    `stream_options` keeps them, with this one key added.
    """
    options = arguments.get("stream_options")
    if not isinstance(options, dict):
        options = {}
    if options.get("include_usage") is not True:
        arguments["stream_options"] = {**options, "include_usage": True}


# --- the call, and the mapping of its outcome ------------------------------------


def _refusal_from(error: dict) -> ModelRefused:
    """A broker refusal — `{"error": ..., "denied_by": "broker"}` — in the dialect.

    The sentence is always Carnet's own, so `--simulate`, the door log and the SDK's
    exception say the same thing. The dialect's `code` is read off the sentence's
    markers rather than off a class, because the broker returns data, not exceptions,
    and the markers are the fixed strings the two ceilings already carry for exactly
    this kind of reader.
    """
    message = str(error.get("error") or "")
    if SPEND_REFUSAL_MARKER in message or door.CEILING_REFUSAL_MARKER in message:
        return ModelRefused(429, "insufficient_quota", "daily_limit_reached", message)
    if "is unavailable:" in message:
        # Step 3: the connector's credential could not be resolved. Nothing was dialled.
        return ModelRefused(502, "api_error", "upstream_credential_unavailable", message)
    return ModelRefused(403, "permission_error", "insufficient_scope", message)


def _before_first_byte(streamed) -> ModelRefused:
    """A call that failed before the vendor answered a byte, in the dialect.

    Two of these are the caller's: an argument the vetted schema does not declare, and
    a value that cannot travel where the binding sends it. The REST tool refuses both
    with a sentence naming the argument, and here they are 400s — the SDK raises
    `BadRequestError` with the sentence, which is what its author needs to see.
    """
    message = str((streamed.error or {}).get("error") or "the call failed")
    if "does not accept" in message or "argument '" in message:
        return ModelRefused(400, "invalid_request_error", "unknown_parameter", message)
    if "did not answer in time" in message or "did not accept a connection in time" in message:
        return ModelRefused(504, "api_error", "upstream_unavailable", message)
    return ModelRefused(502, "api_error", "upstream_unavailable", message)


def _brokered(principal: Principal, tool, arguments: dict):
    """`door.stream_tool`, with the door's two exceptions in the dialect."""
    try:
        return door.stream_tool(
            principal, tool.name, arguments, call_id=door.new_call_id(), redact=NEVER_RECORDED
        )
    except door.DoorRefused as exc:
        raise ModelRefused(403, "permission_error", "insufficient_scope", str(exc)) from exc
    except door.ToolUnavailable as exc:
        raise ModelRefused(502, "api_error", "upstream_unavailable", str(exc)) from exc


def _error_event(message: str, code: str) -> bytes:
    """One SSE event carrying an error, the shape the SDK raises on, then `[DONE]`."""
    body = {"error": {"message": message, "type": "api_error", "code": code, "param": None}}
    return f"data: {json.dumps(body)}\n\ndata: [DONE]\n\n".encode("utf-8")


def _relay(streamed, *, stream: bool) -> Response:
    """The vendor's answer, forwarded — or the refusal that stands in for it.

    Read in this order, because each is settled before the next: a refusal by the door
    or the broker (nothing dialled); a failure before the first byte; the vendor refusing
    Carnet's credential (status travels, body does not); a vendor refusal relayed whole;
    and then the answer, streamed chunk for chunk or buffered whole, with the audit row
    written by the broker when the last byte has passed.
    """
    if streamed.refused:
        raise _refusal_from(streamed.error)
    if streamed.status is None:
        raise _before_first_byte(streamed)
    if not streamed.relay_body:
        # 401/403 from the vendor: Carnet's key, not the caller's. Names the connector,
        # quotes nothing. The row says `error` with the same sentence.
        for _ in streamed:
            pass
        raise ModelRefused(
            502, "api_error", "upstream_credential_refused",
            str(streamed.error.get("error")),
        )

    media_type = streamed.headers.get("Content-Type") or "application/json"
    relayed = {k: v for k, v in streamed.headers.items() if k == "Retry-After"}

    if stream and 200 <= streamed.status < 300:
        return StreamingResponse(
            _pulled(_forward(streamed)), status_code=streamed.status,
            media_type=media_type, headers={**relayed, "Cache-Control": "no-store"},
        )

    body = b"".join(streamed)
    if streamed.outcome == "oversize":
        raise ModelRefused(
            502, "api_error", "response_too_large",
            f"the answer from the model passed this tool's size limit "
            f"({streamed.error['limit']} bytes) and was discarded. An administrator "
            "raises the limit on the vetted tool.",
        )
    if streamed.outcome in ("error", "unknown") and 200 <= streamed.status < 300:
        raise ModelRefused(
            502, "api_error", "upstream_unavailable", str(streamed.error.get("error"))
        )
    return Response(content=body, status_code=streamed.status, media_type=media_type,
                    headers={**relayed, "Cache-Control": "no-store"})


def _forward(streamed) -> Iterator[bytes]:
    """The stream, chunk for chunk, unmodified — and what to say when it ends badly.

    Past the byte cap the broker has closed the upstream and stopped; the client is
    owed a terminal event, so it gets an error event and `[DONE]` (S7). A break
    mid-answer gets the same treatment with the broker's sentence. A client that
    disconnects closes this generator, and `close()` on the `Streamed` is what turns
    that into a closed upstream and an `aborted` row — done in `finally` rather than
    left to the garbage collector, because a completion Azure keeps generating for a
    listener that has gone is money.
    """
    try:
        for chunk in streamed:
            yield chunk
        if streamed.outcome == "oversize":
            yield _error_event(
                "the answer passed this tool's size limit and was cut off; an "
                "administrator raises the limit on the vetted tool.",
                "response_too_large",
            )
        elif streamed.outcome in ("error", "unknown"):
            yield _error_event(str(streamed.error.get("error")), "upstream_unavailable")
    finally:
        streamed.close()


class _Exhausted(Exception):
    """`StopIteration` cannot cross a thread boundary; this can."""


def _next_or_exhausted(iterator: Iterator[bytes]) -> bytes:
    try:
        return next(iterator)
    except StopIteration as exc:
        raise _Exhausted from exc


async def _pulled(iterator: Generator[bytes, None, None]) -> AsyncIterator[bytes]:
    """The sync stream, pulled from the threadpool, **and closed when the client goes**.

    Starlette's own `iterate_in_threadpool` does the first half and not the second: when
    the client disconnects it stops pulling and leaves the sync generator suspended at
    its `yield`, to be finalised whenever the garbage collector gets to it — which the
    e2e measured at *process exit*, twenty-six seconds after the engineer's Ctrl-C,
    with the upstream request open and Azure generating the whole time. So this pulls
    each chunk with `abandon_on_cancel=False` (the default): a cancellation is delivered
    only once the chunk in hand has been read, so the generator is never closed while it
    is executing, and `finally` then closes it — under a shielded scope, because after a
    cancellation an unshielded await in `finally` is cancelled again. Closing the sync
    generator is what runs `_forward`'s own `finally`, which closes the `Streamed`, which
    closes the upstream and writes the `aborted` row. Within one chunk, as the plan says.
    """
    try:
        while True:
            try:
                chunk = await anyio.to_thread.run_sync(_next_or_exhausted, iterator)
            except _Exhausted:
                return
            yield chunk
    finally:
        with anyio.CancelScope(shield=True):
            await anyio.to_thread.run_sync(iterator.close)


def _complete(request: Request, principal: Principal, payload, suffix: str, what: str,
              deployment_from_path: str | None) -> Response:
    """One model call, either shape, either role."""
    payload = _object(payload)
    _check_size(request, payload)
    deployment = _deployment(payload, deployment_from_path)
    arguments = _arguments(payload, deployment, request)
    tool = _choose(principal, suffix, deployment, what)

    # **What will be written down has to be writable**, and the door owns that rule —
    # `door.unstorable_call` asks the storage layer what a column can hold, checks the
    # *recorded* form, and answers for `/mcp` in its dialect and for this surface in
    # OpenAI's. `NEVER_RECORDED` is passed because it is what this surface hands
    # `stream_tool`: the prompt is a digest by the time it reaches a column, so a file
    # with undecodable bytes stays sendable. Everything else — the deployment name, the
    # temperature, the caller's `user` string — is stored as sent, and Postgres refuses
    # a lone surrogate, a NUL or a `NaN` in jsonb outright. Step 108's edge pass watched
    # such a call execute, get paid for, and then lose its audit row to the
    # degraded-mode file.
    unstorable = door.unstorable_call(principal, tool.name, arguments,
                                      extra_redact=NEVER_RECORDED)
    if unstorable is not None:
        raise ModelRefused(
            400, "invalid_request_error", "unencodable_text",
            f"{unstorable} Every call is recorded, and this value cannot be written "
            "down. The prompt itself is exempt — it is hashed rather than stored, so a "
            "file with undecodable bytes can still be sent.",
        )

    stream = _wants_stream(payload)
    if stream:
        _inject_usage(arguments)

    # **The row is owed the moment the broker admits the call**, and `Streamed` writes
    # it when its iteration ends — by exhaustion, by the cap, or by `close()`. Every
    # path out of `_relay` that does not iterate is therefore a path that must close,
    # and the guard is here rather than at each of them: the edge pass found three
    # (a vendor that never answered, streamed and not, and an argument the tool would
    # not send) where a call spent its budget, resolved a credential and left the log
    # with nothing. A refusal from the door or the broker arrives already finalised,
    # so this costs it nothing.
    streamed = _brokered(principal, tool, arguments)
    try:
        return _relay(streamed, stream=stream)
    except BaseException:
        streamed.close()
        raise


# --- routes ---------------------------------------------------------------------------


@router.post("/v1/chat/completions")
def chat_completions(
    request: Request,
    payload: Any = Body(default=None),
    principal: Principal = Depends(model_principal),
) -> Response:
    """A chat completion, `OpenAI(base_url=…)`'s shape: model in the body."""
    return _complete(request, principal, payload, CHAT_SUFFIX, "chat completions", None)


@router.post("/openai/deployments/{deployment}/chat/completions")
def azure_chat_completions(
    deployment: str,
    request: Request,
    payload: Any = Body(default=None),
    principal: Principal = Depends(model_principal),
) -> Response:
    """The same, `AzureOpenAI(azure_endpoint=…)`'s shape: deployment in the path."""
    return _complete(request, principal, payload, CHAT_SUFFIX, "chat completions", deployment)


@router.post("/v1/embeddings")
def embeddings(
    request: Request,
    payload: Any = Body(default=None),
    principal: Principal = Depends(model_principal),
) -> Response:
    """An embedding — a coding agent's retrieval. Same binding shape, `input` never
    recorded, `usage.prompt_tokens` the only counter."""
    return _complete(request, principal, payload, EMBEDDINGS_SUFFIX, "embeddings", None)


@router.post("/openai/deployments/{deployment}/embeddings")
def azure_embeddings(
    deployment: str,
    request: Request,
    payload: Any = Body(default=None),
    principal: Principal = Depends(model_principal),
) -> Response:
    return _complete(request, principal, payload, EMBEDDINGS_SUFFIX, "embeddings", deployment)


def _models(principal: Principal) -> dict:
    """What this token may reach, in OpenAI's `models` shape.

    SDKs and agent frameworks call this on start-up. The answer is the deployments this
    token's scope admits — `reach` in OpenAI's shape — which is not the deployments that
    exist: an admin who scoped `write: ["*"]` sees the wildcard, because Carnet does not
    enumerate Foundry. The SDK tolerates it; a person reading it might not expect it, and
    the plan says so under known limits. Not a broker call, so no audit row, exactly as
    `tools/list` writes none.
    """
    seen: dict = {}
    reach = door.reach(principal)
    roles = {t.name: t for t in _tools_with_role(principal, CHAT_SUFFIX)}
    roles.update({t.name: t for t in _tools_with_role(principal, EMBEDDINGS_SUFFIX)})
    for row in reach["by_tool"]:
        tool = roles.get(row["tool"])
        if tool is None:
            continue
        for grant in row["granted_by"]:
            for patterns in grant["applies"].values():
                for pattern in patterns:
                    seen.setdefault(pattern, tool.connector or "carnet")
    return {
        "object": "list",
        "data": [
            {"id": name, "object": "model", "created": 0, "owned_by": owner}
            for name, owner in sorted(seen.items())
        ],
    }


@router.get("/v1/models")
def models(principal: Principal = Depends(model_principal)) -> dict:
    return _models(principal)


@router.get("/openai/models")
def azure_models(principal: Principal = Depends(model_principal)) -> dict:
    return _models(principal)


# Everything else under the two prefixes: refused with a sentence, in the dialect, so an
# SDK reaching for audio, images, files, fine-tuning, assistants or the legacy
# completions endpoint is told this surface does not offer it rather than shown a route
# table's 404. Each of those is its own decision (plan 108, decision 13).
_NOT_OFFERED = (
    "this surface offers chat completions, embeddings and the models list — the calls a "
    "coding agent makes. '{path}' is not one of them; audio, images, files, fine-tuning, "
    "assistants and the legacy completions endpoint are each a decision not yet taken."
)


# Behind the same credential as the rest of the surface — an unauthenticated caller
# learns nothing about what this prefix offers, and the surface has no open route to
# argue for in `deps.OPEN_SURFACE`. Out of the OpenAPI document: a catch-all is not an
# operation a client is generated against, and five methods on one path would give the
# document five operations with one id. The route table — `docs/CAPABILITIES.md` and
# `test_every_http_route_is_catalogued` — still sees both.


@router.api_route("/v1/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                  include_in_schema=False)
def not_offered(
    rest: str, request: Request, _principal: Principal = Depends(model_principal)
) -> Response:
    raise ModelRefused(404, "invalid_request_error", "not_offered",
                       _NOT_OFFERED.format(path=request.url.path))


@router.api_route("/openai/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                  include_in_schema=False)
def azure_not_offered(
    rest: str, request: Request, _principal: Principal = Depends(model_principal)
) -> Response:
    raise ModelRefused(404, "invalid_request_error", "not_offered",
                       _NOT_OFFERED.format(path=request.url.path))
