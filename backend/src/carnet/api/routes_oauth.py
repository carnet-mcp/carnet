"""The door as an OAuth resource server — the HTTP half. Step 083.

Six routes. **Four carry no principal**, and every one of them is in `deps.OPEN_SURFACE`
with its reason; the other two carry the person's own bearer:

    GET  /.well-known/oauth-protected-resource[/{path}]   RFC 9728    open
    GET  /.well-known/oauth-authorization-server          RFC 8414    open
    POST /oauth/register                                  RFC 7591    open
    POST /oauth/token                                     RFC 6749    open — the code and
                                                                      its verifier are
                                                                      the credential
    GET  /oauth/clients/{client_id}                       the consent page's read
    POST /oauth/consent                                   the person's decision

What a request *means* is `access/oauth_server.py`'s; this file is HTTP shape. Two
shapes are the RFCs' rather than this API's, and both are deliberate departures from
`api/errors.py`'s `detail`: an error is `{"error", "error_description"}` with the RFC's
status (the SDK parses it), and the token request is `application/x-www-form-urlencoded`
(RFC 6749 §4.1.3 — every client sends a form). JSON is accepted there too, because a
client that sends one is not wrong in any way that matters.

`GET /oauth/authorize` is **not here**. It is the SPA's route: the person signs in
behind the app's gate with the identity provider they already have, and the page then
reads `/oauth/clients/{id}` and posts to `/oauth/consent` with the session it acquired.
The metadata names it at the origin, where the front door's fallback serves the app.
"""

import json
import logging
from urllib.parse import parse_qsl

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..access import oauth_server
from ..core import Principal
from .deps import principal_from_request

log = logging.getLogger(__name__)

router = APIRouter(tags=["oauth"])

# The token request is small by construction — a code, a verifier, two identifiers. A
# form larger than this is not one.
MAX_TOKEN_REQUEST_BYTES = 8192

# **And the same for a registration, which is the one unauthenticated *write* this API
# has.** The row it produces is bounded — ten URIs, a short name, a small object — but
# until the testing pass the *request* was not, so a stranger's script could post a
# hundred megabytes of JSON and have it parsed into memory before a single bound was
# consulted. That is the door's own `MCP_MAX_CALL_BYTES` argument at a new address:
# what arrives unauthenticated is bounded before anything reads it. 32 KiB is what a
# legal registration can reach — ten redirect URIs of 2 KiB is 20 KiB of it — with room
# for the JSON around them, so the bound refuses nothing the RFC permits.
MAX_REGISTRATION_BYTES = 32768


def _document(body: dict) -> JSONResponse:
    # `no-store`: both documents are derived from configuration and a client that
    # cached one across a `PUBLIC_ORIGIN` change would be sent to the wrong place.
    return JSONResponse(body, headers={"Cache-Control": "no-store"})


@router.get("/.well-known/oauth-protected-resource")
@router.get("/.well-known/oauth-protected-resource/{rest:path}")
def protected_resource(rest: str = "") -> JSONResponse:
    """RFC 9728. No auth and no storage read: a client holding nothing reads this first.

    The path form (`…/api/mcp`) is what the MCP specification has a client try first,
    built from the resource's own path; the bare form is its fallback. Both answer the
    same document. A suffix that names no resource of ours is a 404, so a client
    probing for some other resource on this host is told there is none.
    """
    if not oauth_server.resource_path_matches(rest):
        return JSONResponse(
            {"error": "not_found", "error_description": "no such protected resource"},
            status_code=404,
        )
    return _document(oauth_server.protected_resource_metadata())


@router.get("/.well-known/oauth-authorization-server")
def authorization_server() -> JSONResponse:
    """RFC 8414. No auth and no storage read, for the reason above."""
    return _document(oauth_server.authorization_server_metadata())


async def _registration_request(request: Request) -> dict:
    """The registration body, bounded before it is parsed, in the RFC's error shape.

    A dependency rather than `metadata: dict = Body(...)` for two reasons, and neither
    is style. The body is read here so `MAX_REGISTRATION_BYTES` can refuse a large one
    without FastAPI having already materialised it. And a body that is not a JSON object
    now answers `invalid_client_metadata` — RFC 7591 §3.2.2's shape, which is what an
    MCP client parses — rather than FastAPI's 422 with a `detail` list, which is a
    shape no OAuth client has ever read.
    """
    raw = await request.body()
    if len(raw) > MAX_REGISTRATION_BYTES:
        raise oauth_server.OAuthError(
            "invalid_client_metadata",
            f"a client registration is at most {MAX_REGISTRATION_BYTES} bytes. Nothing "
            "was registered.",
        )
    try:
        parsed = json.loads(raw or b"")
    except ValueError as exc:
        raise oauth_server.OAuthError(
            "invalid_client_metadata", "the registration is not JSON."
        ) from exc
    if not isinstance(parsed, dict):
        raise oauth_server.OAuthError(
            "invalid_client_metadata", "the registration is a JSON object."
        )
    return parsed


@router.post("/oauth/register", status_code=201)
def register(metadata: dict = Depends(_registration_request)) -> JSONResponse:
    """RFC 7591. The one unauthenticated write in this API, bounded at both layers.

    201 with the registration as recorded, which is the RFC's shape and the one the
    SDK stores. No secret is in the response because none exists.
    """
    return JSONResponse(oauth_server.register_client(metadata), status_code=201)


class ClientDescription(BaseModel):
    client_id: str
    client_name: str
    client_uri: str
    redirect_uris: list[str]


@router.get("/oauth/clients/{client_id}", response_model=ClientDescription)
def describe_client(
    client_id: str, principal: Principal = Depends(principal_from_request)
):
    """What the consent page shows before the person decides.

    Behind a principal — the page has one, and a registration is not a public
    directory. The redirect list is returned so the page can refuse to send the browser
    anywhere a query string chose, on the same comparison the server makes at consent.
    """
    return oauth_server.describe_client(client_id)


class Consent(BaseModel):
    """The authorize request's parameters, carried through the page, plus the decision."""

    # Bounded, generously, because a bound nobody reaches still keeps an authenticated
    # write from being unbounded. `state` is the only one a client chooses freely; the
    # rest are compared against something that is already short.
    client_id: str = Field(max_length=200)
    redirect_uri: str = Field(max_length=2048)
    approve: bool
    state: str | None = Field(default=None, max_length=2048)
    response_type: str | None = Field(default=None, max_length=64)
    code_challenge: str | None = Field(default=None, max_length=256)
    code_challenge_method: str | None = Field(default=None, max_length=32)
    resource: str | None = Field(default=None, max_length=2048)
    scope: str | None = Field(default=None, max_length=1024)
    token_name: str | None = Field(default=None, max_length=200)


class Redirect(BaseModel):
    redirect_to: str


@router.post("/oauth/consent", response_model=Redirect)
def consent(body: Consent, principal: Principal = Depends(principal_from_request)):
    """The person's decision. Answers with where the browser goes next, always a
    registered redirect URI — or a 400 that names why nothing is redirected."""
    return Redirect(redirect_to=oauth_server.consent(principal, body.model_dump()))


async def _token_request(request: Request) -> dict:
    """The token request's parameters, from a form or from JSON.

    `async` because a body is read on the event loop; the endpoint itself stays `def`
    like every other here (`test_every_endpoint_is_sync`), so the exchange — which
    touches storage — runs in the threadpool as every storage-touching route does.
    """
    raw = await request.body()
    if len(raw) > MAX_TOKEN_REQUEST_BYTES:
        raise oauth_server.OAuthError(
            "invalid_request",
            f"a token request is at most {MAX_TOKEN_REQUEST_BYTES} bytes.",
        )
    content_type = (request.headers.get("content-type") or "").split(";")[0].strip()
    if content_type == "application/json":
        try:
            parsed = json.loads(raw or b"{}")
        except ValueError as exc:
            raise oauth_server.OAuthError("invalid_request", "the body is not JSON.") from exc
        if not isinstance(parsed, dict):
            raise oauth_server.OAuthError("invalid_request", "the body is a JSON object.")
        return {k: v for k, v in parsed.items() if isinstance(v, str)}
    return dict(parse_qsl(raw.decode("utf-8", errors="replace"), keep_blank_values=True))


@router.post("/oauth/token")
def token(form: dict = Depends(_token_request)) -> JSONResponse:
    """RFC 6749 §4.1.3. The code and its PKCE verifier are the credential.

    `Cache-Control: no-store` and `Pragma: no-cache` are §5.1's requirement on a
    response carrying a token; the token in it is the only copy of its secret.
    """
    answer = oauth_server.exchange(form)
    return JSONResponse(
        answer, headers={"Cache-Control": "no-store", "Pragma": "no-cache"}
    )
