"""The door as an OAuth 2.1 authorization and resource server. Step 083.

**This is the other end of `access/oauth.py`.** That module is this deployment acting as
an OAuth *client* toward a vendor — a person clicks Connect, the vendor's token lands in
`connections`. This module is this deployment acting as an OAuth *server* toward an MCP
client — Claude Desktop, Claude.ai, Cursor — that was handed nothing but the door's URL.
The two share two RFC numbers and nothing else, and are kept in two files so that a
reader of either never has to ask which side of the flow a function is on.

## The flow, and what it ends in

    client → GET  /mcp, no token                  401, WWW-Authenticate: Bearer
                                                  resource_metadata="…"    (routes_mcp)
    client → GET  /.well-known/oauth-protected-resource/api/mcp     → `protected_resource_metadata`
    client → GET  /.well-known/oauth-authorization-server           → `authorization_server_metadata`
    client → POST /oauth/register                                   → `register_client`
    client → browser → <origin>/oauth/authorize?…                   the SPA: sign in, consent
    page   → POST /oauth/consent   (the person's bearer)             → `consent`
    browser → redirect_uri?code=…&state=…
    client → POST /oauth/token     code + code_verifier              → `exchange`
    client → POST /mcp  Bearer art_…                                 the door, unchanged

**The access token is an `api_tokens` row** — a *personal* `art_` token minted by
`tokens.mint(acts_as_owner=True)`, exactly as the CLI's `--mint-token --as-owner` and the
tokens page mint one. Nothing downstream changes: `tokens.resolve` reads it,
`door.require_machine` admits it, every call is audited under its id, it is on the
person's tokens page, revocable there, and dead when they are. This module is the
bookkeeping *before* the token exists and nothing here is a credential.

## The decision this re-opens, and the argument that survives it

`access/tokens.py`: *"It does not mint over HTTP."* `exchange` is a mint route. What
keeps 020's refusal intact — narrowed, as 044 narrowed it for `POST /me/tokens`:

1. **Nothing a bearer holder has can reach the mint.** A code is issued only by
   `consent`, which requires a *user* principal — a person's session — and refuses a
   machine before reading anything. A stolen `art_` token cannot obtain a code.
2. **A stolen code is useless.** PKCE `S256` is required; the verifier never left the
   client. The code lives five minutes, is single-use by compare-and-set, and a second
   presentation **revokes the token the first one minted** (RFC 6749 §4.1.2).
3. **The only grant type is `authorization_code`.** `client_credentials` is a
   bearer-shaped mint — the thing 020 refused — and `refresh_token` is a mint of a
   successor for a bearer, which is the same shape. Both are refused here, and
   `tests/test_oauth_server.py` pins it on 020's tripwire pattern, so the next person
   adding a grant type meets a failing test rather than a docstring.
4. **What is minted is bounded by the person.** A personal token holds no grants of its
   own (`grants.share` refuses it as a grantee); its reach is its owner's, capped at
   `user`. Consent cannot widen anything.

## What is taken from Portkey's gateway, and what is not

The shape of the two well-known documents, the `WWW-Authenticate` challenge, DCR with
public clients and PKCE only, and the consent page as the place where the person
decides. Not their token model, not introspection per call against a control plane, and
not a token cache — `door._granted_agents` re-reads grants on every call because *"a
revocation that takes effect in 'up to 30 seconds' is not a revocation."*
"""

import base64
import hashlib
import hmac
import json
import logging
import secrets
import string
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlsplit, urlunsplit

from .. import config, storage
from ..core import Principal
from ..storage import ValueRefused, tenancy
from ..storage.base import (
    OAUTH_CLIENT_MAX_METADATA_BYTES,
    OAUTH_CLIENT_MAX_NAME_LENGTH,
    OAUTH_CLIENT_MAX_REDIRECT_URIS,
    OAUTH_CLIENT_MAX_URI_LENGTH,
    check_name_is_text,
)
from . import tokens
from .users import AccessDenied

log = logging.getLogger(__name__)

# `oc_` and sixteen hex characters, on `api_tokens.id`'s pattern: opaque, minted, never
# derived from anything the registrant sent.
CLIENT_ID_PREFIX = "oc_"
CLIENT_ID_HEX = 16

# Domain separation for the code digest, on `tokens._HASH_DOMAIN`'s pattern.
_CODE_HASH_DOMAIN = b"carnet/oauth-code/v1"
_HASH_SCHEME = "sha256"

# The only grant type, the only challenge method, the only client auth method. Each is
# a decision the module docstring argues; the metadata document advertises exactly
# these and `register_client`/`exchange` refuse anything else.
GRANT_TYPES = ("authorization_code",)
RESPONSE_TYPES = ("code",)
CODE_CHALLENGE_METHODS = ("S256",)
TOKEN_ENDPOINT_AUTH_METHODS = ("none",)

# Grant types a registration may *ask* for without being refused. RFC 7591 lets a
# server replace requested metadata, and the official SDK registers with
# `["authorization_code", "refresh_token"]` by default — refusing that would refuse
# every SDK client. So `refresh_token` is dropped from what is registered, and the
# registration response says so by listing what was. Anything else is refused: a client
# that asks for `client_credentials` is asking for the bearer-shaped mint this server
# does not have, and should learn that at registration rather than at the exchange.
_TOLERATED_GRANT_TYPES = frozenset({"authorization_code", "refresh_token"})

# Redirect URI schemes that are never a client's callback, whatever RFC 8252 says
# about private-use schemes. A page of ours must never send a browser to one.
_REFUSED_SCHEMES = frozenset({"javascript", "data", "file", "blob", "vbscript", "about"})
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]", "::1"})

# How much of `client_uri`, `software_id` and `software_version` is kept. Long enough
# for any real URL, short enough that three of them cannot reach the row's bound.
MAX_METADATA_FIELD_LENGTH = 512

# RFC 7636 §4.1: 43 to 128 characters from the unreserved set — and **the set is part
# of the rule, not decoration**. `S256(verifier)` is defined over ASCII octets, so a
# verifier carrying anything else has no digest to compare: computing one raised
# `UnicodeEncodeError` and turned a malformed token request into a 500, which is a
# refusal wearing an outage's clothes. Found in the testing pass by sending one.
_VERIFIER_MIN, _VERIFIER_MAX = 43, 128
_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")

# base64url of a SHA-256 without padding: exactly 43 characters from this set. Spelled
# out rather than asked of `str.isalnum()`, which is Unicode-aware and answers True for
# `é` and `１` — so a challenge of 43 accented letters passed a check whose docstring
# said base64url, was stored, and could only fail much later at the comparison.
_CHALLENGE_LENGTH = 43
_BASE64URL = frozenset(string.ascii_letters + string.digits + "-_")

# How many numeric suffixes a token name is tried with before giving up. One person
# connecting the same client from a second machine must not be refused; since migration
# 054 a personal token's name is unique per *owner*, so two colleagues no longer collide
# at all and the loop is only ever about one person's own tokens. A hundred of those is
# a tokens page nobody can read anyway.
_NAME_ATTEMPTS = 100

# The actor a replay-triggered revocation is recorded under. `system:` because no
# person and no machine did it: the server noticed a code presented twice.
REPLAY_ACTOR = "system:oauth"


class OAuthError(Exception):
    """An error in the RFCs' own shape: `{"error": …, "error_description": …}`.

    Raised rather than `HTTPException` because the SDK parses the body, and a FastAPI
    `detail` is not the shape it parses. `api/errors.py` renders it.
    """

    def __init__(self, error: str, description: str, *, status: int = 400):
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status


def refuse_unstorable_strings(body, error: str) -> None:
    """Refuse a parsed JSON body holding a string no text column can take. Step 087.

    **The two routes that call this are the two that parse JSON themselves** — the
    registration and token endpoints answer in the RFCs' shape, so they read the body
    with `json.loads` rather than through a Pydantic model, and `json.loads` turns the
    six ASCII bytes `\\ud800` into a lone surrogate: a string Python holds and UTF-8
    cannot encode. Driven against Postgres, one in `client_name` was a **500** out of
    the driver and one in a `redirect_uri` a **503**; one in `code` at the token
    endpoint was a 500 before the code was even looked up, because `digest` encodes
    it. Both routes are unauthenticated, and an outage-shaped answer from an
    unauthenticated route is the exact defect 083's testing pass fixed for a NUL —
    this is the same defect one character over. A NUL is refused by the same walk.

    Every string in every dict and list, so a field added later is covered without
    anybody remembering. `error` is the endpoint's own code, because the SDK reads it.
    """
    stack = [body]
    while stack:
        value = stack.pop()
        if isinstance(value, str):
            if "\x00" in value:
                raise OAuthError(
                    error,
                    "the request contains a NUL byte. No text column can hold one, and "
                    "control characters are not a part of any name or URI this server "
                    "records. Nothing was recorded.",
                )
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                raise OAuthError(
                    error,
                    "the request contains an unpaired surrogate (a `\\ud800`-style "
                    "escape), which no UTF-8 encoder can write. Nothing was recorded.",
                ) from None
        elif isinstance(value, dict):
            stack.extend(value.keys())
            stack.extend(value.values())
        elif isinstance(value, (list, tuple)):
            stack.extend(value)


# --- the documents ---------------------------------------------------------------


def endpoints() -> dict:
    """Every URL the three documents and the 401 challenge name, from one setting.

    `config.public_origin_parts` says why there is no second setting. The issuer is the
    bare origin, so RFC 8414 puts its document at the origin root, which is where the
    three ingresses forward `/.well-known/oauth-*` to the API.
    """
    origin, prefix = config.public_origin_parts()
    return {
        "issuer": origin,
        "resource": f"{origin}{prefix}/mcp",
        "resource_metadata": f"{origin}/.well-known/oauth-protected-resource{prefix}/mcp",
        "authorization_endpoint": f"{origin}/oauth/authorize",
        "token_endpoint": f"{origin}{prefix}/oauth/token",
        "registration_endpoint": f"{origin}{prefix}/oauth/register",
    }


def protected_resource_metadata() -> dict:
    """RFC 9728. What a client that holds nothing reads first."""
    urls = endpoints()
    return {
        "resource": urls["resource"],
        "authorization_servers": [urls["issuer"]],
        "bearer_methods_supported": ["header"],
        "resource_name": "Carnet MCP door",
    }


def authorization_server_metadata() -> dict:
    """RFC 8414. Advertises exactly what `register_client` and `exchange` accept."""
    urls = endpoints()
    return {
        "issuer": urls["issuer"],
        "authorization_endpoint": urls["authorization_endpoint"],
        "token_endpoint": urls["token_endpoint"],
        "registration_endpoint": urls["registration_endpoint"],
        "response_types_supported": list(RESPONSE_TYPES),
        "response_modes_supported": ["query"],
        "grant_types_supported": list(GRANT_TYPES),
        "code_challenge_methods_supported": list(CODE_CHALLENGE_METHODS),
        "token_endpoint_auth_methods_supported": list(TOKEN_ENDPOINT_AUTH_METHODS),
    }


def resource_path_matches(rest: str) -> bool:
    """Whether a `/.well-known/oauth-protected-resource/<rest>` suffix names the door.

    RFC 9728 §3.1: the document for a resource with a path lives at the well-known
    path *plus* that path. An empty suffix is the origin-wide document and also
    answers; anything else is not a resource this deployment has.
    """
    _, prefix = config.public_origin_parts()
    door = f"{prefix}/mcp".lstrip("/")
    return rest.strip("/") in ("", door)


# --- registration -----------------------------------------------------------------


def new_client_id() -> str:
    return f"{CLIENT_ID_PREFIX}{uuid.uuid4().hex[:CLIENT_ID_HEX]}"


def check_redirect_uri(uri: str) -> None:
    """RFC 8252's rule for a public client's callback, with a short denylist.

    `https://` anywhere; `http://` only to the loopback (§7.3, any port); a private-use
    scheme (§7.1 — Cursor's callback is one). Refused: `http://` to anything else, a
    fragment, and the handful of schemes that are a browser feature rather than an
    application. Exact-match against the registered list happens elsewhere; this is
    only about what may be registered at all.
    """
    if not isinstance(uri, str) or not uri or len(uri) > OAUTH_CLIENT_MAX_URI_LENGTH:
        raise OAuthError(
            "invalid_redirect_uri",
            f"each redirect_uri is a string of at most {OAUTH_CLIENT_MAX_URI_LENGTH} "
            "characters.",
        )
    try:
        parts = urlsplit(uri)
        # `.username`/`.password`/`.hostname` parse the authority lazily, so a malformed
        # one raises here rather than above — `http://[::1].evil.example/` is the case
        # that found this, and an unhandled `ValueError` from an unauthenticated route
        # is a 500 about a request that was merely wrong.
        _ = (parts.username, parts.password, parts.hostname, parts.port)
    except ValueError as exc:
        raise OAuthError(
            "invalid_redirect_uri", f"'{uri[:80]}' is not a URI this server can parse."
        ) from exc
    scheme = parts.scheme.lower()
    if not scheme or parts.fragment or any(c.isspace() for c in uri):
        raise OAuthError(
            "invalid_redirect_uri",
            f"'{uri[:80]}' is not an absolute URI without a fragment.",
        )
    if scheme in _REFUSED_SCHEMES:
        raise OAuthError(
            "invalid_redirect_uri", f"a {scheme}: URI is not a place a browser is sent."
        )
    # **No credentials in the authority.** `https://claude.ai@evil.example/cb` has host
    # `evil.example` and reads, to a person scanning it, as `claude.ai` — and the
    # consent page shows a registered name it cannot verify beside it. The page already
    # renders the *parsed* host, so this is defence rather than the fix; what settles it
    # is that no MCP client's callback has ever needed userinfo, so refusing costs a
    # legitimate registration nothing.
    if parts.username or parts.password:
        raise OAuthError(
            "invalid_redirect_uri",
            "a redirect_uri may not carry credentials in its authority: "
            "'https://name@host/cb' is a URI for `host`, and reads as one for `name`.",
        )
    if scheme == "https":
        if not parts.netloc:
            raise OAuthError("invalid_redirect_uri", "an https redirect_uri needs a host.")
        return
    if scheme == "http":
        if parts.hostname not in _LOOPBACK_HOSTS:
            raise OAuthError(
                "invalid_redirect_uri",
                "an http:// redirect_uri is accepted only for the loopback (localhost, "
                "127.0.0.1, [::1]) — RFC 8252 §7.3. Anything else must be https://.",
            )
        return
    # A private-use scheme, RFC 8252 §7.1. `cursor://…` is the case in point.
    return


def register_client(metadata) -> dict:
    """RFC 7591 Dynamic Client Registration, public clients only.

    No credential arrives and none is issued: `token_endpoint_auth_method` is `none`,
    always, because the clients this exists for are desktop applications that cannot
    keep a secret — and a client secret would be a second bearer-shaped credential this
    server would have to store and verify. The response is the registration as it was
    *recorded*, which may differ from what was asked (RFC 7591 §3.2.1 allows it): a
    request for `refresh_token` is registered without it, and the response says so.
    """
    if not isinstance(metadata, dict):
        raise OAuthError("invalid_client_metadata", "the registration is a JSON object.")
    refuse_unstorable_strings(metadata, "invalid_client_metadata")

    uris = metadata.get("redirect_uris")
    if not isinstance(uris, list) or not uris:
        raise OAuthError(
            "invalid_redirect_uri",
            "redirect_uris is required: a list of the URIs this client will be sent "
            "back to. There is no default.",
        )
    if len(uris) > OAUTH_CLIENT_MAX_REDIRECT_URIS:
        raise OAuthError(
            "invalid_redirect_uri",
            f"at most {OAUTH_CLIENT_MAX_REDIRECT_URIS} redirect_uris may be registered.",
        )
    for uri in uris:
        check_redirect_uri(uri)

    auth_method = metadata.get("token_endpoint_auth_method") or "none"
    if auth_method not in TOKEN_ENDPOINT_AUTH_METHODS:
        raise OAuthError(
            "invalid_client_metadata",
            f"token_endpoint_auth_method '{_short(auth_method)}' is not offered. This "
            "server registers public clients only (`none`): it issues no client secret, "
            "and a desktop application could not keep one.",
        )

    asked_grants = metadata.get("grant_types") or list(GRANT_TYPES)
    if not isinstance(asked_grants, list) or any(
        not isinstance(g, str) or g not in _TOLERATED_GRANT_TYPES for g in asked_grants
    ):
        raise OAuthError(
            "invalid_client_metadata",
            f"grant_types may name only {', '.join(sorted(_TOLERATED_GRANT_TYPES))}. "
            "authorization_code with PKCE is the one grant this server issues a token "
            "for; client_credentials would be a mint for a bearer, which this server "
            "refuses by design.",
        )
    asked_responses = metadata.get("response_types") or list(RESPONSE_TYPES)
    if not isinstance(asked_responses, list) or any(
        r not in RESPONSE_TYPES for r in asked_responses
    ):
        raise OAuthError(
            "invalid_client_metadata", "response_types may name only 'code'."
        )

    name = metadata.get("client_name")
    if name is not None and not isinstance(name, str):
        raise OAuthError("invalid_client_metadata", "client_name is a string.")
    name = (name or "").strip()
    # **A control character is not a name, and one of them is an outage.** A NUL cannot
    # be stored in a Postgres text column at all, so an unauthenticated registration
    # carrying one came back 503 — the status that says *this server is broken* about a
    # request that was merely wrong, and the one an operator is paged for. The rest of
    # C0 stores perfectly well and then renders as a line break or a bell on the consent
    # page. Both are refused here as what they are: a bad registration.
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
        raise OAuthError(
            "invalid_client_metadata",
            "client_name may not contain control characters. It is rendered on a "
            "consent page as text.",
        )
    if not name:
        # A registration without a name is legal. Name it for the page by the host it
        # is sent back to, which is the one fact about it the page shows anyway.
        first = urlsplit(uris[0])
        name = first.hostname or first.scheme or "an MCP client"
    if len(name) > OAUTH_CLIENT_MAX_NAME_LENGTH:
        raise OAuthError(
            "invalid_client_metadata",
            f"client_name is at most {OAUTH_CLIENT_MAX_NAME_LENGTH} characters.",
        )

    # What is kept of the rest: the three things a page might show or a log might want.
    # `logo_uri` is deliberately not one of them — a remote image on our consent page is
    # a request to the registrant's server every time somebody looks at it.
    kept = {}
    for key in ("client_uri", "software_id", "software_version"):
        value = metadata.get(key)
        if isinstance(value, str) and value:
            # Truncated per field rather than refused, and to a length three of them
            # cannot add up past the row's bound: the first version capped each at
            # 2048 and then refused the *total* over 4096, so a registration whose
            # three fields were each individually legal was rejected as "too large".
            # A bound that refuses what its own truncation produced is not a bound.
            kept[key] = value[:MAX_METADATA_FIELD_LENGTH]
    if len(json.dumps(kept).encode("utf-8")) > OAUTH_CLIENT_MAX_METADATA_BYTES:
        # Unreachable by construction — three 512-character fields cannot reach 4 KiB —
        # and kept as the backstop for a fourth key somebody adds above.
        raise OAuthError("invalid_client_metadata", "the registration is too large.")

    row = storage.active().create_oauth_client(
        {
            "id": new_client_id(),
            "client_name": name,
            "redirect_uris": [str(u) for u in uris],
            "metadata": kept,
        }
    )
    log.info("oauth: registered client %s (%s)", row["id"], name)
    return _registration(row)


def _registration(row: dict) -> dict:
    """RFC 7591 §3.2.1: the registration as recorded, plus the id."""
    return {
        "client_id": row["id"],
        "client_id_issued_at": int(row["created_at"].timestamp()),
        "client_name": row["client_name"],
        "redirect_uris": list(row["redirect_uris"]),
        "grant_types": list(GRANT_TYPES),
        "response_types": list(RESPONSE_TYPES),
        "token_endpoint_auth_method": "none",
        **{k: v for k, v in (row.get("metadata") or {}).items()},
    }


def describe_client(client_id: str) -> dict:
    """What the consent page renders. Raises `OAuthError(invalid_client)` for nobody."""
    row = storage.active().find_oauth_client(client_id or "")
    if row is None:
        raise OAuthError(
            "invalid_client",
            "no client is registered under that id. Clients register themselves at the "
            "registration endpoint named in /.well-known/oauth-authorization-server.",
        )
    return {
        "client_id": row["id"],
        "client_name": row["client_name"],
        "client_uri": (row.get("metadata") or {}).get("client_uri", ""),
        "redirect_uris": list(row["redirect_uris"]),
    }


# --- consent ------------------------------------------------------------------------


def _trusted_target(params: dict) -> tuple[dict, str]:
    """The client and the one redirect URI a browser may be sent to, or refuse.

    RFC 6749 §4.1.2.1: an unknown client or an unregistered `redirect_uri` is **never**
    answered by redirecting — that would be an open redirect on our own origin — so
    both raise here, and everything downstream may redirect because the target has
    been matched byte-for-byte against what the client registered.
    """
    client = storage.active().find_oauth_client(str(params.get("client_id") or ""))
    if client is None:
        raise OAuthError("invalid_client", "no client is registered under that id.")
    redirect_uri = params.get("redirect_uri")
    if not isinstance(redirect_uri, str) or redirect_uri not in client["redirect_uris"]:
        raise OAuthError(
            "invalid_request",
            "redirect_uri is not one this client registered. Nothing is redirected: a "
            "consent page that sent a browser to an address the query string chose "
            "would be an open redirect.",
        )
    return client, redirect_uri


def _with_query(url: str, extra: dict) -> str:
    """`url` with `extra` appended to its query, existing query kept (RFC 6749 §3.1.2)."""
    parts = urlsplit(url)
    query = parts.query
    added = urlencode({k: v for k, v in extra.items() if v is not None and v != ""})
    joined = f"{query}&{added}" if query and added else (query or added)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, joined, ""))


def _looks_like_challenge(value) -> bool:
    """base64url of a SHA-256 without padding: 43 characters from the url-safe set."""
    if not isinstance(value, str) or len(value) != _CHALLENGE_LENGTH:
        return False
    return all(c in _BASE64URL for c in value)


def consent(principal: Principal, params: dict) -> str:
    """The person's decision, turned into the URL the browser goes to next.

    Called by `POST /oauth/consent` with the person's own bearer. **Refuses a machine
    before anything else** — this is the mint's only gate, and 044's guard on
    `POST /me/tokens` is the precedent word for word. Everything after the target is
    trusted answers by redirecting, with the RFC's error when the request is wrong and
    with a code when the person approved.
    """
    if principal.kind != "user":
        raise AccessDenied(
            "consent is given by a person. A machine credential may not mint another: "
            "what a stolen bearer token lacks is persistence, and a consent open to "
            "machines would hand it a durable successor."
        )

    client, redirect_uri = _trusted_target(params)
    state = params.get("state")
    state = state if isinstance(state, str) and state else None

    def bounce(error: str, description: str) -> str:
        return _with_query(
            redirect_uri,
            {"error": error, "error_description": description, "state": state},
        )

    if not params.get("approve"):
        return bounce("access_denied", "the person declined.")
    if params.get("response_type") != "code":
        return bounce("unsupported_response_type", "only response_type=code is offered.")
    if params.get("code_challenge_method") != "S256" or not _looks_like_challenge(
        params.get("code_challenge")
    ):
        return bounce(
            "invalid_request",
            "PKCE with code_challenge_method=S256 is required, and the challenge is "
            "base64url of a SHA-256 without padding.",
        )
    urls = endpoints()
    resource = params.get("resource") or ""
    if resource and resource != urls["resource"]:
        return bounce(
            "invalid_target",
            f"the only resource this server issues tokens for is {urls['resource']}.",
        )

    token_name = params.get("token_name")
    token_name = (token_name if isinstance(token_name, str) else "").strip()
    token_name = (token_name or client["client_name"])[:OAUTH_CLIENT_MAX_NAME_LENGTH]
    # **Refused here, before a code exists, and not left to the store.** Step 087. The
    # store refuses it too (`normalize_oauth_code`), but a refusal there is after the
    # person clicked Approve, and a refusal at the *exchange* would be worse still: the
    # mint's name-suffix loop retries on `ValueRefused` because that is what a duplicate
    # name raises, so a NUL would spin a hundred times and answer *this customer already
    # has 100 live tokens*, which is a sentence about the wrong thing. Not bounced to
    # the redirect URI either: the name is the page's own field, not the client's request.
    try:
        check_name_is_text(token_name, what="the token name")
    except ValueRefused as exc:
        raise OAuthError("invalid_request", str(exc)) from None

    code = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    storage.active().create_oauth_code(
        principal.tenant_id,
        {
            "code_hash": digest(code),
            "client_id": client["id"],
            "owner_id": principal.id,
            "redirect_uri": redirect_uri,
            "code_challenge": params["code_challenge"],
            "resource": resource,
            "token_name": token_name,
            "expires_at": now + timedelta(seconds=config.OAUTH_CODE_TTL_SECONDS),
        },
    )
    storage.active().touch_oauth_client(client["id"])
    log.info("oauth: %s consented to client %s", principal, client["id"])
    return _with_query(redirect_uri, {"code": code, "state": state})


# --- the exchange -------------------------------------------------------------------


def digest(code: str) -> str:
    """The stored form of a code. `tokens.digest`'s shape under its own domain."""
    body = hashlib.sha256(_CODE_HASH_DOMAIN + code.encode("utf-8")).hexdigest()
    return f"{_HASH_SCHEME}${body}"


def _pkce_matches(verifier: str, challenge: str) -> bool:
    """RFC 7636 §4.6: `S256(verifier) == challenge`, in constant time.

    **The shape is checked before the digest, and that is not tidiness.** A verifier is
    ASCII by definition, so encoding one that is not raises rather than mismatching —
    and an exception here is a 500 at the token endpoint, which tells an operator the
    server is broken about a request that was merely wrong. Anything outside the
    unreserved set or the length range is simply not a verifier, and says so as a
    mismatch.
    """
    if not (_VERIFIER_MIN <= len(verifier) <= _VERIFIER_MAX):
        return False
    if not all(c in _UNRESERVED for c in verifier):
        return False
    computed = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    return hmac.compare_digest(computed, challenge)


def _invalid_grant() -> OAuthError:
    """One sentence for unknown, used, expired, mismatched and mis-proved codes.

    `tokens._refuse`'s reasoning: telling a presenter *which* half was wrong is free
    help, and a replayed code in particular must look exactly like an unknown one.
    """
    return OAuthError(
        "invalid_grant",
        "the authorization code is not valid for this client. Codes are single-use "
        "and expire in minutes; start the authorization again.",
    )


def exchange(form: dict) -> dict:
    """`POST /oauth/token`. Verify, consume, mint. RFC 6749 §4.1.3 and §5.1.

    The order is deliberate: nothing about the row is acted on until the client has
    proved it holds the verifier, and the row is consumed (compare-and-set) *before*
    the mint, so two exchanges racing on one code cannot both produce a token. The one
    exception to *one sentence for everything* is the replay: a used code is still
    refused identically, but the token it minted is revoked first — the second
    presentation is RFC 6749's own signal that the first was intercepted.
    """
    grant_type = form.get("grant_type")
    if grant_type != "authorization_code":
        raise OAuthError(
            "unsupported_grant_type",
            f"grant_type '{_short(grant_type)}' is not offered. authorization_code with "
            "PKCE is the one grant this server exchanges for a token: it is gated on a "
            "person's interactive sign-in, so a stolen bearer cannot mint a successor. "
            "client_credentials would be exactly that mint, and refresh_token a mint of "
            "a successor for a bearer, and this server issues neither by design.",
        )
    refuse_unstorable_strings(form, "invalid_request")
    code = form.get("code")
    verifier = form.get("code_verifier")
    client_id = form.get("client_id")
    if not all(isinstance(v, str) and v for v in (code, verifier, client_id)):
        raise OAuthError(
            "invalid_request", "code, code_verifier and client_id are all required."
        )

    store = storage.active()
    now = datetime.now(timezone.utc)
    row = store.find_oauth_code(digest(code))
    if row is None:
        raise _invalid_grant()

    if row["used_at"] is not None:
        # A replay. Revoke what the first presentation minted, then refuse identically.
        if row["token_id"]:
            revoked = store.revoke_api_token(
                row["tenant_id"], row["token_id"], actor=REPLAY_ACTOR
            )
            log.warning(
                "oauth: code for client %s presented twice; revoked token %s (%s)",
                row["client_id"],
                row["token_id"],
                "revoked" if revoked else "already gone",
            )
        raise _invalid_grant()

    if row["expires_at"] <= now or row["client_id"] != client_id:
        raise _invalid_grant()
    redirect_uri = form.get("redirect_uri")
    if redirect_uri is not None and redirect_uri != row["redirect_uri"]:
        raise _invalid_grant()
    resource = form.get("resource") or ""
    if resource and resource != endpoints()["resource"]:
        raise OAuthError(
            "invalid_target",
            f"the only resource this server issues tokens for is "
            f"{endpoints()['resource']}.",
        )
    if not _pkce_matches(verifier, row["code_challenge"]):
        raise _invalid_grant()

    # The person must still be live. `check_row_is_live` would refuse the token at its
    # first use anyway; minting for somebody who has been disabled since they consented
    # is wrong even for the seconds it would take.
    owner = store.get_user(row["tenant_id"], row["owner_id"])
    if owner is None or owner["status"] != "active":
        raise _invalid_grant()

    if not store.consume_oauth_code(row["code_hash"]):
        # Lost the race with another exchange of the same code. That other exchange
        # will mint; this one refuses. Not a replay — no token exists yet to revoke —
        # and if it was one, the winner's row will say so on the next presentation.
        raise _invalid_grant()

    tenancy.scope_to(row["tenant_id"])
    expires_at = (
        now + timedelta(days=config.OAUTH_TOKEN_DAYS) if config.OAUTH_TOKEN_DAYS > 0 else None
    )
    actor = str(Principal.user(row["owner_id"], row["tenant_id"]))
    minted = None
    presented = ""
    base = row["token_name"]
    for attempt in range(_NAME_ATTEMPTS):
        name = base if attempt == 0 else f"{base} ({attempt + 1})"
        try:
            minted, presented = tokens.mint(
                row["tenant_id"],
                name,
                row["owner_id"],
                actor=actor,
                expires_at=expires_at,
                acts_as_owner=True,
                via=f"oauth:{row['client_id']}",
            )
            break
        except ValueRefused:
            continue
    if minted is None:
        raise OAuthError(
            "server_error",
            f"you already have {_NAME_ATTEMPTS} live tokens called "
            f"'{base}'. Revoke some on your tokens page and try again.",
            status=500,
        )
    store.record_oauth_code_token(row["code_hash"], minted["id"])
    log.info(
        "oauth: minted token %s for %s via client %s", minted["id"], actor, row["client_id"]
    )

    answer = {"access_token": presented, "token_type": "Bearer"}
    if expires_at is not None:
        answer["expires_in"] = int((expires_at - now).total_seconds())
    return answer


# --- housekeeping -------------------------------------------------------------------


def sweep() -> dict:
    """Expired codes and never-consented clients. Rides on `api.LogMaintainer`."""
    store = storage.active()
    return {
        "codes": store.sweep_oauth_codes(older_than_seconds=config.OAUTH_CODE_SWEEP_SECONDS),
        "clients": store.sweep_oauth_clients(
            unused_for_seconds=config.OAUTH_CLIENT_UNUSED_DAYS * 86400
        ),
    }


def _short(value) -> str:
    text = str(value)
    return text if len(text) <= 80 else f"{text[:80]}…"
