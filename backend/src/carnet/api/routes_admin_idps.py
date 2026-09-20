"""Identity providers over HTTP — step 110, decisions 2 and 5.

The first thing in an administrator's hour, and until this file the only one with no
browser path at all: `--add-idp` and `--list-idps` were the whole of it, so the hour
began in `docker compose exec` whatever else had a screen. Four routes:

    GET    /admin/idps           the tenant's providers, every column
    POST   /admin/idps           register or replace one — `--add-idp`, as a body
    DELETE /admin/idps           remove one, by issuer (and discriminator value)
    POST   /admin/idps/discover  ask an issuer for its discovery document

**Who this is for, and who it is not.** A tenant administrator registers the provider
their own tenant signs in through. The CLI's `--add-idp TENANT_ID` is the operator's
cross-tenant act and stays; this route takes the tenant off the principal, which is
the rule every route in this API follows and the reason an administrator of one tenant
cannot register a provider for another.

**Removal goes in the query, not the path.** An issuer is a URL, and 12b's edge pass
established that a `/` in a path segment is a routing 404 even percent-encoded, because
uvicorn decodes before Starlette routes. The host revoke keeps its path because a host
never carries a slash; an issuer always does.

**One removal is refused, and the refusal is the point.** The provider the caller
signed in through, because removing it locks the tenant out with the person who pressed
the button inside it — the tenant-deletion button plan 110 declined, in miniature.
There is no `--delete-idp` in the CLI either, so a refused removal is not a shell
command away; it is a row a database administrator edits, and that is the right cost.
A separate "never the last provider" rule was written and taken out again: over HTTP
the caller is always a signed-in person whose own provider exists and is enabled, so
the last provider *is* the caller's, and a second rule would have been a control that
no request could reach — off, and looking on.

**Discovery is an SSRF primitive with a friendly form in front of it**, which is the
sentence `tools/mcp/egress.py` was written around. Fetching `{issuer}/.well-known/
openid-configuration` is a server-side request to an address an administrator chose.
It goes through `egress.dial` with `operator_consented=True`, exactly as the JWKS fetch
in `access/oidc.py` already does — an identity provider is the deployment's own and
legitimately lives on a private network in every estate step 109 was written for — so
loopback and private answers are legal while the never-consentable ranges (link-local,
the metadata service) are refused like for every dial, and a redirect is never followed.
What the document says its issuer is must equal what was asked for: a token's `iss` is
compared byte for byte, and a form that "helpfully" registered the corrected spelling
would register a provider no token ever matches.

**Both acts are recorded.** `idp.save` and `idp.remove` land in the administrative log
with the person who made them — the one gap plan 110 shipped knowing about, closed in
the pass after 110f. The record is written by the store, inside the same transaction as
the row, so it cannot be absent while the change stands. `--add-idp` records the same
way; a deployment building its own world passes no actor and writes nothing, because
nobody there made a decision.

What is deliberately not here: no `enabled` toggle (there is no CLI for it either, and
a disabled provider is a row somebody edited on purpose), and no edit route —
registration is an upsert, which is what editing is.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import storage
from ..core import Principal
from ..storage import ValueRefused
from ..tools import mcp
from .deps import admin_from_request
from .schemas import (
    IdpDiscovered,
    IdpDiscoveryRequest,
    IdpEntry,
    IdpRegistered,
    IdpRemoved,
    IdpRequest,
)

log = logging.getLogger(__name__)

router = APIRouter(tags=["administration"])

DISCOVERY_PATH = "/.well-known/openid-configuration"


def _entry(row: dict) -> IdpEntry:
    return IdpEntry(
        issuer=row["issuer"],
        jwks_uri=row["jwks_uri"],
        audience=row["audience"],
        discriminator_claim=row.get("discriminator_claim"),
        discriminator_value=row.get("discriminator_value"),
        subject_claim=row.get("subject_claim") or "sub",
        email_claim=row.get("email_claim") or "email",
        groups_claim=row.get("groups_claim"),
        allowed_domains=list(row.get("allowed_domains") or ()),
        enabled=bool(row.get("enabled", True)),
    )


def _find(rows: list[dict], issuer: str, discriminator_value: str | None) -> dict | None:
    for row in rows:
        if row["issuer"] == issuer and (row.get("discriminator_value") or None) == (
            discriminator_value or None
        ):
            return row
    return None


@router.get("/admin/idps", response_model=list[IdpEntry])
def list_idps(principal: Principal = Depends(admin_from_request)):
    """This tenant's identity providers — `--list-idps TENANT`, for the tenant the caller
    administers. Ordered by issuer, as the store returns them."""
    return [_entry(row) for row in storage.active().list_tenant_idps(principal.tenant_id)]


@router.post("/admin/idps", response_model=IdpRegistered)
def register_idp(request: IdpRequest, principal: Principal = Depends(admin_from_request)):
    """Register a provider, or replace the one with this issuer and discriminator.

    200 rather than 201, because `save_tenant_idp` is an upsert by design and there is no
    new URL to point at; `replaced` says which happened. Every refusal is the store's
    own: a malformed row is `normalize_idp`'s 400, a `'*'` domain on anybody but the
    local provider is `check_allowed_domains`'s 400, and an issuer that would make a
    token ambiguous between two tenants is `IssuerConflictError`, a 409 (`errors.py`).
    """
    store = storage.active()
    before = _find(
        store.list_tenant_idps(principal.tenant_id), request.issuer, request.discriminator_value
    )
    store.save_tenant_idp(
        principal.tenant_id,
        {
            "issuer": request.issuer,
            "jwks_uri": request.jwks_uri,
            "audience": request.audience,
            "discriminator_claim": request.discriminator_claim or None,
            "discriminator_value": request.discriminator_value or None,
            "subject_claim": request.subject_claim,
            "email_claim": request.email_claim,
            "groups_claim": request.groups_claim or None,
            "allowed_domains": tuple(request.allowed_domains),
        },
        actor=str(principal),
    )
    after = _find(
        store.list_tenant_idps(principal.tenant_id), request.issuer, request.discriminator_value
    )
    log.info(
        "identity provider %s registered for tenant %s by %s%s",
        request.issuer, principal.tenant_id, principal, " (replaced)" if before else "",
    )
    assert after is not None  # the store just wrote it
    return IdpRegistered(provider=_entry(after), replaced=before is not None)


@router.delete("/admin/idps", response_model=IdpRemoved)
def remove_idp(
    issuer: str = Query(min_length=1),
    discriminator_value: str | None = Query(default=None),
    principal: Principal = Depends(admin_from_request),
):
    """Remove a provider. **Refuses the caller's own.**

    A 400 with the sentence, and it exists because this button sits in a browser: an
    administrator who removes the provider they signed in through has locked the tenant
    out with themselves inside it, and a stolen admin session cannot do worse than that
    from here, since the session's own provider is the one it cannot remove. There is
    no CLI remedy — no `--delete-idp` — so the refusal is the whole guard.

    Idempotent otherwise, and says whether a row was there.
    """
    store = storage.active()
    rows = store.list_tenant_idps(principal.tenant_id)
    target = _find(rows, issuer, discriminator_value)
    if target is None:
        return IdpRemoved(issuer=issuer, discriminator_value=discriminator_value, removed=False)

    if principal.kind == "user":
        me = store.get_user(principal.tenant_id, principal.id)
        if me is not None and me.get("issuer") == issuer:
            raise ValueRefused(
                f"you signed in through {issuer}, so removing it would lock this tenant "
                "out — including you, at your next sign-in. Register the provider that "
                "replaces it first, sign in through that one, and remove this one from "
                "there."
            )
    store.delete_tenant_idp(
        principal.tenant_id, issuer, discriminator_value or None, actor=str(principal)
    )
    log.info(
        "identity provider %s removed from tenant %s by %s", issuer, principal.tenant_id, principal
    )
    return IdpRemoved(issuer=issuer, discriminator_value=discriminator_value, removed=True)


def _fetch_discovery(issuer: str) -> dict:
    """The document at `{issuer}/.well-known/openid-configuration`, through the pinned
    dial. Raises `HTTPException(502)` for anything but a 200 with a JSON object, and
    lets `EgressRefused` (a 400 with the sentence) through untouched."""
    import requests

    from ..config import REQUEST_TIMEOUT

    url = issuer.rstrip("/") + DISCOVERY_PATH
    with requests.Session() as session:
        try:
            response = mcp.egress.dial(
                session, "GET", url, operator_consented=True, timeout=REQUEST_TIMEOUT
            )
        except requests.RequestException as exc:
            raise HTTPException(
                502,
                f"could not fetch {url}: {exc}. If the provider serves no discovery "
                "document, enter its JWKS URL by hand.",
            ) from exc
    if 300 <= response.status_code < 400:
        target = response.headers.get("Location") or "somewhere it did not name"
        raise HTTPException(
            502,
            f"{url} answered HTTP {response.status_code} redirecting to {target}, and "
            "a redirect is not followed: the address a pin checked is the only one it "
            "may dial. Enter the issuer as the provider actually serves it.",
        )
    if response.status_code != 200:
        raise HTTPException(
            502,
            f"{url} answered HTTP {response.status_code}. If the provider serves no "
            "discovery document, enter its JWKS URL by hand.",
        )
    try:
        document = response.json()
    except ValueError as exc:
        raise HTTPException(502, f"{url} did not answer with JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise HTTPException(502, f"{url} answered with JSON that is not an object.")
    return document


@router.post("/admin/idps/discover", response_model=IdpDiscovered)
def discover_idp(
    request: IdpDiscoveryRequest, principal: Principal = Depends(admin_from_request)
):
    """Ask an issuer for its discovery document and return the two things the form
    needs from it. Offered, never required: a provider that serves no discovery is
    typed in by hand, as it always was.

    The document's `issuer` must equal the one asked for. RFC 8414 and OpenID Discovery
    both require it, and here it is load-bearing rather than pedantic: a token's `iss`
    is compared byte for byte against the registered issuer, so a document reached at
    `https://idp.example.com` that names `https://idp.example.com/` (or the reverse, or
    a different host) describes a provider whose tokens would never match this row.
    Refused with both spellings in the sentence rather than silently corrected.
    """
    document = _fetch_discovery(request.issuer)
    stated = document.get("issuer")
    if not isinstance(stated, str) or not stated:
        raise ValueRefused(
            f"the discovery document under {request.issuer} names no issuer. Enter the "
            "issuer and JWKS URL by hand, from the provider's own documentation."
        )
    if stated != request.issuer:
        raise ValueRefused(
            f"the discovery document under {request.issuer} says its issuer is "
            f"{stated}. A token's `iss` must match the registered issuer exactly, so "
            f"register {stated} — spelled as the provider spells it — rather than the "
            "address you typed."
        )
    jwks_uri = document.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri:
        raise ValueRefused(
            f"the discovery document at {request.issuer} names no jwks_uri. Enter the "
            "JWKS URL by hand, from the provider's own documentation."
        )
    claims = document.get("claims_supported")
    return IdpDiscovered(
        issuer=stated,
        jwks_uri=jwks_uri,
        claims_supported=[c for c in claims if isinstance(c, str)]
        if isinstance(claims, list)
        else [],
    )
