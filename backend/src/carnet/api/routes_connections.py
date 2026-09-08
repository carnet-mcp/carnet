"""Connecting your own account — the first routes in this API that are about *you*.

Step 7b. Four routes, and the division between them is the persona split migration 003
drew and step 012 earned:

    GET    /connections                        what can I connect, and what have I
    POST   /connectors/{id}/connect            start a consent flow for myself
    GET    /connect/callback                   the provider sending somebody back
    DELETE /connectors/{id}/connection         disconnect myself

**There is no administrative route here and that is deliberate.** `--set-oauth`
configures a connector's OAuth application and stays on the CLI. When this was written it
was behind the wall 011 and 012 hit — it needs a tenant-admin role, which did not exist.
**12b built the role and the wall is gone**; the flag stays here until 12c, whose
administration surface is where the person who would use it is standing. Shipping it as a
route with no screen would repeat 7b's own finding knowingly. The distinction 012 drew
holds either way — *connecting your own account* is self-serve and is what these routes
are; *configuring the connector* is not.

## Every route here is about the caller, and none of them takes a principal

`GET /connections` answers for whoever is asking. There is no `?user=` and there will not
be one: a route that could report somebody else's connections is an administrative route.
The role it would belong behind exists as of 12b, and that does not change the answer —
**an admin is not a superuser**, and reading whose account is connected where is tenant
*data* rather than tenant configuration. See migration 026, which states that boundary in
the schema's voice for exactly this reason. The same reasoning that keeps the
tenant off the URL in `api/deps.py`, one level in.

## The callback is the exception to every rule in this file, and it has to be

`GET /connect/callback` is the one route in this entire API with **no** authentication.
It cannot have any: it is a top-level browser navigation initiated by a third party, so
the SPA's bearer token — which lives in memory — is not on it, and there is nowhere for
it to come from. See `access/oauth.complete` and decision 2: the binding "whose
connection is this" rides in a server-side, single-use `state` minted while the person
*was* authenticated, and the row is what supplies the principal and the tenant.

That makes `state` a bearer credential for one flow, which is why it is 256 bits of
`secrets.token_urlsafe`, consumed atomically, and expires in minutes. It is also the CSRF
defence: an attacker cannot forge one we never minted.
"""

import logging

from fastapi import APIRouter, Depends, Query
from fastapi.responses import RedirectResponse

from .. import storage, tools
from ..access import connections, oauth
from ..tools.mcp import egress
from ..core import Principal
from .deps import principal_from_request
from .schemas import ConnectionState, ConnectionSummary, ConsentStart

log = logging.getLogger(__name__)

router = APIRouter(tags=["connections"])

# Where the callback sends a browser when the flow carried no `return_to`. The
# Connections page, because that is the screen somebody clicked Connect on and the one
# that will now show the row as connected.
DEFAULT_RETURN_TO = "/connections"

# The path the provider redirects to, relative to this deployment's public origin. It is
# **fixed per deployment and registered at each provider** — decision 3 — which is why it
# is a constant rather than anything a request supplies. A redirect URI a caller could
# influence is the open-redirect half of an OAuth flow, and providers check it against
# their own registration precisely so that it cannot be.
CALLBACK_PATH = "/connect/callback"


@router.get("/connections", response_model=list[ConnectionSummary])
def list_connections(principal: Principal = Depends(principal_from_request)):
    """Every connector this tenant has vetted, and this person's own state for each.

    **Three states, not two**, and the third is the one worth building deliberately:

        connected       this person has a credential. `account_label` says as whom
        connectable     a consent flow exists and they have not used it
        unavailable     no consent flow is configured — ask an administrator

    A **Connect** button on the third would be the *"a control that exists and does
    nothing reads as a bug"* failure 10d's share sheet already learned, so the state is a
    field rather than something a client infers from a missing endpoint.

    **What a row carries about a credential that exists — 035f.** Beside the state:
    `credential_kind`, and three instants that are only readable together. `expires_at` is
    the access token's and matters on a pasted credential, which nothing renews;
    `refresh_expires_at` is when the *connection itself* lapses and is the one that
    predicts re-consent; `updated_at` is when it last changed. The three fields answer one
    question — *is there anything behind this when it lapses* — and any one of them alone
    is either noise or silence. See `ConnectionSummary`.

    Requires no grant, on `GET /tools`' precedent and for its reason: this is the menu of
    what a person could connect, not anybody's data. **035f widened the row and not the
    audience**: everything added is a fact about the caller's own credential, null on a
    row they do not have, so the route stays out of `deps.ADMIN_SURFACE`. It discloses which connectors this
    customer vetted — which `GET /tools` already does — plus the caller's own connection
    state, which is theirs by construction.
    """
    tenant_id = principal.tenant_id
    apps = oauth.configured(tenant_id)
    mine = {
        row["connector_id"]: row
        for row in connections.list_accounts(tenant_id, principal)
    }

    summaries = []
    for connector in tools.mcp.connectors_for(tenant_id):
        row = mine.get(connector.id)
        app = apps.get(connector.id)
        summaries.append(
            ConnectionSummary(
                connector_id=connector.id,
                description=connector.description,
                state=_state_of(row, app),
                account_label=(row or {}).get("account_label") or "",
                credential_kind=(row or {}).get("credential_kind") or "",
                # The **access** token's expiry. Only renderable beside `credential_kind`
                # — see `ConnectionSummary.expires_at`, whose resting state on a healthy
                # OAuth row is *in the past*.
                expires_at=(row or {}).get("expires_at"),
                # **Both of these were already on the row and were simply never passed —
                # 035f.** `_CONNECTION_META_COLUMNS` has projected `refresh_expires_at`
                # since migration 024 and `updated_at` since 013, both stores return them,
                # and `connections.list_accounts` hands them through untouched. This
                # constructor is built with explicit kwargs rather than `**row`, so
                # nothing was dropped in 035c's silent sense; two facts were just never
                # named, and *"this connection will need re-consenting in six months"* was
                # therefore unpredictable from any surface for eleven steps.
                refresh_expires_at=(row or {}).get("refresh_expires_at"),
                updated_at=(row or {}).get("updated_at"),
                # The provider's own sentence, or ''. Rendered rather than paraphrased:
                # "reconnect" is what a person does, and *why* is what tells them whether
                # doing it will help.
                reconsent_reason=(row or {}).get("reconsent_reason") or "",
                # **The OAuth application's configured ask, not anybody's granted scope.**
                # `app` is `oauth.configured(tenant_id)` — the row `oauth.begin` builds the
                # authorize query from — so this says what a consent flow would request
                # *now*. What a person consented to is stored nowhere. See
                # `ConnectionSummary.scopes`; a client that renders this beside a connected
                # row has to say which question it is answering.
                scopes=list((app or {}).get("scopes") or ()),
                # Migration 051, from the same row and carrying the same caveat: what a
                # consent flow would ask for now, in words, rather than what anybody
                # granted. This is the reader the column was added for.
                scope_notes=dict((app or {}).get("scope_notes") or {}),
            )
        )
    return summaries


def _state_of(row: dict | None, app: dict | None) -> str:
    """Which of the three states this connector is in for this person.

    Computed here rather than in the client, so the CLI and the page cannot develop
    different opinions about what "connected" means — the same argument that puts
    `catalogue` in `tools/` rather than in the route.
    """
    if row is not None and row.get("reconsent_reason"):
        # Connected and unusable, which is genuinely a fourth thing and is deliberately
        # collapsed onto `connectable` **only when there is a flow to reconnect with**.
        # A connection needing re-consent for a connector whose OAuth app was since
        # removed is `unavailable`, and saying "Connect" there would be the dead button
        # again.
        return ConnectionState.RECONNECT if app else ConnectionState.UNAVAILABLE
    if row is not None:
        return ConnectionState.CONNECTED
    return ConnectionState.CONNECTABLE if app else ConnectionState.UNAVAILABLE


@router.post("/connectors/{connector_id}/connect", response_model=ConsentStart)
def start_consent(
    connector_id: str,
    return_to: str = Query(default=DEFAULT_RETURN_TO),
    principal: Principal = Depends(principal_from_request),
):
    """Mint a consent flow and return the URL to send this person's browser to.

    **Returns the URL rather than redirecting**, and that is a decision the SPA depends
    on: `fetch` follows a 302 transparently and would fetch the provider's *consent HTML*
    into a promise nobody can render, while a top-level navigation is what actually has to
    happen. So the route answers 200 with a URL and the client assigns
    `window.location` — the browser leaves this origin the way it has to, at a moment the
    client chose.

    `return_to` is where the callback lands the browser afterwards. It is validated as a
    path within this application (`check_pending_authorization`), because it becomes a
    `Location` header and an absolute URL there is an open redirect on this deployment's
    own domain.
    """
    # Refuse a connector that is not this tenant's before minting anything. The consent
    # flow would fail at the callback anyway, but only after the person had approved
    # access at a third party — which is the worst place to discover a typo.
    if tools.mcp.get_connector(principal.tenant_id, connector_id) is None:
        raise oauth.OAuthRefused(
            storage.NO_SUCH_CONNECTOR.format(
                connector=connector_id, tenant=principal.tenant_id
            )
        )

    url = oauth.begin(
        principal,
        connector_id,
        redirect_uri=_redirect_uri(),
        return_to=return_to or DEFAULT_RETURN_TO,
    )
    return ConsentStart(authorize_url=url)


@router.get(CALLBACK_PATH, include_in_schema=False)
def consent_callback(
    state: str = Query(default=""),
    code: str = Query(default=""),
    error: str = Query(default=""),
    error_description: str = Query(default=""),
):
    """The provider sending somebody back. **No authentication, and none is possible.**

    See the module docstring. Everything this handler knows comes out of the row `state`
    is a handle on.

    Answers a **redirect, not JSON**, because the thing on the other end is a person's
    browser rather than a client library: the whole flow ends with them looking at a
    page, and a JSON body would be a blank tab with `{"connector_id": "jira"}` in it.

    `include_in_schema=False` — this is not an API anybody calls, it is a URL registered
    at an identity provider, and putting it in the OpenAPI document would invite exactly
    the client that must not exist.

    **Nothing in the redirect carries a token, and nothing could.** The query string here
    ends up in the browser's history, in any proxy's access log, and in the `Referer` of
    the next request the page makes. What goes on it is a connector id and an outcome.
    """
    if error:
        # The person pressed Deny, or the provider refused. Not our failure and not an
        # error page: they made a choice, and the Connections page is where they see the
        # result of it.
        log.info("consent declined or refused upstream: %s", error)
        return _back(
            DEFAULT_RETURN_TO,
            connected="",
            failed=error_description or error,
        )

    try:
        outcome = oauth.complete(state, code)
    except (oauth.OAuthRefused, egress.EgressRefused) as exc:
        # A forged `state`, a replayed one, an expired one, a provider that refused the
        # exchange — or a host an administrator revoked between this flow starting and
        # finishing, which is `EgressRefused` and was a **500** until it was caught here.
        # Every one of them is reported to the person in the same place and **nothing was
        # sealed** in any of them.
        log.info("consent callback refused: %s", exc)
        return _back(DEFAULT_RETURN_TO, connected="", failed=str(exc))

    return _back(
        outcome["return_to"] or DEFAULT_RETURN_TO,
        connected=outcome["connector_id"],
        failed="",
    )


def _back(path: str, *, connected: str, failed: str):
    """A 303 to somewhere inside this app, carrying only what a page needs to render.

    **303 rather than 302**, which matters here rather than being pedantry: this is the
    end of a `GET`, and a 303 is the status that means *"go and GET this other thing"*
    without any suggestion that the resource moved. Browsers treat the redirect as a new
    navigation and the consent URL does not stay in the address bar, which is what stops
    somebody bookmarking or sharing a URL containing a spent authorization code.
    """
    from urllib.parse import urlencode

    query = {k: v for k, v in (("connected", connected), ("failed", failed)) if v}
    target = f"{path}?{urlencode(query)}" if query else path
    return RedirectResponse(target, status_code=303)


def _redirect_uri() -> str:
    """This deployment's callback URL, as registered at every provider.

    Configuration rather than anything derived from the request, which is decision 3 and
    is the half people want to skip. Building it from `Host` or `X-Forwarded-Host` means
    the redirect URI is whatever a header says — and a provider that did not validate it
    strictly would then send somebody's authorization code wherever an attacker asked.
    Providers do validate it, so the practical consequence of getting this from a header
    is not a vulnerability but an `invalid_grant` that appears only behind a proxy; the
    reason to refuse anyway is that "safe because somebody else checks" is not a property
    to depend on.
    """
    from ..config import PUBLIC_ORIGIN

    return f"{PUBLIC_ORIGIN.rstrip('/')}{CALLBACK_PATH}"


@router.delete("/connectors/{connector_id}/connection", status_code=200)
def disconnect(
    connector_id: str, principal: Principal = Depends(principal_from_request)
):
    """Disconnect this person's own account. Revokes upstream where it can.

    **200 with a body rather than 204**, which departs from every other delete in this
    API and does so on purpose: whether the token was revoked at the provider is the one
    thing a person cannot find out any other way, and a 204 has nowhere to say it.
    `revoked_upstream` is `true`, `false`, or `null` for a connection there was nobody to
    revoke to — a pasted credential, or a provider publishing no revocation endpoint.

    Disconnecting something that was never connected answers 200 with
    `disconnected: false` rather than 404. It is idempotent, and a 404 would make the
    ordinary double-click read as an error.
    """
    return oauth.disconnect(principal, connector_id, actor=str(principal))
