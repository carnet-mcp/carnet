"""Where a request becomes a `Principal`. The only place, with one named exception.

The API is an entry point, and the whole job of an entry point here is to establish
*who a call is made for* and hand that down. `cli.py` does it in one line because a
terminal has one answer. An HTTP server has one answer per request, and this is it.

**The exception was the trigger door** (step 023, removed in 078), and it was an
exception to the *where*, never to the *what*: `POST /hooks/{id}` carries no bearer —
its caller is an outside system that never signed into anything — and authenticates
instead by proving possession of a per-trigger secret with an HMAC over the request
body. The principal it resolves to is still built by this module's machinery
(`tokens.act_for`, the same four row checks `resolve` runs), after proof, never before.
This sentence used to read "the only place, deliberately", and the door is the one
thing that has ever qualified it.

## What a request goes through

```
Authorization: Bearer <credential>
        │
        ├── starts "art_" ──► tokens.resolve()      a machine: step 020
        │                       │  ── unknown / wrong secret / revoked / expired ──► 401
        │                       │  ── suspended customer / owner disabled ──────────► 403
        │                       ▼
        │                     Principal.machine(token_id, tenant_id)
        │
        ▼
providers.resolve()      which customer's provider signed this, and is it genuine
        │                 ── unregistered issuer / bad signature / wrong aud ──► 401
        ▼
users.resolve()          who this is, creating them if their provider may vouch
        │                 ── unlisted domain / disabled account ──► 403
        ▼
Principal.user(id, tenant_id)        the tenant from OUR row, never from a claim
```

Both branches take the tenant from **our** row — a `tenant_idps` row for a person, an
`api_tokens` row for a machine — and never from anything the caller sent.

401 and 403 are not interchangeable. A 401 means *authenticate again* — the token is
expired, forged, or not ours. A 403 means *authenticating again will not help* — you
are genuinely who you say and still may not use this. Collapsing them makes a UI either
loop on a login that cannot succeed, or give up on one that would.

## The second gate, added in 12b

`admin_from_request` sits beside `principal_from_request` and depends on it, so an
administrative route gets **401 then 403** in that order rather than either alone. It is a
dependency and not a line inside each route for the reason `test_every_endpoint_is_sync`
exists: a rule enforced by remembering is a rule that is already broken somewhere you have
not looked.

**HTTP structurally cannot produce a `system` principal** — every path through this file
ends at `users.resolve` or `tokens.resolve`, which return `Principal.user(...)` and
`Principal.machine(...)`. `access/roles.py` treats `system` as always-admin and that is
only safe because of this sentence, so `test_http_can_never_mint_a_system_principal` pins
it here rather than trusting it, and its sibling pins the same property on
`access/tokens.py` — the file that could have broken it, and the reason a machine caller
is a third principal kind rather than a `system` one.

## The second door, added in 020

A machine caller presents `art_<id>.<secret>` instead of a JWT and resolves through
`access/tokens.py`. It is dispatched on the credential's *shape*, before anything is
verified, and there is no fallback between the two paths. What arrives is a `machine`
principal, which is an administrator nowhere: `roles.is_admin` has no branch for it and
`check_platform_role` refuses to give it one.

## The tenant is never a path or query parameter

    GET /agents                 ✓   tenant comes off the principal
    GET /tenants/{t}/agents     ✗   never

A tenant in the URL is the caller asserting *which customer's data to read*, which is
precisely the assertion this module exists to refuse. It would also be enforced by
remembering to check it on every route, which is the same shape as the missed-`WHERE`
leak already documented as a known limit.

## What used to be here

`X-Dev-Principal` and `AGENT_RUNTIME_INSECURE_DEV_AUTH` (the name it actually had —
it was deleted long before the rename): a header that was trusted, so
any caller could act as any user in any tenant. It was the entire authentication story
for one step, and it is **deleted** rather than switched off — a bypass that outlives
the thing it stood in for is the one that gets left on. `tests/test_api.py` fails if
that header is ever honoured again.
"""

import logging

from fastapi import Depends, Header, HTTPException

from ..access import TokenError, TokenExpired, providers, roles, tokens, users
from ..access.users import AccessDenied
from ..core import Principal
from ..storage import tenancy

log = logging.getLogger(__name__)

# The per-process JWKS cache is `providers.KEYS` since 033c — the MCP door became a
# second verifier (`access/acting.py`), and two caches fetching the same `jwks_uri`
# would double the load on a customer's IdP while both claiming to be "the" process
# cache. Deliberately no alias here: a test that patched a `deps.KEYS` copy would make
# the browser door and the MCP door verify against different keys, which is exactly
# the disagreement one name exists to prevent.


def principal_from_request(
    authorization: str | None = Header(default=None),
) -> Principal:
    """Build the `Principal` this request acts under, or refuse.

    **Two doors, chosen by the shape of the credential**, and neither ever falls back to
    the other: a malformed machine token is refused as one rather than retried as a JWT.
    A resolver that tried both would produce two reasons for one failure and log the
    wrong one — and the shapes cannot collide, because a JWT is base64 of `{"alg"...`
    and begins `eyJ`.

    One `try` covering both, so the machine door inherits all three refusals exactly as
    written rather than growing its own copies. This merged what were two adjacent
    blocks; it is behaviour-preserving for the human path, because `providers.resolve`
    raises no `AccessDenied` and `users.resolve` raises no `TokenError`.

    **This is also where the request's tenant scope is bound** (step 029): the moment a
    credential resolves to a `Principal`, the cell the middleware installed learns its
    tenant, and every storage borrow the endpoint makes runs as the tenant-scoped
    database role. Here rather than per endpoint, because this dependency is the one
    door every authenticated route already passes through — a new route is scoped by
    construction, not by remembering. The lookups *inside* this function (`find_user`,
    `find_api_token`) necessarily run unscoped: they are the queries that produce the
    tenant, so no scope can precede them.
    """
    token = _bearer(authorization)

    try:
        if tokens.looks_like_api_token(token):
            principal = tokens.resolve(token)
        else:
            provider, claims = providers.resolve(token, providers.KEYS)
            principal = users.resolve(provider, claims)
        tenancy.scope_to(principal.tenant_id)
        return principal
    except TokenExpired as exc:
        # Told apart from every other 401 because a client can act on it: refresh and
        # retry, rather than prompting somebody who is already signed in.
        raise HTTPException(
            status_code=401,
            detail="token expired",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        ) from exc
    except TokenError as exc:
        # The reason goes to the log, not to the caller. Telling an attacker which half
        # of their guess was wrong is free help — which is why `tokens.resolve` raises
        # *this* class for a revoked or expired token rather than a class of its own:
        # the sentence is then identical by construction rather than by two strings
        # being kept in step.
        log.info("rejected token: %s", exc)
        raise HTTPException(
            status_code=401,
            detail="not a valid token for this service",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        ) from exc
    except AccessDenied as exc:
        # 403: genuinely authenticated, and still not allowed. The message IS returned
        # here, because it is actionable by a person — "your domain is not registered"
        # is something they take to their admin, and "this token's owner has left" is
        # something they take to whoever owns the pipeline.
        log.info("denied access: %s", exc)
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def admin_from_request(
    principal: Principal = Depends(principal_from_request),
) -> Principal:
    """The same principal, refused unless they may administer this tenant.

    **A dependency rather than a line at the top of each route**, and that is the whole
    reason it exists. A per-route check is a rule that lives in a docstring, which is a
    rule somebody breaks in six months — and this one is invisible until an incident,
    because the failure is a route that *works* for somebody who should have been refused.
    `test_every_admin_route_carries_the_dependency` walks the route table and compares it
    against `ADMIN_SURFACE` below, the same device `test_every_endpoint_is_sync` uses.

    **The ordering is load-bearing: authentication first, then the role.** It comes for
    free from the `Depends` chain — `principal_from_request` must answer before this body
    runs — and it has to. A 403 to an unauthenticated caller would tell somebody who has
    not even proved a tenant that this route exists. Cheap to get right now, incoherent to
    fix later.

    A 403 rather than a 404, which inverts what agent routes do. See `RoleRequired`: an
    agent's existence is a secret worth keeping and `/admin-audit`'s is not, because the
    route is in the OpenAPI document and is identical for every tenant.
    """
    roles.require_admin(principal)
    return principal


# Every route that must carry `admin_from_request`, written down so that adding one and
# forgetting the dependency is a failing test rather than an open door.
#
# **Two directions, both asserted.** A route in this set without the dependency is the
# obvious failure; a route *with* the dependency that is not in this set is the other one
# — it means somebody closed a surface without saying so here, and the next person reading
# this list would believe the wrong thing about what the product exposes.
#
# `GET /me` and `GET /groups` are deliberately absent. `/me` answers "who am I, here" and
# a non-admin needs it precisely to be told they are not one; `GET /groups` is the menu an
# `editor` picks from when sharing — see `access/groups.list_groups`.
#
# **12c's ten routes are the reason this test earns itself twice over.** 12b's harder pass
# found that on the group routes the dependency is behaviourally *invisible* — every one
# of them goes through `access/groups.py`, which does its own `require_admin`, so removing
# either guard alone changes no behaviour at all and no amount of driving the product can
# tell you it is still there. The connector routes below are worse in the same direction:
# `tools.register_connector`, `storage.allow_host` and `mcp.discovery.discover` check **no
# role at all** — they were written for a CLI whose caller is `system` and always an
# administrator. For those, this dependency is not defence in depth. It is the only thing
# standing between any authenticated employee and registering a connector.
ADMIN_SURFACE = frozenset(
    {
        ("GET", "/admin-audit"),
        # 015 — the access-denial log. Reading it needs the role, and a non-admin's
        # attempt on it is itself recorded: the log records its own door.
        ("GET", "/admin/denials"),
        # 035a — the MCP door's traffic. A reader over `audit`, filtered to the rows a
        # run can never have written, and admin surface for the reason the denial log is:
        # it is every caller's activity, not the reader's own.
        ("GET", "/admin/door-calls"),
        # 041 — the overview. Admin surface for the reason the two logs above are: it is
        # every caller's activity aggregated, not the reader's own. The audience it was
        # built for is a manager rather than an administrator, and that tension is real
        # and unresolved — a read-only `viewer` platform role is the honest answer and is
        # its own step, because `platform_roles` CHECKs `'admin'` alone. Until then this
        # sits with the rest, because the alternative is a tenant-wide governance read
        # that anybody authenticated can make.
        ("GET", "/admin/overview"),
        # 013b — the tenant's model spend, per agent and per person. Here for
        # `/admin/overview`'s reason exactly: the *totals* are a fact about the
        # deployment and ride on `/me/usage` for everybody, while **who spent them** is
        # a fact about colleagues and needs the role.
        # 057 — the Prometheus scrape. Every caller's operational state and nobody's
        # data, the logs' standing exactly; a scraper carries an admin machine token.
        ("GET", "/metrics"),
        ("POST", "/groups"),
        ("GET", "/groups/{group_id}"),
        # 033e — linking a group to a directory group. Admin surface for the reason
        # `connector.asserted_identity` is: it decides who may change who is in it.
        ("PATCH", "/groups/{group_id}"),
        ("DELETE", "/groups/{group_id}"),
        ("PUT", "/groups/{group_id}/members/{member_kind}/{member_id}"),
        ("DELETE", "/groups/{group_id}/members/{member_kind}/{member_id}"),
        # 12c — connector onboarding. See `routes_admin_connectors.py`.
        ("GET", "/admin/hosts"),
        ("POST", "/admin/hosts"),
        ("DELETE", "/admin/hosts/{host}"),
        ("GET", "/admin/connectors"),
        ("POST", "/admin/connectors"),
        # 068 — the connector recipes this build ships. Identical for every tenant and
        # in the public repository, so this is not secrecy: it is a control on the
        # registration screen, and a route answering to any signed-in caller invites a
        # client to render an administrative affordance to somebody who cannot use it.
        # The same reasoning `GET /admin/hosts` applies to a list of hostnames.
        ("GET", "/admin/recipes"),
        ("GET", "/admin/connectors/{connector_id}"),
        ("POST", "/admin/connectors/{connector_id}/discovery"),
        ("PUT", "/admin/connectors/{connector_id}/tools/{remote_name}"),
        # 033c — a security control being switched, so it is admin surface by
        # definition: what it toggles is whether the MCP door believes an unverified
        # acting-for for this connector's tools.
        ("PUT", "/admin/connectors/{connector_id}/asserted-identity"),
        ("PUT", "/admin/connectors/{connector_id}/oauth"),
        ("DELETE", "/admin/connectors/{connector_id}/oauth"),
    }
)


# Every route that carries **no** principal at all, written down for the reason
# `ADMIN_SURFACE` is: a route that authenticates nobody is a decision, and a decision
# that lives only in the route's own file is one the next reader cannot see. Compared in
# both directions by `test_every_open_route_is_listed_and_argued`: an unlisted open
# route fails, and a listed route that grew a dependency fails too.
#
# Three existed before step 083 — the two probes, and the connector callback, which
# authenticates on a server-side single-use `state` because a provider's redirect is a
# top-level navigation with no bearer on it. 083 adds four, each for a reason the plan
# states: a client that holds nothing yet has to be able to read where to authenticate
# (the two `.well-known` documents, RFC 9728 and 8414), register itself (RFC 7591), and
# exchange a code it proves possession of with a PKCE verifier (RFC 6749) — a bearer at
# that last one would be the mint-for-a-bearer `access/tokens.py` refuses.
OPEN_SURFACE = frozenset(
    {
        ("GET", "/health"),
        ("GET", "/health/ready"),
        ("GET", "/connect/callback"),
        ("GET", "/.well-known/oauth-protected-resource"),
        ("GET", "/.well-known/oauth-protected-resource/{rest:path}"),
        ("GET", "/.well-known/oauth-authorization-server"),
        ("POST", "/oauth/register"),
        ("POST", "/oauth/token"),
    }
)


def _bearer(header: str | None) -> str:
    if not header:
        raise HTTPException(
            status_code=401,
            detail="an Authorization: Bearer token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=401,
            detail="Authorization must be 'Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token.strip()
