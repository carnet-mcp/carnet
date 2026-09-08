"""Outbound OAuth: obtaining a token from somebody else's authorization server.

Step 7b. This is the module that lets a person click **Connect Jira**, approve at
*Jira's* consent screen, and end up with a credential of their own in the row 7a already
built — without the token ever touching their browser or the operator's terminal.

## This is not `oidc.py`, and the direction is the whole reason

The tempting shortcut is *"we already do OAuth — reuse `oidc.py`"*. It is wrong, and it
is wrong in a way that produces working-looking code:

    oidc.py     INBOUND.  A customer's IdP signs a token whose `aud` is **us**, and we
                verify the signature and the audience to decide who is calling. We are
                the resource server. The module is entirely *verification*, and it holds
                no secrets at all.

    this        OUTBOUND. We are the **client** of a third party's authorization server,
                obtaining a token whose audience is **that server**, to hold and use
                server-side on somebody's behalf. We hold a client secret. Nothing here
                verifies a signature, because nothing here receives a token that is
                about us.

A building badge opens the office, not your bank account. Jira has never heard of the
Okta token that got somebody into this product and would reject it, which is why the two
credentials cannot be the same credential and these cannot be the same code.

The consequence that matters most: **the connector token must never reach the browser.**
Login's token is for us, and the SPA holds it in memory to call our own API. A connector
token is for Jira and is used server-side, so a browser holding it is an exfiltration
surface for zero benefit. It goes from the provider's token endpoint straight into
`connections` and is never sent outward again except as a header on a call the broker
has already authorised.

## Where this sits, and why it is not in the runtime

`access/` — above `core/`, and that placement is forced rather than chosen. The import
graph, checked rather than remembered:

    core/broker.py              from ... import tools as tool_registry     core → tools
    access/connections.py       from ..core import crypto                  access → core

`core` already depends on `tools` and `access` already depends on `core`, so `core`
importing `access` is a cycle and a layering inversion at once — a runtime cannot reach
an access-layer refresh. It also could not go in `core/credentials.py` even if the graph
allowed it: that module is on the hot path of every tool call and is deliberately
read-only and network-free, and a token endpoint round trip there would make every call
wait on a third party.

So the refresh happens **before the run**, and `runs.execute` is where it is invoked.
Plan 007b's decision 5 states the cost as *"`run_agent` is reached from more than one
entry point, so each has to call the refresh before it"*, and that turned out to
overstate it: `runs.execute` is the **only** caller of `run_agent` in this codebase — the
every caller arrives through it, which is the seam the broker exists to be. One
call, in one place, and `test_every_path_to_a_run_refreshes_first` is what keeps it that
way rather than hope.

## What is deliberately not here

**Dynamic Client Registration (RFC 7591)** and **protected-resource-metadata discovery
(RFC 9728)**, which the MCP authorization spec recommends. GitHub, Atlassian and Google
all require a pre-registered app today, so DCR is the spec-ideal path most real servers
do not offer, and discovery only saves an admin from pasting two URLs. Both return
behind this same storage: a connector that supports DCR fills `client_id` and
`client_secret` automatically instead of by hand, and nothing else changes.
"""

import base64
import hashlib
import json
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from .. import storage, tools
from ..storage import tenancy
from ..config import REQUEST_TIMEOUT
from ..core import crypto
from ..tools.mcp import egress
from . import connections
from .connections import OAuthTokens

log = logging.getLogger(__name__)

# How long a consent flow may stay in flight. Long enough for somebody to read a consent
# screen and find their password manager; short enough that an abandoned flow is not a
# row with a secret in it sitting around all afternoon.
PENDING_TTL_SECONDS = 15 * 60

# How much of an access token's life to treat as already spent. A token that expires in
# nine seconds is a token that expires halfway through the run about to start, and
# refreshing it costs one round trip against a run that would otherwise fail on its
# second tool call.
#
# This is the cheap half of the mid-run expiry named in the plan's known limits. It does
# not fix it — a long agent can still outlive a fresh token, and the real fix is
# finer-grained refresh in 7c — but it turns "expires during the run" from something that
# happens to every run started in the last minute of a token's life into something that
# needs a genuinely long run.
EXPIRY_SKEW_SECONDS = 120

# `secrets.token_urlsafe(32)` gives 43 characters from 256 bits. The floor in migration
# 024 and `check_pending_authorization` is 32; this is what we actually mint.
STATE_BYTES = 32
VERIFIER_BYTES = 32

# How often a thread that lost the single-flight race re-reads the row. Short, because
# what it is waiting for is one HTTP round trip and the whole wait sits on the run path;
# not zero, because a spin would burn a database connection per poll for no gain.
_WAIT_POLL_SECONDS = 0.05


class OAuthRefused(RuntimeError):
    """A consent flow cannot proceed, and the reason is safe to explain.

    `ConnectionRefused`'s sibling and for its reason: the caller is entitled to do what
    they asked and *this particular* request is wrong. It covers a connector with no
    consent flow configured, a `state` we never minted or have already spent, and a
    provider that answered the exchange with an error.
    """


class ReconsentRequired(OAuthRefused):
    """The grant is gone at the provider and only the person can restore it.

    Its own class because it is the one failure here whose fix is **not** an
    administrator's. A `400 invalid_grant` means consent was revoked, the refresh token
    expired, or it was already spent — and every one of those is terminal. It is never
    retried: retrying an `invalid_grant` is how one dead connection becomes a rate-limit
    incident at a customer's identity provider, and Atlassian additionally treats reuse
    of a spent refresh token as a breach signal and kills the whole grant.
    """


# --- the OAuth application ------------------------------------------------------------

# The refusal a stdio connector gets, written once because it now has two callers.
#
# **It used to live in `cli._set_oauth`, and 12c moved it down.** That is finding 3 of the
# plan and it is `groups.members`' lesson wearing a different hat: a guard in an entry
# point is a guard the *next* entry point does not have, and the next entry point was
# `PUT /admin/connectors/{id}/oauth`. A route calling `configure` directly would have let
# an administrator configure a consent flow on a stdio connector — the exact
# half-configured state this check exists to prevent, reachable through the new door.
#
# One sentence rather than two, deliberately. The CLI's version was longer than an API
# refusal usually is and the length is earned: this is the one refusal in the product
# whose remedy is *change your infrastructure*, and it costs three paragraphs to say what
# to change and why the platform's own connectors are the only ones it can happen to.
# Verification 2 asserts the two callers refuse **identically**, which is only checkable
# because there is one string.
STDIO_CONSENT_REFUSED = (
    "connector '{connector}' speaks stdio, and a consent flow produces a per-user "
    "credential. A stdio server takes its credential from the environment when it "
    "starts and holds it for as long as it runs, so it cannot act as two people — "
    "every user of every agent would share one service account.\n"
    "  Configuring a consent flow here would let somebody complete a screen at a third "
    "party, granting real access, for a credential this platform could never use. "
    "Refused now rather than at their first run.\n"
    "  Move the connector to the HTTP transport first. Connectors a customer registers "
    "are HTTP-only already; this only applies to the ones that ship with the platform."
)


def configure(
    tenant_id: str,
    connector_id: str,
    *,
    authorize_endpoint: str,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    revoke_endpoint: str = "",
    scopes=(),
    authorize_params=None,
    scope_notes=None,
    actor: str,
) -> dict:
    """Record the OAuth application for a connector. Returns what was stored, less secret.

    The client secret is sealed with the same crypto as a credential, because it is one.
    Bound to `(tenant, connector)` — see `crypto.oauth_app_aad` for why a primary key is
    not a substitute for that binding.

    **The token endpoint's host must be on the tenant's egress allowlist**, checked here
    at configuration time as well as at every use. This is finding 7: an OAuth flow adds
    a second way a stored row causes an outbound connection, and the token endpoint is
    the one that matters — a server-side POST carrying this deployment's client secret,
    the same risk class as dialling the MCP server. The authorize endpoint is
    deliberately **not** checked, because nothing of ours dials it: it is a redirect the
    browser follows, and an allowlist entry would be describing a connection we never
    make.

    Refusing here as well as at use is 012's redundancy and its argument: a refusal an
    admin gets while the command is still in their shell is one they can act on, where
    the same refusal three days later at somebody's first Connect is a mystery. The
    check at use is the load-bearing one, because a host can be revoked after it was
    approved.

    **The transport check is here as of 12c and used to be in the CLI** — see
    `STDIO_CONSENT_REFUSED`. It runs first, before the secret is even looked at, because
    the answer does not depend on anything the caller sent: a stdio connector cannot hold
    a consent flow whatever the rest of the request says, and refusing before reading a
    secret means a refused request is one where no secret was handled at all.
    """
    # Before the secret, and before the egress check. `get_connector` is also the
    # existence check: `set_connector_oauth` would refuse an unregistered connector with
    # a `NoSuchConnectorError`, which is a `StorageError` and therefore a 503 — "try
    # again later" about a connector that will never exist. The same shape 011's
    # `NoSuchGroupError` had, caught before it could ship.
    connector = tools.mcp.get_connector(tenant_id, connector_id)
    if connector is None:
        raise OAuthRefused(
            storage.NO_SUCH_CONNECTOR_TO_VET.format(
                connector=connector_id, tenant=tenant_id
            )
        )

    if not tools.mcp.supports_delegation(connector):
        raise OAuthRefused(STDIO_CONSENT_REFUSED.format(connector=connector_id))

    if not (client_secret or "").strip():
        raise OAuthRefused(
            "a client secret is required. This is a confidential client — the secret is "
            "what lets the exchange happen on the server, which is what keeps the "
            "resulting token out of the browser. A public client (PKCE only) would put "
            "a third party's credential in a page whose only job is then to post it "
            "back to us."
        )

    # Before anything is sealed or stored, so a refused host leaves nothing behind.
    egress.check(tenant_id, token_endpoint)

    aad = crypto.oauth_app_aad(tenant_id, connector_id)
    ciphertext, key_id = crypto.seal(
        client_secret.strip(), tenant_id=tenant_id, aad=aad
    )

    storage.active().set_connector_oauth(
        tenant_id,
        connector_id,
        authorize_endpoint=authorize_endpoint,
        token_endpoint=token_endpoint,
        revoke_endpoint=revoke_endpoint or "",
        client_id=client_id,
        client_secret=ciphertext,
        key_id=key_id,
        scopes=scopes,
        # Provider-specific, and the first real provider needed two. See migration 025:
        # Atlassian mandates `audience` and `prompt`, which nothing here builds.
        authorize_params=authorize_params,
        # Migration 051. Refused by `normalize_scope_notes` if it describes a scope this
        # flow does not request — checked in the storage layer rather than here, beside
        # the scopes it is checked against, on `redact_args`' precedent.
        scope_notes=scope_notes,
        actor=actor,
    )
    return next(
        row
        for row in storage.active().list_connector_oauth(tenant_id)
        if row["connector_id"] == connector_id
    )


def unconfigure(tenant_id: str, connector_id: str, *, actor: str) -> bool:
    """Remove a connector's consent flow. Returns whether one was there."""
    return storage.active().delete_connector_oauth(
        tenant_id, connector_id, actor=actor
    )


def configured(tenant_id: str) -> dict:
    """`connector_id -> the public OAuth configuration`, for this tenant.

    A dict rather than a list because every caller is asking *about a connector they
    already have* — the Connections page joins it against the vetted connectors, and the
    third state on that screen is exactly a connector absent from these keys.
    """
    return {
        row["connector_id"]: row
        for row in storage.active().list_connector_oauth(tenant_id)
    }


def _app(tenant_id: str, connector_id: str) -> dict:
    """The OAuth application with its client secret opened, or a refusal.

    The one place the secret is in plaintext, and it is a local variable in whatever
    called this. It is never stored on an object, never logged, and never returned to a
    route.
    """
    row = storage.active().get_connector_oauth(tenant_id, connector_id)
    if row is None:
        raise OAuthRefused(
            f"connector '{connector_id}' has no consent flow configured, so there is "
            "nothing to connect to. An administrator sets one up with:\n"
            f"  carnet --set-oauth {connector_id} --auth-server <url> "
            "--client-id <id> --client-secret-stdin\n"
            "Until then this connector's credential is a token somebody pastes in."
        )

    secret = crypto.open_(
        row["client_secret"],
        tenant_id=tenant_id,
        aad=crypto.oauth_app_aad(tenant_id, connector_id),
        key_id=row["key_id"],
    )
    return {**row, "client_secret": secret}


# --- starting a flow --------------------------------------------------------------------


def begin(principal, connector_id: str, *, redirect_uri: str, return_to: str = "") -> str:
    """Mint a pending authorization and return the URL to send this person's browser to.

    Called from an authenticated request, which is the only moment in the whole flow at
    which we know whose connection this is — see `complete` for why that is the design
    rather than an accident.

    PKCE (RFC 7636) is generated here and the *verifier* is sealed into the row while
    only its **challenge** goes into the URL. That asymmetry is the point of PKCE: the
    thing that travels through the browser and the provider's website is a hash, and the
    thing that proves we are the same client at the exchange never leaves this server.
    """
    # Before anything is minted, and turned into this module's own exception so the
    # route answers 400 rather than the 503 a bare `StorageError` becomes. The same check
    # runs again inside `create_pending_authorization`, which is where it is load-bearing
    # — 012's redundancy argument, applied to a value that would become a redirect.
    try:
        storage.check_return_to(return_to)
    except storage.StorageError as exc:
        raise OAuthRefused(str(exc)) from exc

    app = _app(principal.tenant_id, connector_id)

    state = secrets.token_urlsafe(STATE_BYTES)
    verifier = secrets.token_urlsafe(VERIFIER_BYTES)

    sealed, key_id = crypto.seal(
        verifier,
        tenant_id=principal.tenant_id,
        aad=crypto.pending_authorization_aad(principal.tenant_id, state),
    )

    # The row before the URL. A URL handed out for a `state` that failed to store is a
    # person sent to a consent screen whose approval nothing can accept — and they would
    # find out after granting access to a third party, which is the worst possible place
    # for this ordering to be wrong.
    storage.active().create_pending_authorization(
        state,
        principal.tenant_id,
        principal_kind=principal.kind,
        principal_id=principal.id,
        connector_id=connector_id,
        code_verifier=sealed,
        key_id=key_id,
        redirect_uri=redirect_uri,
        return_to=return_to,
    )

    # **The stored parameters go in first, and ours overwrite them.** Migration 025 and
    # `RESERVED_AUTHORIZE_PARAMS` already refuse the seven names this builds, so the
    # collision cannot happen through `--set-oauth` — this ordering is the second lock on
    # the same door, for a row written by some future path that forgot to validate. The
    # two that matter are `state`, which is the only thing binding a callback to the
    # person who started it, and `redirect_uri`, which decides where their authorization
    # code is delivered.
    query = {
        **(app.get("authorize_params") or {}),
        "response_type": "code",
        "client_id": app["client_id"],
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": _challenge(verifier),
        "code_challenge_method": "S256",
    }
    if app["scopes"]:
        query["scope"] = " ".join(app["scopes"])

    # A query string on the endpoint still works and is no longer the only way. It was the
    # only way until a real Atlassian flow needed `audience` and `prompt` — see migration
    # 025 for why that worked by accident and why the column exists now.
    separator = "&" if "?" in app["authorize_endpoint"] else "?"
    return f"{app['authorize_endpoint']}{separator}{urlencode(query)}"


def _challenge(verifier: str) -> str:
    """S256, per RFC 7636 — base64url of the SHA-256 digest, **without padding**.

    The padding matters and is the classic way to get this subtly wrong: `=` is not in
    the base64url character set the spec names, and providers differ in whether they
    reject it or strip it — so a padded challenge works against some servers and fails
    against others with an error that says nothing about padding.
    """
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


# --- finishing a flow -------------------------------------------------------------------


def complete(state: str, code: str) -> dict:
    """Exchange an authorization code for a token and seal it. Returns what to report.

    **This trusts `state` and nothing else about the request, and that is the security
    crux of the whole step.** When the provider redirects the browser here, the request
    is a plain top-level navigation: the SPA's bearer token lives in memory and is not on
    it, so there is no `Authorization` header, no principal, and no tenant. Every one of
    those comes out of the row `state` is a handle on — which we minted at `begin`, while
    the person *was* authenticated.

    That also makes it the CSRF defence the callback needs. An attacker cannot forge a
    `state` we never minted, and cannot replay one: the row is consumed atomically, so a
    second callback carrying the same value finds nothing. Both of those are properties
    of `consume_pending_authorization` being one `DELETE ... RETURNING` rather than of
    anything written here.

    Returns a small dict for the caller to render — the connector, the verified account
    label, and where to send the browser. **Never a token**, and there is no argument
    that would make it return one.
    """
    # **A callback with neither a code nor an error is malformed, and is refused before
    # anything is spent.** RFC 6749 says the provider returns one or the other; getting
    # neither means a truncated redirect, a proxy that dropped the query, or somebody
    # hand-assembling a URL. Found by driving the callback at its edges: without this,
    # `state` was consumed and an empty `code` was POSTed to the provider — an outbound
    # request we already know is nonsense, whose refusal we then report as though the
    # provider had decided something.
    #
    # Checked **before** the row is consumed, unlike the expiry below, and the asymmetry
    # is deliberate: an expired state is a flow that genuinely happened and must not be
    # replayable, while this one never carried an authorization at all. Burning somebody's
    # pending row because a proxy mangled their redirect would make a recoverable problem
    # unrecoverable.
    if not code:
        raise OAuthRefused(
            "the provider sent us back without an authorization code and without saying "
            "why. Nothing was stored. This usually means the redirect was truncated on "
            "the way — try connecting again."
        )

    pending = storage.active().consume_pending_authorization(state)
    if pending is None:
        raise OAuthRefused(
            "this sign-in link is not one we issued, or it has already been used. "
            "Consent links are single-use and expire in a few minutes. Start again from "
            "the Connections page."
        )

    age = datetime.now(timezone.utc) - pending["created_at"]
    if age > timedelta(seconds=PENDING_TTL_SECONDS):
        # The row is already gone — consumed above — so an expired flow costs nothing to
        # clean up and cannot be retried. Checked after consuming rather than before
        # precisely so that an expired `state` is also a spent one.
        raise OAuthRefused(
            "this consent flow took too long and has expired. Nothing was stored. "
            "Start again from the Connections page."
        )

    tenant_id = pending["tenant_id"]
    connector_id = pending["connector_id"]
    principal = _principal_of(pending)

    # The callback arrives with no bearer, so `principal_from_request` never ran and
    # the middleware's cell is still empty; the state row is what produces the tenant,
    # and the scope is bound the moment it does. Everything inside the bracket — the
    # OAuth app read, the token exchange bookkeeping, storing the connection — runs as
    # the tenant-scoped database role. A bracket rather than a set-and-forget because
    # tests call this function directly and a scope must not outlive the flow it was
    # opened for. Step 029, and the same late binding the trigger door had until 078; the
    # `consume_pending_authorization` above is necessarily unscoped — it is the lookup
    # that produces the tenant.
    with tenancy.scoped(tenant_id):
        verifier = crypto.open_(
            pending["code_verifier"],
            tenant_id=tenant_id,
            aad=crypto.pending_authorization_aad(tenant_id, state),
            key_id=pending["key_id"],
        )

        app = _app(tenant_id, connector_id)
        payload = _token_request(
            tenant_id,
            app,
            {
                "grant_type": "authorization_code",
                "code": code,
                # Byte-identical to what `begin` sent, because it is the same stored
                # string rather than a second reconstruction. Recomputing it here from
                # a request header is how a deployment behind a proxy earns an
                # `invalid_grant` that reads like a code bug.
                "redirect_uri": pending["redirect_uri"],
                "code_verifier": verifier,
            },
        )

        tokens = _tokens_from(payload)
        label = _account_label(payload)

        row = connections.connect_account(
            principal,
            connector_id,
            tokens,
            account_label=label,
            # The person themselves. **The first administrative record in this system
            # whose actor and subject are the same principal**, and correctly so: a
            # consent flow is something somebody does to themselves, and that is
            # exactly what distinguishes it from `--connect-account`, where an operator
            # holds their token.
            actor=str(principal),
        )

    return {
        "connector_id": connector_id,
        "account_label": row["account_label"],
        "return_to": pending["return_to"],
        "tenant_id": tenant_id,
        "principal": principal,
        # So a caller can say "it works until Tuesday" rather than nothing. Never the
        # token, and there is nothing in this dict that would help anybody who stole it.
        "expires_at": row["expires_at"],
    }


def _principal_of(pending: dict):
    """The principal a pending row names. Built here so `complete` reads as one story."""
    from ..core import Principal

    return Principal(
        kind=pending["principal_kind"],
        id=pending["principal_id"],
        tenant_id=pending["tenant_id"],
    )


def _account_label(payload: dict) -> str:
    """Whose account this is, according to the provider. Decision 6, and it is free.

    7a's README flagged that `account_label` is *"whatever somebody typed"*, because the
    platform ships no integrations and cannot ask an arbitrary MCP server whose token
    this is — and predicted that *"7b's OAuth flow gets it from the token response for
    free"*. It does, when the provider volunteers it.

    Three places it can be, in order of how much they are worth trusting:

      1. an `id_token`'s claims, which is OIDC and therefore standardised
      2. a top-level `email` / `username` / `account` on the token response, which
         several providers add and none are required to
      3. nowhere, which is the common case for a plain OAuth 2 server

    **The `id_token` is read, not verified**, and that is a deliberate and stated
    limitation rather than an oversight. Verifying it means fetching and caching that
    provider's JWKS — which is `oidc.py`'s entire job, for tokens whose audience is us —
    and the value would still only ever be a display string beside a Disconnect button.
    It is never used to decide anything: the principal comes from the `state` row, which
    we minted, and no claim in here can change it. If this label is ever consulted for an
    authorization decision, it has to be verified first, and that is what this paragraph
    is for.
    """
    for key in ("email", "username", "account", "name"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:200]

    raw = payload.get("id_token")
    if isinstance(raw, str) and raw.count(".") == 2:
        try:
            body = raw.split(".")[1]
            claims = json.loads(
                base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
            )
        except Exception:  # noqa: BLE001 - a label is never worth failing a connection
            return ""
        for key in ("email", "preferred_username", "sub"):
            value = claims.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()[:200]

    return ""


# --- keeping a token fresh ----------------------------------------------------------


def refresh_for_run(principal, config: dict) -> list[str]:
    """Refresh whatever this agent's connectors need, before the run starts.

    Returns the connector ids that were actually refreshed, which is for logging and for
    a test to assert against rather than for any caller to branch on.

    Called from `runs.execute` — see the module docstring for why that is one place and
    not four. It is deliberately best-effort **per connector**: an agent granting tools
    from two connectors, one of whose providers is down, still runs and still reaches the
    other. What it does *not* do is swallow the failure — a connection whose grant is
    gone is marked as needing re-consent, so the run then fails at the credential read
    with a sentence naming the connector, rather than silently falling back to the
    operator's credential.

    **A run can now be delayed by a third party's identity provider**, which is new and
    worth stating: before this step nothing on the run path made an outbound call before
    the first tool call. It is bounded by `REQUEST_TIMEOUT`, paid at most once per run
    per connector, and skipped entirely for a token with life left on it — which is every
    run but the first of each hour.
    """
    refreshed = []
    for connector in tools.connectors_for_agent(config, principal.tenant_id):
        try:
            if refresh_connection(principal, connector.id):
                refreshed.append(connector.id)
        except ReconsentRequired:
            # Already recorded on the row by `refresh_connection`. Not re-raised: the
            # run may not even touch this connector's tools, and failing a whole run for
            # a connection it might not use would be worse than failing at the call that
            # needs it — which is where `for_connector` now raises with the reason.
            log.info(
                "connection to %s for %s needs re-consent", connector.id, principal
            )
        except OAuthRefused as exc:
            # No consent flow configured is the overwhelmingly common case here and is
            # not an error at all: a connector whose credential is a pasted token has
            # nothing to refresh.
            log.debug("no refresh for %s: %s", connector.id, exc)
        except Exception:  # noqa: BLE001 - a provider being down must not lose the run
            log.exception(
                "could not refresh the connection to %s for %s", connector.id, principal
            )
    return refreshed


def refresh_connection(principal, connector_id: str, *, force: bool = False) -> bool:
    """Renew one connection's access token if it needs it. Returns whether it did.

    This is decision 11, and it is two mechanisms answering two different halves.

    **The single-flight lock** makes the common case cost one token-endpoint call rather
    than N. Eight runs for one person starting together — the ordinary case, because
    `POST /runs` is a queue with a worker — would otherwise make eight exchanges, of
    which seven come back `invalid_grant` because most providers rotate refresh tokens
    and kill the old one on every use. Seven failures is not just waste: it is eight
    requests with a spent credential arriving at a customer's identity provider inside a
    second, which is what credential stuffing looks like from their side.

    **The compare-and-set** makes a lost update impossible even if the lock is not held —
    two processes, a lock that expired, a store that does not have one. It is the
    `update_agent` device for the `update_agent` reason, and the stakes are higher here:
    a lost update stores a refresh token the provider has *already invalidated*, so the
    connection is permanently broken with nothing anywhere saying why.

    **A refresh that loses the race re-reads; it never retries.** The refresh token it
    holds has been spent by the winner, and exchanging a spent refresh token is the thing
    Atlassian treats as a breach signal. The winner has already written a good token, so
    the correct response to losing is to use it.
    """
    store = storage.active()

    with store.refresh_lock(
        principal.tenant_id, principal.kind, principal.id, connector_id
    ) as holding:
        if not holding:
            # Somebody else is refreshing this connection right now. **Wait for them and
            # use what they store — never refresh anyway.** The refresh token this thread
            # can see is the one the winner is in the middle of spending, so exchanging it
            # is the reuse a rotating provider treats as a breach signal.
            #
            # The wait happens here, outside the lock and outside any database
            # connection, which is the whole point of the lock being `try` rather than
            # blocking — see `PostgresStorage.refresh_lock`.
            return _wait_for_the_winner(principal, connector_id)

        # Read **inside** the lock. Reading outside it and refreshing inside is the
        # check-then-act that makes the lock decorative: seven waiters would each wake up
        # holding the stale row they read before queueing and refresh it anyway, spending
        # the refresh token the winner just obtained.
        row = store.find_connection(
            principal.tenant_id, principal.kind, principal.id, connector_id
        )
        if row is None or row.get("credential_kind") != storage.OAUTH_CREDENTIAL:
            # No connection, or a pasted token. Neither is refreshable and neither is a
            # failure: a static credential is somebody's PAT and only they can rotate it.
            return False

        if row.get("reconsent_reason"):
            raise ReconsentRequired(row["reconsent_reason"])

        if not force and not _stale(row):
            # The overwhelmingly common path, and the reason the lock is cheap: a run
            # that starts within an hour of the last one does no I/O at all here.
            return False

        stored = crypto.open_(
            row["ciphertext"],
            tenant_id=principal.tenant_id,
            aad=crypto.connection_aad(
                principal.tenant_id, principal.kind, principal.id, connector_id
            ),
            key_id=row["key_id"],
        )
        try:
            refresh_token = json.loads(stored).get(OAuthTokens.REFRESH) or ""
        except ValueError:
            refresh_token = ""

        if not refresh_token:
            # A provider that issued none — no `offline_access`, or a server that simply
            # does not. Surfaced as re-consent rather than as a failure, because that is
            # honestly what it is: this connection works until the access token expires
            # and then the person has to approve again. Not fixable from our side.
            _mark_reconsent(
                principal,
                connector_id,
                "this connection has no refresh token, so it cannot be renewed "
                "automatically. Connect the account again.",
            )
            raise ReconsentRequired(
                f"the connection to '{connector_id}' carries no refresh token"
            )

        app = _app(principal.tenant_id, connector_id)
        try:
            payload = _token_request(
                principal.tenant_id,
                app,
                {"grant_type": "refresh_token", "refresh_token": refresh_token},
            )
        except ReconsentRequired as exc:
            _mark_reconsent(principal, connector_id, str(exc))
            raise

        tokens = _tokens_from(payload)
        if not tokens.refresh_token:
            # A provider that rotates gives a new one; a provider that does not omits the
            # field and means "keep using the one you have". Dropping it on the second
            # reading would break the connection at the *next* refresh rather than this
            # one, which is the kind of bug that gets attributed to the provider.
            #
            # **And the expiry is kept with the token — 035f, found by testing the field
            # that chunk had just put on a screen.** `update_connection_credential` writes
            # `refresh_expires_at` unconditionally, so a provider that answered *how long
            # does the refresh token live* at consent time and stayed quiet on the refresh
            # had that answer erased — while the refresh token itself was byte-identical.
            # The row then claimed to know nothing about a token whose lifetime it did
            # know, and the Connections page's *"this connection lapses on 26 February"*
            # silently became no sentence at all after the first run.
            #
            # This is `account_label`'s `COALESCE` and its argument — *"overwriting a
            # verified label with '' because the provider stayed quiet would lose the only
            # thing on this row a person recognises"* — applied to the one branch where
            # the credential did not change.
            #
            # **Deliberately not applied to the rotating branch below.** There the
            # provider issued a *different* refresh token, so the old expiry describes a
            # credential that no longer exists; carrying it forward would be a confident
            # claim about the wrong token, which is worse than null. Null there means
            # exactly what it means everywhere else on this column: the provider did not
            # say.
            tokens = OAuthTokens(
                access_token=tokens.access_token,
                refresh_token=refresh_token,
                expires_at=tokens.expires_at,
                refresh_expires_at=tokens.refresh_expires_at or row["refresh_expires_at"],
            )

        sealed, key_id = crypto.seal(
            tokens.sealed_form(),
            tenant_id=principal.tenant_id,
            aad=crypto.connection_aad(
                principal.tenant_id, principal.kind, principal.id, connector_id
            ),
        )

        updated = store.update_connection_credential(
            principal.tenant_id,
            principal.kind,
            principal.id,
            connector_id,
            ciphertext=sealed,
            key_id=key_id,
            expires_at=tokens.expires_at,
            refresh_expires_at=tokens.refresh_expires_at,
            account_label=_account_label(payload) or None,
            if_updated_at=row["updated_at"],
        )

        if updated is None:
            # Somebody refreshed between our read and our write, which under the lock
            # means a second process or a store whose lock is process-local. **Not
            # retried**, for the reason in the docstring: the token we just obtained is
            # good but the row now holds one obtained later, and overwriting a newer
            # credential with an older one is the lost update this whole mechanism
            # exists to prevent, arriving from the other direction.
            log.info(
                "a concurrent refresh of %s for %s won; using the token it stored",
                connector_id,
                principal,
            )
            return False

        return True


def _wait_for_the_winner(principal, connector_id: str) -> bool:
    """Poll until whoever holds the lock has stored a fresh token. Always returns False.

    False because *this* call refreshed nothing — which is the honest answer and the one
    `refresh_for_run` reports. What the caller gets is the guarantee that by the time this
    returns, the row is either fresh or the winner has failed, and `for_connector` will
    read whichever it is.

    Bounded, and the bound is the point: this runs on the run path, so a winner that hangs
    must cost one request timeout rather than the run. Past the bound the run proceeds and
    the credential read reports whatever the row actually says — which is a third party's
    401 or a reconsent sentence, both of which are true statements, where waiting forever
    is a run that never starts and never says why.

    A poll rather than a condition variable, because the thing being waited on is in
    another **process** as often as another thread. There is nothing in-process to signal.
    """
    store = storage.active()
    deadline = time.monotonic() + REQUEST_TIMEOUT

    while time.monotonic() < deadline:
        time.sleep(_WAIT_POLL_SECONDS)
        row = store.find_connection(
            principal.tenant_id, principal.kind, principal.id, connector_id
        )
        if row is None or row.get("reconsent_reason") or not _stale(row):
            # Fresh, gone, or the winner discovered the grant is dead. All three are
            # settled states and there is nothing left to wait for.
            return False

    log.warning(
        "waited %ss for another refresh of %s for %s and it did not finish; the run will "
        "use whatever the row holds",
        REQUEST_TIMEOUT,
        connector_id,
        principal,
    )
    return False


def _stale(row: dict) -> bool:
    """Whether this access token is close enough to expiry to be worth renewing.

    A row with **no** `expires_at` is not stale, and that asymmetry is load-bearing: it
    is what makes a provider that does not say when its token expires produce a
    connection that is refreshed when it fails rather than before every single run. The
    alternative reading — no expiry means unknown means refresh — turns every run into a
    token endpoint round trip and rotates a refresh token per run, which is the
    behaviour most likely to trip a provider's abuse detection.
    """
    expires_at = row.get("expires_at")
    if expires_at is None:
        return False
    return expires_at <= datetime.now(timezone.utc) + timedelta(
        seconds=EXPIRY_SKEW_SECONDS
    )


def _mark_reconsent(principal, connector_id: str, reason: str) -> None:
    storage.active().mark_connection_reconsent(
        principal.tenant_id,
        principal.kind,
        principal.id,
        connector_id,
        reason=reason,
    )


# --- disconnecting ----------------------------------------------------------------------


def disconnect(principal, connector_id: str, *, actor: str) -> dict:
    """Revoke upstream where we can, then delete locally. **Delete happens either way.**

    Decision 12, and the ordering is the decision. Deleting our row today leaves a live
    token at the provider; for a pasted personal access token that is unavoidable — only
    the person who issued it can revoke it — but for an OAuth connection it is not. RFC
    7009 gives a revocation endpoint, and having obtained the token on somebody's behalf
    we are the right party to hand it back.

    **Revoke, then delete**, because the failure modes are not symmetric. Delete-then-
    revoke loses the token needed to revoke if the process dies in between, and there is
    then nothing anywhere that could ever revoke it. Revoke-then-delete can at worst
    leave a local row for a token already dead, which the next use reports as needing
    re-consent — a recoverable state rather than an unrecoverable one.

    **Best-effort, and the delete is unconditional.** A provider that is down, slow, or
    publishes no revocation endpoint must not leave somebody unable to end a connection
    they have asked to end. The failure is reported and recorded — `revoked_upstream` in
    the administrative record — rather than swallowed, so *"is that token still live at
    Atlassian"* has an answer.
    """
    revoked = None
    row = storage.active().find_connection(
        principal.tenant_id, principal.kind, principal.id, connector_id
    )

    if row is not None and row.get("credential_kind") == storage.OAUTH_CREDENTIAL:
        revoked = _revoke_upstream(principal, connector_id, row)

    detail = {"kind": (row or {}).get("credential_kind", "")} if row else {}
    if revoked is not None:
        detail["revoked_upstream"] = revoked

    existed = connections.disconnect_account(
        principal, connector_id, actor=actor, detail=detail
    )
    return {"disconnected": existed, "revoked_upstream": revoked}


def _revoke_upstream(principal, connector_id: str, row: dict) -> bool | None:
    """Tell the provider to kill this token. None when there was nobody to tell.

    Every failure is caught. This runs on the way out of a connection somebody has asked
    to end, and an exception here would turn a provider's bad afternoon into a person
    who cannot disconnect.
    """
    try:
        app = _app(principal.tenant_id, connector_id)
    except OAuthRefused:
        # The consent flow was removed after they connected. Nothing to revoke against.
        return None

    if not app["revoke_endpoint"]:
        return None

    try:
        stored = crypto.open_(
            row["ciphertext"],
            tenant_id=principal.tenant_id,
            aad=crypto.connection_aad(
                principal.tenant_id, principal.kind, principal.id, connector_id
            ),
            key_id=row["key_id"],
        )
        parsed = json.loads(stored)
        # The refresh token where there is one: revoking it kills the whole grant at
        # most providers, where revoking an access token kills one hour of it.
        token = parsed.get(OAuthTokens.REFRESH) or parsed.get(OAuthTokens.ACCESS) or ""
        if not token:
            return None

        egress.check(principal.tenant_id, app["revoke_endpoint"])
        _post_form(
            app["revoke_endpoint"],
            {
                "token": token,
                "token_type_hint": (
                    "refresh_token" if parsed.get(OAuthTokens.REFRESH) else "access_token"
                ),
            },
            auth=(app["client_id"], app["client_secret"]),
        )
        return True
    except Exception:  # noqa: BLE001 - see the docstring; the delete must still happen
        log.warning(
            "could not revoke the token for %s at the provider; deleting locally anyway",
            connector_id,
            exc_info=True,
        )
        return False


# --- talking to the token endpoint ------------------------------------------------------


def _token_request(tenant_id: str, app: dict, form: dict) -> dict:
    """POST the token endpoint and return its JSON. Raises on anything else.

    **The egress check is here, on every call**, not only at configuration. A stored row
    outlives the moment it was written: revoke a host and a connector already configured
    against it would keep POSTing a client secret to it, which is a control that works
    right up until somebody uses it. This is `_transport_for`'s argument, applied to the
    second kind of outbound connection this platform now makes.
    """
    egress.check(tenant_id, app["token_endpoint"])

    status, payload = _post_form(
        app["token_endpoint"],
        {**form, "client_id": app["client_id"]},
        # `client_secret_basic` — the secret in the Authorization header rather than in
        # the form body. It is the scheme RFC 6749 says a server MUST support where
        # `client_secret_post` is optional, and it keeps the secret out of any
        # intermediary that logs request bodies. `client_id` goes in the body as well
        # because several providers read it from there regardless.
        auth=(app["client_id"], app["client_secret"]),
        want_body=True,
    )

    if status == 400 or status == 401:
        error = (payload or {}).get("error", "")
        if error in ("invalid_grant", "unauthorized_client", "access_denied"):
            raise ReconsentRequired(
                f"the provider refused this connection ({error}). Consent was withdrawn, "
                "or the refresh token expired or had already been used. Connect the "
                "account again."
            )
        raise OAuthRefused(
            f"the provider refused the token request ({error or status}). "
            f"{(payload or {}).get('error_description', '')}".strip()
        )

    if status >= 400 or not isinstance(payload, dict):
        raise OAuthRefused(
            f"the provider's token endpoint answered {status} with something that is "
            "not a token response. Nothing was stored."
        )

    if not payload.get("access_token"):
        raise OAuthRefused(
            "the provider's token endpoint answered without an access token. Nothing "
            "was stored."
        )

    return payload


def _tokens_from(payload: dict) -> OAuthTokens:
    """A token response mapped onto what we keep. See `OAuthTokens` for what we do not.

    `expires_in` is seconds-from-now and is turned into an instant here, at the one
    moment "now" is unambiguous. Storing the duration and adding it at read time would
    make every reader's clock part of the answer.
    """
    now = datetime.now(timezone.utc)
    return OAuthTokens(
        access_token=payload["access_token"],
        refresh_token=payload.get("refresh_token") or "",
        expires_at=_instant(now, payload.get("expires_in")),
        # **Two spellings, because there is no standard one.** RFC 6749 defines
        # `expires_in` for the access token and says nothing at all about the refresh
        # token's lifetime, so every provider that volunteers it invented a field name:
        #
        #     refresh_token_expires_in    GitHub          15897600 (six months)
        #     refresh_expires_in          Keycloak, Okta
        #
        # Reading only one of them is not a missing feature, it is a **silent wrong
        # answer**: the column stays NULL, "this connection will need reconnecting in six
        # months" becomes unpredictable, and nothing anywhere says the provider told us.
        #
        # This read `refresh_expires_in` alone and would have stored NULL against GitHub —
        # which, as a GitHub App with expiring user tokens, is the most likely real
        # provider this will meet and the one whose rotation behaviour makes it worth
        # testing against. Found by reading GitHub's documentation rather than by any
        # test, because every provider in this repository's tests is one we wrote.
        refresh_expires_at=_instant(
            now,
            payload.get("refresh_token_expires_in")
            if payload.get("refresh_token_expires_in") is not None
            else payload.get("refresh_expires_in"),
        ),
    )


def _instant(now: datetime, seconds) -> datetime | None:
    try:
        return now + timedelta(seconds=int(seconds)) if seconds is not None else None
    except (TypeError, ValueError):
        # A provider sending a non-numeric `expires_in` gets treated as one that sent
        # nothing, which is the conservative reading: a connection with no known expiry
        # is refreshed when it fails rather than on a schedule derived from nonsense.
        return None


def _post_form(url: str, form: dict, *, auth, want_body: bool = False):
    """One `application/x-www-form-urlencoded` POST. The only network call in this module.

    Isolated into one function so a test can replace it — the same seam `transport.py` is,
    for the same reason. Nothing here retries: a retried exchange is a second attempt to
    spend a credential that is single-use.

    **The dial is pinned, and step 064 is the step that noticed it wasn't.** 058 closed
    DNS rebinding for the connector dials and left this one open, which was the worst
    place to leave it: the three calls that come through here — the code exchange, the
    refresh, the revoke — carry the client secret and the refresh token, and they are
    guarded only by `egress.check`, which vets the *name*. A token endpoint registered
    while its host resolved publicly, rebound afterwards into RFC1918 space or at the
    metadata service, would have had this function POST the deployment's credentials to
    it. `egress.dial` resolves at dial time, refuses every answer nobody may consent to,
    and sends to the address that was vetted.

    Tenant consent, not operator: these endpoints come off `oauth_apps`, a tenant's own
    registration, so loopback and private answers are refused unless the operator has
    named the host in `CARNET_EGRESS_INTERNAL_HOSTS` — the same boundary `check` draws
    one line up in `_token_request`.

    A redirect is still never followed, and now that is `dial`'s guarantee rather than
    this call's keyword: a token endpoint that redirects is a token endpoint we should
    not be following.
    """
    import requests

    from ..tools.mcp import egress

    with requests.Session() as session:
        response = egress.dial(
            session,
            "POST",
            url,
            data=form,
            auth=auth,
            timeout=REQUEST_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        # Read inside the session's lifetime. The body is already buffered (nothing
        # here streams), but a response outliving its session is the shape that stops
        # being true the day somebody adds `stream=True` to the call above.
        if not want_body:
            return response.status_code, None
        try:
            return response.status_code, response.json()
        except ValueError:
            return response.status_code, None


__all__ = [
    "EXPIRY_SKEW_SECONDS",
    "PENDING_TTL_SECONDS",
    "OAuthRefused",
    "OAuthTokens",
    "ReconsentRequired",
    "begin",
    "complete",
    "configure",
    "configured",
    "disconnect",
    "refresh_connection",
    "refresh_for_run",
    "unconfigure",
]
