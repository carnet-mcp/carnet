"""Whom a door call says it is for, and what that claim is worth. Step 033c.

The MCP door's caller is commonly a *shared service* — one machine token serving fifty
people — and 033a made the consequence fail-closed: a `user`-identity tool called
through the door was simply refused, because nothing could say which person's account
to act as. Acting-for is that saying. It arrives per call, in the request's `_meta`
(the wire shape is `api/routes_mcp.py`'s business), and this module decides what the
claim is worth:

    verified   the caller forwarded the person's own IdP token, and it checks out
               against the same `tenant_idps` row browser logins are verified with.
               Nothing is trusted; the chatbot cannot claim to be Tom.
    asserted   the caller supplied an email and this tenant chose to believe it —
               per connector, `allow_asserted_identity`, default off. The enterprise
               trusted-subsystem pattern, exactly as honest as the calling app.

**What resolution is not: authorization.** The value produced here changes whose
connected account a `user`-identity tool resolves and what the audit record says —
`core.principal.ActingFor`'s docstring is the contract — and the door checks the
token's grants before this module ever runs. That is also why this file lives in
`access/` and not in the door: it reads `tenant_idps` and `users`, which are identity
questions, while the door composes tools and grants and may not answer identity
questions of its own.

## The tenant boundary, which is the check that matters most

`providers.resolve` answers "whose token is this" *globally* — the issuer picks the
tenant. Here the tenant is already known (it is the door principal's), so the rule
inverts: a forwarded token is verified **only against providers of that tenant**, and
one that verifies perfectly against some other tenant's row is refused without being
tried. The discriminator-claim rule for shared issuers is kept as-is, because two
customers on one issuer is exactly when it fires.

## Failures are sentences, and none of them fall through

Every miss raises `ActingForError` with the thing somebody can act on: an expired
token says *forward a fresh one*, an unknown person says *sign in once*, a disabled
one says so. The door turns each into a JSON-RPC refusal before the broker — nothing
here is a broker credential problem, because no credential was being resolved yet;
what failed is the claim about *who*, which is this layer's own kind of failure.
"""

import logging

from .. import storage
from ..core.principal import ASSERTED, VERIFIED, ActingFor, Principal
from . import oidc, providers
from .oidc import TokenError, TokenExpired

log = logging.getLogger(__name__)


class ActingForError(RuntimeError):
    """An acting-for claim that cannot be honoured, with the sentence saying why.

    Safe to show the caller: everything quoted back is either our own configuration's
    vocabulary or the bounded email the caller sent us, and the caller holding an
    authenticated machine token has already seen its own tool list.
    """


# The two keys the acting-for object may carry, exactly one of them. Spelled here so
# the route, the door and the tests all point at one place.
TOKEN_KEY = "token"
EMAIL_KEY = "email"

# The wire maximum for an address (RFC 5321's 254), enforced before the value can
# reach a sentence, a log line, or the audit column — migration 041's 320-char CHECK
# is the structural bound behind this one.
MAX_EMAIL_LENGTH = 254

# How much caller text a refusal may quote back, and how many pieces of it.
#
# `api/routes_mcp.py`'s `QUOTE_LIMIT` for the same reason, restated here because **this
# module is the producer of these sentences** and the rule is a producer's to keep —
# the same shape `make_denial_record`'s docstring records from 033b. The near-miss was
# real: an acting-for object's *keys* are caller-supplied text, bounded only by
# `MCP_MAX_ACTING_FOR_BYTES`, so a single 4 KB key came back inside a 4 KB refusal.
#
# Trimmed rather than dropped, because naming the misspelling is the actionable half of
# the refusal — telling somebody they sent `emial` is the whole point of refusing.
QUOTE_LIMIT = 40
QUOTE_MAX_KEYS = 3


def _quote(keys: list) -> str:
    """Caller-supplied key names, safe to put in a sentence."""
    shown = []
    for key in keys[:QUOTE_MAX_KEYS]:
        text = str(key)
        shown.append(repr(text if len(text) <= QUOTE_LIMIT else f"{text[:QUOTE_LIMIT]}…"))
    if len(keys) > QUOTE_MAX_KEYS:
        shown.append(f"and {len(keys) - QUOTE_MAX_KEYS} more")
    return ", ".join(shown)


def parse(raw) -> tuple[str, str]:
    """`(kind, value)` off the wire, or a refusal. Shape only — nothing is looked up.

    Exactly one of `token` or `email`, as a non-empty string. Both, neither, an
    unknown key or a non-string value refuses loudly: a typo'd `emial` must fail here,
    never quietly become a call with no acting-for — an audit row that says `none`
    about a call somebody meant to attribute is the log being wrong at the exact
    moment it was being used most deliberately.
    """
    if not isinstance(raw, dict):
        raise ActingForError(
            "acting-for must be an object with exactly one of "
            f"'{TOKEN_KEY}' (a forwarded IdP token) or '{EMAIL_KEY}' (an asserted "
            "address)."
        )

    unknown = sorted(set(raw) - {TOKEN_KEY, EMAIL_KEY}, key=str)
    if unknown:
        raise ActingForError(
            f"acting-for carries {_quote(unknown)}, which this server does not "
            f"understand. It takes exactly one of '{TOKEN_KEY}' or '{EMAIL_KEY}'. "
            "Refused rather than ignored, so a misspelled key cannot silently drop "
            "the identity it was meant to carry."
        )

    if (TOKEN_KEY in raw) == (EMAIL_KEY in raw):
        raise ActingForError(
            f"acting-for takes exactly one of '{TOKEN_KEY}' (verified — the person's "
            f"own IdP token, forwarded) or '{EMAIL_KEY}' (asserted — believed only "
            "where a connector enables it), and this call "
            + ("carried both." if raw else "carried neither.")
        )

    kind = TOKEN_KEY if TOKEN_KEY in raw else EMAIL_KEY
    value = raw[kind]
    if not isinstance(value, str) or not value:
        raise ActingForError(f"acting-for '{kind}' must be a non-empty string.")

    if kind == EMAIL_KEY:
        if len(value) > MAX_EMAIL_LENGTH:
            raise ActingForError(
                f"an asserted address is at most {MAX_EMAIL_LENGTH} characters, and "
                f"this one is {len(value)}."
            )
        if value.count("@") != 1 or any(c.isspace() or ord(c) < 32 for c in value):
            # Not RFC validation — a light gate on what may reach a column kept
            # forever, and on what a refusal sentence may quote back.
            raise ActingForError(
                "an asserted identity is an email address: one '@', no whitespace."
            )

    return kind, value


def verify(principal: Principal, token: str) -> ActingFor:
    """The verified path: a forwarded IdP token becomes a person, or a refusal.

    The same verification browser logins get — `oidc.verify`, through the one
    per-process `providers.KEYS` cache — constrained to the door principal's tenant as
    the module docstring argues. The person must already exist and be active: a tool
    call creates nobody (`users.resolve`'s first-time path is a *login* path), and a
    disabled person must not keep acting through a bot.
    """
    try:
        issuer = oidc.peek_issuer(token)
    except TokenError as exc:
        raise ActingForError(
            f"the forwarded acting-for token could not be read: {exc}"
        ) from exc

    candidates = [
        row
        for row in storage.active().find_tenant_idps(issuer)
        if row["enabled"] and row["tenant_id"] == principal.tenant_id
    ]
    if not candidates:
        # Deliberately the same silence `providers.resolve` keeps: whether this issuer
        # belongs to another tenant, is disabled, or is unheard of is not the caller's
        # business. The remedy is the same in every case.
        raise ActingForError(
            "the forwarded acting-for token was not issued by an identity provider "
            "registered for this customer. Forward the person's own sign-in token, "
            "from the same provider they sign in to Carnet with."
        )

    failure: TokenError | None = None
    for candidate in candidates:
        try:
            claims = oidc.verify(token, candidate, providers.KEYS)
        except TokenExpired as exc:
            # The one failure the calling service can fix by itself, kept distinct
            # exactly as `providers.resolve` keeps it.
            raise ActingForError(
                "the forwarded acting-for token has expired. Forward a fresh one — "
                "the person's current session token, not a stored copy."
            ) from exc
        except TokenError as exc:
            failure = exc
            continue

        claim = candidate["discriminator_claim"]
        if claim is not None and claims.get(claim) != candidate["discriminator_value"]:
            # Verified, and for a different customer on the same shared provider.
            continue

        return _person(principal, candidate, claims, issuer)

    if failure is not None:
        log.info("acting-for token refused for %s: %s", principal, failure)
    raise ActingForError(
        "the forwarded acting-for token did not verify against this customer's "
        "identity provider."
    )


def _person(
    principal: Principal, provider: dict, claims: dict, issuer: str
) -> ActingFor:
    """Verified claims become an `ActingFor`, under the same rules a login applies."""
    subject = claims.get(provider["subject_claim"])
    if not subject:
        raise ActingForError(
            f"the forwarded token carries no '{provider['subject_claim']}' claim, so "
            "it identifies nobody stably."
        )

    user = storage.active().find_user(issuer, subject)
    if user is None:
        raise ActingForError(
            "the forwarded token verifies, but that person has never signed in to "
            "Carnet. They sign in once — which is what creates their account — and "
            "then this call works."
        )

    if user["tenant_id"] != principal.tenant_id:
        # Should be impossible — the provider row was filtered to this tenant and
        # `(issuer, subject)` decided the user's tenant — but if it ever happens it is
        # a cross-tenant act-as, so it refuses loudly. `users._returning` keeps the
        # same tripwire on the login path.
        log.error(
            "acting-for resolved user %s of tenant %s through a provider of tenant %s",
            user["id"],
            user["tenant_id"],
            principal.tenant_id,
        )
        raise ActingForError("that person's customer does not match this token's.")

    if user["status"] != "active":
        raise ActingForError(
            f"account '{user['id']}' is disabled, so nothing may act for it."
        )

    # Our stored email, never claim text: what lands in the audit column on this path
    # is a value this system already owns. Falls back to the identity pair only for a
    # row that has no address at all, which `_email`'s refusals make rare.
    email = (user.get("email") or "").strip() or f"{issuer}#{subject}"
    return ActingFor(user_id=user["id"], email=email[:MAX_EMAIL_LENGTH], source=VERIFIED)


def assert_identity(principal: Principal, email: str) -> ActingFor:
    """The asserted path: an address this tenant chose to believe.

    The believing is the *door's* gate — `allow_asserted_identity` lives on the
    connector, and connectors are not this layer's vocabulary — so by the time this
    runs the only questions left are who the address matches and whether that person
    may still be acted for.

    A match fills `user_id`; no match leaves it None **deliberately**: on a
    `service`-identity tool the assertion is only an audit fact and recording it as
    given is the honest thing, while a `user`-identity tool will refuse it at
    credential time with the broker writing both the sentence and the record
    (`credentials._acted_for_credential`). A *disabled* match refuses here instead —
    "we know nothing about that name" and "we know they were turned off" are
    different answers, and only the second is a decision this tenant already made.
    """
    user = storage.active().find_user_by_email(principal.tenant_id, email)

    if user is not None and user["status"] != "active":
        raise ActingForError(
            f"account '{user['id']}' is disabled, so nothing may act for it."
        )

    return ActingFor(
        user_id=user["id"] if user is not None else None,
        email=email,
        source=ASSERTED,
    )
