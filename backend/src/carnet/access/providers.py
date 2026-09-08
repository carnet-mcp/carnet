"""Which customer signed this token.

This is the tenant boundary of the access layer. `oidc.py` answers *is this token
real*; this answers *whose it is*, and getting it wrong is not a permission bug — it is
one company's employees reading another company's data.

## The tenant never comes from the token

Providers can be configured to put an organisation id in a claim, and trusting it would
delete this module. It would also make the customer's own identity provider
authoritative over **our** tenancy: a mis-mapped claim in someone else's admin console
becomes a cross-tenant read here, in a setting we cannot see or audit.

So the token proves who; a row we own decides whose data.

## Two rules, and the second is the one that gets forgotten

    a candidate matches iff  verify() succeeds  AND  the discriminating claim matches

Most providers issue one issuer per customer — Okta gives `https://acme.okta.com`,
Entra one per directory — so a lookup returns a single row and the first half settles
it. Google Workspace shares `https://accounts.google.com` across every organisation on
it, so a lookup can return several.

For those, **verification alone is not enough**. Two customers on one issuer may have
registered the same OAuth client and therefore share an audience, in which case every
candidate verifies and the first would win — a cross-tenant read produced by nothing
more exotic than two companies both using Google. The discriminating claim (`hd`, the
hosted domain) is what actually tells them apart, and it is read from the **verified**
claims, never the raw token.
"""

import logging

from .. import storage
from . import oidc
from .oidc import TokenError, TokenExpired

log = logging.getLogger(__name__)

# One JWKS cache per process, holding each provider's signing keys. It lived in
# `api/deps.py` for four steps while browser logins were the only verifier; step 033c
# added a second — `acting.py`, verifying a forwarded token at the MCP door — and two
# caches fetching the same `jwks_uri` would have made "one cache per process" quietly
# untrue while doubling the load on a customer's IdP. Hoisted here because this module
# is what both verifiers already call through, and `api/` may import downward while
# `access/` may not import up.
KEYS = oidc.JwksCache()


def resolve(token: str, cache: oidc.JwksCache) -> tuple[dict, dict]:
    """`(provider_row, verified_claims)`, or raise `TokenError`.

    The issuer is read unverified to choose which keys to check against — see
    `oidc.peek_issuer` for why that is safe and where its limits are. Everything
    returned has been verified.
    """
    issuer = oidc.peek_issuer(token)

    candidates = [row for row in storage.active().find_tenant_idps(issuer) if row["enabled"]]
    if not candidates:
        # Deliberately says nothing about whether this issuer is known-but-disabled or
        # entirely unheard of. Neither is the caller's business.
        log.info("token from unregistered issuer %s", issuer)
        raise TokenError(f"no identity provider is registered for issuer '{issuer}'")

    failure: TokenError | None = None

    for candidate in candidates:
        try:
            claims = oidc.verify(token, candidate, cache)
        except TokenExpired:
            # Expiry is a property of the token, not of which candidate we tried, and
            # it is the one failure a client can act on. Propagated rather than
            # collected, so "log in again" does not get flattened into "invalid".
            raise
        except TokenError as exc:
            failure = exc
            continue

        claim = candidate["discriminator_claim"]
        if claim is None:
            # This row claims the whole issuer, which storage guarantees means it is
            # the only row for it.
            return candidate, claims

        if claims.get(claim) != candidate["discriminator_value"]:
            # Verified, and for a different customer on the same provider. Not an
            # error yet — another candidate may be the right one.
            continue

        return candidate, claims

    if failure is not None:
        raise failure

    # Every candidate verified and none matched on the discriminator: a real user at a
    # real customer's provider, whose organisation nobody has onboarded.
    raise TokenError(
        f"token from '{issuer}' does not identify a registered customer. The provider "
        "is shared between organisations and this one is not onboarded."
    )
