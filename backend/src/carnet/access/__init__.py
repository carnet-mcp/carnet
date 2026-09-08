"""The identity seam: turning a token into somebody.

Sits beside `agents/` in the layering — above `core/`, below the entry points:

```
cli / api     entry points — establish the principal, carry the tenant
access/       who is calling, and which customer they belong to
agents/       who exists and what they may do          (config only)
core/         the tiers and the broker                 (knows no tool, no agent)
tools/        what can actually be done
storage/      rows in, rows out
config.py     paths, defaults, limits
```

It may read storage. It may not know what a tool is, and **nothing here may change
`core/permissions.py`** — that module answers "may this agent do this thing?" and has
gone five steps without learning what a user is. Answering "who is calling?" inside it
would put identity into the policy engine, which is the one boundary this codebase has
protected hardest.

What lives here, by chunk:

    oidc.py       validating a token against a provider's published keys   (005 chunk 2)
    providers.py  which customer an issuer speaks for                      (005 chunk 3)
    users.py      (issuer, subject) -> principal, with gated creation      (005 chunk 3)
    grants.py     may this principal use this agent, and at what level?    (006)
    groups.py     a name for a set of principals, to grant to              (9a)
    roles.py      may this principal administer this TENANT?               (12b)
    tokens.py     an API token -> a `machine` principal                    (020)
    connections.py / oauth.py   whose credential a delegated call acts with (7a/7b)
    acting.py     whom a door call says it is for, verified or asserted    (033c)
"""

from .oidc import (
    ALLOWED_ALGORITHMS,
    JwksCache,
    TokenError,
    TokenExpired,
    peek_issuer,
    verify,
)

# Imported after oidc so the modules that build on it can import from it by name.
from . import acting, grants, providers, roles, tokens, users  # noqa: E402  isort:skip
from .grants import NoAccess, ShareRefused  # noqa: E402
from .roles import RoleRequired  # noqa: E402
from .users import AccessDenied  # noqa: E402

__all__ = [
    "ALLOWED_ALGORITHMS",
    "AccessDenied",
    "JwksCache",
    "NoAccess",
    "RoleRequired",
    "ShareRefused",
    "TokenError",
    "TokenExpired",
    "acting",
    "grants",
    "peek_issuer",
    "providers",
    "roles",
    "tokens",
    "users",
    "verify",
]
