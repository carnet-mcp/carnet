"""Who a call is made *for*.

The agent is the actor; the principal is the authority it acts under. Same agent
config invoked by two different users should reach different resources — and that
sentence has no subject unless the user is represented somewhere.

Today every call is `system`: the CLI and (later) the scheduler run agents that no
one opened. When the access layer lands, interactive requests carry a real user and
the scoping model reads it from here. Nothing else about the call path changes.

Deliberately minimal. Adding a field to a dataclass later is cheap; changing a
signature through the loop, the broker, and the audit schema is not — which is the
entire reason this exists before it does anything.
"""

from dataclasses import dataclass
from typing import Literal

# `machine` arrives with step 020, and it is a third kind rather than a spelling of
# `system` for one reason: `access/roles.py` treats every `system` principal as an
# administrator, before storage is touched, and its docstring records that this is safe
# **because no HTTP caller can be one**. A machine token minting a `system` principal
# would make every API token a tenant administrator. See `storage/base.py`'s
# `PRINCIPAL_KINDS`, where the same three words are a frozenset, and migration 031, where
# they are CHECK constraints on six columns and deliberately not on two others.
PrincipalKind = Literal["user", "system", "machine"]


@dataclass(frozen=True)
class Principal:
    """The authority a tool call is made under.

    kind:      "user"    — an interactive request authenticated against the IdP
               "system"  — the CLI and the deployment's own unattended paths. **Always
                           an administrator**, which is the bootstrap rather than a
                           shortcut; see `access/roles.py`. Never reachable over HTTP.
               "machine"  — an API token: a cron job, a CI pipeline, a webhook receiver.
                           Reachable over HTTP, and therefore an administrator nowhere.
                           Its access is grants, exactly like a person's.
    id:        stable identifier within that kind. For users this becomes our opaque
               user id; for system callers it names the caller ("cli", "bootstrap"); for
               machines it is the token's own id.
    tenant_id: which customer this principal belongs to.

    **`system` and `machine` are not two names for "not a person".** The difference is
    which side of the network they arrive from, and it decides everything: whoever runs
    the CLI already holds `CARNET_DATABASE_URL` and can write any row by hand, so
    refusing them anything is a control with nothing behind it. A machine presents a
    credential over the same door as everybody else and gets what its grants say.

    **`tenant_id` lives here rather than on `RunContext`** — a deliberate choice, and
    the same kind of choice `RunContext` itself was. A principal belongs to a tenant,
    including a system one: the scheduler that runs a customer's nightly job is that
    customer's scheduler. Because the principal is already threaded through the broker,
    the audit log, the credential lookup and the permission check, all four get tenancy
    without growing a parameter.

    The alternative — carrying it on the run — would mean tenancy existed in two places
    that could disagree, and a disagreement between them is exactly the shape of a
    cross-tenant leak. `RunContext.tenant_id` derives from here and stores nothing.

    There is **no default**. A defaulted tenant on a frozen security-relevant dataclass
    is how a construction site quietly ends up in the wrong customer's data, and an
    argument the compiler demands is the only kind nobody forgets.
    """

    kind: PrincipalKind
    id: str
    tenant_id: str

    @classmethod
    def system(cls, id: str, tenant_id: str) -> "Principal":
        """A headless caller. No human authorized this specific run."""
        return cls(kind="system", id=id, tenant_id=tenant_id)

    @classmethod
    def user(cls, id: str, tenant_id: str) -> "Principal":
        """An authenticated human, on whose authority the agent acts."""
        return cls(kind="user", id=id, tenant_id=tenant_id)

    @classmethod
    def machine(cls, id: str, tenant_id: str) -> "Principal":
        """An API token: headless, over HTTP, and an administrator nowhere.

        `id` is the token's row id, so every audit record a machine writes resolves to a
        name and an owner in `api_tokens` — which is why revocation stamps that row
        rather than deleting it.

        The only caller is `access/tokens.py`. `api/deps.py` deliberately constructs no
        principal itself, so both tripwire tests can assert on a single seam each.
        """
        return cls(kind="machine", id=id, tenant_id=tenant_id)

    def __str__(self) -> str:
        # Deliberately unchanged. This string is the caller's *identity*, and it is
        # what a refusal message shows a person; the tenant is routing, and it has its
        # own column in the audit log. Folding it in here would change the wording of
        # every denial for no one's benefit.
        return f"{self.kind}:{self.id}"


# How an acting-for identity arrived, and how much it is worth. Three values, never
# collapsed: `none` is what every record without an acting-for writes, and it is the
# default in `core/audit.py` rather than an absence — an audit row must always answer
# "how sure are we who this was for", including when the answer is "nobody claimed it
# was for anyone".
VERIFIED = "verified"
ASSERTED = "asserted"
NO_IDENTITY = "none"


@dataclass(frozen=True)
class ActingFor:
    """Whom a brokered call is made *for*, when that differs from the principal.

    Step 033c. A shared service — one machine token serving fifty people — names the
    person behind a call, and this is that name after `access/acting.py` has decided
    what it is worth. It lives here rather than in `access/` because the broker and
    `RunContext` carry it, and `core/` may not import upward — the same layering that
    put `Principal` here.

    **This is not a principal, and must never become one.** Authorization is the
    token's: grants, scope and budget are checked against the door principal before
    this is ever read. What acting-for changes is exactly two things — whose connected
    account a `user`-identity tool resolves (see `credentials.for_connector`), and what
    the audit record says. An `ActingFor` naming an administrator grants a token
    nothing.

    user_id:  our user row's id, when the identity resolved to one. None for an
              asserted email that matches nobody — the assertion is still recorded as
              given, and a `user`-identity tool refuses it at credential time with the
              sentence naming the account.
    email:    what the audit column carries. For `verified` it is our stored email off
              the user row, never claim text; for `asserted` it is the caller's text,
              bounded and shape-checked at the door's edge before anything here exists.
    source:   `verified` — a forwarded IdP token checked against the same
              `tenant_idps` row browser logins use. `asserted` — believed because the
              tenant enabled `allow_asserted_identity` on that connector. Never
              `none`: no acting-for is represented by no `ActingFor`, not by a third
              value here that a credential lookup would then have to reason about.
    """

    user_id: str | None
    email: str
    source: str

    def __str__(self) -> str:
        return f"{self.email} ({self.source})"
