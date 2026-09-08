"""Credential store — the ONLY module that reads secrets.

Nothing here is ever returned to the agent loop or the model. The broker calls
`for_tool()` immediately before execution and passes the result straight into the
tool implementation as keyword arguments. Credentials never appear in:

  - the agent config
  - the tool schemas the model sees
  - the tool arguments the model produces
  - the audit log

Channels map to *per-channel* webhook URLs, so the credential lookup is itself a
second enforcement point: even if a channel somehow passed the permission check, an
unmapped channel has no secret to send with.

Lookups are keyed by (tool, principal). See `for_tool` for why the principal is part
of the key even while every caller is `system`.
"""

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone

from .. import config, storage
from . import crypto, vault
from .principal import ActingFor, Principal


class CredentialError(RuntimeError):
    """Raised when a required secret is missing, malformed, or unreadable."""


# How a credential was obtained. Two values today; the reason this is a string rather
# than a boolean is that 7b adds OAuth and a customer's own vault is a third — and the
# audit log this feeds is append-only, so a field that has to widen later is a field
# that has to be backfilled later.
#
# **Step 070 built the customer's own vault, and it is NOT the third value.** The
# sentence above anticipated the wrong axis, which is worth leaving standing because the
# near-miss it invited is the one thing in this step that could not have been corrected
# afterwards. `source` says *whose account a call went out as*. A pointer says *where the
# secret was read from*, which is an encoding — a pointer to the organisation's token is
# still `shared`, exactly as an OAuth connection is still `delegated` (see OAUTH below).
# A third value here would have gone into `audit.credential`, which is append-only by
# trigger, and made every existing query for "calls made as the caller" quietly wrong on
# a table nothing can rewrite.
#
# So a vault-resolved call and an environment-variable call produce **identical** audit
# rows. Plan 067's done-when asked for "identical except for the credential kind"; there
# is no such exception available, because `credential_kind` has never been in an audit
# row. The truth is stricter than the promise. `test_a_pointer_call_and_an_env_call_are
# _the_same_audit_row` is the assertion.
SHARED = "shared"
DELEGATED = "delegated"

# Whose account a tool acts as — step 033a, the vetted `identity`. Which of the two
# lookups below runs, decided at approval time rather than by whether the caller
# happened to have connected an account.
#
# Duplicated from `tools.base.Identity` rather than imported, on `_OAUTH_ACCESS`'s
# argument: this module deliberately knows no specific tool, and two constants in two
# modules is the cost of that boundary — cheap, because a test fails if they drift.
SERVICE_IDENTITY = "service"
USER_IDENTITY = "user"

# `connections.credential_kind` for a row a consent flow wrote. **Not a third value of
# `source` above**, which is the near-miss worth naming: `source` says whose account a
# call went out as and is written to an append-only audit table, while this says how a
# stored row is encoded. An OAuth connection is `delegated` up there — it is the most
# delegated thing in the system — and a fourth `source` value would make every existing
# query for "calls made as the caller" quietly wrong.
OAUTH = storage.OAUTH_CREDENTIAL


@dataclass(frozen=True)
class Credential:
    """A secret, and where it came from.

    The second half is not decoration. Once some calls go out as the caller and some
    as the operator, an audit record naming only the principal is quietly untrue about
    the account a write was made from — and the account is what decides what the write
    could reach. `source` is what the broker records; see `core/audit.py`.

    Deliberately not *whose* credential. That would put a second identifier in a table
    that is append-only by trigger and already has an undesigned retention problem,
    to answer a question the principal column mostly answers already.
    """

    value: str
    source: str


@dataclass(frozen=True)
class ToolCredentials:
    """What the broker injects, and how it was obtained.

    `kwargs` goes straight into the tool implementation. `source` is None for a tool
    that needs no credential at all, which is a different fact from "shared" and worth
    keeping distinct in the log.

    One return value rather than two calls, because two lookups that can disagree
    about which credential a call used is precisely the failure this field exists to
    prevent, arriving one layer up.
    """

    kwargs: dict
    source: str | None


# Logical channel name -> env var holding that channel's incoming-webhook URL.
# Works unchanged for Slack or Discord incoming webhooks; both are per-channel URLs.
# Add a channel by adding a row here and granting it in an agent's permissions.
CHANNEL_WEBHOOK_ENV = {
    "#eng": "WEBHOOK_URL_ENG",
    "#general": "WEBHOOK_URL_GENERAL",
}

# Connector id -> env var holding that server's credential. A fallback now rather than
# the authority: a connector row names its own `credential_env`, and a hardcoded map
# could not answer for a connector nobody had edited this file for. Kept for rows
# written before that field existed.
CONNECTOR_CREDENTIAL_ENV = {
    "github-mcp": "GITHUB_PERSONAL_ACCESS_TOKEN",
}

# Which environment variables a connector may never name is `config.is_platform_env` —
# step 050, blocker B1 of plan 049. It used to be a one-name frozenset here
# (`{"ANTHROPIC_API_KEY"}`, read by a model loop this tree no longer has); the rule now
# covers the whole platform surface (the master key, the database DSN, cloud
# credentials) and is enforced at registration too. The rule lives in `config` because `tools.register_connector`
# must ask it as well and `tools/` may not import `core` — see the block beside it.
#
# The trust argument the old one-name list carried has gone stale and is worth recording
# as it fell: it said a connector admin already supplies `StdioLaunch.command`, which the
# platform executes, and so has strictly more power than reading a variable anyway. But
# the HTTP/REST schema deliberately has no command field, so an HTTP admin has no code
# execution — and naming the platform's key is then a real escalation, not a no-op.

# Credential-shaped keyword names the model is never allowed to supply itself.
# permissions.py rejects any tool_input containing one of these; audit.py redacts
# them unconditionally.
RESERVED_KWARGS = frozenset({"webhook_url", "token", "api_key", "authorization", "secret"})


def _webhook_for_channel(channel: str) -> str | None:
    """Resolve a channel to its webhook URL, or None if none is configured.

    None is not an error: the message tool falls back to a local outbox file so the
    runtime is fully exercisable without signing up for anything.
    """
    env_var = CHANNEL_WEBHOOK_ENV.get(channel)
    if not env_var:
        return None
    return os.environ.get(env_var) or None


def personal_owner(principal) -> Principal | None:
    """The owner a *personal* token answers as, or None. Step 033d, the one address.

    Two different questions get the same answer from this one fact, and 021's lesson
    is that the fact must have exactly one reader of the row:

        whose GRANT ROWS answer for this principal    access/grants.py
        whose CONNECTION a user-identity call uses    _delegated_credential, door.py

    The questions stay separate — grants still applies the machine ceiling to what it
    gets back, credentials still runs its own branch order — but which token is
    personal is decided here, so the door's list, the run path's `require` and the
    broker's credential read cannot drift apart on it.

    It lives here rather than on `Principal` because a principal is reconstructed in
    more than one place (`tokens.resolve` and the scheduler's `act_for` — an earlier
    draft of this comment expected agent mode to add a third, which is withdrawn; see
    `docs/PREMISE.md`), and a flag one construction site forgets is 021's defect shape;
    and here rather than in `access/` because this module needs it and core cannot
    import access. Reading the row where the question is asked costs one primary-key
    lookup per machine-principal resolution, and plan 033 decision 12 already refused
    the cache that would remove it.

    `find_api_token` is tenantless by design (it is what *produces* a tenant for
    `resolve`), so the row's tenant must agree with the principal's — `act_for`'s
    check, kept. A missing row, a foreign tenant, or a service token all answer None,
    which fails closed: the caller falls back to the machine's own (empty or
    deliberate) rows, never to somebody else's.
    """
    if principal.kind != "machine":
        return None

    row = storage.active().find_api_token(principal.id)
    if row is None or row["tenant_id"] != principal.tenant_id:
        return None
    if not row["acts_as_owner"]:
        return None

    return Principal.user(row["owner_id"], principal.tenant_id)


def for_connector(
    connector_id: str,
    principal,
    env_var: str | None = None,
    *,
    identity: str = SERVICE_IDENTITY,
    acting_for: ActingFor | None = None,
    ref: str | None = None,
) -> Credential | None:
    """The credential a vetted MCP server should act with, for this caller.

    Keyed by connector rather than by tool: one GitHub token serves every GitHub tool,
    so growing `for_tool` by a row per tool would be twenty copies of one fact.

    `env_var` comes off the connector's manifest, which is where it belongs now that
    connectors are rows: a hardcoded map here could only answer for connectors somebody
    had edited this file for, so every new one would have authenticated as nobody. See
    `config.is_platform_env` for what a connector may never name and why (step 050).

    This module is told a variable *name* and an identity *word*; it never learns what
    an MCP server is, which is the property that kept `core/` free of tool-specific
    knowledge — and which is why the refusal for a connector that *cannot* carry a
    per-user credential lives in `tools/mcp`, where the transport is known, not here.

    **`identity` decides which lookup runs — step 033a, and it retires a fallback.**
    This function used to try the caller's delegated connection and fall back to the
    environment variable, so which account a call went out as depended on whether the
    caller happened to have connected one — an invisible per-principal condition nobody
    stated at vetting time. Convenient for one person at a CLI; indefensible for a
    shared service, where it is how somebody reads data their own account cannot open.
    Now the vetted descriptor says which, and there is no third value meaning
    "whichever exists":

        service   the environment variable, always. A `connections` row — including
                  one that is expired or flagged for reconsent — is never consulted,
                  so one person's connected (or broken) account cannot change how a
                  shared tool behaves for a run of theirs.
        user      the caller's own connection, always. No row **raises**, with the
                  connection to make. Never the environment variable: the silent
                  fallback is the exact untruth this field exists to end — acting as
                  the operator while the log names the person.

    Within `user`, the old third outcome still holds: a row that will not decrypt, has
    expired, or is flagged for reconsent raises its own sentence rather than degrading.
    A broken credential has to look broken. An expired row gets its own message, which
    is why `connections.expires_at` is nullable rather than absent: never connected and
    connected-but-expired send a person to two different places.

    **Step 7b adds no branch here.** An OAuth connection is a `connections` row like
    any other; what OAuth changed is only *how a row got there* and how its ciphertext
    is encoded, both handled inside `_delegated_credential`. A connector with OAuth
    configured **and** `credential_env` set is still legal: which one a call uses is
    now the vetted identity's answer, not an accident of who connected.

    **This function made no outbound call for six steps, and step 070 changed that on
    purpose — for one branch, when a customer asks for it.** Finding 5's sentence stood
    here and its argument is unchanged: a token-endpoint round trip on the hot path
    would make *every* call wait on a third party, which is why auto-refresh is still
    not here and why `access/oauth.refresh_for_run` still runs before the run.

    What a pointer changes is that there is no row holding the answer. The round trip is
    not an optimisation of a lookup that could have been local — **it is the credential**,
    and a customer who chose a reference chose to pay for it. The sealed blob remains the
    default and still dials nothing, so the cost lands only on connectors whose
    administrator asked for it. `_reference_credential`, `service` identity only.

    **`acting_for` — step 033c — is read in exactly one branch, and it substitutes a
    person, never a policy.** When a shared service through the door has named whom a
    call is for, a `user`-identity tool resolves *that person's* connection — the whole
    point of the feature — and the caller's own row is deliberately not a fallback:
    "the person you named has no account connected, so act as the service's instead"
    is the Tom defect with the names changed. The `service` branch never reads it,
    which is the rule that keeps acting-for from becoming a back door into the vetted
    identity: whose account a tool acts as stays the approval's decision, and
    acting-for only ever picks *which person* within a decision that already said
    "a person's".
    """
    if identity == USER_IDENTITY:
        if acting_for is not None:
            return _acted_for_credential(connector_id, principal, acting_for)

        delegated = _delegated_credential(connector_id, principal)
        if delegated is None:
            # A personal token's missing connection is its *owner's* missing
            # connection — `_delegated_credential` already read the owner's rows, so
            # the remedy has to name the owner or it sends somebody to connect an
            # account for a machine that will never be consulted. One extra row read,
            # on the refusal path only.
            whose = personal_owner(principal)

            # **A service token gets its own sentence — step 046.** The one below
            # tells it to "use the Connections page", which connects accounts for the
            # signed-in person and can never help a machine; and it never names the
            # common fix at all. All three real remedies, in the order somebody
            # actually reaches for them: the personal token, the machine's own pasted
            # connection (legitimate since before 033 — `_delegated_credential` reads
            # a machine's rows directly), and acting-for.
            if whose is None and getattr(principal, "kind", None) == "machine":
                raise CredentialError(
                    f"'{connector_id}' acts as the person calling it (its vetted "
                    f"identity is '{USER_IDENTITY}'), and {principal} is a service "
                    "token — no person stands behind it whose account could be used. "
                    "Either call this tool with a personal token (Tokens page: "
                    "'Personal — acts as you'), connect an account for this machine "
                    f"(carnet --connect-account {connector_id} {principal}), or "
                    "have the calling service name whom each call is for "
                    "(acting-for, in the call's _meta)."
                )

            whose = whose or principal
            raise CredentialError(
                f"'{connector_id}' acts as the person calling it (its vetted identity "
                f"is '{USER_IDENTITY}'), and {whose} has no account connected for "
                "it. Connect one:\n"
                f"    carnet --connect-account {connector_id}\n"
                "  or use the Connections page. A shared service calling through the "
                "MCP door instead names the person each call is for (acting-for, in "
                "the call's _meta), and that person's own connection is used. This "
                "call is refused rather than falling back to the platform's shared "
                "credential, which would act as the operator while the audit log "
                "named you."
            )
        return delegated

    if identity != SERVICE_IDENTITY:
        # Unreachable through the broker — `tools.validation` refuses the descriptor
        # first — so this is the fail-closed backstop for a caller that bypassed it.
        raise CredentialError(
            f"'{connector_id}' was asked for an unknown identity '{identity}'; "
            f"expected '{SERVICE_IDENTITY}' or '{USER_IDENTITY}'."
        )

    return _shared_credential(connector_id, env_var, ref)


def for_discovery(
    connector_id: str,
    principal,
    env_var: str | None = None,
    ref: str | None = None,
) -> Credential | None:
    """The credential to *look at a server* with: the caller's own, else the shared one.

    One of the two callers the old delegated-then-shared order survives for, and the
    reason it is a separate function with a narrow name rather than a flag on
    `for_connector`: discovery happens **before vetting**, so there is no identity to
    consult — the field this module now requires everywhere a tool actually runs. And
    the fallback that is indefensible on the call path is honest here: nothing
    executes, the answer is a tool list read by the administrator choosing what to
    approve, and it is attributed to them. `--add-connector` created the row,
    `--connect-account` sealed their credential against it, and this reads that back —
    decision 4's ordering. `--who` exists so an admin can look as somebody specific,
    which is why the caller's own row wins here and does not in `for_session` below.

    The third outcome still raises: a row that will not decrypt or has expired must
    look broken, because discovering anonymously on a broken credential would produce
    a tool list that does not match what a run would see.
    """
    delegated = _delegated_credential(connector_id, principal)
    if delegated is not None:
        return delegated

    return _shared_credential(connector_id, env_var, ref)


def for_session(
    connector_id: str,
    principal,
    env_var: str | None = None,
    ref: str | None = None,
) -> Credential | None:
    """The credential to **open a session and list tools** with. Never a call's account.

    The distinction this function exists to keep is the one `ensure_available` already
    draws: *binding is a tenant fact, a session is a credential fact.* Which tools
    exist comes from the tenant's vetting and is identical for everybody in it, so the
    handshake that asks a server for its tool list is not the moment "whose account?"
    is being answered — `for_connector` answers that, per call, from the vetting. What
    happens here has no effect on which tools bind, because the advertisement is
    intersected with the manifest either way.

    **Shared first, and the caller's own only when there is no shared one**, which is
    the inverse of `for_discovery` and is deliberate in both directions:

      - Preferring the shared credential keeps a caller's connection state out of a
        path that does not depend on it. The alternative — delegated first, which is
        what this did before 033a — means Priya's *expired* connection raises and
        kills her run on a connector whose tools are every one of them `service` and
        would never have read her row. That is 033a's own complaint, one layer up.
      - Falling back to hers when no variable is set is what keeps
        "everybody connects their own account and no shared credential exists" a
        working deployment. `test_a_delegated_lookup_does_not_need_the_environment_at
        _all` calls that shape normal, and binding with no credential at all would
        meet a real server's 401 **before the model is shown a single tool** — the
        silent-degrade `ensure_available` raises rather than tolerates.

    Returning None is still legal: an unauthenticated MCP server is a real thing, and
    a server that wants auth answers 401, which is its answer to give.
    """
    shared = _shared_credential(connector_id, env_var, ref)
    if shared is not None:
        return shared

    # Only now is a `connections` row worth reading — and a broken one still raises,
    # because with no variable configured there is genuinely nothing else to list with.
    return _delegated_credential(connector_id, principal)


def _delegated_credential(connector_id: str, principal) -> Credential | None:
    """This principal's own credential for this connector, or None if they have none.

    None means "not connected" and nothing else. Every other failure raises — see
    `for_connector` for why that asymmetry is the whole point.

    **A personal token reads its owner's row, and never its own** — step 033d,
    `_acted_for_credential`'s substitution one constant further out. Priya's
    connection was made by consent as `user:u_…`; her token has no row, and without
    this redirect a `user`-identity tool through it would refuse with "connect an
    account" about an account she has already connected. The token's own row, if an
    operator ever provisioned one, is deliberately not a fallback: "the owner has no
    connection, so act as the machine's instead" is the Tom defect with the names
    changed. Redirecting *here* rather than in one caller means `for_connector`'s
    `user` branch and `for_session`'s no-shared-credential fallback agree by
    construction — binding in the everybody-connects-their-own deployment works
    through a personal token the way it works for its owner. Every sentence below
    then names the owner, which is whose account genuinely needs reconnecting.
    """
    owner = personal_owner(principal)
    if owner is not None:
        principal = owner

    row = storage.active().find_connection(
        principal.tenant_id, principal.kind, principal.id, connector_id
    )
    if row is None:
        return None

    # Checked before the expiry, because it is the more specific answer and the two
    # co-occur constantly: a connection whose grant was revoked at the provider is also
    # a connection whose access token is about to expire, and "reconnect, because
    # Atlassian says the grant is gone" is a sentence somebody can act on where "it
    # expired" sends them to try again and watch it fail identically.
    #
    # **This raises rather than returning None**, which is the whole of 7a's third
    # outcome arriving through a new door. Returning None would fall through to
    # `_shared_credential` and the agent would quietly start acting as the *operator* —
    # reaching data the person has no access to and attributing it to them in a log kept
    # forever. See `mark_connection_reconsent` for why the row is kept rather than
    # deleted: deleting it is what would produce that fallback.
    reconsent = row.get("reconsent_reason") or ""
    if reconsent:
        raise CredentialError(
            f"the connection to '{connector_id}' for {principal} needs to be set up "
            f"again: {reconsent} This call is refused rather than falling back to the "
            "platform's shared credential, which would act as the operator while "
            "reporting it as you."
        )

    expires_at = row.get("expires_at")
    if expires_at is not None and expires_at <= datetime.now(timezone.utc):
        raise CredentialError(
            f"the connection to '{connector_id}' for {principal} expired on "
            f"{expires_at:%Y-%m-%d}. Reconnect that account — this call is refused "
            "rather than falling back to the platform's shared credential."
        )

    # The ciphertext is bound to exactly this row's identity, so a value moved between
    # principals or tenants fails here rather than decrypting into somebody else's run.
    aad = crypto.connection_aad(
        principal.tenant_id, principal.kind, principal.id, connector_id
    )

    try:
        value = crypto.open_(
            row["ciphertext"],
            tenant_id=principal.tenant_id,
            aad=aad,
            key_id=row["key_id"],
        )
    except crypto.CryptoError as exc:
        # Re-raised as a CredentialError so the broker treats it like any other
        # credential failure: the call does not happen, the refusal is audited, and the
        # model is told the tool is unavailable rather than being handed a reason it
        # could act on.
        raise CredentialError(
            f"the stored credential for '{connector_id}' could not be read. {exc}"
        ) from exc

    return Credential(access_token(value, row.get("credential_kind")), DELEGATED)


def _acted_for_credential(
    connector_id: str, principal, acting_for: ActingFor
) -> Credential:
    """The acted-for person's own connection, or a refusal naming them. Step 033c.

    Raises rather than returning None on every miss, because by the time this runs
    three decisions have already been made — the tool acts as a person (the vetting),
    the caller named which person (the door), and the claim was worth acting on
    (`access/acting.py` or the connector's opt-in). A call that then cannot resolve
    that person's account has nothing honest left to fall back to: not the shared
    credential (the operator's account under the person's name in the log) and not the
    calling service's own connection (a different person's account under the same
    lie). The broker turns this into the audited `allow`/`outcome="error"` record,
    which is where the sentence below reaches whoever can fix it.

    `user_id` is None when an asserted email matched no user row — the door lets that
    through deliberately, because on a `service` tool the assertion is only an audit
    fact. Here it has to become an account and cannot.
    """
    if acting_for.user_id is None:
        raise CredentialError(
            f"'{connector_id}' acts as the person calling it, and the asserted "
            f"identity '{acting_for.email}' matches nobody with an account here. "
            "That person signs in once and connects an account:\n"
            f"    carnet --connect-account {connector_id}\n"
            "  or the Connections page. Nothing was called."
        )

    person = Principal.user(acting_for.user_id, principal.tenant_id)
    delegated = _delegated_credential(connector_id, person)
    if delegated is None:
        raise CredentialError(
            f"'{connector_id}' acts as the person calling it, and "
            f"{acting_for.email} has no account connected for it. They connect one:\n"
            f"    carnet --connect-account {connector_id}\n"
            "  or the Connections page. This call is refused rather than falling "
            "back to any other account, which would act as somebody else while the "
            "audit log named them."
        )
    return delegated


# The two names inside a sealed OAuth credential. Duplicated from
# `access.connections.OAuthTokens` rather than imported, and the duplication is the
# layering: `core/` sits **below** `access/` and importing upward would be the cycle
# finding 5 spends a paragraph on. Two constants in two modules is the cost of that
# boundary, and it is a cheap one — they are field names in a format this codebase owns
# on both sides, and `test_an_oauth_credential_round_trips_through_storage` fails if they
# ever drift apart.
_OAUTH_ACCESS = "access"


def access_token(sealed: str, credential_kind: str | None) -> str:
    """The token to authenticate with, out of whatever this row's `credential_kind` says.

    **Told, never inferred.** `json.loads` on a bare token usually raises and sometimes
    does not — a token that happens to be all digits parses as a number, one that happens
    to be `null` parses as None — so sniffing would work for years and then hand a
    connector the string `None`. Migration 024 exists so this function is a lookup.

    A `static` row is its own answer, which keeps every connection written before this
    step working with no back-fill: they were all pasted in, and the column's default
    says so.
    """
    if credential_kind != OAUTH:
        return sealed

    try:
        parsed = json.loads(sealed)
        token = parsed[_OAUTH_ACCESS]
    except (ValueError, TypeError, KeyError) as exc:
        # The row says `oauth` and does not contain an OAuth credential. That is not a
        # recoverable state and must not degrade to treating the ciphertext as a bare
        # token: the value would be sent to a vendor as an `Authorization` header, which
        # is a JSON document containing somebody's refresh token posted to a third party.
        raise CredentialError(
            f"a connection marked '{OAUTH}' did not decrypt to an OAuth credential "
            f"({type(exc).__name__}). Reconnect the account — the row is not something "
            "this can guess its way out of, and guessing would send the sealed value "
            "itself to a vendor."
        ) from exc

    if not isinstance(token, str) or not token:
        raise CredentialError(
            f"a connection marked '{OAUTH}' carries no access token. Reconnect the "
            "account."
        )
    return token


def _reference_credential(connector_id: str, ref: str) -> Credential:
    """The organisational credential, read from the customer's vault at call time.

    The third lookup the register asked for, beside `_shared_credential` and
    `_delegated_credential` — and it is a third **encoding**, not a third identity:
    `source` is `SHARED`, because a pointer to the organisation's token is the
    organisation's token. See the block beside `SHARED` for why that is the one decision
    here that could not have been corrected later.

    **`SHARED` and not `DELEGATED`, structurally**: this is reached only from
    `_shared_credential`, which the `user` identity branch never calls. A pointer on a
    connector all of whose tools are `user` is simply never read — which is a real dead
    field and is in the plan's known limits.

    **Raises rather than returning None on every miss.** `_shared_credential` returns
    None for an unset environment variable because "no credential configured" is a legal
    state a server answers 401 to. A pointer is not that: somebody wrote a reference,
    which is a statement that there *is* a credential and where it lives, so a pointer
    that does not resolve is broken rather than absent. Returning None would send the
    call out unauthenticated and let a vendor's 401 be the error message — which is
    `_delegated_credential`'s own asymmetry, at the third address.

    This module still learns nothing about vaults: it is handed a *string* and hands it
    to `core/vault`, exactly as it is handed a variable *name* and hands it to
    `os.environ`. What it does gain is the first outbound call in its own life — see
    `for_connector`'s finding-5 paragraph, which is amended rather than contradicted.
    """
    try:
        pointer = vault.parse(ref)
        return Credential(vault.resolve(pointer), SHARED)
    except vault.VaultError as exc:
        # Re-raised as a `CredentialError` so the broker treats it like any other
        # credential failure: the call does not happen, the refusal is audited, and the
        # model is told the tool is unavailable. The sentence survives verbatim, which
        # is the whole reason `core/vault` writes nine of them instead of one — and it
        # is prefixed with the connector, because by the time it reaches somebody the
        # only context left is which tool went unavailable.
        raise CredentialError(f"'{connector_id}': {exc}") from exc


def _shared_credential(
    connector_id: str, env_var: str | None, ref: str | None = None
) -> Credential | None:
    """The organisational credential: one environment variable, the same for everybody.

    Still the right answer for a headless run, for anybody who has not connected an
    account, and for a connector whose credential genuinely is the company's rather
    than a person's.

    **Or a reference into the customer's own vault — step 070.** `ref` and `env_var` are
    two fields rather than one sniffed field, on `access_token`'s sentence: *told, never
    inferred.* An environment variable's name can never contain `:` or `/`, so one field
    holding either would in fact be unambiguous — and it would make every reader of the
    manifest wrong about what the row says, from the admin screen to the next person.
    Setting both is refused here as well as at registration, for `mcp.egress.check`'s
    reason: a stored row outlives the moment it was written, and a path may have skipped
    the registration check.

    **No tenant is passed, and the plan said one would be.** 070 decided the vault would
    be dialled against `tenant_egress_hosts`; `core/vault` reverses it — the vault URL is
    the operator's, in the deployment's environment, and a pointer contributes path
    segments only, so no row decides where anything dials. The argument is written out
    there. The visible consequence here is that this signature did not have to grow a
    tenant, which is also the tell that the check would have been decoration.
    """
    if ref:
        if env_var:
            raise CredentialError(
                f"connector '{connector_id}' has both a credential_env "
                f"({env_var!r}) and a credential_ref ({ref!r}), and there is no rule "
                "for which wins. A connector's shared credential is one or the other: "
                "an environment variable this deployment holds, or a reference into "
                "your own vault that is read at call time. Clear one of them."
            )
        return _reference_credential(connector_id, ref)

    env_var = env_var or CONNECTOR_CREDENTIAL_ENV.get(connector_id)
    if not env_var:
        return None

    if config.is_platform_env(env_var):
        raise CredentialError(
            f"connector '{connector_id}' asks for {env_var}, which is one of the "
            "platform's own environment variables and is never sent to a vetted server. "
            "A connector's credential must be its own — a variable outside the "
            "CARNET_ namespace, or one under CARNET_CONNECTOR_."
        )

    value = os.environ.get(env_var)
    return Credential(value, SHARED) if value else None


def for_tool(
    tool_name: str,
    tool_input: dict,
    principal,
    *,
    connector: str | None = None,
    identity: str = SERVICE_IDENTITY,
    env_var: str | None = None,
    credential_ref: str | None = None,
    acting_for: ActingFor | None = None,
) -> ToolCredentials:
    """Return the credential kwargs a given tool call needs, and how they were obtained.

    Keys returned here are injected into the tool function by the broker. They are
    deliberately NOT part of any tool's input_schema, so the model has no way to
    supply or override them.

    Keyed by **(tool, principal)**, because there are two kinds of credential and only
    one of them is a property of the tool alone:

      shared     one organisational secret, the same for everyone. The #eng webhook is
                 this: whoever asks, the message lands in the same channel, and the
                 broker's permission check is what decides who may ask.
      delegated  each user connects their own account, and the vendor enforces what
                 that account can see. A ticket agent run by two people must reach two
                 different sets of tickets, and no policy of ours can produce that —
                 it is the credential that differs.

    The principal was in this signature for four steps before anything read it, so that
    delegation would be a lookup rather than a change to this signature, the broker's
    call site and every connector at once. `for_connector` now reads it.

    `credential_ref` is step 070's `op://vault/item/field`, threaded exactly as `env_var`
    is and for the same reason: this module is told a *location* and never learns what an
    MCP server, or a vault, is. **Nothing above this function learns anything either** —
    a reference resolves to the same `Credential`, with the same `source`, so the broker,
    the door cannot tell a vault-backed connector from an
    environment-variable one. That is 067's first constraint, and it is the same
    discipline 069 kept when it refused to let a simulator hold a second opinion about
    permission.
    """
    # A connector tool's credential belongs to its server, not to the tool. The broker
    # passes the connector id, the vetted identity and the manifest's variable name off
    # the Tool, so this module never learns what an MCP server is and core/ keeps
    # knowing no specific tool.
    if connector is not None:
        credential = for_connector(
            connector,
            principal,
            env_var,
            identity=identity,
            acting_for=acting_for,
            ref=credential_ref,
        )
        if credential is None:
            # No credential configured at all. Not an error here: some servers need
            # none, and one that does will answer 401 — which is its answer to give.
            return ToolCredentials({"token": None}, None)
        return ToolCredentials({"token": credential.value}, credential.source)

    if tool_name == "post_message":
        # Shared: a channel's webhook is the organisation's, not the caller's, and no
        # amount of delegation changes that. A channel with no mapping has no secret to
        # send with, which is the second enforcement point described above.
        return ToolCredentials(
            {"webhook_url": _webhook_for_channel(tool_input.get("channel", ""))}, SHARED
        )

    # A tool that needs no secret. Distinct from "shared" on purpose: the audit log
    # should not imply an organisational credential was used where none exists.
    return ToolCredentials({}, None)
