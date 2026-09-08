"""API tokens: where a machine becomes a `Principal`. Step 020.

Every caller until now was a human. `api/deps.py` ended at `users.resolve`, which needs a
subject claim and gates first-time creation on an email domain — so a cron job, a CI
pipeline or a webhook receiver could not submit a run at all. This module is the other
door, and it is deliberately a *second* door rather than a branch inside the first: a
token shape decides which one it goes through, and neither ever falls back to the other.

```
Authorization: Bearer art_<id>.<secret>
        │
        ▼
_split()                 shape. Not a JWT, so nothing here retries as one
        │                 ── malformed ──► 401
        ▼
find_api_token(id)       tenantless: the token is what PRODUCES a tenant
        │                 ── unknown / wrong secret / revoked / expired ──► 401
        ▼
require_active_tenant()  the suspension gate, shared verbatim with the human door
        │                 ── suspended ──► 403
        ▼
the owner is live        a machine belongs to a person, checked every request
        │                 ── missing / disabled ──► 403
        ▼
Principal.machine(id, tenant_id)         an administrator NOWHERE
```

## The one sentence

Unknown id, wrong secret, revoked, expired: **one refusal, byte for byte the same as the
one an unregistered issuer gets**, produced by raising the same `TokenError` that
`providers.resolve` raises and letting `deps.py`'s existing handler write it. Saying
"revoked" would confirm to whoever is holding a stolen token that it was real and once
worked, which is the anti-enumeration argument `api/errors.py` already makes about the
404 for an agent nobody shared with you.

The two 403s *are* specific, on the same reasoning `deps.py` documents for the human
door: authenticating again will not help, and the operator reading the log needs to know
which of the two it was. Neither reveals anything to somebody who does not already hold a
valid credential, because both are reached only after the secret has been verified.

## `machine` is not `system`, and this module is why that mattered

`access/roles.py` treats every `system` principal as an administrator — before storage is
touched — and its docstring records that this is safe *because no HTTP caller can be one*.
This module is the first thing that could have broken that sentence. It does not:
`Principal.machine` is a third kind, `roles.is_admin` falls through to `platform_roles`
for it, and `check_platform_role` refuses to put one there. See migration 031, which
widens six CHECK constraints and pointedly leaves two narrow.

`test_a_machine_token_never_resolves_to_a_system_principal` and the source-text assertion
on this file are what pin it, on `test_http_can_never_mint_a_system_principal`'s pattern.

## What this module does not do

It does not mint for a **bearer**. Minting is `cli.py`'s, on 12b decision 5's argument
— see `mint`'s own docstring for why a token is a sharper case of it than a role was —
and the two HTTP callers that exist since are both gated on a *person's* session and
refuse a machine before reading a byte: `POST /me/tokens` (044) and the OAuth exchange
(083, `access/oauth_server.py`), whose code is issued only to a signed-in person and
whose only grant type is `authorization_code`. A credential that survives its presenter
still cannot create another.
"""

import hashlib
import hmac
import logging
import secrets
import uuid
from datetime import datetime, timezone

from .. import storage
from ..core import Principal
from ..storage import API_TOKEN_PREFIX, API_TOKEN_SEPARATOR
from .oidc import TokenError
from .users import AccessDenied, require_active_tenant

log = logging.getLogger(__name__)

# The secret's entropy, in bytes, before base64. 32 bytes is 256 bits — the same order as
# the AES key in `core/crypto.py`, and the reason no password-stretching KDF is used to
# hash it: scrypt and argon2 exist to make a *guessable* secret expensive to guess, and
# there is nothing here to guess.
SECRET_BYTES = 32

# Domain separation, on `core/crypto.py`'s `_KEY_ID_DOMAIN` pattern. It costs nothing and
# it means a digest from this table can never be confused with, or replayed against, a
# digest computed anywhere else in the system.
_HASH_DOMAIN = b"carnet/api-token/v1"

# Self-describing: the algorithm is *in* the stored value, so moving to another one is a
# rehash on next mint rather than a schema change and a migration that cannot read what
# it is replacing. The same record shape the bundled identity provider uses for password
# hashes — deliberately described rather than named, because `api/` and `access/` may not
# reference that package and a test walks both directories asserting it.
_HASH_SCHEME = "sha256"

# What a token id looks like. `m_` for machine, so a `machine:m_...` string in an audit
# record is legible beside `user:u_...` without a lookup — and 16 hex characters of
# uuid4, exactly as `access/users.py` mints a user id, because an id that leaks anything
# about what it names is one somebody eventually parses.
ID_PREFIX = "m_"
ID_HEX = 16


def new_token_id() -> str:
    return f"{ID_PREFIX}{uuid.uuid4().hex[:ID_HEX]}"


def digest(secret: str) -> str:
    """The stored form of a presented secret. Never reversible, and never needs to be."""
    body = hashlib.sha256(_HASH_DOMAIN + secret.encode("utf-8")).hexdigest()
    return f"{_HASH_SCHEME}${body}"


def format_token(token_id: str, secret: str) -> str:
    """`art_m_<hex>.<secret>` — the string a machine presents, assembled in one place.

    The prefix is what `api/deps.py` dispatches on, and it is why that dispatch needs no
    parsing and cannot be ambiguous: a JWT is base64 of `{"alg"...` and begins `eyJ`.
    The id travels in the clear on purpose — it is the lookup key, and hiding it would
    mean scanning every row and comparing every hash to find out whose token this is.
    """
    return f"{API_TOKEN_PREFIX}{token_id}{API_TOKEN_SEPARATOR}{secret}"


def looks_like_api_token(presented: str) -> bool:
    """Which door this string goes through. Shape only — never validity."""
    return presented.startswith(API_TOKEN_PREFIX)


def new_presented() -> str:
    """A token with no row behind it yet — `carnet --new-token`, step 095.

    The fileborne door declares its tokens in `carnet.yaml` as `${ENV}` pointers, and
    the variable has to hold the *presented* string: the file may not hold a secret, and
    a digest cannot make one. So this is `mint` with the store taken out — the same id
    shape, the same `token_urlsafe` secret, the same `format_token` — and the row is
    written at boot by `carnetfile.apply`, from the digest, exactly as `mint` would have
    written it. The plaintext exists in one place: the line this returns.
    """
    return format_token(new_token_id(), secrets.token_urlsafe(SECRET_BYTES))


def digest_presented(presented: str) -> tuple[str, str]:
    """`art_m_<hex>.<secret>` -> `(token_id, digest)`. Raises `TokenError` on any other shape.

    The loader's half of `new_presented`: it holds the secret for exactly as long as it
    takes to hash it, and hands storage the id and the digest — the same two fields
    `mint` hands it — so `resolve` cannot tell a file-declared token from a minted one.
    """
    token_id, secret = _split(presented)
    return token_id, digest(secret)


def mint(
    tenant_id: str,
    name: str,
    owner_id: str,
    *,
    actor: str,
    expires_at: datetime | None = None,
    acts_as_owner: bool = False,
    via: str = "",
) -> tuple[dict, str]:
    """Create a token. Returns the row and **the only copy of its secret**.

    The secret is generated here, hashed here, and the plaintext is returned to exactly
    one caller and stored nowhere. `storage` is handed the digest and never sees the
    secret, which is the same division `core/crypto.py` has with `connections` and for
    the same reason: a layer that cannot see a secret cannot log one.

    **`acts_as_owner` — step 033d — is chosen here and never changed.** True mints a
    *personal* token: its access is resolved through its owner (the owner's grants and
    group memberships, capped at `user`), it may hold no grant of its own, and a
    `user`-identity tool it calls acts as the owner's connected account. False is
    020's service token, unchanged. There is no update path — to change kind, mint the
    other kind; the name-recycling index frees the name on revocation.

    **One HTTP caller, and the old refusal is narrowed rather than repealed — step
    044.** This docstring said *"there is no HTTP caller and there is deliberately no
    route"*, on 12b decision 5's argument: what a stolen bearer token lacks is
    *persistence*, and a mint route would hand it a durable successor. That argument is
    kept where it bites — `POST /me/tokens` refuses every **machine** principal before
    validation, so no credential that survives its presenter can create another — and
    released where it never did: a browser *session* minting a token owned by its own
    person is the actor 022b already let create a schedule and 023b already let hold a
    trigger secret, with the same recorded cost. The route mints for its caller only;
    minting for someone else stays here at the terminal. The secret does now cross one
    HTTP response body, once — the trade 023b priced for trigger secrets, given up for
    self-serve.
    """
    secret = secrets.token_urlsafe(SECRET_BYTES)
    row = storage.active().create_api_token(
        tenant_id,
        {
            "id": new_token_id(),
            "name": name,
            "owner_id": owner_id,
            "acts_as_owner": acts_as_owner,
            "secret_hash": digest(secret),
            "expires_at": expires_at,
            "via": via,
        },
        actor=actor,
    )
    return row, format_token(row["id"], secret)


def _refuse() -> TokenError:
    """The one sentence, for every way a presented token can fail to be a live one.

    Raising the same class `providers.resolve` raises rather than a new one, so the
    refusal a machine gets is byte-identical to the refusal a forged JWT gets **by
    construction** rather than by two strings being kept in step. `deps.py` writes it.
    """
    return TokenError("not a valid token for this service")


def _split(presented: str) -> tuple[str, str]:
    """`art_m_<hex>.<secret>` -> `('m_<hex>', '<secret>')`. Raises on anything else.

    Partitioning on the **first** dot: `token_urlsafe` emits `-` and `_` and never a dot,
    so the separator is unambiguous, and the id is the half whose shape this module
    controls. The stored id keeps its own `m_` prefix rather than having it stripped and
    re-added — it is `Principal.id`, and an identifier that is spelled one way in a
    credential and another way in an audit record is a lookup somebody gets wrong.
    """
    body = presented[len(API_TOKEN_PREFIX) :]
    token_id, separator, secret = body.partition(API_TOKEN_SEPARATOR)
    if not separator or not token_id or not secret:
        raise _refuse()
    return token_id, secret


def check_row_is_live(store, row: dict, *, presented: bool) -> None:
    """The four checks that are about the **row** rather than about the presenter.

    Revoked, expired, the customer suspended, the owner gone. Raises, or returns.

    **One function because there are now two ways to become a machine principal**, and
    step 021's sharpest defect was a rule stated twice that guarded one path: 020's
    machine ceiling was written in `MACHINE_ROLES` *and* in a CHECK constraint, both
    guarding a direct grant, and a machine in an editor group walked past both. So the
    scheduler (022) does not get its own copy of these — it calls this, and a fifth check
    added here is one every caller inherits.

    `presented` is what differs between the callers, and it names exactly the thing that
    differs. **True** is `resolve`: somebody handed us a credential, so revoked and
    expired collapse into the single anti-enumeration sentence — saying "revoked" tells
    whoever holds a stolen token that it was real and once worked. **False** is
    `act_for`: nothing was presented, the row is one this platform already trusts, and
    the reader of the refusal is an operator asking why nothing ran at 7am. There is
    nobody to enumerate anything to, and "not a valid token for this service" stamped on
    a schedule would be an answer to a question nobody asked.

    The two 403s are specific either way, on the reasoning `deps.py` documents: they are
    unreachable without a valid credential, and the operator reading a log needs to know
    which of the two it was.
    """
    if row["revoked_at"] is not None:
        log.info("refused revoked api token %s", row["id"])
        if presented:
            raise _refuse()
        raise AccessDenied(
            f"API token '{row['id']}' was revoked at "
            f"{row['revoked_at'].isoformat(timespec='seconds')}. Revocation closes a "
            "door and reaches through none — anything already queued still runs."
        )

    # Strictly `<=`, so a token at exactly `expires_at` is refused: a boundary must have
    # one answer, and the one that keeps a credential alive is the wrong one to guess.
    if row["expires_at"] is not None and row["expires_at"] <= datetime.now(timezone.utc):
        log.info("refused expired api token %s", row["id"])
        if presented:
            raise _refuse()
        raise AccessDenied(
            f"API token '{row['id']}' expired at "
            f"{row['expires_at'].isoformat(timespec='seconds')}. Mint a replacement and "
            "point this at it — an expiry is not something anything here can extend."
        )

    # **The third door suspension has to close.** Migration 020 named two — authentication
    # and the claim loop — and this is a way work arrives that did not exist then. Called
    # rather than reimplemented so the sentence is the same one a person gets, which is
    # asserted by equality rather than by both being written carefully.
    #
    # 022 makes it a fourth door and needs no line here, which is the point of calling it.
    require_active_tenant(store, row["tenant_id"])

    # **A machine belongs to a person, and the person is checked live.** This is what
    # makes offboarding somebody offboard their machines: `set_user_status` is described
    # as "the only thing that can cut somebody off immediately", and without this that
    # sentence would have quietly stopped being true the day tokens shipped.
    #
    # Fail closed on a missing row as well as a disabled one. There is no user-delete
    # path today, so the first branch is defence rather than a case — and the direction
    # to be wrong in is obvious.
    owner = store.get_user(row["tenant_id"], row["owner_id"])
    if owner is None or owner["status"] != "active":
        log.info("refused api token %s: owner %s is not live", row["id"], row["owner_id"])
        raise AccessDenied(
            f"the owner of this API token ('{row['owner_id']}') is no longer an active "
            "account, so the token does not act for anybody. A machine credential "
            "belongs to a person; when they go, it goes."
        )


def resolve(presented: str) -> Principal:
    """The principal this token acts as, or refuse. The only caller is `api/deps.py`.

    Ordering is deliberate and is the reason this reads as five checks rather than one
    query: **nothing about a row is acted on until the presenter has proved they hold
    the secret.** So a wrong secret and a revoked token do the same work and produce the
    same sentence, and the two 403s in `check_row_is_live` — which are specific, and must
    be — are unreachable without a valid credential.
    """
    token_id, secret = _split(presented)
    store = storage.active()
    row = store.find_api_token(token_id)

    if row is None:
        # A timing equalizer, on the same reasoning the bundled identity provider's
        # login check uses: without it an unknown id answers measurably faster than a
        # known one with a wrong secret, which turns this endpoint into an oracle for
        # which token ids exist.
        hmac.compare_digest(digest(secret), digest("timing-equalizer"))
        raise _refuse()

    if not hmac.compare_digest(digest(secret), row["secret_hash"]):
        raise _refuse()

    check_row_is_live(store, row, presented=True)

    store.touch_api_token(token_id)
    return Principal.machine(token_id, row["tenant_id"])


def act_for(tenant_id: str, token_id: str) -> Principal:
    """The principal a **stored** token id acts as. Step 022's only new entry point.

    `resolve` answers "who is presenting this credential"; this answers "who does this
    row act as", and the difference is that nothing is presented. The scheduler holds a
    `schedules` row naming a token by id, in-process, and never sees or needs a secret —
    which is why a schedule stores no credential and a stolen `schedules` row is a piece
    of configuration rather than a key.

    **Everything else is identical, and deliberately so.** The same four row checks in
    the same order, from the same function, so revoking a token, letting it expire,
    disabling its owner or suspending the customer each stop that customer's schedules at
    the next due instant with no rule written a second time. This is where the register's
    "a schedule is a machine caller with a clock" stops being a slogan and becomes a
    function call.

    `tenant_id` is passed and checked rather than taken from the row, because the caller
    already knows which customer it is acting for and a row fetched by a global id could
    otherwise carry a different one. `find_api_token` is tenantless by design (it is what
    *produces* a tenant for `resolve`), so this is the check that keeps that shape safe
    for a caller that already has one.

    Raises `AccessDenied` for every way a fire cannot happen, so one `except` in the
    scheduler catches them all and stamps the sentence where an operator will read it.
    """
    store = storage.active()
    row = store.find_api_token(token_id)

    if row is None or row["tenant_id"] != tenant_id:
        raise AccessDenied(
            f"there is no API token '{token_id}' in this customer, so nothing can fire "
            "as it. A token is never deleted, only revoked — so this id was either never "
            "minted here or belongs to somebody else."
        )

    check_row_is_live(store, row, presented=False)

    # Stamped, exactly as a request stamps it. A fire **is** a use of this token's
    # authority, and `--list-tokens`' "is this credential still in use" answer would
    # otherwise say `never` about a token that has been running an agent nightly for a
    # year — which is the one question an offboarding review asks that nothing else can.
    store.touch_api_token(token_id)
    return Principal.machine(token_id, row["tenant_id"])


def require_owner_or_admin(principal: Principal, token_id: str) -> dict:
    """The token row, once this principal is established as entitled to aim it.

    Raises `ValueRefused` if this principal may not aim this token — **whether that is
    because it does not exist or because it is somebody else's, in one sentence that
    cannot tell them apart.**

    ## The two refusals became one — step 069

    They used to be two. `ValueRefused` for an id this customer does not have, and an
    `AccessDenied` for one that belongs to a colleague, which also **named the owner**.
    Within a tenant that pair is an existence oracle over token ids, and 028 already
    decided this shape for a different id: *"any difference between 'not yours' and 'not
    there' turns the id into a way to enumerate colleagues' uploads."* 069 needed the
    rule at a new surface and found it owed here, which is where it is fixed — one seam,
    five callers, rather than one route quietly holding a stricter opinion than its four
    neighbours.

    **The collapse costs no legitimate caller a sentence, and that is what makes it
    right rather than merely safe.** The refused branch is reached only when the caller
    is neither an administrator nor the owner — and an administrator administers every
    token in this tenant, so they never see it. Every caller who has ever read that
    refusal is exactly a caller who must not be told the token exists.

    What is lost is the explanation, and the explanation was the leak: *"only <owner> …
    may aim it"* named a colleague to somebody with no claim on the row. It also named
    the wrong verb for one of its callers (`reach` only reads), which `DEFERRED.md` has
    carried since 035d and which goes with it.

    The refusal **family** is unchanged: `ValueRefused` → 400, not a 503 and not a new
    404. 035d reasons about why a mistyped id must not look like an outage, and changing
    the status as well as the distinction would be a second decision this needed none of.

    **One rule, two features, however many verbs.** Deciding when a token's authority
    runs — creating a schedule or a trigger, turning one on or off, deleting one — is
    the same act as holding the token, so it takes the same permission, written once.
    It was `schedules._require_may_schedule` for one step; 023 hoisted it here the day
    a second module needed it, which is 021's `role_of` lesson applied on schedule
    rather than after a defect: a control written at one surface is a control the next
    surface does not have.

    **An agent's owner is deliberately not on this list**, and the asymmetry is a
    decision rather than a gap: what an agent's owner controls is whether the machine
    may run their agent at all, and revoking that grant silences every schedule and
    trigger aimed at it at the next fire, with a denial row saying so. They can defang
    what they cannot delete — the right shape, because the standing instruction is the
    token holder's and the grant is theirs.
    """
    from . import roles
    from ..storage import ValueRefused

    # One sentence, both refusals, and it is deliberately the *absence* sentence rather
    # than a new neutral one: a caller who mistyped an id is the common case and is owed
    # the two flags that fix it, while a caller reaching for somebody else's token learns
    # only what a caller reaching for nothing learns.
    #
    # `ValueRefused` (400 over HTTP), not `StorageError` (503). A mistyped id is the
    # caller's, and the wrong refusal family sends somebody to read logs about an outage
    # that did not happen — 021's 503-for-a-machine-editor lesson.
    refused = ValueRefused(
        f"there is no API token '{token_id}' you may aim. `--list-tokens` shows the "
        "ids you can; `--mint-token` makes one."
    )

    token = storage.active().find_api_token(token_id)
    if token is None or token["tenant_id"] != principal.tenant_id:
        raise refused

    if not roles.is_admin(principal) and not _is_owner(principal, token):
        raise refused

    return token


def _is_owner(principal: Principal, token: dict) -> bool:
    """Whether this principal is the person a token belongs to.

    `kind` is compared as well as `id` because ids are minted per population and nothing
    guarantees a machine's id can never equal a user's — a comparison on `id` alone is
    the kind that is true until the day it is not.
    """
    return principal.kind == "user" and principal.id == token["owner_id"]
