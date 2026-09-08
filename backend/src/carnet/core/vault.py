"""Resolve a credential held in the customer's vault, at call time. Step 070.

Item 3 of plan 067, and the whole of it is one sentence a customer says back to us:

    "If you would rather we didn't hold it, we don't have to."

Not *we cannot read your keys* — see `Known limits` in the plan, and the paragraph on
`CARNET_VAULT_TOKEN` below. What is true is narrower and still worth buying: the
secret is not at rest in this database, it is not in `--finish-rotation`'s population,
and its lifetime inside this process is bounded: for a REST connector the resolved value
lives for one call; for an HTTP MCP connector it lives as long as the pooled session
(`mcp.POOL` keys a session by the credential and bakes it into the transport, up to
`CARNET_MCP_SESSION_IDLE_TTL` idle), so a rotation at the vault reaches an HTTP MCP
connector only when its session is evicted. The register's 070 rows carry the second half.

## The shape, and the half that did not transfer

onecli offers two vault integrations and only one of them is expressible here. Theirs
is the 1Password shape — a row holding `op://vault/item/field` **instead of** an
encrypted value, resolved through a service account at request time. Their Bitwarden
shape asks a paired vault, keyed by domain, when *no stored secret matched an outbound
request*; that is their MITM gateway's shape, and step 007 already wrote the sentence
this is the third recurrence of — *their proxy is the half that does not transfer*. We
broker named tools. There is no moment at which nothing matched.

## What this module is, in the layering

`core/` may import `tools/` (`core/broker.py` does; `config.py`'s own comment states the
direction), and `tools/mcp/egress` imports only `config` and `storage`, so the dial
below is downward even though the address reads upward. `access/oidc.py`,
`access/oauth.py` and `access/recipes.py` already import it the same way. The import is
made inside the function, as those three do, so nothing pays for the MCP package at
import time.

**Every request here goes through `egress.dial`.** Step 064's finding was that five
hand-assembled dial sites meant two of them never got pinned at all; a sixth that
assembled its own would be that finding recurring in the step that had just read it.

**Under operator consent, and NOT against the tenant's allowlist — which reverses what
plan 070 decided.** The plan said `tenant_egress_hosts` applies, so that a tenant who has
not approved the vault's host cannot resolve a pointer. Building it showed that is the
wrong control, on a precedent already in the tree: `access/oidc._fetch_jwks` dials a
tenant's `jwks_uri` — registered by the **operator**, with `--add-idp` — under
`operator_consented=True` and against no allowlist at all. This is the same shape. Three
reasons the plan's version is worse than it sounds:

  - **The tenant did not choose the address and cannot change it.** One vault per
    deployment, named in the operator's own environment. Requiring each tenant to
    `--allow-host` it is asking a customer to consent to a decision that was not theirs
    and that refusing does not undo — they decline the vault by not writing a pointer.
  - **A BYOC vault is on a private address**, which is what `CARNET_EGRESS_INTERNAL_HOSTS`
    exists for; `egress.check` refuses loopback and private *before* it reads the
    allowlist, so the plan's version would have made an internal 1Password Connect
    unreachable by any configuration. That is the shape almost every deployment has.
  - **There is no SSRF surface for an allowlist to bound.** The host comes from the
    deployment's environment and never from a row: a pointer contributes *path* segments
    only, percent-encoded by `item_path`. The thing a tenant allowlist protects against —
    a database row causing an outbound connection to somewhere the customer never
    approved — cannot happen here, which is the property that makes the check redundant
    rather than merely inconvenient.

What `dial` still guarantees under operator consent is the half that matters: the name is
resolved once and every answer vetted, the socket goes to the vetted address with the TLS
name kept, link-local (the metadata service) is refused under every flag, and a redirect
is never followed.

## The credential that opens the vault

`CARNET_VAULT_TOKEN` is a 1Password Connect service-account token and it lives in the
deployment's environment. It can read every item its vault grants — which, for any
pointer to resolve, includes the item behind every pointer. **That is the asterisk on
the claim**, it is in the plan's known limits, and it is written here as well so that
nobody has to find the plan to know it. Under BYOC the deployment is the customer's, so
the token is theirs, which is why this is deployment configuration and not a sealed row:
a table holding *the credential that opens every other credential*, sealed under the
platform key this feature exists to stop mattering, is the feature arguing with itself.

## The refusals are the deliverable

A sealed blob has two failure modes and both are local. A pointer has nine and most of
them are somebody else's network. The register's own words: *its refusal must name the
vault and the item rather than read as a generic credential error* — and 033b's lesson
is why: a true-sounding sentence that sends somebody to the wrong fix is worse than a
blunt one. A timeout that reads as "the credential is broken" sends an administrator to
reconnect an account that is fine.

What no refusal carries is **the item's field labels**. They would be the most useful
thing in the world for case 8, and a `CredentialError` becomes `Tool 'X' is unavailable:
…` and goes back through the door to whoever holds the token, and to the model. The
structure of an organisation's password vault is not owed to a caller. It is owed to an
administrator at a shell, which is what `carnet --check-credential` is for — see
`describe_fields`.
"""

import json
import time
from dataclasses import dataclass
from urllib.parse import quote, unquote

from .. import config

SCHEME = "op://"

# Every failure below is one of these, so a caller can tell "the vault said no" from
# "the reference is wrong" without matching on prose — 069's `Decision.rule` lesson,
# taken early rather than after somebody parses a sentence.
UNCONFIGURED = "unconfigured"
MALFORMED = "malformed"
REFUSED_EGRESS = "egress"
UNREACHABLE = "unreachable"
UNAUTHORIZED = "unauthorized"
NO_VAULT = "no_vault"
NO_ITEM = "no_item"
NO_FIELD = "no_field"
EMPTY = "empty"

# **A tenth, found by driving it rather than by planning it.** Plan 070 enumerated nine
# refusals; this one is not in that list because nothing about a *sealed* credential
# suggests it. A 1Password field is often a **note**, and a note is exactly where somebody
# pastes a key — so a resolved value routinely contains a line break, and a credential is
# presented in an HTTP header (`HttpLaunch.headers_for`, `RestLaunch.headers_for`), which
# cannot carry one. Without this, `requests` raises `InvalidHeader` two layers down and
# the model is told *"Invalid leading whitespace, reserved character(s), or return
# character(s) in header value"* — a true sentence about the wrong subject, which is 033b's
# lesson exactly. Refused here, naming the field.
UNUSABLE = "unusable"

# An eleventh, and it is the same refusal `_fetch_item` makes about two vaults sharing a
# name, one level down: **two fields match, so which secret goes to the vendor?** The
# first build answered *the first one*, silently, which is the one kind of guess this
# module exists not to make.
AMBIGUOUS = "ambiguous"


class VaultError(RuntimeError):
    """A pointer that did not become a credential, and which of the nine it was.

    `core/credentials.py` re-raises this as a `CredentialError` so the broker treats it
    like any other credential failure — the call does not happen, the refusal is
    audited, and the model is told the tool is unavailable. The sentence survives that
    translation verbatim, which is the whole point of writing nine of them.
    """

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class Pointer:
    """A parsed `op://` reference. Segments are decoded; nothing here is a secret.

    `section` is `''` for the three-segment form, which is what almost everybody
    writes. The four-segment form addresses a field inside a named section, because
    1Password items routinely carry two fields called `password` in different sections
    and a reference that cannot distinguish them would resolve to whichever came first.
    """

    vault: str
    item: str
    field: str
    section: str = ""

    def __str__(self) -> str:
        parts = [self.vault, self.item] + ([self.section] if self.section else [])
        parts.append(self.field)
        # Re-encoded, so a pointer echoed into a refusal is one that can be pasted back
        # into `--credential-ref`. A name containing a space round-trips as `%20`
        # rather than as a broken command line.
        return SCHEME + "/".join(quote(part, safe="") for part in parts)


def looks_like_reference(value: str) -> bool:
    """True for anything meant as a pointer, **including a malformed one**.

    Deliberately not "is a valid pointer": this is what `register_connector` and the
    admin form use to decide *which refusal to write*, and a value beginning `op://`
    with four slashes is a broken pointer rather than an environment variable. A
    predicate that answered False for it would send somebody to the wrong sentence,
    which is this module's whole subject.
    """
    return (value or "").strip().lower().startswith(SCHEME)


def parse(raw: str) -> Pointer:
    """`op://vault/item/field` or `op://vault/item/section/field`, or `VaultError`.

    Segments are percent-decoded, so a vault or item whose name contains a `/` is
    expressible and one containing a space needs nothing. Anything that is not `op://`
    is refused **by name** rather than attempted: a resolver that ignored a scheme it
    did not know would look up `vault://Engineering/…` as a 1Password item titled
    `vault:`, find nothing, and report a missing item — which is case 7's sentence
    describing case 2's problem.
    """
    value = (raw or "").strip()
    if not looks_like_reference(value):
        raise VaultError(
            MALFORMED,
            f"a credential reference must begin with '{SCHEME}' — got {value!r}. "
            f"1Password is the only vault this supports, and its references look like "
            f"{SCHEME}Engineering/GitHub/credential (or "
            f"{SCHEME}Engineering/GitHub/Section/credential to name a section). "
            "A connector whose credential is an environment variable uses "
            "--credential-env instead.",
        )

    parts = [unquote(part) for part in value[len(SCHEME) :].split("/")]
    if len(parts) not in (3, 4) or not all(part.strip() for part in parts):
        raise VaultError(
            MALFORMED,
            f"'{value}' is not a usable reference: it needs a vault, an item and a "
            f"field — {SCHEME}<vault>/<item>/<field>, or "
            f"{SCHEME}<vault>/<item>/<section>/<field> — and every part must be "
            f"non-empty. Got {len(parts)} part(s). A name containing a '/' is "
            "percent-encoded as %2F.",
        )

    if len(parts) == 3:
        return Pointer(vault=parts[0], item=parts[1], field=parts[2])
    return Pointer(vault=parts[0], item=parts[1], section=parts[2], field=parts[3])


# A 1Password Connect id: 26 lowercase base32 characters. Matched so a pointer written
# with ids costs **one** round trip where a pointer written with names costs three —
# the list endpoints do not return field values, so a name-addressed reference cannot
# be one request however it is asked. `--check-credential` prints the count, and the
# README says to use ids for a connector on a hot path.
_ID_LENGTH = 26


def _is_id(segment: str) -> bool:
    return len(segment) == _ID_LENGTH and all(
        char.isdigit() or ("a" <= char <= "z") for char in segment
    )


class _Deadline:
    """One budget for the whole resolution, not one timeout per hop.

    Three requests at three seconds each is a nine-second door call, and a caller's
    patience is not per-hop — `CARNET_VAULT_TIMEOUT_SECONDS` is what somebody sets
    when they mean *this must not hang*, and honouring it per request would make the
    setting mean a third of what it says.
    """

    # Never less than this per request, so an almost-exhausted budget produces a
    # timeout refusal rather than a connection that could not have succeeded.
    FLOOR = 0.05

    def __init__(self, seconds: float):
        self.total = seconds
        self.started = time.monotonic()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def remaining(self) -> float:
        left = self.total - self.elapsed
        if left <= self.FLOOR:
            raise _Expired()
        return left


class _Expired(Exception):
    """Budget gone. Translated to case 4 by the one handler in `resolve`."""


def configured() -> bool:
    """Whether this deployment has a vault at all. Read by the admin form and the CLI
    so a pointer can be refused at *registration* — while the command is still in
    somebody's shell — rather than at the first door call three days later."""
    return bool(config.VAULT_URL and config.VAULT_TOKEN)


def _unconfigured_error() -> VaultError:
    """Names the **file**, not the shell.

    `credentials.anthropic_api_key` spends a paragraph on why, and it cost somebody a
    real evening: an `export` lives in one terminal, so the thing works in that window
    and fails in the uvicorn somebody else started, in the worker, and in anything
    scheduled.
    """
    missing = [
        name
        for name, value in (
            ("CARNET_VAULT_URL", config.VAULT_URL),
            ("CARNET_VAULT_TOKEN", config.VAULT_TOKEN),
        )
        if not value
    ]
    return VaultError(
        UNCONFIGURED,
        "this connector's credential is held in a vault (its credential_ref is an "
        f"{SCHEME} reference), and this deployment has no vault configured: "
        f"{', '.join(missing)} {'is' if len(missing) == 1 else 'are'} not set.\n"
        "  Put both in backend/.env, beside CARNET_SECRET_KEY:\n"
        "      CARNET_VAULT_URL=https://vault.example.internal\n"
        "      CARNET_VAULT_TOKEN=<1Password Connect service-account token>\n"
        "  then restart the server, the worker and anything scheduled. An `export` in "
        "one terminal is not enough — every other process will still be missing it, "
        "and the failure shows up as a tool that is unavailable rather than as a "
        "variable that is absent."
    )


def resolve(pointer: Pointer) -> str:
    """The secret behind a pointer, or one of nine sentences. **Never cached.**

    The cache is refused rather than forgotten, and both halves of the argument are
    worth keeping where somebody will read them before adding one:

      - A cached secret is a held secret. The claim is *we do not hold it*, and a
        sixty-second cache puts an asterisk on that sentence in the one part of the
        product whose value is the absence of the asterisk.
      - Invalidation is what a vault is **for**. A customer rotates the item and
        expects the next call to use it; with a cache, *the next call* means *within a
        minute*, and a call authenticating with a token they believe they revoked is
        precisely what this feature is bought to prevent.

    The cost is one to three network round trips per call, measured rather than
    guessed — see `scripts/measure_door.py` and the register row.
    """
    if not configured():
        raise _unconfigured_error()

    deadline = _Deadline(config.VAULT_TIMEOUT_SECONDS)
    return _field_of(_item(pointer, deadline), pointer)


def describe_fields(pointer: Pointer) -> list:
    """The field labels an item carries. **For a shell, never for a refusal.**

    This is the half of case 8 that is genuinely useful — *you asked for `token`, the
    item has `credential`* — and it is kept out of `resolve`'s refusals on 069's oracle
    discipline, because those refusals reach the model. Here the audience is somebody
    at a CLI who can already open the vault, so telling them what is in it costs
    nothing.

    Values are never returned, only labels.
    """
    if not configured():
        raise _unconfigured_error()

    item = _item(pointer, _Deadline(config.VAULT_TIMEOUT_SECONDS))

    labels = []
    for field in item.get("fields") or []:
        if not isinstance(field, dict):
            continue
        section = ((field.get("section") or {}).get("label") or "").strip()
        label = (field.get("label") or field.get("id") or "").strip()
        if not label:
            continue
        labels.append(f"{section}/{label}" if section else label)
    return labels


def _item(pointer: Pointer, deadline: _Deadline) -> dict:
    """One item, over **one** connection, with the budget's expiry turned into a sentence.

    The single place a session is opened, so the three hops of a name-addressed reference
    share a connection rather than paying three TLS handshakes — and the single place
    `_Expired` becomes case 4, so `resolve` and `describe_fields` cannot disagree about
    what a spent budget says.
    """
    import requests

    try:
        with requests.Session() as session:
            return _fetch_item(session, pointer, deadline)
    except _Expired:
        raise _timeout_error(pointer, deadline) from None


def _timeout_error(pointer: Pointer, deadline: _Deadline) -> VaultError:
    """Case 4, and the sentence says **it is not a credential problem**.

    This is the refusal a generic message destroys most completely. A vault that is
    slow or down produces a credential error, and a credential error sends an
    administrator to reconnect an account, rotate a token, or re-vet a connector —
    three fixes for a problem none of them touches. It names the elapsed time rather
    than asserting the vault is down, because from this side of the socket a vault
    that answers in four seconds under a three-second deadline is indistinguishable
    from one that is switched off.
    """
    return VaultError(
        UNREACHABLE,
        f"the vault did not answer in time, so this connector's credential could not "
        f"be read.\n"
        f"  reference  {pointer}\n"
        f"  vault      {config.VAULT_URL} (gave up after "
        f"{deadline.elapsed:.1f}s of a {deadline.total:.1f}s budget)\n"
        "  Nothing was called. This is not a permission problem and not a missing "
        "credential — the reference is stored and well-formed, and the vault at the "
        "address above did not return it in time. Check that the vault is reachable "
        "from this deployment, then retry; raise CARNET_VAULT_TIMEOUT_SECONDS if it "
        "is merely slow.",
    )


def _get(
    session, path: str, pointer: Pointer, deadline: _Deadline, by_id: bool = False, **params
):
    """One pinned GET against Connect, or the refusal it earned.

    `by_id` says whether an id **the customer wrote** is in this request's path, because
    a 404 means two different things by it — see the branch below.

    The dial goes through `egress.dial` — see the module docstring — under **operator**
    consent, so the address that was checked is the address the socket goes to, every DNS
    answer is vetted, link-local is refused whatever the setting, and a redirect is never
    followed.

    **The session is the caller's, and both reasons are corrections.** It was created here,
    per request, which was wrong twice: the streamed body was then read *after* the
    `with` had closed the session — working only because urllib3's response holds its own
    connection, which is not a promise anybody made — and a name-addressed reference paid
    a fresh TCP and TLS handshake on each of its three hops. One session for the whole
    resolution fixes both, and `egress.mount_pinned` is idempotent per host, so the pin is
    established once and reused.

    **The body is streamed against the deadline rather than buffered**, and both halves of
    that are a fix rather than a style. `requests`' read timeout is *between* reads, so a
    server that never stalls longer than the timeout never trips it: measured at a
    **5.92s hold under a 0.4s budget** against a vault answering one byte every 100ms —
    on the door's hot path, holding an MCP request open the whole time, while `_Deadline`,
    `config.CARNET_VAULT_TIMEOUT_SECONDS` and this module's own timeout sentence all
    claimed a whole-resolution budget. A timeout that is only true of a server that stops
    answering is not the timeout anybody set. The same read also bounds the **size**: a
    vault answering without end is the identical hold with no clock involved.
    """
    import requests

    from ..tools.mcp import egress

    url = config.VAULT_URL.rstrip("/") + path
    timeout = deadline.remaining()

    try:
        response = egress.dial(
            session,
            "GET",
            url,
            # Read against the clock rather than buffered — see `_read_bounded`.
            stream=True,
            # See the module docstring: the address is the operator's, written in
            # the deployment's own environment, and a BYOC vault is on a private
            # network. `egress.check` is deliberately not called — the pointer
            # contributes path segments only, so no row decides where this dials.
            operator_consented=True,
            headers={
                "Authorization": f"Bearer {config.VAULT_TOKEN}",
                "Accept": "application/json",
            },
            params=params or None,
            timeout=(timeout, timeout),
        )
    except egress.EgressRefused as exc:
        # Case 3. Under operator consent this is now the narrow set — a vault URL that
        # does not resolve, or that resolves to link-local, which no setting admits.
        # The egress sentence names the address; this says which reference sent us
        # there, because an administrator reading "'…' will not be dialled" during a
        # tool call has no way to know a *credential* asked for it.
        raise VaultError(
            REFUSED_EGRESS,
            f"this connector's credential is held at {config.VAULT_URL}, and that "
            f"address will not be dialled.\n"
            f"  reference  {pointer}\n"
            f"  {exc}\n"
            "  CARNET_VAULT_URL is this deployment's own setting; nothing a customer "
            "configures can change it.",
        ) from exc
    except requests.exceptions.Timeout:
        raise _Expired() from None
    except requests.RequestException as exc:
        raise VaultError(
            UNREACHABLE,
            f"the vault could not be reached, so this connector's credential could "
            f"not be read.\n"
            f"  reference  {pointer}\n"
            f"  vault      {config.VAULT_URL}\n"
            f"  {type(exc).__name__}: {exc}\n"
            "  Nothing was called. This is not a permission problem and not a missing "
            "credential — the reference is stored and well-formed, and the vault did "
            "not answer.",
        ) from exc

    if response.status_code in (401, 403):
        # Case 5. **Our** service account, never the caller's — said explicitly,
        # because "unauthorized" during a tool call reads as the caller's problem and
        # the caller cannot fix this one.
        raise VaultError(
            UNAUTHORIZED,
            f"the vault refused this deployment's own service account (HTTP "
            f"{response.status_code}), so this connector's credential could not be "
            f"read.\n"
            f"  reference  {pointer}\n"
            f"  vault      {config.VAULT_URL}\n"
            "  Nothing was called, and this is not about the caller's permissions: "
            "CARNET_VAULT_TOKEN is expired, revoked, or was not granted access to "
            f"the vault named in the reference ('{pointer.vault}').",
        )

    if response.status_code == 404 and by_id:
        # **An id-addressed reference with a typo lands here and nowhere else**, because
        # an id skips the lookup that would otherwise have produced case 6 or 7. Reported
        # as *no such vault or item* rather than as "the vault answered 404", which is
        # true and sends nobody anywhere: a 26-character id is not something somebody
        # eyeballs, and the remedy is the command that lists what is there.
        raise VaultError(
            NO_ITEM,
            f"the vault has no such vault or item, so this connector's credential could "
            f"not be read.\n"
            f"  reference  {pointer}\n"
            f"  vault      {config.VAULT_URL}\n"
            "  Nothing was called. This reference addresses by id rather than by name, "
            "so a wrong id is a 404 with nothing to suggest — check it against the vault, "
            "or write the reference with names instead (three requests per call rather "
            "than one, and legible).",
        )

    if response.status_code == 404:
        # Every id in this path came from the vault's own answer a moment ago, or the
        # path is a list endpoint that has no id in it — so a 404 is not a typo. It is
        # either a URL that is not Connect at all (a proxy answering 404 for a path it
        # has no route for), or an item deleted between the lookup and the read. The
        # first draft told both cases their reference "addresses by id", which was false
        # of the reference and sent somebody to check an id they never wrote.
        raise VaultError(
            NO_ITEM,
            f"the vault answered HTTP 404 for a path it had just named, so this "
            f"connector's credential could not be read.\n"
            f"  reference  {pointer}\n"
            f"  vault      {config.VAULT_URL}{path}\n"
            "  Nothing was called. This usually means CARNET_VAULT_URL does not point "
            "at a 1Password Connect server, or the item was removed between lookup and "
            "read; `carnet --check-credential <connector>` says which.",
        )

    if 300 <= response.status_code < 400:
        # `egress.dial` never follows a redirect, because a 3xx points somewhere no check
        # saw — and deciding what a refusal *means* is the caller's job (064). Named
        # rather than left to fall through to the not-JSON branch, which would describe a
        # proxy or a login page: the common cause here is a Connect deployment behind a
        # front door that upgrades http to https, and the fix is the URL.
        raise VaultError(
            UNREACHABLE,
            f"the vault answered HTTP {response.status_code} — a redirect, which is not "
            f"followed, so this connector's credential could not be read.\n"
            f"  reference  {pointer}\n"
            f"  vault      {config.VAULT_URL}{path}\n"
            f"  it points at: {response.headers.get('Location') or '(no Location header)'}\n"
            "  Nothing was called, and nothing was sent to that address — a redirect "
            "goes somewhere the egress check never saw. Set CARNET_VAULT_URL to where "
            "it actually points (most often the https form of the same host).",
        )

    if response.status_code >= 400:
        raise VaultError(
            UNREACHABLE,
            f"the vault answered HTTP {response.status_code}, so this connector's "
            f"credential could not be read.\n"
            f"  reference  {pointer}\n"
            f"  vault      {config.VAULT_URL}{path}\n"
            "  Nothing was called.",
        )

    try:
        return json.loads(_read_bounded(response, pointer, deadline))
    except ValueError as exc:
        # A 200 that is not JSON is a captive portal, a proxy error page, or a URL
        # pointing at something that is not Connect. Named as such rather than as a
        # missing item, which is where "it parsed to nothing" would land somebody.
        raise VaultError(
            UNREACHABLE,
            f"the vault answered with something that is not JSON, so this "
            f"connector's credential could not be read.\n"
            f"  reference  {pointer}\n"
            f"  vault      {config.VAULT_URL}{path}\n"
            "  Nothing was called. Check that CARNET_VAULT_URL points at a "
            "1Password Connect server and not at a proxy or a login page.",
        ) from exc


# The most one vault response may be. Measured shapes: a Connect vault list is ~100
# bytes, an item list ~220, an item with five fields ~800. 64 KiB is eighty times the
# largest of those — room for an item carrying an SSH key and a long note — and it is not
# a tuning knob: it is the size above which the answer is not an item this can use.
#
# It does two jobs, and the second is why it is 64 KiB rather than a megabyte. Without a
# ceiling at all, a vault answering without end holds an MCP request open for as long as
# it keeps writing. And because the body is read **byte by byte** (see `_CHUNK`), the
# ceiling is also the bound on how much CPU one pathological answer can burn with the GIL
# held: 64 KiB is ~94ms of reading, where a megabyte would have been 1.5 seconds.
MAX_VAULT_RESPONSE_BYTES = 65_536

# **The chunk size is the deadline's granularity, and one byte is the only value that
# makes the budget mean what it says.** `iter_content(n)` yields only when `n` bytes have
# arrived or the body ends — a blocking `read(n)` underneath — so the clock can be
# consulted every `n` bytes and no sooner. A larger chunk does not merely blur the bound,
# it *is* the bound: at 256 bytes, a vault delivering one byte per 100ms overshoots a 0.4s
# budget by 25 seconds, and for the two list responses — which are smaller than one chunk
# — a larger chunk buys nothing at all, because the whole body is a single read.
#
# Measured on a local socket, against the payloads Connect actually returns:
#
#     payload            chunk=1    chunk=256
#     vault list ~100B    0.17ms       0.01ms
#     item list  ~220B    0.32ms       0.01ms
#     an item    ~800B    1.12ms       0.02ms
#     ----------------------------------------
#     all three hops      ~1.6ms       ~0.04ms
#
# **~1.6ms, once, against three network round trips.** That is the price of the setting
# above being true, and it is cheap. What it is *not* cheap for is a large body — 4 KB
# costs 5.9ms and a megabyte 1.5 **seconds** of CPU with the GIL held — which is why
# `MAX_VAULT_RESPONSE_BYTES` is 64 KiB rather than a megabyte. The two constants are one
# decision: read exactly, and refuse anything big enough for exactness to cost.
_CHUNK = 1


def _read_bounded(response, pointer: Pointer, deadline: _Deadline) -> bytes:
    """The body, read against the clock and against a ceiling. Raises `_Expired`.

    **What the budget bounds exactly, and what it bounds only approximately.** Said here
    rather than implied, because `config.CARNET_VAULT_TIMEOUT_SECONDS` reads as a hard
    ceiling and three of the four cases are one:

        a vault that is DOWN       the connect timeout
        a vault that STALLS        the read timeout — it fires on no data
        a vault that never ENDS    MAX_VAULT_RESPONSE_BYTES, no clock involved
        a vault that is SLOW       the clock, consulted every byte (see `_CHUNK`)
        a NAME that will not       NOT BOUNDED — `egress.pinned` resolves it with
          resolve                  `socket.getaddrinfo`, which takes no timeout, so
                                   a stalled resolver holds the call for the OS's own
                                   resolver timeout before any of the above applies

    The fourth is the one that needed building. A read timeout is *between* reads, so a
    server that never stalls longer than the timeout never trips it — and a blocking
    `read(n)` returns only when `n` bytes have arrived, so the clock can be consulted
    every `n` bytes and no sooner. That makes the chunk size the bound rather than a
    detail of it.

    The residual, stated exactly: one `read(1)` can still block for as long as the read
    timeout, which is the remaining budget — so the true ceiling is *about twice* the
    setting, not once. That is the same factor the connect-plus-read pair already implies
    and it is the floor for any synchronous client; going below it means a watchdog thread
    or an async one, which is more machinery than a latency property of a dependency the
    **operator** runs at an address no tenant can influence.

    This began as a measurement rather than a worry: before the streamed read, a 0.4s
    budget produced a **5.92s** hold against a vault answering one byte every 100ms, on
    the door's hot path, holding an MCP request open the whole time.
    """
    import requests

    body = bytearray()
    try:
        for chunk in response.iter_content(chunk_size=_CHUNK):
            # Before appending, so an over-long answer is refused rather than accumulated.
            if len(body) + len(chunk) > MAX_VAULT_RESPONSE_BYTES:
                raise VaultError(
                    UNREACHABLE,
                    f"the vault's answer is longer than "
                    f"{MAX_VAULT_RESPONSE_BYTES} bytes, so this connector's credential "
                    f"could not be read.\n"
                    f"  reference  {pointer}\n"
                    f"  vault      {config.VAULT_URL}\n"
                    "  Nothing was called. A 1Password item is under a kilobyte; an "
                    "answer this size is not one, and reading it to the end would hold "
                    "this call open for as long as the sender kept writing.",
                )
            body += chunk
            # **Between chunks, which is the point.** A read timeout only fires when a
            # server stops answering; this fires when it answers too slowly.
            deadline.remaining()
    except requests.exceptions.Timeout:
        raise _Expired() from None
    except requests.RequestException as exc:
        raise VaultError(
            UNREACHABLE,
            f"the vault stopped answering part-way through, so this connector's "
            f"credential could not be read.\n"
            f"  reference  {pointer}\n"
            f"  vault      {config.VAULT_URL}\n"
            f"  {type(exc).__name__}: {exc}\n"
            "  Nothing was called.",
        ) from exc
    finally:
        response.close()

    return bytes(body)


def _fetch_item(session, pointer: Pointer, deadline: _Deadline) -> dict:
    """The item behind a pointer: one to three hops, fewest when it is written with ids.

    The list endpoints return items **without** their field values, which is why the
    item fetch is always the last hop and why a name-addressed reference cannot be a
    single request however it is asked.
    """
    # Both names vetted before the first request, so a bad item name costs no vault
    # lookup and "Nothing was called" is true of the vault as well as the vendor.
    if not _is_id(pointer.vault):
        _refuse_unfilterable(pointer, "vault", pointer.vault)
    if not _is_id(pointer.item):
        _refuse_unfilterable(pointer, "item", pointer.item)

    vault_id = pointer.vault
    if not _is_id(vault_id):
        vaults = _get(
            session,
            "/v1/vaults",
            pointer,
            deadline,
            **{"filter": f'name eq "{pointer.vault}"'},
        )
        found = _ids_named(vaults, pointer.vault, "name")
        if len(found) > 1:
            # Guessing which of two vaults a customer meant is guessing at which secret
            # to send to a vendor — and reporting it as "no such vault" sends them to
            # check a name that is right, twice over. `--check-credential` cannot list
            # vaults (it resolves one reference), so the remedy names where the ids are.
            raise VaultError(
                AMBIGUOUS,
                f"{len(found)} vaults are called '{pointer.vault}', so this connector's "
                f"credential could not be read.\n"
                f"  reference  {pointer}\n"
                f"  vault      {config.VAULT_URL}\n"
                "  Nothing was called: which of them to open is a guess, and a guess "
                "here is a guess at which secret goes to a vendor. Address the vault by "
                "its id instead — the 1Password admin console or `op vault list` shows "
                "each vault's id — and write the reference as op://<vault id>/….",
            )
        vault_id = found[0] if found else None
        if vault_id is None:
            raise VaultError(
                NO_VAULT,
                f"there is no vault called '{pointer.vault}' that this deployment's "
                f"service account can see, so this connector's credential could not "
                f"be read.\n"
                f"  reference  {pointer}\n"
                f"  vault      {config.VAULT_URL}\n"
                "  Nothing was called. Either the name is wrong or "
                "CARNET_VAULT_TOKEN was not granted access to that vault; "
                "`carnet --check-credential <connector>` says which.",
            )

    item_id = pointer.item
    if not _is_id(item_id):
        items = _get(
            session,
            f"/v1/vaults/{item_path(vault_id)}/items",
            pointer,
            deadline,
            # The id the customer wrote, if the vault was addressed by one; a 404 here
            # is then a typo in it rather than a path the vault itself just named.
            by_id=_is_id(pointer.vault),
            **{"filter": f'title eq "{pointer.item}"'},
        )
        found = _ids_named(items, pointer.item, "title")
        if len(found) > 1:
            raise VaultError(
                AMBIGUOUS,
                f"{len(found)} items in the vault '{pointer.vault}' are called "
                f"'{pointer.item}', so this connector's credential could not be read.\n"
                f"  reference  {pointer}\n"
                f"  vault      {config.VAULT_URL}\n"
                "  Nothing was called: which of them to read is a guess, and a guess "
                "here is a guess at which secret goes to a vendor. Address the item by "
                "its id instead — the 1Password admin console or `op item list --vault "
                f"'{pointer.vault}'` shows each item's id — and write the reference as "
                "op://<vault>/<item id>/….",
            )
        item_id = found[0] if found else None
        if item_id is None:
            raise VaultError(
                NO_ITEM,
                f"the vault '{pointer.vault}' has no item called '{pointer.item}', so "
                f"this connector's credential could not be read.\n"
                f"  reference  {pointer}\n"
                f"  vault      {config.VAULT_URL}\n"
                "  Nothing was called. The vault was found and opened; the item was "
                "not in it.",
            )

    item = _get(
        session,
        f"/v1/vaults/{item_path(vault_id)}/items/{item_path(item_id)}",
        pointer,
        deadline,
        by_id=_is_id(pointer.vault) or _is_id(pointer.item),
    )
    if not isinstance(item, dict):
        raise VaultError(
            NO_ITEM,
            f"the vault returned something that is not an item for '{pointer.item}', "
            f"so this connector's credential could not be read.\n"
            f"  reference  {pointer}\n"
            f"  vault      {config.VAULT_URL}\n"
            "  Nothing was called.",
        )
    return item


def item_path(segment: str) -> str:
    """One path segment, encoded. Connect ids are safe already; a caller who put a
    name where an id goes gets a 404 rather than a request to a path they wrote."""
    return quote(segment, safe="")


# The characters a name cannot carry into a Connect filter. The filter is `name eq
# "<name>"` — SCIM-shaped — and the documentation shows no escape for a `"` inside the
# quoted string; whether a backslash escapes is equally undocumented. A guessed escape
# that is wrong sends a filter the server reads as something else and reports as HTTP
# 400 — or, worse, as a *match* — so a name carrying either character is refused up
# front and pointed at the id, which needs no filter at all. Recorded in the register's 070 row
# about a client that has never met a real Connect.
_UNFILTERABLE = ('"', "\\")


def _refuse_unfilterable(pointer: Pointer, kind: str, name: str) -> None:
    """Refuse a vault or item name the filter grammar cannot carry, before a request."""
    bad = [char for char in _UNFILTERABLE if char in name]
    if not bad:
        return
    shown = " or ".join(repr(char) for char in bad)
    raise VaultError(
        MALFORMED,
        f"the {kind} name '{name}' contains {shown}, which cannot be sent in a 1Password "
        f"Connect name filter, so this connector's credential could not be read.\n"
        f"  reference  {pointer}\n"
        f"  Nothing was called. Address that {kind} by its id instead — the 1Password "
        f"admin console or `op {kind} list` shows it — which needs no filter at all.",
    )


def _ids_named(payload, wanted: str, key: str) -> list:
    """The ids of every row whose `key` equals `wanted`. Empty for a payload that is
    not a list.

    The filter is sent to the server and the match is checked again here, because
    Connect's filter is a *query* and a server that ignored or widened it would
    otherwise hand back the first row of the vault list — a credential from an item
    nobody named. The caller decides what more than one means, and it has its own
    sentence: guessing which of two vaults a customer meant is guessing at which secret
    to send to a vendor, and reporting it as *no such vault* sends them to check a name
    that is right.
    """
    if not isinstance(payload, list):
        return []
    return [
        row.get("id")
        for row in payload
        if isinstance(row, dict) and (row.get(key) or "") == wanted and row.get("id")
    ]


def _field_of(item: dict, pointer: Pointer) -> str:
    """The field a pointer names, out of an item that was found.

    **The matching order is a decision and it is written down** — label, then id, then
    the well-known purposes — because *which field did `op://…/password` mean* is a
    question somebody will ask about a value that has already been sent to a vendor. An
    item can carry a field labelled `password` and a login field whose purpose is
    `PASSWORD`, and they can differ; the label wins, because a label is what somebody
    typed and a purpose is what 1Password inferred.

    **Sectionless fields are tried first, and sectioned ones after** — both halves matter
    and the first build got the second half wrong:

      - *first*, so that adding a section to an item can never change what an existing
        reference already resolves to. That would be a silent change in which secret
        leaves the building.
      - *after*, because 1Password's own `op://` resolves an unqualified name against the
        whole item. Trying only the sectionless ones refused a reference the vendor's own
        tooling reads, which is a divergence nobody would think to look for.

    **Two matches is a refusal, never the first of them.** `_fetch_item` already makes this
    call about two vaults sharing a name — *guessing which of two a customer meant is
    guessing at which secret to send to a vendor* — and this is the same sentence one
    level down, where the first build silently answered with whichever the vendor happened
    to list first.
    """
    fields = [f for f in (item.get("fields") or []) if isinstance(f, dict)]

    def section_of(field: dict) -> str:
        return ((field.get("section") or {}).get("label") or "").strip()

    if pointer.section:
        tiers = [[f for f in fields if section_of(f) == pointer.section]]
    else:
        tiers = [
            [f for f in fields if not section_of(f)],
            [f for f in fields if section_of(f)],
        ]

    for tier in tiers:
        for attribute, fold in (("label", False), ("id", False), ("purpose", True)):
            matches = [
                field
                for field in tier
                if _names(field.get(attribute), pointer.field, fold)
            ]
            if not matches:
                continue
            if len(matches) > 1:
                # The sections are **not** named, for the reason the missing-field
                # refusal does not list the labels: this sentence reaches whoever holds
                # the calling token, and through them the model. `--check-credential`
                # prints them, to somebody who can already open the vault.
                raise VaultError(
                    AMBIGUOUS,
                    f"the item '{pointer.item}' has {len(matches)} fields called "
                    f"'{pointer.field}', so there is no telling which credential was "
                    f"meant.\n"
                    f"  reference  {pointer}\n"
                    f"  vault      {config.VAULT_URL}\n"
                    "  Nothing was called, and nothing was guessed — picking one would "
                    "be picking which secret gets sent to a vendor. Name the section "
                    "the reference means: op://<vault>/<item>/<section>/<field>. "
                    "`carnet --check-credential <connector>` lists the sections the "
                    "item has.",
                )
            return _value_of(matches[0], pointer)

    where = f"section '{pointer.section}' of " if pointer.section else ""
    raise VaultError(
        NO_FIELD,
        f"the item '{pointer.item}' has no field called '{pointer.field}', so this "
        f"connector's credential could not be read.\n"
        f"  reference  {pointer}\n"
        f"  vault      {config.VAULT_URL}\n"
        f"  Nothing was called. The vault was reached and {where}the item was found; "
        "the field was not in it. `carnet --check-credential <connector>` lists the "
        "fields the item does carry — that is not printed here, because this sentence "
        "reaches whoever holds the calling token.",
    )


def _names(value, wanted: str, fold: bool) -> bool:
    """Whether one of a field's attributes names the field a pointer asked for.

    `fold` is true only for `purpose`, whose values are 1Password's own vocabulary
    (`PASSWORD`, `USERNAME`) rather than anything somebody typed — so `op://…/password`
    reads naturally. A label is compared exactly, because a label *is* what somebody
    typed and two labels differing only in case are two fields.
    """
    value = (value or "").strip()
    if not value:
        return False
    return value == wanted or (fold and value.lower() == wanted.lower())


def _value_of(field: dict, pointer: Pointer) -> str:
    """One matched field's value, or the two refusals a value can earn."""
    secret = field.get("value")
    if not isinstance(secret, str) or not secret:
        # Case 9. The reference **worked** — said in as many words, because "no
        # credential" is what this reads as otherwise and it sends somebody to configure
        # one that is already configured.
        raise VaultError(
            EMPTY,
            f"the reference resolved, and the field it names is empty.\n"
            f"  reference  {pointer}\n"
            f"  vault      {config.VAULT_URL}\n"
            "  Nothing was called. The vault was reached, the item was found and it "
            f"does have a field called '{pointer.field}' — that field has no value. "
            "This is not a configuration problem at this end.",
        )

    if any(character in secret for character in "\r\n"):
        # See UNUSABLE. The value is **not** stripped: silently trimming a secret is
        # guessing at what somebody meant to store, and a guess here decides what is
        # sent to a vendor.
        raise VaultError(
            UNUSABLE,
            f"the reference resolved, and what it names cannot be used as a "
            f"credential: it contains a line break.\n"
            f"  reference  {pointer}\n"
            f"  vault      {config.VAULT_URL}\n"
            "  Nothing was called. A credential is presented in an HTTP header, which "
            "cannot carry a line break — so this is most often a multi-line note where "
            "a single-line token was meant. The value is not trimmed for you: what to "
            "store is your decision, not a guess this makes on your behalf.",
        )

    return secret
