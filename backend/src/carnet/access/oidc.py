"""Is this token real, and is it for us?

The whole of the cryptographic surface, and deliberately nothing else: this module does
not know what a tenant is, does not read the database, and does not decide who anybody
is. It answers one question about one token against one already-registered provider.

That separation is why it can be tested hard. Every test signs a **real** token with a
locally generated key, because a fake that returns "valid" proves nothing about code
whose entire job is deciding what counts as valid.

## The three ways to get this wrong

**Algorithm confusion.** If a verifier accepts `HS256` alongside `RS256`, an attacker
signs a token using the provider's *public* key as an HMAC secret — a key we publish
and they can fetch — and it verifies. If it accepts `none`, they need no key at all.
Both are famous, both are trivial, and both are prevented by never letting the token
choose: `ALLOWED_ALGORITHMS` is asymmetric-only and is passed to the decoder, so the
`alg` header selects from our list rather than supplying its own.

**Forgetting the audience.** A token from the right provider, correctly signed and
unexpired, may have been minted for a *different application* at that provider. It is
genuine and it is not for us; accepting it means any app a customer runs on their IdP
becomes a login here. `aud` is required, not optional.

**Trusting an unverified claim.** `peek_issuer` reads the issuer without checking
anything, because you cannot verify a signature before knowing which keys to check it
against. That is safe only because an unrecognised issuer is refused outright and a
recognised one is then verified properly — the unverified value selects a key, it never
grants anything. It is named to make using it for anything else feel wrong.

## What a caller has to do with more than one candidate

Most providers issue one issuer per customer, so a lookup returns one row and `verify`
settles it. Google Workspace shares one issuer across every organisation, so a lookup
can return several — and picking among them is the caller's job, with one rule:

    a candidate matches iff verify() succeeds AND the discriminating claim matches

Both halves are load-bearing. Verification alone is not enough, because two customers
on one issuer may share an OAuth client and therefore an audience, in which case every
candidate would verify and the first would win — which is the cross-tenant read this
design exists to prevent. See `access/providers.py`.
"""

import logging
import threading
import time

import jwt

from ..config import CLOCK_SKEW_LEEWAY, JWKS_CACHE_TTL, JWKS_MIN_REFRESH_INTERVAL

log = logging.getLogger(__name__)

# Asymmetric only, and never negotiable by the token.
#
# `none` is absent for the obvious reason. **`HS*` is absent for the less obvious one**:
# HMAC verification uses the same value to sign and to check, so a verifier that accepts
# HS256 will happily validate a token an attacker signed with the provider's published
# public key. The signing key must be one only the provider holds, which means it must
# be asymmetric.
ALLOWED_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
)

# Claims we refuse to proceed without. `sub` is here because it is the identity — a
# token with no subject describes nobody, and the caller would have to invent one.
REQUIRED_CLAIMS = ("exp", "iss", "aud", "sub")


class TokenError(RuntimeError):
    """This token does not entitle the caller to anything.

    One class for every failure, because they all mean the same thing to a caller and
    all become a 401: distinguishing "expired" from "forged" *to the client* tells an
    attacker which half of their guess was right. The distinction is preserved in the
    message, which goes to the log.
    """


class TokenExpired(TokenError):
    """The one distinction worth making, and only because a client can act on it.

    Expired means "log in again"; anything else means "something is wrong". A UI that
    cannot tell them apart either nags about outages or silently retries forgeries.
    """


def peek_issuer(token: str) -> str:
    """The `iss` claim, **unverified**, for looking up which provider signed this.

    Named to be uncomfortable. Nothing this returns has been checked — the signature
    has not been examined and the payload is attacker-controlled. It is safe for
    exactly one purpose: choosing which registered provider's keys to verify against,
    where an unrecognised value is refused and a recognised one leads to real
    verification.

    Using it for anything else — a tenant, a user, a permission — is the vulnerability
    this whole module is arranged to prevent.
    """
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError as exc:
        raise TokenError(f"not a readable JWT: {exc}") from exc

    issuer = claims.get("iss")
    if not issuer or not isinstance(issuer, str):
        raise TokenError("token carries no issuer, so nothing can say who signed it")
    return issuer


def verify(token: str, provider: dict, cache: "JwksCache", *, leeway: float | None = None) -> dict:
    """Fully verify `token` against `provider`, or raise `TokenError`.

    Checks, all of them, none optional: the signature against the provider's published
    keys; that the algorithm is one of ours rather than one the token chose; `iss`
    exactly matching the registered issuer; `aud` exactly matching the registered
    audience; `exp` and `nbf` within `leeway`.

    Returns the verified claims. Everything downstream may trust them; nothing upstream
    of this may trust anything.
    """
    leeway = CLOCK_SKEW_LEEWAY if leeway is None else leeway

    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise TokenError(f"unreadable token header: {exc}") from exc

    algorithm = header.get("alg")
    if algorithm not in ALLOWED_ALGORITHMS:
        # Checked here as well as by the decoder, because this is the failure worth
        # naming precisely in a log: `none` and `HS256` are not typos, they are attacks.
        raise TokenError(
            f"algorithm '{algorithm}' is not accepted. Only asymmetric signatures are, "
            f"because a shared-secret algorithm lets anyone holding the provider's "
            f"public key mint tokens. Accepted: {sorted(ALLOWED_ALGORITHMS)}"
        )

    key = cache.key_for(provider["jwks_uri"], header.get("kid"))

    try:
        return jwt.decode(
            token,
            key=key,
            # Our list, never the token's. This is what closes algorithm confusion.
            algorithms=sorted(ALLOWED_ALGORITHMS),
            issuer=provider["issuer"],
            audience=provider["audience"],
            leeway=leeway,
            options={"require": list(REQUIRED_CLAIMS)},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenExpired(f"token expired: {exc}") from exc
    except jwt.ImmatureSignatureError as exc:
        raise TokenError(f"token is not valid yet: {exc}") from exc
    except jwt.InvalidAudienceError as exc:
        raise TokenError(
            f"token's audience is not ours ({exc}). It may be a genuine token for a "
            "different application at the same provider."
        ) from exc
    except jwt.InvalidIssuerError as exc:
        raise TokenError(f"token's issuer is not the registered one: {exc}") from exc
    except jwt.MissingRequiredClaimError as exc:
        raise TokenError(f"token is missing a claim we require: {exc}") from exc
    except jwt.PyJWTError as exc:
        # Signature failures land here. The message stays generic to the caller and
        # specific in the log — see TokenError.
        raise TokenError(f"token failed verification: {exc}") from exc


class _Cached:
    __slots__ = ("keys", "fetched_at", "last_forced")

    def __init__(self, keys: dict, fetched_at: float):
        self.keys = keys
        self.fetched_at = fetched_at
        # `None`, meaning never — not `0.0`, and not `fetched_at`.
        #
        # Not `fetched_at`, because the rate limit governs *forced* refetches and
        # seeding it from the first ordinary fetch blocks the very first unknown `kid`,
        # which is exactly the rotation the forced path exists to pick up.
        #
        # Not `0.0` either, and that one took a CI failure to find. `time.monotonic()`
        # counts from an arbitrary origin — on Linux, from boot — so on a freshly
        # started machine `now - 0.0` is a small number and the comparison reads as
        # "forced a moment ago". A server started soon after its host would refuse to
        # refetch for the first hour of its life, and so would silently fail to pick up
        # a key rotation. It passed locally only because that machine had been up for
        # days.
        self.last_forced: float | None = None


class JwksCache:
    """A provider's signing keys, fetched rarely and held.

    ## Why the fetch is injectable

    The same reason `HttpTransport` takes an HTTP callable: the suite starts nothing
    and calls nothing, and that property has survived five steps. Tests hand in a
    function returning a key set they generated, so every assertion here is about our
    verification rather than about a provider being reachable.

    ## Why a stale key set beats a failed fetch

    Every authenticated request needs these keys, so a JWKS endpoint being unreachable
    would otherwise be a total outage — ours, caused by somebody else's. Signing keys
    rotate on the order of months and the previous set stays valid across a rotation,
    so serving keys we already have is very likely correct and certainly better than
    refusing everybody.

    **This is not failing open.** A stale key still has to verify the signature; what
    is relaxed is the freshness of the key list, never whether the token is genuine.

    ## Why an unknown `kid` triggers exactly one refetch

    Key rotation shows up as a token signed by a key we have not seen. Refetching
    handles it. But `kid` is attacker-controlled, so refetching on every unknown one
    turns a stream of junk tokens into a stream of requests at the customer's IdP —
    with our name on them. `JWKS_MIN_REFRESH_INTERVAL` bounds that.

    ## Why fetching is serialized per URI

    This object is process-wide and endpoints run in a threadpool, so a cold start
    under load means every in-flight request misses at once. Measured: eight
    concurrent misses produced **eight** fetches of the same key set. Nothing breaks —
    they all get the same answer — but it is a thundering herd at a customer's
    identity provider every time this process restarts, which is exactly when they are
    least inclined to be forgiving.

    So a fetch takes a per-URI lock and re-checks, the same double-checked shape
    `SessionPool.get_or_create` uses. Per URI rather than global, because one slow
    provider must not hold up every other customer's.
    """

    def __init__(self, fetch=None, ttl: float | None = None, min_refresh: float | None = None):
        self._fetch = fetch or _fetch_jwks
        self._ttl = JWKS_CACHE_TTL if ttl is None else ttl
        self._min_refresh = (
            JWKS_MIN_REFRESH_INTERVAL if min_refresh is None else min_refresh
        )
        self._lock = threading.RLock()
        self._entries: dict[str, _Cached] = {}
        self._fetching: dict[str, threading.Lock] = {}

    def key_for(self, jwks_uri: str, kid: str | None):
        """The signing key this token names, refetching once if it is unknown."""
        keys = self._keys(jwks_uri)

        key = self._select(keys, kid)
        if key is not None:
            return key

        # Unknown kid: either a rotation we have not seen, or nonsense. One refetch
        # tells us which, and the rate limit keeps nonsense from becoming traffic.
        keys = self._keys(jwks_uri, force=True)
        key = self._select(keys, kid)
        if key is None:
            raise TokenError(
                f"no signing key '{kid}' at {jwks_uri}. The provider does not publish "
                "the key this token claims to be signed with."
            )
        return key

    @staticmethod
    def _select(keys: dict, kid: str | None):
        if kid is not None:
            return keys.get(kid)
        # A key set with exactly one key needs no `kid` to be unambiguous. More than
        # one and we refuse rather than guess: trying each in turn would mean a token
        # verifying against a key it never named.
        return next(iter(keys.values())) if len(keys) == 1 else None

    def _keys(self, jwks_uri: str, *, force: bool = False) -> dict:
        cached, stamp = self._cached(jwks_uri, force=force)
        if cached is not None:
            return cached

        with self._lock:
            gate = self._fetching.get(jwks_uri)
            if gate is None:
                gate = self._fetching[jwks_uri] = threading.Lock()

        with gate:
            # Another thread may have fetched while we queued. Detected by the
            # timestamp having moved, **not** by re-running the decision above — that
            # would consume the rate-limit slot a second time and then refuse to
            # fetch, so a rotation would never be picked up at all.
            with self._lock:
                entry = self._entries.get(jwks_uri)
                if entry is not None and entry.fetched_at != stamp:
                    return entry.keys
            return self._fetch_now(jwks_uri)

    def _cached(self, jwks_uri: str, *, force: bool) -> tuple:
        """`(keys_or_None, fetched_at_or_None)`. Decides; never fetches.

        The timestamp comes back so the caller can tell "nobody has fetched since I
        looked" from "somebody just did".
        """
        now = time.monotonic()

        with self._lock:
            entry = self._entries.get(jwks_uri)
            if entry is None:
                return None, None
            if not force and (now - entry.fetched_at) < self._ttl:
                return entry.keys, entry.fetched_at
            if force:
                if (
                    entry.last_forced is not None
                    and (now - entry.last_forced) < self._min_refresh
                ):
                    # Rate-limited. Serve what we have rather than dialling the IdP
                    # for every junk `kid` somebody sends.
                    return entry.keys, entry.fetched_at
                entry.last_forced = now
            return None, entry.fetched_at

    def _fetch_now(self, jwks_uri: str) -> dict:
        try:
            keys = self._fetch(jwks_uri)
        except Exception as exc:  # noqa: BLE001 - any failure to reach the IdP
            with self._lock:
                entry = self._entries.get(jwks_uri)
            if entry is not None:
                log.warning(
                    "could not refresh signing keys from %s (%s); using the set "
                    "fetched %.0fs ago",
                    jwks_uri,
                    exc,
                    time.monotonic() - entry.fetched_at,
                )
                return entry.keys
            raise TokenError(
                f"cannot reach the identity provider's keys at {jwks_uri}: {exc}"
            ) from exc

        with self._lock:
            previous = self._entries.get(jwks_uri)
            entry = _Cached(keys, time.monotonic())
            if previous is not None:
                # Carried across, because a fresh `_Cached` starts at zero and would
                # re-open the rate limit on every forced refetch — turning the limit
                # into a no-op for exactly the junk-`kid` stream it exists to stop.
                entry.last_forced = previous.last_forced
            self._entries[jwks_uri] = entry
            return keys

    def forget(self, jwks_uri: str | None = None) -> None:
        """Drop cached keys. For tests, and for a provider whose URL changed."""
        with self._lock:
            if jwks_uri is None:
                self._entries.clear()
            else:
                self._entries.pop(jwks_uri, None)


def _fetch_jwks(jwks_uri: str) -> dict:
    """`kid` -> key, from a provider's published JWKS. The real network call.

    Keys that fail to parse are skipped rather than fatal: a provider publishing one
    key type we do not support must not stop us using the ones we do.

    **The dial is pinned (step 058), with the operator's consent presumed.** This URL
    is a `tenant_idps` value written by `--add-idp` — an operator's registration, not
    a tenant admin's form — so loopback and private answers are legal (a `--local`
    provider and an in-network IdP live exactly there), while the never-consentable
    ranges (link-local: the metadata service) are refused for it like for every dial,
    and the socket goes to the address that was checked. This was 049's
    unguarded-jwks major: the one bare `requests.get` on the auth hot path.
    """
    import requests

    from ..config import REQUEST_TIMEOUT
    from ..tools.mcp import egress

    with requests.Session() as session:
        response = egress.dial(
            session,
            "GET",
            jwks_uri,
            operator_consented=True,
            timeout=REQUEST_TIMEOUT,
        )
        # **A redirect, named.** `raise_for_status` raises on 4xx and 5xx only, so
        # before step 064 a 3xx fell straight through into `.json()` and died on the
        # redirect's empty body — which `_fetch_now` swallowed into "cannot reach the
        # identity provider's keys". An IdP whose `jwks_uri` answers a 301 (apex to
        # www, http to https, a CDN normalizing a trailing slash) worked before 058
        # followed redirects and broke every sign-in for that tenant afterwards, with
        # a sentence naming neither the redirect nor a remedy.
        #
        # Still not followed — a 3xx points somewhere no pin checked — but now the
        # refusal says so and carries the `Location`, because the fix is an operator
        # re-registering the provider at the URL it actually serves from.
        if 300 <= response.status_code < 400:
            target = response.headers.get("Location") or "somewhere it did not name"
            raise RuntimeError(
                f"the JWKS URL answered HTTP {response.status_code} redirecting to "
                f"{target}, and a redirect is not followed: the address a pin checked "
                f"is the only one it may dial. Register this provider's jwks_uri as "
                f"the URL it actually serves the key set from."
            )
        response.raise_for_status()
        return keys_from_jwks(response.json())


def keys_from_jwks(document: dict) -> dict:
    """`kid` -> key object, from a parsed JWKS document. Exposed so tests share it."""
    keys = {}
    for entry in document.get("keys") or ():
        kid = entry.get("kid")
        try:
            key = jwt.PyJWK(entry).key
        except Exception as exc:  # noqa: BLE001 - one unusable key is not fatal
            log.warning("skipping unusable JWKS entry %s: %s", kid, exc)
            continue
        keys[kid] = key
    return keys
