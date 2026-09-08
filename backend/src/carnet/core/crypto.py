"""Encryption at rest for delegated credentials — the ONLY module that holds a key.

`credentials.py` is the only module that reads secrets; this is the only one that can
*unlock* them. The containment is the same idea one layer down: a stored credential is
unreadable everywhere in this codebase except here, so the question "where could a
credential leak from?" has one answer rather than a search.

Three properties, and each is a decision rather than a default:

**AES-256-GCM, and no negotiation.** Authenticated encryption, so a tampered row fails
loudly instead of decrypting to garbage that something downstream then sends to a
vendor. One algorithm because an algorithm field is a downgrade attack with a
migration path attached.

**The key is supplied or the process refuses to start.** Auto-generating one when none
is set is the right call for a five-minute `docker compose up` and the wrong one here:
a key that regenerates makes every stored credential silently unreadable — not at write
time, not at boot, but the first time somebody's agent runs, on a row that looks fine.
A production server on a key nobody chose is also a server nobody can restore. See
`from_environment`, and `bootstrap` for where the refusal happens.

**The ciphertext is bound to the row it belongs in.** GCM authenticates additional data
for free: data that is not encrypted but that the ciphertext will not verify without.
Binding `(tenant, principal, connector)` means a row lifted into another user's row —
or another tenant's — *fails to decrypt* rather than working. The database cannot
express that; a primary key stops two rows colliding and has no opinion about a value
moved between them. It is the cheapest cross-tenant defence available, in a system
whose stated known limit is that tenant isolation is enforced by the application rather
than by the database.

### Why there is a Cipher indirection at all

There is exactly one implementation and the interface still exists, for the same reason
`storage` has one: the thing a large customer asks for is *their* key, in *their* KMS,
and often per customer rather than per platform. With a KMS the key never leaves the
service at all — you send a blob and get plaintext back — so an interface that handed
out key *bytes* would have foreclosed the design it exists to allow. The seam is at
seal/open, which is the level both a local key and a KMS can implement.

`tenant_id` is a parameter on both operations for the same reason `principal` was a
parameter on `for_connector` two steps before anything read it. Today every tenant
resolves to the same key and `LocalKeyCipher` ignores the argument entirely. Adding it
later means changing this interface, both call sites, and every stored row at once.
"""

import base64
import binascii
import hashlib
import os
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Where the key comes from. These names live here rather than in `config.py` on
# purpose: this module is meant to be the only one that knows how to find a key, and a
# variable name in a second module is a second place that knows.
KEY_ENV = "CARNET_SECRET_KEY"
OLD_KEYS_ENV = "CARNET_SECRET_KEYS_OLD"

KEY_BYTES = 32  # AES-256
NONCE_BYTES = 12  # GCM's standard nonce width

# Domain separator for the derived key id. Hashing the raw key and publishing a prefix
# of it would be safe for a 256-bit random key, but a hash of a secret that appears in
# a database column is a smell worth not having; a separator costs nothing and means
# the stored value is not a prefix of `sha256(key)`.
_KEY_ID_DOMAIN = b"carnet/crypto/key-id/v1"
KEY_ID_CHARS = 8

# Version tag on the additional-data encoding. If the bound fields ever change, rows
# written under the old scheme must fail to verify rather than quietly verifying
# against a different set of fields.
_AAD_VERSION = "v1"


class CryptoError(RuntimeError):
    """Base for anything this module refuses to do."""


class MissingKeyError(CryptoError):
    """No key is configured, or a row names a key this process does not hold.

    Distinct from `UndecryptableError` because a person acts on them differently. This
    one says "the key list is wrong" — most often a rotation where the old key was
    dropped from `CARNET_SECRET_KEYS_OLD` before the rows were re-encrypted.
    That is recoverable by putting the key back.
    """


class UndecryptableError(CryptoError):
    """The ciphertext did not authenticate.

    The row was altered, or it was copied from another principal or another tenant and
    the bound additional data no longer matches. Not recoverable, and not a fallback:
    see `credentials.for_connector` for why an unreadable delegated credential must
    never quietly become the operator's.
    """


@runtime_checkable
class Cipher(Protocol):
    """Seal and open. Implemented locally today, by a KMS later.

    `aad` is caller-supplied rather than assembled here, because this module does not
    know what a connection is. `connection_aad` is where that shape is decided.
    """

    def seal(self, plaintext: str, *, tenant_id: str, aad: str) -> tuple[bytes, str]:
        """Returns `(blob, key_id)`. The blob is opaque and self-contained."""

    def open_(self, blob: bytes, *, tenant_id: str, aad: str, key_id: str) -> str:
        """The plaintext, or a raised error. Never a partial or a fallback."""


def key_id_for(key: bytes) -> str:
    """A short, stable name for a key, derived from the key itself.

    Derived rather than assigned, for the same reason `Connector.read_only` is derived
    and refused in storage: a value somebody maintains by hand is free to stop being
    true. Nobody picks this, so a row cannot claim a key it was not encrypted with, and
    two operators cannot both call their different keys `v1`.
    """
    return hashlib.sha256(_KEY_ID_DOMAIN + key).hexdigest()[:KEY_ID_CHARS]


def connection_aad(
    tenant_id: str, principal_kind: str, principal_id: str, connector_id: str
) -> str:
    """The additional data a `connections` row's ciphertext is bound to.

    **Length-prefixed, not joined by a separator.** `"|".join(parts)` lets two
    different rows produce the same string whenever a value can contain the separator —
    tenant `a|b` with kind `c` and tenant `a` with kind `b|c` are indistinguishable, and
    the whole point of this string is that two different rows are never the same. None
    of the current values can contain a pipe, which is exactly the kind of thing that is
    true until somebody adds a tenant id with punctuation in it. Free to prevent now and
    impossible to fix later without re-encrypting every row.
    """
    parts = (tenant_id, principal_kind, principal_id, connector_id)
    return "|".join([_AAD_VERSION, *(f"{len(p)}:{p}" for p in parts)])


def _domained_aad(domain: str, *parts: str) -> str:
    """Length-prefixed additional data under a named domain. See `connection_aad`.

    **`connection_aad` deliberately does not go through this**, even though it would read
    better if it did. Its exact output is bound into every `connections` row written
    since 7a, so changing the string by so much as a domain tag would make every stored
    credential fail to authenticate — silently at write time, loudly on somebody's next
    run, and unfixably because the platform cannot decrypt its own storage to re-seal it.
    A helper that tidied it would be a helper that cost every customer their credentials.

    Everything added after it gets a domain. Two different kinds of secret sealed under
    one key must not be able to produce the same additional data: length-prefixing alone
    already makes a two-part AAD unequal to a four-part one, and relying on that is
    relying on an accident of the current field counts rather than on a decision.
    """
    return "|".join([_AAD_VERSION, domain, *(f"{len(p)}:{p}" for p in parts)])


def oauth_app_aad(tenant_id: str, connector_id: str) -> str:
    """What a `connector_oauth` row's sealed client secret is bound to.

    Not merely decoration on a table whose primary key is the same two values. A primary
    key stops two rows colliding and has no opinion about a *value copied between them* —
    so without this, a client secret lifted from one tenant's row into another's would
    decrypt happily and be POSTed to a token endpoint as that tenant. The database cannot
    express "this ciphertext belongs in this row"; GCM's additional data can, for free.
    """
    return _domained_aad("oauth-app", tenant_id, connector_id)


def trigger_secret_aad(tenant_id: str, trigger_id: str) -> str:
    """What a `triggers` row's sealed HMAC secret is bound to. Step 023.

    Sealed rather than hashed, unlike `api_tokens.secret_hash`, because an HMAC is
    *computed*, not presented: the verifier is handed a signature and must derive its own
    from the raw secret, so a digest-only store could never check a delivery. That makes
    this the first credential since 020 to join the re-encryption population a key
    rotation must sweep — migration 034's header states the trade in full.

    Bound to the trigger id so a sealed secret lifted into another trigger's row — or
    another tenant's — refuses to open rather than authenticating deliveries as them,
    which is `oauth_app_aad`'s argument at the fourth table.
    """
    return _domained_aad("trigger-secret", tenant_id, trigger_id)


def pending_authorization_aad(tenant_id: str, state: str) -> str:
    """What a `pending_authorizations` row's sealed PKCE verifier is bound to.

    Bound to the `state` rather than to the principal, which is the one asymmetry with
    `connection_aad` worth noticing: the callback has the `state` and *learns* the
    principal from the row, so binding to the principal would mean trusting the row's own
    account of whose flow this is in order to check that same row. The `state` is the
    only thing the callback holds independently, so it is the only thing that can bind.
    """
    return _domained_aad("pending-authorization", tenant_id, state)


class LocalKeyCipher:
    """AES-256-GCM with keys held in this process.

    One key encrypts; any number of retired keys may still decrypt. That is what makes
    rotation possible without a KMS and without a maintenance window: set the new key,
    keep the old one listed, re-encrypt rows in the background, then drop it. `key_id`
    on each row is what says which key that row still needs.

    Every tenant resolves to the same key — see the module docstring for why the
    parameter is there anyway.
    """

    def __init__(self, key: bytes, old_keys=()):
        _check_key_length(key)
        self._current = key
        self._current_id = key_id_for(key)

        # Retired keys first, so a key listed in both places is treated as current.
        self._by_id = {}
        for old in old_keys:
            _check_key_length(old)
            self._by_id[key_id_for(old)] = old
        self._by_id[self._current_id] = key

    @property
    def key_id(self) -> str:
        """The id new rows will be written with."""
        return self._current_id

    @property
    def key_ids(self) -> frozenset[str]:
        """Every key id this process can open — the current one included.

        Ids, never bytes. This exists so a rotation sweep can classify a stored row's
        `key_id` as current, retired, or *unknown to this process* without key material
        leaving this class. It is deliberately not on the `Cipher` protocol: a KMS does
        not enumerate its keys to callers, and rotation of locally-held keys is this
        implementation's concern — `rotation.py` asks for a `LocalKeyCipher` by name.
        """
        return frozenset(self._by_id)

    def seal(self, plaintext: str, *, tenant_id: str, aad: str) -> tuple[bytes, str]:
        """Encrypt under the current key.

        A fresh nonce per call, stored as `nonce || ciphertext || tag` in the single
        BYTEA column the migration already shaped for it. Reusing a nonce under one key
        is the way to break GCM catastrophically, so it is generated here and never
        derived from anything about the row.
        """
        nonce = os.urandom(NONCE_BYTES)
        body = AESGCM(self._current).encrypt(
            nonce, plaintext.encode("utf-8"), aad.encode("utf-8")
        )
        return nonce + body, self._current_id

    def open_(self, blob: bytes, *, tenant_id: str, aad: str, key_id: str) -> str:
        key = self._by_id.get(key_id)
        if key is None:
            raise MissingKeyError(
                f"this credential was encrypted with key '{key_id}', which this "
                f"process does not hold. Current key is '{self._current_id}'. If you "
                f"have rotated, list the previous key in {OLD_KEYS_ENV} until every "
                "row has been re-encrypted."
            )

        if len(blob) <= NONCE_BYTES:
            raise UndecryptableError(
                f"stored credential is {len(blob)} bytes, too short to contain a "
                f"{NONCE_BYTES}-byte nonce and a tag. The row is truncated."
            )

        try:
            plaintext = AESGCM(key).decrypt(
                blob[:NONCE_BYTES], blob[NONCE_BYTES:], aad.encode("utf-8")
            )
        except InvalidTag as exc:
            raise UndecryptableError(
                "stored credential failed authentication under key "
                f"'{key_id}'. Either the row was altered, or it belongs to a "
                "different principal or tenant than the one reading it — the "
                "ciphertext is bound to both and will not open anywhere else."
            ) from exc

        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:  # pragma: no cover - authenticated already
            raise UndecryptableError(
                "stored credential decrypted to bytes that are not valid UTF-8."
            ) from exc


def _check_key_length(key: bytes) -> None:
    if len(key) != KEY_BYTES:
        raise CryptoError(
            f"an encryption key must be exactly {KEY_BYTES} bytes for AES-256, not "
            f"{len(key)}. Generate one with:  openssl rand -base64 32"
        )


def decode_key(text: str) -> bytes:
    """Accept a key as base64 or as hex, because both are what people actually paste.

    `openssl rand -base64 32` and `openssl rand -hex 32` are equally likely to be the
    command somebody ran, and refusing one of them would only produce a confusing
    startup failure on a key that is perfectly good.
    """
    raw = "".join(text.split())
    if not raw:
        raise CryptoError("encryption key is empty")

    if len(raw) == KEY_BYTES * 2:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass  # not hex after all; fall through and try base64

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            key = decoder(raw + "=" * (-len(raw) % 4))
        except (ValueError, binascii.Error):
            continue
        if len(key) == KEY_BYTES:
            return key

    raise CryptoError(
        f"could not read an encryption key from {KEY_ENV}. Expected {KEY_BYTES} bytes "
        "as base64 (44 characters) or hex (64 characters). Generate one with:  "
        "openssl rand -base64 32"
    )


def generate_key() -> str:
    """A fresh key, base64-encoded, for an operator to store somewhere safe.

    Offered as a command rather than as a fallback. The distinction is the whole of
    decision 2: printing a key a person then has to write down is help; using one
    nobody chose is a silent security change.
    """
    return base64.b64encode(os.urandom(KEY_BYTES)).decode("ascii")


def from_environment() -> LocalKeyCipher:
    """Build the local cipher from the environment, or refuse with instructions.

    Called by an entry point at startup — **not lazily at first use**. A server that
    boots and then fails on somebody's first run has moved a configuration error into a
    user's request, where it reads as the product being broken.
    """
    supplied = os.environ.get(KEY_ENV)
    if not supplied:
        raise CryptoError(
            f"{KEY_ENV} is not set, and delegated credentials cannot be read or "
            "written without it.\n\n"
            "  Generate one:   carnet --generate-key\n"
            f'  PowerShell:     $env:{KEY_ENV} = "<key>"\n'
            f"  macOS / Linux:  export {KEY_ENV}=<key>\n\n"
            "This is deliberately not auto-generated. A key that regenerates makes "
            "every stored credential unreadable, and the failure appears on somebody's "
            "first agent run rather than at startup."
        )

    old = [
        decode_key(part)
        for part in (os.environ.get(OLD_KEYS_ENV) or "").split(",")
        if part.strip()
    ]
    return LocalKeyCipher(decode_key(supplied), old)


# --- the active cipher ------------------------------------------------------------
#
# One per process, set once by an entry point — the same shape as `storage.configure`,
# and for the same reason. `active()` raising rather than lazily building from the
# environment is what keeps the "refuse at startup" property: a lazy default would
# move the missing-key failure back into the first request.

_active: Cipher | None = None


def configure(cipher: Cipher) -> Cipher:
    """Set the process-wide cipher. Returns it, so a caller can keep a handle."""
    global _active
    _active = cipher
    return cipher


def active() -> Cipher:
    """The configured cipher, or a loud failure."""
    if _active is None:
        raise MissingKeyError(
            "no encryption key is configured, so delegated credentials can be neither "
            f"read nor written. Set {KEY_ENV} and start again — "
            "`carnet --generate-key` prints one. (Embedding this runtime? An "
            "entry point must call crypto.configure(crypto.from_environment()).)"
        )
    return _active


def reset() -> None:
    """Drop the active cipher. For tests and for a process that reconfigures."""
    global _active
    _active = None


def seal(plaintext: str, *, tenant_id: str, aad: str) -> tuple[bytes, str]:
    """Seal with the active cipher. See `Cipher.seal`."""
    return active().seal(plaintext, tenant_id=tenant_id, aad=aad)


def open_(blob: bytes, *, tenant_id: str, aad: str, key_id: str) -> str:
    """Open with the active cipher. See `Cipher.open_`."""
    return active().open_(blob, tenant_id=tenant_id, aad=aad, key_id=key_id)


__all__ = [
    "KEY_BYTES",
    "KEY_ENV",
    "OLD_KEYS_ENV",
    "Cipher",
    "CryptoError",
    "LocalKeyCipher",
    "MissingKeyError",
    "UndecryptableError",
    "active",
    "configure",
    "connection_aad",
    "decode_key",
    "from_environment",
    "generate_key",
    "key_id_for",
    "oauth_app_aad",
    "open_",
    "pending_authorization_aad",
    "reset",
    "seal",
    "trigger_secret_aad",
]
