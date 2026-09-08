"""Encryption at rest for delegated credentials.

The weight here is on the *refusals*, not on the round trip. A cipher that encrypts and
decrypts correctly is table stakes and would pass with none of the properties this
module exists for: that a row moved between users fails, that an unknown key is an
error rather than a fallback, and that a missing key stops the process instead of
somebody's first agent run.
"""

import base64
import os

import pytest

from carnet.core import crypto

TENANT = "t-test"
OTHER_TENANT = "t-other"


def a_key(seed: int = 1) -> bytes:
    """A deterministic 32-byte key. Distinct seeds give distinct keys."""
    return bytes([seed]) * crypto.KEY_BYTES


def an_aad(principal_id: str = "u_priya", tenant_id: str = TENANT) -> str:
    return crypto.connection_aad(tenant_id, "user", principal_id, "github-mcp")


@pytest.fixture
def cipher():
    return crypto.LocalKeyCipher(a_key())


# --- the round trip ---------------------------------------------------------------


def test_round_trip_returns_the_input(cipher):
    blob, key_id = cipher.seal("github_pat_secret", tenant_id=TENANT, aad=an_aad())
    assert cipher.open_(blob, tenant_id=TENANT, aad=an_aad(), key_id=key_id) == (
        "github_pat_secret"
    )


def test_the_plaintext_is_not_in_the_blob(cipher):
    blob, _ = cipher.seal("github_pat_secret", tenant_id=TENANT, aad=an_aad())
    assert b"github_pat_secret" not in blob


def test_each_seal_uses_a_fresh_nonce(cipher):
    """Two seals of one plaintext must not produce one ciphertext.

    Nonce reuse under a single key is how GCM breaks catastrophically rather than
    gracefully, and a deterministic ciphertext is also an oracle: equal blobs would
    tell anybody with read access that two users connected the same account.
    """
    first, _ = cipher.seal("same", tenant_id=TENANT, aad=an_aad())
    second, _ = cipher.seal("same", tenant_id=TENANT, aad=an_aad())
    assert first != second
    assert first[: crypto.NONCE_BYTES] != second[: crypto.NONCE_BYTES]


# --- tampering --------------------------------------------------------------------


@pytest.mark.parametrize("index", [0, crypto.NONCE_BYTES, -1])
def test_a_single_flipped_byte_fails(cipher, index):
    """Anywhere in the blob: the nonce, the ciphertext body, and the trailing tag."""
    blob, key_id = cipher.seal("secret", tenant_id=TENANT, aad=an_aad())

    tampered = bytearray(blob)
    tampered[index] ^= 0x01

    with pytest.raises(crypto.UndecryptableError):
        cipher.open_(bytes(tampered), tenant_id=TENANT, aad=an_aad(), key_id=key_id)


def test_a_truncated_row_fails(cipher):
    blob, key_id = cipher.seal("secret", tenant_id=TENANT, aad=an_aad())
    with pytest.raises(crypto.UndecryptableError):
        cipher.open_(blob[:8], tenant_id=TENANT, aad=an_aad(), key_id=key_id)


# --- the binding, which is the point ----------------------------------------------


def test_a_row_moved_to_another_principal_fails_to_decrypt(cipher):
    """The cheapest defence against a credential lifted between users.

    The primary key stops two rows colliding and has no opinion about a value copied
    from one to another. This does.
    """
    blob, key_id = cipher.seal("priyas_token", tenant_id=TENANT, aad=an_aad("u_priya"))

    with pytest.raises(crypto.UndecryptableError):
        cipher.open_(blob, tenant_id=TENANT, aad=an_aad("u_sam"), key_id=key_id)


def test_a_row_moved_to_another_tenant_fails_to_decrypt(cipher):
    blob, key_id = cipher.seal("token", tenant_id=TENANT, aad=an_aad(tenant_id=TENANT))

    with pytest.raises(crypto.UndecryptableError):
        cipher.open_(
            blob,
            tenant_id=OTHER_TENANT,
            aad=an_aad(tenant_id=OTHER_TENANT),
            key_id=key_id,
        )


def test_a_row_moved_to_another_connector_fails_to_decrypt(cipher):
    aad = crypto.connection_aad(TENANT, "user", "u_priya", "github-mcp")
    other = crypto.connection_aad(TENANT, "user", "u_priya", "jira")

    blob, key_id = cipher.seal("token", tenant_id=TENANT, aad=aad)

    with pytest.raises(crypto.UndecryptableError):
        cipher.open_(blob, tenant_id=TENANT, aad=other, key_id=key_id)


def test_the_aad_encoding_is_unambiguous():
    """Two different rows must never produce the same bound string.

    Joining on a separator makes tenant `a|b` + kind `c` indistinguishable from tenant
    `a` + kind `b|c`. Length prefixes are what make that unrepresentable rather than
    merely unlikely — and this is impossible to change later without re-encrypting
    every stored row.
    """
    assert crypto.connection_aad("a|b", "c", "u", "k") != crypto.connection_aad(
        "a", "b|c", "u", "k"
    )
    assert crypto.connection_aad("a", "user", "1:x", "k") != crypto.connection_aad(
        "a", "user", "1", "x:k"
    )


def test_the_aad_carries_a_version_tag():
    """So a future change to which fields are bound cannot verify against the old set."""
    assert crypto.connection_aad(TENANT, "user", "u", "c").startswith("v1|")


# --- keys and rotation ------------------------------------------------------------


def test_key_id_is_derived_from_the_key_and_is_stable():
    assert crypto.key_id_for(a_key(1)) == crypto.key_id_for(a_key(1))
    assert crypto.key_id_for(a_key(1)) != crypto.key_id_for(a_key(2))
    assert len(crypto.key_id_for(a_key(1))) == crypto.KEY_ID_CHARS


def test_key_id_is_not_a_prefix_of_the_raw_hash():
    """Derived through a domain separator, so the column is not `sha256(key)[:8]`."""
    import hashlib

    assert not hashlib.sha256(a_key()).hexdigest().startswith(crypto.key_id_for(a_key()))


def test_an_unknown_key_id_raises_and_names_the_fix(cipher):
    """Never a fallback. See `credentials.for_connector` for why that matters."""
    blob, _ = cipher.seal("secret", tenant_id=TENANT, aad=an_aad())

    with pytest.raises(crypto.MissingKeyError) as caught:
        cipher.open_(blob, tenant_id=TENANT, aad=an_aad(), key_id="deadbeef")

    assert crypto.OLD_KEYS_ENV in str(caught.value)


def test_a_retired_key_still_opens_rows_the_current_key_cannot():
    """Rotation without a maintenance window: new key encrypts, old key still decrypts."""
    old_cipher = crypto.LocalKeyCipher(a_key(1))
    blob, old_id = old_cipher.seal("older_token", tenant_id=TENANT, aad=an_aad())

    rotated = crypto.LocalKeyCipher(a_key(2), old_keys=[a_key(1)])

    assert rotated.open_(blob, tenant_id=TENANT, aad=an_aad(), key_id=old_id) == (
        "older_token"
    )


def test_rotation_writes_new_rows_under_the_current_key():
    rotated = crypto.LocalKeyCipher(a_key(2), old_keys=[a_key(1)])
    _, key_id = rotated.seal("fresh", tenant_id=TENANT, aad=an_aad())

    assert key_id == crypto.key_id_for(a_key(2))
    assert rotated.key_id == key_id


def test_dropping_the_old_key_makes_its_rows_unreadable_rather_than_wrong():
    """The failure mode of a botched rotation is an error, not the wrong credential."""
    old_cipher = crypto.LocalKeyCipher(a_key(1))
    blob, old_id = old_cipher.seal("older_token", tenant_id=TENANT, aad=an_aad())

    dropped = crypto.LocalKeyCipher(a_key(2))  # old key no longer listed

    with pytest.raises(crypto.MissingKeyError):
        dropped.open_(blob, tenant_id=TENANT, aad=an_aad(), key_id=old_id)


def test_a_key_listed_as_both_current_and_old_is_treated_as_current():
    both = crypto.LocalKeyCipher(a_key(1), old_keys=[a_key(1), a_key(2)])
    _, key_id = both.seal("x", tenant_id=TENANT, aad=an_aad())
    assert key_id == crypto.key_id_for(a_key(1))


@pytest.mark.parametrize("size", [16, 31, 33, 64])
def test_a_key_of_the_wrong_length_is_refused(size):
    with pytest.raises(crypto.CryptoError, match="32 bytes"):
        crypto.LocalKeyCipher(bytes(size))


# --- reading a key out of the environment -----------------------------------------


def test_no_key_set_refuses_with_instructions(monkeypatch):
    """The refusal happens at startup. See bootstrap for where it is called."""
    monkeypatch.delenv(crypto.KEY_ENV, raising=False)

    with pytest.raises(crypto.CryptoError) as caught:
        crypto.from_environment()

    message = str(caught.value)
    assert crypto.KEY_ENV in message
    assert "--generate-key" in message


def test_base64_and_hex_are_both_accepted(monkeypatch):
    """Both are what `openssl rand` prints, depending on which flag somebody used."""
    key = a_key(7)

    monkeypatch.setenv(crypto.KEY_ENV, base64.b64encode(key).decode())
    monkeypatch.delenv(crypto.OLD_KEYS_ENV, raising=False)
    assert crypto.from_environment().key_id == crypto.key_id_for(key)

    monkeypatch.setenv(crypto.KEY_ENV, key.hex())
    assert crypto.from_environment().key_id == crypto.key_id_for(key)


def test_surrounding_whitespace_is_tolerated(monkeypatch):
    key = a_key(7)
    monkeypatch.setenv(crypto.KEY_ENV, f"  {base64.b64encode(key).decode()}\n")
    monkeypatch.delenv(crypto.OLD_KEYS_ENV, raising=False)
    assert crypto.from_environment().key_id == crypto.key_id_for(key)


def test_a_malformed_key_is_refused(monkeypatch):
    monkeypatch.setenv(crypto.KEY_ENV, "not-a-key")
    with pytest.raises(crypto.CryptoError, match="base64"):
        crypto.from_environment()


def test_retired_keys_are_read_as_a_comma_separated_list(monkeypatch):
    monkeypatch.setenv(crypto.KEY_ENV, base64.b64encode(a_key(3)).decode())
    monkeypatch.setenv(
        crypto.OLD_KEYS_ENV,
        f"{base64.b64encode(a_key(1)).decode()}, {a_key(2).hex()}",
    )

    built = crypto.from_environment()
    for seed in (1, 2):
        blob, key_id = crypto.LocalKeyCipher(a_key(seed)).seal(
            "old", tenant_id=TENANT, aad=an_aad()
        )
        assert built.open_(blob, tenant_id=TENANT, aad=an_aad(), key_id=key_id) == "old"


def test_generate_key_produces_a_usable_key():
    generated = crypto.generate_key()
    assert len(crypto.decode_key(generated)) == crypto.KEY_BYTES
    crypto.LocalKeyCipher(crypto.decode_key(generated))  # does not raise


def test_generated_keys_differ():
    assert crypto.generate_key() != crypto.generate_key()


# --- the process-wide cipher ------------------------------------------------------


def test_active_raises_when_nothing_is_configured():
    """A lazy default would move the missing-key failure into somebody's first run.

    The message names the variable rather than the internal call, because the person
    who reads it is far more often an operator than somebody embedding this.
    """
    crypto.reset()
    with pytest.raises(crypto.MissingKeyError) as caught:
        crypto.active()

    assert crypto.KEY_ENV in str(caught.value)


def test_module_level_seal_and_open_use_the_configured_cipher():
    crypto.configure(crypto.LocalKeyCipher(a_key(9)))
    blob, key_id = crypto.seal("through the module", tenant_id=TENANT, aad=an_aad())
    assert crypto.open_(blob, tenant_id=TENANT, aad=an_aad(), key_id=key_id) == (
        "through the module"
    )


def test_the_local_cipher_satisfies_the_protocol():
    assert isinstance(crypto.LocalKeyCipher(a_key()), crypto.Cipher)


# --- when a process refuses to start ----------------------------------------------


def test_a_durable_store_requires_a_key(monkeypatch):
    """With a database, a connections row may already exist or arrive at any moment, so
    a process without a key is one that will fail later on somebody's behalf."""
    from carnet import bootstrap, config

    monkeypatch.setattr(config, "DATABASE_URL", "postgresql://localhost/x")
    monkeypatch.delenv(crypto.KEY_ENV, raising=False)

    with pytest.raises(crypto.CryptoError, match=crypto.KEY_ENV):
        bootstrap.configure_crypto()


def test_an_in_memory_run_does_not_require_a_key(monkeypatch):
    """A key here would protect nothing — no connection can outlive the process — and
    it would break the property that a fresh clone runs an agent with nothing
    installed and nothing running."""
    from carnet import bootstrap, config

    monkeypatch.setattr(config, "DATABASE_URL", None)
    monkeypatch.delenv(crypto.KEY_ENV, raising=False)

    assert bootstrap.configure_crypto() is None


def test_an_entry_point_may_insist_regardless_of_the_store(monkeypatch):
    """The HTTP server does. It is multi-user, and acting as the person who asked is
    the reason it exists."""
    from carnet import bootstrap, config

    monkeypatch.setattr(config, "DATABASE_URL", None)
    monkeypatch.delenv(crypto.KEY_ENV, raising=False)

    with pytest.raises(crypto.CryptoError):
        bootstrap.configure_crypto(required=True)


def test_a_key_is_never_generated_to_fill_the_gap(monkeypatch):
    """The one deliberate divergence from the tool that settled this design.

    Generating one would make a `docker compose up` work in five minutes and would
    also mean every stored credential becomes unreadable the next time the process
    starts — not at write time, not at boot, but on a row that still looks fine.
    """
    from carnet import bootstrap, config

    monkeypatch.setattr(config, "DATABASE_URL", None)
    monkeypatch.delenv(crypto.KEY_ENV, raising=False)
    crypto.reset()

    bootstrap.configure_crypto()

    with pytest.raises(crypto.MissingKeyError):
        crypto.active()


def test_a_configured_key_is_the_one_that_gets_used(monkeypatch):
    from carnet import bootstrap, config

    monkeypatch.setattr(config, "DATABASE_URL", "postgresql://localhost/x")
    monkeypatch.setenv(crypto.KEY_ENV, base64.b64encode(a_key(5)).decode())
    monkeypatch.delenv(crypto.OLD_KEYS_ENV, raising=False)

    bootstrap.configure_crypto()

    assert crypto.active().key_id == crypto.key_id_for(a_key(5))


def test_a_real_random_key_round_trips():
    """`a_key` is a repeated byte; make sure nothing depends on that shape."""
    cipher = crypto.LocalKeyCipher(os.urandom(crypto.KEY_BYTES))
    blob, key_id = cipher.seal("real", tenant_id=TENANT, aad=an_aad())
    assert cipher.open_(blob, tenant_id=TENANT, aad=an_aad(), key_id=key_id) == "real"
