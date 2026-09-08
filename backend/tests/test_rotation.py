"""The sweep that finishes a key rotation. Step 026.

What is asserted here is `rotation.py`'s semantics — the buckets, the verdict, the
resume property. The storage methods it stands on are asserted in
`test_storage_contract.py` against both stores; the door's behaviour when a key is
gone is `test_triggers.py`'s; and the whole procedure driven through the real CLI
against real Postgres is `scripts/e2e_key_rotation.py`.
"""

import pytest

from carnet import rotation, storage
from carnet.core import crypto
from conftest import TEST_ACTOR, TEST_TENANT

KEY_A = b"\xaa" * crypto.KEY_BYTES  # the retired key: everything is seeded under it
KEY_B = b"\xbb" * crypto.KEY_BYTES  # the current key after the rotation
KEY_C = b"\xcc" * crypto.KEY_BYTES  # a key the rotated process has never held

STATE = "s" * 43

AGENT = {
    "name": "issue-reporter",
    "runtime": "simple",
    "system": "You read issues.",
    "permissions": {
        "tools": ["post_message"],
        "scope": {"chat.channel": {"write": ["#eng"]}},
    },
}


def rotated() -> crypto.LocalKeyCipher:
    """The environment mid-rotation: B current, A retired but still listed."""
    return crypto.LocalKeyCipher(KEY_B, [KEY_A])


def seed_all_four(store) -> None:
    """One row per sealed table, every blob sealed under key A."""
    sealer = crypto.LocalKeyCipher(KEY_A)
    store.save_connector(
        TEST_TENANT, {"id": "jira", "launch": {}, "vetted": []}, actor=TEST_ACTOR
    )

    sealed, key_id = sealer.seal(
        "priya-token",
        tenant_id=TEST_TENANT,
        aad=crypto.connection_aad(TEST_TENANT, "user", "u_priya", "jira"),
    )
    store.save_connection(
        TEST_TENANT, "user", "u_priya", "jira",
        ciphertext=sealed, key_id=key_id, actor=TEST_ACTOR,
    )

    sealed, key_id = sealer.seal(
        "client-secret",
        tenant_id=TEST_TENANT,
        aad=crypto.oauth_app_aad(TEST_TENANT, "jira"),
    )
    store.set_connector_oauth(
        TEST_TENANT, "jira",
        authorize_endpoint="https://auth.example.com/authorize",
        token_endpoint="https://auth.example.com/token",
        client_id="client-abc",
        client_secret=sealed,
        key_id=key_id,
        actor=TEST_ACTOR,
    )

    store.save_agent(TEST_TENANT, AGENT, actor=TEST_ACTOR)
    store.create_api_token(
        TEST_TENANT,
        {"id": "m_rot", "name": "ci", "owner_id": "u-1", "secret_hash": "sha256$abc"},
        actor=TEST_ACTOR,
    )
    sealed, key_id = sealer.seal(
        "trigger-secret",
        tenant_id=TEST_TENANT,
        aad=crypto.trigger_secret_aad(TEST_TENANT, "trg_rotate0001"),
    )
    store.create_trigger(
        TEST_TENANT,
        {
            "id": "trg_rotate0001",
            "agent_name": "issue-reporter",
            "token_id": "m_rot",
            "name": "hook",
            "task": "triage the event below",
            "secret_sealed": sealed,
            "secret_key_id": key_id,
        },
        actor=TEST_ACTOR,
    )

    sealed, key_id = sealer.seal(
        "pkce-verifier",
        tenant_id=TEST_TENANT,
        aad=crypto.pending_authorization_aad(TEST_TENANT, STATE),
    )
    store.create_pending_authorization(
        STATE, TEST_TENANT,
        principal_kind="user",
        principal_id="u_priya",
        connector_id="jira",
        code_verifier=sealed,
        key_id=key_id,
        redirect_uri="https://runtime.acme.com/connect/callback",
    )


def test_the_sweep_reseals_all_four_tables_and_the_old_key_becomes_droppable():
    store = storage.active()
    seed_all_four(store)

    report = rotation.sweep(rotated())

    assert report.finished
    assert {t.table: t.resealed for t in report.tables} == {
        "connections": 1,
        "connector_oauth": 1,
        "triggers": 1,
        "pending_authorizations": 1,
    }
    assert report.stranded == []
    assert all(counts == {} for counts in report.remaining.values())

    # The proof of step four: a process holding ONLY key B — the old list emptied —
    # opens every row, and each decrypts to the plaintext seeded under A.
    b_only = crypto.LocalKeyCipher(KEY_B)

    row = store.find_connection(TEST_TENANT, "user", "u_priya", "jira")
    assert b_only.open_(
        row["ciphertext"],
        tenant_id=TEST_TENANT,
        aad=crypto.connection_aad(TEST_TENANT, "user", "u_priya", "jira"),
        key_id=row["key_id"],
    ) == "priya-token"

    row = store.get_connector_oauth(TEST_TENANT, "jira")
    assert b_only.open_(
        row["client_secret"],
        tenant_id=TEST_TENANT,
        aad=crypto.oauth_app_aad(TEST_TENANT, "jira"),
        key_id=row["key_id"],
    ) == "client-secret"

    row = store.get_trigger(TEST_TENANT, "trg_rotate0001")
    assert b_only.open_(
        row["secret_sealed"],
        tenant_id=TEST_TENANT,
        aad=crypto.trigger_secret_aad(TEST_TENANT, "trg_rotate0001"),
        key_id=row["secret_key_id"],
    ) == "trigger-secret"

    row = store.consume_pending_authorization(STATE)
    assert b_only.open_(
        row["code_verifier"],
        tenant_id=TEST_TENANT,
        aad=crypto.pending_authorization_aad(TEST_TENANT, STATE),
        key_id=row["key_id"],
    ) == "pkce-verifier"


def test_running_it_again_finds_nothing_owed():
    """Resume is the predicate: a finished sweep's re-run is a no-op status check."""
    store = storage.active()
    seed_all_four(store)
    rotation.sweep(rotated())

    again = rotation.sweep(rotated())

    assert again.finished
    assert all(t.resealed == 0 for t in again.tables)
    assert again.expired_pending_removed == 0


def test_a_row_in_neither_list_is_reported_skipped_and_does_not_block():
    store = storage.active()
    store.save_connector(
        TEST_TENANT, {"id": "jira", "launch": {}, "vetted": []}, actor=TEST_ACTOR
    )
    stranger = crypto.LocalKeyCipher(KEY_C)
    sealed, key_id = stranger.seal(
        "lost-token",
        tenant_id=TEST_TENANT,
        aad=crypto.connection_aad(TEST_TENANT, "user", "u_lost", "jira"),
    )
    store.save_connection(
        TEST_TENANT, "user", "u_lost", "jira",
        ciphertext=sealed, key_id=key_id, actor=TEST_ACTOR,
    )

    report = rotation.sweep(rotated())

    assert [s.table for s in report.stranded] == ["connections"]
    stranded = report.stranded[0]
    assert stranded.blocks is False
    assert stranded.key_id == key_id
    assert "does not hold" in stranded.reason
    assert crypto.OLD_KEYS_ENV in stranded.remedy
    # Untouched: still sealed under C, exactly as unreadable as before the sweep.
    row = store.find_connection(TEST_TENANT, "user", "u_lost", "jira")
    assert (row["ciphertext"], row["key_id"]) == (sealed, key_id)
    # And not a hostage: the done-when is about RETIRED keys, and no row names one.
    assert report.finished
    assert report.remaining["connections"] == {key_id: 1}


def test_a_tampered_retired_row_blocks_the_verdict():
    """An UndecryptableError under a listed key is a security event, and it holds up
    the drop on purpose: the query stays pure and the operator cannot scroll past."""
    store = storage.active()
    seed_all_four(store)
    row = store.get_trigger(TEST_TENANT, "trg_rotate0001")
    # The tamper: garbage bytes under the same key id, written through the CAS so the
    # simulation is honest about what an attacker with row access could do.
    assert store.reseal_trigger_secret(
        TEST_TENANT, "trg_rotate0001",
        secret_sealed=b"\x00garbage",
        secret_key_id=row["secret_key_id"],
        if_secret_sealed=row["secret_sealed"],
    )

    report = rotation.sweep(rotated())

    assert not report.finished
    tampered = [s for s in report.stranded if s.table == "triggers"]
    assert len(tampered) == 1 and tampered[0].blocks is True
    assert "failed authentication" in tampered[0].reason
    assert report.remaining["triggers"] == {row["secret_key_id"]: 1}
    # Everything else still finished: one bad row does not stall the rotation.
    assert {t.table: t.resealed for t in report.tables}["connections"] == 1


def _pending_under(store, cipher, plaintext="orphan-verifier", state=STATE):
    sealed, key_id = cipher.seal(
        plaintext,
        tenant_id=TEST_TENANT,
        aad=crypto.pending_authorization_aad(TEST_TENANT, state),
    )
    store.create_pending_authorization(
        state, TEST_TENANT,
        principal_kind="user",
        principal_id="u_priya",
        connector_id="jira",
        code_verifier=sealed,
        key_id=key_id,
        redirect_uri="https://runtime.acme.com/connect/callback",
    )
    return sealed, key_id


def test_a_pending_flow_under_an_unknown_key_is_kept_and_reported():
    """**The rule the whole module holds to: nothing a restored key would recover is
    destroyed** — and this table is not an exception to it, which the first version of
    the sweep got wrong. It deleted any pending row it could not open, including ones
    whose key was merely absent from the list, so an operator who dropped the old key
    early and then ran the command destroyed the very rows the printed remedy ("put the
    key back and run again") was about to tell them to recover."""
    store = storage.active()
    sealed, key_id = _pending_under(store, crypto.LocalKeyCipher(KEY_C))

    report = rotation.sweep(rotated())

    assert report.unreadable_pending_removed == 0
    assert [s.table for s in report.stranded] == ["pending_authorizations"]
    assert report.stranded[0].blocks is False
    # Kept, byte for byte — so restoring key C really does recover it.
    kept = store.consume_pending_authorization(STATE)
    assert kept is not None and kept["code_verifier"] == sealed
    # And the address carries no `state`: it is a bearer handle for one flow.
    assert STATE not in report.stranded[0].address
    assert report.finished


def test_a_pending_flow_no_key_can_open_is_deleted():
    """The one destructive branch, and the case where destruction is the only outcome
    available: the key IS held and the blob still will not authenticate, so no restored
    key recovers it and its only future is a 503 at somebody's callback."""
    store = storage.active()
    _pending_under(store, crypto.LocalKeyCipher(KEY_A))
    row = store.consume_pending_authorization(STATE)
    store.create_pending_authorization(
        STATE, TEST_TENANT,
        principal_kind="user",
        principal_id="u_priya",
        connector_id="jira",
        code_verifier=b"\x00garbage-under-a-held-key",
        key_id=row["key_id"],
        redirect_uri="https://runtime.acme.com/connect/callback",
    )

    report = rotation.sweep(rotated())

    assert report.unreadable_pending_removed == 1
    assert store.consume_pending_authorization(STATE) is None
    assert report.finished
    # **The row goes and the evidence stays.** On the other three tables this exact
    # condition is a security event that blocks the verdict; folding it into a bare
    # count here lost both the address and the fact that a verifier had been altered
    # or copied out of another flow.
    assert [s.table for s in report.stranded] == ["pending_authorizations"]
    assert "failed authentication" in report.stranded[0].reason
    assert "write access" in report.stranded[0].remedy
    assert STATE not in report.stranded[0].address
    # Nobody can act on a row that is already gone, so it does not fail the command.
    assert report.stranded[0].needs_a_person is False
    assert report.needs_a_person == []


def test_expired_pending_flows_are_removed_before_anything_is_resealed(monkeypatch):
    store = storage.active()
    seed_all_four(store)
    # Age is caller-supplied, not stored; shrinking the TTL is how a test says
    # "everything is expired" without reaching into the store's rows.
    monkeypatch.setattr(rotation, "PENDING_TTL_SECONDS", -1)

    report = rotation.sweep(rotated())

    assert report.expired_pending_removed == 1
    assert {t.table: t.resealed for t in report.tables}["pending_authorizations"] == 0
    assert report.finished


def test_the_sweep_requires_locally_held_keys():
    class KmsShaped:
        def seal(self, plaintext, *, tenant_id, aad):
            raise AssertionError("never reached")

        def open_(self, blob, *, tenant_id, aad, key_id):
            raise AssertionError("never reached")

    with pytest.raises(crypto.CryptoError, match="KMS"):
        rotation.sweep(KmsShaped())


# --- edge cases, driven in the testing pass ------------------------------------------


def test_more_than_one_retired_key_is_swept_in_one_pass():
    """An operator who rotated twice without finishing, or who lists two old keys.

    `CARNET_SECRET_KEYS_OLD` is a comma-separated list for exactly this, and a
    sweep that only handled one of them would leave the second permanently listed.
    """
    store = storage.active()
    store.save_connector(
        TEST_TENANT, {"id": "jira", "launch": {}, "vetted": []}, actor=TEST_ACTOR
    )
    for key, who in ((KEY_A, "u_a"), (KEY_C, "u_c")):
        sealed, key_id = crypto.LocalKeyCipher(key).seal(
            f"token-{who}",
            tenant_id=TEST_TENANT,
            aad=crypto.connection_aad(TEST_TENANT, "user", who, "jira"),
        )
        store.save_connection(
            TEST_TENANT, "user", who, "jira",
            ciphertext=sealed, key_id=key_id, actor=TEST_ACTOR,
        )

    report = rotation.sweep(crypto.LocalKeyCipher(KEY_B, [KEY_A, KEY_C]))

    assert report.finished and report.stranded == []
    assert {t.table: t.resealed for t in report.tables}["connections"] == 2
    b_only = crypto.LocalKeyCipher(KEY_B)
    for who in ("u_a", "u_c"):
        row = store.find_connection(TEST_TENANT, "user", who, "jira")
        assert b_only.open_(
            row["ciphertext"],
            tenant_id=TEST_TENANT,
            aad=crypto.connection_aad(TEST_TENANT, "user", who, "jira"),
            key_id=row["key_id"],
        ) == f"token-{who}"


def test_a_key_listed_as_both_current_and_retired_sweeps_nothing():
    """`LocalKeyCipher` already resolves the collision — a key in both places is
    current. The population must agree, or the sweep would re-seal every row in the
    deployment under the key it already holds, every run, forever."""
    store = storage.active()
    seed_all_four(store)

    report = rotation.sweep(crypto.LocalKeyCipher(KEY_A, [KEY_A]))

    assert report.finished
    assert all(t.resealed == 0 for t in report.tables)
    assert report.retired_key_ids == frozenset()


def test_rotation_preserves_the_binding_that_stops_a_row_being_moved():
    """The security property the whole scheme rests on, re-asserted on the far side of
    a rotation: a re-sealed blob must still refuse to open in any other row. A sweep
    that rebuilt the AAD from the wrong columns would silently unbind every credential
    in the deployment, and nothing else would notice until somebody moved a row."""
    store = storage.active()
    seed_all_four(store)
    rotation.sweep(rotated())
    b_only = crypto.LocalKeyCipher(KEY_B)

    row = store.find_connection(TEST_TENANT, "user", "u_priya", "jira")
    for wrong in (
        crypto.connection_aad(TEST_TENANT, "user", "u_mallory", "jira"),
        crypto.connection_aad("other-tenant", "user", "u_priya", "jira"),
        crypto.connection_aad(TEST_TENANT, "machine", "u_priya", "jira"),
        crypto.connection_aad(TEST_TENANT, "user", "u_priya", "github-mcp"),
    ):
        with pytest.raises(crypto.UndecryptableError):
            b_only.open_(
                row["ciphertext"], tenant_id=TEST_TENANT, aad=wrong, key_id=row["key_id"]
            )

    trigger = store.get_trigger(TEST_TENANT, "trg_rotate0001")
    with pytest.raises(crypto.UndecryptableError):
        b_only.open_(
            trigger["secret_sealed"],
            tenant_id=TEST_TENANT,
            aad=crypto.trigger_secret_aad(TEST_TENANT, "trg_someothertrig"),
            key_id=trigger["secret_key_id"],
        )


def test_an_oauth_credential_survives_as_the_json_its_reader_expects():
    """A `connections` row's plaintext is not always a bare token: an OAuth row holds
    `{"access": ..., "refresh": ...}` and `credentials.access_token` parses it. A sweep
    that mangled the plaintext — or that re-sealed the JSON as something else — would
    send the whole document to a vendor as an Authorization header."""
    from carnet.access.connections import OAuthTokens, connect_account
    from carnet.core import credentials
    from carnet.core.principal import Principal
    from carnet.storage import OAUTH_CREDENTIAL

    store = storage.active()
    store.save_connector(
        TEST_TENANT, {"id": "jira", "launch": {}, "vetted": []}, actor=TEST_ACTOR
    )
    crypto.configure(crypto.LocalKeyCipher(KEY_A))
    priya = Principal.user("u_priya", TEST_TENANT)
    connect_account(
        priya,
        "jira",
        OAuthTokens(access_token="at-123", refresh_token="rt-456"),
        actor=TEST_ACTOR,
    )

    crypto.configure(rotated())
    assert rotation.sweep().finished

    crypto.configure(crypto.LocalKeyCipher(KEY_B))
    row = store.find_connection(TEST_TENANT, "user", "u_priya", "jira")
    assert row["credential_kind"] == OAUTH_CREDENTIAL
    opened = crypto.open_(
        row["ciphertext"],
        tenant_id=TEST_TENANT,
        aad=crypto.connection_aad(TEST_TENANT, "user", "u_priya", "jira"),
        key_id=row["key_id"],
    )
    assert credentials.access_token(opened, OAUTH_CREDENTIAL) == "at-123"
    assert "rt-456" in opened
    # And the reader that runs on the hot path agrees.
    assert credentials.for_connector("jira", priya, identity="user").value == "at-123"


def test_a_plaintext_that_is_not_ascii_survives_the_round_trip():
    """Seal encodes UTF-8 and open decodes it; a sweep that touched bytes rather than
    the string would corrupt any credential with a non-ASCII character in it."""
    store = storage.active()
    store.save_connector(
        TEST_TENANT, {"id": "jira", "launch": {}, "vetted": []}, actor=TEST_ACTOR
    )
    secret = "påsswörd-🔐-日本語"
    sealed, key_id = crypto.LocalKeyCipher(KEY_A).seal(
        secret,
        tenant_id=TEST_TENANT,
        aad=crypto.connection_aad(TEST_TENANT, "user", "u_priya", "jira"),
    )
    store.save_connection(
        TEST_TENANT, "user", "u_priya", "jira",
        ciphertext=sealed, key_id=key_id, actor=TEST_ACTOR,
    )

    rotation.sweep(rotated())

    row = store.find_connection(TEST_TENANT, "user", "u_priya", "jira")
    assert crypto.LocalKeyCipher(KEY_B).open_(
        row["ciphertext"],
        tenant_id=TEST_TENANT,
        aad=crypto.connection_aad(TEST_TENANT, "user", "u_priya", "jira"),
        key_id=row["key_id"],
    ) == secret


def test_every_tenant_is_swept_including_a_suspended_one():
    """A rotation serves every customer. A suspended tenant is not a deleted one — its
    credentials must survive the rotation, or reactivating them is a support ticket."""
    store = storage.active()
    store.create_tenant("t-second", "Second")
    store.create_tenant("t-suspended", "Suspended")
    sealer = crypto.LocalKeyCipher(KEY_A)
    for tenant in (TEST_TENANT, "t-second", "t-suspended"):
        store.save_connector(
            tenant, {"id": "jira", "launch": {}, "vetted": []}, actor=TEST_ACTOR
        )
        sealed, key_id = sealer.seal(
            f"token-{tenant}",
            tenant_id=tenant,
            aad=crypto.connection_aad(tenant, "user", "u_priya", "jira"),
        )
        store.save_connection(
            tenant, "user", "u_priya", "jira",
            ciphertext=sealed, key_id=key_id, actor=TEST_ACTOR,
        )
    store.set_tenant_status("t-suspended", "suspended")

    report = rotation.sweep(rotated())

    assert {t.table: t.resealed for t in report.tables}["connections"] == 3
    b_only = crypto.LocalKeyCipher(KEY_B)
    for tenant in (TEST_TENANT, "t-second", "t-suspended"):
        row = store.find_connection(tenant, "user", "u_priya", "jira")
        assert b_only.open_(
            row["ciphertext"],
            tenant_id=tenant,
            aad=crypto.connection_aad(tenant, "user", "u_priya", "jira"),
            key_id=row["key_id"],
        ) == f"token-{tenant}"


def test_an_empty_deployment_is_finished_and_says_so():
    report = rotation.sweep(rotated())

    assert report.finished and report.stranded == []
    assert report.remaining == {
        "connections": {},
        "connector_oauth": {},
        "triggers": {},
        "pending_authorizations": {},
    }


def test_a_row_already_under_the_current_key_is_never_touched():
    """Not merely an optimization: re-sealing on every run would rewrite every blob in
    the deployment nightly, and the CAS makes that a write storm rather than a no-op."""
    store = storage.active()
    store.save_connector(
        TEST_TENANT, {"id": "jira", "launch": {}, "vetted": []}, actor=TEST_ACTOR
    )
    sealed, key_id = crypto.LocalKeyCipher(KEY_B).seal(
        "already-current",
        tenant_id=TEST_TENANT,
        aad=crypto.connection_aad(TEST_TENANT, "user", "u_priya", "jira"),
    )
    store.save_connection(
        TEST_TENANT, "user", "u_priya", "jira",
        ciphertext=sealed, key_id=key_id, actor=TEST_ACTOR,
    )

    report = rotation.sweep(rotated())

    assert {t.table: t.resealed for t in report.tables}["connections"] == 0
    # Byte-identical: a fresh seal would have a different nonce.
    assert store.find_connection(
        TEST_TENANT, "user", "u_priya", "jira"
    )["ciphertext"] == sealed


def test_a_refresh_that_lands_first_wins_and_the_sweep_stands_down():
    """The interleaving `base.py` promises: the sweep reads a blob, a token refresh
    rewrites the row, and the sweep's write must match nothing rather than reverting
    the newer credential to an older plaintext."""
    store = storage.active()
    store.save_connector(
        TEST_TENANT, {"id": "jira", "launch": {}, "vetted": []}, actor=TEST_ACTOR
    )
    old_sealed, old_key = crypto.LocalKeyCipher(KEY_A).seal(
        "the-old-token",
        tenant_id=TEST_TENANT,
        aad=crypto.connection_aad(TEST_TENANT, "user", "u_priya", "jira"),
    )
    store.save_connection(
        TEST_TENANT, "user", "u_priya", "jira",
        ciphertext=old_sealed, key_id=old_key, actor=TEST_ACTOR,
    )
    row = store.find_connection(TEST_TENANT, "user", "u_priya", "jira")

    # The refresh, landing while the sweep holds the bytes it read.
    fresh_sealed, fresh_key = rotated().seal(
        "the-refreshed-token",
        tenant_id=TEST_TENANT,
        aad=crypto.connection_aad(TEST_TENANT, "user", "u_priya", "jira"),
    )
    assert store.update_connection_credential(
        TEST_TENANT, "user", "u_priya", "jira",
        ciphertext=fresh_sealed, key_id=fresh_key,
        expires_at=None, refresh_expires_at=None,
        if_updated_at=row["updated_at"],
    ) is not None

    # The sweep's write, with the stale expectation: it must not land.
    assert store.reseal_connection(
        TEST_TENANT, "user", "u_priya", "jira",
        ciphertext=b"would-be-a-revert", key_id=rotated().key_id,
        if_ciphertext=old_sealed,
    ) is False
    assert store.find_connection(
        TEST_TENANT, "user", "u_priya", "jira"
    )["ciphertext"] == fresh_sealed


def test_a_reseal_leaves_the_refreshs_compare_and_set_token_usable():
    """The other order, and the one that would break silently: the sweep re-seals, and
    a refresh that read the row *before* it must still be able to land its own write.
    If a reseal bumped `updated_at`, every in-flight refresh would lose its race and
    a provider that rotates refresh tokens would leave the connection dead."""
    store = storage.active()
    store.save_connector(
        TEST_TENANT, {"id": "jira", "launch": {}, "vetted": []}, actor=TEST_ACTOR
    )
    sealed, key_id = crypto.LocalKeyCipher(KEY_A).seal(
        "the-old-token",
        tenant_id=TEST_TENANT,
        aad=crypto.connection_aad(TEST_TENANT, "user", "u_priya", "jira"),
    )
    store.save_connection(
        TEST_TENANT, "user", "u_priya", "jira",
        ciphertext=sealed, key_id=key_id, actor=TEST_ACTOR,
    )
    seen_by_the_refresh = store.find_connection(
        TEST_TENANT, "user", "u_priya", "jira"
    )["updated_at"]

    assert rotation.sweep(rotated()).finished

    fresh_sealed, fresh_key = rotated().seal(
        "the-refreshed-token",
        tenant_id=TEST_TENANT,
        aad=crypto.connection_aad(TEST_TENANT, "user", "u_priya", "jira"),
    )
    assert store.update_connection_credential(
        TEST_TENANT, "user", "u_priya", "jira",
        ciphertext=fresh_sealed, key_id=fresh_key,
        expires_at=None, refresh_expires_at=None,
        if_updated_at=seen_by_the_refresh,
    ) is not None


def test_the_report_never_carries_a_plaintext_or_a_blob():
    """Everything in the report is printed. A stranded row is addressed by its identity
    columns and its key id, and nothing else may travel with it."""
    store = storage.active()
    store.save_connector(
        TEST_TENANT, {"id": "jira", "launch": {}, "vetted": []}, actor=TEST_ACTOR
    )
    sealed, key_id = crypto.LocalKeyCipher(KEY_C).seal(
        "the-unreachable-secret",
        tenant_id=TEST_TENANT,
        aad=crypto.connection_aad(TEST_TENANT, "user", "u_lost", "jira"),
    )
    store.save_connection(
        TEST_TENANT, "user", "u_lost", "jira",
        ciphertext=sealed, key_id=key_id, actor=TEST_ACTOR,
    )

    report = rotation.sweep(rotated())

    printed = repr(report)
    assert "the-unreachable-secret" not in printed
    assert repr(sealed)[2:20] not in printed


def test_one_tables_storage_failure_does_not_discard_the_others_or_the_record():
    """**A sweep that dies partway has still done durable work, and the operator is
    left holding whatever it printed.** The first version let the exception carry the
    whole report away, so a blip on table two after four hundred re-seals on table one
    printed nothing at all — and every one of those re-seals was permanent."""
    store = storage.active()
    seed_all_four(store)

    class OneTableIsDown:
        """The real store, with `connector_oauth` unreachable."""

        def __init__(self, real):
            self._real = real

        def __getattr__(self, name):
            if name == "connector_oauth_not_sealed_under":
                def down(*_args, **_kwargs):
                    raise storage.StorageError("connection pool exhausted")
                return down
            return getattr(self._real, name)

    storage.configure(OneTableIsDown(store))
    try:
        report = rotation.sweep(rotated())
    finally:
        storage.configure(store)

    landed = {t.table: t.resealed for t in report.tables}
    assert landed["connections"] == 1 and landed["triggers"] == 1
    assert landed["connector_oauth"] == 0
    failed = [t for t in report.tables if t.failed]
    assert [t.table for t in failed] == ["connector_oauth"]
    assert "pool exhausted" in failed[0].failed
    # And the verdict is honest about the table that did not finish.
    assert not report.finished
    assert list(report.remaining["connector_oauth"]) != []


def test_a_process_still_on_the_old_key_is_named_rather_than_guessed_at():
    """**The one rotation failure whose remedy is not on any row.** A server that was
    never restarted seals with *its* current key — the retired one — so the sweep
    re-seals and it writes back, forever, and every printed remedy (reconnect,
    reconfigure, recreate) is useless. It is inferred by subtraction: a row under a
    retired key that no stranded row explains was written after the sweep passed it,
    and nothing but a process still holding that key can have written it."""
    store = storage.active()
    store.save_connector(
        TEST_TENANT, {"id": "jira", "launch": {}, "vetted": []}, actor=TEST_ACTOR
    )
    # A row that arrives under the retired key *after* the sweep has walked past it.
    stale, stale_key = crypto.LocalKeyCipher(KEY_A).seal(
        "written-by-a-server-nobody-restarted",
        tenant_id=TEST_TENANT,
        aad=crypto.connection_aad(TEST_TENANT, "user", "u_late", "jira"),
    )

    class WritesBehindTheSweep:
        def __init__(self, real):
            self._real = real
            self.swept = False

        def __getattr__(self, name):
            if name == "connections_not_sealed_under":
                def fetch(*args, **kwargs):
                    rows = self._real.connections_not_sealed_under(*args, **kwargs)
                    if not self.swept:
                        self.swept = True
                        self._real.save_connection(
                            TEST_TENANT, "user", "u_late", "jira",
                            ciphertext=stale, key_id=stale_key, actor=TEST_ACTOR,
                        )
                    return rows
                return fetch
            return getattr(self._real, name)

    storage.configure(WritesBehindTheSweep(store))
    try:
        report = rotation.sweep(rotated())
    finally:
        storage.configure(store)

    assert not report.finished
    assert report.stranded == []  # nothing failed to open; the row simply appeared
    assert report.rows_written_under_a_retired_key == 1


def test_a_row_the_sweep_could_not_open_is_not_mistaken_for_a_stale_writer():
    """The subtraction's other half: a blocking stranded row already explains itself,
    so it must not also be reported as a process still writing under the old key."""
    store = storage.active()
    seed_all_four(store)
    row = store.get_trigger(TEST_TENANT, "trg_rotate0001")
    store.reseal_trigger_secret(
        TEST_TENANT, "trg_rotate0001",
        secret_sealed=b"\x00garbage", secret_key_id=row["secret_key_id"],
        if_secret_sealed=row["secret_sealed"],
    )

    report = rotation.sweep(rotated())

    assert not report.finished
    assert [s.blocks for s in report.stranded] == [True]
    assert report.rows_written_under_a_retired_key == 0
