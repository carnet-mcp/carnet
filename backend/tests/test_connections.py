"""Connecting an account — the write half of delegated credentials.

`test_credentials.py` covers the read path. This covers how a credential arrives, and
the properties that have to hold at the moment it is stored: that it is sealed before
it is a row, that nothing returns it afterwards, and that reconnecting replaces rather
than accumulates.
"""

import pytest

from carnet import storage
from carnet.storage import StorageError
from carnet.access import connections
from carnet.core import credentials, crypto
from carnet.core.principal import Principal
from conftest import TEST_ACTOR

TENANT = "t-test"

PRIYA = Principal.user("u_priya", TENANT)
SAM = Principal.user("u_sam", TENANT)
SCHEDULER = Principal.system("nightly", TENANT)


@pytest.fixture(autouse=True)
def vetted_connectors(isolated_storage):
    """The connectors these tests connect to, because migration 021 requires they exist.

    Autouse and file-wide rather than a parameter on fourteen tests: every test here is
    about the write path for a credential, and since `connections_connector_fk` a
    credential is meaningless without a connector row to hang it on. Seeding them here
    keeps each test body about the property it is actually asserting.

    Minimal manifests — nothing in this file launches anything, and what the foreign key
    wants is a row rather than a working server. `isolated_storage` is named so this
    runs after the tenant exists rather than relying on autouse ordering.
    """
    store = storage.active()
    for connector_id in ("github-mcp", "jira"):
        store.save_connector(TENANT, {"id": connector_id, "launch": {}, "vetted": []}, actor=TEST_ACTOR)


def test_a_connected_credential_is_readable_by_its_owner():
    """The round trip the whole step is for: written here, read by the broker's path."""
    connections.connect_account(PRIYA, "github-mcp", "priyas-token", actor=TEST_ACTOR)

    found = credentials.for_connector(
        "github-mcp", PRIYA, "SOME_VENDOR_TOKEN", identity="user"
    )

    assert found.value == "priyas-token"
    assert found.source == credentials.DELEGATED


def test_the_credential_is_sealed_before_it_is_a_row():
    """Never at rest in the clear, not even briefly."""
    connections.connect_account(PRIYA, "github-mcp", "priyas-token", actor=TEST_ACTOR)

    row = storage.active().find_connection(TENANT, "user", "u_priya", "github-mcp")

    assert b"priyas-token" not in row["ciphertext"]
    assert row["key_id"] == crypto.active().key_id


def test_connecting_returns_metadata_and_never_the_credential():
    """A caller reports what it did without holding what it wrote."""
    row = connections.connect_account(
        PRIYA, "github-mcp", "priyas-token", account_label="@priya-acme",
        actor=TEST_ACTOR,
    )

    assert row["account_label"] == "@priya-acme"
    assert "ciphertext" not in row
    assert "priyas-token" not in str(row)


def test_two_people_connect_independently():
    connections.connect_account(PRIYA, "github-mcp", "priyas-token", actor=TEST_ACTOR)
    connections.connect_account(SAM, "github-mcp", "sams-token", actor=TEST_ACTOR)

    assert (
        credentials.for_connector("github-mcp", PRIYA, identity="user").value
        == "priyas-token"
    )
    assert (
        credentials.for_connector("github-mcp", SAM, identity="user").value
        == "sams-token"
    )


def test_reconnecting_replaces_rather_than_accumulates():
    """How a rotated token is fixed. Making somebody disconnect first would leave a
    window in which they have no credential at all."""
    connections.connect_account(PRIYA, "github-mcp", "the-old-one", actor=TEST_ACTOR)
    connections.connect_account(PRIYA, "github-mcp", "the-new-one", actor=TEST_ACTOR)

    assert (
        credentials.for_connector("github-mcp", PRIYA, identity="user").value
        == "the-new-one"
    )
    assert len(connections.list_accounts(TENANT)) == 1


def test_an_empty_credential_is_refused():
    """A connection that exists and cannot authenticate is worse than none: the read
    path would find a row, decrypt it, and send an empty token to a vendor."""
    with pytest.raises(connections.ConnectionRefused, match="no credential"):
        connections.connect_account(PRIYA, "github-mcp", "   ", actor=TEST_ACTOR)

    assert connections.list_accounts(TENANT) == []


def test_surrounding_whitespace_is_stripped():
    """Pasting a token into a terminal brings a newline with it more often than not."""
    connections.connect_account(PRIYA, "github-mcp", "  priyas-token\n", actor=TEST_ACTOR)

    assert (
        credentials.for_connector("github-mcp", PRIYA, identity="user").value
        == "priyas-token"
    )


def test_disconnecting_removes_the_credential():
    connections.connect_account(PRIYA, "github-mcp", "priyas-token", actor=TEST_ACTOR)

    assert connections.disconnect_account(PRIYA, "github-mcp", actor=TEST_ACTOR) is True
    assert storage.active().find_connection(TENANT, "user", "u_priya", "github-mcp") is (
        None
    )


def test_disconnecting_falls_back_rather_than_failing(monkeypatch):
    """After disconnecting, runs go back to the shared credential — they do not break."""
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "the-operators")
    connections.connect_account(PRIYA, "github-mcp", "priyas-token", actor=TEST_ACTOR)
    connections.disconnect_account(PRIYA, "github-mcp", actor=TEST_ACTOR)

    found = credentials.for_connector("github-mcp", PRIYA, "SOME_VENDOR_TOKEN")

    assert found.value == "the-operators"
    assert found.source == credentials.SHARED


def test_disconnecting_something_unconnected_says_so():
    """The boolean exists only so a caller can avoid claiming to have done something."""
    assert connections.disconnect_account(PRIYA, "github-mcp", actor=TEST_ACTOR) is False


def test_disconnecting_one_person_leaves_the_others():
    connections.connect_account(PRIYA, "github-mcp", "priyas-token", actor=TEST_ACTOR)
    connections.connect_account(SAM, "github-mcp", "sams-token", actor=TEST_ACTOR)

    connections.disconnect_account(PRIYA, "github-mcp", actor=TEST_ACTOR)

    assert (
        credentials.for_connector("github-mcp", SAM, identity="user").value
        == "sams-token"
    )


def test_listing_is_scoped_to_one_principal_when_asked():
    connections.connect_account(PRIYA, "github-mcp", "priyas-token", actor=TEST_ACTOR)
    connections.connect_account(SAM, "github-mcp", "sams-token", actor=TEST_ACTOR)

    assert len(connections.list_accounts(TENANT)) == 2
    assert [r["principal_id"] for r in connections.list_accounts(TENANT, PRIYA)] == (
        ["u_priya"]
    )


def test_listing_never_carries_a_credential():
    connections.connect_account(PRIYA, "github-mcp", "priyas-token", actor=TEST_ACTOR)

    listed = connections.list_accounts(TENANT)

    assert "ciphertext" not in listed[0]
    assert "priyas-token" not in str(listed)


def test_a_system_principal_may_connect_its_own_account():
    """A scheduler running a customer's nightly job may act with a service credential
    rather than the platform-wide one."""
    connections.connect_account(SCHEDULER, "github-mcp", "the-schedulers-own", actor=TEST_ACTOR)

    assert credentials.for_connector(
        "github-mcp", SCHEDULER, identity="user"
    ).value == ("the-schedulers-own")


def test_a_connection_is_per_connector():
    connections.connect_account(PRIYA, "github-mcp", "gh-token", actor=TEST_ACTOR)
    connections.connect_account(PRIYA, "jira", "jira-token", actor=TEST_ACTOR)

    assert credentials.for_connector("jira", PRIYA, identity="user").value == "jira-token"
    assert (
        credentials.for_connector("github-mcp", PRIYA, identity="user").value
        == "gh-token"
    )


def test_a_connection_without_a_connector_is_refused():
    with pytest.raises(connections.ConnectionRefused, match="name the connector"):
        connections.connect_account(PRIYA, "", "priyas-token", actor=TEST_ACTOR)


def test_connecting_to_a_connector_nobody_vetted_is_refused():
    """Migration 021, seen from where a person meets it.

    The failure mode this replaces: the row was stored happily and failed at the first
    run that needed it, long after whoever pasted the token had moved on. A typo in a
    connector name is now answered at the moment of typing it.
    """
    with pytest.raises(connections.ConnectionRefused, match="no connector 'github-mpc'"):
        connections.connect_account(PRIYA, "github-mpc", "priyas-token", actor=TEST_ACTOR)

    assert connections.list_accounts(TENANT) == []


def test_an_unvetted_connector_is_a_refusal_rather_than_a_storage_failure():
    """`ConnectionRefused`, not `StorageError`, and the distinction is what the caller
    tells the person: every other StorageError is a 503, and "the database is
    unavailable" is the wrong answer to a mistyped name."""
    with pytest.raises(connections.ConnectionRefused) as caught:
        connections.connect_account(PRIYA, "github-mpc", "priyas-token", actor=TEST_ACTOR)

    assert not isinstance(caught.value, StorageError)


def test_one_tenants_connection_is_invisible_to_another(monkeypatch):
    """Tenancy comes off the principal, as it does everywhere else.

    The same principal *id* in two tenants is a real shape — ids are ours and opaque,
    and nothing stops two customers' sequences colliding. What must not happen is one
    of them reaching the other's credential.

    The environment is cleared explicitly. `CONNECTOR_CREDENTIAL_ENV` maps `github-mcp`
    to a variable a developer running this suite probably has set to a real token, and
    a test that reads one is a test that can print one into a failure message.
    """
    monkeypatch.delenv("GITHUB_PERSONAL_ACCESS_TOKEN", raising=False)
    storage.active().create_tenant("t-other", "Other")
    elsewhere = Principal.user("u_priya", "t-other")

    connections.connect_account(PRIYA, "github-mcp", "priyas-token", actor=TEST_ACTOR)

    assert connections.list_accounts("t-other") == []
    # Not Priya's, and not an error: the other tenant simply has no delegated
    # credential, so it falls through to a shared one that is not configured either.
    assert credentials.for_connector("github-mcp", elsewhere) is None
