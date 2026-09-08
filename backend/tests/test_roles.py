"""Platform roles: who may administer this tenant.

The risk 12b sets out to retire is one question — *does an administrative role arrive
without becoming a master key?* — so the assertion that matters most here is not the
happy path. It is `test_holding_admin_grants_access_to_no_agent_run_or_connection`,
which is 7b's argument one level up: an `admin` that implied agent access would rebuild
the operator who holds everybody's credentials, one grant away.

Everything else divides into two: the seam (`require_admin`, and what `system` means),
and the log (what a grant, a re-grant and a revoke leave behind).

`test_storage_contract.py` covers what the two stores do with a role row. This covers
what a role *means*.
"""

import pytest

from carnet import agents, storage
from carnet.access import connections, grants, roles
from carnet.access.grants import NoAccess
from carnet.access.roles import RoleRequired
from carnet.core import Principal

from conftest import TEST_TENANT

ACTOR = "system:cli"

AGENT = {
    "name": "payroll-bot",
    "system": "You are a demo agent.",
    "permissions": {
        "tools": ["post_message"],
        "scope": {"chat.channel": {"write": ["#eng"]}},
    },
}


def user(id_):
    return Principal.user(id_, TEST_TENANT)


def cli():
    return Principal.system("cli", TEST_TENANT)


def make_admin(id_="u-priya"):
    storage.active().grant_platform_role(
        TEST_TENANT, "user", id_, "admin", actor=ACTOR
    )
    return user(id_)


# --- the seam --------------------------------------------------------------------


def test_an_ordinary_person_is_not_an_administrator(isolated_storage):
    assert roles.is_admin(user("u-1")) is False

    with pytest.raises(RoleRequired, match="administrator"):
        roles.require_admin(user("u-1"))


def test_a_row_makes_somebody_an_administrator(isolated_storage):
    priya = make_admin()

    assert roles.is_admin(priya) is True
    roles.require_admin(priya)


def test_a_system_principal_is_an_administrator_with_no_row(isolated_storage):
    """The bootstrap, and it is a decision rather than a shortcut.

    HTTP cannot mint a `system` principal — every path through `api/deps.py` ends at
    `users.resolve`, which returns `Principal.user(...)` — so this is safe over HTTP, and
    it is what makes *who grants the first admin?* answerable at all: whoever has the
    shell, which is this deployment's actual root of trust.
    """
    assert roles.is_admin(cli()) is True
    assert storage.active().list_platform_roles(TEST_TENANT) == []


def test_the_refusal_names_no_administrators(isolated_storage):
    """Finding 7's cost, priced deliberately: a person asks a colleague rather than
    reading a screen, and nobody gets a directory of who to phish."""
    make_admin("u-priya")

    with pytest.raises(RoleRequired) as refused:
        roles.require_admin(user("u-nobody"))

    assert "u-priya" not in str(refused.value)
    assert "grant" in str(refused.value)


def test_a_refused_admin_check_is_recorded_with_its_what(isolated_storage):
    """015's hook at the second seam. The `what` its callers already pass — "creating
    a group", '' — is recorded for free, with no new parameter anywhere."""
    with pytest.raises(RoleRequired):
        roles.require_admin(user("u-sam"), "creating a group")

    (record,) = storage.active().denial_records(TEST_TENANT)
    assert (record["principal_kind"], record["principal_id"]) == ("user", "u-sam")
    assert (record["resource_kind"], record["resource_id"]) == ("admin", "creating a group")
    assert (record["required"], record["held"]) == ("admin", "")


def test_a_refusal_with_no_what_still_records(isolated_storage):
    """An empty `what` is most callers — `admin_from_request` passes none — and a
    record with an empty resource id still names who tried, which is the question."""
    with pytest.raises(RoleRequired):
        roles.require_admin(user("u-sam"))

    (record,) = storage.active().denial_records(TEST_TENANT)
    assert (record["resource_kind"], record["resource_id"]) == ("admin", "")


def test_a_system_principal_is_never_refused_so_never_recorded(isolated_storage):
    """The edge table's row: always-admin is the bootstrap, so the deny branch — and
    the hook inside it — is unreachable for `system`."""
    roles.require_admin(cli(), "anything at all")

    assert storage.active().denial_records(TEST_TENANT) == []


def test_an_admitted_administrator_records_nothing(isolated_storage):
    make_admin("u-priya")

    roles.require_admin(user("u-priya"))

    assert storage.active().denial_records(TEST_TENANT) == []


def test_the_role_is_scoped_to_one_tenant(isolated_storage):
    """`admin` of tenant A holds nothing in tenant B. There is deliberately no
    platform-wide super-role: cross-tenant administration is the operator's, on the
    shell, where it already lives."""
    storage.active().create_tenant("globex", "Globex")
    make_admin("u-priya")

    assert roles.is_admin(user("u-priya")) is True
    assert roles.is_admin(Principal.user("u-priya", "globex")) is False


# --- an admin is not a superuser -------------------------------------------------


def test_holding_admin_grants_access_to_no_agent_run_or_connection(isolated_storage):
    """**The most important assertion in this file.**

    The ladder still answers who may use an agent; `for_connector` still answers whose
    credential a call acts with. A role row changes neither, and the reason it must not
    is 7b's: delegated credentials exist so that no operator holds everybody's tokens,
    and an `admin` that implied access would rebuild that operator under a new name.
    """
    agents.save(TEST_TENANT, AGENT, actor=ACTOR)
    priya = make_admin()

    assert grants.check(priya, "payroll-bot") is False

    with pytest.raises(NoAccess):
        grants.require(priya, "payroll-bot")

    # And the credential half, which is where the argument comes from. Sam has connected
    # his Jira account; being an administrator does not make it Priya's.
    store = storage.active()
    store.create_connector(
        TEST_TENANT,
        "jira",
        launch={"transport": "http", "url": "https://mcp.example.com/jira"},
        actor=ACTOR,
    )
    store.save_connection(
        TEST_TENANT, "user", "u-sam", "jira", ciphertext=b"sealed", key_id="k1",
        actor="user:u-sam",
    )

    assert store.has_connection(TEST_TENANT, "user", "u-sam", "jira") is True
    assert store.has_connection(TEST_TENANT, "user", "u-priya", "jira") is False
    assert connections.list_accounts(TEST_TENANT, priya) == []


def test_an_administrator_gets_an_agent_the_ordinary_way(isolated_storage):
    """The other half, so the test above is not read as "admins can never run anything".
    An admin who wants an agent gets a grant like anybody else, recorded like anybody's."""
    agents.save(TEST_TENANT, AGENT, actor=ACTOR)
    priya = make_admin()

    storage.active().grant_agent(
        TEST_TENANT, "payroll-bot", "user", "u-priya", role="user", actor=ACTOR
    )

    assert grants.check(priya, "payroll-bot") is True


# --- granting, revoking, and what the log says -----------------------------------


def test_granting_needs_an_administrator(isolated_storage):
    with pytest.raises(RoleRequired, match="administrator"):
        roles.grant(user("u-1"), user("u-2"))

    with pytest.raises(RoleRequired, match="administrator"):
        roles.revoke(user("u-1"), user("u-2"))

    with pytest.raises(RoleRequired, match="administrator"):
        roles.list_roles(user("u-1"))


def test_an_administrator_may_make_another_one(isolated_storage):
    """Over the CLI, which is the only entry point that grants. There is no
    `PUT /roles/...` — see `access/roles.py` for why admins minting admins over HTTP is
    the one thing a compromised admin token cannot currently do."""
    priya = make_admin()

    roles.grant(priya, user("u-sam"))

    assert roles.is_admin(user("u-sam")) is True


def test_a_group_may_not_hold_a_role(isolated_storage):
    """Otherwise group membership is self-service promotion: add yourself, or be added
    by any current member-adder, and be an administrator. Refused in `check_platform_role`
    and by migration 026's CHECK — both, so widening the frozenset does not open it."""
    with pytest.raises(storage.StorageError, match="group cannot hold"):
        roles.grant(cli(), Principal(kind="group", id="g-1", tenant_id=TEST_TENANT))


def test_a_role_that_is_not_one_is_refused(isolated_storage):
    with pytest.raises(storage.StorageError, match="PLATFORM_ROLES"):
        roles.grant(cli(), user("u-1"), "superuser")


def test_re_granting_records_again_and_refreshes_who_granted_it(isolated_storage):
    """`allow_host`'s argument verbatim: a second approval is a second decision, and the
    most recent yes is who an incident wants to talk to."""
    roles.grant(cli(), user("u-sam"))
    roles.grant(make_admin("u-priya"), user("u-sam"))

    row = [r for r in roles.list_roles(cli()) if r["principal_id"] == "u-sam"][0]
    assert row["granted_by"] == "user:u-priya"

    granted = [
        r
        for r in storage.active().admin_audit_records(TEST_TENANT, action="role.grant")
        if r["target_id"] == "u-sam"
    ]
    assert [r["actor_id"] for r in granted] == ["cli", "u-priya"]


def test_revoking_a_role_nobody_holds_is_a_no_op_and_records_nothing(isolated_storage):
    """`delete_connection`'s rule: the log records changes, not attempts."""
    assert roles.revoke(cli(), user("u-nobody")) is False

    assert (
        storage.active().admin_audit_records(TEST_TENANT, action="role.revoke") == []
    )


def test_revoking_your_own_role_is_allowed_and_the_record_says_so(isolated_storage):
    """7b's `connection.create` precedent: self-action is a real case the log must be
    able to represent, not a degenerate one to refuse."""
    priya = make_admin()

    assert roles.revoke(priya, priya) is True
    assert roles.is_admin(priya) is False

    record = storage.active().admin_audit_records(TEST_TENANT, action="role.revoke")[0]
    assert (record["actor_kind"], record["actor_id"]) == ("user", "u-priya")
    assert (record["target_kind"], record["target_id"]) == ("user", "u-priya")


def test_revoking_the_last_administrator_is_allowed(isolated_storage):
    """Lockout is impossible — the CLI is always an administrator — so a
    "cannot remove the last admin" rule would guard a failure that cannot occur here, and
    would become wrong the day role administration moves to HTTP, where it has to be
    re-decided rather than inherited."""
    priya = make_admin()

    assert roles.revoke(cli(), priya) is True
    assert roles.list_roles(cli()) == []
    assert roles.is_admin(cli()) is True


def test_a_disabled_user_keeps_the_row_and_it_is_revoked_separately(isolated_storage):
    """Two acts, two records. Disabling answers "cut off now" and is enforced at login;
    revoking answers "no longer trusted". Collapsing them would make re-enabling somebody
    silently restore an administrative role nobody re-granted."""
    priya = make_admin()
    storage.active().create_user(
        TEST_TENANT,
        {"id": "u-priya", "issuer": "https://idp", "subject": "00u-priya"},
    )
    storage.active().set_user_status(TEST_TENANT, "u-priya", "disabled", actor="system:test")

    assert roles.is_admin(priya) is True

    roles.revoke(cli(), priya)
    assert roles.is_admin(priya) is False


def test_the_listing_is_what_the_table_holds(isolated_storage):
    """`list_roles` returns rows and **does not invent one for `system`**. A listing that
    included the always-admin would be answering a different question than the one the
    table can answer; `--list-roles` prints the rule as a note under the table instead."""
    make_admin("u-priya")
    roles.grant(cli(), Principal.system("nightly", TEST_TENANT))

    listed = {(r["principal_kind"], r["principal_id"]) for r in roles.list_roles(cli())}

    assert listed == {("user", "u-priya"), ("system", "nightly")}
    assert ("system", "cli") not in listed


def test_nothing_in_the_pending_grant_path_touches_roles(isolated_storage):
    """**There is no pending role, by construction**, and this is where a later "helpful"
    one would leak in: `claim_pending_grants` is the path that turns an address into
    access at first sign-in, and a pending *admin* grant would promote whoever eventually
    claimed a mistyped or recycled address, silently, weeks after somebody typed it.
    """
    agents.save(TEST_TENANT, AGENT, actor=ACTOR)
    store = storage.active()
    store.add_pending_grant(
        TEST_TENANT, "payroll-bot", "sam@acme.com", role="editor", actor=ACTOR
    )

    claimed = store.claim_pending_grants(TEST_TENANT, "sam@acme.com", "user", "u-sam")

    assert claimed == ["payroll-bot"]
    assert roles.is_admin(user("u-sam")) is False
    assert store.list_platform_roles(TEST_TENANT) == []


# --- CARNET_OPEN_ADMIN — step 097 ---------------------------------------------------
#
# One flag at the one seam. What matters is exactly what it opens (every signed-in
# person), exactly what it does not (a machine token; the agent ladder), and that it
# writes nothing — so unsetting it puts the gate back.


def test_open_admin_lets_a_member_with_no_role_administer(monkeypatch):
    from carnet import config

    monkeypatch.setattr(config, "OPEN_ADMIN", True)
    priya = user("u-priya")
    assert roles.is_admin(priya)
    roles.require_admin(priya, "vetting a tool")  # does not raise
    assert storage.active().list_platform_roles(TEST_TENANT) == []


def test_open_admin_does_not_open_for_a_machine_token(monkeypatch):
    from carnet import config

    monkeypatch.setattr(config, "OPEN_ADMIN", True)
    machine = Principal.machine("m_deadbeef", TEST_TENANT)
    assert not roles.is_admin(machine)
    with pytest.raises(RoleRequired):
        roles.require_admin(machine)


def test_open_admin_off_restores_the_gate_with_a_denial_row(monkeypatch):
    from carnet import config

    monkeypatch.setattr(config, "OPEN_ADMIN", False)
    priya = user("u-priya")
    with pytest.raises(RoleRequired) as caught:
        roles.require_admin(priya, "vetting a tool")
    assert roles.NOT_AN_ADMINISTRATOR in str(caught.value)
    (denial,) = storage.active().denial_records(TEST_TENANT)
    assert denial["principal_id"] == "u-priya"


def test_open_admin_grants_no_agent(monkeypatch):
    """An admin is not a superuser, and neither is everybody."""
    from carnet import config

    monkeypatch.setattr(config, "OPEN_ADMIN", True)
    agents.save(TEST_TENANT, AGENT, actor=ACTOR)
    with pytest.raises(NoAccess):
        grants.require(user("u-priya"), "payroll-bot", "user")


def test_open_admin_reaches_the_screens_and_the_record_names_the_member(monkeypatch):
    """Through HTTP: `/me` says admin, an administrative write succeeds, and the
    administrative log carries the member as the actor — the property 094 called what
    survives."""
    from fastapi.testclient import TestClient

    from carnet import config
    from carnet.api import create_app, deps

    monkeypatch.setattr(config, "OPEN_ADMIN", True)
    app = create_app()
    app.dependency_overrides[deps.principal_from_request] = lambda: user("u-priya")
    client = TestClient(app)

    assert client.get("/me").json()["admin"] is True

    response = client.post("/admin/hosts", json={"host": "mcp.example.net", "note": ""})
    assert response.status_code in (200, 201), response.text

    (record,) = [
        r
        for r in storage.active().admin_audit_records(TEST_TENANT)
        if r["target_id"] == "mcp.example.net"
    ]
    assert (record["actor_kind"], record["actor_id"]) == ("user", "u-priya")

    monkeypatch.setattr(config, "OPEN_ADMIN", False)
    assert client.get("/me").json()["admin"] is False
    assert client.post("/admin/hosts", json={"host": "other.example.net", "note": ""}).status_code == 403


def test_open_admin_refuses_a_value_that_is_neither_on_nor_off(monkeypatch):
    import importlib

    from carnet import config

    monkeypatch.setenv("CARNET_OPEN_ADMIN", "yes")
    with pytest.raises(ValueError) as caught:
        importlib.reload(config)
    assert "CARNET_OPEN_ADMIN must be 'on' or 'off'" in str(caught.value)
    monkeypatch.delenv("CARNET_OPEN_ADMIN")
    importlib.reload(config)
