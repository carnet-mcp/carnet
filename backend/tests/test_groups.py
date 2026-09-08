"""Groups: sharing with "the support team".

The risk step 9a set out to retire is one question — *does the permission check survive
an indirection without becoming two questions?* — so the assertions that matter most here
are not the happy path. They are:

  - `core/permissions.py` is still untouched, asserted by reading its source
  - a group cannot hold a credential, own a run, or appear in an audit record
  - an inherited access cannot be revoked by pretending to revoke a grant

The first two are the ones somebody would quietly undo by widening one constant, which is
why they are asserted here as well as constrained in migration 017.

`test_storage_contract.py` covers what the two stores do with a group. This covers what a
group *means*.
"""

import pathlib

import pytest

from conftest import TEST_ACTOR

from carnet import agents, storage
from carnet.access import grants, groups
from carnet.access.grants import NoAccess, ShareRefused
from carnet.access.groups import GroupRefused
from carnet.access.roles import RoleRequired
from carnet.core import Principal

from conftest import TEST_TENANT


def config(name):
    return {
        "name": name,
        "system": "You are a demo agent.",
        "permissions": {
            "tools": ["post_message"],
            "scope": {"chat.channel": {"write": ["#eng"]}},
        },
    }


def user(id_):
    return Principal.user(id_, TEST_TENANT)


def admin():
    """Group administration is the CLI's, running as a system principal. See
    `access/groups.py` for why that is a placeholder rather than a model."""
    return Principal.system("cli", TEST_TENANT)


@pytest.fixture
def agent(isolated_storage):
    agents.save(TEST_TENANT, config("reporter"), actor="system:cli")
    return "reporter"


@pytest.fixture
def owner(agent):
    storage.active().grant_agent(TEST_TENANT, agent, "user", "u-owner", role="owner", actor="system:cli")
    return user("u-owner")


@pytest.fixture
def support(agent):
    """A group with two members, and no grant on anything yet."""
    group = groups.create(admin(), "support")
    groups.add_member(admin(), group["group_id"], "user", "u-sam")
    groups.add_member(admin(), group["group_id"], "user", "u-priya")
    return group


# --- the done-when list ----------------------------------------------------------------


def test_a_group_grant_reaches_every_member(agent, owner, support):
    """The headline. Two members, one grant, and neither has a row in `agent_grants`."""
    grants.share(owner, agent, "group", support["group_id"], role="user")

    assert grants.check(user("u-sam"), agent) is True
    assert grants.check(user("u-priya"), agent) is True

    written = {
        (g["grantee_kind"], g["grantee_id"])
        for g in storage.active().list_agent_grants(TEST_TENANT, agent)
    }
    assert ("user", "u-sam") not in written
    assert ("user", "u-priya") not in written


def test_removing_somebody_from_a_group_takes_their_access(agent, owner, support):
    """With no grant touched — which is the whole reason to have groups."""
    grants.share(owner, agent, "group", support["group_id"], role="user")
    before = storage.active().list_agent_grants(TEST_TENANT, agent)

    groups.remove_member(admin(), support["group_id"], "user", "u-sam")

    assert grants.check(user("u-sam"), agent) is False
    assert grants.check(user("u-priya"), agent) is True
    assert storage.active().list_agent_grants(TEST_TENANT, agent) == before


def test_deleting_a_group_takes_the_access_with_it(agent, owner, support):
    """By cascade, not by cleanup code. See migration 017's trigger for why a foreign
    key cannot express this."""
    grants.share(owner, agent, "group", support["group_id"], role="user")

    groups.delete(admin(), support["group_id"])

    assert grants.check(user("u-sam"), agent) is False
    # And no row is left behind naming a group that no longer exists — that row would
    # grant nobody anything and look exactly like access.
    assert [
        g
        for g in storage.active().list_agent_grants(TEST_TENANT, agent)
        if g["grantee_kind"] == "group"
    ] == []


def test_highest_wins_when_direct_is_lower(agent, owner, support):
    """Decision 2. The alternative — direct overrides inherited — silently denies
    somebody what the rest of their team has, for a reason invisible in the grant list."""
    grants.share(owner, agent, "group", support["group_id"], role="editor")
    grants.share(owner, agent, "user", "u-sam", role="user")

    assert grants.role_of(user("u-sam"), agent) == "editor"


def test_highest_wins_when_direct_is_higher(agent, owner, support):
    """And the reverse arrangement, because a rule that only holds one way round is a
    coincidence."""
    grants.share(owner, agent, "group", support["group_id"], role="user")
    grants.share(owner, agent, "user", "u-sam", role="editor")

    assert grants.role_of(user("u-sam"), agent) == "editor"


def test_a_group_cannot_be_granted_ownership(agent, owner, support):
    """Refused with a sentence about accountability, not a constraint name.

    **Both entry points**, because they are different code paths and the second one was
    broken. `share` routes an `owner` role to `transfer`, and the CLI calls `transfer`
    directly without going through `share` at all — so a guard that lived only in `share`
    was one every real caller went around, and `--share-agent AGENT group:x --role owner`
    produced a `StorageError` traceback. Found by running the command; the 29 tests in
    this file all called `share`.
    """
    with pytest.raises(ShareRefused, match="cannot own"):
        grants.share(owner, agent, "group", support["group_id"], role="owner")

    with pytest.raises(ShareRefused, match="cannot own"):
        grants.transfer(owner, agent, "group", support["group_id"])

    # And the index that makes "one owner" a property of the data is untouched.
    owners = [
        g
        for g in storage.active().list_agent_grants(TEST_TENANT, agent)
        if g["role"] == "owner"
    ]
    assert [(g["grantee_kind"], g["grantee_id"]) for g in owners] == [("user", "u-owner")]


def test_a_group_cannot_be_a_member_of_a_group(support):
    """Refused by `check_principal_kind`, which has permitted exactly user and system
    since 009 — so nesting costs no new rule and no cycle detection."""
    other = groups.create(admin(), "leads")

    with pytest.raises(GroupRefused, match="principal_kind"):
        groups.add_member(admin(), other["group_id"], "group", support["group_id"])


def test_a_group_cannot_act(isolated_storage, support):
    """**Decision 1, asserted directly.**

    This is the one that would be quietly undone by somebody widening one constant, and
    a test written in the same language as that constant is a weak guard — so migration
    017 puts the same three words into CHECK constraints on all three tables. This
    asserts the Python half; `test_storage_contract.py` asserts it against Postgres.

    A group holding a credential is the precise inversion of step 7a, where a credential
    belongs to one person and is bound to (tenant, principal, connector) as GCM
    additional data.
    """
    store = storage.active()
    gid = support["group_id"]

    with pytest.raises(storage.StorageError, match="never a principal"):
        store.save_connection(
            TEST_TENANT, "group", gid, "github-mcp", ciphertext=b"x", key_id="k1",
            actor=TEST_ACTOR,
        )

    with pytest.raises(storage.StorageError, match="never a principal"):
        store.enqueue_run(
            TEST_TENANT,
            {
                "run_id": "r-1",
                "agent": "reporter",
                "principal_kind": "group",
                "principal_id": gid,
                "task": "t",
            },
        )

    with pytest.raises(storage.StorageError, match="never a principal"):
        store.append_audit(
            TEST_TENANT,
            {
                "v": 1,
                "ts": "2026-01-01T00:00:00Z",
                "run_id": "r-1",
                "principal_kind": "group",
                "principal_id": gid,
                "agent": "reporter",
                "tool": "post_message",
                "effect": "write",
                "args": {},
                "decision": "allow",
            },
        )


def test_unsharing_an_inherited_access_is_refused_and_names_the_group(
    agent, owner, support
):
    """Decision 6, and the same failure 8c's 409 prevents: an interface that reports
    success for an action that did nothing is worse than one that refuses, because the
    person stops looking."""
    grants.share(owner, agent, "group", support["group_id"], role="user")

    with pytest.raises(ShareRefused, match=support["group_id"]):
        grants.unshare(owner, agent, "user", "u-sam")

    # And it changed nothing, which is the property the refusal exists to protect.
    assert grants.check(user("u-sam"), agent) is True


def test_unsharing_a_real_grant_still_works_when_a_group_also_grants(
    agent, owner, support
):
    """The refusal is about *nothing to remove*, not about groups being involved. A
    person with a grant of their own has one to revoke, and revoking it must not be
    refused just because it will not take all their access away."""
    grants.share(owner, agent, "group", support["group_id"], role="user")
    grants.share(owner, agent, "user", "u-sam", role="editor")

    grants.unshare(owner, agent, "user", "u-sam")

    assert grants.role_of(user("u-sam"), agent) == "user"  # what the group gives


def test_unsharing_a_group_is_not_refused(agent, owner, support):
    """The other of the two things an owner can do about an inherited access."""
    grants.share(owner, agent, "group", support["group_id"], role="user")

    grants.unshare(owner, agent, "group", support["group_id"])

    assert grants.check(user("u-sam"), agent) is False


def test_unsharing_somebody_with_no_access_at_all_is_still_idempotent(agent, owner):
    """What is refused above is the case where the access is real and the call would not
    have touched it. Revoking a grant nobody has is what it always was."""
    grants.unshare(owner, agent, "user", "u-nobody")


def test_who_has_access_says_how(agent, owner, support):
    """Decision 5. Without the third column the list is unactionable in the exact
    situation it is read in: an owner sees Sam, removes Sam, and Sam still has access."""
    grants.share(owner, agent, "group", support["group_id"], role="user")
    grants.share(owner, agent, "user", "u-priya", role="editor")

    rows = {(r["kind"], r["id"]): r for r in grants.who_has_access(owner, agent)}

    sam = rows[("user", "u-sam")]
    assert sam["role"] == "user"
    assert sam["direct"] is None
    assert sam["via"] == [support["group_id"]]

    # Priya holds both, so she is ONE row saying both rather than two disagreeing.
    priya = rows[("user", "u-priya")]
    assert priya["role"] == "editor"
    assert priya["direct"] == "editor"
    assert priya["via"] == [support["group_id"]]

    # The group is a row of its own, because revoking its grant is one of the two things
    # an owner can do about an inherited access.
    assert rows[("group", support["group_id"])]["direct"] == "user"

    assert rows[("user", "u-owner")]["via"] == []


def test_an_empty_group_grants_nothing_and_looks_like_access(agent, owner):
    """A stated limit rather than a discovered one, and the same family as a pending
    grant to an address nobody carries."""
    empty = groups.create(admin(), "nobody-yet")
    grants.share(owner, agent, "group", empty["group_id"], role="user")

    rows = grants.who_has_access(owner, agent)

    assert ("group", empty["group_id"]) in {(r["kind"], r["id"]) for r in rows}
    assert [r for r in rows if r["via"]] == []


def test_no_grant_and_no_membership_is_the_same_404(agent, owner, support):
    """The property the whole model rests on, through the group path this time: a
    refusal is indistinguishable from an absence, at every level."""
    grants.share(owner, agent, "group", support["group_id"], role="user")
    stranger = user("u-stranger")

    with pytest.raises(NoAccess) as absent:
        grants.require(stranger, "never-existed")

    with pytest.raises(NoAccess) as refused:
        grants.require(stranger, agent)

    # Not merely both NoAccess — the same sentence, modulo the name asked for.
    assert str(absent.value) == "no agent named 'never-existed'"
    assert str(refused.value) == f"no agent named '{agent}'"


def test_a_member_may_not_share_what_the_group_only_lets_them_run(
    agent, owner, support
):
    """The ladder is not bypassed by the indirection: a group granting `user` gives its
    members `user`, and `user` may not share."""
    grants.share(owner, agent, "group", support["group_id"], role="user")

    with pytest.raises(NoAccess):
        grants.share(user("u-sam"), agent, "user", "u-outsider")


def test_a_group_editor_may_share_it_on(agent, owner, support):
    """And the same indirection carries `editor`'s one live power."""
    grants.share(owner, agent, "group", support["group_id"], role="editor")

    grants.share(user("u-sam"), agent, "user", "u-outsider")

    assert grants.check(user("u-outsider"), agent) is True


def test_granting_a_group_that_does_not_exist_is_refused(agent, owner):
    """No foreign key expresses this — `grantee_id` names a different table depending on
    the column beside it — so both stores check it."""
    with pytest.raises(storage.StorageError, match="no group"):
        grants.share(owner, agent, "group", "g_ghost", role="user")


def test_a_system_principal_may_be_in_a_group(agent, owner):
    """Permitted deliberately: a scheduler belonging to a group is exactly as legitimate
    as a scheduler holding a grant, which migration 009 already argued for."""
    group = groups.create(admin(), "nightly")
    groups.add_member(admin(), group["group_id"], "system", "scheduler")
    grants.share(owner, agent, "group", group["group_id"], role="user")

    assert grants.check(Principal.system("scheduler", TEST_TENANT), agent) is True


# --- administration --------------------------------------------------------------------


def test_only_an_administrator_may_administer_a_group(isolated_storage):
    """The restrictive choice 9a made, now backed by a role rather than by a placeholder.

    It used to raise `GroupRefused` saying *"this platform has no tenant-admin role yet"*.
    It raises `RoleRequired` now — a 403 rather than a 400 — and the reasoning is
    unchanged and still the point: anybody who could add themselves to a group holding an
    `editor` grant would be promoting themselves.
    """
    group = groups.create(admin(), "support")

    with pytest.raises(RoleRequired, match="administrator"):
        groups.create(user("u-1"), "mine")

    with pytest.raises(RoleRequired, match="administrator"):
        groups.add_member(user("u-1"), group["group_id"], "user", "u-1")

    with pytest.raises(RoleRequired, match="administrator"):
        groups.delete(user("u-1"), group["group_id"])


def test_a_person_granted_the_role_may_administer_a_group(isolated_storage):
    """The other half, and the whole point of 12b: the refusal above is now something a
    row can lift, rather than something only a shell can."""
    storage.active().grant_platform_role(
        TEST_TENANT, "user", "u-1", "admin", actor="system:cli"
    )

    group = groups.create(user("u-1"), "support")
    groups.add_member(user("u-1"), group["group_id"], "user", "u-sam")

    assert [m["principal_id"] for m in groups.members(user("u-1"), group["group_id"])] == [
        "u-sam"
    ]


def test_holding_admin_grants_no_access_to_any_agent(isolated_storage):
    """**An admin is not a superuser**, asserted where it would be most tempting to blur.

    `access/grants.py` never consults `platform_roles` and this is what says so. The
    argument is 7b's: an `admin` that implied agent access would rebuild the operator who
    holds everybody's credentials, one grant away.
    """
    agents.save(TEST_TENANT, config("secret-bot"), actor="system:cli")
    storage.active().grant_platform_role(
        TEST_TENANT, "user", "u-1", "admin", actor="system:cli"
    )

    assert grants.check(user("u-1"), "secret-bot") is False

    with pytest.raises(NoAccess):
        grants.require(user("u-1"), "secret-bot")


def test_membership_is_administrators_only_and_the_menu_is_not(support):
    """**This narrowed in 12b, and the reason it could is that nothing had disclosed it.**

    It used to read *"readable by anybody in the tenant"*, on the argument that somebody
    deciding whether to run an agent should see who else can reach it. That argument
    survives and justifies less than it was being used for: it argues for *who will this
    share reach*, which `who_has_access` answers per agent, for an agent you hold a grant
    on. `members` answers *who is in any group you can name*, which is a directory of the
    company.

    `list_groups` is deliberately still open — a name is the menu, membership is the
    directory — and that half is asserted here so narrowing one does not silently narrow
    both.
    """
    with pytest.raises(RoleRequired, match="administrator"):
        groups.members(user("u-nobody"), support["group_id"])

    assert {m["principal_id"] for m in groups.members(admin(), support["group_id"])} == {
        "u-sam",
        "u-priya",
    }

    assert [row["name"] for row in groups.list_groups(user("u-nobody"))] == ["support"]


def test_a_group_is_resolved_by_name_or_by_id(support):
    assert groups.resolve(admin(), "support")["group_id"] == support["group_id"]
    assert groups.resolve(admin(), support["group_id"])["name"] == "support"

    with pytest.raises(GroupRefused, match="no group"):
        groups.resolve(admin(), "finance")


def test_two_groups_may_not_share_a_name(support):
    """A name is how a person picks a group on the command line, so two with one name is
    a command whose meaning depends on insertion order."""
    with pytest.raises(GroupRefused, match="already has a group"):
        groups.create(admin(), "support")


def test_a_renamed_group_keeps_its_grants(agent, owner, support):
    """The id is what a grant records, and it is never derived from the name."""
    grants.share(owner, agent, "group", support["group_id"], role="user")
    store = storage.active()

    # There is no rename command yet; this asserts the property the id buys.
    assert store.get_group(TEST_TENANT, support["group_id"])["name"] == "support"
    assert grants.check(user("u-sam"), agent) is True


def test_adding_a_member_twice_is_idempotent(support):
    groups.add_member(admin(), support["group_id"], "user", "u-sam")

    assert len(groups.members(admin(), support["group_id"])) == 2


def test_removing_somebody_who_was_never_in_it_says_so(support):
    assert groups.remove_member(admin(), support["group_id"], "user", "u-nope") is False


def test_groups_do_not_cross_tenants(agent, owner, support):
    """A group in one customer's tenant grants nothing in another's."""
    other = Principal.user("u-sam", "t-other")
    grants.share(owner, agent, "group", support["group_id"], role="user")

    assert grants.check(other, agent) is False


# --- the layering rule -----------------------------------------------------------------


def test_permissions_still_does_not_know_what_a_user_is():
    """The assertion this step is measured against, and the reason it is repeated here
    rather than left in `test_grants.py`: an indirection is exactly the kind of change
    that gets "just one import" added to the policy engine to make a check convenient.

    If groups had forced identity into `core/permissions.py`, the model would be wrong
    and the right time to find that out was before a UI was built on it.
    """
    import carnet.core.permissions as permissions

    source = pathlib.Path(permissions.__file__).read_text(encoding="utf-8")

    assert "grants" not in source
    assert "group" not in source
    assert "agent_grant" not in source


def test_core_does_not_know_what_a_group_is():
    """`core/` may not learn about groups, for the reason it may not learn about jobs.

    Asserted over the source of every module in `core/`, including lazy imports, which
    is the spelling a string search on the import block would miss.
    """
    import carnet.core as core

    root = pathlib.Path(core.__file__).parent
    offenders = []

    for path in root.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        if "access.groups" in source or "from ..access import groups" in source:
            offenders.append(path.name)

    assert offenders == []


# --- the administrative log --------------------------------------------------------


def test_removing_somebody_from_a_group_records_who_did_it(isolated_storage):
    """The removal with the widest blast radius in this codebase: it takes away every
    access that person had through the group, on every agent, and nothing tells them.
    Before step 011 it was also the one that left no trace of who did it."""
    admin = Principal.system("ops", TEST_TENANT)
    group = groups.create(admin, "oncall")
    groups.add_member(admin, group["group_id"], "user", "u-sam")

    groups.remove_member(admin, group["group_id"], "user", "u-sam")

    (removed,) = storage.active().admin_audit_records(
        TEST_TENANT, action="group.member.remove"
    )
    assert (removed["actor_kind"], removed["actor_id"]) == ("system", "ops")
    assert removed["target_id"] == group["group_id"]
    assert removed["detail"]["member_id"] == "u-sam"


def test_deleting_a_group_records_the_access_that_went_with_it(isolated_storage):
    """The cascade is the consequence, and after it there is nothing left to count."""
    agents.save(TEST_TENANT, config("reporter"), actor="system:cli")
    admin = Principal.system("ops", TEST_TENANT)
    group = groups.create(admin, "oncall")
    groups.add_member(admin, group["group_id"], "user", "u-sam")
    storage.active().grant_agent(
        TEST_TENANT, "reporter", "group", group["group_id"], actor="system:ops"
    )

    groups.delete(admin, group["group_id"])

    (gone,) = storage.active().admin_audit_records(TEST_TENANT, action="group.delete")
    assert gone["actor_id"] == "ops"
    assert gone["detail"] == {"name": "oncall", "members": 1, "grants": 1}


def test_a_personal_token_may_not_be_a_group_member(agent, owner):
    """Step 033d's group seam. A personal token's access is its owner's, including the
    owner's memberships — a membership of the token's own would be the direct-grant
    escalation wearing a group, which is 021's exact lesson. A *service* token stays a
    legitimate member (031's widening, unchanged), which is asserted beside the
    refusal so the seam cannot quietly widen into refusing all machines."""
    from carnet.access import tokens

    personal, _ = tokens.mint(
        TEST_TENANT, "priya-cursor", "u-priya", actor="system:cli", acts_as_owner=True
    )
    service, _ = tokens.mint(TEST_TENANT, "nightly-ci", "u-priya", actor="system:cli")
    group = groups.create(admin(), "eng")
    grants.share(owner, agent, "group", group["group_id"], role="user")

    with pytest.raises(GroupRefused, match="personal token") as caught:
        groups.add_member(admin(), group["group_id"], "machine", personal["id"])
    assert "u-priya" in str(caught.value)

    # The remedy the sentence names, shown to work: add the OWNER, and the token
    # follows through the owner's membership.
    groups.add_member(admin(), group["group_id"], "user", "u-priya")
    assert grants.check(Principal.machine(personal["id"], TEST_TENANT), agent) is True

    groups.add_member(admin(), group["group_id"], "machine", service["id"])
    assert grants.check(Principal.machine(service["id"], TEST_TENANT), agent) is True


def test_reading_who_is_in_a_group_for_a_link_warning_needs_the_role(isolated_storage):
    """`unmanaged_members` returns member rows, and *who is in a group you can name* is
    a directory of the company — the gate `members` has, for the reason `members` gives.

    It was missing, and the rule was being kept by the fact that its only caller runs as
    `system`: a rule enforced by which caller happens to exist rather than by the seam.
    """
    group = groups.create(admin(), "oncall")["group_id"]
    groups.add_member(admin(), group, "user", "u_sam")

    with pytest.raises(RoleRequired):
        groups.unmanaged_members(user("u_nobody"), group)

    assert [
        member["principal_id"] for member in groups.unmanaged_members(admin(), group)
    ] == ["u_sam"]
