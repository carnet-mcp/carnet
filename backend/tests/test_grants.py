"""Sharing: may this person use this agent, and at what level?

The policy half. `test_storage_contract.py` covers what the two stores do with a role;
this covers what the ladder *means* — who may share, who may not, and the property the
whole model rests on: that a refusal is indistinguishable from an absence.

The one assertion that is not about behaviour is at the bottom, and it is the most
important: `core/permissions.py` must not have learned what a user is.
"""

import pytest

from carnet import agents, storage
from carnet.access import grants
from carnet.access.grants import NoAccess, ShareRefused
from carnet.core import Principal

from conftest import TEST_TENANT

OTHER_TENANT = "t-other"


def config(name):
    """The smallest agent that validates. What it does is irrelevant here — every test
    in this file is about who may reach it, not about what it may reach."""
    return {
        "name": name,
        "system": "You are a demo agent.",
        "permissions": {
            "tools": ["post_message"],
            "scope": {"chat.channel": {"write": ["#eng"]}},
        },
    }


@pytest.fixture
def agent(isolated_storage):
    """One valid agent, owned by nobody. Absence is denial, so this is unrunnable."""
    agents.save(TEST_TENANT, config("reporter"), actor="system:cli")
    return "reporter"


def user(id_):
    return Principal.user(id_, TEST_TENANT)


def owner_of(agent_name, principal):
    storage.active().grant_agent(
        TEST_TENANT, agent_name, principal.kind, principal.id, role="owner", actor="system:cli")
    return principal


# --- the ladder ----------------------------------------------------------------------


def test_no_grant_is_no_access(agent):
    """The default state of every agent, and the state migration 011 exists to move
    existing ones out of."""
    assert grants.check(user("u-1"), agent) is False
    assert grants.role_of(user("u-1"), agent) is None


@pytest.mark.parametrize("role", ["user", "editor", "owner"])
def test_every_level_may_run(agent, role):
    """There is deliberately no level that may look but not run. An agent nobody may
    run is a config file."""
    storage.active().grant_agent(TEST_TENANT, agent, "user", "u-1", role=role, actor="system:cli")

    assert grants.check(user("u-1"), agent) is True


def test_the_ladder_is_ordered(agent):
    """Each level contains the one below, so a check is one comparison."""
    storage.active().grant_agent(TEST_TENANT, agent, "user", "u-1", role="editor", actor="system:cli")
    editor = user("u-1")

    assert grants.check(editor, agent, "user") is True
    assert grants.check(editor, agent, "editor") is True
    assert grants.check(editor, agent, "owner") is False


def test_a_typo_in_the_required_level_raises(agent):
    """A check that can never pass is a denial that looks like a policy — the same
    reasoning that makes a malformed scope pattern raise at config load."""
    with pytest.raises(ValueError, match="required must be one of"):
        grants.check(user("u-1"), agent, "administrator")


def test_runnable_names_is_what_this_person_may_run(isolated_storage):
    agents.save(TEST_TENANT, config("alpha"), actor="system:cli")
    agents.save(TEST_TENANT, config("zulu"), actor="system:cli")
    storage.active().grant_agent(TEST_TENANT, "zulu", "user", "u-1", actor="system:cli")

    assert grants.runnable_names(user("u-1")) == ["zulu"]


def test_a_system_principal_is_granted_the_same_way(agent):
    """A scheduler running a customer's nightly job needs the same permission a person
    does, and giving it a special case would be the exception that erodes this."""
    scheduler = Principal.system("scheduler", TEST_TENANT)
    storage.active().grant_agent(TEST_TENANT, agent, "system", "scheduler", actor="system:cli")

    assert grants.check(scheduler, agent) is True
    assert grants.check(user("scheduler"), agent) is False


# --- a refusal looks like an absence --------------------------------------------------


def refusal(principal, agent_name, required="user"):
    with pytest.raises(NoAccess) as raised:
        grants.require(principal, agent_name, required)
    return str(raised.value)


def test_an_ungranted_agent_is_indistinguishable_from_a_missing_one(agent):
    """The property the 404-not-403 rule rests on. If these two ever differ, the API
    leaks which agents exist in a tenant you cannot see.

    Compared for the **same name**, which is the only comparison that means anything —
    two different names giving two different messages is the message doing its job.
    """
    ungranted = refusal(user("u-1"), agent)

    storage.active().delete_agent(TEST_TENANT, agent, actor="system:cli")
    missing = refusal(user("u-1"), agent)

    assert ungranted == missing


def test_too_low_a_level_reads_the_same_as_no_agent_at_all(agent):
    """True at every rung, not just the bottom. Telling somebody "you may run this but
    not edit it" confirms the agent exists."""
    storage.active().grant_agent(TEST_TENANT, agent, "user", "u-1", role="user", actor="system:cli")
    too_low = refusal(user("u-1"), agent, "editor")

    storage.active().delete_agent(TEST_TENANT, agent, actor="system:cli")
    missing = refusal(user("u-1"), agent, "editor")

    assert too_low == missing


def test_a_grant_does_not_cross_tenants(agent):
    """A principal carries its tenant, so the same id in another customer reaches
    nothing — the check never takes a tenant as an argument."""
    storage.active().create_tenant(OTHER_TENANT, "Other")
    storage.active().grant_agent(TEST_TENANT, agent, "user", "u-1", actor="system:cli")

    assert grants.check(Principal.user("u-1", OTHER_TENANT), agent) is False


# --- the denial log's hook (015) ------------------------------------------------------
#
# The hook lives inside `require` and nowhere else, so the CLI and the API — the two
# entry points that share this one seam — cannot disagree about what gets recorded.
# These assert at the seam; the byte-identity of the HTTP responses is test_api.py's.


def test_a_refusal_is_recorded_at_the_seam(agent):
    """One record per refusal, naming who asked, what they asked for, and the level
    the request needed. `held` is `''` — the headline case: no grant at all."""
    with pytest.raises(NoAccess):
        grants.require(user("u-sam"), agent)

    (record,) = storage.active().denial_records(TEST_TENANT)
    assert (record["principal_kind"], record["principal_id"]) == ("user", "u-sam")
    assert (record["resource_kind"], record["resource_id"]) == ("agent", "reporter")
    assert (record["required"], record["held"]) == ("user", "")


def test_too_low_a_level_is_recorded_with_what_was_held(agent):
    """The edge an incident review reads closest: a `user` probing for `editor` reads
    differently from a stranger probing at all, and this pair is what says which."""
    storage.active().grant_agent(TEST_TENANT, agent, "user", "u-1", role="user", actor="system:cli")

    with pytest.raises(NoAccess):
        grants.require(user("u-1"), agent, "editor")

    (record,) = storage.active().denial_records(TEST_TENANT)
    assert (record["required"], record["held"]) == ("editor", "user")


def test_an_absent_agent_leaves_the_same_shaped_record(agent):
    """Finding 4: `require` does not know whether the agent exists and must not learn —
    the record says what was asked and by whom, existence unrecorded."""
    with pytest.raises(NoAccess):
        grants.require(user("u-1"), "no-such-agent")

    (record,) = storage.active().denial_records(TEST_TENANT)
    assert (record["resource_kind"], record["resource_id"]) == ("agent", "no-such-agent")
    assert record["held"] == ""


def test_a_typoed_level_is_a_programmer_error_not_an_attempt(agent):
    with pytest.raises(ValueError):
        grants.require(user("u-1"), agent, "adminz")

    assert storage.active().denial_records(TEST_TENANT) == []


def test_check_records_nothing(agent):
    """Decision 4's line: `require` is called when somebody asked to act on a named
    thing; `check` is called when the system decides what to show. Only the first is
    an attempt, and logging every filtered row would bury the attempts under the
    renders."""
    assert grants.check(user("u-1"), agent) is False

    assert storage.active().denial_records(TEST_TENANT) == []


def test_an_allowed_call_records_nothing(agent):
    owner_of(agent, user("u-1"))

    grants.require(user("u-1"), agent)

    assert storage.active().denial_records(TEST_TENANT) == []


def test_a_failing_append_never_changes_the_refusal(agent, monkeypatch, caplog):
    """Decision 3: the refusal is the security behavior, the record is evidence, and
    `runs._finish` is the precedent — log the exception, swallow it, serve the
    refusal. Asserted on the exact message, because the equality is the property."""
    def boom(*_args, **_kwargs):
        raise RuntimeError("denial store down")

    monkeypatch.setattr(storage.active(), "record_denial", boom)

    with caplog.at_level("ERROR", logger="carnet.access.denials"):
        with pytest.raises(NoAccess, match="no agent named 'reporter'"):
            grants.require(user("u-1"), agent)

    assert "could not record the denial" in caplog.text


# --- who may share --------------------------------------------------------------------


def test_an_owner_may_share(agent):
    owner = owner_of(agent, user("u-1"))

    grants.share(owner, agent, "user", "u-2")

    assert grants.check(user("u-2"), agent) is True


def test_an_editor_may_share_it_on(agent):
    """The Google Docs rule, and the reason it was asked for. Access fans out without
    the owner being told, which is the cost of this model, accepted knowingly."""
    owner_of(agent, user("u-1"))
    storage.active().grant_agent(TEST_TENANT, agent, "user", "u-2", role="editor", actor="system:cli")

    grants.share(user("u-2"), agent, "user", "u-3")

    assert grants.check(user("u-3"), agent) is True


def test_a_user_may_not_share(agent):
    owner_of(agent, user("u-1"))
    storage.active().grant_agent(TEST_TENANT, agent, "user", "u-2", role="user", actor="system:cli")

    with pytest.raises(NoAccess):
        grants.share(user("u-2"), agent, "user", "u-3")

    assert grants.check(user("u-3"), agent) is False


def test_a_stranger_may_not_share(agent):
    """And the refusal says nothing about the agent existing."""
    owner_of(agent, user("u-1"))

    with pytest.raises(NoAccess, match="no agent named"):
        grants.share(user("nobody"), agent, "user", "u-3")


def test_sharing_records_who_did_it(agent):
    owner = owner_of(agent, user("u-1"))

    grants.share(owner, agent, "user", "u-2")

    by_principal = {g["id"]: g for g in grants.who_has_access(owner, agent)}
    assert by_principal["u-2"]["granted_by"] == "user:u-1"


# --- taking access away ---------------------------------------------------------------


def test_an_editor_may_unshare(agent):
    owner = owner_of(agent, user("u-1"))
    grants.share(owner, agent, "user", "u-2")

    grants.unshare(owner, agent, "user", "u-2")

    assert grants.check(user("u-2"), agent) is False


def test_nobody_may_unshare_the_owner(agent):
    """An editor who may orphan an agent may take it from the person who made it."""
    owner = owner_of(agent, user("u-1"))
    grants.share(owner, agent, "user", "u-2", role="editor")

    with pytest.raises(NoAccess, match="owns"):
        grants.unshare(user("u-2"), agent, "user", "u-1")

    assert grants.role_of(user("u-1"), agent) == "owner"


def test_an_owner_may_not_unshare_themselves(agent):
    """Same rule, and it applies to the owner too — leaving is a transfer."""
    owner = owner_of(agent, user("u-1"))

    with pytest.raises(NoAccess, match="owns"):
        grants.unshare(owner, agent, "user", "u-1")


def test_a_user_may_not_unshare(agent):
    owner = owner_of(agent, user("u-1"))
    grants.share(owner, agent, "user", "u-2", role="user")

    with pytest.raises(NoAccess):
        grants.unshare(user("u-2"), agent, "user", "u-1")


# --- transfer -------------------------------------------------------------------------


def test_an_owner_may_transfer(agent):
    owner = owner_of(agent, user("u-1"))

    grants.transfer(owner, agent, "user", "u-2")

    assert grants.role_of(user("u-2"), agent) == "owner"
    assert grants.role_of(user("u-1"), agent) == "editor"


def test_an_editor_may_not_transfer(agent):
    owner_of(agent, user("u-1"))
    storage.active().grant_agent(TEST_TENANT, agent, "user", "u-2", role="editor", actor="system:cli")

    with pytest.raises(NoAccess):
        grants.transfer(user("u-2"), agent, "user", "u-2")

    assert grants.role_of(user("u-1"), agent) == "owner"


def test_sharing_ownership_is_a_transfer(agent):
    """`share(..., role="owner")` routes to `transfer` rather than being refused, so
    there is one path to one outcome — and it therefore needs owner, not editor."""
    owner = owner_of(agent, user("u-1"))
    grants.share(owner, agent, "user", "u-2", role="editor")

    with pytest.raises(NoAccess):
        grants.share(user("u-2"), agent, "user", "u-3", role="owner")

    grants.share(owner, agent, "user", "u-3", role="owner")
    assert grants.role_of(user("u-3"), agent) == "owner"
    assert grants.role_of(user("u-1"), agent) == "editor"


# --- seeding --------------------------------------------------------------------------


def test_seeding_gives_the_shipped_agents_an_owner(isolated_storage):
    """The in-memory half of migration 011. A fresh clone whose seeded agents nobody
    could run would be a clone that does not work."""
    from carnet import bootstrap

    bootstrap.seed_tenant(TEST_TENANT)

    cli = Principal.system("cli", TEST_TENANT)
    assert grants.role_of(cli, "issue-reporter") == "owner"


def test_re_seeding_does_not_wrench_back_a_transferred_agent(isolated_storage):
    """`--seed` is documented as safe to re-run against a store that already has
    customer data. Quietly reversing a transfer is not safe."""
    from carnet import bootstrap

    bootstrap.seed_tenant(TEST_TENANT)
    cli = Principal.system("cli", TEST_TENANT)
    grants.transfer(cli, "issue-reporter", "user", "u-1")

    bootstrap.seed_tenant(TEST_TENANT)

    assert grants.role_of(user("u-1"), "issue-reporter") == "owner"


# --- the layering rule ----------------------------------------------------------------


def test_permissions_still_does_not_know_what_a_user_is():
    """The assertion this whole step is measured against.

    `core/permissions.py` answers "may this AGENT do this thing?" and has gone six steps
    without learning who is asking. Sharing answers "may this PERSON use this agent?",
    once, before a run exists. If the second question ever moves into that module the
    two have merged, and a grant check on every tool call is a policy engine that needs
    an identity model.

    Asserted against the source rather than by behaviour, because the failure mode is a
    helpful import somebody adds without noticing what it costs.
    """
    import pathlib

    import carnet.core.permissions as permissions

    source = pathlib.Path(permissions.__file__).read_text(encoding="utf-8")

    assert "grants" not in source
    assert "agent_grant" not in source


# --- sharing by email -----------------------------------------------------------------
#
# The interface a person actually wanted: type an address, that person has access. The
# gap it has to close is that a `users` row is keyed (issuer, subject) and a subject only
# arrives inside a token, so there is no principal to name until a first login.


@pytest.fixture
def provider(isolated_storage):
    """A registered provider for the test tenant, vouching for acme.com."""
    storage.active().save_tenant_idp(
        TEST_TENANT,
        {
            "issuer": "https://acme.okta.example",
            "jwks_uri": "https://acme.okta.example/keys",
            "audience": "api://default",
            "allowed_domains": ("acme.com",),
        },
    )


@pytest.fixture
def wildcard_provider(isolated_storage):
    """The local identity provider's row: `allowed_domains = ("*",)`.

    The shape `--local` writes, and the one no test in this file ever had — which is how
    share-by-email came to refuse every address on that deployment without anything going
    red.
    """
    storage.active().save_tenant_idp(
        TEST_TENANT,
        {
            "issuer": storage.LOCAL_ISSUER_WILDCARD_OK,
            "jwks_uri": "http://127.0.0.1:7300/idp/v1/keys",
            "audience": storage.LOCAL_ISSUER_WILDCARD_OK,
            "allowed_domains": ("*",),
        },
    )


def a_user(user_id, email):
    storage.active().create_user(
        TEST_TENANT,
        {
            "id": user_id,
            "issuer": "https://acme.okta.example",
            "subject": user_id,
            "email": email,
        },
    )
    return Principal.user(user_id, TEST_TENANT)


def test_sharing_with_somebody_who_exists_grants_immediately(agent, provider):
    owner = owner_of(agent, user("u-1"))
    priya = a_user("u-priya", "priya@acme.com")

    assert grants.share_by_email(owner, agent, "priya@acme.com") == "granted"
    assert grants.check(priya, agent) is True


def test_a_wildcard_provider_can_share_with_any_address(agent, wildcard_provider):
    """The defect this fixture exists for.

    `_check_domain` built the allowed set and asked `domain not in allowed`. Against
    `{"*"}` that is false for every address on earth, so sharing refused everybody on the
    one deployment shape the local provider produces — fail-closed, and invisible, because
    nothing here had ever shared an agent under a wildcard row.

    Two readers of one rule and only the edited one learned it: `users._first_time`
    honoured the wildcard from the day it was added, and this function did not.
    """
    owner = owner_of(agent, user("u-1"))

    assert grants.share_by_email(owner, agent, "friend@gmail.example") == "pending"

    waiting = grants.who_is_waiting(owner, agent)
    assert [w["email"] for w in waiting] == ["friend@gmail.example"]


def test_a_wildcard_provider_still_refuses_a_non_address(agent, wildcard_provider):
    """The mutation check on the branch above: it returns early, so whatever refuses a
    non-address has to sit upstream of it rather than in the code it skipped.

    It does — `share_by_email` normalizes and rejects anything without an `@` before
    `_check_domain` is reached at all, which is why the wildcard branch has nothing left
    to check and can say so.
    """
    owner = owner_of(agent, user("u-1"))

    with pytest.raises(ValueError, match="is not an email address"):
        grants.share_by_email(owner, agent, "not-an-address")


def test_sharing_with_somebody_who_has_never_logged_in_waits(agent, provider):
    owner = owner_of(agent, user("u-1"))

    assert grants.share_by_email(owner, agent, "newhire@acme.com") == "pending"

    waiting = grants.who_is_waiting(owner, agent)
    assert [(w["email"], w["role"]) for w in waiting] == [("newhire@acme.com", "user")]


def test_a_pending_grant_lands_at_first_login(agent, provider):
    """The moment the chunk exists for. Nothing about the person is known at share
    time except the address they will one day arrive with."""
    owner = owner_of(agent, user("u-1"))
    grants.share_by_email(owner, agent, "newhire@acme.com", role="editor")

    newhire = a_user("u-new", "newhire@acme.com")
    claimed = grants.claim_for(newhire, "newhire@acme.com")

    assert claimed == [agent]
    assert grants.role_of(newhire, agent) == "editor"
    assert grants.who_is_waiting(owner, agent) == []


def test_the_sharer_cannot_tell_which_path_ran(agent, provider):
    """Both outcomes are a share. The return value exists so the CLI can say something
    true afterwards, not so a caller can branch on it."""
    owner = owner_of(agent, user("u-1"))
    a_user("u-priya", "priya@acme.com")

    assert grants.share_by_email(owner, agent, "priya@acme.com") == "granted"
    assert grants.share_by_email(owner, agent, "other@acme.com") == "pending"


def test_sharing_by_email_still_needs_editor(agent, provider):
    owner_of(agent, user("u-1"))
    storage.active().grant_agent(TEST_TENANT, agent, "user", "u-2", role="user", actor="system:cli")

    with pytest.raises(NoAccess):
        grants.share_by_email(user("u-2"), agent, "newhire@acme.com")


def test_case_does_not_matter(agent, provider):
    """Somebody types a colleague's address the way it appears in their contacts."""
    owner = owner_of(agent, user("u-1"))
    grants.share_by_email(owner, agent, "  NewHire@Acme.COM ")

    newhire = a_user("u-new", "newhire@acme.com")
    assert grants.claim_for(newhire, "NEWHIRE@acme.com") == [agent]


def test_a_domain_no_provider_vouches_for_is_refused(agent, provider):
    """**The one place this deliberately does not behave like a Google Doc.** Docs lets
    you share with any address on earth; here that address names somebody who can never
    authenticate into this tenant, so the grant is either inert forever or the first
    half of a route across the tenant boundary."""
    owner = owner_of(agent, user("u-1"))

    with pytest.raises(ShareRefused, match="could never log in"):
        grants.share_by_email(owner, agent, "someone@evil.example")

    assert grants.who_is_waiting(owner, agent) == []


def test_a_tenant_with_no_vouchable_domains_refuses_loudly(agent, isolated_storage):
    """An empty allowed-domain list is not "allow everything" — it creates nobody, so a
    pending grant against it could never be claimed."""
    owner = owner_of(agent, user("u-1"))

    with pytest.raises(ShareRefused, match="may vouch for anybody"):
        grants.share_by_email(owner, agent, "priya@acme.com")


def test_an_existing_user_off_a_vouchable_domain_is_still_shareable(agent, provider):
    """The domain gate exists to stop a grant that can never be claimed. Somebody who
    already has a row here has already been vouched for, whatever their address."""
    owner = owner_of(agent, user("u-1"))
    contractor = a_user("u-c", "contractor@partner.example")

    assert grants.share_by_email(owner, agent, "contractor@partner.example") == "granted"
    assert grants.check(contractor, agent) is True


def test_something_that_is_not_an_address_is_refused(agent, provider):
    owner = owner_of(agent, user("u-1"))

    with pytest.raises(ValueError, match="not an email address"):
        grants.share_by_email(owner, agent, "u_8f2c1a")


def test_a_pending_grant_can_be_cancelled_before_it_lands(agent, provider):
    owner = owner_of(agent, user("u-1"))
    grants.share_by_email(owner, agent, "newhire@acme.com")

    assert grants.unshare_email(owner, agent, "newhire@acme.com") == "cancelled"

    newhire = a_user("u-new", "newhire@acme.com")
    assert grants.claim_for(newhire, "newhire@acme.com") == []
    assert grants.check(newhire, agent) is False


def test_revoking_by_email_clears_a_pending_row_too(agent, provider):
    """Somebody can hold both: shared before they logged in, then again after. A revoke
    that left the pending row armed would silently restore access at their next login
    with a changed address."""
    owner = owner_of(agent, user("u-1"))
    priya = a_user("u-priya", "priya@acme.com")
    grants.share_by_email(owner, agent, "priya@acme.com")
    storage.active().add_pending_grant(TEST_TENANT, agent, "priya@acme.com", actor="system:cli")

    assert grants.unshare_email(owner, agent, "priya@acme.com") == "revoked"

    assert grants.check(priya, agent) is False
    assert grants.who_is_waiting(owner, agent) == []


def test_waiting_addresses_are_not_reported_as_access(agent, provider):
    """Separate lists, because they are different facts: nobody has this access,
    somebody *will* if a person ever arrives at that address."""
    owner = owner_of(agent, user("u-1"))
    grants.share_by_email(owner, agent, "newhire@acme.com")

    holders = {g["id"] for g in grants.who_has_access(owner, agent)}
    assert "newhire@acme.com" not in holders
    assert holders == {"u-1"}


def test_a_refused_share_is_not_a_refused_caller(agent, provider):
    """The distinction a real run against Postgres forced, after the CLI told an
    operator who **owned** the agent that it had not been shared with them.

    `NoAccess` and `ShareRefused` say opposite things about the caller, so they must not
    be the same exception: one means "you may not touch this, and it may not exist", the
    other means "you may share this, and this particular share is bad". The second is
    safe to explain — the caller has already proved `editor` — and behind a share
    endpoint it is a 400, never a 404.
    """
    owner = owner_of(agent, user("u-1"))

    with pytest.raises(ShareRefused):
        grants.share_by_email(owner, agent, "someone@evil.example")

    # And the caller's own access is untouched by that refusal.
    assert grants.role_of(owner, agent) == "owner"
    assert not isinstance(ShareRefused("x"), NoAccess)


# --- the administrative log, from this altitude ---------------------------------------
#
# `test_storage_contract.py` asserts that storage writes a record. These assert that the
# *access layer* hands it a real person — which is the half a storage test cannot see,
# and the half that broke in 9a when a guard lived only on the path nobody took.


def test_unsharing_records_who_did_it(agent, isolated_storage):
    """The question that had no answer before step 011, asked through the door a person
    actually uses rather than through storage directly."""
    priya = owner_of(agent, user("u-priya"))
    grants.share(priya, agent, "user", "u-sam", role="editor")

    grants.unshare(priya, agent, "user", "u-sam")

    (revoked,) = storage.active().admin_audit_records(
        TEST_TENANT, action="grant.revoke"
    )
    assert (revoked["actor_kind"], revoked["actor_id"]) == ("user", "u-priya")
    assert revoked["detail"]["grantee_id"] == "u-sam"
    assert revoked["detail"]["role"] == "editor"


def test_cancelling_an_invitation_records_who_cancelled_it(agent, provider):
    """A pending grant is the one revocation with no principal on either side of it —
    the grantee is an address — so the actor is the only name in the record."""
    priya = owner_of(agent, user("u-priya"))
    grants.share_by_email(priya, agent, "newhire@acme.com")

    grants.unshare_email(priya, agent, "newhire@acme.com")

    (cancelled,) = storage.active().admin_audit_records(
        TEST_TENANT, action="grant.pending.delete"
    )
    assert cancelled["actor_id"] == "u-priya"
    assert cancelled["detail"]["email"] == "newhire@acme.com"


def test_revoking_a_real_grant_does_not_also_log_a_cancellation(agent, provider):
    """`unshare_email` clears any pending row on both of its branches, so a record
    written unconditionally would report an invitation cancelled every time somebody
    revoked an ordinary grant. Storage records only what it actually removed."""
    priya = owner_of(agent, user("u-priya"))
    storage.active().create_user(
        TEST_TENANT,
        {"id": "u-sam", "issuer": "https://idp.example", "subject": "sam",
         "email": "sam@acme.com"},
    )
    grants.share_by_email(priya, agent, "sam@acme.com")

    grants.unshare_email(priya, agent, "sam@acme.com")

    assert storage.active().admin_audit_records(
        TEST_TENANT, action="grant.pending.delete"
    ) == []
    assert len(storage.active().admin_audit_records(
        TEST_TENANT, action="grant.revoke"
    )) == 1


# --- personal tokens (033d): a cap, never a grant --------------------------------------
#
# A personal token resolves access through its owner — the owner's direct grants and
# group memberships, still capped at `user` — and may hold no access of its own. The
# control is construction, not a filter: `role_of` and `runnable_names` query as the
# owner, so rows naming the token never enter the statement. The seam refusals in
# `share` and `groups.add_member` are the courtesy on top; the smuggling tests below
# are what prove the courtesy is not the control.


def _mint(name, owner_id, *, personal):
    from carnet.access import tokens

    row, _ = tokens.mint(
        TEST_TENANT, name, owner_id, actor="system:cli", acts_as_owner=personal
    )
    return Principal.machine(row["id"], TEST_TENANT)


def test_a_personal_token_holds_its_owners_access(agent):
    """The headline: the owner's grant is the token's access, and somebody else's
    owner is not."""
    storage.active().grant_agent(TEST_TENANT, agent, "user", "u-priya", actor="system:cli")
    priyas = _mint("priya-cursor", "u-priya", personal=True)
    sams = _mint("sam-cursor", "u-sam", personal=True)

    assert grants.role_of(priyas, agent) == "user"
    assert grants.runnable_names(priyas) == [agent]
    assert grants.role_of(sams, agent) is None
    assert grants.runnable_names(sams) == []


def test_a_service_token_still_holds_only_its_own_grants(agent):
    """020's shape, untouched: the default kind ignores its owner's access entirely."""
    storage.active().grant_agent(TEST_TENANT, agent, "user", "u-priya", actor="system:cli")

    assert grants.role_of(_mint("nightly-ci", "u-priya", personal=False), agent) is None


def test_the_machine_ceiling_caps_what_the_owner_holds(agent):
    """The owner OWNS the agent; their token may only run it. The cap applies to the
    owner's answer because the caller is a machine — editing and sharing are human
    acts, and a personal token cannot make a machine a person any more than a group
    could (021's lesson, at the redirection this chunk adds)."""
    owner_of(agent, user("u-priya"))
    priyas = _mint("priya-cursor", "u-priya", personal=True)

    assert grants.role_of(priyas, agent) == "user"
    assert grants.check(priyas, agent, "editor") is False
    assert grants.check(priyas, agent) is True


def test_the_owners_group_membership_reaches_a_personal_token(agent):
    """The point of the feature: Priya joins eng, and her editor follows — no admin
    action on the token, ever."""
    from carnet.access import groups

    eng = groups.create(Principal.system("cli", TEST_TENANT), "eng")
    storage.active().grant_agent(
        TEST_TENANT, agent, "group", eng["group_id"], actor="system:cli"
    )
    priyas = _mint("priya-cursor", "u-priya", personal=True)
    assert grants.role_of(priyas, agent) is None

    groups.add_member(
        Principal.system("cli", TEST_TENANT), eng["group_id"], "user", "u-priya"
    )

    assert grants.role_of(priyas, agent) == "user"


def test_losing_a_grant_loses_it_through_every_token_the_owner_holds(agent):
    """Nothing is cached: the next resolution reads the live rows, so revoking the
    owner revokes the tokens in the same moment."""
    storage.active().grant_agent(TEST_TENANT, agent, "user", "u-priya", actor="system:cli")
    priyas = _mint("priya-cursor", "u-priya", personal=True)
    also = _mint("priya-laptop", "u-priya", personal=True)
    assert grants.check(priyas, agent) and grants.check(also, agent)

    storage.active().revoke_agent(
        TEST_TENANT, agent, "user", "u-priya", actor="system:cli"
    )

    assert grants.role_of(priyas, agent) is None
    assert grants.role_of(also, agent) is None
    assert grants.runnable_names(priyas) == []


def test_sharing_with_a_personal_token_is_refused_naming_the_owner(agent):
    """A grant to a personal token could only report success and change nothing, or —
    honoured — hand the token something its owner lacks. `ShareRefused`, because the
    sharer has proved editor and the sentence can safely say what to do instead. A
    service token stays grantable, which is the whole of 020."""
    priya = owner_of(agent, user("u-priya"))
    personal = _mint("sam-cursor", "u-sam", personal=True)
    service = _mint("nightly-ci", "u-sam", personal=False)

    with pytest.raises(ShareRefused, match="personal token") as caught:
        grants.share(priya, agent, "machine", personal.id)
    assert "u-sam" in str(caught.value)

    grants.share(priya, agent, "machine", service.id)
    assert grants.role_of(service, agent) == "user"


def test_a_smuggled_grant_row_is_inert(agent):
    """The seam is the courtesy; this is the control. A row written past `share` —
    direct SQL, a future seam that forgets — confers nothing, because resolution
    queries as the owner and machine rows never enter the statement."""
    priyas = _mint("priya-cursor", "u-priya", personal=True)
    storage.active().grant_agent(
        TEST_TENANT, agent, "machine", priyas.id, actor="system:cli"
    )

    assert grants.role_of(priyas, agent) is None
    assert grants.runnable_names(priyas) == []
    assert grants.check(priyas, agent) is False


def test_a_smuggled_membership_is_inert(agent):
    """The group half of the same control: a personal token placed in a granted group
    by hand gains nothing — only the OWNER's memberships are consulted, so there is no
    union to compute."""
    from carnet.access import groups

    eng = groups.create(Principal.system("cli", TEST_TENANT), "eng")
    storage.active().grant_agent(
        TEST_TENANT, agent, "group", eng["group_id"], actor="system:cli"
    )
    priyas = _mint("priya-cursor", "u-priya", personal=True)
    storage.active().add_group_member(
        TEST_TENANT,
        eng["group_id"],
        "machine",
        priyas.id,
        added_by="system:cli",
        actor="system:cli",
    )

    assert grants.role_of(priyas, agent) is None
    assert grants.runnable_names(priyas) == []


def test_a_foreign_tenants_token_id_does_not_redirect(agent):
    """`find_api_token` is tenantless by design, so the redirect checks the row's
    tenant against the principal's — a mismatched pair falls back to the machine's own
    (empty) rows rather than reading an owner across the boundary."""
    from carnet.access import tokens

    storage.active().create_tenant(OTHER_TENANT, "Other")
    row, _ = tokens.mint(
        OTHER_TENANT, "priya-cursor", "u-priya", actor="system:cli", acts_as_owner=True
    )
    storage.active().grant_agent(TEST_TENANT, agent, "user", "u-priya", actor="system:cli")

    crossed = Principal.machine(row["id"], TEST_TENANT)

    assert grants.role_of(crossed, agent) is None
    assert grants.runnable_names(crossed) == []


def test_an_admin_owner_confers_no_administration(agent):
    """The 020 tripwire family's sibling, at the redirection: admin powers are not
    grant rows, so a personal token owned by an administrator resolves the admin's
    *grants* and none of their authority. Editing `role_of` is precisely where 021
    says this could have leaked, which is why it is pinned here."""
    from carnet.access import roles

    storage.active().grant_platform_role(
        TEST_TENANT, "user", "u-priya", "admin", actor="system:cli"
    )
    priyas = _mint("priya-cursor", "u-priya", personal=True)

    assert roles.is_admin(priyas) is False
    with pytest.raises(roles.RoleRequired):
        roles.require_admin(priyas)
