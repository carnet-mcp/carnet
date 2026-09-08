"""Directory-backed group membership: the claim, and what is made of it.

Step 033e. Everything here drives `users.resolve` through a **real signed token**, the
way `test_access.py`'s bootstrap tests do, because the whole feature is a side effect of
signing in and a test calling `directory.reconcile` directly would prove nothing about
whether the login path reaches it.

The file is arranged as the decisions were made: what the claim means, what it is refused
for, when the work runs, whose name is on it, and what it must never touch.
"""

import time

import pytest

pytest.importorskip("jwt", reason="install the 'access' extra to run these")

from carnet import storage  # noqa: E402
from carnet.access import directory, grants, groups, users  # noqa: E402
from carnet.core import Principal  # noqa: E402

from test_access import ACME, OKTA_ISSUER, Provider, cache_for, tenants  # noqa: E402,F401

CLI = Principal.system("cli", ACME)


@pytest.fixture
def entra():
    """A provider whose tokens carry a groups claim, registered with one."""
    return Provider(OKTA_ISSUER)


@pytest.fixture
def signed_in(tenants, entra):  # noqa: F811
    """Register the provider, then sign somebody in with whatever claims are asked for."""
    tenants.save_tenant_idp(ACME, entra.row(groups_claim="groups"))

    def sign_in(**claims):
        from carnet.access import providers

        token = entra.token(**claims)
        return users.resolve(*providers.resolve(token, cache_for(entra)))

    return sign_in


def linked(name="eng", external_id="dir-eng"):
    return groups.create(CLI, name, external_id=external_id)["group_id"]


def members_of(group_id):
    return [f"{m['principal_kind']}:{m['principal_id']}" for m in groups.members(CLI, group_id)]


# --- the claim is the membership ----------------------------------------------------


def test_the_claim_places_somebody_in_the_group_it_names(signed_in):
    eng = linked()

    priya = signed_in(groups=["dir-eng"])

    assert members_of(eng) == [f"user:{priya.id}"]


def test_a_group_the_claim_stops_naming_loses_them(signed_in):
    eng = linked()
    ops = linked("ops", "dir-ops")

    priya = signed_in(groups=["dir-eng", "dir-ops"])
    assert members_of(eng) == [f"user:{priya.id}"]
    assert members_of(ops) == [f"user:{priya.id}"]

    signed_in(groups=["dir-ops"])

    assert members_of(eng) == []
    assert members_of(ops) == [f"user:{priya.id}"]


def test_a_hand_made_group_is_never_touched(signed_in):
    """The rule that keeps the two sources of membership from fighting: a group with no
    `external_id` is not the directory's to change, in either direction."""
    eng = linked()
    by_hand = groups.create(CLI, "by-hand")["group_id"]

    priya = signed_in(groups=["dir-eng"])
    groups.add_member(CLI, by_hand, "user", priya.id)

    signed_in(groups=[])

    assert members_of(eng) == [], "the directory's group followed the claim"
    assert members_of(by_hand) == [f"user:{priya.id}"], "the admin's group did not"


def test_an_unmatched_value_creates_nothing_and_says_so(signed_in, caplog):
    """A directory that could mint groups would define this customer's grant targets,
    which inverts who approves what."""
    linked()

    with caplog.at_level("INFO"):
        signed_in(groups=["dir-eng", "dir-nobody-mapped"])

    assert [g["name"] for g in groups.list_groups(CLI)] == ["eng"]
    assert "dir-nobody-mapped" in caplog.text


def test_access_follows_the_claim_in_both_directions(signed_in):
    """The point of the feature, asserted where it is enforced rather than on rows."""
    eng = linked()
    storage.active().save_agent(ACME, {"name": "reporter"}, actor="system:cli")
    storage.active().grant_agent(ACME, "reporter", "group", eng, role="user", actor="system:cli")

    priya = signed_in(groups=["dir-eng"])
    assert grants.runnable_names(priya) == ["reporter"]
    assert grants.role_of(priya, "reporter") == "user"

    signed_in(groups=[])
    assert grants.runnable_names(priya) == []
    assert grants.role_of(priya, "reporter") is None


def test_somebody_created_by_this_request_is_reconciled_before_it_returns(signed_in):
    """A first login must not need a second one: `_first_time` has no marker to read,
    so the reconciliation runs on the request that creates the row."""
    eng = linked()

    priya = signed_in(groups=["dir-eng"])

    assert members_of(eng) == [f"user:{priya.id}"]


def test_only_the_person_signing_in_is_ever_written(signed_in, entra):  # noqa: F811
    """No login writes anybody else's row — which is what keeps this feature out of the
    class of things that can go wrong in bulk."""
    eng = linked()

    sam = signed_in(sub="00u-sam", email="sam@acme.com", groups=["dir-eng"])
    signed_in(groups=[])  # priya, in no directory group

    assert members_of(eng) == [f"user:{sam.id}"]


# --- absence is not emptiness -------------------------------------------------------


def test_a_missing_claim_is_an_empty_membership(signed_in):
    """Okta and Entra both omit the claim for somebody in no matched group, so an
    ordinary absence has to mean what it says or the removal half is unreachable."""
    eng = linked()
    priya = signed_in(groups=["dir-eng"])
    assert members_of(eng) == [f"user:{priya.id}"]

    signed_in()  # no groups claim at all

    assert members_of(eng) == []


def test_an_overage_token_changes_nothing(signed_in, caplog):
    """Entra omits the claim when somebody is in more groups than a token may carry, and
    names it in `_claim_names`. Read as an absence that is a mass revocation."""
    eng = linked()
    priya = signed_in(groups=["dir-eng"])

    with caplog.at_level("ERROR"):
        signed_in(
            _claim_names={"groups": {"essential": True, "source": "src1"}},
            _claim_sources={"src1": {"endpoint": "https://graph.example/…"}},
        )

    assert members_of(eng) == [f"user:{priya.id}"]
    assert "more groups than the token may carry" in caplog.text


def test_claim_names_about_something_else_is_still_an_absence(signed_in):
    """The tell is our claim being named, not the marker being present."""
    eng = linked()
    priya = signed_in(groups=["dir-eng"])
    assert members_of(eng) == [f"user:{priya.id}"]

    signed_in(_claim_names={"roles": {"essential": True, "source": "src1"}})

    assert members_of(eng) == []


# --- the claim is taken whole or not at all -----------------------------------------


@pytest.mark.parametrize(
    "claim,because",
    [
        (["dir-eng"] * (directory.DIRECTORY_GROUPS_MAX + 1), "over the"),
        (["x" * (directory.DIRECTORY_GROUP_ID_MAX + 1)], "characters"),
        ([{"id": "dir-eng"}], "is a string"),
        ({"groups": ["dir-eng"]}, "list of strings"),
        (7, "list of strings"),
    ],
)
def test_a_claim_over_a_bound_reconciles_nothing(signed_in, caplog, claim, because):
    """Every partial reading of this claim is a removal, so nothing is truncated: the
    membership that existed before an unreadable token is the membership after it."""
    eng = linked()
    priya = signed_in(groups=["dir-eng"])

    with caplog.at_level("ERROR"):
        signed_in(groups=claim)

    assert members_of(eng) == [f"user:{priya.id}"]
    assert because in caplog.text


def test_one_string_is_one_value(signed_in):
    """A provider emitting a single group as a bare string, and the thing never done to
    it: split on a separator. `Data Science` is one group."""
    spaced = linked("data science", "Data Science")

    priya = signed_in(groups="Data Science")

    assert members_of(spaced) == [f"user:{priya.id}"]


def test_matching_is_exact(signed_in):
    """Byte for byte, migration 007's rule one column over: case-folding would let two
    distinct directory groups collide into one."""
    eng = linked(external_id="DIR-ENG")

    signed_in(groups=["dir-eng"])

    assert members_of(eng) == []


def test_a_pasted_directory_id_still_matches(signed_in):
    """Stripped where it is written, so the comparison at sign-in never has to guess."""
    eng = groups.create(CLI, "eng")["group_id"]
    groups.link(CLI, eng, "  dir-eng\n")

    priya = signed_in(groups=["dir-eng"])

    assert members_of(eng) == [f"user:{priya.id}"]


# --- when the work runs -------------------------------------------------------------


def counting(monkeypatch):
    """Count the reconciliation's own read, which happens exactly when work happens."""
    store = storage.active()
    calls = []
    original = store.directory_groups

    def counted(tenant_id, user_id):
        calls.append(user_id)
        return original(tenant_id, user_id)

    monkeypatch.setattr(store, "directory_groups", counted)
    return calls


def test_the_same_claim_set_does_no_work_twice(signed_in, monkeypatch):
    """The whole reason there is a marker: `users.resolve` runs on every authenticated
    request, and the claim set is constant for the life of a token."""
    linked()
    signed_in(groups=["dir-eng"])

    calls = counting(monkeypatch)
    signed_in(groups=["dir-eng"])
    signed_in(groups=["dir-eng"])

    assert calls == []


def test_a_changed_claim_set_does(signed_in, monkeypatch):
    linked()
    signed_in(groups=["dir-eng"])

    calls = counting(monkeypatch)
    signed_in(groups=[])

    assert len(calls) == 1


def test_ordering_the_values_differently_is_the_same_claim_set(signed_in, monkeypatch):
    linked()
    linked("ops", "dir-ops")
    signed_in(groups=["dir-eng", "dir-ops"])

    calls = counting(monkeypatch)
    signed_in(groups=["dir-ops", "dir-eng", "dir-ops"])

    assert calls == []


def test_a_provider_with_no_groups_claim_does_nothing_at_all(tenants, entra, monkeypatch):  # noqa: F811
    """Every deployment that has not configured this pays nothing — not a query, not a
    write, not a log line."""
    from carnet.access import providers

    tenants.save_tenant_idp(ACME, entra.row())
    linked()

    calls = counting(monkeypatch)
    users.resolve(*providers.resolve(entra.token(groups=["dir-eng"]), cache_for(entra)))

    assert calls == []
    assert members_of(storage.active().list_groups(ACME)[0]["group_id"]) == []


def test_linking_a_group_makes_the_next_request_reconcile(signed_in, monkeypatch):
    """The marker's other input, invalidated at its own write: *I linked the group, why
    is nobody in it* is answered at their next request rather than at some later time."""
    signed_in(groups=["dir-eng"])

    eng = groups.create(CLI, "eng")["group_id"]
    groups.link(CLI, eng, "dir-eng")

    calls = counting(monkeypatch)
    priya = signed_in(groups=["dir-eng"])

    assert len(calls) == 1
    assert members_of(eng) == [f"user:{priya.id}"]


def test_moving_the_claim_mapping_makes_the_next_request_reconcile(
    signed_in, tenants, entra, monkeypatch  # noqa: F811
):
    """The other half of the marker's input. Narrowed in the edge-case pass to the
    registrations that actually move it: `--add-idp` is an upsert, so a provisioning
    script re-runs it, and clearing every marker in the workspace to rotate a
    `jwks_uri` is the stampede the marker exists to prevent."""
    linked()
    signed_in(groups=["dir-eng"])

    calls = counting(monkeypatch)

    tenants.save_tenant_idp(ACME, entra.row(groups_claim="groups"))
    signed_in(groups=["dir-eng"])
    assert calls == [], "the same registration, twice, is not a change"

    tenants.save_tenant_idp(ACME, entra.row(groups_claim="roles"))
    signed_in(groups=["dir-eng"], roles=["dir-eng"])
    assert len(calls) == 1, "moving the claim is"


def test_an_older_token_does_not_undo_a_newer_one(signed_in, entra, monkeypatch):  # noqa: F811
    """Two live tokens — a tab that has not renewed, and a fresh sign-in — must not make
    somebody's access oscillate with nothing to blame."""
    eng = linked()
    now = int(time.time())

    priya = signed_in(groups=["dir-eng"], iat=now)
    assert members_of(eng) == [f"user:{priya.id}"]

    calls = counting(monkeypatch)
    signed_in(groups=[], iat=now - 600)

    assert calls == [], "the older token was not read at all"
    assert members_of(eng) == [f"user:{priya.id}"]


def test_a_newer_token_is_believed(signed_in, entra):  # noqa: F811
    eng = linked()
    now = int(time.time())

    priya = signed_in(groups=["dir-eng"], iat=now - 600)
    assert members_of(eng) == [f"user:{priya.id}"]

    signed_in(groups=[], iat=now)

    assert members_of(eng) == []


def test_a_token_with_no_iat_still_reconciles(signed_in):
    """`iat` is not required by `oidc.REQUIRED_CLAIMS`, so its absence means *no ordering
    information* rather than *the beginning of time*."""
    eng = linked()

    priya = signed_in(groups=["dir-eng"], iat=None)

    assert members_of(eng) == [f"user:{priya.id}"]


def test_a_failed_reconciliation_is_retried_rather_than_remembered(
    signed_in, monkeypatch
):
    """The marker is written last and only on success, so a partial failure does not
    read as a finished job — and a person can still sign in through one."""
    eng = linked()

    def boom(*args, **kwargs):
        raise RuntimeError("the database went away")

    monkeypatch.setattr(storage.active(), "add_group_member", boom)
    priya = signed_in(groups=["dir-eng"])
    assert members_of(eng) == [], "the write failed"

    monkeypatch.undo()
    signed_in(groups=["dir-eng"])

    assert members_of(eng) == [f"user:{priya.id}"], "and was retried at the next request"


# --- whose name is on the writes ----------------------------------------------------


def test_the_directory_is_the_actor(signed_in, tenants):  # noqa: F811
    """Not the person signing in — the log would read as though they had added
    themselves — and never a machine, which `split_actor` refuses outright."""
    linked()

    priya = signed_in(groups=["dir-eng"])
    signed_in(groups=[])

    records = [
        r
        for r in tenants.admin_audit_records(ACME)
        if r["action"].startswith("group.member.")
    ]
    assert [r["action"] for r in records] == ["group.member.add", "group.member.remove"]
    for record in records:
        assert (record["actor_kind"], record["actor_id"]) == ("system", "directory")
        assert record["detail"]["member_id"] == priya.id


def test_saying_the_same_thing_twice_writes_one_record(signed_in, tenants, entra):  # noqa: F811
    """Inherited from the seam rather than implemented again: `ON CONFLICT DO NOTHING`
    returns no row, and nothing means no record."""
    linked()
    signed_in(groups=["dir-eng"])

    # A different claim set that resolves to the same membership: the digest moves, the
    # rows do not.
    signed_in(groups=["dir-eng", "dir-unmapped"])

    records = [
        r for r in tenants.admin_audit_records(ACME) if r["action"] == "group.member.add"
    ]
    assert len(records) == 1


# --- what it must never touch -------------------------------------------------------


def test_a_system_member_of_a_linked_group_survives(signed_in):
    """The reconciliation writes nobody but the person signing in, so the two sources of
    membership touch disjoint rows — which is why a scheduler in a directory-backed
    group is legitimate rather than an exception."""
    eng = linked()
    groups.add_member(CLI, eng, "system", "nightly")

    signed_in(groups=[])

    assert members_of(eng) == ["system:nightly"]


def test_a_person_may_not_be_hand_added_to_a_linked_group(signed_in):
    """A row added here is deleted at that person's next sign-in, which is a write that
    reports success and quietly does nothing."""
    eng = linked()
    priya = signed_in(groups=[])

    with pytest.raises(groups.GroupRefused, match="follows your directory"):
        groups.add_member(CLI, eng, "user", priya.id)


def test_a_person_may_not_be_hand_removed_from_a_linked_group(signed_in):
    eng = linked()
    priya = signed_in(groups=["dir-eng"])

    with pytest.raises(groups.GroupRefused, match="follows your directory"):
        groups.remove_member(CLI, eng, "user", priya.id)

    assert members_of(eng) == [f"user:{priya.id}"]


def test_unlinking_hands_the_group_back(signed_in):
    """The safe direction: nobody is removed, and the admin owns the membership again."""
    eng = linked()
    priya = signed_in(groups=["dir-eng"])

    groups.link(CLI, eng, None)

    assert members_of(eng) == [f"user:{priya.id}"]
    groups.remove_member(CLI, eng, "user", priya.id)
    assert members_of(eng) == []

    # ...and the directory has stopped speaking for it.
    signed_in(groups=["dir-eng"])
    assert members_of(eng) == []


def test_a_hand_made_group_still_takes_members(signed_in):
    eng = groups.create(CLI, "by-hand")["group_id"]
    priya = signed_in(groups=[])

    groups.add_member(CLI, eng, "user", priya.id)

    assert members_of(eng) == [f"user:{priya.id}"]


# --- what the edge-case pass found -------------------------------------------------
#
# Every test below is a defect that shipped in the first build of this step and was
# caught by driving the login path rather than by reading it. They are grouped so the
# next person can see what this feature's failure modes actually look like: they are
# almost all *a sign-in that keeps working while doing the wrong thing quietly*.


def test_a_claim_value_utf8_cannot_encode_does_not_break_signing_in(signed_in):
    """A lone surrogate — which `json.loads` accepts and UTF-8 cannot encode — used to
    come out of the digest as a `UnicodeEncodeError`, past `users.resolve`, past
    `deps.py`'s three expected exception types, and land as a **500 on every request
    that person made** for as long as the value stood in their directory."""
    eng = linked()

    priya = signed_in(groups=["dir-eng", "\ud800"])

    assert members_of(eng) == [f"user:{priya.id}"]


def test_two_claim_sets_that_differ_only_by_a_separator_are_not_the_same():
    """`["a\nb"]` and `["a", "b"]` are different claim sets, and a digest that joined
    values on a newline said they were the same — so a person moving between them was
    skipped as already reconciled.

    Asserted on the digest rather than through a login, because the *other* half of the
    edge-case pass closed the door this came in through: an `external_id` may no longer
    contain a control character, so no group can be linked to `a\nb` and the two claim
    sets are no longer distinguishable by their outcome. The ambiguity was in the
    encoding, and that is where it is pinned.
    """
    assert directory._digest("groups", frozenset({"a\nb"})) != directory._digest(
        "groups", frozenset({"a", "b"})
    )
    # ...and the claim's *name* cannot bleed into its values either.
    assert directory._digest("groups\nx", frozenset()) != directory._digest(
        "groups", frozenset({"x"})
    )


def test_a_refused_claim_is_complained_about_once_per_claim_set(signed_in, caplog):
    """Entra's group overage is a **steady state** for a large directory, not a
    transient. Logging it per request put tens of thousands of ERROR lines a day in
    front of the one that matters."""
    eng = linked()
    overage = {"_claim_names": {"groups": {"essential": True, "source": "s"}}}

    with caplog.at_level("ERROR"):
        for _ in range(3):
            signed_in(**overage)

    assert caplog.text.count("more groups than the token may carry") == 1

    # ...and the moment the provider is fixed, the input has changed and is read again.
    caplog.clear()
    priya = signed_in(groups=["dir-eng"])
    assert members_of(eng) == [f"user:{priya.id}"]


def test_a_null_claim_is_an_absent_claim(signed_in):
    """Some providers emit `null` where Okta and Entra emit nothing, and both mean *in
    none of them*. Refusing it made the removal half unreachable for those customers."""
    eng = linked()
    priya = signed_in(groups=["dir-eng"])
    assert members_of(eng) == [f"user:{priya.id}"]

    signed_in(groups=None)

    assert members_of(eng) == []


def test_a_null_claim_with_the_overage_marker_is_still_refused(signed_in):
    """...and the withheld check runs first, so the reading above cannot be turned into
    a mass removal by a provider that nulls the claim *and* says it withheld it."""
    eng = linked()
    priya = signed_in(groups=["dir-eng"])

    signed_in(groups=None, _claim_names={"groups": {"essential": True, "source": "s"}})

    assert members_of(eng) == [f"user:{priya.id}"]


def test_removals_are_applied_before_additions(signed_in, monkeypatch):
    """Each seam write is its own transaction, so a failure part-way through leaves
    whatever has been applied. Adding first would leave somebody holding **more** than
    the directory says until the retry; removing first can only leave them holding
    less."""
    eng = linked()
    ops = linked("ops", "dir-ops")

    priya = signed_in(groups=["dir-eng"])
    assert members_of(eng) == [f"user:{priya.id}"]

    def refuse(*args, **kwargs):
        raise RuntimeError("the database went away")

    monkeypatch.setattr(storage.active(), "add_group_member", refuse)
    signed_in(groups=["dir-ops"])

    assert members_of(eng) == [], "the removal went first, so it survived the failure"
    assert members_of(ops) == []


def test_a_numeric_string_iat_still_orders_the_tokens(signed_in):
    """PyJWT validates `iat` by calling `int()` on it, so a provider that quotes its
    numbers verifies — and used to silently disable the staleness guard rather than
    obviously break."""
    eng = linked()
    now = int(time.time())

    priya = signed_in(groups=["dir-eng"], iat=str(now))
    assert members_of(eng) == [f"user:{priya.id}"]

    signed_in(groups=[], iat=str(now - 600))

    assert members_of(eng) == [f"user:{priya.id}"]


def test_linking_a_group_does_not_re_arm_an_older_token(signed_in):
    """Invalidation clears the digest — *what has been done* — and must not clear the
    ordering fact beside it. It did, so linking any unrelated group let one stale tab
    per person put back a membership their newer token had already removed."""
    eng = linked()
    now = int(time.time())

    signed_in(groups=["dir-eng"], iat=now - 600)
    signed_in(groups=[], iat=now)
    assert members_of(eng) == []

    groups.create(CLI, "unrelated", external_id="dir-unrelated")

    signed_in(groups=["dir-eng"], iat=now - 600)

    assert members_of(eng) == [], "the stale tab did not restore what was removed"


def test_a_marker_is_not_written_for_a_group_set_that_moved_under_it(
    signed_in, monkeypatch
):
    """The marker is a compare-and-set. An admin linking a group *while* a
    reconciliation is in flight clears the markers; without the check the in-flight
    request writes one straight back — computed against the group set as it stood
    before the link — and that person never reconciles again, because the digest covers
    the claim and the claim may never change."""
    signed_in(groups=["dir-eng"])

    store = storage.active()
    original = store.directory_groups

    def link_midway(tenant_id, user_id):
        rows = original(tenant_id, user_id)
        # The admin's link lands between the read and the marker write.
        groups.create(CLI, "eng", external_id="dir-eng")
        monkeypatch.setattr(store, "directory_groups", original)
        return rows

    monkeypatch.setattr(store, "directory_groups", link_midway)
    signed_in(groups=["dir-eng", "dir-other"])

    eng = storage.active().find_group_by_name(CLI.tenant_id, "eng")["group_id"]
    assert members_of(eng) == [], "the racing request could not see the new group"

    priya = signed_in(groups=["dir-eng", "dir-other"])
    assert members_of(eng) == [f"user:{priya.id}"], "and the next request picked it up"


def test_a_padded_claim_value_matches_nothing(signed_in):
    """Stated rather than fixed: matching is byte for byte, and the strip happens where
    an `external_id` is **written**. A directory emitting padded values is a directory
    whose people are in no group here, and the log line is the only signal."""
    eng = linked()

    signed_in(groups=[" dir-eng"])

    assert members_of(eng) == []
