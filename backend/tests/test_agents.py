"""Agent configs as data: the write path, the load path, and what a bad row does.

Validation used to run at import, so its only test was that the process started. Now
it runs at write time and again at load time, and both paths get exercised here.

The distinction these tests are really about:

    write time   an invalid config never becomes a row
    load time    a row that has *become* invalid never becomes a run

The second exists because the first is not enough. A config referencing
`github_mcp_list_issues` is valid the day it is saved and dangling the day someone
removes that connector, and nothing about the agent row changed in between.
"""

import logging
from unittest.mock import patch

import pytest

from carnet import agents, bootstrap, storage
from carnet.agents import InvalidAgentError
from carnet.storage import AgentNameTaken

from conftest import TEST_TENANT

OTHER_TENANT = "t-other"


def agent(**overrides) -> dict:
    config = {
        "name": "test-agent",
        "runtime": "simple",
        "system": "irrelevant",
        "permissions": {
            "tools": ["post_message"],
            "scope": {"chat.channel": {"write": ["#eng"]}},
        },
    }
    config.update(overrides)
    return config


def permissions(**overrides) -> dict:
    base = {"tools": ["post_message"], "scope": {"chat.channel": {"write": ["#eng"]}}}
    base.update(overrides)
    return {"permissions": base}


# --- validation: capability -----------------------------------------------------


def test_a_well_formed_agent_validates():
    agents.validate(TEST_TENANT, agent())


def test_missing_tools_list_is_refused():
    """The pre-migration shape. Treating it as 'no tools granted' would be safe and
    completely baffling."""
    with pytest.raises(InvalidAgentError, match="no 'tools' list"):
        agents.validate(TEST_TENANT, agent(permissions={"scope": {}}))


def test_tools_must_be_a_list():
    with pytest.raises(InvalidAgentError, match="must be a list"):
        agents.validate(TEST_TENANT, agent(**permissions(tools="post_message")))


def test_an_unknown_tool_name_is_refused():
    """A typo'd grant is a permission that silently never applies."""
    with pytest.raises(InvalidAgentError, match="not a registered tool"):
        agents.validate(TEST_TENANT, agent(**permissions(tools=["post_mesage"])))


def test_a_vetted_but_unconnected_connector_tool_is_accepted(vetted_github):
    """Validated against every name the tenant knows, not just the bound ones —
    granting an MCP tool is legitimate before anyone has connected to its server."""
    agents.validate(
        TEST_TENANT,
        agent(
            **permissions(
                tools=["github_mcp_list_issues"],
                scope={"github.repo": {"read": ["anthropics/*"]}},
            )
        ),
    )


# --- validation: reach ----------------------------------------------------------


def test_an_unknown_effect_is_refused():
    with pytest.raises(InvalidAgentError, match="expected 'read' or 'write'"):
        agents.validate(
            TEST_TENANT,
            agent(**permissions(scope={"chat.channel": {"delete": ["#eng"]}})),
        )


def test_a_malformed_pattern_is_refused():
    """A pattern that can never match is a policy that denies everything — safe, and
    baffling at 3am."""
    with pytest.raises(InvalidAgentError, match="bad pattern"):
        agents.validate(
            TEST_TENANT,
            agent(**permissions(scope={"chat.channel": {"write": ["#eng/**/x"]}})),
        )


def test_a_granted_tool_with_no_matching_grant_is_refused():
    """Every call to it would be denied. The agent reads as capable and isn't."""
    with pytest.raises(InvalidAgentError, match="Every call to them would be denied"):
        agents.validate(TEST_TENANT, agent(**permissions(scope={})))


def test_a_grant_no_granted_tool_can_use_is_refused():
    """The visible half of a misspelled resource type."""
    with pytest.raises(InvalidAgentError, match="none of its granted tools touch"):
        agents.validate(
            TEST_TENANT,
            agent(
                **permissions(
                    scope={
                        "chat.channel": {"write": ["#eng"]},
                        "github.repos": {"read": ["anthropics/*"]},
                    }
                )
            ),
        )


# --- validation: limits ---------------------------------------------------------


def test_an_unknown_limit_key_is_refused():
    """A typo'd dial leaves the real one on its default — capped in review, uncapped
    in fact."""
    with pytest.raises(InvalidAgentError, match="unknown limit"):
        agents.validate(TEST_TENANT, agent(limits={"max_write": 0}))


def test_a_negative_limit_is_refused():
    with pytest.raises(InvalidAgentError, match="non-negative integer"):
        agents.validate(TEST_TENANT, agent(limits={"max_writes": -1}))


def test_zero_is_a_valid_limit():
    """max_writes: 0 is the read-only agent, not a missing value."""
    agents.validate(TEST_TENANT, agent(limits={"max_writes": 0}))


def test_a_boolean_is_not_an_integer_limit():
    with pytest.raises(InvalidAgentError, match="non-negative integer"):
        agents.validate(TEST_TENANT, agent(limits={"max_writes": True}))


# --- the write path -------------------------------------------------------------


def test_save_then_get_round_trips():
    agents.save(TEST_TENANT, agent(), actor="system:cli")
    assert agents.get(TEST_TENANT, "test-agent") == agent()


def test_save_refuses_an_invalid_config():
    with pytest.raises(InvalidAgentError):
        agents.save(TEST_TENANT, agent(**permissions(tools=["post_mesage"])), actor="system:cli")


def test_a_refused_save_writes_nothing():
    """Validation runs before the write, so an invalid config never becomes a row.
    That is what keeps load-time failures rare enough to be worth shouting about."""
    with pytest.raises(InvalidAgentError):
        agents.save(TEST_TENANT, agent(**permissions(tools=["post_mesage"])), actor="system:cli")

    assert agents.get(TEST_TENANT, "test-agent") is None


# --- create, which is the write path a form lands on ------------------------------


def test_create_writes_the_agent_and_claims_ownership():
    agents.create(TEST_TENANT, agent(), "user", "u-priya")

    assert agents.get(TEST_TENANT, "test-agent") == agent()
    assert storage.active().granted_agent_names(TEST_TENANT, "user", "u-priya") == [
        "test-agent"
    ]


def test_create_refuses_an_invalid_config_and_writes_nothing():
    with pytest.raises(InvalidAgentError):
        agents.create(
            TEST_TENANT, agent(**permissions(tools=["post_mesage"])), "user", "u-priya"
        )

    assert agents.get(TEST_TENANT, "test-agent") is None
    assert storage.active().granted_agent_names(TEST_TENANT, "user", "u-priya") == []


def test_create_refuses_a_name_that_exists():
    agents.create(TEST_TENANT, agent(), "user", "u-priya")

    with pytest.raises(AgentNameTaken):
        agents.create(TEST_TENANT, agent(system="Mine."), "user", "u-mallory")

    assert agents.get(TEST_TENANT, "test-agent")["system"] == "irrelevant"


def test_save_is_still_an_upsert_and_create_is_not():
    """Both, in one test, so that collapsing them is a failure rather than a tidy-up.

    `--seed` is documented as safe to re-run and needs the first behaviour; a create
    route would silently replace somebody else's agent with it.
    """
    agents.save(TEST_TENANT, agent(), actor="system:cli")
    agents.save(TEST_TENANT, agent(system="Replaced."), actor="system:cli")
    assert agents.get(TEST_TENANT, "test-agent")["system"] == "Replaced."

    with pytest.raises(AgentNameTaken):
        agents.create(TEST_TENANT, agent(), "user", "u-priya")


# --- the name, which is four things at once ---------------------------------------


@pytest.mark.parametrize(
    "name", ["Triage Bot", "TriageBot", "triage_bot", "-x", "x-", "x--y", "x.y", "a" * 65]
)
def test_a_name_that_is_not_a_slug_is_refused(name):
    """It is the URL, the audit string, the storage key and the broker's identity.

    Refused with the validator's own sentence rather than a constraint name, because in
    10c the person who typed it is at a form.
    """
    with pytest.raises(InvalidAgentError):
        agents.validate(TEST_TENANT, agent(name=name))


def test_the_name_rule_is_checked_by_the_dry_run_too():
    """Otherwise the wizard's last step is where a person first learns their name is
    illegal, which is the failure the dry run exists to prevent."""
    with pytest.raises(InvalidAgentError):
        agents.validate_draft(TEST_TENANT, agent(name="Triage Bot"))


def test_validate_is_a_reserved_name():
    """`POST /agents/validate` is a path. FastAPI matches a literal segment before a
    parameterised one, so an agent called this would be the one agent whose own URL a
    route shadows."""
    with pytest.raises(InvalidAgentError, match="reserved"):
        agents.validate_draft(TEST_TENANT, agent(name="validate"))

    with pytest.raises(InvalidAgentError, match="reserved"):
        agents.create(TEST_TENANT, agent(name="validate"), "user", "u-priya")


def test_a_reserved_name_is_refused_at_create_and_not_at_load():
    """The asymmetry is deliberate, and it is why `validate_draft` is a second function
    rather than a flag on the first.

    Reservation is a fact about the URL namespace. An agent that already holds the name
    still works — `GET /agents/validate` is a different method on that path and collides
    with nothing — so refusing it at load would take a working agent away to close a hole
    it is not in.
    """
    storage.active().save_agent(TEST_TENANT, agent(name="validate"), actor="system:cli")

    agents.validate(TEST_TENANT, agent(name="validate"))
    assert agents.get(TEST_TENANT, "validate") is not None


def test_new_is_a_reserved_name_too():
    """Step 025, and it was missing rather than excluded.

    `/agents/new` is routed before `/agents/:name` in the browser and the router comment
    says why — react-router would otherwise match an agent called `new`. So the client has
    reserved this name since 10c and the server never did: an agent called `new` could be
    created by curl and was then the one agent whose detail page was the create wizard.
    """
    with pytest.raises(InvalidAgentError, match="reserved"):
        agents.validate_draft(TEST_TENANT, agent(name="new"))

    with pytest.raises(InvalidAgentError, match="reserved"):
        agents.create(TEST_TENANT, agent(name="new"), "user", "u-priya")

    # And, like `validate`, it is a rule about *taking* the name rather than holding it: a
    # row that already exists keeps loading.
    storage.active().save_agent(TEST_TENANT, agent(name="new"), actor="system:cli")
    agents.validate(TEST_TENANT, agent(name="new"))
    assert agents.get(TEST_TENANT, "new") is not None


# --- rename, step 025 ------------------------------------------------------------


def test_rename_refuses_a_reserved_target():
    """**A rename takes a name, so the draft-side rules apply to it.**

    This is the judgement call in `agents.rename`: the agent already exists, so the obvious
    reading is that `validate` — not `validate_draft` — is the relevant checker. But the
    reserved-name rule exists to stop somebody *taking* a shadowed URL, and a rename is
    the one other way to take one. Without this it would arrive through the only path that
    did not look.
    """
    agents.create(TEST_TENANT, agent(name="triage"), "user", "u-priya")

    for target in ("validate", "new"):
        with pytest.raises(InvalidAgentError, match="reserved"):
            agents.rename(TEST_TENANT, "triage", target, actor="user:u-priya")

    assert agents.get(TEST_TENANT, "triage") is not None


def test_rename_refuses_a_name_that_is_not_a_slug():
    """Migration 019's shape, as this module's exception rather than a storage one — so a
    form user reads it beside the scope errors instead of getting a 503."""
    agents.create(TEST_TENANT, agent(name="triage"), "user", "u-priya")

    with pytest.raises(InvalidAgentError, match="not a usable agent name"):
        agents.rename(TEST_TENANT, "triage", "Triage Bot", actor="user:u-priya")


def test_rename_does_not_re_validate_the_rest_of_the_config():
    """**A rename is not an occasion to fix everything else about an agent.**

    The decision, and the failure it avoids: an agent granted a tool that has since been
    un-vetted no longer passes `validate()`, and if a rename ran it, renaming that agent
    would be impossible until somebody first repaired its permissions. "Change this
    agent's name" would mean "and also fix everything else", which is the shape of refusal
    that gets an agent deleted and re-created instead.

    Nothing a rename changes can make a valid config invalid — the only key it touches is
    the name, and the name rules have just been checked.
    """
    _write_bypassing_validation(
        TEST_TENANT, agent(name="triage", **permissions(tools=["gone_away"]))
    )

    # It does not validate today, which is the premise: `get` raises rather than
    # returning it.
    with pytest.raises(InvalidAgentError, match="not a registered tool"):
        agents.get(TEST_TENANT, "triage")

    row = agents.rename(TEST_TENANT, "triage", "support-triage", actor="user:u-priya")
    assert row["name"] == "support-triage"
    # Still broken, still renamed. The rename fixed nothing and refused nothing.
    with pytest.raises(InvalidAgentError, match="not a registered tool"):
        agents.get(TEST_TENANT, "support-triage")


def test_a_restore_across_a_rename_keeps_the_new_name():
    """Step 025 decision 7, and the property a person is most likely to be surprised by.

    Restoring a version written before a rename restores its *behaviour* and never its
    identity. Two reasons, and the second is not a nicety: "restore Tuesday's prompt" must
    not also mean "un-rename the agent", and `agent_name_matches_config` from migration 002
    would refuse the write outright if the snapshot's name went in verbatim — a 503 for an
    entirely reasonable request.
    """
    agents.create(TEST_TENANT, agent(name="triage", system="Tuesday."), "user", "u-priya")
    # The *row*, not the config: `agents.get` returns the latter and the ETag is on the
    # former. See `agents.get`, which says so.
    row = storage.active().get_agent(TEST_TENANT, "triage")
    agents.update(
        TEST_TENANT,
        "triage",
        {"system": "Wednesday."},
        actor="user:u-priya",
        if_unchanged_since=row["updated_at"],
    )
    agents.rename(TEST_TENANT, "triage", "support-triage", actor="user:u-priya")

    live = storage.active().get_agent(TEST_TENANT, "support-triage")
    restored = agents.restore(
        TEST_TENANT,
        "support-triage",
        1,
        actor="user:u-priya",
        if_unchanged_since=live["updated_at"],
    )

    # Tuesday's prompt is back...
    assert restored["config"]["system"] == "Tuesday."
    # ...and the agent is still called what it was called a moment ago.
    assert restored["name"] == "support-triage"
    assert restored["config"]["name"] == "support-triage"
    assert agents.get(TEST_TENANT, "triage") is None


def test_a_missing_agent_reads_as_none():
    assert agents.get(TEST_TENANT, "never-existed") is None


# --- the load path: a row that went bad -----------------------------------------


def _write_bypassing_validation(tenant_id, config):
    """Put a row in directly, as a config whose connector was later removed would
    look. `agents.save` would refuse it; the database has no such opinion."""
    storage.active().save_agent(tenant_id, config, actor="system:cli")


def test_get_raises_for_a_row_that_became_invalid():
    """**Not** None. Returning None would turn "this agent is broken" into "this agent
    does not exist", and those call for completely different responses."""
    _write_bypassing_validation(TEST_TENANT, agent(**permissions(tools=["gone_away"])))

    with pytest.raises(InvalidAgentError, match="not a registered tool"):
        agents.get(TEST_TENANT, "test-agent")


def test_load_skips_an_invalid_row_rather_than_raising(capsys):
    """One broken agent must not make a tenant's whole list unreadable."""
    agents.save(TEST_TENANT, agent(name="good"), actor="system:cli")
    _write_bypassing_validation(
        TEST_TENANT, agent(name="broken", **permissions(tools=["gone_away"]))
    )

    assert agents.names(TEST_TENANT) == ["good"]


def test_skipping_an_invalid_row_is_reported(caplog):
    """Loud, never silent. A skipped agent nobody mentions is an agent somebody
    thinks is running.

    Asserted against the log rather than stdout since this went behind a server: a
    `print` reaches nobody there, which is the whole reason it stopped being one. The
    level matters as much as the message — this is a WARNING, so `--quiet` and a
    production log threshold both still show it.
    """
    _write_bypassing_validation(
        TEST_TENANT, agent(name="broken", **permissions(tools=["gone_away"]))
    )

    with caplog.at_level(logging.WARNING, logger="carnet.agents"):
        agents.load(TEST_TENANT)

    assert "broken" in caplog.text
    assert caplog.records and caplog.records[-1].levelno == logging.WARNING


def test_one_broken_agent_does_not_hide_the_others():
    for name in ("alpha", "zulu"):
        agents.save(TEST_TENANT, agent(name=name), actor="system:cli")
    _write_bypassing_validation(
        TEST_TENANT, agent(name="mike", **permissions(tools=["gone_away"]))
    )

    assert agents.names(TEST_TENANT) == ["alpha", "zulu"]


# --- tenancy --------------------------------------------------------------------


def test_agents_are_not_visible_across_tenants():
    storage.active().create_tenant(OTHER_TENANT, "Other")
    agents.save(TEST_TENANT, agent(), actor="system:cli")

    assert agents.get(OTHER_TENANT, "test-agent") is None
    assert agents.names(OTHER_TENANT) == []


def test_a_broken_row_in_one_tenant_does_not_affect_another():
    """The whole reason load-time failure stopped taking the process down."""
    storage.active().create_tenant(OTHER_TENANT, "Other")
    _write_bypassing_validation(
        OTHER_TENANT, agent(name="broken", **permissions(tools=["gone_away"]))
    )
    agents.save(TEST_TENANT, agent(), actor="system:cli")

    assert agents.names(TEST_TENANT) == ["test-agent"]


# --- the shipped configs --------------------------------------------------------


def test_the_shipped_agent_seeds_and_validates():
    """Seeding goes through `save()`, so a broken shipped config still fails loudly at
    startup — which is most of what import-time validation was doing for us."""
    bootstrap.seed_tenant(TEST_TENANT)

    assert "issue-reporter" in agents.names(TEST_TENANT)


def test_seeding_is_idempotent():
    bootstrap.seed_tenant(TEST_TENANT)
    bootstrap.seed_tenant(TEST_TENANT)

    assert agents.names(TEST_TENANT).count("issue-reporter") == 1


def test_re_seeding_after_a_rename_writes_a_fresh_shipped_agent():
    """**A decision, pinned, rather than a defect** — and one step 025 made reachable.

    `--seed` writes the shipped configs by name, and deployments run it on every boot. Once
    an agent can be renamed, a customer who renames `issue-reporter` frees that name, and
    the next boot fills it: they end up with their renamed agent *and* a fresh shipped one.

    That is defensible — nothing is destroyed, their agent keeps its identity, its grants
    and its history — and it is a surprise, so it is written down here and in the register
    rather than discovered on somebody's second deploy.

    The related hazard is **older than this step and is the register's row**: a customer
    who takes a freed shipped name for an agent of their own has its config overwritten by
    the next `--seed`, because `save_agent` is an upsert on the name. Reachable before 025
    by deleting the shipped agent first; 025 adds renaming as a second route to it.
    """
    bootstrap.seed_tenant(TEST_TENANT)
    original = storage.active().get_agent(TEST_TENANT, "issue-reporter")["agent_id"]

    agents.rename(TEST_TENANT, "issue-reporter", "my-triage", actor="user:u-priya")
    bootstrap.seed_tenant(TEST_TENANT)

    names = agents.names(TEST_TENANT)
    assert "my-triage" in names, "the renamed agent is untouched"
    assert "issue-reporter" in names, "and the shipped name is filled again"

    # A different agent, not the one that was renamed.
    fresh = storage.active().get_agent(TEST_TENANT, "issue-reporter")
    assert fresh["agent_id"] != original
    # The renamed one keeps the identity, and therefore its grants and its history.
    kept = storage.active().get_agent(TEST_TENANT, "my-triage")
    assert kept["agent_id"] == original
    assert [g["role"] for g in storage.active().list_agent_grants(
        TEST_TENANT, "my-triage")] == ["owner"]


def test_seed_never_overwrites_a_config_a_human_last_wrote():
    """The register's row, closed. 027.

    A customer edits the shipped agent — the ordinary thing to do with an example — and
    every subsequent boot used to put ours back, silently, because `save_agent` is an
    upsert keyed by the name. Recoverable through version history and invisible at the
    time, which is the worst combination available.
    """
    bootstrap.seed_tenant(TEST_TENANT)
    row = storage.active().get_agent(TEST_TENANT, "issue-reporter")
    agents.update(
        TEST_TENANT,
        "issue-reporter",
        {"system": "answer only in haiku"},
        actor="user:u-priya",
        if_unchanged_since=row["updated_at"],
    )

    skipped = bootstrap.seed_tenant(TEST_TENANT)

    live = storage.active().get_agent(TEST_TENANT, "issue-reporter")["config"]
    assert live["system"] == "answer only in haiku", "their edit survived the re-seed"
    assert skipped == [("issue-reporter", "user:u-priya")], "and --seed said so"


def test_seed_skips_a_customer_agent_that_has_taken_a_shipped_name():
    """The sharper half, and the one that predates 025: their agent, our name.

    Delete the shipped agent and the name is genuinely free, so creating one of their
    own under it is not a collision — it is a customer using a name we happen to also
    ship. The next boot used to replace its configuration with ours.
    """
    bootstrap.seed_tenant(TEST_TENANT)
    agents.delete(TEST_TENANT, "issue-reporter", actor="user:u-priya")
    mine = dict(bootstrap.SHIPPED_AGENTS[0])
    mine["system"] = "ours, actually"
    agents.create(TEST_TENANT, mine, "user", "u-priya")

    skipped = bootstrap.seed_tenant(TEST_TENANT)

    live = storage.active().get_agent(TEST_TENANT, "issue-reporter")["config"]
    assert live["system"] == "ours, actually"
    assert [name for name, _ in skipped] == ["issue-reporter"]


def test_seed_still_refreshes_a_shipped_agent_nobody_has_touched():
    """The other half of the rule, and the half that keeps `--seed` a useful command.

    Asserted together with the two above deliberately: a guard that never writes would
    pass both of those and be useless, and this is the test that fails if somebody
    inverts the condition.
    """
    bootstrap.seed_tenant(TEST_TENANT)

    changed = dict(bootstrap.SHIPPED_AGENTS[0])
    changed["system"] = "a newer shipped prompt"
    with patch.object(bootstrap, "SHIPPED_AGENTS", [changed]):
        skipped = bootstrap.seed_tenant(TEST_TENANT)

    live = storage.active().get_agent(TEST_TENANT, "issue-reporter")["config"]
    assert live["system"] == "a newer shipped prompt", "ours is still ours to update"
    assert skipped == []


# --- version history ------------------------------------------------------------
#
# Step 021. The functions here are the one reader both entry points would share; the
# routes over them are in test_api.py. What is worth testing at this altitude is what a
# route cannot express: that validity is a **read-time** verdict, and that a restore is
# a whole-config write rather than a merge.


def _edit(**overrides):
    """Read, change, write back — what an edit screen does, at this layer."""
    row = storage.active().get_agent(TEST_TENANT, "test-agent")
    return agents.update(
        TEST_TENANT,
        "test-agent",
        overrides,
        actor="user:u-1",
        if_unchanged_since=row["updated_at"],
    )


def test_a_versions_verdict_is_computed_when_it_is_read():
    """**The field that would be wrong if it were stored.**

    A version is a configuration that *was* live, and what may be live moves under it: a
    tool removed with a connector makes a version from last month unrestorable, and the
    stored row is unchanged by that. Nothing rewrites version rows, so a verdict written
    at save time would still say `valid` about a config that can no longer be saved.
    """
    agents.save(TEST_TENANT, agent(), actor="system:cli")
    _edit(permissions={"tools": [], "scope": {}})

    assert [row["valid"] for row in agents.versions(TEST_TENANT, "test-agent")] == [
        True,
        True,
    ]

    # The tool version 1 was granted stops being a name this tenant knows — which is
    # exactly the scenario in this file's own docstring, one table over.
    _write_bypassing_validation(TEST_TENANT, agent(**permissions(tools=["gone_away"])))

    history = agents.versions(TEST_TENANT, "test-agent")
    assert [(row["version"], row["valid"]) for row in history] == [
        (3, False),
        (2, True),
        (1, True),
    ]
    assert "not a registered tool" in history[0]["error"]
    # And the stored row itself is untouched: storage says what was stored, and this
    # layer says whether it would run today.
    assert storage.active().get_agent_version(TEST_TENANT, "test-agent", 3)[
        "config"
    ]["permissions"]["tools"] == ["gone_away"]


def test_a_version_that_was_never_written_raises_rather_than_returning_none():
    """Unlike `get()`, and the difference is which question is being asked. `get()`
    answers *is there an agent here*, where absence is ordinary. Here the agent is known
    to exist, so a missing version is a caller naming something that never was."""
    agents.save(TEST_TENANT, agent(), actor="system:cli")

    with pytest.raises(agents.NoSuchVersion, match="no version 7"):
        agents.version(TEST_TENANT, "test-agent", 7)


def test_a_restore_replaces_the_whole_config_rather_than_merging_it():
    """**The finding the restore route exists for**, at the layer it is decided.

    `merge` is a top-level merge, so a key the old config does not carry survives from
    the live one. Restoring must not merge, or a version written before a field existed
    comes back carrying today's value of it — neither version, silently.
    """
    agents.save(TEST_TENANT, agent(), actor="system:cli")
    _edit(model="claude-haiku-4-5-20251001")
    assert agents.get(TEST_TENANT, "test-agent")["model"] == "claude-haiku-4-5-20251001"

    row = storage.active().get_agent(TEST_TENANT, "test-agent")
    restored = agents.restore(
        TEST_TENANT, "test-agent", 1,
        actor="user:u-1", if_unchanged_since=row["updated_at"],
    )

    assert "model" not in restored["config"]
    assert agents.get(TEST_TENANT, "test-agent") == agent()


def test_restoring_a_version_that_no_longer_validates_is_refused_and_writes_nothing():
    """The same sentence `versions()` showed beside it, so the refusal is never a
    surprise — and the agent is left exactly as it was."""
    _write_bypassing_validation(TEST_TENANT, agent(**permissions(tools=["gone_away"])))
    agents.save(TEST_TENANT, agent(), actor="system:cli")

    row = storage.active().get_agent(TEST_TENANT, "test-agent")
    with pytest.raises(InvalidAgentError, match="not a registered tool"):
        agents.restore(
            TEST_TENANT, "test-agent", 1,
            actor="user:u-1", if_unchanged_since=row["updated_at"],
        )

    assert agents.get(TEST_TENANT, "test-agent") == agent()
    assert len(agents.versions(TEST_TENANT, "test-agent")) == 2


def test_a_restore_from_a_stale_read_raises_the_same_conflict_an_edit_does():
    """A restore is an edit, so it owes the same 409 — and its `changed` list is wider,
    because a restore writes every key rather than the ones a form sent."""
    agents.save(TEST_TENANT, agent(), actor="system:cli")
    stale = storage.active().get_agent(TEST_TENANT, "test-agent")["updated_at"]
    _edit(system="Priya got here first.")

    with pytest.raises(agents.AgentChanged) as raised:
        agents.restore(
            TEST_TENANT, "test-agent", 1,
            actor="user:u-2", if_unchanged_since=stale,
        )

    assert raised.value.changed == ["system"]
    assert len(agents.versions(TEST_TENANT, "test-agent")) == 2


def test_restoring_a_deleted_agent_is_refused_by_its_history_being_gone_too():
    """Deleting an agent deletes its versions, so this is `NoSuchVersion` rather than the
    `None` an absent agent gives — and that is worth pinning because it is not the
    answer the code was written expecting.

    **`restore`'s `None` branch survives anyway, and is a race rather than dead code**:
    the version read can succeed and the delete land before the write, in which case
    `update_agent` matches nothing and the re-read finds no agent. Unreachable
    sequentially, reachable with two callers, and the alternative — assuming the version
    read proves the agent is still there — is the read-then-write window this whole
    family of methods exists to refuse.
    """
    agents.save(TEST_TENANT, agent(), actor="system:cli")
    row = storage.active().get_agent(TEST_TENANT, "test-agent")
    agents.delete(TEST_TENANT, "test-agent", actor="user:u-1")

    with pytest.raises(agents.NoSuchVersion):
        agents.restore(
            TEST_TENANT, "test-agent", 1,
            actor="user:u-1", if_unchanged_since=row["updated_at"],
        )

    assert agents.get(TEST_TENANT, "test-agent") is None


def test_a_restore_racing_a_delete_is_none_rather_than_a_resurrection(monkeypatch):
    """The branch the test above cannot reach sequentially, reached by making the delete
    land between the version read and the write — which is exactly where a second caller
    would land it.

    A restore that resurrected the agent would recreate it **with no owner grant**,
    because grants cascade with the row: an agent nobody can run, including whoever
    restored it. That is the artifact `create_agent`'s transaction exists to prevent,
    arriving through a different door.
    """
    agents.save(TEST_TENANT, agent(), actor="system:cli")
    row = storage.active().get_agent(TEST_TENANT, "test-agent")

    real = agents.validate

    def delete_then_validate(tenant_id, config):
        agents.delete(TEST_TENANT, "test-agent", actor="user:u-2")
        return real(tenant_id, config)

    monkeypatch.setattr(agents, "validate", delete_then_validate)

    assert agents.restore(
        TEST_TENANT, "test-agent", 1,
        actor="user:u-1", if_unchanged_since=row["updated_at"],
    ) is None
    assert agents.get(TEST_TENANT, "test-agent") is None


def test_reading_history_survives_the_agent_being_deleted_underneath_it():
    """**Two un-transacted reads, and the loop was written as though the list could not
    move.**

    `versions()` lists the rows and then reads each config; a `DELETE` between the two
    cascades the whole history, and `stored["config"]` on a `None` was a `TypeError` —
    a 500 for a race whose honest answer is that there is nothing there now. `version()`
    two functions down handled the same None correctly, which is what made it an
    inconsistency rather than an oversight nobody could have caught.

    Forced here by deleting inside the loop, which is where a second caller would land it.
    """
    agents.save(TEST_TENANT, agent(), actor="system:cli")
    _edit(system="Second.")

    store = storage.active()
    real = store.get_agent_version
    calls = []

    def delete_then_read(tenant_id, name, version):
        calls.append(version)
        if len(calls) == 1:
            agents.delete(TEST_TENANT, "test-agent", actor="user:u-2")
        return real(tenant_id, name, version)

    store.get_agent_version = delete_then_read
    try:
        assert agents.versions(TEST_TENANT, "test-agent") == []
    finally:
        store.get_agent_version = real


# --- validation: the output section (step 024) ------------------------------------
#
# The write-time half of the output contract, and **since 081 the only half**. Every
# refusal here is `InvalidAgentError` — the narrow class, asserted as such — so the form,
# PATCH, `POST /agents/validate` and `--seed` refuse a bad schema with the same sentences
# before a row exists.
#
# There used to be a second family below: `OutputInvalid`, a *run outcome*, raised by
# `check_output` when a finished answer did not conform, with a test pinning that the two
# stayed disjoint. Both are gone — see the section further down for why a dead enforcement
# point is not free. Storing a schema this deployment does not enforce is fine; storing
# one that is not a schema is a row nobody can explain later, which is what these keep
# refusing.


OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "vendor": {"type": "string"},
        "total_cents": {"type": "integer"},
    },
    "required": ["vendor", "total_cents"],
    "additionalProperties": False,
}


def test_a_well_formed_output_section_validates():
    agents.validate(TEST_TENANT, agent(output={"schema": OUTPUT_SCHEMA}))


def test_output_null_is_refused():
    """Explicit null and absent key mean different things: absent is prose behaviour,
    null is a key that means nothing. Refused with the sentence about removal needing
    the CLI — the standing merge cost, loud instead of stored."""
    with pytest.raises(InvalidAgentError, match="output is null"):
        agents.validate(TEST_TENANT, agent(output=None))


def test_output_must_be_a_dict():
    with pytest.raises(InvalidAgentError, match="must be an object"):
        agents.validate(TEST_TENANT, agent(output=[{"schema": OUTPUT_SCHEMA}]))


def test_an_unknown_output_key_is_refused():
    """A typo'd key is a constraint that silently never applies — `limits`' argument."""
    with pytest.raises(InvalidAgentError, match="unknown key.*shcema"):
        agents.validate(TEST_TENANT, agent(output={"shcema": OUTPUT_SCHEMA}))


def test_an_output_section_without_a_schema_is_refused():
    with pytest.raises(InvalidAgentError, match="no 'schema'"):
        agents.validate(TEST_TENANT, agent(output={}))


def test_a_schema_that_is_not_a_dict_is_refused():
    with pytest.raises(InvalidAgentError, match="must be a JSON Schema object"):
        agents.validate(TEST_TENANT, agent(output={"schema": "object"}))


def test_a_structurally_invalid_schema_is_refused():
    """The validator library's own verdict, in the refusal — `{"type": 12}` is not a
    schema anything can check an answer against."""
    with pytest.raises(InvalidAgentError, match="not a valid JSON Schema"):
        agents.validate(TEST_TENANT, agent(output={"schema": {"type": 12}}))


def test_a_non_object_root_is_refused():
    with pytest.raises(InvalidAgentError, match="rooted at type 'object'"):
        agents.validate(TEST_TENANT, agent(output={"schema": {"type": "string"}}))


def test_an_open_root_object_is_refused():
    """`additionalProperties: false` is the model API's documented hard requirement
    and this platform's own contract: a schema that admits unknown keys admits
    answers the consumer's code never handles."""
    with pytest.raises(InvalidAgentError, match=r"additionalProperties.*\$"):
        agents.validate(
            TEST_TENANT,
            agent(output={"schema": {"type": "object", "properties": {}}}),
        )


def test_an_open_nested_object_is_refused_by_path():
    """The walk reaches nested objects and the refusal names where — a sentence that
    says 'somewhere in your schema' is a sentence somebody reads at 3am."""
    nested = {
        "type": "object",
        "properties": {
            "vendor": {"type": "object", "properties": {"name": {"type": "string"}}}
        },
        "additionalProperties": False,
    }
    with pytest.raises(InvalidAgentError, match=r"\$\.properties\.vendor"):
        agents.validate(TEST_TENANT, agent(output={"schema": nested}))


# --- the completion-time check, and where it went (step 081) ------------------------
#
# `check_output` and `OutputInvalid` were the completion-time half of 024's contract:
# called from `runs.execute` so the CLI and a worker refused identically, rather than
# delegated to the model API whose guarantee excludes refusals and truncation. Step 078
# deleted `runs.execute` from this tree and left both behind, which is 080 section B2 —
# `agents.check_output` still raising from a loop that no longer exists, under an edit
# screen and a detail card that read as a contract being enforced.
#
# **The write-time half stays and its tests are above.** A schema somebody stores is still
# refused if it is malformed, because a stored lie is worse than a stored unread truth;
# what is gone is the pretence that anything checks an answer against it. The tests that
# lived here — the JSON families, the nonfinite literals, the degenerate nesting, the
# unresolvable `$ref` — all drove `check_output`, and there is nothing left for them to
# drive. They are recoverable from git if a tree ever executes an agent again.


def test_the_completion_time_check_is_gone_rather_than_dormant():
    """081, and it is asserted rather than assumed.

    A dead function that still raises is not free: it reads as an enforcement point to
    anybody grepping for one, which is exactly how the edit screen came to promise a
    contract nothing keeps. The write-time validator is the one that survives, and the
    test below it proves the pair did not both go.
    """
    assert not hasattr(agents, "check_output")
    assert not hasattr(agents, "OutputInvalid")
    assert "check_output" not in agents.__all__
    assert "OutputInvalid" not in agents.__all__


def test_a_malformed_schema_is_still_refused_at_write():
    """The half that stays. Storing a schema this deployment does not enforce is fine;
    storing one that is not a schema is a row nobody can explain later."""
    with pytest.raises(InvalidAgentError, match="additionalProperties"):
        agents.validate(
            TEST_TENANT,
            agent(output={"schema": {"type": "object", "properties": {}}}),
        )


def test_a_stale_output_row_is_refused_at_load_and_skipped_in_listing(caplog):
    """The module's write-time/load-time split, applied to the new section: a row
    written under looser rules (or directly to storage, past validation) raises at
    `get()` — so running it is a 422, never a stranded surprise — and the listing
    skips it loudly rather than going unreadable."""
    import logging

    store = storage.active()
    store.save_agent(
        TEST_TENANT,
        {
            "name": "stale-schema",
            "runtime": "simple",
            "system": "s",
            "permissions": {"tools": [], "scope": {}},
            "output": {"schema": {
                "type": "object", "additionalProperties": False,
                "properties": {"x": {"$ref": "https://old.invalid/s.json"}},
            }},
        },
        actor="system:cli",
    )

    with pytest.raises(InvalidAgentError, match="refers outside itself"):
        agents.get(TEST_TENANT, "stale-schema")
    with caplog.at_level(logging.WARNING):
        assert "stale-schema" not in agents.names(TEST_TENANT)
    assert "skipping invalid config" in caplog.text


def test_the_version_screen_warns_before_a_restore_would_refuse():
    """021's read-time verdict, inherited by the section for free: a version whose
    schema today's rules refuse shows `valid: false` with the validator's own
    sentence, so the refusal arrives before the click rather than as the 422 after."""
    store = storage.active()
    store.save_agent(
        TEST_TENANT,
        {
            "name": "stale-schema",
            "runtime": "simple",
            "system": "s",
            "permissions": {"tools": [], "scope": {}},
            "output": {"schema": {
                "type": "object", "additionalProperties": False,
                "properties": {"x": {"$ref": "https://old.invalid/s.json"}},
            }},
        },
        actor="system:cli",
    )

    rows = agents.versions(TEST_TENANT, "stale-schema")
    assert rows[0]["valid"] is False
    assert "refers outside itself" in rows[0]["error"]
