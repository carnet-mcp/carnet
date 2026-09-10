"""The command line, and specifically the onboarding commands.

There was no test file for the CLI at all before this. That was defensible while it
was a thin wrapper over things tested elsewhere — and stopped being defensible when it
grew the commands that create customers and register identity providers, because those
are the only way a customer comes into existence and their refusals are the ones that
prevent a cross-tenant read.

The refusals get more attention than the happy paths here, on purpose. `--add-tenant`
working is obvious the first time somebody runs it; `--add-idp` quietly accepting a
second registration for an issuer another customer already owns is not obvious ever.

`main()` is driven through `sys.argv`, the way a person drives it, so the argument
parsing is under test rather than bypassed.
"""

import io
import sys
from datetime import datetime, timezone

import pytest

from carnet import bootstrap, cli, storage, tools
from carnet.access import grants
from carnet.core import Principal, crypto


from conftest import GITHUB

TENANT = "acme"
OTHER = "globex"

OKTA = [
    "--issuer",
    "https://acme.okta.example",
    "--jwks-uri",
    "https://acme.okta.example/oauth2/v1/keys",
    "--audience",
    "api://default",
]

GOOGLE = [
    "--issuer",
    "https://accounts.google.example",
    "--jwks-uri",
    "https://www.googleapis.com/oauth2/v3/certs",
    "--audience",
    "123.apps.googleusercontent.com",
]


def run(monkeypatch, *args):
    """Invoke the CLI as a person would. Returns nothing; raises SystemExit on error."""
    monkeypatch.setattr(sys, "argv", ["carnet", *args])
    cli.main()


def fails(monkeypatch, *args) -> str:
    """Invoke the CLI expecting a refusal. Returns what it said."""
    with pytest.raises(SystemExit) as caught:
        run(monkeypatch, *args)
    assert caught.value.code != 0
    return str(caught.value)


@pytest.fixture(autouse=True)
def one_store(monkeypatch, isolated_storage):
    """Keep one store across several commands in one process.

    `main()` configures storage on every invocation, so in-process the second command
    would throw away what the first created. A person does not see that — their store
    is a database and outlives the process — so the fixture restores the continuity
    they experience rather than papering over a bug.

    `DATABASE_URL` is faked truthy for the same reason: the onboarding commands now
    refuse to run without one, and a test driving them must take the path a real user
    takes rather than a bypass.
    """
    monkeypatch.setattr(cli, "DATABASE_URL", "postgresql://not-actually-connected")
    monkeypatch.setattr(
        cli.bootstrap, "configure", lambda tenant_id=None, seed=True: storage.active()
    )


def message(capsys) -> str:
    captured = capsys.readouterr()
    return captured.out + captured.err


# --- creating a customer ----------------------------------------------------------


def test_add_tenant_creates_a_customer(monkeypatch, capsys):
    run(monkeypatch, "--add-tenant", TENANT, "Acme Corp")

    assert storage.active().get_tenant(TENANT)["name"] == "Acme Corp"
    assert "--add-idp" in message(capsys), "should say what to do next"


def test_add_tenant_is_idempotent(monkeypatch):
    run(monkeypatch, "--add-tenant", TENANT, "Acme Corp")
    run(monkeypatch, "--add-tenant", TENANT, "Acme Corp")

    assert storage.active().get_tenant(TENANT) is not None


# --- registering an identity provider ---------------------------------------------


def test_add_idp_registers_a_provider(monkeypatch):
    run(monkeypatch, "--add-tenant", TENANT, "Acme")
    run(monkeypatch, "--add-idp", TENANT, *OKTA, "--domain", "acme.com")

    rows = storage.active().find_tenant_idps("https://acme.okta.example")
    assert len(rows) == 1
    assert rows[0]["tenant_id"] == TENANT
    assert rows[0]["allowed_domains"] == ("acme.com",)


def test_domains_are_repeatable(monkeypatch):
    run(monkeypatch, "--add-tenant", TENANT, "Acme")
    run(
        monkeypatch,
        "--add-idp", TENANT, *OKTA,
        "--domain", "acme.com",
        "--domain", "acme.co.uk",
    )

    row = storage.active().find_tenant_idps("https://acme.okta.example")[0]
    assert row["allowed_domains"] == ("acme.com", "acme.co.uk")


def test_a_wildcard_domain_on_a_customers_provider_is_refused(monkeypatch, capsys):
    """`--domain '*'` used to register and print a warning. It now refuses.

    A warning next to a control that has been switched off is the shape migration 020
    already ruled on — *a CHECK value no code path answers is a control that lies* — and
    this is that in prose. The refusal lives in `normalize_idp`, so this asserts the CLI
    reports it rather than deciding it, and that no row is left behind.
    """
    run(monkeypatch, "--add-tenant", TENANT, "Acme")
    fails(monkeypatch, "--add-idp", TENANT, *OKTA, "--domain", "*")

    assert "not an allowed email domain" in message(capsys)
    assert storage.active().find_tenant_idps("https://acme.okta.example") == []


def test_a_wildcard_domain_is_still_legal_for_the_local_provider(monkeypatch):
    """The one exemption, exercised through the same command a person would type — the
    local provider is its own account authority, so a domain check there refuses the
    first teammate on a personal address and protects nothing."""
    local_issuer = storage.LOCAL_ISSUER_WILDCARD_OK
    run(monkeypatch, "--add-tenant", TENANT, "Acme")
    run(
        monkeypatch,
        "--add-idp", TENANT,
        "--issuer", local_issuer,
        "--jwks-uri", "http://127.0.0.1:7300/idp/v1/keys",
        "--audience", local_issuer,
        "--domain", "*",
    )

    row = storage.active().find_tenant_idps(local_issuer)[0]
    assert row["allowed_domains"] == ("*",)


def test_a_discriminator_is_parsed(monkeypatch):
    """`hd=acme.com` — the shape that lets two Google Workspace customers share an
    issuer."""
    run(monkeypatch, "--add-tenant", TENANT, "Acme")
    run(
        monkeypatch,
        "--add-idp", TENANT, *GOOGLE,
        "--discriminator", "hd=acme.com",
        "--domain", "acme.com",
    )

    row = storage.active().find_tenant_idps("https://accounts.google.example")[0]
    assert row["discriminator_claim"] == "hd"
    assert row["discriminator_value"] == "acme.com"


def test_a_discriminator_value_may_contain_equals(monkeypatch):
    """Split on the FIRST `=` only. A value that contains one is not a parse error."""
    run(monkeypatch, "--add-tenant", TENANT, "Acme")
    run(
        monkeypatch,
        "--add-idp", TENANT, *GOOGLE,
        "--discriminator", "hd=a=b",
        "--domain", "acme.com",
    )

    row = storage.active().find_tenant_idps("https://accounts.google.example")[0]
    assert (row["discriminator_claim"], row["discriminator_value"]) == ("hd", "a=b")


def test_a_malformed_discriminator_is_refused(monkeypatch, capsys):
    run(monkeypatch, "--add-tenant", TENANT, "Acme")

    fails(monkeypatch, "--add-idp", TENANT, *GOOGLE, "--discriminator", "justhd")

    assert "CLAIM=VALUE" in message(capsys)


def test_the_subject_claim_is_stored(monkeypatch):
    """Okta's access tokens put the login in `sub` and the stable id in `uid`."""
    run(monkeypatch, "--add-tenant", TENANT, "Acme")
    run(monkeypatch, "--add-idp", TENANT, *OKTA, "--subject-claim", "uid")

    row = storage.active().find_tenant_idps("https://acme.okta.example")[0]
    assert row["subject_claim"] == "uid"


def test_the_subject_claim_defaults_to_sub(monkeypatch):
    run(monkeypatch, "--add-tenant", TENANT, "Acme")
    run(monkeypatch, "--add-idp", TENANT, *OKTA)

    assert storage.active().find_tenant_idps("https://acme.okta.example")[0][
        "subject_claim"
    ] == "sub"


@pytest.mark.parametrize("missing", ["--issuer", "--jwks-uri", "--audience"])
def test_add_idp_names_what_is_missing(monkeypatch, capsys, missing):
    run(monkeypatch, "--add-tenant", TENANT, "Acme")

    args = [a for pair in zip(OKTA[::2], OKTA[1::2]) if pair[0] != missing for a in pair]
    fails(monkeypatch, "--add-idp", TENANT, *args)

    assert missing in message(capsys)


def test_add_idp_for_an_unknown_tenant_says_how_to_fix_it(monkeypatch, capsys):
    fails(monkeypatch, "--add-idp", "nobody", *OKTA)

    said = message(capsys)
    assert "does not exist" in said
    assert "--add-tenant nobody" in said, "should print the command that fixes it"


def test_no_domains_warns_that_nobody_will_be_created(monkeypatch, capsys):
    """An empty allowed-domain list is not "allow everything" — it creates nobody, and
    somebody registering a provider should learn that now rather than at first login."""
    run(monkeypatch, "--add-tenant", TENANT, "Acme")
    run(monkeypatch, "--add-idp", TENANT, *OKTA)

    assert "no --domain" in message(capsys)


# --- the refusals that prevent a cross-tenant read --------------------------------


def test_another_tenant_cannot_take_over_an_issuer(monkeypatch, capsys):
    """Not a mistake — a takeover. Without this, registering Acme's issuer hands you
    Acme's users."""
    run(monkeypatch, "--add-tenant", TENANT, "Acme")
    run(monkeypatch, "--add-tenant", OTHER, "Globex")
    run(monkeypatch, "--add-idp", TENANT, *OKTA, "--domain", "acme.com")

    fails(monkeypatch, "--add-idp", OTHER, *OKTA, "--domain", "globex.com")

    assert "already registered to tenant" in message(capsys)


def test_claiming_a_discriminated_issuer_outright_is_refused(monkeypatch, capsys):
    run(monkeypatch, "--add-tenant", TENANT, "Acme")
    run(monkeypatch, "--add-tenant", OTHER, "Globex")
    run(
        monkeypatch,
        "--add-idp", TENANT, *GOOGLE,
        "--discriminator", "hd=acme.com",
        "--domain", "acme.com",
    )

    fails(monkeypatch, "--add-idp", OTHER, *GOOGLE, "--domain", "globex.com")

    assert "cannot coexist" in message(capsys)


def test_two_customers_may_share_a_discriminated_issuer(monkeypatch):
    """The Google Workspace case, which must keep working."""
    run(monkeypatch, "--add-tenant", TENANT, "Acme")
    run(monkeypatch, "--add-tenant", OTHER, "Globex")
    run(monkeypatch, "--add-idp", TENANT, *GOOGLE, "--discriminator", "hd=acme.com")
    run(monkeypatch, "--add-idp", OTHER, *GOOGLE, "--discriminator", "hd=globex.com")

    rows = storage.active().find_tenant_idps("https://accounts.google.example")
    assert {r["discriminator_value"]: r["tenant_id"] for r in rows} == {
        "acme.com": TENANT,
        "globex.com": OTHER,
    }


# --- listing ----------------------------------------------------------------------


def test_list_idps_shows_how_each_one_routes(monkeypatch, capsys):
    run(monkeypatch, "--add-tenant", TENANT, "Acme")
    run(monkeypatch, "--add-idp", TENANT, *OKTA, "--domain", "acme.com")
    run(monkeypatch, "--add-idp", TENANT, *GOOGLE, "--discriminator", "hd=acme.com")
    capsys.readouterr()

    run(monkeypatch, "--list-idps")

    said = message(capsys)
    assert "(whole issuer)" in said
    assert "hd=acme.com" in said
    assert "acme.com" in said


def test_list_idps_can_be_scoped_to_one_tenant(monkeypatch, capsys):
    run(monkeypatch, "--add-tenant", TENANT, "Acme")
    run(monkeypatch, "--add-tenant", OTHER, "Globex")
    run(monkeypatch, "--add-idp", TENANT, *OKTA)
    capsys.readouterr()

    run(monkeypatch, "--list-idps", OTHER)

    assert "No identity providers" in message(capsys)


def test_list_idps_with_none_registered(monkeypatch, capsys):
    run(monkeypatch, "--list-idps")

    assert "No identity providers" in message(capsys)


# --- running an agent -------------------------------------------------------------


def test_listing_agents_works(monkeypatch, capsys):
    bootstrap.seed_tenant(cli.DEFAULT_TENANT_ID)

    run(monkeypatch, "--list")

    assert "issue-reporter" in message(capsys)


# --- the guard that keeps onboarding honest ---------------------------------------


def test_onboarding_refuses_without_a_database(monkeypatch, capsys):
    """Two commands, two processes, two empty dicts.

    Without a database, `--add-tenant` then `--add-idp` would print two successes and
    leave nothing behind — a failure indistinguishable from success, which is the
    worst kind. Found by writing these tests: the first draft could not chain the two
    commands and the reason was this, not the test.
    """
    monkeypatch.setattr(cli, "DATABASE_URL", None)

    fails(monkeypatch, "--add-tenant", TENANT, "Acme")

    said = message(capsys)
    assert "CARNET_DATABASE_URL" in said
    assert "vanishes" in said


def test_add_idp_also_refuses_without_a_database(monkeypatch, capsys):
    monkeypatch.setattr(cli, "DATABASE_URL", None)

    fails(monkeypatch, "--add-idp", TENANT, *OKTA)

    assert "CARNET_DATABASE_URL" in message(capsys)


# --- sharing an agent -------------------------------------------------------------
#
# The CLI acts as `system:cli`, which migration 011 made the owner of every agent that
# predates sharing. That is what makes these commands work on an existing database
# without a bootstrap step — and what makes them stop working on an agent somebody has
# taken over, which is the model working rather than a rough edge.


@pytest.fixture
def owned_agent():
    """The default tenant with one agent, owned by `system:cli` as the migration
    leaves it."""
    store = storage.active()
    store.create_tenant(cli.DEFAULT_TENANT_ID, "Default")
    store.save_agent(
        cli.DEFAULT_TENANT_ID,
        {
            "name": "triage",
            "system": "You are a demo agent.",
            "permissions": {
                "tools": ["post_message"],
                "scope": {"chat.channel": {"write": ["#eng"]}},
            },
        },
        actor="system:cli",
    )
    store.grant_agent(
        cli.DEFAULT_TENANT_ID, "triage", "system", "cli", role="owner",
        granted_by="migration:011",
        actor="system:cli",
    )
    return "triage"


def roles_on(agent_name):
    """The grant ROWS, keyed by grantee. Deliberately not `who_has_access`, which
    expands groups — these tests are about what was written down."""
    return {
        f"{g['grantee_kind']}:{g['grantee_id']}": g["role"]
        for g in storage.active().list_agent_grants(cli.DEFAULT_TENANT_ID, agent_name)
    }


def test_rename_agent_keeps_its_grants(monkeypatch, owned_agent, capsys):
    """Step 025, and parity: the CLI and the route refuse and succeed identically.

    The grants surviving is the point. Before migration 035 the only way to change a name
    was delete-and-recreate, which takes every grant with it.
    """
    run(monkeypatch, "--share-agent", owned_agent, "u_priya", "--role", "editor")
    capsys.readouterr()

    run(monkeypatch, "--rename-agent", owned_agent, "support-triage")

    said = message(capsys)
    assert "Renamed 'triage' to 'support-triage'" in said
    # The broken-bookmark warning, said out loud because it is the consequence nobody
    # thinks of until a webhook starts 404ing.
    assert "/agents/triage" in said and "/agents/support-triage" in said

    assert storage.active().get_agent(cli.DEFAULT_TENANT_ID, "triage") is None
    assert roles_on("support-triage")["user:u_priya"] == "editor"
    assert roles_on("support-triage")["system:cli"] == "owner"


def test_rename_agent_refuses_without_a_traceback(monkeypatch, owned_agent, capsys):
    """Three refusals, three sentences, exit 2 — `--share-agent`'s lesson, which 018
    learned the hard way: a rule added below the CLI arrives as a stack trace in somebody's
    terminal until somebody types the command."""
    storage.active().save_agent(
        cli.DEFAULT_TENANT_ID,
        {
            "name": "billing",
            "permissions": {"tools": [], "scope": {}},
        },
        actor="system:cli",
    )
    capsys.readouterr()

    for target, expected in (
        ("Support Triage", "not a usable agent name"),
        ("validate", "reserved"),
        ("new", "reserved"),
        ("triage", "already called that"),
        ("billing", "already has an agent called 'billing'"),
    ):
        fails(monkeypatch, "--rename-agent", owned_agent, target)
        # `message`, not `fails`' return: `parser.error` writes the sentence to stderr and
        # exits, so the exception carries the code and the terminal carries the words.
        said = message(capsys)
        assert expected in said, target
        assert "Traceback" not in said, target

    assert storage.active().get_agent(cli.DEFAULT_TENANT_ID, "triage") is not None


def test_renaming_an_agent_that_is_not_there_is_a_sentence(
    monkeypatch, owned_agent, capsys
):
    """`owned_agent` so the *tenant* exists and only the agent is missing, which is the
    situation a person is actually in.

    Worth stating because the other shape is noisier and is not this step's: with no tenant
    at all, `denials.record` cannot write its record and logs the failure with a traceback —
    which `--agent-access` and `--share-agent` do too, identically, and have since 015. The
    refusal is still served in every case; the traceback is the denial log complaining about
    a tenant that was never created.
    """
    capsys.readouterr()

    fails(monkeypatch, "--rename-agent", "ghost", "still-a-ghost")

    said = message(capsys)
    assert "no agent named 'ghost'" in said
    assert "Traceback" not in said


def test_share_agent_grants_access(monkeypatch, owned_agent):
    run(monkeypatch, "--share-agent", owned_agent, "u_priya")

    assert roles_on(owned_agent)["user:u_priya"] == "user"


def test_share_agent_takes_a_role(monkeypatch, owned_agent):
    run(monkeypatch, "--share-agent", owned_agent, "u_priya", "--role", "editor")

    assert roles_on(owned_agent)["user:u_priya"] == "editor"


def test_sharing_with_a_machine_above_user_is_refused_not_a_traceback(
    monkeypatch, owned_agent, capsys
):
    """**A storage-layer refusal arriving as a refusal.** 018 learned this about
    `--add-tenant`: a rule added below the CLI shows up as a stack trace in somebody's
    terminal until they type the command. The machine ceiling is the first rule to reach
    this path, and it did exactly that — found by driving the e2e, not by the suite,
    which is why this test exists rather than only that one.
    """
    run(monkeypatch, "--share-agent", owned_agent, "machine:m_ci")
    assert roles_on(owned_agent)["machine:m_ci"] == "user"
    capsys.readouterr()

    fails(monkeypatch, "--share-agent", owned_agent, "machine:m_ci", "--role", "editor")

    said = message(capsys)
    assert "a machine may be granted" in said
    assert "Traceback" not in said
    assert roles_on(owned_agent)["machine:m_ci"] == "user", "the grant must be unchanged"


def test_sharing_at_owner_is_a_transfer(monkeypatch, owned_agent):
    """One path to one outcome: `--role owner` moves ownership and demotes the
    incumbent, rather than being refused by a unique index."""
    run(monkeypatch, "--share-agent", owned_agent, "u_priya", "--role", "owner")

    assert roles_on(owned_agent) == {"user:u_priya": "owner", "system:cli": "editor"}


def test_a_kind_can_be_named_for_a_system_principal(monkeypatch, owned_agent):
    """A scheduler needs the same grant a person does."""
    run(monkeypatch, "--share-agent", owned_agent, "system:nightly")

    assert roles_on(owned_agent)["system:nightly"] == "user"


def test_an_unknown_role_is_refused_by_the_parser(monkeypatch, owned_agent, capsys):
    """Rejected before anything is written, and the message names the three levels.

    argparse exits with a code rather than a sentence, so this reads stderr — and it
    asserts the levels are *mentioned*, not how argparse punctuates them. The first
    version pinned `"'user', 'editor', 'owner'"` and CI caught it: newer 3.12 patches
    print `choose from user, editor, owner` without the quotes, so py3.10 passed and
    py3.12 failed. A test that fails when the standard library changes its commas is
    testing the standard library.
    """
    fails(monkeypatch, "--share-agent", owned_agent, "u_priya", "--role", "admin")

    said = message(capsys)
    assert "invalid choice" in said and "admin" in said
    for level in ("user", "editor", "owner"):
        assert level in said, f"the refusal should say {level!r} is available"


def test_sharing_an_agent_the_cli_does_not_own_is_refused(monkeypatch, owned_agent, capsys):
    """The operator is a principal with grants, not a superuser. After handing `triage`
    to somebody, the CLI is an editor and may still share — so this transfers it twice
    to reach a state where the CLI holds nothing at all."""
    run(monkeypatch, "--share-agent", owned_agent, "u_priya", "--role", "owner")
    storage.active().revoke_agent(cli.DEFAULT_TENANT_ID, owned_agent, "system", "cli", actor="system:cli")

    fails(monkeypatch, "--share-agent", owned_agent, "u_bob")

    said = message(capsys)
    # The exception's own wording is the API's — one sentence for absent, ungranted and
    # too-low, because over HTTP distinguishing them enumerates a company's agents.
    assert "no agent named" in said
    # And on a terminal the CLI adds what it already knows. Whoever ran this holds the
    # database and has probably just seen the agent in `--list`; telling them it does
    # not exist teaches them to distrust the tool.
    assert "It exists" in said
    assert "--agent-access" in said


def test_a_genuinely_absent_agent_gets_no_existence_hint(monkeypatch, owned_agent, capsys):
    """The other half of the test above: the hint is conditional on the row being
    there, so it cannot become a way to probe for names."""
    fails(monkeypatch, "--share-agent", "never-existed", "u_bob")

    said = message(capsys)
    assert "no agent named 'never-existed'" in said
    assert "It exists" not in said


def test_unshare_agent_takes_access_away(monkeypatch, owned_agent):
    run(monkeypatch, "--share-agent", owned_agent, "u_priya")
    run(monkeypatch, "--unshare-agent", owned_agent, "u_priya")

    assert "user:u_priya" not in roles_on(owned_agent)


def test_unsharing_the_owner_is_refused(monkeypatch, owned_agent, capsys):
    """An editor who may orphan an agent may take it from whoever made it."""
    fails(monkeypatch, "--unshare-agent", owned_agent, "system:cli")

    assert "owns" in message(capsys)
    assert roles_on(owned_agent)["system:cli"] == "owner"


def test_agent_access_lists_who_can_use_it(monkeypatch, owned_agent, capsys):
    run(monkeypatch, "--share-agent", owned_agent, "u_priya", "--role", "editor")
    run(monkeypatch, "--agent-access", owned_agent)

    said = message(capsys)
    assert "system:cli" in said and "owner" in said
    assert "u_priya" in said and "editor" in said
    assert "migration:011" in said, "should say a migration did it, not a person"


def test_agent_access_answers_the_operator_who_holds_no_grant(
    monkeypatch, owned_agent, capsys
):
    """**Step 072's second finding, and the behaviour it reversed.**

    This test used to assert the opposite — that the CLI, holding no *grant*, was told
    the agent did not exist, "which is the rule applying to the operator exactly as it
    applies to everybody else". It is not that rule. Whoever runs this holds
    `CARNET_DATABASE_URL` and can read `agent_grants` in the next shell, so refusing
    here protected nothing and cost the one person who asks this question their answer:
    *who could reach what the leaver owned?*

    The agent ladder is untouched — the CLI still cannot **run** this agent. What it may
    do is read, as an administrator of the tenant.
    """
    run(monkeypatch, "--share-agent", owned_agent, "u_priya", "--role", "editor")
    storage.active().revoke_agent(cli.DEFAULT_TENANT_ID, owned_agent, "system", "cli", actor="system:cli")
    capsys.readouterr()

    run(monkeypatch, "--agent-access", owned_agent)

    said = message(capsys)
    assert "u_priya" in said and "editor" in said
    assert "principal" in said and "granted by" in said, "the table, not a refusal"
    assert "usage:" not in said and "--add-tenant" not in said
    # Reading is not a grant: the operator is not in the sheet it just printed.
    assert "system:cli" not in {
        line.split()[0] for line in said.splitlines() if line.strip()
    }


def test_agent_access_refuses_with_a_sentence_and_never_the_usage_block(
    monkeypatch, owned_agent, capsys
):
    """The other half of the same finding: the refusal arrived through `parser.error`,
    which prints ~90 lines of argparse usage after a permission failure. Nothing was
    wrong with the *arguments*, so nothing about their shape belongs in the answer.

    Asserted on a name that does not exist, which is the one refusal `--agent-access`
    still makes. `--add-tenant` stands in for the usage block: argparse's banner lists
    every flag this CLI has, so its presence is the block's presence.
    """
    capsys.readouterr()

    fails(monkeypatch, "--agent-access", "ghost")

    said = message(capsys)
    assert "no agent named 'ghost'" in said
    assert "usage:" not in said
    assert "--add-tenant" not in said, "the flag list is the usage block"


def test_agent_access_on_an_orphaned_agent_says_nobody_can_run_it(
    monkeypatch, owned_agent, capsys
):
    """Reachable: revoking an owner is permitted and leaves an agent orphaned — and
    reachable *from here* since the operator reads as an administrator, which is what
    made this the one thing a shell can say about an agent nobody can run."""
    storage.active().revoke_agent(cli.DEFAULT_TENANT_ID, owned_agent, "system", "cli", actor="system:cli")
    capsys.readouterr()

    run(monkeypatch, "--agent-access", owned_agent)

    assert "Nobody has access" in message(capsys)


def test_sharing_refuses_without_a_database(monkeypatch, owned_agent, capsys):
    """Same guard as onboarding, and one worse: "I shared that with her last week" is
    a thing somebody will believe about a grant that went into a dict and died."""
    monkeypatch.setattr(cli, "DATABASE_URL", None)

    fails(monkeypatch, "--share-agent", owned_agent, "u_priya")

    assert "CARNET_DATABASE_URL" in message(capsys)


def test_list_marks_agents_the_cli_cannot_run(monkeypatch, owned_agent, capsys):
    """Marked, not hidden. Whoever runs this holds the database and can read the table,
    so filtering would be theatre — but an agent that `--agent` then refuses is a
    confusing five minutes."""
    storage.active().save_agent(
        cli.DEFAULT_TENANT_ID,
        {
            "name": "someone-elses",
            "system": "You are a demo agent.",
            "permissions": {
                "tools": ["post_message"],
                "scope": {"chat.channel": {"write": ["#eng"]}},
            },
        },
        actor="system:cli",
    )
    storage.active().grant_agent(
        cli.DEFAULT_TENANT_ID, "someone-elses", "user", "u_priya", role="owner", actor="system:cli")

    run(monkeypatch, "--list")

    said = message(capsys)
    assert "someone-elses" in said and "not shared" in said
    triage_line = next(line for line in said.splitlines() if line.startswith("triage"))
    assert "not shared" not in triage_line


# --- sharing by email -------------------------------------------------------------
#
# The interface people actually asked for. `--share-agent triage priya@acme.com` rather
# than an opaque id — which is what 6a and 6b shipped and what made the command awkward.


@pytest.fixture
def with_provider(owned_agent):
    """A provider for the default tenant, vouching for acme.com. Without one, no
    address could ever log in and every share by email is refused."""
    storage.active().save_tenant_idp(
        cli.DEFAULT_TENANT_ID,
        {
            "issuer": "https://acme.okta.example",
            "jwks_uri": "https://acme.okta.example/keys",
            "audience": "api://default",
            "allowed_domains": ("acme.com",),
        },
    )
    return owned_agent


def a_user(user_id, email):
    storage.active().create_user(
        cli.DEFAULT_TENANT_ID,
        {
            "id": user_id,
            "issuer": "https://acme.okta.example",
            "subject": user_id,
            "email": email,
        },
    )


def pending_on(agent_name):
    return {
        row["email"]: row["role"]
        for row in storage.active().list_pending_grants(
            cli.DEFAULT_TENANT_ID, agent_name
        )
    }


def test_sharing_with_a_known_address_grants_immediately(monkeypatch, with_provider, capsys):
    a_user("u_priya", "priya@acme.com")

    run(monkeypatch, "--share-agent", with_provider, "priya@acme.com")

    assert roles_on(with_provider)["user:u_priya"] == "user"
    assert "now has user access" in message(capsys)


def test_sharing_with_an_unknown_address_is_held(monkeypatch, with_provider, capsys):
    run(monkeypatch, "--share-agent", with_provider, "newhire@acme.com", "--role", "editor")

    assert pending_on(with_provider) == {"newhire@acme.com": "editor"}
    said = message(capsys)
    assert "has not logged in yet" in said
    assert "first time they sign in" in said, "should say when it will take effect"


def test_an_address_is_normalised_on_the_way_in(monkeypatch, with_provider):
    run(monkeypatch, "--share-agent", with_provider, "  NewHire@Acme.COM ")

    assert pending_on(with_provider) == {"newhire@acme.com": "user"}


def test_a_domain_nobody_vouches_for_is_refused(monkeypatch, with_provider, capsys):
    fails(monkeypatch, "--share-agent", with_provider, "someone@evil.example")

    assert "could never log in" in message(capsys)
    assert pending_on(with_provider) == {}


def test_ownership_cannot_be_left_waiting_on_an_address(monkeypatch, with_provider, capsys):
    """An agent owned by a row that is never claimed is an orphan made on purpose."""
    fails(monkeypatch, "--share-agent", with_provider, "newhire@acme.com", "--role", "owner")

    said = message(capsys)
    assert "nobody has logged in as" in said
    assert "orphan" in said
    assert "Share it at editor" in said, "should say what to do instead"
    assert roles_on(with_provider)["system:cli"] == "owner"


def test_ownership_can_be_handed_to_an_address_that_resolves(monkeypatch, with_provider):
    a_user("u_priya", "priya@acme.com")

    run(monkeypatch, "--share-agent", with_provider, "priya@acme.com", "--role", "owner")

    assert roles_on(with_provider) == {"user:u_priya": "owner", "system:cli": "editor"}


def test_a_principal_id_still_works(monkeypatch, with_provider):
    """Addresses are the interface; ids remain for what an address cannot name — a
    scheduler, or somebody whose provider supplies no email claim."""
    run(monkeypatch, "--share-agent", with_provider, "system:nightly")

    assert roles_on(with_provider)["system:nightly"] == "user"


def test_agent_access_lists_who_is_still_waiting(monkeypatch, with_provider, capsys):
    run(monkeypatch, "--share-agent", with_provider, "newhire@acme.com", "--role", "editor")
    run(monkeypatch, "--agent-access", with_provider)

    said = message(capsys)
    assert "waiting on a first login" in said
    assert "newhire@acme.com" in said and "editor" in said
    # Reported apart from real grants: nobody has this access yet.
    assert "system:cli" in said and "owner" in said


def test_an_invitation_can_be_cancelled(monkeypatch, with_provider, capsys):
    run(monkeypatch, "--share-agent", with_provider, "newhire@acme.com")
    run(monkeypatch, "--unshare-agent", with_provider, "newhire@acme.com")

    assert pending_on(with_provider) == {}
    assert "Cancelled the invitation" in message(capsys)


def test_unsharing_by_address_revokes_a_real_grant(monkeypatch, with_provider, capsys):
    a_user("u_priya", "priya@acme.com")
    run(monkeypatch, "--share-agent", with_provider, "priya@acme.com")

    run(monkeypatch, "--unshare-agent", with_provider, "priya@acme.com")

    assert "user:u_priya" not in roles_on(with_provider)
    assert "no longer has access" in message(capsys)


def test_a_refused_address_does_not_claim_the_operator_lacks_access(
    monkeypatch, with_provider, capsys
):
    """The bug a real run against Postgres found. `--share-agent` appends "it has not
    been shared with you at the level this needs" to a permission failure, which was
    being appended to a *domain* refusal too — telling the operator who owned the agent
    that they did not."""
    fails(monkeypatch, "--share-agent", with_provider, "someone@evil.example")

    said = message(capsys)
    assert "could never log in" in said
    assert "has not been shared with" not in said, (
        "a refused address was reported as the caller lacking access"
    )
    assert roles_on(with_provider)["system:cli"] == "owner"


# --- cancelling a run --------------------------------------------------------------
#
# Two shapes, and they are the same mechanism reached from opposite ends: `--cancel` for
# a run somebody else's worker is executing, and Ctrl-C for the one this process is
# executing itself. The second is the interesting one — a signal handler that does no I/O
# and a row that reaches `cancelled` anyway.


# --- groups -------------------------------------------------------------------------
#
# Group administration is the CLI's, running as `system:cli`, and there is deliberately
# no HTTP route — see `access/groups.py`. These cover the paths a person types, which is
# where step 9a's one real bug was: `--role owner` on a group crashed with a traceback,
# because the CLI calls `grants.transfer` directly and the guard lived in `grants.share`.


@pytest.fixture
def directory_provider(owned_agent):
    """An identity provider that names a groups claim — step 033e.

    Linking a group only takes its membership away from the administrator while the
    directory is actually speaking, so a test about that refusal has to say so.
    """
    storage.active().save_tenant_idp(
        cli.DEFAULT_TENANT_ID,
        {
            "issuer": "https://acme.okta.example",
            "jwks_uri": "https://acme.okta.example/v1/keys",
            "audience": "api://default",
            "groups_claim": "groups",
        },
    )


@pytest.fixture
def a_group(monkeypatch, owned_agent):
    """One group with two members, created the way a person would."""
    run(monkeypatch, "--add-group", "support", "The support team")
    run(monkeypatch, "--group-add", "support", "u_sam")
    run(monkeypatch, "--group-add", "support", "u_priya")
    return storage.active().find_group_by_name(cli.DEFAULT_TENANT_ID, "support")


def test_a_group_is_created_and_listed(monkeypatch, a_group, capsys):
    run(monkeypatch, "--groups")

    said = capsys.readouterr().out
    assert "support" in said
    assert a_group["group_id"] in said


def test_a_group_is_shared_with_by_name(monkeypatch, owned_agent, a_group):
    """`group:support` is what a person types; `group:g_...` is what the grant records."""
    run(monkeypatch, "--share-agent", owned_agent, "group:support", "--role", "user")

    assert roles_on(owned_agent)[f"group:{a_group['group_id']}"] == "user"


def test_a_group_grant_reaches_its_members(monkeypatch, owned_agent, a_group):
    run(monkeypatch, "--share-agent", owned_agent, "group:support")

    sam = Principal.user("u_sam", cli.DEFAULT_TENANT_ID)
    assert grants.check(sam, owned_agent) is True
    assert "user:u_sam" not in roles_on(owned_agent)


def test_agent_access_says_how_each_person_has_it(monkeypatch, owned_agent, a_group, capsys):
    run(monkeypatch, "--share-agent", owned_agent, "group:support")
    capsys.readouterr()

    run(monkeypatch, "--agent-access", owned_agent)

    said = capsys.readouterr()
    assert f"group:{a_group['group_id']}" in said.out
    # The warning about what an inherited access means for unsharing goes to stderr,
    # so it does not corrupt the table for anything reading it.
    assert "only through a group" in said.err


def test_one_directory_group_is_named_in_the_singular_all_the_way_through(
    monkeypatch, owned_agent, a_group, directory_provider, capsys
):
    """035h pass two. The verb agreed and the pronoun did not.

    `--agent-access` pluralised `follow{s}` and then hardcoded *"People placed in **them**
    there"*, so the commonest case there is — one directory-backed group on one agent —
    read as broken English. It matters more than a typo because `ShareSheet.tsx`'s comment
    cites this sentence as the one it agrees with: *"one fact should not read two ways
    depending on which door you are standing at."* It read two ways.
    """
    run(monkeypatch, "--group-link", "support", "dir-support")
    run(monkeypatch, "--share-agent", owned_agent, "group:support")
    capsys.readouterr()

    run(monkeypatch, "--agent-access", owned_agent)

    said = capsys.readouterr().err
    assert "follows your directory" in said
    assert "People placed in\nit there" in said
    assert "them there" not in said


def test_unsharing_an_inherited_access_is_refused(monkeypatch, owned_agent, a_group, capsys):
    """Decision 6 at the command line: the person who runs this must not be told the
    access is gone when it is not."""
    run(monkeypatch, "--share-agent", owned_agent, "group:support")

    fails(monkeypatch, "--unshare-agent", owned_agent, "u_sam")

    said = message(capsys)
    assert a_group["group_id"] in said
    assert grants.check(Principal.user("u_sam", cli.DEFAULT_TENANT_ID), owned_agent)


def test_sharing_a_group_at_owner_is_refused_with_a_sentence(
    monkeypatch, owned_agent, a_group, capsys
):
    """**The bug this step actually shipped and then fixed.**

    `--role owner` does not go through `grants.share`; it calls `grants.transfer`
    directly, so the guard had to be there. Before the fix this produced a
    `StorageError` traceback rather than a refusal, and every unit test passed because
    they all called `share`.
    """
    fails(monkeypatch, "--share-agent", owned_agent, "group:support", "--role", "owner")

    assert "cannot own" in message(capsys)
    assert roles_on(owned_agent)["system:cli"] == "owner"


def test_sharing_with_a_group_that_does_not_exist_names_the_ones_that_do(
    monkeypatch, owned_agent, a_group, capsys
):
    fails(monkeypatch, "--share-agent", owned_agent, "group:finance")

    said = message(capsys)
    assert "no group 'finance'" in said
    assert "support" in said


def test_sharing_with_an_empty_group_warns(monkeypatch, owned_agent, capsys):
    """A grant to a group with no members is a row that gives nobody anything and looks
    exactly like access."""
    run(monkeypatch, "--add-group", "nobody-yet")
    capsys.readouterr()

    run(monkeypatch, "--share-agent", owned_agent, "group:nobody-yet")

    assert "no members" in capsys.readouterr().err


def test_removing_a_member_takes_their_access(monkeypatch, owned_agent, a_group, capsys):
    run(monkeypatch, "--share-agent", owned_agent, "group:support")
    sam = Principal.user("u_sam", cli.DEFAULT_TENANT_ID)
    assert grants.check(sam, owned_agent) is True
    capsys.readouterr()

    run(monkeypatch, "--group-remove", "support", "u_sam")

    assert grants.check(sam, owned_agent) is False
    # Said out loud, because nothing tells the person who lost access.
    assert "have not been told" in capsys.readouterr().err


def test_deleting_a_group_takes_the_access_with_it(monkeypatch, owned_agent, a_group, capsys):
    run(monkeypatch, "--share-agent", owned_agent, "group:support")

    run(monkeypatch, "--delete-group", "support")

    assert grants.check(Principal.user("u_sam", cli.DEFAULT_TENANT_ID), owned_agent) is False
    assert roles_on(owned_agent) == {"system:cli": "owner"}


def test_deleting_a_group_that_is_not_there_is_an_error(monkeypatch, owned_agent, capsys):
    """Deliberately not idempotent, unlike `groups.delete` underneath it. Nothing
    retries a typed command, and "nothing to do" for a typo'd name reports success for
    an action that did nothing — the failure decision 6 exists to refuse."""
    fails(monkeypatch, "--delete-group", "finanace")

    assert "no group 'finanace'" in message(capsys)


def test_a_group_cannot_be_put_in_a_group(monkeypatch, a_group, capsys):
    run(monkeypatch, "--add-group", "leads")

    fails(monkeypatch, "--group-add", "leads", f"group:{a_group['group_id']}")

    assert "principal_kind" in message(capsys)


def test_a_group_is_linked_to_a_directory_and_says_what_that_costs(
    monkeypatch, a_group, capsys
):
    """Step 033e. Linking is a takeover, and the count of who is at risk stops being
    knowable the moment it starts happening — so it is printed before, the way
    `--delete-group` reports what a deletion is about to take."""
    run(monkeypatch, "--group-link", "support", "dir-support")

    said = capsys.readouterr()
    assert "follows directory group 'dir-support'" in said.out
    assert "at each person's next sign-in" in said.err
    assert "2 person(s) are in it now" in said.err

    row = storage.active().find_group_by_name(cli.DEFAULT_TENANT_ID, "support")
    assert row["external_id"] == "dir-support"


def test_a_linked_group_is_marked_in_both_listings(monkeypatch, a_group, capsys):
    run(monkeypatch, "--group-link", "support", "dir-support")
    capsys.readouterr()

    run(monkeypatch, "--groups")
    assert "dir-support" in capsys.readouterr().out

    run(monkeypatch, "--groups", "support")
    assert "Membership follows your directory" in capsys.readouterr().out


def test_a_person_may_not_be_hand_added_to_a_linked_group(
    monkeypatch, a_group, directory_provider, capsys
):
    """A row added here is deleted at that person's next sign-in — a write that reports
    success and does nothing."""
    run(monkeypatch, "--group-link", "support", "dir-support")

    fails(monkeypatch, "--group-add", "support", "u_new")
    assert "follows your directory" in message(capsys)

    fails(monkeypatch, "--group-remove", "support", "u_sam")
    assert "follows your directory" in message(capsys)


def test_unlinking_removes_nobody_and_hands_the_group_back(
    monkeypatch, a_group, directory_provider, capsys
):
    run(monkeypatch, "--group-link", "support", "dir-support")
    capsys.readouterr()

    run(monkeypatch, "--group-unlink", "support")

    assert "Nobody was removed" in capsys.readouterr().out
    run(monkeypatch, "--group-remove", "support", "u_sam")


def test_a_directory_id_another_group_holds_is_refused(monkeypatch, a_group, capsys):
    run(monkeypatch, "--add-group", "leads")
    run(monkeypatch, "--group-link", "support", "dir-support")

    fails(monkeypatch, "--group-link", "leads", "dir-support")

    assert "already has a group linked to directory" in message(capsys)


def test_the_claim_mapping_is_printed_by_the_command_that_writes_it(
    monkeypatch, owned_agent, capsys
):
    """`--add-idp` is an upsert, so re-running it to change one thing resets the rest.
    The line exists so a registration that dropped the groups claim is visible at the
    moment it happens rather than the week nobody joins a group."""
    run(
        monkeypatch,
        "--add-idp",
        cli.DEFAULT_TENANT_ID,
        "--issuer",
        "https://acme.okta.example",
        "--jwks-uri",
        "https://acme.okta.example/v1/keys",
        "--audience",
        "api://default",
        "--domain",
        "acme.com",
        "--groups-claim",
        "groups",
    )
    assert "groups=groups" in capsys.readouterr().out

    run(
        monkeypatch,
        "--add-idp",
        cli.DEFAULT_TENANT_ID,
        "--issuer",
        "https://acme.okta.example",
        "--jwks-uri",
        "https://acme.okta.example/v1/keys",
        "--audience",
        "api://default",
        "--domain",
        "acme.com",
    )
    said = capsys.readouterr().out
    assert "groups=<none>" in said
    assert "stays what --group-add makes it" in said

    run(monkeypatch, "--list-idps")
    assert "<none>" in capsys.readouterr().out


def test_group_commands_refuse_without_a_database(monkeypatch, capsys):
    """Same guard the other writes have: an in-memory group is a belief with nothing
    behind it, and "I put her in that group last week" is a thing somebody will say."""
    monkeypatch.setattr(cli, "DATABASE_URL", None)

    fails(monkeypatch, "--add-group", "support")

    assert "CARNET_DATABASE_URL" in message(capsys)


# --- the administrative log ---------------------------------------------------------


def test_the_admin_log_says_who_took_access_away(monkeypatch, owned_agent, capsys):
    """`--admin-log` was the whole read surface for migration 022, and plan 011 said why:
    a read route needs a tenant-admin role this platform did not have. **12b built the
    role, so `GET /admin-audit` exists** — and this stays, because it is the reader that
    works when the API is down and during the bootstrap, where there is by definition no
    administrator to sign in as. It exists because a log nobody can read is a log nobody
    notices is broken."""
    run(monkeypatch, "--share-agent", owned_agent, "u_priya", "--role", "editor")
    run(monkeypatch, "--unshare-agent", owned_agent, "u_priya")

    run(monkeypatch, "--admin-log")

    said = message(capsys)
    assert "grant.revoke" in said
    assert "system:cli" in said, "the record has to name whoever ran the command"
    assert "role=editor" in said, "and the level that was taken away"


def test_the_admin_log_on_a_tenant_with_no_changes_says_so(monkeypatch, capsys):
    run(monkeypatch, "--admin-log")

    assert "No administrative records" in message(capsys)


# --- platform roles ------------------------------------------------------------------
#
# `--grant-role` stays on the CLI and there is deliberately no HTTP route for it: a role
# model whose first version lets admins mint admins over HTTP hands a compromised admin
# token the one thing it lacks, in the step whose purpose is containment.


@pytest.fixture
def tenant_with_a_person():
    """The default tenant, and somebody who has logged in once."""
    store = storage.active()
    store.create_tenant(cli.DEFAULT_TENANT_ID, "Default")
    store.create_user(
        cli.DEFAULT_TENANT_ID,
        {
            "id": "u_priya",
            "issuer": "https://acme.okta.example",
            "subject": "00u-priya",
            "email": "priya@acme.com",
        },
    )
    return "u_priya"


def test_the_connection_listing_calls_the_stamp_changed_rather_than_connected(
    monkeypatch, tenant_with_a_person, capsys
):
    """**A live mislabel, corrected in 035f rather than copied onto a screen.**

    The column prints `connections.updated_at`, which a refresh and a reconnection both
    bump — so it has not meant *connected* since the first renewal. Migration 013 added it
    for the other question outright (*"when did this last change"*) and kept `created_at`
    distinct for the first one.

    Found while deciding what word the Connections page should use for the same field, and
    fixed here rather than recorded: a browser saying *changed* beside a shell saying
    *connected* about one column is how two surfaces develop two opinions about a fact,
    which is what `_state_of` refuses one field over.

    Asserted because it had no assertion — nothing in this suite read the header at all,
    which is why it was wrong for eleven steps and why the next person moving it should
    have to mean it.
    """
    from carnet.access import connections

    storage.active().allow_host(
        cli.DEFAULT_TENANT_ID, "jira.example", actor="system:test"
    )
    tools.register_connector(
        cli.DEFAULT_TENANT_ID, "jira", url="https://jira.example/mcp", actor="system:test"
    )
    connections.connect_account(
        Principal.user("u_priya", cli.DEFAULT_TENANT_ID),
        "jira",
        "a-pasted-token",
        actor="system:test",
    )

    run(monkeypatch, "--list-connections")

    header = message(capsys).splitlines()[0]

    assert "changed" in header
    assert "connected" not in header


def test_grant_role_makes_somebody_an_administrator(
    monkeypatch, tenant_with_a_person, capsys
):
    run(monkeypatch, "--grant-role", "admin", "priya@acme.com")

    assert storage.active().has_platform_role(
        cli.DEFAULT_TENANT_ID, "user", "u_priya", "admin"
    )
    said = message(capsys)
    assert "administrator" in said
    assert "no agent" in said, "it must say plainly that this is not a master key"


def test_a_role_is_granted_by_principal_id_too(monkeypatch, tenant_with_a_person):
    run(monkeypatch, "--grant-role", "admin", "system:nightly")

    assert storage.active().has_platform_role(
        cli.DEFAULT_TENANT_ID, "system", "nightly", "admin"
    )


def test_granting_a_role_to_an_address_nobody_has_used_is_refused(
    monkeypatch, tenant_with_a_person, capsys
):
    """**A role is not an invitation**, and this is sharper than `--connect-account`'s
    version of the same refusal: a pending admin grant promotes whoever eventually claims
    a mistyped or recycled address, silently, at login, weeks after somebody typed it."""
    fails(monkeypatch, "--grant-role", "admin", "newhire@acme.com")

    assert "not an invitation" in message(capsys)
    assert storage.active().list_platform_roles(cli.DEFAULT_TENANT_ID) == []


def test_granting_a_role_to_a_group_is_refused(
    monkeypatch, tenant_with_a_person, capsys
):
    """Otherwise group membership is self-service promotion."""
    fails(monkeypatch, "--grant-role", "admin", "group:g-oncall")

    assert "group cannot hold" in message(capsys)


def test_a_role_outside_the_vocabulary_is_refused(
    monkeypatch, tenant_with_a_person, capsys
):
    said = fails(monkeypatch, "--grant-role", "superuser", "priya@acme.com")

    assert "PLATFORM_ROLES" in message(capsys)
    assert said == "2", "argparse's own exit code, not a traceback"


def test_revoking_a_role_nobody_holds_says_so(monkeypatch, tenant_with_a_person, capsys):
    run(monkeypatch, "--revoke-role", "admin", "priya@acme.com")

    assert "Nothing to do" in message(capsys)
    assert storage.active().admin_audit_records(
        cli.DEFAULT_TENANT_ID, action="role.revoke"
    ) == []


def test_revoking_the_last_administrator_warns_rather_than_refusing(
    monkeypatch, tenant_with_a_person, capsys
):
    """Lockout is impossible — this command runs as `system:cli`, which is always an
    administrator — so the guard would defend a failure that cannot occur. What it gets
    instead is a sentence, because the *product* becomes unadministerable without a shell.
    """
    run(monkeypatch, "--grant-role", "admin", "priya@acme.com")
    capsys.readouterr()

    run(monkeypatch, "--revoke-role", "admin", "priya@acme.com")

    said = message(capsys)
    assert "no administrators" in said
    assert "--grant-role admin" in said, "and the way back"
    assert storage.active().list_platform_roles(cli.DEFAULT_TENANT_ID) == []


def test_list_roles_says_what_the_table_holds_and_what_it_cannot(
    monkeypatch, tenant_with_a_person, capsys
):
    """The note under the table is not decoration: `system` principals administer and hold
    no row, so a listing without it answers "who can administer this" incompletely — which
    is the one question it exists for."""
    run(monkeypatch, "--grant-role", "admin", "priya@acme.com")
    capsys.readouterr()

    run(monkeypatch, "--list-roles")

    said = message(capsys)
    assert "user:u_priya" in said
    assert "system:cli" in said
    assert "system` principal is an administrator" in said


def test_list_roles_on_a_tenant_with_none_still_says_the_rule(
    monkeypatch, tenant_with_a_person, capsys
):
    run(monkeypatch, "--list-roles")

    said = message(capsys)
    assert "No platform roles" in said
    assert "system:cli" in said


def test_granting_a_role_refuses_without_a_database(monkeypatch, capsys):
    """The worst member of that guard's list: it would print that somebody is an
    administrator and leave nothing behind, and they would not find out until a screen
    refused them."""
    monkeypatch.setattr(cli, "DATABASE_URL", "")

    fails(monkeypatch, "--grant-role", "admin", "priya@acme.com")

    assert "CARNET_DATABASE_URL" in message(capsys)


def test_a_granted_role_lets_that_person_administer_a_group(
    monkeypatch, tenant_with_a_person
):
    """The seam, end to end on the CLI: the refusal `access/groups.py` carried for three
    steps is now something a row lifts."""
    from carnet.access import groups
    from carnet.access.roles import RoleRequired
    from carnet.core import Principal as P

    priya = P.user("u_priya", cli.DEFAULT_TENANT_ID)

    with pytest.raises(RoleRequired):
        groups.create(priya, "oncall")

    run(monkeypatch, "--grant-role", "admin", "priya@acme.com")

    assert groups.create(priya, "oncall")["name"] == "oncall"


# --- the guards 12c moved out of this file ------------------------------------------
#
# Both of these were written here in earlier steps and both had to come down when a route
# grew a second caller, which is finding 3 of plan 012c. What stays here is the assertion
# that the *command* still refuses — the rule moved, the behaviour did not — and, for the
# consent flow, that the words are the seam's rather than a second copy that agrees today.


def test_set_oauth_refuses_a_stdio_connector_in_the_seams_own_words(
    monkeypatch, capsys
):
    """Verification 2: **the same sentence, byte for byte**, from the CLI and the seam.

    The point of moving a guard down is that there is one rule, and the only way to know
    it is one rule rather than two copies that happen to agree is to compare the strings.
    `--set-oauth` no longer decides this; `oauth.configure` does, and this command turns
    the refusal into a `parser.error`.

    The secret is **piped rather than prompted** — `_read_secret`'s other branch — which
    is also what makes the ordering change affordable. The check used to run before the
    prompt and now runs after it, so an operator pastes a secret and is then refused. It
    is never stored, never logged and never in argv, which is why that is annoyance
    rather than exposure.
    """
    from carnet.access import oauth

    storage.active().create_tenant(cli.DEFAULT_TENANT_ID, "Default")
    tools.save_connector(cli.DEFAULT_TENANT_ID, GITHUB, actor="system:test")
    monkeypatch.setattr(sys, "stdin", io.StringIO("MARKER-CLIENT-SECRET-e3f1\n"))

    fails(
        monkeypatch,
        "--set-oauth",
        GITHUB.id,
        "--auth-server",
        "https://auth.example.com",
        "--client-id",
        "client-abc",
    )

    assert oauth.STDIO_CONSENT_REFUSED.format(connector=GITHUB.id) in message(capsys)


def test_allow_host_warns_in_the_seams_own_words(monkeypatch, capsys):
    """The other moved guard, and the row is written anyway.

    `--allow-host localhost` answered *"Tenant 'default' will now dial 'localhost'"* until
    step 012 — false, and being told yes about a control that is not in force is the
    precise failure `egress.py` is written against. The warning stays; what moved is the
    sentence, because `POST /admin/hosts` has no stderr to print it to and a route that
    reworded it would be a second answer to *did this approval do anything*.

    **A warning and not a refusal**, asserted by reading the table afterwards: the row
    records that somebody asked, and nothing will act on it.
    """
    from carnet.tools.mcp import egress

    storage.active().create_tenant(cli.DEFAULT_TENANT_ID, "Default")

    run(monkeypatch, "--allow-host", "localhost")

    assert egress.approval_warning("localhost") in message(capsys)
    assert [row["host"] for row in storage.active().allowed_hosts(cli.DEFAULT_TENANT_ID)] == [
        "localhost"
    ]


def test_allow_host_says_nothing_extra_about_a_host_it_will_actually_dial(
    monkeypatch, capsys
):
    """The other half, so the test above cannot pass by the warning being unconditional."""
    storage.active().create_tenant(cli.DEFAULT_TENANT_ID, "Default")

    run(monkeypatch, "--allow-host", "mcp.acme.com")

    said = message(capsys)
    assert "will now dial 'mcp.acme.com'" in said
    assert "will NOT be dialled" not in said


# --- deleting a customer, step 018 --------------------------------------------------


DOOMED_AGENT = {
    "name": "issue-reporter",
    "runtime": "simple",
    "system": "You read issues.",
    "permissions": {"tools": [], "scope": {}},
}


class _Terminal(io.StringIO):
    """A stdin that says it is one. `--delete-tenant` refuses everything else."""

    def isatty(self):
        return True


def _at_a_terminal(monkeypatch, typed=""):
    """Put the operator in front of the command.

    Every test below that gets as far as the confirmation needs this, since the fix
    for 072's third finding:
    the check is `sys.stdin.isatty()` and pytest's stdin is not a terminal, so without
    it these would all pass on the refusal instead of on what they claim to be about.
    """
    monkeypatch.setattr(sys, "stdin", _Terminal(typed))


def _doomed(monkeypatch):
    """A customer with something in them, suspended and ready to be deleted."""
    _at_a_terminal(monkeypatch)
    run(monkeypatch, "--add-tenant", TENANT, "Acme Corp")
    store = storage.active()
    store.save_agent(TENANT, DOOMED_AGENT, actor="system:cli")
    store.append_audit(
        TENANT,
        {
            "v": 6,
            "ts": datetime.now(timezone.utc),
            "run_id": "r-1",
            "principal_kind": "system",
            "principal_id": "cli",
            "agent": DOOMED_AGENT["name"],
            "tool": "post_message",
            "args": {},
            "decision": "allow",
        },
    )
    run(monkeypatch, "--tenant-status", TENANT, "suspended")
    return store


def test_deleting_a_tenant_needs_the_tenant_id_typed(monkeypatch, capsys):
    """The confirmation is the id itself, not a fixed word.

    `--fresh` types 'fresh', which is right for a local scratch database and wrong here:
    a fixed word can be pasted out of a runbook without reading the line above it, and
    the thing that has to be read is *which customer*.
    """
    store = _doomed(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")

    with pytest.raises(SystemExit) as caught:
        run(monkeypatch, "--delete-tenant", TENANT)

    assert "nothing deleted" in str(caught.value)
    assert store.get_tenant(TENANT) is not None
    assert len(store.audit_records(TENANT)) == 1


def test_deleting_a_tenant_says_what_it_will_destroy_before_asking(monkeypatch, capsys):
    """Counted from the database rather than described in general terms — the same
    numbers the tombstone will carry, so the prompt and the record cannot tell
    different stories."""
    _doomed(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda _prompt: "")

    with pytest.raises(SystemExit):
        run(monkeypatch, "--delete-tenant", TENANT)

    said = message(capsys)
    assert "1  agents" in said
    assert "1  audit records" in said
    assert "can never be created again" in said


def test_deleting_a_tenant_erases_it_and_leaves_a_tombstone(monkeypatch, capsys):
    store = _doomed(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda _prompt: TENANT)

    run(monkeypatch, "--delete-tenant", TENANT)

    assert store.get_tenant(TENANT) is None
    tombstone = store.get_tenant_tombstone(TENANT)
    assert tombstone["actor"] == "system:cli"
    assert tombstone["detail"]["rows"]["audit"] == 1
    assert "is deleted" in message(capsys)


def test_deleting_an_active_tenant_is_refused_by_the_cli(monkeypatch, capsys):
    """The storage refusal, surfaced as a sentence rather than a traceback."""
    _at_a_terminal(monkeypatch)
    run(monkeypatch, "--add-tenant", TENANT, "Acme Corp")
    monkeypatch.setattr("builtins.input", lambda _prompt: TENANT)

    fails(monkeypatch, "--delete-tenant", TENANT)

    assert "Suspend it first" in message(capsys)
    assert storage.active().get_tenant(TENANT) is not None


def test_deleting_an_unknown_tenant_says_so(monkeypatch, capsys):
    fails(monkeypatch, "--delete-tenant", "never-existed")

    assert "no tenant" in message(capsys)


def test_deleting_a_deleted_tenant_answers_with_the_tombstone(monkeypatch, capsys):
    """More useful than "no such tenant", which is indistinguishable from a typo."""
    _doomed(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda _prompt: TENANT)
    run(monkeypatch, "--delete-tenant", TENANT)
    capsys.readouterr()

    with pytest.raises(SystemExit) as caught:
        run(monkeypatch, "--delete-tenant", TENANT)

    assert caught.value.code == 0
    said = message(capsys)
    assert "was already deleted" in said
    assert "system:cli" in said


def test_adding_a_deleted_tenants_id_back_is_a_sentence_not_a_traceback(
    monkeypatch, capsys
):
    """Found by typing the command rather than by reading the code: `create_tenant`
    acquired a refusal in 018 and `--add-tenant` had no catch, so it arrived as a
    traceback. That is `api/errors.py`'s family in its CLI form."""
    _doomed(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda _prompt: TENANT)
    run(monkeypatch, "--delete-tenant", TENANT)

    fails(monkeypatch, "--add-tenant", TENANT, "Acme Reborn")

    assert "never reused" in message(capsys)


def test_prune_logs_without_a_policy_is_refused(monkeypatch, capsys):
    """Deliberately not a way to prune without a configured window. A flag that could
    delete records with no policy would be a second, undocumented retention policy
    living in somebody's shell history."""
    monkeypatch.setattr("carnet.config.RETENTION_DAYS", None)

    fails(monkeypatch, "--prune-logs")

    said = message(capsys)
    assert "no retention policy is configured" in said
    assert "CARNET_RETENTION_DAYS" in said


def test_deleting_a_tenant_refuses_when_there_is_no_terminal(monkeypatch, capsys):
    """A CI job, a cron entry, a closed pipe. Found by running it with stdin closed,
    where it raised an unhandled `EOFError` out of the most destructive command here.

    Refusing is the only defensible answer: the confirmation exists so a person reads
    which customer is about to be destroyed, and nothing read it. There is deliberately
    no `--yes` to add later.
    """
    store = _doomed(monkeypatch)
    monkeypatch.setattr(sys, "stdin", io.StringIO())

    def nobody_is_asked(_prompt):
        raise AssertionError("it must not reach the prompt without a terminal")

    monkeypatch.setattr("builtins.input", nobody_is_asked)

    with pytest.raises(SystemExit) as caught:
        run(monkeypatch, "--delete-tenant", TENANT)

    assert "nothing deleted" in str(caught.value)
    assert "will not run unattended" in str(caught.value)
    assert store.get_tenant(TENANT) is not None
    assert len(store.audit_records(TENANT)) == 1


def test_the_refusal_names_the_terminal_and_the_one_way_past_it(monkeypatch):
    """Both halves, because a refusal that names neither is a puzzle.

    The sentence has to say *terminal* — that is the guarantee somebody relies on when
    deciding whether this command is safe to put in a script — and it has to name the
    rehearsal variable, because the one caller that legitimately needs past it should not
    have to find it by reading the source.
    """
    _doomed(monkeypatch)
    monkeypatch.setattr(sys, "stdin", io.StringIO())

    with pytest.raises(SystemExit) as caught:
        run(monkeypatch, "--delete-tenant", TENANT)

    said = str(caught.value)
    assert "needs a terminal to confirm in" in said
    assert cli.DELETION_REHEARSAL_ENV in said
    assert "e2e_tenant_deletion.py" in said, "should say what it is for"


def test_a_piped_tenant_id_no_longer_deletes_a_customer(monkeypatch, capsys):
    """**Step 072's drill, as a test.** `echo <id> | carnet --delete-tenant <id>` used
    to work: the check was that `input()` did not raise, which a pipe satisfies, while the
    sentence it printed otherwise claimed a person was required.

    Driven through `input()` reading a patched `sys.stdin` rather than through a patched
    `input`, because a patched `input` cannot tell a pipe from a keyboard — which is the
    exact confusion the defect was made of.
    """
    store = _doomed(monkeypatch)
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"{TENANT}\n"))

    with pytest.raises(SystemExit) as caught:
        run(monkeypatch, "--delete-tenant", TENANT)

    assert "nothing deleted" in str(caught.value)
    assert store.get_tenant(TENANT) is not None
    assert store.get_tenant_tombstone(TENANT) is None


def test_the_rehearsal_variable_lets_the_e2e_through_and_nothing_else(
    monkeypatch, capsys
):
    """The documented way past, which `scripts/e2e_tenant_deletion.py` sets and which
    nothing reaches by accident: it is an environment variable whose name is a sentence
    about what setting it means.

    The confirmation is still typed and still checked — the variable buys a rehearsal a
    prompt it can answer, not a `--yes`.
    """
    store = _doomed(monkeypatch)
    monkeypatch.setenv(cli.DELETION_REHEARSAL_ENV, "yes")
    monkeypatch.setattr(sys, "stdin", io.StringIO(f"{TENANT}\n"))

    run(monkeypatch, "--delete-tenant", TENANT)

    assert store.get_tenant(TENANT) is None
    assert store.get_tenant_tombstone(TENANT)["actor"] == "system:cli"
    assert "is deleted" in message(capsys)


def test_the_rehearsal_variable_still_checks_what_was_typed(monkeypatch, capsys):
    """Set the variable and pipe the wrong word: nothing is deleted. The gate is about
    who may be asked, not about what the answer has to be."""
    store = _doomed(monkeypatch)
    monkeypatch.setenv(cli.DELETION_REHEARSAL_ENV, "yes")
    monkeypatch.setattr(sys, "stdin", io.StringIO("yes\n"))

    with pytest.raises(SystemExit) as caught:
        run(monkeypatch, "--delete-tenant", TENANT)

    assert str(caught.value) == "nothing deleted."
    assert store.get_tenant(TENANT) is not None


def test_ctrl_d_at_a_terminal_deletes_nothing(monkeypatch, capsys):
    """The `EOFError` branch, still reachable past the terminal check: somebody reads
    which customer this is and presses Ctrl-D instead of typing it."""
    store = _doomed(monkeypatch)

    def eof(_prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)

    with pytest.raises(SystemExit) as caught:
        run(monkeypatch, "--delete-tenant", TENANT)

    assert "nothing deleted" in str(caught.value)
    assert store.get_tenant(TENANT) is not None


# --- api tokens, step 020 ---------------------------------------------------------
#
# Minting stays on the CLI on 12b decision 5's argument made sharper: what a stolen
# bearer token lacks is persistence, and a mint route would hand it a durable successor
# that outlives both its own expiry and its holder's employment.


def _token_string(said: str) -> str:
    """The token out of what `--mint-token` printed. The only copy there is.

    Takes the captured text rather than `capsys`, because `message()` drains the buffer
    and a helper that quietly consumed it would leave the caller asserting against "".
    """
    for line in said.splitlines():
        if line.strip().startswith("art_"):
            return line.strip()
    raise AssertionError(f"no token in output:\n{said}")


def test_mint_token_prints_the_secret_exactly_once(
    monkeypatch, tenant_with_a_person, capsys
):
    """And the secret is nowhere in the database afterwards, which is the assertion
    worth having: what is stored is a digest, so nothing can show it again."""
    run(monkeypatch, "--mint-token", "nightly-ci", "priya@acme.com")

    said = message(capsys)
    presented = _token_string(said)
    secret = presented.rsplit(".", 1)[1]

    assert said.count(presented) == 1
    assert "only time that string exists" in said

    rows = storage.active().list_api_tokens(cli.DEFAULT_TENANT_ID)
    assert [row["name"] for row in rows] == ["nightly-ci"]
    stored = storage.active().find_api_token(rows[0]["id"])
    assert secret not in repr(stored)


def test_a_minted_token_resolves_to_a_machine_that_administers_nothing(
    monkeypatch, tenant_with_a_person, capsys
):
    """The CLI half of the escalation trap: what comes back out of the string this
    command printed is a `machine`, and `roles.is_admin` is false for it."""
    from carnet.access import roles, tokens

    run(monkeypatch, "--mint-token", "nightly-ci", "priya@acme.com")

    principal = tokens.resolve(_token_string(message(capsys)))

    assert principal.kind == "machine"
    assert roles.is_admin(principal) is False


def test_mint_says_the_token_can_run_nothing_yet(
    monkeypatch, tenant_with_a_person, capsys
):
    """A credential that silently could do nothing would read as a broken mint. It says
    so, and it says the exact command that fixes it.

    **This test asserted the wrong string for two steps, and its own docstring said so.**
    It claimed the suggestion was spelled *"the way `--share-agent` parses it"* while
    pinning `--share-agent <agent> machine:<id> user` — which argparse refuses with
    *"unrecognized arguments: user"*, because the level is `--role` and the command takes
    exactly two positionals. A string assertion cannot tell a command from a sentence, so
    the assertion below **runs** what was printed. Found in 022 by copying the line into
    another function and then typing it.
    """
    run(monkeypatch, "--mint-token", "nightly-ci", "priya@acme.com")

    said = message(capsys)
    token_id = storage.active().list_api_tokens(cli.DEFAULT_TENANT_ID)[0]["id"]
    assert "call nothing yet" in said
    assert f"--share-agent <agent> machine:{token_id} --role user" in said

    # And it is a command rather than a sentence: run it, with a real agent in place of
    # the placeholder, and require that the grant lands.
    storage.active().save_agent(
        cli.DEFAULT_TENANT_ID,
        {"name": "scheduled", "system": "s", "permissions": {"tools": [], "scope": {}}},
        actor="system:cli",
    )
    # `--share-agent` is itself an act that needs authority — the CLI principal must own
    # the agent. Granted here rather than worked around, because a test that ran the
    # command as somebody who could not have run it would prove less than it looks.
    storage.active().grant_agent(
        cli.DEFAULT_TENANT_ID, "scheduled", "system", "cli", role="owner",
        granted_by="system:cli", actor="system:cli",
    )
    # `startswith`, not `in`: argparse's `usage:` banner names every flag this CLI has.
    suggestion = next(
        line.strip()
        for line in said.splitlines()
        if line.strip().startswith("--share-agent")
    ).replace("<agent>", "scheduled")
    run(monkeypatch, *suggestion.split())

    assert storage.active().agent_grant_role(
        cli.DEFAULT_TENANT_ID, "scheduled", "machine", token_id
    ) == "user"


def test_mint_as_owner_says_what_it_made_and_suggests_no_grant(
    monkeypatch, tenant_with_a_person, capsys
):
    """Step 033d. The service hint names the exact command (`--share-agent ...
    machine:<id>`) that `grants.share` now REFUSES for a personal token — so the
    personal print must not contain it, on this file's own suggested-command lesson
    one test up: a printed command somebody types and watches fail is this CLI's
    recorded defect shape. What is printed instead is what is true — the owner's
    access is the token's, live."""
    run(monkeypatch, "--mint-token", "priya-editor", "priya@acme.com", "--as-owner")

    said = message(capsys)
    row = storage.active().list_api_tokens(cli.DEFAULT_TENANT_ID)[0]
    assert row["acts_as_owner"] is True
    assert "personal" in said
    assert "call whatever" in said
    assert "--share-agent" not in said
    assert "call nothing yet" not in said


def test_a_personal_name_is_the_owners_and_may_match_a_service_tokens(
    monkeypatch, tenant_with_a_person, capsys
):
    """Migration 054. A personal token and a service token may share a name — they are
    never on the same list — and one person may not hold two live personal tokens by one
    name. The refusal names the owner, which on this command is the person the operator
    typed, not the customer."""
    run(monkeypatch, "--mint-token", "agent", "priya@acme.com")
    capsys.readouterr()
    run(monkeypatch, "--mint-token", "agent", "priya@acme.com", "--as-owner")
    capsys.readouterr()
    assert len(storage.active().list_api_tokens(cli.DEFAULT_TENANT_ID)) == 2

    fails(monkeypatch, "--mint-token", "agent", "priya@acme.com", "--as-owner")

    said = message(capsys)
    assert "this owner already has a live personal token called 'agent'" in said
    assert "Revoking the old one frees the name" in said


def test_reach_says_whose_day_the_ceilings_count(monkeypatch, tenant_with_a_person, capsys):
    """Step 108, decision 7: `--reach` is the command an administrator reads before
    asking why a token was refused, and for a personal token the answer is often another
    machine's morning. Both kinds say which applies."""
    run(monkeypatch, "--mint-token", "priya-editor", "priya@acme.com", "--as-owner")
    capsys.readouterr()
    run(monkeypatch, "--mint-token", "nightly-ci", "priya@acme.com")
    capsys.readouterr()
    rows = {row["name"]: row["id"] for row in storage.active().list_api_tokens(cli.DEFAULT_TENANT_ID)}

    run(monkeypatch, "--reach", rows["priya-editor"])
    assert "shared with every personal token user:u_priya holds" in message(capsys)

    run(monkeypatch, "--reach", rows["nightly-ci"])
    assert "this token's own" in message(capsys)


def test_list_tokens_shows_the_kind(monkeypatch, tenant_with_a_person, capsys):
    """The kind column is also where an operator holding a `machine:m_...` string
    from an old audit record reads the "via" half — derived from this table at read
    time, never stored per record."""
    run(monkeypatch, "--mint-token", "nightly-ci", "priya@acme.com")
    capsys.readouterr()
    run(monkeypatch, "--mint-token", "priya-editor", "priya@acme.com", "--as-owner")
    capsys.readouterr()

    run(monkeypatch, "--list-tokens")

    lines = message(capsys).splitlines()
    assert any("nightly-ci" in line and "service" in line for line in lines)
    assert any("priya-editor" in line and "personal" in line for line in lines)


def test_a_token_owner_must_be_a_person(monkeypatch, tenant_with_a_person, capsys):
    fails(monkeypatch, "--mint-token", "ci", "machine:m_abc")

    assert "must be a person" in message(capsys)
    assert storage.active().list_api_tokens(cli.DEFAULT_TENANT_ID) == []


def test_minting_for_an_address_nobody_has_used_is_refused(
    monkeypatch, tenant_with_a_person, capsys
):
    """`--grant-role`'s refusal, one step further on: every request re-reads the owner,
    so a token owned by nobody could never make one. Failing at mint is the same
    refusal, six weeks earlier and with somebody watching."""
    fails(monkeypatch, "--mint-token", "ci", "newhire@acme.com")

    assert "not an invitation" in message(capsys)
    assert storage.active().list_api_tokens(cli.DEFAULT_TENANT_ID) == []


def test_two_live_tokens_cannot_share_a_name(monkeypatch, tenant_with_a_person, capsys):
    """A `ValueRefused` from the store arriving as a refusal rather than a traceback —
    018's `--add-tenant` lesson, which is `api/errors.py`'s family in its CLI form."""
    run(monkeypatch, "--mint-token", "ci", "priya@acme.com")
    capsys.readouterr()

    fails(monkeypatch, "--mint-token", "ci", "priya@acme.com")

    said = message(capsys)
    assert "already has a live API token called" in said
    # The sentence has to say what to do about it, because the operator reading it is
    # usually mid-incident and the answer is not obvious.
    assert "Revoking the old one frees the name" in said


def test_revoking_frees_the_name_so_a_replacement_can_be_minted(
    monkeypatch, tenant_with_a_person, capsys
):
    """The edge hunt's first defect, from the terminal: a leaked `nightly-ci` is revoked
    and its replacement takes the name the pipeline's config already refers to."""
    run(monkeypatch, "--mint-token", "nightly-ci", "priya@acme.com")
    first = storage.active().list_api_tokens(cli.DEFAULT_TENANT_ID)[0]["id"]
    run(monkeypatch, "--revoke-token", first)
    capsys.readouterr()

    run(monkeypatch, "--mint-token", "nightly-ci", "priya@acme.com")

    rows = storage.active().list_api_tokens(cli.DEFAULT_TENANT_ID)
    assert [row["name"] for row in rows] == ["nightly-ci", "nightly-ci"]
    assert sum(1 for row in rows if row["revoked_at"] is None) == 1


def test_expires_days_must_be_at_least_one(monkeypatch, tenant_with_a_person, capsys):
    """`RETENTION_DAYS`' argument: "off" and "expired already" must not share a
    spelling, and there is a command that means the second one."""
    fails(monkeypatch, "--mint-token", "ci", "priya@acme.com", "--expires-days", "0")

    said = message(capsys)
    assert "at least 1" in said
    assert "--revoke-token" in said


def test_an_absurd_expiry_is_refused_not_a_traceback(
    monkeypatch, tenant_with_a_person, capsys
):
    """Found by an edge hunt. `--expires-days 100000000` overflowed the date arithmetic
    and arrived as an `OverflowError` traceback — the same family as every other refusal
    on this path, through a door nobody had tried.

    Refused rather than clamped: silently turning a hundred million days into year 9999
    answers a question the operator did not ask. The ceiling is what a date can
    represent, so there is no invented number here to re-derive later.
    """
    fails(monkeypatch, "--mint-token", "ci", "priya@acme.com",
          "--expires-days", "100000000")

    said = message(capsys)
    assert "further ahead than a date can be written" in said
    assert "Traceback" not in said
    assert storage.active().list_api_tokens(cli.DEFAULT_TENANT_ID) == []


def test_a_long_but_writable_expiry_is_accepted(monkeypatch, tenant_with_a_person):
    """The other side of the ceiling: ten years is ordinary and must not be caught by it."""
    run(monkeypatch, "--mint-token", "decade", "priya@acme.com", "--expires-days", "3650")

    assert storage.active().list_api_tokens(cli.DEFAULT_TENANT_ID)[0]["expires_at"]


def test_minting_without_a_database_is_refused(monkeypatch, tenant_with_a_person, capsys):
    """Plan edge 17, and the sharpest member of the durability-guard list: `--mint-token`
    **prints a secret**. Without a database the row dies with the process, so the operator
    is left holding a credential that authenticates against nothing — and the only copy
    has already been shown, so re-running is not a recovery but a second dead secret."""
    monkeypatch.setattr(cli, "DATABASE_URL", "")

    fails(monkeypatch, "--mint-token", "ci", "priya@acme.com")

    said = message(capsys)
    assert "CARNET_DATABASE_URL" in said
    assert "art_" not in said, "a refused mint must not have printed a secret first"


def test_revoke_stamps_the_row_and_keeps_it(monkeypatch, tenant_with_a_person, capsys):
    run(monkeypatch, "--mint-token", "ci", "priya@acme.com")
    token_id = storage.active().list_api_tokens(cli.DEFAULT_TENANT_ID)[0]["id"]
    capsys.readouterr()

    run(monkeypatch, "--revoke-token", token_id)

    assert "is revoked" in message(capsys)
    row = storage.active().find_api_token(token_id)
    assert row is not None and row["revoked_at"] is not None


def test_revoking_an_unknown_token_is_refused_not_silent(
    monkeypatch, tenant_with_a_person, capsys
):
    fails(monkeypatch, "--revoke-token", "m_nosuchtoken")

    assert "no API token with id" in message(capsys)


def test_list_tokens_shows_revoked_ones_and_what_they_are(
    monkeypatch, tenant_with_a_person, capsys
):
    """A revoked row that vanished would look like a token somebody deleted, and there
    is no delete."""
    run(monkeypatch, "--mint-token", "live-one", "priya@acme.com")
    run(monkeypatch, "--mint-token", "dead-one", "priya@acme.com")
    token_id = [
        row["id"]
        for row in storage.active().list_api_tokens(cli.DEFAULT_TENANT_ID)
        if row["name"] == "dead-one"
    ][0]
    run(monkeypatch, "--revoke-token", token_id)
    capsys.readouterr()

    run(monkeypatch, "--list-tokens")

    said = message(capsys)
    assert "live-one" in said and "live" in said
    assert "dead-one" in said and "revoked" in said
    assert "never" in said, "an unused token must say so — it is what a review reads"


def test_list_tokens_on_an_empty_tenant_says_how_to_make_one(
    monkeypatch, tenant_with_a_person, capsys
):
    run(monkeypatch, "--list-tokens")

    said = message(capsys)
    assert "No API tokens" in said
    assert "--mint-token" in said


# --- a nonconforming answer at the terminal (step 024) -----------------------------


# --- finishing a key rotation (026) ------------------------------------------------
#
# The sweep's semantics live in test_rotation.py; what is under test here is the
# command — the guard, the wiring, the verdict sentence and the exit codes, because
# the printout is the drill's transcript and the exit code is what a runbook branches
# on.


def test_finish_rotation_needs_a_database(monkeypatch, capsys):
    monkeypatch.setattr(cli, "DATABASE_URL", "")
    with pytest.raises(SystemExit) as caught:
        run(monkeypatch, "--finish-rotation")
    assert caught.value.code == 2
    assert "this command writes" in message(capsys)


def test_finish_rotation_reseals_and_prints_the_verdict(monkeypatch, capsys):
    """One connection under a retired key: swept, and the done-when sentence lands."""
    from conftest import TEST_ACTOR, TEST_TENANT

    monkeypatch.delenv(crypto.KEY_ENV, raising=False)
    monkeypatch.delenv(crypto.OLD_KEYS_ENV, raising=False)

    key_a, key_b = b"\xaa" * crypto.KEY_BYTES, b"\xbb" * crypto.KEY_BYTES
    store = storage.active()
    store.save_connector(
        TEST_TENANT, {"id": "jira", "launch": {}, "vetted": []}, actor=TEST_ACTOR
    )
    sealed, key_id = crypto.LocalKeyCipher(key_a).seal(
        "priya-token",
        tenant_id=TEST_TENANT,
        aad=crypto.connection_aad(TEST_TENANT, "user", "u_priya", "jira"),
    )
    store.save_connection(
        TEST_TENANT, "user", "u_priya", "jira",
        ciphertext=sealed, key_id=key_id, actor=TEST_ACTOR,
    )
    crypto.configure(crypto.LocalKeyCipher(key_b, [key_a]))

    with pytest.raises(SystemExit) as caught:
        run(monkeypatch, "--finish-rotation")

    assert caught.value.code == 0
    said = message(capsys)
    assert "1 re-sealed" in said
    assert "No row names a retired key." in said
    assert "can be emptied" in said
    assert store.find_connection(TEST_TENANT, "user", "u_priya", "jira")["key_id"] == (
        crypto.LocalKeyCipher(key_b).key_id
    )


def test_finish_rotation_with_nothing_to_do_is_the_status_check(monkeypatch, capsys):

    monkeypatch.delenv(crypto.KEY_ENV, raising=False)
    monkeypatch.delenv(crypto.OLD_KEYS_ENV, raising=False)

    with pytest.raises(SystemExit) as caught:
        run(monkeypatch, "--finish-rotation")

    assert caught.value.code == 0
    said = message(capsys)
    assert "No row names a retired key." in said
    assert "none listed" in said


def test_finish_rotation_exits_1_when_a_row_cannot_be_read_at_all(monkeypatch, capsys):
    """**The rotation is finished and the command still fails, on purpose.** The verdict
    about emptying the old list stays true — a row naming a key nobody holds is not
    helped by keeping it — but a deployment holding rows it cannot decrypt is not clean,
    and a runbook branching on the exit code must stop. The sharp case this was found
    for: an operator who dropped the old key *before* sweeping would otherwise have been
    told exit 0, "rotation complete", with every credential under that key unreadable."""
    from conftest import TEST_ACTOR, TEST_TENANT

    monkeypatch.delenv(crypto.KEY_ENV, raising=False)
    monkeypatch.delenv(crypto.OLD_KEYS_ENV, raising=False)

    key_b, key_lost = b"\xbb" * crypto.KEY_BYTES, b"\xcc" * crypto.KEY_BYTES
    store = storage.active()
    store.save_connector(
        TEST_TENANT, {"id": "jira", "launch": {}, "vetted": []}, actor=TEST_ACTOR
    )
    sealed, key_id = crypto.LocalKeyCipher(key_lost).seal(
        "unreachable",
        tenant_id=TEST_TENANT,
        aad=crypto.connection_aad(TEST_TENANT, "user", "u_lost", "jira"),
    )
    store.save_connection(
        TEST_TENANT, "user", "u_lost", "jira",
        ciphertext=sealed, key_id=key_id, actor=TEST_ACTOR,
    )
    crypto.configure(crypto.LocalKeyCipher(key_b))

    with pytest.raises(SystemExit) as caught:
        run(monkeypatch, "--finish-rotation")

    assert caught.value.code == 1
    said = message(capsys)
    # Both facts, printed apart: the rotation is done, and this is a separate problem.
    assert "No row names a retired key." in said
    assert "never held" in said
    assert "put it back" in said
    # Nothing was destroyed — restoring the key is still the remedy that works.
    assert store.find_connection(
        TEST_TENANT, "user", "u_lost", "jira"
    )["ciphertext"] == sealed


# --- step 028: --upload ---------------------------------------------------------------
#
# The CLI takes the same two steps the API does — `store_upload`, then `submit` with the
# id — through the *same* functions, so a file the CLI accepts is a file the server
# accepts and a refusal reads the same in both places. What is CLI-only is the extension
# map: a file on disk has no Content-Type, so this is where the claim comes from.


def test_a_group_linked_before_its_provider_is_still_the_admins(
    monkeypatch, a_group, capsys
):
    """The freeze this seam could have caused, pinned. A group linked in a workspace
    whose provider names no groups claim is filled by nothing — so if hand edits were
    refused too, it would be editable by **nobody**, and the way out (unlink) is one
    nothing tells the administrator about."""
    run(monkeypatch, "--group-link", "support", "dir-support")

    run(monkeypatch, "--group-add", "support", "u_new")
    run(monkeypatch, "--group-remove", "support", "u_sam")


def test_clearing_the_groups_claim_hands_the_groups_back(
    monkeypatch, a_group, directory_provider, capsys
):
    """The other direction, which the upgrade note promises: a provider re-registered
    without `--groups-claim` stops speaking for its groups, and the memberships it left
    become the administrator's again rather than frozen where they stand."""
    run(monkeypatch, "--group-link", "support", "dir-support")
    fails(monkeypatch, "--group-add", "support", "u_new")

    storage.active().save_tenant_idp(
        cli.DEFAULT_TENANT_ID,
        {
            "issuer": "https://acme.okta.example",
            "jwks_uri": "https://acme.okta.example/v1/keys",
            "audience": "api://default",
        },
    )

    run(monkeypatch, "--group-add", "support", "u_new")

# --- editing a schedule and rotating a trigger, step 035k ----------------------------
#
# **Parity is the point of these being here at all.** The register row that asked for
# `PATCH /agents/{name}/schedules/{id}` says *"the CLI must gain the same verb in the same
# step"*, on 12c's argument that a capability reachable from one door and not the other is
# one nobody can reason about. So the flags land beside the routes and are tested beside
# them.



# --- recipes: step 068 ---------------------------------------------------------------


def _jira_from_recipe(monkeypatch):
    """A tenant with the Jira recipe's two hosts approved and its connector registered."""
    storage.active().create_tenant(cli.DEFAULT_TENANT_ID, "Default")
    for host in ("mcp.atlassian.com", "auth.atlassian.com"):
        run(monkeypatch, "--allow-host", host)
    run(monkeypatch, "--add-connector", "jira", "--from-recipe", "atlassian-jira")


def test_a_recipes_scope_notes_narrow_with_the_scopes(monkeypatch, capsys):
    """**Found by driving it, and it was a defect I introduced.**

    `normalize_scope_notes` refuses a note for a scope the flow does not request, which is
    right — it would describe a permission nobody is granting, on the screen where
    somebody decides whether to grant it. Applied to a *preset*, that made
    `--scope read:jira-work` against a two-scope recipe fail with a refusal about a file
    the operator did not write, when narrowing the scopes is precisely what somebody who
    wants read-only access would do.

    Filtering is not inventing: it drops descriptions of permissions no longer being asked
    for, which is what the rule wants rather than something it forbids.
    """
    _jira_from_recipe(monkeypatch)
    monkeypatch.setattr(sys, "stdin", io.StringIO("MARKER-CLIENT-SECRET\n"))

    run(
        monkeypatch,
        "--set-oauth", "jira",
        "--from-recipe", "atlassian-jira",
        "--client-id", "the-customers-own",
        "--scope", "read:jira-work",
    )

    row = storage.active().get_connector_oauth(cli.DEFAULT_TENANT_ID, "jira")
    assert row["scopes"] == ["read:jira-work"]
    assert list(row["scope_notes"]) == ["read:jira-work"]
    assert "Read issues" in row["scope_notes"]["read:jira-work"]["name"]


def test_a_typed_scope_note_mismatch_is_still_refused(monkeypatch, capsys):
    """The other half of the distinction: a preset narrows, a typo does not.

    Here the operator wrote both the scopes and the notes, so a note describing a scope
    they did not request is their mistake to see rather than a file's to be filtered.
    """
    _jira_from_recipe(monkeypatch)
    monkeypatch.setattr(sys, "stdin", io.StringIO("MARKER-CLIENT-SECRET\n"))

    fails(
        monkeypatch,
        "--set-oauth", "jira",
        "--auth-server", "https://auth.atlassian.com",
        "--client-id", "the-customers-own",
        "--scope", "read:jira-work",
        "--scope-notes",
        '{"write:jira-work": {"name": "W", "description": "d", "access": "write"}}',
    )
    assert "does not request" in message(capsys)


def test_an_unstated_effect_still_means_read(monkeypatch, capsys):
    """**A regression guard on a default this step changed.**

    `--effect` and `--identity` moved from `"read"`/`"service"` to `None` so a recipe's
    proposal could be told from an explicit flag. That is only safe if a command that
    omits them still means exactly what it always meant.
    """
    storage.active().create_tenant(cli.DEFAULT_TENANT_ID, "Default")
    run(monkeypatch, "--allow-host", "api.anthropic.com")
    run(monkeypatch, "--add-connector", "anth", "--from-recipe", "anthropic-messages")

    run(
        monkeypatch,
        "--vet", "anth", "--tool", "ping",
        "--method", "GET", "--path", "/v1/models",
        "--schema", '{"type": "object", "properties": {}}',
    )

    # The annotation lives on the manifest; `load_vetting_record` carries provenance.
    (row,) = [
        r
        for r in storage.active().get_connector(cli.DEFAULT_TENANT_ID, "anth")["vetted"]
        if r["remote_name"] == "ping"
    ]
    assert row["effect"] == "read"
    assert row["identity"] == "service"


def test_a_recipe_proposal_carries_its_vendors_families(monkeypatch, capsys):
    """Step 086. The families ship with the recipe, so a customer registering their first
    model connector from a preset can write `{"anthropic.model": {"write": ["haiku"]}}`
    without knowing the flag exists — which is the difference between a capability and a
    capability somebody has to be told about."""
    storage.active().create_tenant(cli.DEFAULT_TENANT_ID, "Default")
    run(monkeypatch, "--allow-host", "api.anthropic.com")
    run(monkeypatch, "--add-connector", "anth", "--from-recipe", "anthropic-messages")

    run(
        monkeypatch,
        "--vet", "anth", "--tool", "chat",
        "--from-recipe", "anthropic-messages",
    )

    from carnet.tools import mcp

    (vetted,) = [
        v for v in mcp.get_connector(cli.DEFAULT_TENANT_ID, "anth").vetted
        if v.remote_name == "chat"
    ]
    (ref,) = vetted.resources
    assert ref.families == ("opus", "sonnet", "haiku")
    assert ref.family_of("claude-haiku-4-5-20251001") == "haiku"


def test_a_recipe_proposal_fills_the_vet_but_a_flag_still_wins(monkeypatch, capsys):
    """One command per tool, and the effect is still the vetter's.

    The Anthropic proposal says `write`; `--effect read` must beat it, because a file in
    this repository is not the person doing the approving.
    """
    storage.active().create_tenant(cli.DEFAULT_TENANT_ID, "Default")
    run(monkeypatch, "--allow-host", "api.anthropic.com")
    run(monkeypatch, "--add-connector", "anth", "--from-recipe", "anthropic-messages")

    run(
        monkeypatch,
        "--vet", "anth", "--tool", "chat",
        "--from-recipe", "anthropic-messages",
        "--effect", "read",
    )

    (row,) = [
        r
        for r in storage.active().get_connector(cli.DEFAULT_TENANT_ID, "anth")["vetted"]
        if r["remote_name"] == "chat"
    ]
    assert row["effect"] == "read", "an explicit flag must beat a recipe's proposal"
    # And the rest of the proposal still landed, which is what makes it worth using.
    assert sorted(row["redact_args"]) == ["messages", "system"]
    assert row["binding"]["path"] == "/v1/messages"


def test_list_recipes_needs_no_database(monkeypatch, capsys):
    """It answers before the store is configured, so somebody deciding whether this
    product can reach their Jira does not have to stand a deployment up first."""
    run(monkeypatch, "--list-recipes")
    said = message(capsys)
    assert "atlassian-jira" in said
    assert "NOT CHECKED" in said, "an unverified recipe must not look checked"


# --- 069: --reach and --simulate, at a terminal ------------------------------------


def _granted_token(monkeypatch, *scopes):
    """A machine token granted one agent per scope, all carrying `post_message`.

    `DEFAULT_TENANT_ID` is pointed at the fixture's tenant rather than the fixture's
    tenant being renamed: the CLI takes its customer from `CARNET_TENANT` at import,
    and a test that created rows in one tenant and drove the CLI against another would
    be testing the refusal every time.
    """
    from conftest import TEST_ACTOR, TEST_TENANT
    from carnet import agents
    from carnet.access import tokens

    monkeypatch.setattr(cli, "DEFAULT_TENANT_ID", TEST_TENANT)
    store = storage.active()
    store.create_user(
        TEST_TENANT,
        {"id": "u-me", "issuer": "https://idp", "subject": "s1", "email": "me@acme.com"},
    )
    for name, channels in scopes:
        agents.save(
            TEST_TENANT,
            {
                "name": name,
                "system": "s",
                "runtime": "simple",
                "permissions": {
                    "tools": ["post_message"],
                    "scope": {"chat.channel": {"write": list(channels)}},
                },
            },
            actor=TEST_ACTOR,
        )
    row, _ = tokens.mint(TEST_TENANT, "laptop", "u-me", actor=TEST_ACTOR)
    for name, _ in scopes:
        store.grant_agent(
            TEST_TENANT, name, "machine", row["id"], role="user", actor=TEST_ACTOR
        )
    return row["id"]


def test_reach_reads_a_token_tool_first(monkeypatch, capsys):
    """The transpose at a terminal, which is where an operator is during an incident.

    The per-agent view is what the browser already had and is the one that cannot be read
    tool-first: under the union rule each tool keeps its own agent's scope, so three
    grants is a cross-reference exercise handed to whoever is asking whether a credential
    is over-broad.
    """
    token_id = _granted_token(
        monkeypatch, ("triage", ["#eng", "#ops"]), ("security", ["#sec"])
    )

    run(monkeypatch, "--reach", token_id)
    said = message(capsys)

    assert "post_message  (write)" in said
    assert "via triage: chat.channel #eng, #ops" in said
    assert "via security: chat.channel #sec" in said
    # It says which of the two would take a call, and that it depends on the arguments.
    assert "attributed to the first of them whose" in said
    # And it does not claim to say whether the credential still works.
    assert "--list-tokens" in said


def test_reach_of_a_token_granted_nothing_says_so(monkeypatch, capsys):
    from conftest import TEST_ACTOR, TEST_TENANT
    from carnet.access import tokens

    monkeypatch.setattr(cli, "DEFAULT_TENANT_ID", TEST_TENANT)
    storage.active().create_user(
        TEST_TENANT,
        {"id": "u-me", "issuer": "https://idp", "subject": "s1", "email": "me@acme.com"},
    )
    row, _ = tokens.mint(TEST_TENANT, "laptop", "u-me", actor=TEST_ACTOR)

    run(monkeypatch, "--reach", row["id"])

    assert "granted nothing" in message(capsys)


def test_simulate_names_the_rule_and_every_agent_that_refused(monkeypatch, capsys):
    """`considered` at a terminal. The list is the answer — a verdict alone is what
    somebody could have got by making the call."""
    token_id = _granted_token(
        monkeypatch, ("triage", ["#eng"]), ("security", ["#sec"])
    )

    run(
        monkeypatch,
        "--simulate", token_id,
        "--call", "post_message",
        "--arg", "channel=#random",
        "--arg", "text=hello",
    )
    said = message(capsys)

    assert said.startswith("REFUSED  post_message")
    assert "rule:          outside_scope" in said
    assert "triage — refuses" in said
    assert "security — refuses" in said
    assert "Allowed: #eng" in said and "Allowed: #sec" in said
    assert (
        "Not checked: authentication, binding, acting-for, credential, budget."
        in said
    )


def test_simulate_says_recorded_under_rather_than_attributed_on_a_refusal(
    monkeypatch, capsys
):
    """Two words, and driving it is what asked for them. *Attributed to* beside a REFUSED
    reads as *this is the one that let it through*; what it actually names is the agent
    the **denial** would be recorded under, which is a different and less reassuring
    fact."""
    token_id = _granted_token(monkeypatch, ("triage", ["#eng"]))

    run(monkeypatch, "--simulate", token_id, "--call", "post_message",
        "--arg", "channel=#nope")
    refused = message(capsys)

    run(monkeypatch, "--simulate", token_id, "--call", "post_message",
        "--arg", "channel=#eng")
    allowed = message(capsys)

    assert "recorded under: triage" in refused
    assert "attributed to: triage" in allowed


def test_simulate_needs_a_call_and_says_which_flag(monkeypatch, capsys):
    token_id = _granted_token(monkeypatch, ("triage", ["#eng"]))

    fails(monkeypatch, "--simulate", token_id)

    assert "--call" in message(capsys)


def test_simulate_refuses_a_malformed_argument(monkeypatch, capsys):
    """`NAME=VALUE`, on `--header`'s precedent. A bare word is a typo, and silently
    dropping it would answer a question about a call nobody described."""
    token_id = _granted_token(monkeypatch, ("triage", ["#eng"]))

    fails(
        monkeypatch, "--simulate", token_id, "--call", "post_message", "--arg", "channel"
    )

    assert "NAME=VALUE" in message(capsys)


def test_neither_reader_touches_a_token_it_reads(monkeypatch, capsys):
    """**Reading a token is not using it**, and `last_used_at` is the column that would
    silently record the opposite. 035d made the same argument for the reach route and got
    it by omission; these two get it the same way — nothing here calls `act_for`."""

    token_id = _granted_token(monkeypatch, ("triage", ["#eng"]))

    run(monkeypatch, "--reach", token_id)
    run(monkeypatch, "--simulate", token_id, "--call", "post_message",
        "--arg", "channel=#eng")

    assert storage.active().find_api_token(token_id)["last_used_at"] is None


def test_neither_reader_writes_any_row(monkeypatch, capsys):
    """The CLI half of the audit decision. A flag is where a convenience log gets added
    by somebody who did not read plan 069, so the count is asserted here too."""
    from conftest import TEST_TENANT

    token_id = _granted_token(monkeypatch, ("triage", ["#eng"]))
    store = storage.active()
    before = (
        len(store.audit_records(TEST_TENANT)),
        len(store.denial_records(TEST_TENANT)),
        len(store.admin_audit_records(TEST_TENANT)),
    )

    for channel in ("#eng", "#nope") * 5:
        run(monkeypatch, "--simulate", token_id, "--call", "post_message",
            "--arg", f"channel={channel}")
        run(monkeypatch, "--reach", token_id)

    assert (
        len(store.audit_records(TEST_TENANT)),
        len(store.denial_records(TEST_TENANT)),
        len(store.admin_audit_records(TEST_TENANT)),
    ) == before


def test_a_token_from_another_customer_is_refused_by_both(monkeypatch, capsys):
    """The CLI is an operator's tool with a shell and a DSN, so this is not the oracle
    the HTTP surface guards against — it is the tenant boundary, which holds everywhere
    or nowhere."""
    from conftest import TEST_ACTOR
    from carnet.access import tokens

    store = storage.active()
    store.create_tenant("other", name="Other")
    store.create_user(
        "other",
        {"id": "u-them", "issuer": "https://idp", "subject": "s9", "email": "t@o.com"},
    )
    theirs, _ = tokens.mint("other", "theirs", "u-them", actor=TEST_ACTOR)

    fails(monkeypatch, "--reach", theirs["id"])
    assert "no API token" in message(capsys)

    fails(monkeypatch, "--simulate", theirs["id"], "--call", "post_message")
    assert "no API token" in message(capsys)


# --- 070: a credential held in the customer's own vault -------------------------------


def _a_vault_on_loopback(monkeypatch):
    """The Connect stub from `test_vault`, started for one CLI test.

    The stub itself is shared rather than re-written, because two Connect fakes that can
    disagree about the wire format are two chances to test against a protocol nobody
    speaks — `_descriptor`'s drift problem, in a test directory.
    """
    import threading
    from http.server import ThreadingHTTPServer

    from carnet import config as vault_config
    from test_vault import Stub

    Stub.delay, Stub.status, Stub.body, Stub.hits = 0.0, 200, None, []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
    ).start()
    monkeypatch.setattr(
        vault_config, "VAULT_URL", f"http://127.0.0.1:{server.server_address[1]}"
    )
    monkeypatch.setattr(vault_config, "VAULT_TOKEN", "connect-token")
    monkeypatch.setattr(vault_config, "VAULT_TIMEOUT_SECONDS", 2.0)
    return server


def _a_connector_with_a_reference(monkeypatch, reference: str):
    storage.active().create_tenant(cli.DEFAULT_TENANT_ID, "Default")
    run(monkeypatch, "--allow-host", "mcp.acme.com")
    run(
        monkeypatch,
        "--add-connector", "tracker",
        "--url", "https://mcp.acme.com/mcp",
        "--credential-ref", reference,
    )


def test_add_connector_takes_a_vault_reference(monkeypatch, capsys):
    _a_connector_with_a_reference(
        monkeypatch, "op://Engineering/GitHub Deploy Key/credential"
    )
    connector = tools.mcp.get_connector(cli.DEFAULT_TENANT_ID, "tracker")
    assert connector.launch.credential_ref == (
        "op://Engineering/GitHub Deploy Key/credential"
    )
    assert connector.launch.credential_env is None


def test_a_malformed_reference_is_refused_while_the_command_is_still_in_the_shell(
    monkeypatch, capsys
):
    """The friendly half of the two-place check. The load-bearing one is at the credential
    read, because `--seed` can write a row that skipped this."""
    storage.active().create_tenant(cli.DEFAULT_TENANT_ID, "Default")
    run(monkeypatch, "--allow-host", "mcp.acme.com")
    refusal = fails(
        monkeypatch,
        "--add-connector", "tracker",
        "--url", "https://mcp.acme.com/mcp",
        "--credential-ref", "op://Engineering/GitHub",
    )
    assert refusal == "2"
    assert "op://" in message(capsys)


def test_both_a_variable_and_a_reference_is_refused(monkeypatch, capsys):
    storage.active().create_tenant(cli.DEFAULT_TENANT_ID, "Default")
    run(monkeypatch, "--allow-host", "mcp.acme.com")
    refusal = fails(
        monkeypatch,
        "--add-connector", "tracker",
        "--url", "https://mcp.acme.com/mcp",
        "--credential-env", "TRACKER_TOKEN",
        "--credential-ref", "op://Engineering/GitHub/credential",
    )
    assert refusal == "2"
    assert "not both" in message(capsys)


def test_a_reference_registered_with_no_vault_configured_warns_and_does_not_refuse(
    monkeypatch, capsys
):
    """`egress.approval_warning`'s reasoning: the row is legitimate — somebody said where
    their credential lives — and the deployment's vault is configured by a different
    person at a different time. What must not happen is silence."""
    from carnet import config as vault_config

    monkeypatch.setattr(vault_config, "VAULT_URL", "")
    monkeypatch.setattr(vault_config, "VAULT_TOKEN", "")
    _a_connector_with_a_reference(monkeypatch, "op://Engineering/GitHub/credential")
    said = message(capsys)
    assert "no vault configured" in said
    assert "CARNET_VAULT_URL" in said
    assert tools.mcp.get_connector(cli.DEFAULT_TENANT_ID, "tracker") is not None


def test_check_credential_resolves_and_never_prints_the_value(monkeypatch, capsys):
    server = _a_vault_on_loopback(monkeypatch)
    try:
        _a_connector_with_a_reference(
            monkeypatch, "op://Engineering/GitHub Deploy Key/credential"
        )
        capsys.readouterr()
        run(monkeypatch, "--check-credential", "tracker")
        said = message(capsys)
    finally:
        server.shutdown()
        server.server_close()

    assert "resolved  yes" in said
    assert f"{len('ghp_the_real_one')} characters" in said
    # The point of the command, and the point of printing a length instead.
    assert "ghp_the_real_one" not in said


def test_check_credential_lists_the_labels_a_refusal_withholds(monkeypatch, capsys):
    """The audience changed, so the answer does. `core/vault`'s case-8 refusal reaches the
    model through the door and carries no labels; here it is somebody at a shell who can
    already open the vault."""
    server = _a_vault_on_loopback(monkeypatch)
    try:
        _a_connector_with_a_reference(
            monkeypatch, "op://Engineering/GitHub Deploy Key/nope"
        )
        capsys.readouterr()
        with pytest.raises(SystemExit):
            run(monkeypatch, "--check-credential", "tracker")
        said = message(capsys)
    finally:
        server.shutdown()
        server.server_close()

    assert "resolved  no" in said
    assert "The item does carry:" in said
    assert "credential" in said
    assert "ghp_the_real_one" not in said


def test_check_credential_answers_about_a_variable_rather_than_refusing(
    monkeypatch, capsys
):
    """*This connector's credential is not a reference* is a real answer to the question
    somebody asked, and a refusal would leave them wondering whether it looked."""
    storage.active().create_tenant(cli.DEFAULT_TENANT_ID, "Default")
    run(monkeypatch, "--allow-host", "mcp.acme.com")
    run(
        monkeypatch,
        "--add-connector", "tracker",
        "--url", "https://mcp.acme.com/mcp",
        "--credential-env", "TRACKER_TOKEN",
    )
    monkeypatch.setenv("TRACKER_TOKEN", "pasted-in")
    capsys.readouterr()
    run(monkeypatch, "--check-credential", "tracker")
    said = message(capsys)

    assert "environment variable" in said
    assert "TRACKER_TOKEN" in said
    assert "pasted-in" not in said


# --- people, and the directory that provisions them (071) ----------------------------


def test_disable_user_is_the_first_surface_that_can_cut_somebody_off(
    monkeypatch, tenant_with_a_person, capsys
):
    """`storage.set_user_status` had no caller before this step. This is one."""
    run(monkeypatch, "--disable-user", "priya@acme.com")

    said = message(capsys)
    assert "is now disabled" in said
    assert "nothing they made is deleted" in said
    assert storage.active().get_user(cli.DEFAULT_TENANT_ID, "u_priya")["status"] == "disabled"
    [record] = storage.active().admin_audit_records(cli.DEFAULT_TENANT_ID, action="user.disable")
    assert (record["actor_kind"], record["actor_id"]) == ("system", "cli")
    assert record["detail"]["cause"] == "--disable-user"


def test_disabling_twice_says_so_and_writes_nothing_twice(
    monkeypatch, tenant_with_a_person, capsys
):
    run(monkeypatch, "--disable-user", "priya@acme.com")
    run(monkeypatch, "--disable-user", "u_priya")
    assert "already disabled" in message(capsys)
    assert len(storage.active().admin_audit_records(cli.DEFAULT_TENANT_ID, action="user.disable")) == 1


def test_enable_user_reverses_the_status_and_nothing_else(
    monkeypatch, tenant_with_a_person, capsys
):
    run(monkeypatch, "--disable-user", "priya@acme.com")
    run(monkeypatch, "--enable-user", "priya@acme.com")
    assert storage.active().get_user(cli.DEFAULT_TENANT_ID, "u_priya")["status"] == "active"


def test_disabling_somebody_who_never_signed_in_is_refused_by_name(
    monkeypatch, tenant_with_a_person, capsys
):
    fails(monkeypatch, "--disable-user", "nobody@acme.com")
    assert "--list-users" in message(capsys)


def test_list_users_shows_a_provisioned_person_who_has_not_arrived(
    monkeypatch, tenant_with_a_person, capsys
):
    storage.active().create_user(
        cli.DEFAULT_TENANT_ID,
        {
            "id": "u_sam",
            "issuer": "https://acme.okta.example",
            "subject": None,
            "external_id": "oid-sam",
            "email": "sam@acme.com",
        },
        actor="system:cli",
    )
    run(monkeypatch, "--list-users")
    said = message(capsys)
    assert "u_sam" in said and "oid-sam" in said and "never" in said
    assert "u_priya" in said


def test_a_resource_family_flag_that_names_nothing_is_refused(monkeypatch, capsys):
    """**A flag that reads as applied and is not**, which is the failure this codebase
    refuses everywhere. `--resource-family openai.model=,,,` parsed, stored nothing, and
    exited 0; the vetter would find out when the family scope they then wrote refused
    every call. The empty right-hand side was already caught and this one was not, which
    is why it took driving the flag rather than reading it.
    """
    import argparse

    from carnet.cli import _with_families
    from carnet.tools.base import Resource

    parser = argparse.ArgumentParser()
    declared = (Resource("openai.model", "model"),)

    for raw in ("openai.model=,,,", "openai.model= , "):
        with pytest.raises(SystemExit):
            _with_families(parser, declared, [raw])

    # And the neighbouring case still means what it says: a stray comma is tolerated,
    # because it names something either side of it.
    (kept,) = _with_families(parser, declared, ["openai.model=gpt-5,,gpt-4"])
    assert kept.families == ("gpt-5", "gpt-4")


def test_the_cli_gives_the_pool_back_on_every_path(monkeypatch, capsys):
    """Step 099's acceptance pass found every CLI command run against Postgres on Python
    3.14 ending in a `PythonFinalizationError` traceback: nothing closed the store, so
    the pool's worker threads were left for the interpreter's finalizer, which can no
    longer join them. `main` now closes the active store in a `finally` around every
    store-dependent command — the success path and the `parser.error` path alike.
    """
    closed: list[bool] = []
    monkeypatch.setattr(storage.active(), "close", lambda: closed.append(True))

    run(monkeypatch, "--list-idps")
    assert closed == [True], "the store was not closed after a command that succeeded"

    fails(monkeypatch, "--grant-role", "admin", "nobody@acme.com")
    assert closed == [True, True], "the store was not closed after a command that was refused"


def test_vetting_from_a_recipe_applies_its_response_cap(monkeypatch, tenant_with_a_person, capsys):
    """Step 108 found `max_response_bytes` declared in the recipe format and ignored at
    vet time: the Azure recipe proposes 4 MiB for a chat completion, and the default 64
    KiB cut every long answer off. Under the flag, like every other proposal field."""
    run(monkeypatch, "--allow-host", "acme-foundry.openai.azure.com")
    run(monkeypatch, "--add-connector", "foundry", "--from-recipe", "azure-openai",
        "--url", "https://acme-foundry.openai.azure.com", "--credential-env", "AZURE_OPENAI_KEY")
    capsys.readouterr()

    run(monkeypatch, "--vet", "foundry", "--tool", "chat_completions", "--from-recipe", "azure-openai")
    run(monkeypatch, "--vet", "foundry", "--tool", "embeddings", "--from-recipe", "azure-openai",
        "--max-response-bytes", "1000")
    capsys.readouterr()

    from carnet.tools import mcp

    vetted = {v.remote_name: v for v in mcp.get_connector(cli.DEFAULT_TENANT_ID, "foundry").vetted}
    assert vetted["chat_completions"].max_response_bytes == 4 * 1024 * 1024
    assert vetted["chat_completions"].redact_args == ("messages", "tools", "functions", "prediction")
    # The flag still wins.
    assert vetted["embeddings"].max_response_bytes == 1000
