"""Step 068: a preset that fills a form and never approves anything.

The tests that matter here are not the ones showing a recipe *works*. They are the four
showing it cannot do the things it is deliberately not allowed to do — vet a tool, allow
a host, carry a client secret, or leave a trace in the database that would make deleting
it unsafe. Each is a place the convenient version of this feature is worse, and each is
the kind of property that decays quietly under later edits.

The fifth is the drift guard, which is the only test here defending against *us*.
"""

import copy
import datetime
import json
import pathlib

import pytest

from carnet import storage, tools
from carnet.tools import mcp
from carnet.access import oauth, recipes
from carnet.storage import base as storage_base

from conftest import TEST_ACTOR, TEST_HOST, TEST_TENANT


@pytest.fixture
def jira_recipe():
    return recipes.load("atlassian-jira")


def _write(tmp_path, recipe):
    path = tmp_path / f"{recipe['id']}.json"
    path.write_text(json.dumps(recipe))
    return tmp_path


# --- the catalogue itself --------------------------------------------------------------


def test_every_shipped_recipe_loads():
    """A malformed recipe is a broken build, not a broken customer.

    `catalogue()` validates each file, so this is the whole shape guard for everything in
    `recipes/` at once — every field checked against the parameter sets it fills.
    """
    found = recipes.catalogue()
    assert found, "this build ships no recipes at all"
    assert len(found) == len({item["id"] for item in found})


def test_the_catalogue_stays_under_its_ceiling():
    """**Plan 068 rule 3, and this failure message is the argument rather than a number.**

    The ceiling is what one person can re-verify against the vendors in one sitting. The
    point is not that eight is correct — the ninth recipe will arrive with a good reason.
    The point is that raising it is a visible act with the plan attached, rather than a
    directory quietly reaching forty while nobody can say when it was last maintained.
    """
    found = recipes.catalogue()
    assert len(found) <= recipes.CEILING, (
        f"{len(found)} recipes, and the ceiling is {recipes.CEILING}.\n"
        "The ceiling is a policy, not a limit of anything: plan 068 rule 3 sets it at "
        "what one person can re-verify against the vendors in one sitting. Every recipe "
        "is a thing that breaks silently when a vendor moves an endpoint, and onecli "
        "pays that bill with a team.\n"
        "Raise it deliberately, in a plan, or delete one — deleting is safe by design "
        "(rule 1: nothing in the database points back at a recipe)."
    )


def test_no_recipe_carries_a_client_id_or_secret(tmp_path, jira_recipe):
    """The one field a recipe cannot fill is the one that identifies you to the vendor.

    A client secret checked into this repository would be one deployment's credential
    shared by every other, in a git history nobody can rewrite.
    """
    for shipped in recipes.catalogue():
        assert not (set(shipped.get("oauth") or {}) & {"client_id", "client_secret"})

    for forbidden in ("client_id", "client_secret"):
        broken = copy.deepcopy(jira_recipe)
        broken["oauth"][forbidden] = "whatever"
        with pytest.raises(recipes.RecipeRefused, match="may never hold either"):
            recipes.validate(broken, source="atlassian-jira")


def test_a_recipe_names_every_host_it_dials(jira_recipe):
    """Otherwise the screen never offers the host and the failure lands at first Connect.

    The authorize endpoint is deliberately exempt: nothing of ours dials it — it is a
    redirect the browser follows — and requiring it would describe a connection this
    platform never makes. That asymmetry is `oauth.configure`'s and is kept here.
    """
    broken = copy.deepcopy(jira_recipe)
    broken["hosts"] = [h for h in broken["hosts"] if h["host"] != "auth.atlassian.com"]
    with pytest.raises(recipes.RecipeRefused, match="does not name it in `hosts`"):
        recipes.validate(broken, source="atlassian-jira")

    # The authorize endpoint on a host nobody names is fine, and must stay fine.
    fine = copy.deepcopy(jira_recipe)
    fine["oauth"]["authorize_endpoint"] = "https://id.atlassian.example/authorize"
    recipes.validate(fine, source="atlassian-jira")


def test_a_stamp_brings_its_signer(jira_recipe):
    """`verified_on` with no `verified_by` is a claim with no author.

    Same defect `admin_audit.actor_id` refuses with a CHECK: a record saying nobody did
    it looks like an answer.
    """
    broken = copy.deepcopy(jira_recipe)
    broken["verified_on"] = "2026-09-02"
    with pytest.raises(recipes.RecipeRefused, match="no verified_by"):
        recipes.validate(broken, source="atlassian-jira")


def test_staleness_is_three_states(jira_recipe):
    fresh = dict(jira_recipe, verified_on="2026-09-01", verified_by="a@b.c")
    today = datetime.date(2026, 9, 2)
    assert recipes.staleness(fresh, today=today) == "verified"

    old = dict(fresh, verified_on="2025-01-01")
    assert recipes.staleness(old, today=today) == "stale"

    assert recipes.staleness(jira_recipe, today=today) == "unverified"


def test_a_recipe_id_cannot_escape_its_directory():
    """The id becomes a filename, so `../` is unrepresentable rather than filtered."""
    assert recipes.load("../../../etc/passwd") is None
    assert recipes.load("../atlassian-jira") is None
    assert recipes.load("") is None
    assert recipes.load("Jira") is None


# --- the drift guard: the only test here defending against us --------------------------


def test_a_renamed_parameter_makes_the_catalogue_refuse(monkeypatch):
    """**Plan 068 rule 5, and the check that earns its keep.**

    Rename `credential_env` on `register_connector` and six recipe files go on setting a
    key nothing reads — every test green, because nothing compares the two. The recipes
    would keep registering connectors that are subtly wrong, and the first symptom would
    be a customer's consent flow failing.
    """
    monkeypatch.setattr(
        recipes,
        "CONNECTOR_FIELDS",
        recipes.CONNECTOR_FIELDS | {"credential_environment"},
    )
    with pytest.raises(recipes.RecipeRefused, match="no longer takes it"):
        recipes.check_field_sets()

    # And it runs on every load, not only under test — a catalogue that cannot be trusted
    # to fill the form is worse than none, because it is a blank form somebody believes.
    with pytest.raises(recipes.RecipeRefused):
        recipes.catalogue()


def test_the_declared_field_sets_match_the_code_they_fill():
    """The same guard, unmocked, as a standing assertion about this build."""
    recipes.check_field_sets()


# --- scope notes: migration 051 ---------------------------------------------------------


def test_a_note_cannot_describe_a_scope_nobody_is_requesting(isolated_storage):
    """A note for an ungranted permission, on the screen where somebody decides.

    `redact_args`' rule from 045c in a different column: a policy that reads as applied
    and is not, caught where it is written rather than never.
    """
    tools.register_connector(
        TEST_TENANT, "jira", url=f"https://{TEST_HOST}/mcp", actor=TEST_ACTOR
    )
    with pytest.raises(storage.ValueRefused, match="does not request"):
        oauth.configure(
            TEST_TENANT,
            "jira",
            authorize_endpoint=f"https://{TEST_HOST}/authorize",
            token_endpoint=f"https://{TEST_HOST}/token",
            client_id="cid",
            client_secret="shh",
            scopes=("read:jira-work",),
            scope_notes={
                "write:jira-work": {
                    "name": "Create issues",
                    "description": "…",
                    "access": "write",
                }
            },
            actor=TEST_ACTOR,
        )


def test_scope_notes_survive_the_round_trip(isolated_storage):
    tools.register_connector(
        TEST_TENANT, "jira", url=f"https://{TEST_HOST}/mcp", actor=TEST_ACTOR
    )
    row = oauth.configure(
        TEST_TENANT,
        "jira",
        authorize_endpoint=f"https://{TEST_HOST}/authorize",
        token_endpoint=f"https://{TEST_HOST}/token",
        client_id="cid",
        client_secret="shh",
        scopes=("read:jira-work", "offline_access"),
        scope_notes={
            "read:jira-work": {
                "name": "Read issues",
                "description": "See issues you already have access to.",
                "access": "read",
            }
        },
        actor=TEST_ACTOR,
    )
    assert row["scope_notes"]["read:jira-work"]["access"] == "read"
    # A scope with no note is normal and stays absent rather than becoming an empty one.
    assert "offline_access" not in row["scope_notes"]


def test_reconfiguring_replaces_notes_rather_than_merging(isolated_storage):
    """A note surviving the scope it described is a consent screen explaining a
    permission the flow no longer asks for."""
    tools.register_connector(
        TEST_TENANT, "jira", url=f"https://{TEST_HOST}/mcp", actor=TEST_ACTOR
    )

    def configure(scopes, notes):
        return oauth.configure(
            TEST_TENANT,
            "jira",
            authorize_endpoint=f"https://{TEST_HOST}/authorize",
            token_endpoint=f"https://{TEST_HOST}/token",
            client_id="cid",
            client_secret="shh",
            scopes=scopes,
            scope_notes=notes,
            actor=TEST_ACTOR,
        )

    configure(
        ("read:jira-work", "write:jira-work"),
        {
            "write:jira-work": {
                "name": "Create issues",
                "description": "…",
                "access": "write",
            }
        },
    )
    narrowed = configure(("read:jira-work",), None)
    assert narrowed["scope_notes"] == {}


def test_the_administrative_record_names_the_scopes_and_not_the_prose(isolated_storage):
    """*Was the consent screen explained* is answerable; three paragraphs per scope in an
    append-only table is how the administrative log stops being readable."""
    tools.register_connector(
        TEST_TENANT, "jira", url=f"https://{TEST_HOST}/mcp", actor=TEST_ACTOR
    )
    oauth.configure(
        TEST_TENANT,
        "jira",
        authorize_endpoint=f"https://{TEST_HOST}/authorize",
        token_endpoint=f"https://{TEST_HOST}/token",
        client_id="cid",
        client_secret="shh",
        scopes=("read:jira-work",),
        scope_notes={
            "read:jira-work": {
                "name": "Read issues",
                "description": "MARKER-PROSE-9f2a",
                "access": "read",
            }
        },
        actor=TEST_ACTOR,
    )
    records = storage.active().admin_audit_records(
        TEST_TENANT, action="connector.oauth.configure"
    )
    assert records[-1]["detail"]["described_scopes"] == ["read:jira-work"]
    assert "MARKER-PROSE-9f2a" not in json.dumps(records[-1])


def test_a_bad_access_value_is_refused_with_the_two_it_allows():
    with pytest.raises(storage.ValueRefused, match="read"):
        storage_base.normalize_scope_notes(
            {"s": {"name": "n", "description": "d", "access": "readonly"}},
            scopes=("s",),
        )


def test_a_note_cannot_carry_a_field_nothing_looked_at():
    """Unknown keys are refused rather than dropped: storing more would let a recipe put
    something in front of a person that nothing here has examined."""
    with pytest.raises(storage.ValueRefused, match="does not hold"):
        storage_base.normalize_scope_notes(
            {"s": {"name": "n", "description": "d", "access": "read", "url": "http://x"}},
            scopes=("s",),
        )


# --- the four things a recipe must not be able to do ------------------------------------


def _register_from(recipe, connector_id, *, cite=True):
    """Register exactly as an entry point would after applying a recipe's defaults."""
    preset = recipe["connector"]
    tools.register_connector(
        TEST_TENANT,
        connector_id,
        url=preset["url"],
        kind=preset.get("kind", "http"),
        credential_env=preset.get("credential_env") or "",
        credential_header=preset.get("credential_header"),
        credential_prefix=preset.get("credential_prefix"),
        headers=dict(preset.get("headers") or {}) or None,
        description=preset.get("description") or "",
        from_recipe=recipe["id"] if cite else "",
        actor=TEST_ACTOR,
    )


@pytest.fixture
def anthropic_here(isolated_storage, monkeypatch):
    """The Anthropic recipe pointed at the test host, so egress is the tenant's own.

    Only the URL moves. Every other field is the shipped recipe's, so what this exercises
    is the real file rather than a fixture shaped like one.
    """
    recipe = recipes.load("anthropic-messages")
    recipe["connector"]["url"] = f"https://{TEST_HOST}"
    recipe["hosts"] = [{"host": TEST_HOST, "why": "the test host"}]
    return recipe


def test_a_recipe_registration_is_indistinguishable_from_a_hand_one(anthropic_here):
    """**Rule 1, and the test that keeps it true as the code grows.**

    Byte-identical rows and byte-identical review records, except the one `detail` key
    that says where the defaults came from. The moment these diverge, a recipe has become
    a thing the database knows about — and deleting one stops being safe.
    """
    storage.active().allow_host(TEST_TENANT, TEST_HOST, actor=TEST_ACTOR)
    _register_from(anthropic_here, "from-recipe")
    _register_from(anthropic_here, "by-hand", cite=False)

    left = dict(storage.active().get_connector(TEST_TENANT, "from-recipe"))
    right = dict(storage.active().get_connector(TEST_TENANT, "by-hand"))
    for row in (left, right):
        row.pop("id", None)
    assert left == right

    records = {
        row["target_id"]: row
        for row in storage.active().admin_audit_records(
            TEST_TENANT, action="connector.create"
        )
    }
    assert records["from-recipe"]["detail"]["from_recipe"] == "anthropic-messages"
    assert records["by-hand"]["detail"]["from_recipe"] == ""
    assert {k: v for k, v in records["from-recipe"]["detail"].items()
            if k != "from_recipe"} == {
        k: v for k, v in records["by-hand"]["detail"].items() if k != "from_recipe"
    }


def test_a_recipe_vets_nothing(anthropic_here):
    """It proposes a tool and approves none of it.

    The Anthropic recipe carries a fully authored REST binding — the twelve-flag `--vet`
    command — which is the largest thing a recipe could be tempted to apply for you.
    """
    assert anthropic_here["tools"], "this test needs a recipe that proposes something"
    storage.active().allow_host(TEST_TENANT, TEST_HOST, actor=TEST_ACTOR)
    _register_from(anthropic_here, "anthropic")

    connector = storage.active().get_connector(TEST_TENANT, "anthropic")
    assert (connector.get("vetted") or []) == []
    assert storage.active().admin_audit_records(TEST_TENANT, action="tool.vet") == []


def test_a_recipe_allows_no_host(anthropic_here):
    """The registration is refused by the same egress check a hand one meets.

    A recipe *names* the hosts it needs and the screen offers them; approving stays a
    separate act by somebody who can make it.

    Pointed at a host the fixture has NOT approved, because `conftest` pre-approves
    `TEST_HOST` — against that one this test would pass with the egress check deleted.
    """
    unapproved = "mcp.not-approved.example"
    anthropic_here["connector"]["url"] = f"https://{unapproved}"
    approved_before = storage.active().allowed_hosts(TEST_TENANT)

    with pytest.raises(mcp.EgressRefused) as refused:
        _register_from(anthropic_here, "anthropic")
    assert unapproved in str(refused.value)

    # Nothing was registered, and nothing was allowed.
    assert storage.active().get_connector(TEST_TENANT, "anthropic") is None
    assert storage.active().allowed_hosts(TEST_TENANT) == approved_before


def test_deleting_every_recipe_leaves_registered_connectors_working(
    anthropic_here, tmp_path, monkeypatch
):
    """**The test that makes the catalogue shrinkable, which is rule 1's whole payoff.**

    A recipe that stops being true can be deleted in the commit that finds out, rather
    than carried half-true until somebody has time. That is only safe while nothing
    references one.
    """
    storage.active().allow_host(TEST_TENANT, TEST_HOST, actor=TEST_ACTOR)
    _register_from(anthropic_here, "anthropic")

    # An empty catalogue: every file gone.
    monkeypatch.setattr(recipes, "RECIPES_DIR", tmp_path)
    assert recipes.catalogue() == []

    connector = storage.active().get_connector(TEST_TENANT, "anthropic")
    assert connector is not None
    assert connector["launch"]["url"] == f"https://{TEST_HOST}"
    # And the record of where it came from survives, because it was never a link.
    records = storage.active().admin_audit_records(
        TEST_TENANT, action="connector.create"
    )
    assert records[-1]["detail"]["from_recipe"] == "anthropic-messages"


def test_a_recipe_cannot_suggest_an_id_that_would_be_refused(jira_recipe):
    """A pre-filled value that fails at submit is a refusal about a string the person did
    not type, at the end of a flow they had no reason to doubt.

    `Connector.__post_init__` is the rule; this is the same rule at the point a recipe
    could break it.
    """
    for bad in ("Jira", "a/b", "-jira", "jira_x", ""):
        broken = copy.deepcopy(jira_recipe)
        broken["connector"]["connector_id"] = bad
        with pytest.raises(recipes.RecipeRefused):
            recipes.validate(broken, source="atlassian-jira")


def test_every_shipped_recipe_suggests_a_registrable_id():
    """The same rule as a standing assertion about what ships."""
    from carnet.tools.mcp.binding import Connector, HttpLaunch

    for shipped in recipes.catalogue():
        # Constructing it is the check: `__post_init__` refuses a bad id.
        Connector(
            id=shipped["connector"]["connector_id"],
            launch=HttpLaunch(url="https://example.com/mcp"),
        )


def test_a_proposal_cannot_redact_an_argument_its_schema_lacks(tmp_path):
    """**This check exists because the shipped Anthropic recipe failed it.**

    It marked `system` redacted and its authored schema had no `system` property.
    `validation.validate` caught it — 045c's guard, and the load-bearing half of that
    step — but at the moment an administrator ran `--vet`, which is a refusal about a
    file they did not write. A recipe's own defects are ours and belong at load.
    """
    broken = recipes.load("anthropic-messages")
    broken["tools"][0]["redact_args"] = ["messages", "nosuchargument"]
    with pytest.raises(recipes.RecipeRefused, match="does not carry"):
        recipes.validate(broken, source="anthropic-messages")


def test_every_shipped_proposal_redacts_only_what_it_declares():
    """The same rule as a standing assertion, over what actually ships."""
    for shipped in recipes.catalogue():
        for tool in shipped.get("tools") or ():
            schema = ((tool.get("binding") or {}).get("input_schema") or {})
            properties = schema.get("properties") or {}
            if properties:
                assert set(tool.get("redact_args") or ()) <= set(properties), (
                    f"{shipped['id']}/{tool['remote_name']}"
                )


def test_a_proposal_cannot_name_a_family_a_scope_line_could_never_use(tmp_path):
    """Step 086, at the redaction check's address and for its reason: the defect would be
    ours, and the alternative is an administrator meeting it as a refusal about a file
    they did not write."""
    broken = recipes.load("anthropic-messages")
    broken["tools"][0]["resources"][0]["families"] = ["haiku", "  "]
    with pytest.raises(recipes.RecipeRefused, match="empty family"):
        recipes.validate(broken, source="anthropic-messages")

    broken = recipes.load("anthropic-messages")
    broken["tools"][0]["resources"][0]["families"] = ["anthropic/haiku"]
    with pytest.raises(recipes.RecipeRefused, match="match nothing at all"):
        recipes.validate(broken, source="anthropic-messages")


def test_the_two_model_recipes_name_their_vendors_families():
    """What ships, so a customer's first model connector can express the middle policy
    without anybody writing a flag. Every family here is derivable from a real id the
    vendor serves — a vocabulary nothing could derive is a scope that refuses."""
    by_id = {shipped["id"]: shipped for shipped in recipes.catalogue()}

    anthropic = by_id["anthropic-messages"]["tools"][0]["resources"][0]
    assert anthropic["families"] == ["opus", "sonnet", "haiku"]

    openai = by_id["openai-chat"]["tools"][0]["resources"][0]
    assert openai["families"] == ["gpt-5", "gpt-4"]


def test_every_shipped_family_is_one_a_scope_line_could_name():
    """The standing assertion beside the redaction one above, over what actually ships."""
    for shipped in recipes.catalogue():
        for tool in shipped.get("tools") or ():
            for ref in tool.get("resources") or ():
                for family in ref.get("families") or ():
                    assert family.strip(), f"{shipped['id']}/{tool['remote_name']}"
                    assert "/" not in family, f"{shipped['id']}/{tool['remote_name']}"


# --- every failure to produce a recipe is a RecipeRefused --------------------------------


def test_a_malformed_recipe_file_is_a_refusal_and_not_a_crash(tmp_path, monkeypatch):
    """**The module's stated contract, which was not true until it was driven.**

    `validate` refused cleanly and `json.loads` and `read_text` did not, so a file with a
    stray comma escaped as a bare `JSONDecodeError` and one saved in the wrong encoding as
    a `UnicodeDecodeError`. Both reached `GET /admin/recipes` unmapped and became an
    unhandled 500 with no sentence and no filename — the shape 7b found twice and 011
    shipped as a 503.
    """
    monkeypatch.setattr(recipes, "RECIPES_DIR", tmp_path)

    (tmp_path / "bad.json").write_text("{ not json")
    with pytest.raises(recipes.RecipeRefused, match="not valid JSON"):
        recipes.catalogue()
    with pytest.raises(recipes.RecipeRefused, match="not valid JSON"):
        recipes.load("bad")

    (tmp_path / "bad.json").write_bytes(b"\xff\xfe{}")
    with pytest.raises(recipes.RecipeRefused, match="not valid UTF-8"):
        recipes.catalogue()

    # And the filename is in every one of them, because the reader is whoever opens it.
    (tmp_path / "bad.json").write_text("[]")
    with pytest.raises(recipes.RecipeRefused, match="bad"):
        recipes.catalogue()


def test_an_absent_catalogue_is_empty_rather_than_an_error(tmp_path, monkeypatch):
    """A deployment with no recipes is a legitimate deployment, not a broken one — and it
    is what rule 1 says a shrunk catalogue looks like at its limit."""
    monkeypatch.setattr(recipes, "RECIPES_DIR", tmp_path / "not-here")
    assert recipes.catalogue() == []
    assert recipes.load("anything") is None

    monkeypatch.setattr(recipes, "RECIPES_DIR", tmp_path)
    assert recipes.catalogue() == []


def test_the_recipe_files_are_declared_as_package_data():
    """**The failure that passes every test from source and ships an empty catalogue.**

    JSON beside a module is not code, so a wheel does not carry it unless
    `pyproject.toml` says so. `carnet.storage` names its migrations for exactly this
    reason and the comment there says why — but a missing migration is a loud error at
    start-up, where a missing recipe is an **empty catalogue**, which is
    indistinguishable from a build that ships none. Every deployment would print *this
    build ships no connector recipes* while the suite stayed green.

    Asserted against the declaration rather than by building a wheel, because a build in
    the unit suite is minutes of CI for a one-line fact. The wheel itself was built and
    installed by hand once, in step 068, and `--list-recipes` was run out of it.
    """
    # Read as text rather than with `tomllib`, which is 3.11 and this package floors at
    # 3.10 — the same fact `access/recipes.py` cites for why a recipe is JSON, applied
    # one file over and missed. CI caught it on the 3.10 leg the first time this branch
    # was ever put through CI; nothing local had run on 3.10.
    manifest = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"
    lines = manifest.read_text().splitlines()
    start = lines.index("[tool.setuptools.package-data]")
    body = []
    for line in lines[start + 1 :]:
        if line.startswith("["):
            break
        body.append(line)
    data = {"carnet.access": [entry for entry in body if '"carnet.access"' in entry]}

    assert any("recipes/*.json" in entry for entry in data["carnet.access"]), (
        "the recipe catalogue is data, not code, and an installed package will not carry "
        "it unless pyproject.toml declares it. Without this line every deployment ships "
        "an empty catalogue and says so as though it were intentional."
    )


def test_the_catalogue_is_found_relative_to_the_module():
    """And it resolves where the package actually is, rather than where the tests run.

    `RECIPES_DIR` is built from `__file__`, so a working directory cannot move it — which
    is what makes `--list-recipes` answer identically from a checkout, a wheel and the
    deployment image.
    """
    assert recipes.RECIPES_DIR.is_dir()
    assert recipes.RECIPES_DIR.parent == pathlib.Path(recipes.__file__).parent
    assert sorted(p.stem for p in recipes.RECIPES_DIR.glob("*.json")) == sorted(
        item["id"] for item in recipes.catalogue()
    )
