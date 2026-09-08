"""Registering from a recipe, end to end, against real Postgres. Step 068.

**Not a test, and here for `e2e_registration.py`'s reason**: `tests/` runs against the
in-memory store by default, and this step adds a migration whose whole subject is a column
— `connector_oauth.scope_notes`, which is JSONB in one store and a dict in the other.

What it drives is the arc a customer's first hour actually takes:

    --list-recipes      what this build ships, and when each was last checked
    --allow-host        still theirs, twice, because a recipe approves nothing
    --add-connector     --from-recipe, which fills the flags and nothing else
    --set-oauth         --from-recipe, with the client id that is only ever theirs
    --vet               --from-recipe, one tool, still one command

And then the four properties that are the whole design and that decay quietly:

  1. **A recipe registration is indistinguishable from a hand one.** Same rows, same
     review record, differing only in `admin_audit.detail.from_recipe`.
  2. **A recipe vets nothing**, including the one that proposes a fully authored REST
     binding — which is the largest thing it could be tempted to apply for you.
  3. **A recipe approves no host**, and the refusal before one is approved is the
     ordinary egress refusal with the ordinary remedy.
  4. **Deleting every recipe leaves everything registered working**, because nothing in
     the database points back at one. That is what makes the catalogue shrinkable, which
     is what makes a bounded catalogue possible at all.

    cd backend && .venv/bin/python scripts/e2e_recipe_registration.py

Needs Postgres. `CARNET_E2E_PG` is a base DSN with no database name.

**Costs nothing and contacts nothing.** No vendor is dialled: registration checks egress
and writes a row, and `--vet` on a REST connector authors rather than discovers, so there
is no server to reach. Probing the real vendors is `verify_recipes.py`, which is
hand-run and deliberately not this.
"""

import os
import pathlib
import sys
from urllib.parse import urlsplit, urlunsplit

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_e2e_recipes"

TENANT = "e2erecipe"
ACTOR = "system:cli"

CHECKS = []


def dsn_for(database: str) -> str:
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit(
        (parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment)
    )


DSN = dsn_for(DB)


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok))
    print(
        f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}"
        + ("" if ok else f"  (expected {expected!r})")
    )


def step(what):
    print(f"\n=== {what}", flush=True)


def _generate_key():
    from carnet.core import crypto

    return crypto.generate_key()


def main():
    import psycopg

    with psycopg.connect(dsn_for("postgres"), autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB} WITH (FORCE)")
        conn.execute(f"CREATE DATABASE {DB}")

    os.environ["CARNET_DATABASE_URL"] = DSN
    os.environ.setdefault("CARNET_SECRET_KEY", _generate_key())

    from carnet import storage, tools
    from carnet.access import oauth, recipes
    from carnet.core import crypto
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage
    from carnet.tools import mcp

    # The env var alone is not enough: an entry point has to install the key, and this
    # script is one. `cli.main` does the same thing at the same point.
    crypto.configure(crypto.from_environment())

    applied = migrate.apply(DSN)
    check("migrations applied include 051", "051_oauth_scope_notes" in applied, True)

    store = storage.configure(PostgresStorage(DSN))
    store.create_tenant(TENANT, "068 end to end")

    # --- the catalogue -----------------------------------------------------------------

    step("the catalogue loads, and every recipe in it is honest about being checked")

    catalogue = recipes.catalogue()
    check("recipes ship", len(catalogue) > 0, True)
    check(
        "and none exceeds the ceiling",
        len(catalogue) <= recipes.CEILING,
        True,
    )
    check(
        "none carries a client id or secret",
        [
            item["id"]
            for item in catalogue
            if set(item.get("oauth") or {}) & {"client_id", "client_secret"}
        ],
        [],
    )

    jira = recipes.load("atlassian-jira")
    anthropic = recipes.load("anthropic-messages")
    check("the Jira recipe has a consent flow", bool(jira["oauth"]), True)
    check("the Anthropic recipe proposes a tool", len(anthropic["tools"]), 1)

    # --- a recipe approves no host -----------------------------------------------------

    step("a recipe names the hosts it needs and approves none of them")

    check("no hosts approved yet", store.allowed_hosts(TENANT), [])
    check(
        "the Jira recipe names two",
        sorted(h["host"] for h in jira["hosts"]),
        ["auth.atlassian.com", "mcp.atlassian.com"],
    )
    check(
        "and each says why, because approving one is a judgment",
        all((h.get("why") or "").strip() for h in jira["hosts"]),
        True,
    )

    try:
        tools.register_connector(
            TENANT,
            "jira",
            url=jira["connector"]["url"],
            kind=jira["connector"]["kind"],
            credential_env=jira["connector"]["credential_env"],
            from_recipe=jira["id"],
            actor=ACTOR,
        )
        check("registering before the host is approved", "allowed", "refused")
    except mcp.EgressRefused as exc:
        check("registering before the host is approved is refused", True, True)
        check("and the refusal names the host", "mcp.atlassian.com" in str(exc), True)

    check("nothing was registered", store.load_connectors(TENANT), [])
    check("and nothing was allowed", store.allowed_hosts(TENANT), [])

    # --- the arc ------------------------------------------------------------------------

    step("approve the hosts — a separate act, by somebody who can make it")

    for entry in jira["hosts"]:
        store.allow_host(TENANT, entry["host"], actor=ACTOR, note=entry["why"])
    check("two hosts approved", len(store.allowed_hosts(TENANT)), 2)

    step("register from the recipe, and by hand, and compare the rows")

    def register(connector_id, recipe, cite):
        preset = recipe["connector"]
        tools.register_connector(
            TENANT,
            connector_id,
            url=preset["url"],
            kind=preset.get("kind", "http"),
            credential_env=preset.get("credential_env") or "",
            credential_header=preset.get("credential_header"),
            credential_prefix=preset.get("credential_prefix"),
            headers=dict(preset.get("headers") or {}) or None,
            description=preset.get("description") or "",
            from_recipe=recipe["id"] if cite else "",
            actor=ACTOR,
        )

    register("jira", jira, cite=True)
    register("jira-by-hand", jira, cite=False)

    left = dict(store.get_connector(TENANT, "jira"))
    right = dict(store.get_connector(TENANT, "jira-by-hand"))
    left.pop("id", None)
    right.pop("id", None)
    check("a recipe row is byte-identical to a hand row", left, right)

    records = {
        row["target_id"]: row
        for row in store.admin_audit_records(TENANT, action="connector.create")
    }
    check(
        "and the only difference in the review record is where it came from",
        records["jira"]["detail"]["from_recipe"],
        "atlassian-jira",
    )
    check(
        "the hand one cites nothing",
        records["jira-by-hand"]["detail"]["from_recipe"],
        "",
    )
    check(
        "and every other key matches",
        {k: v for k, v in records["jira"]["detail"].items() if k != "from_recipe"},
        {k: v for k, v in records["jira-by-hand"]["detail"].items() if k != "from_recipe"},
    )

    # --- the consent flow ----------------------------------------------------------------

    step("the consent flow, whose client id is the only field a recipe cannot fill")

    app = jira["oauth"]
    row = oauth.configure(
        TENANT,
        "jira",
        authorize_endpoint=app["authorize_endpoint"],
        token_endpoint=app["token_endpoint"],
        revoke_endpoint=app.get("revoke_endpoint") or "",
        client_id="the-customers-own-client-id",
        client_secret="MARKER-CLIENT-SECRET-068",
        scopes=tuple(app["scopes"]),
        authorize_params=dict(app["authorize_params"]),
        scope_notes=app["scope_notes"],
        actor=ACTOR,
    )

    check(
        "the endpoints came from the recipe",
        row["token_endpoint"],
        app["token_endpoint"],
    )
    check(
        "Atlassian's two mandated authorize parameters came with them",
        sorted(row["authorize_params"]),
        ["audience", "prompt"],
    )
    check(
        "a write scope carries the sentence a consent screen needs",
        row["scope_notes"]["write:jira-work"]["access"],
        "write",
    )
    check(
        "and a scope with nothing to say has no entry, rather than an empty one",
        "offline_access" in row["scope_notes"],
        False,
    )

    step("what the log kept, and what it did not")

    configured = store.admin_audit_records(
        TENANT, action="connector.oauth.configure"
    )[-1]
    check(
        "the record names which scopes were described",
        configured["detail"]["described_scopes"],
        ["read:jira-work", "write:jira-work"],
    )
    check(
        "and holds none of the prose",
        "Changes nothing" in repr(configured),
        False,
    )
    check(
        "and no secret, as ever",
        any(
            "MARKER-CLIENT-SECRET" in repr(record)
            for record in store.admin_audit_records(TENANT)
        ),
        False,
    )

    # --- a recipe vets nothing -----------------------------------------------------------

    step("a recipe proposes tools and approves none, including a full REST binding")

    store.allow_host(TENANT, "api.anthropic.com", actor=ACTOR, note="the model API")
    register("anthropic", anthropic, cite=True)

    check(
        "the connector is registered",
        store.get_connector(TENANT, "anthropic") is not None,
        True,
    )
    check(
        "and nothing on it is vetted, though the recipe proposed a whole binding",
        store.get_connector(TENANT, "anthropic").get("vetted") or [],
        [],
    )
    check(
        "no tool.vet record exists anywhere",
        store.admin_audit_records(TENANT, action="tool.vet"),
        [],
    )

    step("vetting from the proposal is still one command, and still a person's judgment")

    proposal = anthropic["tools"][0]
    from carnet.tools.base import Resource

    tools.vet_tool(
        TENANT,
        "anthropic",
        proposal["remote_name"],
        effect=proposal["effect"],
        identity=proposal["identity"],
        resources=tuple(
            Resource(type=r["type"], args=tuple(r["args"]), template=r.get("template"))
            for r in proposal["resources"]
        ),
        note=proposal["note"],
        description=proposal["description"],
        redact_args=tuple(proposal["redact_args"]),
        binding=proposal["binding"],
        max_response_bytes=None,
        local_name=None,
        credential=None,
        actor=ACTOR,
    )

    vetted = store.get_connector(TENANT, "anthropic")["vetted"]
    check("one tool, approved by a person", len(vetted), 1)
    check("with the effect the proposal suggested", vetted[0]["effect"], "write")
    check(
        "and the redactions that keep prompts out of the log",
        sorted(vetted[0]["redact_args"]),
        ["messages", "system"],
    )

    review = store.load_vetting_record(TENANT)
    check(
        "the review record names the person, not the recipe",
        [r["vetted_by"] for r in review],
        [ACTOR],
    )

    # --- the catalogue can shrink ---------------------------------------------------------

    step("deleting every recipe leaves everything registered working")

    recipes.RECIPES_DIR = pathlib.Path("/nonexistent-catalogue")
    check("the catalogue is empty", recipes.catalogue(), [])

    check(
        "the connector still resolves",
        store.get_connector(TENANT, "jira") is not None,
        True,
    )
    check(
        "its consent flow still resolves, with its prose",
        store.get_connector_oauth(TENANT, "jira")["scope_notes"]["write:jira-work"][
            "access"
        ],
        "write",
    )
    check("the vetted tool survives", len(store.get_connector(TENANT, "anthropic")["vetted"]), 1)
    check(
        "and the record of where it came from survives, because it was never a link",
        records["jira"]["detail"]["from_recipe"],
        "atlassian-jira",
    )

    passed = sum(1 for _label, ok in CHECKS if ok)
    failed = [label for label, ok in CHECKS if not ok]
    print(f"\n=== {passed}/{len(CHECKS)} checks passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
