"""Config version history against real Postgres, through the real upgrade. Step 021.

Migration 032 adds `agents.version` and the `agent_versions` table, and backfills version
1 for every agent that already exists. Four things can only fail against a real database,
which is why this is a script and not a test:

  - **the backfill**, which the suite structurally cannot exercise. Its database is built
    from `001` every session, so 032 always runs against an empty `agents` table there and
    the `INSERT ... SELECT` is a no-op in every test that will ever run. The only order a
    deployment sees is the opposite one, and it is the one nothing else checks.
  - **the upgrade path** — rows written under 031, then 032 applied, then the same code
    reading them afterwards.
  - **the cascade**, twice over: `tenants` → `agents` → `agent_versions`. Neither chain
    exists in the fake, which hand-deletes instead, and the tenant-deletion catalog walk
    cannot see this table at all because its foreign key points at `agents` rather than at
    `tenants`.
  - **the suppression under a real jsonb comparison.** `IS DISTINCT FROM` on `jsonb`
    compares parsed documents; the fake compares dicts. That they agree is a claim about
    two different engines and is worth making against both.

**It builds its own database** — dropped and recreated on every run — so it needs nobody
at a keyboard.

    cd backend && .venv/bin/python scripts/e2e_versions.py

**Costs nothing.** No run is submitted, so no model is called and no connector launched.
"""

import http.server
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit, urlunsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"
DB = "carnet_versions"

# The HTTP half. A second database, because the first one is walked through the upgrade
# from 031 and this one wants the routes against a schema that is simply current — two
# questions, two worlds, and a shared one would make a failure in either ambiguous.
HTTP_DB = "carnet_versions_http"
ISSUER = "https://e2e-versions.local"
AUDIENCE = "api://default"
JWKS_PORT = 8907
API = "http://127.0.0.1:8129"
HTTP_TENANT = "e2eversions"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True)
JWK.update({"kid": "k1", "use": "sig", "alg": "RS256"})

# The three agents the pre-032 world holds, and the two tenants they are spread across —
# two tenants because a backfill that filtered on nothing and a backfill that filtered on
# the wrong thing look identical with one.
BEFORE = (("acme", "triage"), ("acme", "reporter"), ("globex", "triage"))


def dsn_for(database: str) -> str:
    """Where Postgres is. `CARNET_E2E_PG` is a base DSN with no database name."""
    base = os.environ.get("CARNET_E2E_PG") or f"postgresql://postgres:@/?host={SOCKET}"
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


DSN = dsn_for(DB)

CHECKS = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok))
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}"
          + ("" if ok else f"  (expected {expected!r})"))


def say(what):
    print(f"\n=== {what}", flush=True)


def field(row, *path):
    """Read a nested field without ever raising — 12c's `detail()`, for its reason.

    A route that answers the wrong shape should produce a **failed check**, not a
    `TypeError` on `None` that kills the run and reports one failure where ten follow.
    """
    for key in path:
        if row is None:
            return None
        try:
            row = row[key]
        except (KeyError, IndexError, TypeError):
            return None
    return row


def attempt(label, phase, *args):
    """Run one phase, and report a raise as a **failed check** rather than a traceback.

    12c's `detail()` doctrine, which 019 arrived at by mutating a migration and getting a
    crash where a count belonged. A script that dies still fails, so the mutation is
    technically caught — but it prints a stack trace instead of saying which property
    broke, and the next person reads it as "the script is broken" rather than "the thing
    under test is". Two of this script's own mutations did exactly that before this
    existed: dropping the backfill, and turning the cascade into a restrict.
    """
    try:
        phase(*args)
    except Exception as exc:  # noqa: BLE001 - the exception IS the finding
        CHECKS.append((f"{label} raised: {type(exc).__name__}: {exc}", False))
        print(f"  FAIL {label} raised: {type(exc).__name__}: {exc}")


def report():
    passed = sum(1 for _, ok in CHECKS if ok)
    print(f"\n=== {passed}/{len(CHECKS)} checks passed")
    for label, ok in CHECKS:
        if not ok:
            print(f"  FAILED: {label}")
    return 0 if passed == len(CHECKS) else 1


def token(sub, email):
    now = int(time.time())
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": sub,
            "email": email,
            "iat": now,
            "exp": now + 3600,
        },
        KEY,
        algorithm="RS256",
        headers={"kid": "k1"},
    )


class Jwks(http.server.BaseHTTPRequestHandler):
    """The identity provider's public key, over real HTTP — verified through exactly the
    production path, which does not know it is a fake."""

    def do_GET(self):
        body = json.dumps({"keys": [JWK]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def fresh_database(psycopg, name):
    import contextlib

    with contextlib.closing(psycopg.connect(dsn_for("postgres"), autocommit=True)) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        conn.execute(f"CREATE DATABASE {name}")


def the_world_before_032(psycopg, migrate):
    """Every migration up to and including 031, then agents, and stop.

    `created_at` and `updated_at` are deliberately days apart. With them equal, "the
    backfill used `updated_at`" and "the backfill used `created_at`" are the same
    assertion and neither is tested.
    """
    with psycopg.connect(DSN) as conn:
        migrate.applied(conn)
        conn.commit()
        for version, path in migrate.available():
            if version.startswith("032"):
                break
            with conn.cursor() as cur:
                cur.execute(path.read_text(encoding="utf-8"))
                cur.execute(
                    "INSERT INTO schema_migrations (version) VALUES (%s)", (version,)
                )
            conn.commit()

        conn.execute(
            "INSERT INTO tenants (id, name) VALUES ('acme', 'Acme'), ('globex', 'Globex')"
        )
        for tenant, name in BEFORE:
            conn.execute(
                "INSERT INTO agents (tenant_id, name, config, created_at, updated_at) "
                "VALUES (%s, %s, %s, now() - interval '9 days', "
                "        now() - interval '2 days')",
                (tenant, name, '{"name": "' + name + '", "system": "written before 032"}'),
            )
        conn.commit()

        check(
            "there is no history table yet, which is the state this upgrade starts from",
            conn.execute("SELECT to_regclass('agent_versions')::text").fetchone()[0],
            None,
        )


def the_backfill(psycopg, migrate):
    # **A corrupt row first, and the operator's whole arc**: blocked with a sentence
    # naming the row, fix it, re-run. Only hand-written SQL can produce a config whose
    # name disagrees with its key — 002's CHECK passes NULL and Python blocks every app
    # path — and a migration that failed on one with a bare constraint error would be a
    # blocked upgrade whose operator has to bisect ten thousand agents.
    with psycopg.connect(DSN) as conn:
        conn.execute(
            "INSERT INTO agents (tenant_id, name, config) VALUES "
            "('acme', 'corrupt', '{\"system\": \"nameless\"}')"
        )
        conn.commit()
    try:
        migrate.apply(DSN)
        check("a corrupt row blocks the migration", "it did not", "a refusal")
    except Exception as exc:  # noqa: BLE001 - the message IS the assertion
        text = str(exc)
        check("a corrupt row blocks the migration, naming the row",
              "acme.corrupt" in text and "Fix the row(s)" in text, True)
    with psycopg.connect(DSN) as conn:
        check(
            "and leaves nothing behind",
            conn.execute("SELECT to_regclass('agent_versions')::text").fetchone()[0],
            None,
        )
        conn.execute("DELETE FROM agents WHERE name = 'corrupt'")
        conn.commit()

    # **`[0]` rather than the whole list, and 022 is why.** This asserted
    # `== ["032_agent_versions"]`, which quietly also asserted that 032 was the newest
    # migration in the repository — true for exactly as long as it was, and broken by the
    # next step to add one. What this phase is about is that 032 was the migration
    # outstanding *here*, applied to a world built up to 031; anything after it is a later
    # step's business and its presence is not a finding.
    outstanding = migrate.apply(DSN)
    check("032 was the first migration outstanding", outstanding[:1], ["032_agent_versions"])
    check("and it ran before anything newer", sorted(outstanding), outstanding)

    with psycopg.connect(DSN) as conn:
        # Joined to `agents` for the name, because migration 035 re-keyed this table to
        # `agent_id` — the same join every read path takes now. What this phase asserts is
        # 032's backfill, and it is still the backfill under test: 035 ran in the same
        # `migrate.apply` above, so these rows were written by 032 against the name key and
        # carried across by 035.
        rows = conn.execute(
            "SELECT v.tenant_id, a.name, v.version, v.created_by, v.source, "
            "       v.restored_from, v.config->>'system' "
            "  FROM agent_versions v JOIN agents a "
            "    ON (a.tenant_id, a.agent_id) = (v.tenant_id, v.agent_id) "
            " ORDER BY v.tenant_id, a.name"
        ).fetchall()

        check("one version per agent that already existed", len(rows), len(BEFORE))
        check(
            "each is version 1, authored by the migration, carrying the live config",
            sorted({(r[2], r[3], r[4], r[5], r[6]) for r in rows}),
            [(1, "migration:032", "migration", None, "written before 032")],
        )
        check(
            "both tenants are covered",
            sorted({r[0] for r in rows}),
            ["acme", "globex"],
        )
        check(
            "and the live column agrees with the row it names",
            conn.execute("SELECT DISTINCT version FROM agents").fetchall(),
            [(1,)],
        )
        # What the column comment claims, and the reason it is `updated_at`: a version's
        # timestamp is when that configuration became live, not when the agent was made.
        check(
            "created_at is the agent's updated_at rather than its created_at",
            conn.execute(
                "SELECT count(*) FROM agents a JOIN agent_versions v "
                "  ON (a.tenant_id, a.agent_id) = (v.tenant_id, v.agent_id) "
                " WHERE v.created_at = a.updated_at AND v.created_at <> a.created_at"
            ).fetchone()[0],
            len(BEFORE),
        )
        check(
            "re-running the migration is a no-op, because deploys re-run migrations",
            migrate.apply(DSN),
            [],
        )


def the_writes(store):
    """The three write paths, on a database whose rows predate the table."""
    say("an edit of a backfilled agent continues its history rather than restarting it")
    row = store.get_agent("acme", "triage")
    store.update_agent(
        "acme",
        {**row["config"], "system": "edited after 032"},
        actor="user:u-1",
        if_unchanged_since=row["updated_at"],
    )
    versions = store.list_agent_versions("acme", "triage")
    check("version 2 sits on top of the backfilled 1",
          [v["version"] for v in versions], [2, 1])
    check("and the older one still says what it said",
          store.get_agent_version("acme", "triage", 1)["config"]["system"],
          "written before 032")
    check("the live row names the newest",
          store.get_agent("acme", "triage")["version"], 2)

    say("a no-change write adds nothing — the jsonb comparison, at the real engine")
    live = store.get_agent("acme", "triage")
    store.update_agent(
        "acme", live["config"], actor="user:u-1",
        if_unchanged_since=live["updated_at"],
    )
    check("still two versions", len(store.list_agent_versions("acme", "triage")), 2)
    check("but the ETag moved, exactly as 10d decided",
          store.get_agent("acme", "triage")["updated_at"] > live["updated_at"], True)

    say("a config whose keys are merely reordered is not a change")
    live = store.get_agent("acme", "triage")
    reordered = dict(reversed(list(live["config"].items())))
    store.update_agent(
        "acme", reordered, actor="user:u-1", if_unchanged_since=live["updated_at"]
    )
    check("still two versions", len(store.list_agent_versions("acme", "triage")), 2)

    say("a restore is a new version pointing back, never a pointer moving back")
    live = store.get_agent("acme", "triage")
    store.update_agent(
        "acme",
        store.get_agent_version("acme", "triage", 1)["config"],
        actor="user:u-2",
        if_unchanged_since=live["updated_at"],
        restored_from=1,
    )
    newest = store.get_agent_version("acme", "triage", 3)
    check("version 3 exists and came from 1",
          (newest["version"], newest["source"], newest["restored_from"]),
          (3, "restore", 1))
    check("the live config is version 1's text again",
          store.get_agent("acme", "triage")["config"]["system"], "written before 032")
    check("and version 2 is untouched, so the timeline is still readable",
          store.get_agent_version("acme", "triage", 2)["config"]["system"],
          "edited after 032")
    check("the log calls it a restore rather than an edit",
          store.admin_audit_records("acme")[-1]["action"], "agent.restore")

    say("no prompt reached the administrative log, which 022 forbids and 032 does not relax")
    text = str(store.admin_audit_records("acme"))
    check("NO PROMPT IN THE LOG", "written before 032" in text or "edited after 032" in text,
          False)


def the_cascades(psycopg, store):
    say("deleting an agent takes its history, including the backfilled row")
    store.delete_agent("acme", "reporter", actor="user:u-1")
    check("the history is gone", store.list_agent_versions("acme", "reporter"), [])
    check("the delete is still in the log",
          store.admin_audit_records("acme", action="agent.delete")[-1]["target_id"],
          "reporter")

    say("and a name re-created afterwards starts at 1 rather than inheriting")
    store.create_agent(
        "acme", {"name": "reporter", "system": "somebody else's agent"}, "user", "u-9"
    )
    versions = store.list_agent_versions("acme", "reporter")
    check("one version, authored by whoever made it",
          [(v["version"], v["created_by"], v["source"]) for v in versions],
          [(1, "user:u-9", "create")])

    say("deleting a tenant takes the history the catalog walk cannot see")
    store.set_tenant_status("globex", "suspended")
    store.delete_tenant("globex", actor="system:cli")
    with psycopg.connect(DSN) as conn:
        check(
            "no version rows left for the deleted tenant",
            conn.execute(
                "SELECT count(*) FROM agent_versions WHERE tenant_id = 'globex'"
            ).fetchone()[0],
            0,
        )
        check(
            "and the other tenant's history is untouched",
            conn.execute(
                "SELECT count(*) FROM agent_versions WHERE tenant_id = 'acme'"
            ).fetchone()[0],
            4,
        )


def the_constraints(psycopg):
    """What the schema refuses, asserted past the Python that refuses it first."""
    from carnet.storage.base import RESTORED_FROM_FK

    say("the constraints, reached directly rather than through a store")
    with psycopg.connect(DSN) as conn:
        # **The constraint's own name, read out of the catalog rather than trusted.**
        # 020's lesson: Postgres auto-names a constraint, a rename carries the old name
        # along, and `storage/base.py` hard-codes this one so a foreign-key violation is
        # reported as `ValueRefused` rather than as "unknown tenant". If the name ever
        # drifts, that mapping falls through silently.
        names = {
            row[0]
            for row in conn.execute(
                "SELECT conname FROM pg_constraint WHERE conrelid = 'agent_versions'::regclass"
            ).fetchall()
        }
        # Read out of `base.py` rather than spelled again here, which is the fix migration
        # 035 forced: this line held the literal name, 035 re-keyed the constraint, and a
        # test asserting a string against a string it no longer shares with the code would
        # have passed on both sides of a real drift. The constant is the one place the name
        # lives now, and this asks the catalogue whether it is true.
        check(
            "the restored_from key is named what base.py says it is",
            RESTORED_FROM_FK in names,
            True,
        )
        check(
            "and the agent key is too",
            "agent_versions_agent_fkey" in names,
            True,
        )
        # **Migration 035 dropped `agent_version_name_matches_config`, on purpose.** The
        # constraint said a version's stored config must name the agent it belongs to,
        # which was 002's rule one table over and stopped describing anything structural
        # the moment the key became `agent_id`. After a rename it would be false for every
        # version written under the old name — so the schema no longer asserts it, and this
        # asks the catalogue to confirm the drop rather than leaving the absence implied.
        check(
            "the config-name CHECK is gone, because the key is no longer the name",
            "agent_version_name_matches_config" in names,
            False,
        )

        # Every statement here names the agent by a subquery on `agents`, because migration
        # 035 replaced `agent_versions.agent_name` with `agent_id`. `'triage'` is still what
        # a reader sees; the column it lands in is the identity.
        triage = "(SELECT agent_id FROM agents WHERE tenant_id='acme' AND name='triage')"
        for label, sql, expect in (
            (
                "a restore that does not say what it restored",
                "INSERT INTO agent_versions (tenant_id, agent_id, version, config, "
                f"created_at, created_by, source) VALUES ('acme', {triage}, 98, "
                "'{\"name\": \"triage\"}', now(), 'x', 'restore')",
                "agent_version_restore_names_one",
            ),
            (
                "an ordinary edit claiming to have restored something",
                "INSERT INTO agent_versions (tenant_id, agent_id, version, config, "
                f"created_at, created_by, source, restored_from) VALUES ('acme', {triage}, "
                "97, '{\"name\": \"triage\"}', now(), 'x', 'update', 1)",
                "agent_version_restore_names_one",
            ),
            (
                "version zero",
                "INSERT INTO agent_versions (tenant_id, agent_id, version, config, "
                f"created_at, created_by, source) VALUES ('acme', {triage}, 0, "
                "'{\"name\": \"triage\"}', now(), 'x', 'update')",
                "agent_version_is_positive",
            ),
            (
                "a restore naming a version that was never written",
                "INSERT INTO agent_versions (tenant_id, agent_id, version, config, "
                f"created_at, created_by, source, restored_from) VALUES ('acme', {triage}, "
                "96, '{\"name\": \"triage\"}', now(), 'x', 'restore', 99)",
                RESTORED_FROM_FK,
            ),
            (
                "a version of an agent that does not exist",
                "INSERT INTO agent_versions (tenant_id, agent_id, version, config, "
                "created_at, created_by, source) VALUES ('acme', 'a_0000000000000000', 1, "
                "'{\"name\": \"ghost\"}', now(), 'x', 'create')",
                "agent_versions_agent_fkey",
            ),
        ):
            try:
                with conn.cursor() as cur:
                    cur.execute(sql)
                conn.rollback()
                check(label, "accepted", expect)
            except Exception as exc:  # noqa: BLE001 - the message IS the assertion
                conn.rollback()
                check(label, expect in str(exc), True)

        # **The other half of dropping `agent_version_name_matches_config`: what the schema
        # now accepts.** Two rows this table used to refuse — a config naming a different
        # agent, and a config with no name at all — go in cleanly, and that is the intended
        # consequence rather than a hole. After a rename every version written under the old
        # name is exactly the first case, so refusing it would make renaming an agent
        # corrupt its own history.
        #
        # Asserted rather than left as an absence, because a dropped constraint is invisible
        # in a suite that only ever tests refusals.
        for label, sql in (
            (
                "a version whose config names another agent is accepted after 035",
                "INSERT INTO agent_versions (tenant_id, agent_id, version, config, "
                f"created_at, created_by, source) VALUES ('acme', {triage}, 94, "
                "'{\"name\": \"what-it-was-called-before\"}', now(), 'x', 'update')",
            ),
            (
                "and so is one with no name at all",
                "INSERT INTO agent_versions (tenant_id, agent_id, version, config, "
                f"created_at, created_by, source) VALUES ('acme', {triage}, 93, "
                "'{\"system\": \"nameless\"}', now(), 'x', 'update')",
            ),
        ):
            with conn.cursor() as cur:
                cur.execute(sql)
            conn.rollback()
            check(label, "accepted", "accepted")


def the_http_arc(priya, sam):
    """The three routes, against real Postgres and a real token.

    **This is not what `tests/test_api.py` already covers.** Those drive the same routes
    through `TestClient` against the *in-memory* store, so the one thing they cannot
    exercise is the layer this step actually added: jsonb comparison, a timestamptz
    round-tripping through an `If-Match` header, and a counter advanced by a SQL
    expression. Everything below is the same code meeting a different engine.
    """
    config = {
        "name": "triage",
        "runtime": "simple",
        "system": "You trace incidents.",
        "permissions": {"tools": ["post_message"], "scope": {"chat.channel": {"write": ["#eng"]}}},
    }

    say("an agent, created over HTTP by a person")
    created = httpx.post(f"{API}/agents", json=config, headers=priya, timeout=30)
    check("created", created.status_code, 201)

    def open_agent(headers=priya):
        return httpx.get(f"{API}/agents/triage", headers=headers, timeout=30).json()

    def history(headers=priya):
        response = httpx.get(f"{API}/agents/triage/versions", headers=headers, timeout=30)
        return response.status_code, response.json()

    def edit(body, headers=priya, etag=None):
        return httpx.patch(
            f"{API}/agents/triage",
            json=body,
            headers={**headers, "If-Match": f'"{etag or open_agent()["updated_at"]}"'},
            timeout=30,
        )

    def restore(version, headers=priya, etag=None, precondition=True):
        head = dict(headers)
        if precondition:
            head["If-Match"] = f'"{etag or open_agent()["updated_at"]}"'
        return httpx.post(
            f"{API}/agents/triage/versions/{version}/restore", headers=head, timeout=30
        )

    status, rows = history()
    check("its history starts at one version", (status, len(rows)), (200, 1))
    check("authored by the person who made it", field(rows, 0, "created_by") is not None, True)
    check("and the detail route says which version is live", open_agent()["version"], 1)

    say("an edit, and the older configuration is still readable afterwards")
    check("edited", edit({"system": "Rewritten, badly."}).status_code, 200)
    check("two versions now", len(history()[1]), 2)
    first = httpx.get(f"{API}/agents/triage/versions/1", headers=priya, timeout=30).json()
    check("version 1 still says what it said",
          field(first, "config", "system"), "You trace incidents.")
    check("and the live one does not", open_agent()["config"]["system"], "Rewritten, badly.")

    say("a save that changes nothing: recorded, and not a version")
    before = open_agent()
    check("accepted", edit({"system": "Rewritten, badly."}).status_code, 200)
    after = open_agent()
    check("the version did not move", after["version"], before["version"])
    check("the ETag did", after["updated_at"] > before["updated_at"], True)
    check("still two versions", len(history()[1]), 2)

    say("a restore is a new version, and the field it removes is the point")
    check("a field the old version does not carry", edit({"model": "claude-haiku-4-5-20251001"}).status_code, 200)
    check("is live now", "model" in open_agent()["config"], True)
    restored = restore(1)
    check("restored", restored.status_code, 200)
    check("as a NEW version rather than a pointer moving back",
          field(restored.json(), "version"), 4)
    # The finding this route exists for: no `PATCH` can express this, because a merge
    # keeps every key the old config does not have.
    check("and the field is GONE, which no PATCH could have done",
          "model" in field(restored.json(), "config"), False)
    check("the version it replaced is still there",
          httpx.get(f"{API}/agents/triage/versions/3", headers=priya, timeout=30)
          .status_code, 200)
    check("and the history says where this one came from",
          field(history()[1], 0, "restored_from"), 1)

    say("the preconditions, which a restore owes exactly as an edit does")
    check("no If-Match is 428", restore(1, precondition=False).status_code, 428)
    stale = open_agent()["updated_at"]
    edit({"system": "Priya got here first."})
    conflicted = restore(1, etag=stale)
    check("a stale one is 409", conflicted.status_code, 409)
    check("naming what it would have written",
          "system" in field(conflicted.json(), "changed"), True)
    check("and nothing was written", len(history()[1]), 5)

    say("the grant ladder: a runner reads history and may not restore")
    httpx.put(
        f"{API}/agents/triage/grants/email/sam@acme.com",
        json={"role": "user"},
        headers=priya,
        timeout=30,
    )
    status, sam_sees = history(sam)
    check("sam can read it — the same bytes he can already read live", status, 200)
    check("and sees every version", len(sam_sees), 5)
    check("sam cannot restore, and is told the same 404 an absent agent gives",
          restore(1, headers=sam, etag=open_agent()["updated_at"]).status_code, 404)

    say("a version that stopped being restorable says so before the click")
    # `post_message` is a built-in, so the un-vetting has to happen to a connector tool:
    # this is the state a version reaches when an administrator revokes something after
    # it was legitimately granted.
    from carnet import storage

    storage.active().save_connector(
        HTTP_TENANT,
        {
            "id": "notes",
            "description": "",
            "launch": {"kind": "stdio", "command": ["/bin/true"]},
            "vetted": [
                {
                    "remote_name": "read_page",
                    "effect": "read",
                    "resources": [],
                    "local_name": None,
                    "max_response_bytes": None,
                }
            ],
        },
        actor="system:cli",
    )
    from carnet import tools

    granted = sorted(tools.known_names(HTTP_TENANT) - {"post_message"})[0]
    check("using it is a valid edit while it is vetted",
          edit({"permissions": {"tools": [granted], "scope": {}}}).status_code, 200)
    using = open_agent()["version"]
    edit({"permissions": {"tools": [], "scope": {}}})
    storage.active().save_connector(
        HTTP_TENANT,
        {
            "id": "notes",
            "description": "",
            "launch": {"kind": "stdio", "command": ["/bin/true"]},
            "vetted": [],
        },
        actor="system:cli",
    )

    rows = history()[1]
    stale_row = [row for row in rows if row["version"] == using][0]
    check("the list says that version can no longer be restored", stale_row["valid"], False)
    check("in the validator's own sentence", granted in (stale_row["error"] or ""), True)
    refused = restore(using)
    check("and the restore refuses with the same bytes", refused.status_code, 422)
    check("byte-identical, rather than a paraphrase",
          field(refused.json(), "detail"), stale_row["error"])
    check("while the live agent is untouched and still runnable",
          open_agent()["valid"], True)

    # --- 035i: what a rename does to the history it inherits -------------------------
    #
    # `POST /agents/{name}/rename` has been callable since 025 and never had a browser, so
    # 035i put a control on it — which makes *"everything survives it"* a promise a person
    # can now trigger by pressing a button. This asserts the version half of that promise
    # through HTTP rather than through the schema, which is what the constraint block above
    # reasons about and cannot demonstrate.
    say("a rename keeps the whole history, and adds a row rather than restarting one")
    before = history()[1]
    renamed = httpx.post(
        f"{API}/agents/triage/rename",
        json={"new_name": "triage-2026"},
        headers=priya,
        timeout=30,
    )
    check("the rename is a 200 carrying the whole agent", renamed.status_code, 200)
    check("at its new name", field(renamed.json(), "name"), "triage-2026")
    # No `If-Match` was sent and none was required — the one write on an agent without a
    # precondition, and the route argues why: a rename is one deliberate act from an owner.
    check("and a fresh ETag, which the caller did not have to supply one to earn",
          "ETag" in renamed.headers, True)

    after = httpx.get(f"{API}/agents/triage-2026/versions", headers=priya, timeout=30).json()
    check("every version that existed is still there", len(after), len(before) + 1)
    check("and the numbering continued rather than restarting",
          [row["version"] for row in after[1:]], [row["version"] for row in before])
    check("the rename is itself a version, which is why renaming to the same name is a 422",
          after[0]["version"], before[0]["version"] + 1)
    # A version written under the old name, read at the new one. This is the row the
    # dropped `agent_version_name_matches_config` CHECK would have refused, reached the
    # way a person reaches it rather than by an INSERT.
    old_one = httpx.get(f"{API}/agents/triage-2026/versions/1", headers=priya, timeout=30)
    check("a version written under the old name is readable at the new one",
          old_one.status_code, 200)
    check("and it still says what it said, including the name it was written under",
          field(old_one.json(), "config", "name"), "triage")
    # Decision 9 of 025: no redirect and no memory of former names.
    check("the old name is an ordinary 404 with nothing routed through it",
          httpx.get(f"{API}/agents/triage/versions", headers=priya, timeout=30).status_code,
          404)
    # Everything else survived too — sam's `user` grant from the ladder block above is the
    # one this arc already holds, so it is the one asserted.
    check("and the grant made under the old name came with it",
          httpx.get(f"{API}/agents/triage-2026", headers=sam, timeout=30).status_code, 200)

    say("no prompt reached the administrative log, which 022 forbids and 021 does not relax")
    log = httpx.get(f"{API}/admin/audit", headers=priya, timeout=30)
    text = log.text if log.status_code == 200 else ""
    check("NO PROMPT IN THE LOG", "You trace incidents." in text, False)


def http_world(psycopg):
    """A database, a tenant, a provider and a running server. Torn down by the caller."""
    fresh_database(psycopg, HTTP_DB)
    dsn = dsn_for(HTTP_DB)

    os.environ["CARNET_DATABASE_URL"] = dsn
    os.environ.setdefault("CARNET_SECRET_KEY", _generate_key())
    os.environ["WORKERS"] = "0"

    from carnet import storage
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    migrate.apply(dsn)
    store = storage.configure(PostgresStorage(dsn))
    store.create_tenant(HTTP_TENANT, "021 over HTTP")
    store.save_tenant_idp(
        HTTP_TENANT,
        {
            "issuer": ISSUER,
            "jwks_uri": f"http://127.0.0.1:{JWKS_PORT}/jwks.json",
            "audience": AUDIENCE,
            "allowed_domains": ("acme.com",),
        },
    )

    jwks = http.server.ThreadingHTTPServer(("127.0.0.1", JWKS_PORT), Jwks)
    threading.Thread(target=jwks.serve_forever, daemon=True).start()

    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "carnet.api:app", "--port",
         API.rsplit(":", 1)[1]],
        env={**os.environ, "CARNET_TENANT": HTTP_TENANT},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(60):
        try:
            httpx.get(f"{API}/health", timeout=1)
            break
        except Exception:
            time.sleep(0.5)
    else:
        api.terminate()
        raise SystemExit("uvicorn did not come up")

    return api, jwks


def _generate_key():
    import base64

    return base64.b64encode(os.urandom(32)).decode()


def main():
    root = pathlib.Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root / "src"))

    import psycopg

    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    print(__doc__.strip().splitlines()[0])
    print(f"database: {DSN}\n")

    fresh_database(psycopg, DB)

    say("a database at 031, holding three agents whose history nothing recorded")
    attempt("the pre-032 world", the_world_before_032, psycopg, migrate)

    say("then 032, and the backfill that is the only part a deployment sees")
    attempt("the backfill", the_backfill, psycopg, migrate)

    store = PostgresStorage(DSN)
    try:
        attempt("the write paths", the_writes, store)
        attempt("the cascades", the_cascades, psycopg, store)
    finally:
        store.close()

    attempt("the constraints", the_constraints, psycopg)

    say("and now the routes, against a real server and a real token")
    api, jwks = http_world(psycopg)
    try:
        attempt(
            "the HTTP arc",
            the_http_arc,
            {"Authorization": f"Bearer {token('00u-priya', 'priya@acme.com')}"},
            {"Authorization": f"Bearer {token('00u-sam', 'sam@acme.com')}"},
        )
    finally:
        api.terminate()
        api.wait(timeout=10)
        jwks.shutdown()
        # Closed rather than left to the interpreter. `e2e_oauth_edges.py` leaves its
        # pool open and prints a `PythonFinalizationError` from psycopg_pool's `__del__`
        # **after** reporting 77/77 — harmless, exit code 0, and it reads exactly like a
        # failure to whoever runs it next.
        from carnet import storage as _storage

        _storage.active().close()

    return report()


if __name__ == "__main__":
    sys.exit(main())
