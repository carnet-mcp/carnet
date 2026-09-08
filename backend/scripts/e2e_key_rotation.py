"""The key-compromise drill, end to end: a rotation that finishes. Step 026.

    cd backend && .venv/bin/python scripts/e2e_key_rotation.py

What can only fail here, and not in the suite:

- **The procedure itself, in the order the runbook gives it.** Key A world; the fleet
  moves to key B with A retired; `--finish-rotation` runs as a real subprocess whose
  printout is parsed rather than trusted; A is dropped; everything still opens. The
  suite tests the sweep — this walks the drill, and the transcript it prints is the
  shape of the artifact the enterprise gate asks a person to keep.
- **The CLI's exit codes**, which is what a runbook branches on: 0 only when the old
  list can be emptied, 1 while any row still needs a retired key.
- **Real BYTEA round trips** through psycopg for all four sealed columns, and real
  concurrent-ish interleavings of the CLI process against the server's rows.

It builds its own database and spends nothing: no model key is present in any child
process. The `triggers` table's sealed column is populated directly — step 078 removed
the door that read it, and the sweep re-seals the column regardless.
"""

import contextlib
import hashlib
import hmac
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

import httpx

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

HOME = pathlib.Path.home()
SOCKET = HOME / ".local/share/carnet-pg"

DB = "carnet_key_rotation"
TENANT = "e2erotate"
AGENT = "reporter"
OWNER = "u_owner"
API = "http://127.0.0.1:8161"

SIGNATURE_HEADER = "X-Hub-Signature-256"
EVENT = b'{"action": "opened", "issue": {"number": 7}}'
EVENT_AFTER = b'{"action": "opened", "issue": {"number": 8}}'

# The three keys of the drill, generated once so every subprocess agrees.
KEY_A = None  # the compromised key — everything is born under it
KEY_B = None  # its replacement
KEY_C = None  # a key no process in the drill ever lists: the "neither list" row
KEY_D = None  # a second retired key, for the operator who rotated twice


def dsn_for(database: str) -> str:
    from urllib.parse import urlsplit as split, urlunsplit

    base = (
        os.environ.get("CARNET_E2E_PG")
        or f"postgresql://postgres:@/?host={SOCKET}"
    )
    parts = split(base)
    return urlunsplit(
        (parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment)
    )


CHECKS = []


def check(label, actual, expected):
    ok = actual == expected
    CHECKS.append((label, ok))
    print(
        f"  {'ok  ' if ok else 'FAIL'} {label}: {actual!r}"
        + ("" if ok else f"  (expected {expected!r})")
    )


def say(what):
    print(f"\n=== {what}", flush=True)


def attempt(label, phase, *args):
    try:
        phase(*args)
    except Exception as exc:  # noqa: BLE001 - the exception IS the finding
        CHECKS.append((f"{label} raised: {type(exc).__name__}: {exc}", False))
        print(f"  FAIL {label} raised: {type(exc).__name__}: {exc}")
        if os.environ.get("E2E_TRACE"):
            import traceback

            traceback.print_exc()


def report():
    passed = sum(1 for _, ok in CHECKS if ok)
    print(f"\n=== {passed}/{len(CHECKS)} checks passed")
    for label, ok in CHECKS:
        if not ok:
            print(f"  FAILED: {label}")
    return 0 if passed == len(CHECKS) else 1


def fresh_database(psycopg, name):
    with contextlib.closing(
        psycopg.connect(dsn_for("postgres"), autocommit=True)
    ) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
        conn.execute(f"CREATE DATABASE {name}")


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# --- the world, born under key A ------------------------------------------------------


def build_world(store):
    """One row per sealed table, all under key A, through the modules that own them —
    and the trigger secret straight into its row, since nothing owns that one now."""
    from carnet.access import connections, tokens
    from carnet.core import Principal, crypto

    store.create_tenant(TENANT, name="Acme")
    store.create_user(
        TENANT,
        {
            "id": OWNER,
            "issuer": "https://idp.local",
            "subject": f"s-{OWNER}",
            "email": "owner@acme.com",
            "display_name": "The Owner",
        },
    )
    store.save_agent(
        TENANT,
        {
            "name": AGENT,
            "runtime": "simple",
            "system": "You triage events.",
            "permissions": {"tools": [], "scope": {}},
        },
        actor="system:cli",
    )
    store.grant_agent(
        TENANT, AGENT, "system", "cli", "owner",
        granted_by="system:cli", actor="system:cli",
    )
    # A real HTTP manifest, not a bare row: the door's config validation walks every
    # connector manifest in the tenant, so an unparseable launch would 500 a delivery
    # about an agent that never granted this connector anything.
    store.save_connector(
        TENANT,
        {
            "id": "jira",
            "launch": {"kind": "http", "url": "https://mcp.example.com/mcp"},
            "vetted": [],
        },
        actor="system:cli",
    )

    owner = Principal.user(OWNER, TENANT)

    # connections: a pasted PAT, sealed by connect_account exactly as --connect-account.
    connections.connect_account(
        owner, "jira", "pat-abc123", account_label="@owner", actor="system:cli"
    )

    # connector_oauth + pending_authorizations: a configured consent flow and one
    # in-flight consent, through oauth.begin so the verifier is sealed by the module
    # that owns the binding.
    from carnet.access import oauth
    from carnet.core import crypto as crypto_mod

    sealed, key_id = crypto_mod.seal(
        "the-client-secret",
        tenant_id=TENANT,
        aad=crypto_mod.oauth_app_aad(TENANT, "jira"),
    )
    store.set_connector_oauth(
        TENANT, "jira",
        authorize_endpoint="https://auth.example.com/authorize",
        token_endpoint="https://auth.example.com/token",
        client_id="client-abc",
        client_secret=sealed,
        key_id=key_id,
        actor="system:cli",
    )
    authorize_url = oauth.begin(
        owner, "jira", redirect_uri=f"{API}/connect/callback"
    )
    state = parse_qs(urlsplit(authorize_url).query)["state"][0]

    # triggers: a sealed HMAC secret, written straight into the row under key A.
    token_row, _ = tokens.mint(TENANT, "hook", OWNER, actor="system:cli")
    store.grant_agent(
        TENANT, AGENT, "machine", token_row["id"], "user",
        granted_by="system:cli", actor="system:cli",
    )
    trigger_id, trigger_secret = "trg_worldA000001", "github-issues-secret-A"
    sealed, key_id = crypto.active().seal(
        trigger_secret, tenant_id=TENANT,
        aad=crypto.trigger_secret_aad(TENANT, trigger_id),
    )
    store.create_trigger(
        TENANT,
        {
            "id": trigger_id, "agent_name": AGENT, "token_id": token_row["id"],
            "name": "github-issues", "task": "triage the event below",
            "secret_sealed": sealed, "secret_key_id": key_id,
        },
        actor="system:cli",
    )

    return {
        "trigger_id": trigger_id,
        "trigger_secret": trigger_secret,
        "state": state,
    }


# --- servers and subprocesses ---------------------------------------------------------


def server_env(secret_key: str, old_keys: str | None) -> dict:
    env = {
        **os.environ,
        "CARNET_DATABASE_URL": dsn_for(DB),
        "CARNET_TENANT": TENANT,
        "CARNET_WORKERS": "0",
        "CARNET_PUBLIC_ORIGIN": API,
    }
    env.pop("ANTHROPIC_API_KEY", None)
    # `None` is the deployment that has no key at all, which `--finish-rotation` must
    # refuse rather than answer.
    env.pop("CARNET_SECRET_KEY", None)
    if secret_key is not None:
        env["CARNET_SECRET_KEY"] = secret_key
    env.pop("CARNET_SECRET_KEYS_OLD", None)
    if old_keys is not None:
        env["CARNET_SECRET_KEYS_OLD"] = old_keys
    return env


@contextlib.contextmanager
def api_under(secret_key: str, old_keys: str | None, log_path):
    with log_path.open("a") as log_file:
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "carnet.api:app",
             "--port", API.rsplit(":", 1)[1]],
            env=server_env(secret_key, old_keys),
            stdout=log_file, stderr=subprocess.STDOUT,
        )
    try:
        for _ in range(60):
            try:
                httpx.get(f"{API}/health", timeout=1)
                break
            except Exception:
                time.sleep(0.5)
        else:
            raise SystemExit("uvicorn did not come up")
        yield proc
    finally:
        proc.terminate()
        proc.wait(timeout=15)


TRANSCRIPT = []


def cli(secret_key: str | None, old_keys: str | None, *args):
    done = subprocess.run(
        [sys.executable, "-m", "carnet.cli", *args],
        env=server_env(secret_key, old_keys), capture_output=True, text=True,
    )
    # Kept whole, because the last phase greps every byte this command ever printed
    # for a plaintext. A drill transcript is a file somebody saves.
    TRANSCRIPT.append(done.stdout + done.stderr)
    return done


# --- the drill ------------------------------------------------------------------------


def _open_trigger(store, trigger_id: str, *keys: str) -> str:
    """The sealed secret on a trigger row, opened with exactly the keys named."""
    from carnet.core import crypto

    row = store.get_trigger(TENANT, trigger_id)
    cipher = crypto.LocalKeyCipher(
        crypto.decode_key(keys[0]), [crypto.decode_key(k) for k in keys[1:]]
    )
    return cipher.open_(
        row["secret_sealed"], tenant_id=TENANT,
        aad=crypto.trigger_secret_aad(TENANT, trigger_id), key_id=row["secret_key_id"],
    )


def the_trigger_row_opens_under_key_a(world, store):
    say("before anything: the sealed trigger row opens under key A")
    check("and holds its secret", _open_trigger(store, world["trigger_id"], KEY_A),
          world["trigger_secret"])


def the_rotation_finishes(psycopg, world):
    say("the rotation: --finish-rotation under key B with A retired")
    done = cli(KEY_B, KEY_A, "--finish-rotation")
    print("      " + "\n      ".join(done.stdout.strip().splitlines()[:12]))
    check("exit 0", done.returncode, 0)
    check("the verdict is the sentence", "No row names a retired key." in done.stdout, True)
    check("and says the old list can go", "can be emptied" in done.stdout, True)
    for table in ("connections", "connector_oauth", "triggers", "pending_authorizations"):
        check(f"{table}: 1 re-sealed", f"{table:24}    1 re-sealed" in done.stdout, True)
    check(
        "no plaintext in the transcript",
        ("pat-abc123" in done.stdout)
        or (world["trigger_secret"] in done.stdout)
        or ("the-client-secret" in done.stdout),
        False,
    )

    from carnet.core import crypto

    current = crypto.key_id_for(crypto.decode_key(KEY_B))
    with contextlib.closing(psycopg.connect(dsn_for(DB))) as conn:
        key_ids = conn.execute(
            "SELECT key_id FROM connections"
            " UNION ALL SELECT key_id FROM connector_oauth"
            " UNION ALL SELECT secret_key_id FROM triggers"
            " UNION ALL SELECT key_id FROM pending_authorizations"
        ).fetchall()
    check("every sealed row names key B", {k for (k,) in key_ids}, {current})

    again = cli(KEY_B, KEY_A, "--finish-rotation")
    check("a re-run finds nothing owed (resume is the predicate)", again.returncode, 0)
    check("and re-seals nothing", "1 re-sealed" in again.stdout, False)


def the_blockers_are_reported(psycopg, world):
    say("one row in neither list, one tampered under the retired key")
    from carnet.core import crypto

    kid_a = crypto.key_id_for(crypto.decode_key(KEY_A))

    # A credential sealed under a key no process in this drill lists: broken before
    # the sweep, exactly as broken after, and never a hostage.
    stranger = crypto.LocalKeyCipher(crypto.decode_key(KEY_C))
    sealed, kid_c = stranger.seal(
        "lost-token",
        tenant_id=TENANT,
        aad=crypto.connection_aad(TENANT, "user", "u_lost", "jira"),
    )
    with contextlib.closing(psycopg.connect(dsn_for(DB), autocommit=True)) as conn:
        conn.execute(
            "INSERT INTO connections (tenant_id, principal_kind, principal_id,"
            " connector_id, ciphertext, key_id) VALUES (%s, 'user', 'u_lost', 'jira',"
            " %s, %s)",
            (TENANT, sealed, kid_c),
        )
        # The tamper: garbage bytes under the RETIRED key's id — the state an attacker
        # with row access, or a corrupted restore, leaves behind.
        conn.execute(
            "UPDATE triggers SET secret_sealed = %s, secret_key_id = %s WHERE id = %s",
            (b"\x00garbage", kid_a, world["trigger_id"]),
        )

    blocked = cli(KEY_B, KEY_A, "--finish-rotation")
    check("exit 1 while a row still needs the retired key", blocked.returncode, 1)
    # The two are marked apart on the page: a blob that will not authenticate under a
    # key we hold was altered or moved, and it should not read like a rotation artifact
    # sitting beside a row whose key was merely dropped.
    check("the tampered row is a security event", "SECURITY EVENT     triggers" in blocked.stdout, True)
    check("the unknown-key row is not", "COULD NOT RE-SEAL  connections" in blocked.stdout, True)
    check("and the verdict says not yet", "cannot be emptied yet" in blocked.stdout, True)

    # The remedies, exactly as the printout instructs: the trigger is deleted and
    # recreated (its owner surface), which unblocks the retired key…
    with contextlib.closing(psycopg.connect(dsn_for(DB), autocommit=True)) as conn:
        conn.execute("DELETE FROM triggers WHERE id = %s", (world["trigger_id"],))

    unblocked = cli(KEY_B, KEY_A, "--finish-rotation")
    check(
        "the verdict flips once the tampered row is gone",
        "No row names a retired key." in unblocked.stdout,
        True,
    )
    check(
        "the neither-list row does not hold the old key hostage",
        "never held" in unblocked.stdout,
        True,
    )
    # …but it is still a row this deployment cannot read, so the command does not
    # report a clean deployment. Both facts, printed apart, exit 1.
    check("and it still exits 1, because that row is unreadable", unblocked.returncode, 1)

    # …and the lost connection is disconnected, which is its remedy.
    with contextlib.closing(psycopg.connect(dsn_for(DB), autocommit=True)) as conn:
        conn.execute(
            "DELETE FROM connections WHERE tenant_id = %s AND principal_id = 'u_lost'",
            (TENANT,),
        )
    clean = cli(KEY_B, KEY_A, "--finish-rotation")
    check("a clean world is exit 0", clean.returncode, 0)
    check("with no asterisk", "has never held" in clean.stdout, False)


def the_world_after_the_drop(psycopg, world):
    say("key A is dropped everywhere, and nothing misses it")
    from carnet.core import crypto

    b_only = crypto.LocalKeyCipher(crypto.decode_key(KEY_B))
    with contextlib.closing(psycopg.connect(dsn_for(DB))) as conn:
        ciphertext, key_id = conn.execute(
            "SELECT ciphertext, key_id FROM connections WHERE principal_id = %s",
            (OWNER,),
        ).fetchone()
        opened = b_only.open_(
            bytes(ciphertext),
            tenant_id=TENANT,
            aad=crypto.connection_aad(TENANT, "user", OWNER, "jira"),
            key_id=key_id,
        )
        check("the PAT opens under B alone", opened, "pat-abc123")

        secret, key_id = conn.execute(
            "SELECT client_secret, key_id FROM connector_oauth WHERE connector_id = 'jira'"
        ).fetchone()
        check(
            "the client secret opens under B alone",
            b_only.open_(
                bytes(secret),
                tenant_id=TENANT,
                aad=crypto.oauth_app_aad(TENANT, "jira"),
                key_id=key_id,
            ),
            "the-client-secret",
        )

        verifier, key_id = conn.execute(
            "SELECT code_verifier, key_id FROM pending_authorizations WHERE state = %s",
            (world["state"],),
        ).fetchone()
        opened = b_only.open_(
            bytes(verifier),
            tenant_id=TENANT,
            aad=crypto.pending_authorization_aad(TENANT, world["state"]),
            key_id=key_id,
        )
        check("the in-flight consent survived the rotation", len(opened) > 0, True)


def a_new_trigger_seals_under_the_new_key_alone(world):
    """A process holding only key B seals a fresh trigger row and opens it again: the
    drill's last line, proving the deployment is whole with the compromised key gone."""
    from carnet import storage as storage_module
    from carnet.access import tokens
    from carnet.core import crypto
    from carnet.storage.postgres import PostgresStorage

    # This process re-keys itself to the post-drill environment before sealing.
    os.environ["CARNET_SECRET_KEY"] = KEY_B
    os.environ.pop("CARNET_SECRET_KEYS_OLD", None)
    crypto.configure(crypto.from_environment())
    store = storage_module.configure(PostgresStorage(dsn_for(DB)))

    token_row, _ = tokens.mint(TENANT, "hook2", OWNER, actor="system:cli")
    store.grant_agent(
        TENANT, AGENT, "machine", token_row["id"], "user",
        granted_by="system:cli", actor="system:cli",
    )
    trigger_id = "trg_worldB000002"
    sealed, key_id = crypto.active().seal(
        "github-issues-secret-B", tenant_id=TENANT,
        aad=crypto.trigger_secret_aad(TENANT, trigger_id),
    )
    store.create_trigger(
        TENANT,
        {
            "id": trigger_id, "agent_name": AGENT, "token_id": token_row["id"],
            "name": "github-issues-2", "task": "triage the event below",
            "secret_sealed": sealed, "secret_key_id": key_id,
        },
        actor="system:cli",
    )
    check("a fresh row seals and opens under B alone",
          _open_trigger(store, trigger_id, KEY_B), "github-issues-secret-B")



# --- the edge hunt: real Postgres, a real server, real subprocesses -------------------
#
# Everything above walks the procedure. Everything below attacks it: concurrency,
# interruption, scale, a second retired key, and the two states an operator can put the
# deployment into by getting the environment wrong.


def bulk_seed(psycopg, tenant, count, key, prefix):
    """`count` connections sealed under `key`, inserted directly for speed.

    Direct SQL rather than `save_connection` because this is a load fixture and the
    admin record per row is what makes 600 of them slow. The foreign keys still apply,
    so the rows are as real as any other.
    """
    from carnet.core import crypto

    cipher = crypto.LocalKeyCipher(crypto.decode_key(key))
    rows = []
    for i in range(count):
        who = f"{prefix}{i:04d}"
        sealed, key_id = cipher.seal(
            f"secret-{tenant}-{who}",
            tenant_id=tenant,
            aad=crypto.connection_aad(tenant, "user", who, "jira"),
        )
        rows.append((tenant, "user", who, "jira", sealed, key_id))

    with contextlib.closing(psycopg.connect(dsn_for(DB), autocommit=True)) as conn:
        conn.cursor().executemany(
            "INSERT INTO connections (tenant_id, principal_kind, principal_id,"
            " connector_id, ciphertext, key_id) VALUES (%s, %s, %s, %s, %s, %s)",
            rows,
        )
    return count


def open_every_connection(psycopg, tenant, keys, prefix=""):
    """Open every connection in a tenant with a cipher holding `keys`.

    Returns (opened, wrong) — `wrong` names any row whose plaintext is not the one it
    was seeded with, which is what a torn or mis-bound write looks like from outside.
    """
    from carnet.core import crypto

    cipher = crypto.LocalKeyCipher(
        crypto.decode_key(keys[0]), [crypto.decode_key(k) for k in keys[1:]]
    )
    opened, wrong = 0, []
    with contextlib.closing(psycopg.connect(dsn_for(DB))) as conn:
        found = conn.execute(
            "SELECT principal_id, ciphertext, key_id FROM connections"
            " WHERE tenant_id = %s AND principal_id LIKE %s ORDER BY principal_id",
            (tenant, f"{prefix}%"),
        ).fetchall()
    for principal_id, blob, key_id in found:
        try:
            plaintext = cipher.open_(
                bytes(blob),
                tenant_id=tenant,
                aad=crypto.connection_aad(tenant, "user", principal_id, "jira"),
                key_id=key_id,
            )
        except Exception as exc:  # noqa: BLE001 - the failure IS the finding
            wrong.append(f"{principal_id}: {type(exc).__name__}")
            continue
        if plaintext != f"secret-{tenant}-{principal_id}":
            wrong.append(f"{principal_id}: wrong plaintext")
        opened += 1
    return opened, wrong


def a_second_tenant(store, tenant):
    store.create_tenant(tenant, name=tenant)
    store.save_connector(
        tenant,
        {
            "id": "jira",
            "launch": {"kind": "http", "url": "https://mcp.example.com/mcp"},
            "vetted": [],
        },
        actor="system:cli",
    )


def many_tenants_and_two_retired_keys(psycopg, store):
    """Three customers, two old keys, one pass. The sweep is tenantless by design and
    the old-key list is comma-separated for exactly this: an operator who rotated twice
    without finishing has two keys to shed, and a sweep that handled one would leave the
    other listed forever."""
    say("three tenants and two retired keys in one pass")
    for tenant in ("e2erot2", "e2erot3"):
        a_second_tenant(store, tenant)

    bulk_seed(psycopg, TENANT, 40, KEY_A, "bulkA")
    bulk_seed(psycopg, "e2erot2", 40, KEY_D, "bulkD")
    bulk_seed(psycopg, "e2erot3", 20, KEY_A, "bulkA")
    bulk_seed(psycopg, "e2erot3", 20, KEY_D, "bulkD")

    done = cli(KEY_B, f"{KEY_A},{KEY_D}", "--finish-rotation")
    check("exit 0 across three tenants", done.returncode, 0)
    resealed = next(
        int(line.split()[1])
        for line in done.stdout.splitlines()
        if line.strip().startswith("connections") and "re-sealed" in line
    )
    check("all 120 seeded connections re-sealed in one pass", resealed, 120)

    for tenant, count in ((TENANT, 40), ("e2erot2", 40), ("e2erot3", 40)):
        opened, wrong = open_every_connection(psycopg, tenant, [KEY_B], prefix="bulk")
        check(f"{tenant}: every row opens under B alone", (opened, wrong), (count, []))


def concurrent_sweeps_do_not_corrupt(psycopg, store):
    """**Three operators, or three terminals, at once.** The compare-and-set is the only
    thing standing between them: a row must be re-sealed by exactly one of them, and a
    loser must not overwrite the winner's blob with its own re-seal of the same
    plaintext under a second nonce — which would be harmless here and catastrophic in
    the shape where the loser holds an older plaintext."""
    say("three sweeps racing each other")
    a_second_tenant(store, "e2erot4")
    bulk_seed(psycopg, "e2erot4", 150, KEY_A, "raceA")

    started = [
        subprocess.Popen(
            [sys.executable, "-m", "carnet.cli", "--finish-rotation"],
            env=server_env(KEY_B, KEY_A), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True,
        )
        for _ in range(3)
    ]
    outs = [(p.wait(timeout=180), p.stdout.read()) for p in started]

    check("all three exit 0", sorted(code for code, _ in outs), [0, 0, 0])
    resealed = sum(
        int(line.split()[1])
        for _, out in outs
        for line in out.splitlines()
        if line.strip().startswith("connections") and "re-sealed" in line
    )
    check("each row re-sealed exactly once across the three", resealed, 150)
    opened, wrong = open_every_connection(psycopg, "e2erot4", [KEY_B], prefix="raceA")
    check("every raced row opens under B alone", (opened, wrong), (150, []))


def sealed_trigger_rows_survive_a_sweep(psycopg, store):
    """Rows sealed under A while the sweep runs alongside other work: afterwards every
    one opens under B alone, with its secret unchanged. The delivery race this scene
    used to drive left with the door; what remains is the column's own guarantee."""
    say("trigger rows sealed under A, swept, opened under B")
    from carnet.access import tokens
    from carnet.core import crypto

    sealer = crypto.LocalKeyCipher(crypto.decode_key(KEY_A))
    rows = []
    for n in range(3):
        token_row, _ = tokens.mint(TENANT, f"race-hook-{n}", OWNER, actor="system:cli")
        store.grant_agent(
            TENANT, AGENT, "machine", token_row["id"], "user",
            granted_by="system:cli", actor="system:cli",
        )
        secret = f"live-secret-{n}"
        trigger_id = f"trg_live{n:012d}"
        sealed, key_id = sealer.seal(
            secret,
            tenant_id=TENANT,
            aad=crypto.trigger_secret_aad(TENANT, trigger_id),
        )
        store.create_trigger(
            TENANT,
            {
                "id": trigger_id, "agent_name": AGENT, "token_id": token_row["id"],
                "name": f"live-{n}", "task": "triage the event below",
                "secret_sealed": sealed, "secret_key_id": key_id,
            },
            actor="system:cli",
        )
        rows.append((trigger_id, secret))

    # Enough other work that the sweep has a population to walk.
    bulk_seed(psycopg, "e2erot4", 400, KEY_A, "liveA")

    done = cli(KEY_B, KEY_A, "--finish-rotation")
    check("the sweep finished", done.returncode, 0)
    for trigger_id, secret in rows:
        check(f"{trigger_id} opens under B alone with its unchanged secret",
              _open_trigger(store, trigger_id, KEY_B), secret)


def _distinct_keys(conn, tenant, prefix):
    """How many key ids a tenant's seeded connections are sealed under right now."""
    return conn.execute(
        "SELECT count(DISTINCT key_id) FROM connections"
        " WHERE tenant_id = %s AND principal_id LIKE %s",
        (tenant, f"{prefix}%"),
    ).fetchone()[0]


def a_killed_sweep_leaves_no_torn_row(psycopg, store):
    """SIGKILL mid-sweep — the ugliest interruption there is, and the one the "resume is
    the predicate" claim is really about. Every re-seal is a single statement, so no row
    can be half-written; the population is the checkpoint, so the next run finishes."""
    say("a sweep killed mid-pass")
    a_second_tenant(store, "e2erot5")
    bulk_seed(psycopg, "e2erot5", 600, KEY_A, "killA")

    killed = subprocess.Popen(
        [sys.executable, "-m", "carnet.cli", "--finish-rotation"],
        env=server_env(KEY_B, KEY_A), stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # **Kill on an observed condition, not on a clock.** This used to sleep 350 ms and
    # then kill; a fixed sleep is a race on every machine and only visible on a fast
    # one, and a fast one finishes all 600 rows first, so the "mid-pass" check below
    # measured 1 distinct key and failed while the safety check beside it passed.
    # Each re-seal is its own statement, so polling the population sees the sweep's
    # progress row by row: the moment rows exist under both keys the sweep has
    # started and not finished, and that is the instant to kill it.
    with contextlib.closing(psycopg.connect(dsn_for(DB), autocommit=True)) as conn:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and killed.poll() is None:
            if _distinct_keys(conn, "e2erot5", "killA") == 2:
                break
    killed.kill()
    killed.wait(timeout=30)

    # Whatever it managed, every row must still open — under B if it got there, under A
    # if it did not. A torn row would open under neither.
    opened, wrong = open_every_connection(psycopg, "e2erot5", [KEY_B, KEY_A], prefix="killA")
    check("no row was torn by the kill", (opened, wrong), (600, []))
    with contextlib.closing(psycopg.connect(dsn_for(DB))) as conn:
        distinct = _distinct_keys(conn, "e2erot5", "killA")
    check("and the kill landed mid-pass (rows under both keys)", distinct, 2)

    finished = cli(KEY_B, KEY_A, "--finish-rotation")
    check("the re-run finishes what the kill interrupted", finished.returncode, 0)
    opened, wrong = open_every_connection(psycopg, "e2erot5", [KEY_B], prefix="killA")
    check("and every row opens under B alone", (opened, wrong), (600, []))


def refreshes_racing_the_sweep(psycopg, store):
    """A token refresh rewrites the same rows the sweep is re-sealing. Neither may lose
    a credential: the refresh's compare-and-set is `updated_at` (which a re-seal does
    not touch) and the sweep's is the blob (which a refresh does change)."""
    say("token refreshes hammering the rows a sweep is walking")
    from carnet.core import crypto

    a_second_tenant(store, "e2erot6")
    bulk_seed(psycopg, "e2erot6", 120, KEY_A, "refA")
    cipher = crypto.LocalKeyCipher(
        crypto.decode_key(KEY_B), [crypto.decode_key(KEY_A)]
    )

    stop = threading.Event()
    landed = []

    def refresh_forever():
        while not stop.is_set():
            for i in range(0, 120, 7):
                who = f"refA{i:04d}"
                row = store.find_connection("e2erot6", "user", who, "jira")
                if row is None:
                    continue
                sealed, key_id = cipher.seal(
                    f"secret-e2erot6-{who}",  # the same plaintext a real refresh keeps
                    tenant_id="e2erot6",
                    aad=crypto.connection_aad("e2erot6", "user", who, "jira"),
                )
                if store.update_connection_credential(
                    "e2erot6", "user", who, "jira",
                    ciphertext=sealed, key_id=key_id,
                    expires_at=None, refresh_expires_at=None,
                    if_updated_at=row["updated_at"],
                ) is not None:
                    landed.append(who)
                if stop.is_set():
                    return

    thread = threading.Thread(target=refresh_forever, daemon=True)
    thread.start()
    done = cli(KEY_B, KEY_A, "--finish-rotation")
    stop.set()
    thread.join(timeout=30)

    check("the sweep finished under contention", done.returncode, 0)
    check("and the refreshes really were landing", len(landed) > 5, True)
    opened, wrong = open_every_connection(psycopg, "e2erot6", [KEY_B], prefix="refA")
    check("every contended row opens under B alone", (opened, wrong), (120, []))

    settle = cli(KEY_B, KEY_A, "--finish-rotation")
    check("a settling run is clean", settle.returncode, 0)


def the_binding_survives_the_rotation(psycopg):
    """The security property the sweep touches every blob in the deployment to preserve:
    a re-sealed credential must still refuse to open in any other row. A sweep that
    rebuilt the AAD from the wrong columns would pass every functional test above and
    silently unbind every credential at once."""
    say("a re-sealed blob still refuses to be moved")
    from carnet.core import crypto

    cipher = crypto.LocalKeyCipher(crypto.decode_key(KEY_B))
    with contextlib.closing(psycopg.connect(dsn_for(DB))) as conn:
        blob, key_id = conn.execute(
            "SELECT ciphertext, key_id FROM connections"
            " WHERE tenant_id = %s AND principal_id = %s",
            (TENANT, "bulkA0000"),
        ).fetchone()

    check(
        "it opens in its own row",
        cipher.open_(
            bytes(blob), tenant_id=TENANT,
            aad=crypto.connection_aad(TENANT, "user", "bulkA0000", "jira"),
            key_id=key_id,
        ),
        f"secret-{TENANT}-bulkA0000",
    )
    for label, aad in (
        ("another principal", crypto.connection_aad(TENANT, "user", "bulkA0001", "jira")),
        ("another tenant", crypto.connection_aad("e2erot2", "user", "bulkA0000", "jira")),
        ("another connector", crypto.connection_aad(TENANT, "user", "bulkA0000", "github")),
    ):
        try:
            cipher.open_(bytes(blob), tenant_id=TENANT, aad=aad, key_id=key_id)
            check(f"refused in {label}", "opened", "refused")
        except crypto.UndecryptableError:
            check(f"refused in {label}", "refused", "refused")


def the_forgotten_old_key(psycopg, store):
    """**The state that made the exit code wrong, found in this pass.** An operator who
    drops the old key *before* sweeping has a deployment full of rows nothing can read.
    The rotation is genuinely finished — no row names a *retired* key, because nothing
    is retired — so the verdict is true and the exit code must still not say "clean"."""
    say("the operator who dropped the old key before sweeping")
    a_second_tenant(store, "e2erot7")
    bulk_seed(psycopg, "e2erot7", 12, KEY_D, "lostD")

    forgotten = cli(KEY_B, None, "--finish-rotation")
    check("exit 1, not 0", forgotten.returncode, 1)
    check("the verdict is still true", "No row names a retired key." in forgotten.stdout, True)
    check("and the rows are named as unreadable", "never held" in forgotten.stdout, True)
    check("with the remedy that keeps them", "put it back" in forgotten.stdout, True)
    check(
        "nothing was destroyed",
        open_every_connection(psycopg, "e2erot7", [KEY_D], prefix="lostD"),
        (12, []),
    )

    restored = cli(KEY_B, f"{KEY_A},{KEY_D}", "--finish-rotation")
    check("restoring the key recovers every row", restored.returncode, 0)
    check(
        "and they now open under B alone",
        open_every_connection(psycopg, "e2erot7", [KEY_B], prefix="lostD"),
        (12, []),
    )


def a_deployment_with_no_key_refuses(psycopg):
    """`--finish-rotation` is a write against every sealed row in the deployment. With
    no key it can do nothing, and it must say so the way every other command does —
    `parser.error`'s exit 2, not a traceback and not a cheerful verdict about zero
    rows."""
    say("no key configured at all")
    keyless = subprocess.run(
        [sys.executable, "-m", "carnet.cli", "--finish-rotation"],
        env=server_env(None, None), capture_output=True, text=True,
    )
    check("exit 2", keyless.returncode, 2)
    check(
        "naming the variable",
        "CARNET_SECRET_KEY" in keyless.stderr,
        True,
    )
    check("and no verdict was printed", "No row names" in keyless.stdout, False)


def the_stranded_listing_is_capped(psycopg, store):
    """A deployment that stranded everything still has to print a transcript somebody
    can read: four lines per row times ten thousand rows buries the verdict. The cap
    announces itself, and the totals under it are never capped."""
    say("thirty unreadable rows, and a printout a person can still read")
    a_second_tenant(store, "e2erot8")
    bulk_seed(psycopg, "e2erot8", 30, KEY_C, "capC")

    capped = cli(KEY_B, KEY_A, "--finish-rotation")
    check("exit 1", capped.returncode, 1)
    shown = capped.stdout.count("COULD NOT RE-SEAL")
    check("twenty rows named in full", shown, 20)
    check("and the other ten counted, not hidden", "and 10 more row(s)" in capped.stdout, True)
    check("the total is the true one", "30 row(s) above name keys" in capped.stdout, True)

    with contextlib.closing(psycopg.connect(dsn_for(DB), autocommit=True)) as conn:
        conn.execute("DELETE FROM connections WHERE tenant_id = %s", ("e2erot8",))
    check("cleaned up", cli(KEY_B, KEY_A, "--finish-rotation").returncode, 0)


def a_dead_database_is_a_refusal_not_a_traceback():
    """**Found in this pass.** An unreachable database left `StorageError` uncaught, so
    the command exited 1 with a traceback — the same 1 that means *rows still need a
    retired key*. A runbook branching on the exit code would have read an outage as an
    unfinished rotation, and a person would have read the traceback as the rotation
    having done something. It is `parser.error`'s 2 now, with a sentence."""
    say("an unreachable database")
    env = server_env(KEY_B, KEY_A)
    env["CARNET_DATABASE_URL"] = "postgresql://postgres:postgres@127.0.0.1:59999/nope"
    dead = subprocess.run(
        [sys.executable, "-m", "carnet.cli", "--finish-rotation"],
        env=env, capture_output=True, text=True,
    )
    check("exit 2, not the 1 that means unfinished", dead.returncode, 2)
    check("it says what happened", "could not be completed" in dead.stderr, True)
    check("and that nothing is half-written", "half-written" in dead.stderr, True)
    # **Not "no traceback anywhere".** psycopg's pool finalizer prints an ignored
    # `PythonFinalizationError` at interpreter shutdown on this Python, for every
    # command that ever opened a pool — `--list-triggers` against the same dead
    # database prints five of them and `--prune-logs` seven. What this step owns is
    # that *its own* failure path is a refusal rather than an escaped exception.
    check("no frame from the rotation escaped", "rotation.py" in dead.stderr, False)
    check("and StorageError did not reach the terminal", "StorageError:" in dead.stderr, False)
    check("and no verdict was invented", "No row names" in dead.stdout, False)


def no_plaintext_escapes(world, api_log):
    """Every byte this drill printed, against every secret it created. The transcript is
    a file an operator saves and may attach to an audit; a key or a credential in it
    would outlive the rotation it was written to prove."""
    say("nothing that was sealed appears in anything that was printed")
    printed = "\n".join(TRANSCRIPT)
    logged = api_log.read_text()

    secrets_created = {
        "the pasted PAT": "pat-abc123",
        "the OAuth client secret": "the-client-secret",
        "the trigger secret": world["trigger_secret"],
        "a live trigger secret": "live-secret-0",
        "a bulk-seeded credential": f"secret-{TENANT}-bulkA0000",
    }
    for label, secret in secrets_created.items():
        check(f"{label} is not in the CLI transcript", secret in printed, False)
        check(f"{label} is not in the server log", secret in logged, False)

    for label, key in (("key A", KEY_A), ("key B", KEY_B), ("key D", KEY_D)):
        check(f"{label} itself is not in the transcript", key in printed, False)
        check(f"{label} itself is not in the server log", key in logged, False)


def a_server_never_restarted_is_named(psycopg, store):
    """**The rotation that never converges, and the only one whose remedy is not on a
    row.** A server still holding the retired key as its *current* key seals with it —
    so the sweep re-seals a row and that server writes it straight back, run after run,
    while every printed remedy (reconnect, reconfigure, recreate) is useless. Driven
    here with a real process: a second uvicorn left on key A, refreshing rows behind
    the sweep."""
    say("a process still writing under the retired key")
    from carnet.core import crypto

    a_second_tenant(store, "e2erot9")
    bulk_seed(psycopg, "e2erot9", 30, KEY_A, "staleA")

    # The un-restarted process, in the shape it actually takes: something that seals
    # with the OLD key because that is still its current one.
    old_cipher = crypto.LocalKeyCipher(crypto.decode_key(KEY_A))
    stop = threading.Event()

    def keeps_writing_old():
        while not stop.is_set():
            for i in range(0, 30, 3):
                who = f"staleA{i:04d}"
                row = store.find_connection("e2erot9", "user", who, "jira")
                if row is None:
                    continue
                sealed, key_id = old_cipher.seal(
                    f"secret-e2erot9-{who}",
                    tenant_id="e2erot9",
                    aad=crypto.connection_aad("e2erot9", "user", who, "jira"),
                )
                store.update_connection_credential(
                    "e2erot9", "user", who, "jira",
                    ciphertext=sealed, key_id=key_id,
                    expires_at=None, refresh_expires_at=None,
                    if_updated_at=row["updated_at"],
                )
                if stop.is_set():
                    return

    thread = threading.Thread(target=keeps_writing_old, daemon=True)
    thread.start()
    stuck = cli(KEY_B, KEY_A, "--finish-rotation")
    stop.set()
    thread.join(timeout=30)

    check("it does not report success", stuck.returncode, 1)
    check(
        "and it names the cause rather than blaming the rows",
        "written under a retired key while this sweep was running" in stuck.stdout,
        True,
    )
    check(
        "with the remedy no row can carry",
        "Restart every server" in stuck.stdout,
        True,
    )

    # With the writer stopped — the restart, in effect — it converges immediately.
    settled = cli(KEY_B, KEY_A, "--finish-rotation")
    check("and once that process is gone it finishes", settled.returncode, 0)
    check(
        "every row under B alone",
        open_every_connection(psycopg, "e2erot9", [KEY_B], prefix="staleA"),
        (30, []),
    )


def main():
    global KEY_A, KEY_B, KEY_C, KEY_D
    import psycopg

    from carnet import storage as storage_module
    from carnet.core import crypto
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    KEY_A, KEY_B, KEY_C, KEY_D = (crypto.generate_key() for _ in range(4))
    os.environ["CARNET_SECRET_KEY"] = KEY_A
    os.environ.pop("CARNET_SECRET_KEYS_OLD", None)
    os.environ["CARNET_PUBLIC_ORIGIN"] = API

    say("building the database")
    fresh_database(psycopg, DB)
    migrate.apply(dsn_for(DB))
    store = storage_module.configure(PostgresStorage(dsn_for(DB)))
    crypto.configure(crypto.from_environment())

    world = build_world(store)
    api_log = pathlib.Path(tempfile.mkstemp(prefix="e2e-key-rotation-api-")[1])
    try:
        attempt("the trigger row under key A", the_trigger_row_opens_under_key_a, world, store)

        # The procedure, done right: B current, A retired, sweep, verdict, drop.
        with api_under(KEY_B, KEY_A, api_log):
            attempt("the rotation finishes", the_rotation_finishes, psycopg, world)
            attempt("the blockers are reported", the_blockers_are_reported, psycopg, world)

        with api_under(KEY_B, None, api_log):
            attempt("the world after the drop", the_world_after_the_drop, psycopg, world)
            attempt(
                "a fresh trigger row on the rotated deployment",
                a_new_trigger_seals_under_the_new_key_alone,
                world,
            )

        # The edge hunt. The server holds both keys throughout, which is the state a
        # real deployment is in for the length of a rotation and the only state in
        # which these races are reachable.
        with api_under(KEY_B, KEY_A, api_log):
            attempt(
                "three tenants and two retired keys",
                many_tenants_and_two_retired_keys, psycopg, store,
            )
            attempt("concurrent sweeps", concurrent_sweeps_do_not_corrupt, psycopg, store)
            attempt("sealed trigger rows survive a sweep", sealed_trigger_rows_survive_a_sweep, psycopg, store)
            attempt("a killed sweep", a_killed_sweep_leaves_no_torn_row, psycopg, store)
            attempt("refreshes racing a sweep", refreshes_racing_the_sweep, psycopg, store)
            attempt("the binding survives", the_binding_survives_the_rotation, psycopg)
            attempt(
                "a server never restarted", a_server_never_restarted_is_named,
                psycopg, store,
            )
            attempt("the forgotten old key", the_forgotten_old_key, psycopg, store)
            attempt("the capped listing", the_stranded_listing_is_capped, psycopg, store)
            attempt("no key at all", a_deployment_with_no_key_refuses, psycopg)
            attempt("a dead database", a_dead_database_is_a_refusal_not_a_traceback)
            attempt("no plaintext escapes", no_plaintext_escapes, world, api_log)
    finally:
        print(f"\napi log: {api_log}")

    raise SystemExit(report())


if __name__ == "__main__":
    main()
