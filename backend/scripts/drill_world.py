"""Build a customer worth drilling against. Step 072's fixture, not a test.

The three procedures in `docs/runbooks/` are run against a deployment that has
something to lose: two people, an agent each can reach, a service token, a personal
token, a sealed delegated credential, a consent flow with a sealed client secret, a
sealed HMAC secret in the `triggers` table (seeded directly — nothing fires it, and
the key drill sweeps the column regardless), and enough audit history that a deletion
has something to erase.

Every one of those is deliberate. The offboarding drill needs somebody whose
departure has consequences; the key drill needs all four sealed columns populated,
or `--finish-rotation` sweeps an empty population and proves nothing; the deletion
drill needs rows in every table the tenant blocks on, or "nothing left behind" is a
claim about an empty database.

    CARNET_DATABASE_URL=... python scripts/drill_world.py

Prints what it made, so the transcript that follows has a starting inventory.
"""

import os
import pathlib
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

TENANT = "northwind"
ISSUER = "https://northwind.okta.example"


def main() -> int:
    dsn = os.environ.get("CARNET_DATABASE_URL")
    if not dsn:
        print("CARNET_DATABASE_URL is not set.", file=sys.stderr)
        return 2

    from carnet import agents, storage
    from carnet.access import connections, groups, oauth, roles, tokens
    from carnet.core import Principal, crypto
    from carnet.storage import migrate
    from carnet.storage.postgres import PostgresStorage

    crypto.configure(crypto.from_environment())
    migrate.apply(dsn)
    store = storage.configure(PostgresStorage(dsn))
    cli = Principal.system("cli", TENANT)
    actor = str(cli)

    store.create_tenant(TENANT, "Northwind Traders")
    store.save_tenant_idp(
        TENANT,
        {
            "issuer": ISSUER,
            "jwks_uri": f"{ISSUER}/v1/keys",
            "audience": "api://northwind",
            "allowed_domains": ("northwind.example",),
            "groups_claim": "groups",
        },
    )

    # Two people. Priya administers; Tom is the one who will leave.
    for user_id, subject, email, name in (
        ("u_priya", "00u-priya", "priya@northwind.example", "Priya Raman"),
        ("u_tom", "00u-tom", "tom@northwind.example", "Tom Alvarez"),
    ):
        store.create_user(
            TENANT,
            {"id": user_id, "issuer": ISSUER, "subject": subject, "email": email,
             "display_name": name},
        )
        store.record_user_login(user_id, email, name)
    roles.grant(cli, Principal.user("u_priya", TENANT))

    eng = groups.create(cli, "engineering", external_id="dir-eng")["group_id"]
    groups.add_member(cli, eng, "user", "u_tom", from_directory=True)

    agents.save(
        TENANT,
        {
            "name": "issue-triage",
            "system": "You triage inbound issues.",
            "runtime": "simple",
            "permissions": {"tools": ["post_message"],
                            "scope": {"chat.channel": {"write": ["#support"]}}},
        },
        actor=actor,
    )
    store.grant_agent(TENANT, "issue-triage", "user", "u_tom", role="owner", actor=actor)
    store.grant_agent(TENANT, "issue-triage", "group", eng, role="user", actor=actor)

    # Tom's machine caller. This is what the offboarding drill is about: disabling
    # Tom must refuse it at its next call.
    service, service_secret = tokens.mint(TENANT, "nightly-triage", "u_tom", actor=actor)
    store.grant_agent(TENANT, "issue-triage", "machine", service["id"], role="user", actor=actor)
    personal, _ = tokens.mint(TENANT, "toms-laptop", "u_tom", actor=actor, acts_as_owner=True)

    # A sealed HMAC secret in `triggers` — one of the four columns the key drill
    # sweeps. Seeded straight into the row (step 078 removed the door that read it),
    # so the sweep still has a fourth population to re-seal.
    trigger_id = "trg_drill00000001"
    sealed, key_id = crypto.active().seal(
        "issue-arrived-secret", tenant_id=TENANT,
        aad=crypto.trigger_secret_aad(TENANT, trigger_id),
    )
    trigger = store.create_trigger(
        TENANT,
        {
            "id": trigger_id, "agent_name": "issue-triage", "token_id": service["id"],
            "name": "issue-arrived", "task": "an issue arrived",
            "secret_sealed": sealed, "secret_key_id": key_id,
        },
        actor=actor,
    )

    # A connector with a consent flow (sealed client secret) and a delegated
    # credential (sealed blob). Two more of the four columns.
    store.allow_host(TENANT, "mcp.northwind.example", actor=actor)
    from carnet import tools

    tools.register_connector(
        TENANT, "support-desk", url="https://mcp.northwind.example/mcp", kind="http",
        credential_env="SUPPORT_DESK_TOKEN", description="the support desk", actor=actor,
    )
    oauth.configure(
        TENANT, "support-desk",
        authorize_endpoint="https://mcp.northwind.example/authorize",
        token_endpoint="https://mcp.northwind.example/token",
        client_id="northwind-carnet", client_secret="s3cret-client-secret",
        scopes=("read:tickets", "write:tickets"), actor=actor,
    )
    connections.connect_account(
        Principal.user("u_tom", TENANT), "support-desk", "toms-support-desk-token",
        account_label="tom@northwind.example",
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        actor="user:u_tom",
    )

    counts = {
        "users": len(store.list_users(TENANT)),
        "agents": len(store.load_agents(TENANT)),
        "api_tokens": len(store.list_api_tokens(TENANT)),
        "triggers": len(store.list_triggers(TENANT)),
        "groups": len(store.list_groups(TENANT)),
        "admin_audit": len(store.admin_audit_records(TENANT)),
    }

    print(f"tenant           {TENANT} (Northwind Traders)")
    print(f"identity provider {ISSUER}")
    for label, value in counts.items():
        print(f"  {label:16} {value}")
    print("\nsealed columns now populated:")
    print("  connections.ciphertext        Tom's support-desk account")
    print("  connector_oauth.client_secret support-desk's consent flow")
    print("  triggers.secret_sealed        a seeded HMAC secret, nothing fires it")
    print("\nwho is who:")
    print("  u_priya  administrator")
    print(f"  u_tom    owns issue-triage; owns {service['id']} (service) and "
          f"{personal['id']} (personal)")
    print(f"  trigger  {trigger['id']} is a sealed row naming {service['id']}; nothing fires it")
    print(f"\nservice token (for the offboarding drill): {service_secret}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
