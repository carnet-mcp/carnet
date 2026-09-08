"""Wiring: choose a store, and put the shipped configs in it.

This is an **entry-point concern**, which is why it lives up here beside `cli.py`
rather than inside `storage/`. Storage is the bottom layer and may not import `agents`
or `tools`; something has to compose the two, and that something is whatever starts the
process. The CLI calls this; an HTTP server and the scheduler will call the same
function.

## Why the shipped examples survive

`tools/mcp/connectors/github.py` and the permission list below stay in the tree as
**seed data**: `carnet --list` would otherwise show nothing on a fresh clone, and
the two best worked examples in the repo — of a real grant and of a real vetting
manifest — would go with them.

Seeding goes through `agents.save()`, which validates. So a broken shipped config still
fails loudly at startup, which is most of what import-time validation was doing for us.
"""

from . import agents, config, storage, tools
from .core import crypto
from .tools.mcp.connectors.github import CONNECTOR as _GITHUB

# The shipped example of an agent — which is to say, of a permission list: a named set
# of tools, each with a scope. It is what a token is granted and how the door decides
# what a connected assistant may touch (`docs/PREMISE.md`). Note what is NOT in it: no
# tokens, no webhook URLs. Credentials live in the broker; giving this agent a new
# capability means granting it here, not wiring plumbing.
_ALLOWED_REPO = "anthropics/anthropic-sdk-python"
_ALLOWED_CHANNEL = "#eng"
_ISSUE_REPORTER = {
    "name": "issue-reporter",
    "permissions": {
        "tools": ["github_mcp_list_issues", "post_message"],
        "scope": {
            "github.repo": {"read": [_ALLOWED_REPO]},
            "chat.channel": {"write": [_ALLOWED_CHANNEL]},
        },
    },
}

# The configs this repo ships. Seeded into a fresh store; they are examples, not
# platform furniture, and a real deployment's agents and connectors come from its own
# database.
#
# Connectors are seeded before agents, because an agent granting a connector's tool
# does not validate until that connector exists for the tenant. That ordering is the
# dependency made visible.
SHIPPED_CONNECTORS = [
    _GITHUB,
]

SHIPPED_AGENTS = [
    _ISSUE_REPORTER,
]


def configure(tenant_id: str | None = None, seed: bool = True):
    """Choose and configure the process-wide store. Returns it.

    With `CARNET_DATABASE_URL` set, that database. Without it, an in-memory
    store seeded from the shipped modules — enough to exercise the runtime without
    standing up Postgres, and deliberately not durable.
    """
    tenant_id = tenant_id or config.DEFAULT_TENANT_ID

    if config.DATABASE_URL:
        from .storage.postgres import PostgresStorage

        store = storage.configure(PostgresStorage(config.DATABASE_URL))
    else:
        store = storage.configure(storage.InMemoryStorage())

    # Step 029, and here rather than at each entry point because — unlike
    # `configure_crypto` — the policy does not vary by caller: no process may serve,
    # claim or list against a database where tenant scoping cannot work. Testing found
    # why it must cover more than the API: a serving role that owns nothing and is a
    # member of nothing reads **zero rows with no error**, so a standalone
    # `--worker` would claim nothing forever and say nothing about it. That is the
    # silent-empty-result failure this whole step exists to make loud.
    #
    # `--migrate` is unaffected and must stay that way: it runs before the store is
    # configured, which is what lets a pre-037 database be brought up to date at all.
    try:
        store.verify_tenant_isolation()
    except Exception:
        # Nothing will use this store, so give its pool back rather than leaving it
        # for the interpreter's finalizer — which on 3.14 prints a thread-join error
        # underneath the refusal, burying the one sentence the operator needs.
        store.close()
        raise

    # Step 095: a `carnet.yaml` is the door's whole administration, and it is loaded
    # *instead of* the shipped examples — a stranger's file must not come up carrying
    # `issue-reporter` and a stdio GitHub connector they did not declare. `config`
    # already refused the file beside a database, so this branch is always in-memory.
    if config.CARNET_FILE:
        from . import carnetfile

        carnetfile.apply(tenant_id, carnetfile.load(config.CARNET_FILE))
    elif seed:
        seed_tenant(tenant_id, store=store)

    return store


def configure_crypto(required: bool | None = None):
    """Load the encryption key at startup, or refuse to carry on without one.

    **At startup, not at first use.** A process that boots and then fails on somebody's
    first agent run has moved a configuration error into a user's request, where it
    reads as the product being broken rather than as the product being unconfigured.

    The key is never auto-generated. It is the one place this diverges from the tool
    that settled the design, and deliberately: a key that regenerates makes every
    stored credential silently unreadable — not at write time, not at boot, but on a
    row that still looks perfectly fine. A convenience that quietly changes a security
    property is the one to refuse.

    `required` defaults to **whether there is a durable store**, which is the honest
    line rather than a convenient one:

      - With a database, a `connections` row may already exist or may be written at any
        moment, so a process without a key is one that will fail later on somebody's
        behalf. Refuse now.
      - Without one, the store is an in-memory dict that dies with the process. No
        connection can pre-exist it and none can outlive it, so a key would be a
        requirement that protects nothing — and it would break the property that a
        fresh clone runs an agent with nothing installed and nothing running.

    An entry point may still insist: the HTTP server passes `required=True` regardless,
    because it is multi-user and delegation is the whole reason it exists.
    """
    if required is None:
        required = bool(config.DATABASE_URL)

    try:
        return crypto.configure(crypto.from_environment())
    except crypto.CryptoError:
        if required:
            raise
        # Left unconfigured rather than stubbed. Nothing can reach a connection here,
        # and if something somehow does, `crypto.active()` says which variable is
        # missing — which is a better error than one this function could invent.
        return None


def seed_tenant(tenant_id: str, store=None, name: str = "Default") -> list:
    """Create the tenant if missing and write the shipped configs into it.

    Idempotent — re-seeding replaces the shipped rows and leaves everything else
    alone, so running it against a store that already has customer agents in it is
    safe rather than clever.

    **Never overwrites a config a human last wrote**, and returns the `(name, author)`
    pairs it left alone so the caller can say so. See `_is_ours`: the shipped names are
    ordinary names, a customer can hold one, and `save_agent` is an upsert keyed by
    name — so without this, a deployment that re-seeds on boot replaced that customer's
    agent with ours on every restart, silently, for as long as it was deployed.
    """
    store = store or storage.active()
    store.create_tenant(tenant_id, name)

    for connector in SHIPPED_CONNECTORS:
        # `system:cli` for the reason the seeded owner grant uses it: seeding *is* the
        # CLI acting. It is now also what lands in `vetted_by` for every shipped tool —
        # true, uninformative, and better than the `''` it replaced, which read as a
        # column nobody had got round to filling in.
        tools.save_connector(tenant_id, connector, actor=storage.SYSTEM_ACTOR)

    skipped = []
    for agent in SHIPPED_AGENTS:
        ours, author = _is_ours(store, tenant_id, agent["name"])
        if not ours:
            skipped.append((agent["name"], author))
            continue

        # `system:cli` because seeding *is* the CLI acting, which is the same principal
        # migration 011 stamps on a seeded agent's owner grant. The administrative log
        # does not cover `--seed` beyond recording that a system principal wrote
        # something — the least useful true statement available, and still true.
        agents.save(tenant_id, agent, actor=storage.SYSTEM_ACTOR)
        _adopt(store, tenant_id, agent["name"])

    return skipped


def _is_ours(store, tenant_id: str, agent_name: str):
    """May `--seed` write this name? Returns `(may_write, who_wrote_it_last)`.

    **The question is who wrote the config last, not who owns the agent.** Ownership is
    the wrong test twice over: a seeded agent somebody has since taken over is still
    ours to refresh, and an agent of the customer's own that `system:cli` happens to
    own — every agent in a store seeded before anybody logged in — is still theirs.

    The signal is the newest `agent_versions` row, which carries `created_by`. A seed
    write is uniquely `system:cli`, because `SYSTEM_ACTOR` reaches `save_agent` from
    this module and nowhere else. `migration:*` counts as ours for the same reason: a
    backfilled row records the migration that wrote it, not a person's decision about
    this config.

    An agent with no history at all is ours to write. That is the pre-032 case and the
    fresh-store case, and refusing there would make `--seed` unable to seed.

    **The known hole, documented rather than fixed**: an agent untouched since before
    migration 032 has `migration:032` as its newest version regardless of who authored
    the config, so it is still refreshed. Any human edit after 032 protects it, which
    covers every deployment that has been used since. Closing it properly wants a
    provenance column on `agents`, which is a migration and a decision of its own.
    """
    if store.get_agent(tenant_id, agent_name) is None:
        return True, None

    history = store.list_agent_versions(tenant_id, agent_name, limit=1)
    if not history:
        return True, None

    author = history[0]["created_by"]
    return author == storage.SYSTEM_ACTOR or author.startswith("migration:"), author


def _adopt(store, tenant_id: str, agent_name: str) -> None:
    """Give a freshly seeded agent an owner, if it does not have one.

    The in-memory half of migration 011. Absence is denial, so an agent with no grant is
    an agent nobody can run — and an in-memory store seeded on the way up would come up
    with nothing runnable, which is a fresh clone that does not work.

    `system:cli` for the same reason the migration uses it: seeding *is* the CLI acting,
    and saying so is true. Ownership is claimed only when the agent has none, so
    re-seeding a store where somebody has since taken an agent over does not wrench it
    back — `--seed` is documented as safe to re-run, and quietly reversing a transfer is
    not safe.
    """
    for grant in store.list_agent_grants(tenant_id, agent_name):
        if grant["role"] == storage.OWNER_ROLE:
            return

    store.grant_agent(
        tenant_id,
        agent_name,
        "system",
        "cli",
        role=storage.OWNER_ROLE,
        granted_by="seed",
        # Not `granted_by`. That column is free text and says *what wrote the row*;
        # `actor` is a principal and says *who acted*, which for seeding is the CLI. The
        # two are deliberately different words here, which is the clearest example in the
        # codebase of why step 011 kept them as separate parameters.
        actor=storage.SYSTEM_ACTOR,
    )


__all__ = [
    "SHIPPED_AGENTS",
    "SHIPPED_CONNECTORS",
    "configure",
    "configure_crypto",
    "seed_tenant",
]
