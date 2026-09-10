"""The storage contract: rows in, rows out.

This is the bottom layer. It knows no agent, no tool, and no policy — `load_agents`
returns dicts and has no opinion about what a valid grant is. Validation lives in
`agents/`, which is above this and can import it; the reverse would put the meaning of
a permission inside the thing that stores it.

Everything is dict-in / dict-out. A typed row object here would be a second place the
agent config shape is defined, and keeping one definition is the reason the config is
a plain dict in the first place.

**Every method takes `tenant_id` first.** Not because it reads well, but because a
method that *can* be called without one is a method that eventually is. There is no
"load everything" call anywhere in this interface, and there should never be one on
the path a request takes.

Two implementations, in `memory.py` and `postgres.py`. They are held honest by
`tests/test_storage_contract.py`, which runs one set of assertions against both — the
whole risk of having a fake is that it quietly permits what Postgres would refuse.
"""

import hashlib
import json
import math
import re
import uuid
from datetime import date, datetime, timezone
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable
from urllib.parse import parse_qsl, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones


class StorageError(RuntimeError):
    """Base for anything this layer refuses to do.

    Callers catch this rather than a driver-specific exception, so nothing above
    storage learns which database is underneath.
    """


class UnknownTenantError(StorageError):
    """A write named a tenant that does not exist.

    A real foreign key in Postgres, and enforced identically in memory. Letting the
    fake accept a row Postgres would reject is exactly the drift the contract suite
    exists to catch.
    """


class TenantDeletionRefused(StorageError):
    """`delete_tenant` was asked to delete a tenant that is not ready to be deleted.

    Its own class for the reason `AgentNameTaken` has one: every other `StorageError`
    means the store is broken, and this one means the store is working perfectly and
    the operator has to do something first — suspend the customer, or wait for a run.

    Two conditions raise it, and both are about **racing live work rather than about
    permission**. Deleting an active tenant means somebody may authenticate into it
    during the delete; deleting one with a run in flight means a worker writing audit
    records for a tenant that is being erased underneath it. Suspension already closes
    both doors work arrives through, so requiring it costs an operator one command and
    removes the whole class of race.

    Not raised for a tenant that does not exist — that is `UnknownTenantError`, the
    same sentence every other method gives, including for a tenant deleted a moment ago.
    """


class TenantDeleted(StorageError):
    """A tenant id was reused after that tenant had been deleted.

    An id is never reused. Every record that outlives a deletion — a tombstone, and any
    log row in another deployment naming this id — would otherwise be ambiguous between
    two customers, and those records live in tables nobody can edit to disambiguate.

    Its own class rather than `ValueRefused`, because the remedy is a different one:
    `ValueRefused` means fix the value, and this means *that value belongs to somebody
    who is gone*, which is a sentence about history rather than about syntax.
    """


class AgentNameTaken(StorageError):
    """`create_agent` named an agent that already exists.

    Its own class for the reason `IssuerConflictError` has one: every other
    `StorageError` is a 503, and this is a **409** — the store is working perfectly and
    the caller asked for something that cannot be. Raised rather than upserted, because
    the alternative is one person's form silently replacing another person's agent.

    The message deliberately does not say who owns it. A create route is reachable by
    anybody authenticated in the tenant, so naming the owner of an agent they have no
    grant on would answer "does `payroll-bot` exist and who runs it" through a status
    code — the same enumeration the 404 rule exists to close.
    """


class NoSuchGroupError(StorageError):
    """A grant or a membership named a group that does not exist.

    Its own class for the reason `AgentNameTaken` and `UnknownConnectorError` have one:
    **every other `StorageError` means the store is broken and answers 503**, and this one
    means the store is working perfectly and the caller named something that is not there.
    A 503 tells somebody to try again later about a thing that will never work.

    There is no foreign key for it and cannot be — `grantee_id` means a different table
    depending on the column beside it — so both stores check it and raise this, which is
    also what keeps the two refusals identical.

    Found by running the grant routes at their edges: `PUT .../grants/group/nope` answered
    **503**, which is the same mistake the `AgentNameTaken` handler was registered to fix,
    arriving through a route that did not exist when that reasoning was written.
    """


class UnknownConnectorError(StorageError):
    """A connection named a connector this tenant has not vetted. Migration 021.

    Its own class for the reason `AgentNameTaken` has one: every other `StorageError`
    means the store is broken and answers 503, and this one means the store is working
    and the request is wrong. `access/connections.py` turns it into `ConnectionRefused`,
    which is a sentence a person can act on — "the database is unavailable" is the wrong
    thing to tell somebody who mistyped a connector name.

    Distinguished by class rather than by matching on the message, because a message is
    the thing a later edit changes without anybody noticing what depended on it.
    """


class ConnectorInUseError(StorageError):
    """A connector still holds connected accounts, so it may not be deleted.

    The `RESTRICT` half of migration 021, and a 409 rather than a 503 for the same
    reason as above. Deleting anyway would orphan sealed credentials that nobody can
    read, attribute, or clean up — and that a connector later reusing the id would
    silently inherit.
    """


class ConnectorExistsError(StorageError):
    """`create_connector` named a connector that already exists.

    Its own class, and its own *method*, for exactly the reason `AgentNameTaken` has
    both. `save_connector` is an upsert that **replaces the vetted list wholesale** —
    correct for `--seed`, and catastrophic for registration: an admin who has approved
    nine tools and mistypes `--add-connector jira` a second time would lose all nine,
    silently, to a command whose entire visible effect is "the row exists".

    The distance between the two methods is one line of SQL, the same distance
    `create_agent` put between itself and `save_agent`, and for the same class of
    reason: an upsert reached through a command a person types is a data-loss primitive
    with a friendly name.
    """


class ValueRefused(StorageError):
    """A value this layer checked and will not store, and the caller can fix it.

    **The generalisation of `AgentNameTaken`'s reasoning, made after the fourth time.**
    Every other `StorageError` means the store is broken and answers 503; the store
    refusing a *value* means it is working perfectly and somebody typed something wrong.
    Four classes have already been split out one at a time for that reason —
    `AgentNameTaken`, `NoSuchGroupError`, `ConnectorExistsError`, `UnknownTenantError` —
    each after a caller error shipped as a 503 or a 500 and somebody found it by driving a
    route at its edge.

    This one is deliberately **not** narrow, because narrow is what produced four
    incidents. It covers the validation helpers a person reaches through a form: a host
    that is not a host, an authorization endpoint that is not `https`, a scope that is not
    a string, an authorize parameter the consent flow builds itself. All of those were
    503s until 12c put a screen in front of them, and the next one added to this file
    inherits the right status by using this class instead of the base.

    **Found by driving the new admin routes**, which is how every previous member of this
    family was found. `POST /admin/hosts` with a pasted URL — the single commonest thing
    somebody will do on that screen — answered *"storage unavailable: try again later"*
    about a string that will never be accepted, while `normalize_host` had a sentence
    ready saying exactly what to strip.
    """


class FollowUpConflict(StorageError):
    """A second live follow-up to a parent that already has one. Migration 027.

    Its own class for the reason `AgentNameTaken` has one: every other `StorageError`
    is a 503, and this is a **409** — the store is working perfectly and the request
    is wrong. A thread is linear, so a run has at most one child that is live or
    succeeded; two people (or two retries without a key) racing to continue the same
    turn reach the `runs_one_live_child` index and exactly one wins.

    Raised by the database in Postgres and by the same predicate under the lock in
    memory, so there is no advisory lock and no read-then-write window either way.
    The freed-slot rule is the other half: a child that reaches `failed`, `cancelled`,
    `incomplete` or `interrupted` leaves the index, so this refusal never means a dead
    follow-up has bricked the thread — it means a live or finished one exists, and the
    thing to continue is that.
    """


ONE_LIVE_CHILD = (
    "run '{parent}' already has a continuation. A conversation is linear — follow up "
    "on its latest turn instead, or wait for the follow-up in flight to finish."
)

# The statuses that occupy a parent's one continuation slot. `complete` is in the set
# because a succeeded follow-up is the thread's next turn; everything terminal-but-
# failed leaves it, which is what lets a dead follow-up be asked again.
LIVE_CHILD_STATUSES = frozenset({"queued", "running", "complete"})

# One sentence for a parent that is absent *from this tenant* — which deliberately does
# not distinguish "does not exist" from "belongs to another customer". Raised as
# `ValueRefused` by both stores; the routes never surface it, because they answer 404
# before storage is asked, so this is the backstop that keeps a second caller honest.
NO_SUCH_PARENT = (
    "run '{parent}' does not exist in tenant '{tenant}', so there is nothing to "
    "continue. A follow-up names a run this tenant recorded."
)


class NoSuchConnectorError(StorageError):
    """`vet_tool` named a connector that has not been registered.

    Distinct from `UnknownConnectorError`, which is the *connection* path's version of
    the same sentence — that one is raised when somebody seals a credential against a
    connector that does not exist, and it is turned into a `ConnectionRefused`. This one
    is raised when somebody vets a tool on one. Two classes rather than one because the
    two have different callers, different remedies, and will grow different messages;
    collapsing them is how `--vet` ends up telling a connector admin to go and
    disconnect an account.
    """


class IssuerConflictError(StorageError):
    """Two customers would be routed from one identity provider.

    Its own class because it is the one storage error whose consequence is a
    cross-tenant read rather than a failed write. Raised when registering a provider
    would make a token ambiguous — see `save_tenant_idp` for the two shapes that
    ambiguity takes.
    """


# How a `connections` row's credential was obtained, and therefore how its ciphertext is
# encoded. Migration 024's CHECK, mirrored here so the in-memory store is not the looser
# of the two — the drift the contract suite exists to catch.
#
# **Not the same set as `credentials.SHARED` / `DELEGATED`**, which is a near-miss worth
# naming because the two will sit beside each other in a reader's head. Those two say
# *whose account a call went out as* and are recorded on every audit record, including
# for connectors nobody has connected. These two say *how the row got here* and only
# exist because a row exists at all — every value here is `delegated` over there.
CREDENTIAL_KINDS = frozenset({"static", "oauth"})

STATIC_CREDENTIAL = "static"
OAUTH_CREDENTIAL = "oauth"


# *Not passed*, for the one argument where None is a value. `update_user`'s
# `external_id` can be set, cleared, or left alone, and None already means cleared —
# `groups.external_id` has spelled *not linked* that way since 017 — so leaving it alone
# needs a third spelling. A private object rather than a string, because a string is a
# value somebody could send. Step 071.
_UNSET: Any = object()


@runtime_checkable
class Storage(Protocol):
    """What the platform needs a store to do.

    `runtime_checkable` only checks that the methods exist, never their behaviour —
    the contract suite is the real check, and a class satisfying this Protocol without
    passing that suite is not an implementation.
    """

    # --- readiness ---------------------------------------------------------------

    def ping(self) -> None:
        """One real round trip to the backing store, or `StorageError`. Step 056.

        The whole of what `/health/ready` asks. Returns nothing on purpose: the
        answers are "the store answered" and an exception whose sentence says why it
        did not — a boolean would flatten the remedy `_connection` works to carry
        (the missing role, the missing grant) into `False`.
        """

    def pool_stats(self) -> dict:
        """The connection pool's own numbers, for `/metrics`. Step 057.

        Empty from a store with no pool. Keys are the pool's own vocabulary
        (psycopg_pool's `get_stats`), values numeric — the API renders them without
        knowing psycopg exists, which is the whole reason this crosses the protocol
        rather than the route reaching into an attribute.
        """

    # --- tenants ----------------------------------------------------------------

    def create_tenant(self, tenant_id: str, name: str) -> None:
        """Idempotent: creating an existing tenant is not an error.

        **A deleted tenant's id is never reused** — `TenantDeleted`, migration 029. See
        `delete_tenant`, and note that this is the one input where idempotency stops:
        creating the same tenant twice is fine, and re-creating a deleted one is not.
        """

    def get_tenant(self, tenant_id: str) -> dict | None:
        """The row, including `status`.

        On the authentication path since migration 020: `access/users.py` reads it to
        refuse a suspended customer before anybody becomes a `Principal`.
        """

    def list_tenants(self) -> list[dict]:
        """Every tenant, by id. The one call with no tenant argument, because it is
        the operator's view rather than anything on a request path."""

    def set_tenant_status(self, tenant_id: str, status: str) -> None:
        """`active` or `suspended`. Setting an unknown tenant's status does nothing.

        Suspension closes the two doors work arrives through — authentication, and the
        claim loop — and stops nothing already running. See migration 020 for why those
        are different operations and why collapsing them would make this unusable for
        the maintenance-window case.
        """

    def delete_tenant(self, tenant_id: str, *, actor: str) -> dict:
        """Erase a customer, and leave a tombstone saying they were erased.

        Migration 029, and the row the register carried since 002 whose answer was
        *impossible* rather than *not yet*: five tables reference `tenants(id)` with no
        `ON DELETE CASCADE`, so a plain `DELETE FROM tenants` raises a foreign-key
        violation for any real customer, deliberately.

        **Two refusals before anything is touched**, both `TenantDeletionRefused`:

            status is 'active'          suspend first — suspension is the brake, and
                                        this is the demolition
            any run is 'running'        a worker is mid-flight and will write audit
                                        rows for a tenant being erased underneath it

        `UnknownTenantError` for a tenant that does not exist, including one deleted a
        moment ago — deletion is a ceremony rather than a convergence, so the second
        call is an error and the tombstone is where the operator finds out why.

        Then, in **one transaction**: the five blocking tables emptied in an order the
        foreign keys between them allow, the tombstone written, and the tenant row
        deleted — whose cascades take everything else. Returns the tombstone, whose
        `detail` carries the per-table counts, so a caller can print what was destroyed
        without a second read of a tenant that no longer exists.

        **The log tables are emptied explicitly rather than by cascade, and the keys
        stay as they are.** A no-cascade key means the day somebody adds a table and
        forgets this method, the next deletion fails loudly instead of leaving orphaned
        rows nothing will ever find again.
        """

    def get_tenant_tombstone(self, tenant_id: str) -> dict | None:
        """The record that this tenant was deleted, or `None`. See `TOMBSTONE_FIELDS`.

        Readable for the same reason it is written: an operator who types a deleted
        tenant's id deserves *"deleted on the 3rd by priya"* rather than *"does not
        exist"*, which is indistinguishable from a typo.
        """

    def list_tenant_tombstones(self) -> list[dict]:
        """Every deletion, most recent first. The operator's view, like `list_tenants`."""

    def prune_log_records(self, cutoff) -> dict:
        """Delete log records older than `cutoff`. Returns per-table counts.

        The three append-only tables only — `RETAINED_LOG_TABLES`. Not `runs`, which is
        live product data with foreign keys between rows and a screen that reads them:
        pruning a thread's root is a decision about conversations vanishing rather than a
        compliance sweep, and it belongs with the encrypt-at-rest row it shares a
        register line with.

        **The boundary applied is `prune_floor(cutoff)`, not `cutoff`** — see it for what
        that costs. Since migration 030 this is a partition drop, and a partition is a
        whole month, so a month goes only once the cutoff has passed all of it.
        Still strictly `<` at that boundary.

        **By `ts` and nothing else**, which is what let it become a drop at all. Plan 018
        decision 8 shaped it this way one step ahead of the conversion: no per-tenant
        window, no per-row predicate, nothing a `DROP TABLE` cannot express. The
        prediction held — this is now three statements per expired month rather than a
        batched delete loop, and it collected on the promise without changing a caller.

        **No `batch` parameter, and no batching.** Dropping a partition writes no
        per-row WAL and takes no per-row lock, so the thing batching existed to bound
        does not happen. `check_prune_batch` went with it: `batch=0` was an infinite
        loop in one store and a correct answer in the other, and deleting the loop
        deletes the hazard rather than defending it — 029's own rule about an index
        nothing chooses, applied to a guard nothing needs.

        Two workers pruning at once is safe: the drop of a given month happens once and
        the loser sees it already gone, and each caller's counts report what it removed.

        One `admin_audit` record per affected tenant, action `retention.prune`, actor
        `RETENTION_ACTOR` — and none at all for a sweep that removed nothing, on
        `delete_agent`'s rule that a log recording attempts as well as changes cannot
        answer "what happened" with one row. `detail["cutoff"]` carries the **effective**
        boundary rather than the requested one, because a record claiming a precision the
        operation does not have is the control that looks present and is absent.
        """

    def ensure_log_partitions(self, *, back_to=None) -> list:
        """Create any missing monthly partitions for the three log tables. Migration 030.

        Returns the names created, oldest first — empty when coverage was already
        complete, which is the common case and the reason this is cheap to call often.

        **Ahead of time, never on the write path.** Creating a partition takes a lock on
        the parent, and `_write_admin` runs inside the caller's transaction by design, so
        a partition created there would hold that lock for the length of somebody's
        product write and serialise every log append in the process behind it. Three
        callers keep coverage true instead: migration 030 seeds it, opening a
        `PostgresStorage` repairs it, and the worker's sweep maintains it. An append that
        outruns all three fails loudly — see `missing_partition`.

        `back_to` extends coverage backwards for a caller writing a back-dated world on
        purpose, which is tests and the e2e scripts; production writers stamp `now`.

        A no-op in the in-memory store, which has no partitions and never fails an
        append for want of one. It is on the protocol anyway rather than being a
        Postgres-only method, because the worker calls it against whichever store is
        configured and a method that exists on one side of that seam is the drift the
        contract suite exists to catch.
        """

    # --- agents -----------------------------------------------------------------

    def load_agents(self, tenant_id: str) -> list[dict]:
        """Every agent **row** for this tenant, ordered by name. See `AGENT_FIELDS`.

        Ordered because Postgres without an ORDER BY is unordered, and a caller that
        accidentally depends on insertion order would pass against the fake and fail
        in production.

        **This returned the config alone for eight steps, and step 10d changed it.**
        Three handoffs said *"`agents.updated_at` exists and is the obvious ETag"*; the
        column existed and nothing could read it, because both read methods returned
        `config` and dropped every other column on the floor. A compare-and-set needs the
        timestamp above this layer, so the row is what comes back — and `AGENT_FIELDS`
        is what stops the fake keeping a different set of columns from the table.
        """

    def get_agent(self, tenant_id: str, name: str) -> dict | None:
        """One agent row, or None. `AGENT_FIELDS`, and see `load_agents`."""

    def get_agent_by_id(self, tenant_id: str, agent_id: str) -> dict | None:
        """One agent row by its identity, or None. `AGENT_FIELDS`. Step 025.

        The primary key since migration 035, and the only method that reads it — which is
        why it arrived late rather than with the migration. Every surface above `storage/`
        addresses agents by name, deliberately, so almost nothing needs this.

        **What needs it is anything holding a stored reference to an agent across time**,
        and there is exactly one such thing: `runs.agent_id`. A worker claiming a run whose
        agent was renamed while it sat queued has to find that agent, and the name on the
        row is what the caller typed rather than what the agent is called now. Looking up
        the name would answer "no such agent" about an agent that is right there.

        Returns None for an unknown id, including `''` — the caller has a run row from
        before 035 and should fall back to the name, which is what `Worker._run` does.
        """

    def save_agent(self, tenant_id: str, config: dict, *, actor: str) -> None:
        """Insert or replace, keyed by `config["name"]`.

        The name is taken from the config rather than passed separately: the broker
        trusts `config["name"]` as the agent's identity, so a row whose key disagreed
        with its body would misattribute every audit record it produced. Postgres
        enforces the same thing with a CHECK constraint.

        **An upsert, and that is right for exactly one caller.** `--seed` is documented
        as safe to re-run, which is what this shape buys. Anything that means *create*
        must call `create_agent` — see the warning there.

        Writes `agent.save` to `admin_audit`, in the same transaction. `--seed` passes
        `SYSTEM_ACTOR`, which is the least useful true statement available and is still
        true — see `NO_ACTOR` for why there is no default.

        Writes an `agent_versions` row too, in the same transaction and **only when the
        config actually changed** — so re-running `--seed`, which this method exists for,
        does not fill an agent's history with copies of one configuration. The record is
        still written either way: the log holds writes, the history holds states.
        """

    def create_agent(
        self,
        tenant_id: str,
        config: dict,
        owner_kind: str,
        owner_id: str,
    ) -> None:
        """Write a new agent **and its owner grant**, atomically. Never an upsert.

        Two properties, and both of them are the reason this is one method rather than
        two calls from the layer above.

        **A name that already exists is `AgentNameTaken`, not a replacement.** Building
        a create route on `save_agent` would let somebody silently overwrite an agent
        another person owns, and nothing else on that path would refuse it:
        `agents.validate` checks configs, not grants, and the grant tables are not
        consulted by a write to `agents` at all. The upsert is one line away from being
        correct-looking and catastrophic, so create is a different method.

        **The row and its grant are one transaction.** Nothing creates an agent with an
        owner except migration 011 and `--seed`, and absence is denial — so a process
        that dies between the two writes leaves an agent nobody can run, including its
        author. That failure is invisible: the row looks fine and only *running* it
        fails, at which point the agent is indistinguishable from one somebody has no
        access to. Atomicity is a storage property and nothing above this layer can
        offer it.

        The owner grant is written directly rather than through `access/grants.py`.
        That is not a shortcut around the permission model: `share` requires `editor`
        on an agent, and there is no agent yet to hold a grant on. Creating a thing is
        what makes you its owner.

        `owner_kind` is a **principal**, not a grantee — a group cannot own an agent,
        for the reason `GROUP_ROLES` gives. Validated as one.

        **The owner is also the actor**, so this is the one in-scope method that needed
        no new parameter: creating a thing is what makes you its owner, and the two can
        only disagree if somebody invents a create-on-behalf-of route. `agent.create`
        goes into `admin_audit` as a third statement in the same transaction — the row,
        its grant, and the record of who made both.

        Four statements since 032: version 1 goes in with them, authored by the owner.
        An agent's history therefore starts at the moment it exists, and there is no
        window in which a config is live with nothing recording what it says.
        """

    def update_agent(
        self,
        tenant_id: str,
        config: dict,
        *,
        actor: str,
        if_unchanged_since,
        restored_from: int | None = None,
    ) -> dict | None:
        """Replace an agent's config **only if nobody else has**. The compare-and-set.

        Returns the new row, or **None when the timestamp did not match** — the same
        shape `start_run` and `finish_run` already use, and for the same reason: a lost
        race is the ordinary shape of concurrency rather than an exception, and the loser
        needs to carry on and report rather than to handle one.

        `if_unchanged_since` is the `updated_at` the caller last read. One statement:

            UPDATE agents SET config = %s, updated_at = now()
             WHERE tenant_id = %s AND name = %s AND updated_at = %s

        **The guard cannot live above this layer**, which is the whole reason this is a
        third write method rather than a check in a route. Read-then-write in
        `routes_agents.py` has a window between the two in which the other editor
        commits, and that window is precisely the failure the timestamp exists to catch.
        Atomicity is a storage property, same argument as `create_agent`'s transaction.

        None is also what an **absent** agent produces, and the two are deliberately not
        distinguished here: telling them apart means a second read, and a second read has
        the same window this method exists to close. A caller who needs to know reads the
        row afterwards — by which point "gone" and "changed" are both answerable and
        neither is a race, because the write did not happen either way.

        **`save_agent` keeps its upsert and gains no guard.** It is `--seed`'s method and
        documented as safe to re-run; a conditional upsert is a contradiction. The
        distance between "write this" and "write this if nobody else has" is one WHERE
        clause and one catastrophe, so it is a different method — exactly the argument
        that made `create_agent` a second one.

        Writes `agent.update` to `admin_audit`, in the same transaction, and only when a
        row actually moved.

        **`restored_from` is the one parameter a restore needs, and it is one rather than
        three on purpose.** A restore is an edit whose body is an old config — the same
        compare-and-set, the same 409 when two people race — so the mechanism is shared
        and only the provenance differs. Passing the version being restored *is* the
        provenance: it makes `source` `'restore'` rather than `'update'` and the record
        `agent.restore` rather than `agent.update`, so the three can never disagree with
        each other the way three parameters eventually would. Migration 032's
        `agent_version_restore_names_one` is the same rule stated in the schema.

        The history row goes in beside the record, and **only when the config actually
        changed**: a save that writes back what is already there advances `updated_at`,
        writes its record, and adds nothing to the history — including a restore of the
        version that is already live.
        """

    def rename_agent(
        self,
        tenant_id: str,
        name: str,
        new_name: str,
        *,
        actor: str,
    ) -> dict | None:
        """Give an agent a different name and change nothing else. Step 025.

        Returns the new row, or **None when there is no agent by that name** — `None` is
        absence here and nothing else, unlike `update_agent` where it is also a lost race.
        Raises `AgentNameTaken` when the target is in use, which is `create_agent`'s
        refusal for `create_agent`'s reason: two agents cannot share one URL.

        **The operation this method exists to make possible was previously impossible**,
        and not by omission. `agents` was keyed `(tenant_id, name)` until migration 035, so
        the only way to change a name was to write a second row and delete the first —
        which cascades away every grant, pending grant, schedule, trigger and version the
        agent had, and orphans its run history from every listing. That is a delete wearing
        a rename's clothes. Now the key is `agent_id` and this is one UPDATE.

        **The column and the config move together, in one statement.** `agents.config`
        carries the agent's identity as far as the broker is concerned — `core/broker.py`
        reads `config["name"]` and writes it into every audit record — and migration 002's
        `agent_name_matches_config` refuses a row where the two disagree. So this cannot be
        a column update with a config update behind it: either both land or neither does.

        Three writes, in one transaction, and each of them is load-bearing:

        - the row, which is what changes the URL;
        - an `agent_versions` row with source `rename`, because `config` genuinely changed
          and a history missing the write that changed it is a history with a hole. It is
          keyed by `agent_id`, so the rename lands *in* the agent's existing history
          rather than starting a second one;
        - `agent.rename` in `admin_audit`, with `from` and `to` in the detail. Migration
          035 declines to re-key the log tables, which means an agent's records are written
          under whatever it was called at the time and **this record is the only thing that
          joins them.** Reading an incident across a rename goes through it.

        No `if_unchanged_since`. A rename is not a form submission racing another form
        submission — it is one deliberate act from an owner, serialized on the row like
        every other write here, and the second of two concurrent renames finds no agent by
        the old name and gets `None`. Adding an ETag would mean inventing a 412 for a
        conflict that reads correctly as a 404.
        """

    def delete_agent(self, tenant_id: str, name: str, *, actor: str) -> None:
        """Idempotent: deleting an absent agent is not an error.

        Writes `agent.delete` **only when a row was actually removed**. See
        `ADMIN_ACTIONS` for why the log records changes rather than attempts.

        **The agent's version history goes with it**, by cascade in Postgres and by hand
        in the fake. Stated here because it is a decision rather than a consequence: a run
        *names* an agent and survives it; a version *is* one and does not.

        **Migration 035 removed this cascade's original argument and left the cascade.**
        032 justified it by the key: history was stored under `(tenant_id, name)`, so a
        `triage` re-created next week would open a screen full of the first author's
        prompts. That can no longer happen — a re-created name is a new `agent_id` and
        inherits nothing, which is now true of the run history too. What is left is the
        plainer reason, which was always the better one: erasing an agent erases it.
        """

    def list_agent_versions(
        self,
        tenant_id: str,
        name: str,
        *,
        limit: int = 50,
    ) -> list[dict]:
        """This agent's history, newest first. `AGENT_VERSION_SUMMARY_FIELDS`.

        **No configs.** A history card shows dates and authors, and fifty configs down
        the wire to render one is fifty prompts nobody asked for; `get_agent_version` is
        how a caller asks for one. The `API_TOKEN_PUBLIC_FIELDS` device, here for size
        rather than for secrecy — nothing in a version is a secret from somebody who can
        already read the live config.

        Capped, and the cap is not pagination: section D's row owns that for every list
        in this system at once, and inventing a second convention here would make it two
        problems. An agent edited more than `limit` times has an older history that is
        present in the table and not returned.

        An agent with no row answers `[]` rather than raising, on `load_agents`' shape:
        absence is a caller's question, and the route above already distinguishes it.
        """

    def get_agent_version(self, tenant_id: str, name: str, version: int) -> dict | None:
        """One stored configuration, or None. `AGENT_VERSION_FIELDS`.

        Returns the config **exactly as it was written**, unvalidated. Validity is a
        read-time question and belongs above this layer, because it moves: a tool
        un-vetted last week makes a version from last month unrestorable, and the row is
        unchanged by that. Storage says what was stored; `agents.validate` says whether
        it would run today.
        """

    # --- connectors -------------------------------------------------------------

    def load_connectors(self, tenant_id: str) -> list[dict]:
        """Every connector manifest for this tenant, ordered by id."""

    def get_connector(self, tenant_id: str, connector_id: str) -> dict | None: ...

    def create_connector(
        self,
        tenant_id: str,
        connector_id: str,
        *,
        launch: dict,
        description: str = "",
        allow_asserted_identity: bool = False,
        from_recipe: str = "",
        actor: str,
    ) -> None:
        """Register a connector with an **empty allowlist**. Raises if it exists.

        `from_recipe` is step 068 and is **provenance, never a link**: the id of the
        checked-in preset the values came from, written into `admin_audit.detail` and
        nowhere else. No column, no foreign key, no join — that is rule 1, and it is what
        makes deleting a recipe safe. Answering *which connectors came from the recipe
        that just broke* therefore means reading the log by hand, which is the direct and
        deliberate price.

        The caller asserts it, so the writer checks the recipe exists in this build
        before passing it — otherwise this is a client writing arbitrary text into an
        append-only administrative log, which is `vetted_by`'s objection at a lower
        stake.
        
        The row, so a credential has somewhere to live — migration 021's foreign key
        means `save_connection` refuses a credential for a connector that has not been
        saved, and discovery needs a credential, so "connect, look, then decide whether
        to register" is not expressible. This is the method that resolves that ordering.

        **Vets nothing**, and that is the whole shape of decision 4: registering a server
        and approving one of its tools are two different judgments made at two different
        times by somebody who has read something in between.

        `allow_asserted_identity` — step 033c, default False and the default is the
        posture: whether this tenant will *believe* an unverified acting-for through
        the MCP door for this server's tools. A column rather than a launch key so
        "which connectors accept asserted identity" is a WHERE clause.

        No `ON CONFLICT`, and `ConnectorExistsError` says why.
        """

    def vet_tool(
        self,
        tenant_id: str,
        connector_id: str,
        vetted: dict,
        *,
        actor: str,
        server_name: str = "",
        server_version: str = "",
        vetted_arguments: tuple = (),
    ) -> None:
        """Approve **one** tool on an existing connector. Appended, never replacing.

        This is the method `save_connector` could not be. `save_connector` replaces a
        connector's vetted list wholesale — right for `--seed`, where the module *is* the
        allowlist, and data loss here: an admin who has approved nine tools and is
        looking at the tenth must not lose nine by getting the command wrong.

        So one row, upserted on `(tenant, connector, remote_name)`. Re-vetting the same
        tool replaces that tool's row and no other, which is also the whole of "editing a
        vetted annotation in place is out of scope, re-vet it": the review record is
        overwritten by a new review rather than edited underneath the old one's name.

        **This is the writer `vetted_by` has been waiting for since migration 018.** Every
        row in the catalogue says `vetted_by = ''` today because nothing vets; this is the
        thing that vets, and it stamps the acting principal, the moment, and what the
        server called itself when it was asked. `server_name` and `server_version` come
        from `initialize`'s `serverInfo` and are recorded rather than trusted — see
        migration 023.

        Raises `NoSuchConnectorError` if the connector is not registered. There is no
        create-on-vet: a `--vet` that conjured a connector would be a command that dials
        a host nobody approved.
        """

    def save_connector(self, tenant_id: str, manifest: dict, *, actor: str) -> None:
        """Insert or replace, keyed by `manifest["id"]`.

        The manifest carries `launch` and `vetted`. It must NOT carry `read_only` —
        that is derived from the vetted effects and storing a copy is precisely the
        drift the design forbids. Rejected here rather than ignored, because a field
        that is silently dropped reads as honoured.

        Every vetted row round-trips with exactly `VETTED_TOOL_FIELDS`. Missing keys
        are filled from `VETTED_TOOL_DEFAULTS` so a manifest read back from either
        store has the same shape — the reason `IDP_DEFAULTS` exists, for the same
        failure: a field one implementation keeps and the other drops.

        **Still the wholesale replace, deliberately.** `--seed` re-runs are documented as
        safe and a conditional upsert is a contradiction; `create_connector` and
        `vet_tool` are what registration uses instead. The `actor` is new in step 012 and
        is what finally puts a name on `vetted_by` for the rows this writes — for `--seed`
        that name is `system:cli`, which is the least useful true statement available and
        still true.
        """

    def set_asserted_identity(
        self, tenant_id: str, connector_id: str, allowed: bool, *, actor: str
    ) -> None:
        """Turn asserted acting-for on or off for one connector. Step 033c.

        A dedicated method rather than a `save_connector` round trip, because this is a
        security control changing state and the administrative log should say exactly
        that: one `connector.asserted_identity` record naming the actor and the new
        value, not a `connector.save` that happens to differ in one field a reader has
        to diff for. The allowlist is untouched.

        Raises `NoSuchConnectorError` if the connector is not registered — enabling
        trust in a caller for a server nobody has pointed the tenant at is not a state
        to be able to reach.
        """

    def delete_connector(self, tenant_id: str, connector_id: str, *, actor: str) -> None:
        """Idempotent. Cascades to that connector's vetted tools.

        Writes `connector.delete` **only when a row was actually removed**, on
        `delete_agent`'s precedent: the log records changes rather than attempts.
        """

    def load_vetting_record(self, tenant_id: str) -> list[dict]:
        """Who approved each of this tenant's vetted tools, when, and against what.

        `(connector_id, remote_name, vetted_by, vetted_at, server_name, server_version)`,
        ordered by the first two.

        **Separate from the manifest on purpose**, and this is the one design decision
        in this method. The manifest is the *allowlist* — what may be called — and
        `save_connector` takes it from whoever is doing the saving. Provenance is not
        something a caller gets to assert: a `vetted_by` arriving in a dict is a claim
        that Alice approved this, made by code that is not Alice. So it stays a column
        the database owns and this reads, and nothing can write it by passing a
        manifest.

        **Step 012 gave it a writer.** `vet_tool` stamps all four, so a tool approved
        through `--vet` names a person, a moment, and the server version it was approved
        against. Two things stay true and are worth saying plainly: a row written by
        `save_connector` still has `vetted_at` meaning *when the connector was last
        saved*, because that method still replaces the allowlist wholesale; and
        `server_name`/`server_version` are `''` on every row that predates 023 and on
        every row `--seed` writes, because `--seed` contacts no server and inventing a
        version for it would be the one lie this record exists not to tell.
        """

    # --- egress ---------------------------------------------------------------------

    def allowed_hosts(self, tenant_id: str) -> list[dict]:
        """Hosts this tenant will let us dial, ordered by host.

        `(host, allowed_by, allowed_at, note)`. **An empty list denies everything** —
        that reading lives in `tools/mcp/egress.py`, not here, because this method's job
        is to report rows and a store that returned "no rows, therefore allow" would be
        making a policy decision in a getter.
        """

    def allow_host(
        self, tenant_id: str, host: str, *, actor: str, note: str = ""
    ) -> None:
        """Approve one host for this tenant. Idempotent; re-approving updates the note.

        `host` is normalized by `normalize_host` and refused if it is not a bare host —
        a URL, a port, or a path here means the caller thinks this is an allowlist of
        endpoints, which it deliberately is not.
        """

    def revoke_host(self, tenant_id: str, host: str, *, actor: str) -> bool:
        """Withdraw a host. Returns whether a row was removed.

        Does **not** touch connectors already registered against it. That is deliberate
        and it is the honest shape: the connector row stays, and the next connect to it
        is refused by the egress check. Cascading to delete connectors would make
        revoking a host a destructive operation on unrelated data — and it would destroy
        the vetting record of tools somebody approved, which is the one thing this
        schema goes out of its way to keep.
        """

    # --- audit ------------------------------------------------------------------

    def append_audit(self, tenant_id: str, record: dict) -> None:
        """Append one audit record. Never updates, never deletes.

        `record` is the call — it does not carry its own `tenant_id`, because that is
        routing and having it in two places is how the two disagree. Reads merge it
        back in, so a round trip returns the record plus `tenant_id`.
        """

    def audit_records(
        self,
        tenant_id: str,
        *,
        run_id: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """Audit records for this tenant, **oldest first**.

        Ordered by insertion, not by timestamp: two records written in the same
        millisecond are ambiguous by `ts` and exact by insertion order, and the
        sequence of a run is the thing being read.

        `limit` returns the most recent N — still oldest-first within the result.
        That is what a log view wants, and it is the sort of detail a fake gets
        backwards, so the contract suite asserts it.
        """

    # --- the administrative audit log -------------------------------------------
    #
    # Migration 022. A second log, answering a question the first cannot: not "what did
    # this agent do" but "who changed who may do it".
    #
    # **There is no `append_admin_audit`, and its absence is the design.** Records are
    # written by the storage methods themselves, inside the transaction that performs
    # the write — see decision 2 of step 011. A public append would be a second way to
    # produce a record, which means a record that can be absent when the write succeeded
    # and a record that can exist when nothing happened. Both failures are silent, which
    # is the only kind that matters in a log kept for incidents.
    #
    # The hook lives here rather than in `access/` and `agents/` for the reason every
    # other invariant in this file does: the CLI and the API are separate call paths into
    # the same storage methods, so a record added at one caller is a record missing at
    # the other — and the missing one is invisible until somebody asks a question it
    # cannot answer.

    def admin_audit_records(
        self,
        tenant_id: str,
        *,
        action: str | None = None,
        target_kind: str | None = None,
        target_id: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """Administrative records for this tenant, **oldest first**.

        Ordered by insertion rather than by `ts`, and `limit` returns the most recent N
        still oldest-first — identical to `audit_records`, deliberately, because two
        logs whose read methods disagreed about ordering would be two things to
        remember.

        `target_kind` / `target_id` answer *"everything that ever happened to this
        agent"*, which is the incident query and the reason a grant is recorded against
        its agent rather than against its grantee.

        **Read-only, and as of 12b there is an HTTP route.** `GET /admin-audit` requires
        the `admin` platform role migration 026 adds — which is what this docstring spent
        two steps saying did not exist. The rule it stated still holds and is the reason
        the route waited: a read route retrofitted with authorization later is worse than
        no route, so the authorization arrived first and the route second.
        """

    # --- the access-denial log --------------------------------------------------
    #
    # Migration 028. A third log, answering the question the other two cannot: not
    # "what did this agent do" (`audit`), not "who changed who may do it"
    # (`admin_audit`), but "who tried, and was refused".
    #
    # **`record_denial` is public, and that is not a break with 022's rule — it is the
    # reason this is a separate table.** An `admin_audit` record rides the transaction
    # of the write it describes, so a public append there would be a second way to
    # produce one. A denial performs no write and rides no transaction: the refusal is
    # the whole event, and the hooks in `access/grants.require` and
    # `access/roles.require_admin` are its only producers.

    def record_denial(self, tenant_id: str, record: dict) -> None:
        """Append one denial record, built by `make_denial_record`.

        Raises on a store that cannot take it, and the *caller* decides that recording
        is best-effort — because the caller is the one serving a refusal that must not
        change, and this layer cannot know that. See `access/denials.py`.
        """

    def denial_records(
        self,
        tenant_id: str,
        *,
        principal_kind: str | None = None,
        principal_id: str | None = None,
        resource_kind: str | None = None,
        resource_id: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """Denial records for this tenant, **oldest first**.

        Ordered by insertion rather than by `ts`, and `limit` returns the most recent
        N still oldest-first — `admin_audit_records`' signature shape and ordering
        rules, copied rather than rhymed with, because two logs whose read methods
        disagreed about ordering would be two things to remember.

        The filters are the two incident queries migration 028's second and third
        indexes exist for: *"what else did this person probe?"* and *"who probed
        payroll-bot?"*.
        """

    def last_door_refusal(self, tenant_id: str, tool_names: Sequence[str]) -> dict | None:
        """The newest denial the door wrote for any of these tools, or None. Step 074.

        The connect card's second question. `door_call_summary` answers *has anything
        arrived* from `audit`, and a call the **door** refuses before the broker — a
        token granted no agent that provides the tool, or an acting-for claim that
        fails — never reaches `audit`: it is one `access_denials` row, `resource_kind`
        `tool`, written by `door.call_tool` and nothing else. So the one screen a person
        watches during a first connection rendered *nothing tried* and *everything
        refused* identically, and this is the read that tells them apart.

        **Matched by tool name, not by token.** The failure the card exists for is a
        token that is not granted this agent asking for one of this agent's tools; the
        denial names that tool, and the agent's own permission list is the set to match
        against. A token that *is* granted the agent and asks for something the agent
        does not carry is refused too, but that refusal names a tool this agent has never
        had and is not this agent's news. `tool_names` empty answers None without a read.

        Same record shape as `denial_records` — `DENIAL_FIELDS` with `tenant_id`, `ts` as
        an ISO string — so the API projects it the way it projects any denial.
        """

    # --- the door's traffic -----------------------------------------------------
    #
    # Not a fourth log. A reader over `audit`, filtered to the rows a run can never have
    # written — step 035a, paying the debt four chunks of plan 033 deferred with the same
    # sentence.

    def door_call_records(
        self,
        tenant_id: str,
        *,
        limit: int | None = None,
        since: date | None = None,
        until: date | None = None,
        tool: str | None = None,
        agent: str | None = None,
        principal_id: str | None = None,
        principal_kind: str | None = None,
        acting_for: str | None = None,
        decision: str | None = None,
        outcome: str | None = None,
        effect: str | None = None,
        identity_source: str | None = None,
        owner: str | None = None,
    ) -> list[dict]:
        """Audit records for this tenant's **MCP door** calls, **oldest first**.

        ## `owner`, step 108: the person, on the row, at read time

        Every row carries one field the table does not: `owner`, the email of the person
        whose *personal* token made the call, and `''` for a service token, a person's
        own session, or the system. Resolved by joining `api_tokens.owner_id` to `users`
        as the rows are read — **never written onto the audit row**, because an email on
        an append-only table is the thing 013's redaction argument exists to prevent,
        and the join costs one index lookup per row at this scale. It is the answer to
        the one question a customer opens this listing with — *who used it* — which was
        answerable in the database before and is answerable on the screen now.

        The `owner` filter takes that email and narrows to the person's personal tokens,
        all of them: an engineer's laptop and desktop are two `principal_id`s and one
        owner, and a reader chasing a person should not have to know their machines.

        ## The filters, step 066, and why they arrive now rather than in 035a

        This method took `limit` and nothing else for six steps, and the route above it
        wrote down the condition for more: *"`/admin/denials` earned its two filters from
        the indexes migration 028 exists for; there is no equivalent index or incident
        argument here yet, and a filter added ahead of the query it serves is a guess
        with a signature."*

        **Both halves are now met.** The incident argument is the Overview: every figure
        on it is a query somebody wants to run, and an aggregate that cannot point at the
        rows behind it is the finding 066 exists to answer. The index is migration 050,
        `audit_door`, which is the partial index this docstring has named as *the fix if
        it bites* since 035a — and filtering is what makes it bite, because the backward
        walk that stops as soon as it has a page stops early only while every row it
        meets qualifies.

        Every filter is `None` for *do not narrow*, they are ANDed, and they are applied
        **in the store** rather than by whoever called it. That is not a preference: a
        client filtering a page it was already given is a lie about completeness in a log
        view, which is `/admin/denials`' own `resource_kind` argument.

        `since` and `until` are **inclusive UTC dates**, matching `overview`'s window and
        `door.budget_window()`'s day, so a link from a chart column to this log lands on
        the same day the column drew. Either may be given without the other.

        **Nothing here validates a value.** The route's signature refuses a `decision` the
        column cannot hold, and it derives that refusal from `DECISIONS` / `OUTCOMES` /
        `IDENTITY_SOURCES` / `VALID_EFFECTS` / `PRINCIPAL_KINDS` rather than typing the
        members again. A store asked for `decision='banana'` honestly answers with no
        rows, because that is what the table contains.

        Ordered by insertion and `limit`ed to the most recent N still oldest-first —
        `audit_records`' own rules, which the other two log readers already copy rather
        than rhyme with, because two logs whose read methods disagreed about ordering
        would be two things to remember.

        **Why this exists as a method rather than an argument to `audit_records`.** A
        door call's `run_id` is a correlation id shaped `DOOR_CALL_ID_PREFIX + hex`, and
        `runs.get` matches on a run-id prefix, so such a row can never be reached by the
        one route over this table — `GET /runs/{id}`. Every field that makes a door call
        worth reading (`acting_for`, `identity_source`) is therefore written to a row
        nothing can ask for. This is the ask.

        **The filter is the prefix, and there is deliberately no column.** `door-` is
        already what separates the two, so a `source` column would be a second way to say
        one thing — the shape migration 041's own note about `identity_source` refuses,
        and the shape soft delete, the connector cache and the grant cache were each
        refused for. The cost is measured rather than guessed: the page's `ORDER BY id
        DESC LIMIT n` is an index-ordered backward walk with the `LIKE` as a filter, so
        it stops as soon as it has a page — which makes *sparse* door traffic in a large
        log the slow case rather than heavy traffic, and puts the worst measured layout
        at 29 ms per 1M rows in a partition. The fix if it ever bites is a partial index,
        not a column. See `DEFERRED.md`.

        **Returns the whole record, `args` and `credential` included.** Projecting here
        would serve one caller at the other's expense: an operator with a shell wants
        both, and `api/schemas.DoorCallRecord` is where the browser's narrower view is
        taken — the same layering `denial_records` and `admin_audit_records` already use.
        """

    def door_call_summary(self, tenant_id: str, agent_name: str) -> dict:
        """`{"calls": int, "last_call_at": iso-string | None}` for one agent's door calls.

        Step 044 — the connect card's question: *has anyone knocked on this agent yet?*
        Asked by whoever just pasted the endpoint into their assistant and is watching,
        so it is two scalars for any reader of the agent, where `door_call_records` is
        pages of whole records for an administrator. Projecting one into the other would
        serve neither: the page reader must not lose fields, and this must not load rows
        to count them.

        The filter is `door_call_records`' prefix plus the `agent` column — the name the
        union rule attributed the call to, **as it was spelled when the row was
        written**. A renamed agent's count therefore restarts at the new name; the audit
        log keeps old names on purpose (035i), and this method inherits that rather than
        joining across a rename. Denials count too: the question is whether anything
        arrived, and a refused call arrived.
        """

    # --- the grant, against its evidence -------------------------------------------
    #
    # Step 076. Three readers, no writer, and every one of them reads `audit` filtered
    # to the door's prefix or `access_denials` — never `runs`. The product enforces the
    # permission list; these are what let somebody say whether the list is wider than
    # the work. They are a record, not a control: nothing here revokes anything.

    def door_tool_evidence(
        self,
        tenant_id: str,
        agent_name: str,
        tool_names: Sequence[str],
        *,
        since: date,
        until: date,
    ) -> dict:
        """What one agent's tools were actually asked to do through the door, per tool.

        Two maps, and they come from two tables because the door refuses in two places:

            {
              "tools": {tool: {"admitted": int, "refused": int,
                               "last_admitted_at": iso | None,
                               "last_refused_at": iso | None}},
              "door_refused": {tool: {"count": int, "last_at": iso}},
            }

        `tools` is every tool that appears on a door row attributed to this agent inside
        the window — **including tools the agent no longer carries**, since a call under
        a name that has since been removed is still evidence, and the caller merges this
        against the current permission list. `admitted` and `refused` are the broker's
        `decision`; a refusal here is a call that reached the broker and was out of
        scope, which is the *scope does not match the work* signal.

        `door_refused` is the other refusal — the door's own, before the broker: a token
        granted no agent that provides the tool. Those rows are `access_denials`, they
        name a tool and not an agent, and they are matched by name against `tool_names`
        on 070's argument. It is the *somebody wanted this and was not granted it* signal,
        kept separate because it says something different.

        The window is `overview`'s: UTC calendar dates, `since` and `until` inclusive.
        Stamps are ISO strings with milliseconds, the coercion every log reader applies.
        """

    def token_door_touch(
        self, tenant_id: str, token_id: str, *, since: date, until: date
    ) -> dict:
        """What one token actually touched through the door, in the window.

            {
              "touched": [{"agent": str, "tool": str, "admitted": int, "refused": int,
                           "last_at": iso}],            # ordered by agent, tool
              "door_refused": [{"tool": str, "count": int, "last_at": iso}],  # by tool
            }

        The offboarding and post-incident question — *what did this credential do* — in
        the direction `GET /me/tokens/{id}/reach` does not answer. `reach` says what the
        grant permits; this says what the log records, grouped the way the grant is
        expressed (agent, then tool), so the two can be read side by side.

        Matched on `principal_kind = 'machine'` and `principal_id = token_id`, which is
        how the door audits every token including a personal one — 033d's rule that a
        personal token is *"still a machine principal: audited as machine:<id>"*. A
        personal token's calls are therefore found here and not under its owner.
        """

    def oldest_door_record_at(self, tenant_id: str) -> "str | None":
        """When this tenant's door record begins, or None if it has no door rows at all.

        The evidence boundary. A tool unused for ninety days on a deployment three weeks
        old is a gap in the record rather than a finding, and a review that cannot tell
        the two apart will get a grant cut that somebody needed. Retention (029) trims
        the log from the old end, so this moves forward over time and is read fresh
        rather than remembered.
        """

    def overview_totals(self, tenant_id: str, *, since: date, until: date) -> dict:
        """The window's **scalars only** — the tile row's numbers and nothing else.

        Step 066a, and it exists to be a denominator. The Overview's tiles read "4,120
        calls", which is a number nobody can size without knowing what the month before
        came to; with the preceding window beside it the same tile reads "4,120, up 18%",
        which is a fact. That is the whole purpose, and it is why this is not simply a
        second call to `overview`.

        **A separate method rather than a second `overview()`**, and the difference is
        the cost. `overview` runs **fifteen** statements and returns twenty-five keys,
        every one of which would be built, shipped across the storage boundary and thrown
        away to compute a percentage. This runs **five**, over the same bounded window.

        Both numbers are measured rather than counted by eye, and both moved in step 084:
        `overview` was nineteen statements over thirty-one keys and this was six over
        nine. The figure this docstring carried before that — *"twenty… this runs four"* —
        was wrong in both halves when it was written, which is the argument for measuring
        one that is quoted in an argument about cost.

        **And rather than widening `overview` to return two windows**, which was the
        other shape available: doubling the response of the one aggregating read in this
        interface — the method whose docstring argues at length for being one method for
        one screen — in order to serve a comparison would be paying the whole page's
        price for a footnote on it.

        Returns:

            door_calls, door_denied, door_writes, door_verified, callers,
            refusals, admin_changes                 all int
            door_spend  [{model, input_tokens, output_tokens,
                          cache_read_tokens, cache_write_tokens}]

        **`runs` was a ninth key until step 084**, a count of the window's terminal runs
        that `_previous_window` read and threw away. It went with `overview`'s run series
        and for the same reason: 078 took the runtime out, nothing writes the table, and
        a statement over it on a live read is cost with no reader.

        `door_spend` is **rows, never dollars**, for the reason every other spend read
        here is: the rate table lives in `core/usage.py` and the arithmetic happens in
        the route, so an operator who fixes their prices reprices this history too.
        Grouped by model and **not by day**, because nothing draws a previous window's
        shape — only its total.

        `refusals` is the same five kinds summed that `overview` returns split, and it is
        summed here rather than returned in bands for the same reason: a delta on "how
        much did we refuse" is one number, and five deltas nobody asked for would be five
        chances to draw a percentage on a band that went from 1 to 2.

        A window with nothing in it returns zeros, and that is a true answer rather than
        a missing one: **the caller must not read all-zeros as "no previous window"**. A
        deployment younger than its own window and a quiet fortnight produce the same
        dict, and telling them apart needs the age of the log, which no reader here asks
        for and which this method deliberately does not invent.
        """

    def overview(
        self,
        tenant_id: str,
        *,
        since: date,
        until: date,
        bucket: str = "day",
    ) -> dict:
        """Bucketed counts across this tenant's door traffic, refusals and runs. Step 041.

        **The one aggregating read in this interface**, and the reason it is one method
        rather than nine is that it serves one screen: `GET /admin/overview` loads once
        and renders once, so nine round trips would buy nothing but the chance for two
        of them to straddle a write and disagree about which day it is.

        ## Why this is not `audit_records` with a `group_by`

        Every other reader here returns rows and lets the caller count them.
        `runs.call_index` is what that costs at this size — it loads a tenant's **whole**
        audit log into Python to group it per run, and is registered in `DEFERRED.md` as
        *"`audit_query` aggregation in SQL"*. A dashboard built the same way would load
        five tables into the API process to count them, once per page view, forever.
        `core/audit_query.py` drew the line in advance: *"Comparison, not aggregation…
        the aggregation belongs in SQL once there is a fleet to report on."*

        So the counting happens in the store. The Postgres implementation is `GROUP BY
        date_trunc('day', ts)`; the memory one counts dicts, because its whole dataset is
        already in Python and there is nothing to avoid loading.

        ## The shape, and the door-first ordering

        `since`/`until` are inclusive UTC dates — the caller's window, and the caller
        computes it from `door.budget_window()` so that this and the ceiling it draws
        cannot disagree about which day is today.

        Returns a dict of series. **Every series is sparse** — a day with nothing in it
        is absent, exactly as `mcp_call_windows` is absent, and for its stated reason:
        the zero-fill belongs above both stores so the fake cannot be kinder than
        Postgres. Filling here would hide precisely the drift the contract suite exists
        to catch.

            door_calls    [{day, allowed, denied, errored, oversize, ok, unknown}]
            door_effects  [{day, read, write}]           allowed calls only
            identity      [{day, verified, asserted, none}]
            door_latency  [{day, median_ms, p95_ms}]     allowed, non-null durations
            door_bytes    [{day, bytes, p95_bytes}]      allowed, non-null sizes
            callers       [{principal_kind, principal_id, owner, calls, denied, writes,
                           tools, last_seen}]            window totals, not a series
            door_tools    [{tool, effect, calls, denied}] window totals
            door_agents   [{agent, calls, denied, tools}] window totals, capped
            acting_for    [{acting_for, identity_source, calls}]  capped
            refusal_reasons [{reason, count}]            capped
            tool_latency  [{tool, calls, median_ms, p95_ms}]  capped
            hourly        [{weekday, hour, calls}]       0=Monday, UTC
            refusals      [{day, policy, ceiling, door_spend, run_budget, access}]
            admin_actions [{day, family, count}]

        ## The four series step 084 removed, and the one band it kept

        `run_tools` (with its count and tail), `runs`, `run_latency` and `schedules` were
        returned here until 084 and **discarded by `GET /admin/overview` on every page
        load**, which is how they survived 078: the route stopped reading them in 041, so
        deleting the runtime made them empty rather than broken. **Measured: nineteen
        statements became fifteen here and six became five in `overview_totals`**, and
        four of those five read `runs` or `schedules` — tables nothing in this tree
        writes. `docs/PREMISE.md`: *anything measuring `runs` is measuring nothing.*

        **`refusals.run_budget` is the deliberate exception and stays.** It reads `audit`,
        never `runs`, and an upgraded deployment's `audit` holds refusals a pre-078 tree
        wrote. Dropping the band would silently re-file those as `policy` — see
        `BUDGET_REFUSAL_MARKER`, which now has a reader in this tree and no writer, and
        says so at its definition.

        And, beside every capped list, the two facts that make the cap honest:

            caller_count  int          every distinct caller, not `len(callers)`
            caller_tail   {n, calls, denied}
            tool_count / tool_tail,
            agent_count / agent_tail, acting_for_count / acting_for_tail,
            refusal_reason_count / refusal_reason_tail

        ## The tail, step 066, and why a cap needs two numbers rather than one

        `caller_count` has existed since 041 because *"a tile reading `len(callers)` would
        report the cap as the answer"*. A walkthrough on 2026-08-31 found the other half
        of that defect: the count and the list sat on one screen, disagreed by design, and
        **neither said so** — with eighteen tools and a `LEADERBOARD` of fifteen, a tool
        that had just been called was absent from the page with nothing admitting a cut.

        So every capped list now also returns what it left out: `{n, calls, denied}` for
        the rows below the cap. `n` makes "top 15 of 18" sayable and `calls` makes the
        remainder's size sayable, which is the difference between a truncation a reader
        can reason about and one they cannot see.

        **Both come from the same statement as the list**, never by subtracting the list
        from a second query's total. Two scans of one window can straddle a write, and a
        tail computed against a different scan can be negative — which is the one arithmetic
        a reader would definitely notice.

        The cap itself is unchanged. Fifteen bars is the right number of bars; fifteen bars
        that do not say they are fifteen of eighteen was the defect.

        ## `bucket`, step 066 — the hour, and the one window that uses it

        `"day"` or `"hour"`. Day for every window this route offers but one; hour for the
        24-hour window, which exists because a day's live traffic drawn against a backdated
        month is an eleven-pixel sliver, and no rescaling of a thirty-day chart fixes that.

        The bucket changes the **grouping and the label** and nothing else: keys stay named
        `day`, and an hour renders as `YYYY-MM-DDTHH` — sortable, unambiguous, and told
        apart from a date by its length. Renaming the key on seven series to say `bucket`
        would cost every reader of this shape to buy a better noun; the route carries the
        flag instead.

        Buckets are UTC either way, matching `door.budget_window()`. A reader's local
        midnight is not this system's, and the page and the ceiling it draws must not
        disagree about which day is today.

        The window-total series — the leaderboards, `hourly`, `schedules` — do not bucket
        at all, and are unaffected.

        `hourly` is weekday x hour-of-day **across the whole window**, not a series: it
        answers *when is the door busy*, which is a question about the shape of a week
        rather than about any particular Tuesday. `weekday` is 0=Monday, ISO's numbering
        minus one, because Postgres' `dow` is 0=Sunday and the fake must not be the one
        that decides.

        ## What separates door traffic from a run, and why it is a prefix

        `run_id LIKE 'door-%'` (`DOOR_CALL_ID_PREFIX`). There is deliberately no `source`
        column — `door_call_records` refused one as *"a second way to say one thing"* —
        and this method inherits both the decision and its cost. Its cost here is
        different from that reader's, and worth stating because it is this method's one
        open performance question: the page read is a backward index walk that stops at a
        page, so *sparse* door traffic in a large log is its slow case; this is a forward
        scan over `ts`-bounded partitions, so **total** log volume is the cost driver
        regardless of how much of it came through the door. Migration 030's monthly
        partitioning bounds it; the fix if it bites is the partial index
        `(tenant_id, ts) WHERE run_id LIKE 'door-%'` — a partial index, not a column, on
        that same docstring's reasoning.

        ## The two refusal kinds recovered from sentences

        `refusals.ceiling` and `refusals.run_budget` are `decision='deny'` rows matched
        on `door.CEILING_REFUSAL_MARKER` and `core.limits.BUDGET_REFUSAL_MARKER`. Neither
        is a distinct row kind — a budget denial writes the same record a policy denial
        writes, which 033b obtained on purpose — so the sentence is the only evidence
        left. Both constants carry the argument at their definitions; what matters here
        is that a row matching neither is `policy`, so a **reworded** refusal silently
        re-files itself as one and the graph over-reports the broker. One contract test
        drives the real `TokenBudget` rather than writing a row by hand, which is what
        makes a rewording of *that* marker break something.

        **The `run_budget` half can no longer be driven.** Step 084 deleted
        `core.limits.Budget`, its only writer, so nothing in this tree produces such a
        refusal and its test builds the sentence from the constant instead. The band is
        kept because the *rows* are: an upgraded deployment's `audit` holds refusals a
        pre-078 tree wrote, and dropping the band would re-file those as `policy` — the
        exact silent wrong number this paragraph is about.

        `access` counts `access_denials` rows, which are a genuinely different table:
        refusals that never reached a broker at all.
        """

    # --- identity providers -----------------------------------------------------
    #
    # Two methods here do NOT take a tenant, and that is the point of them rather than
    # an oversight: they are how a tenant is *determined*. Everything else in this
    # interface is handed a tenant by something that already knows it; the access layer
    # has only a token, and these are the lookups that turn one into a customer.
    #
    # They are the only two, and they are both keyed on an issuer — a value the
    # platform registered, not one a caller supplies freely.

    def save_tenant_idp(self, tenant_id: str, idp: dict) -> None:
        """Register an identity provider for a tenant. Insert or update.

        `idp` carries `issuer`, `jwks_uri`, `audience`, and optionally
        `discriminator_claim` / `discriminator_value`, `email_claim`,
        `allowed_domains`, `enabled`.

        **Refuses anything that would make a token ambiguous**, which is the whole job
        of this method. Three shapes, each raising `IssuerConflictError`:

        - The row has no discriminator and another row already uses that issuer. A row
          without one claims the entire issuer; it cannot coexist with anything.
        - The row has a discriminator and an existing row for that issuer has none —
          the same rule from the other direction.
        - The exact key already belongs to a **different tenant**. Without this,
          registering `https://acme.okta.com` would hand you Acme's users.

        Only the first two are expressible as constraints in neither implementation,
        so they are checked here and asserted by the contract suite. The third is the
        one that would be a takeover rather than a mistake.
        """

    def find_tenant_idps(self, issuer: str) -> list[dict]:
        """Every registered provider for this issuer, ordered by discriminator value.

        **No tenant argument, deliberately.** This is the lookup that produces one.

        Returns a list rather than a row because an issuer is not always unique to a
        customer: Google Workspace shares `https://accounts.google.com` across every
        organisation on it, distinguished by an `hd` claim. Okta and Entra issue one
        issuer per customer and will return exactly one row here.

        Ordered so a caller iterating candidates behaves identically against both
        implementations.
        """

    def list_tenant_idps(self, tenant_id: str) -> list[dict]:
        """This tenant's providers, ordered by issuer. The operator's view."""

    def delete_tenant_idp(
        self, tenant_id: str, issuer: str, discriminator_value: str | None = None
    ) -> None:
        """Idempotent. Scoped by tenant, so one customer cannot unregister another's."""

    # --- users ------------------------------------------------------------------

    def create_user(
        self, tenant_id: str, user: dict, *, actor: str | None = None
    ) -> None:
        """Record somebody their identity provider vouched for — or, since 071,
        somebody their directory says is coming.

        `user` carries `id`, `issuer`, and optionally `subject`, `external_id`,
        `email`, `display_name`, `status`.

        `id` is ours and opaque — it becomes `Principal.id` and lands in every audit
        record, so it is never derived from an email. Identity is `(issuer, subject)`,
        which is unique globally: a subject cannot belong to two customers, because the
        issuer already decided which customer it speaks for.

        **`subject` may be None**, migration 052: a row a SCIM push created describes a
        person who has not signed in yet, so the subject is not known. Such a row is
        found by `find_provisioned_user` and adopted by `adopt_user_subject` at the
        first sign-in; `find_user` never returns it. `external_id` is the directory's
        own identifier for the person, unique per `(tenant, issuer)`, and it is not the
        subject — see the migration for why the two cannot be the same column.

        **`actor` decides whether a record is written.** The JIT sign-in path passes
        none, as it always has: a person signing in is not an administrative act, and a
        record per first login would be a request log. A push *is* an administrative
        act — the directory creating a person in this tenant — and passes the SCIM
        principal, which writes `user.create` in the same transaction.
        """

    def find_user(self, issuer: str, subject: str | None) -> dict | None:
        """The person this token is about, or None.

        **No tenant argument** — this is the second lookup that produces one. The
        returned row carries `tenant_id`.

        Keyed on the pair because a `sub` is unique within an issuer and meaningless
        across them; two providers can and do issue the same string.

        **Never matches a null subject, and `''` counts as null.** Since migration 052 a
        provisioned row has no subject, and a token whose subject claim is missing or
        blank must be *nobody* rather than *the first person the directory mentioned*.
        Both stores return None before looking, so the answer does not depend on how a
        driver renders `= NULL`.
        """

    def find_provisioned_user(
        self, tenant_id: str, issuer: str, email: str
    ) -> dict | None:
        """A row a directory push created that nobody has yet been, or None.

        The one place this schema matches a person by email, and it is bounded four
        ways on purpose: same tenant, same issuer, **`subject IS NULL`**, and the
        address compared is the one the same directory vouched for in a token it
        signed. A row that has a subject is never returned by this, whatever its
        email says — authentication still keys on `(issuer, subject)`, and 008's
        refusal to look anybody up by address is kept where it was made.

        Compared case-insensitively, both sides stripped, on `find_user_by_email`'s
        rule. Two provisioned rows sharing an address at one issuer — which the
        directory cannot produce, since `userName` is unique there — resolve to the
        earliest `created_at`, then the lowest `id`, so the choice is stated rather
        than arbitrary.
        """

    def adopt_user_subject(
        self, tenant_id: str, user_id: str, subject: str, *, actor: str
    ) -> bool:
        """Give a provisioned row its subject, once. True iff this call did it.

        A compare-and-set on `subject IS NULL`: the write lands only where no subject
        has been written, so two sign-ins racing for one row adopt it exactly once and
        the loser reads back what the winner wrote. Writes `user.adopt` in the same
        transaction when it applied, and nothing when it did not — a second call is a
        no-op that says so, on `revoke_api_token`'s rule.

        A blank subject is refused with `StorageError` before anything is read: a row
        adopted by `''` would be one `find_user` can never match, which is a person
        locked out with no sentence saying why.
        """

    def find_user_by_external_id(
        self, tenant_id: str, issuer: str, external_id: str
    ) -> dict | None:
        """One person by the directory's own identifier, or None.

        Keyed on `(tenant, issuer, external_id)`, the partial unique index migration
        052 adds. Tenant-filtered, unlike `find_user`: by the time a push asks this the
        tenant is already known from the token, and a read across one would be the
        missed-`WHERE` leak this interface documents as a known limit.
        """

    def update_user(
        self,
        tenant_id: str,
        user_id: str,
        *,
        actor: str,
        email: str | None = None,
        display_name: str | None = None,
        external_id: Any = _UNSET,
    ) -> dict | None:
        """Change what the directory says about somebody. The row after, or None.

        `email` and `display_name` are left alone when None — there is no reason to
        blank either, and a push that omits one is not asking for that. `external_id`
        is different: None is a real value meaning *unlinked*, so it takes a sentinel,
        and passing None explicitly clears it. That is `group.link`'s null-id
        arrangement one table over.

        Writes `user.update` with `{"fields": [...]}` — the names that actually
        changed, sorted — and **only when something changed**, so a push that restates
        what is already there leaves no record claiming otherwise. Values are never in
        the record, on `agent.update`'s rule.

        A second row in this tenant at this issuer already holding the `external_id`
        is refused with `StorageError` naming the id: the directory sent one object id
        for two people, and that is the directory's mistake to read, not ours to
        resolve by picking one.
        """

    def set_user_status(
        self,
        tenant_id: str,
        user_id: str,
        status: str,
        *,
        actor: str,
        detail: dict | None = None,
    ) -> dict | None:
        """`active` or `disabled`. The row after, or None if there was none.

        The only thing that can cut somebody off immediately. There is no token
        introspection, so without this, revocation is only as fast as token expiry —
        and since 071 there *is* a directory push, and this is what it calls.

        Writes `user.disable` or `user.enable` — the action is the new status — in the
        same transaction, **only when the status actually changed**. Disabling somebody
        who is already disabled is a push restating what it already said, and a record
        for it would make the log say the person was cut off twice. `detail` is the
        caller's to fill: the seam names what caused the deprovision, and this method
        does not know.
        """

    def list_users(self, tenant_id: str) -> list[dict]:
        """This tenant's people, ordered by id."""

    def get_user(self, tenant_id: str, user_id: str) -> dict | None:
        """One person by **our** opaque id, or None. A primary-key read.

        The counterpart to `find_user`, which is keyed on `(issuer, subject)` because that
        is what a token carries. This is keyed on the id every row in this schema names a
        person by — `runs.principal_id`, `audit.principal_id`, `agent_grants.grantee_id`
        — and it exists because `GET /me` has a principal and needs the row behind it.

        Tenant-filtered, unlike `find_user`. `find_user` is how a tenant is *determined*;
        by the time anything asks this, the tenant is already known and reading across one
        would be the missed-`WHERE` leak this interface documents as a known limit.
        """

    def record_user_login(self, user_id: str, email: str, display_name: str) -> None:
        """Refresh what the provider says about somebody, and stamp `last_seen_at`.

        Email and display name are the provider's to change and ours to reflect. They
        are never used to look anyone up — see `find_user`.
        """

    # --- directory-backed membership --------------------------------------------
    #
    # Migration 043, step 033e. Two methods that exist so `access/directory.py` can
    # do its work at most once per claim set, on a path that runs on every authenticated
    # request. None of them holds an access answer: what a person may run is still read
    # live from membership rows in one statement, and these say only *what has already
    # been reconciled, and from how new a token*.

    def record_directory_sync(
        self,
        tenant_id: str,
        user_id: str,
        digest: str,
        synced_at: datetime | None,
        *,
        expect: str | None = None,
    ) -> None:
        """Mark this claim set reconciled for this person, from a token minted then.

        **Clearing** a marker is not a method here, deliberately: it is never a thing a
        caller decides, only a thing the writes that invalidate it do inside their own
        transaction (`create_group`, `set_group_external_id`, `save_tenant_idp`). An
        interface method with no caller is a surface somebody later mistakes for a
        supported way to do this by hand — see the two 033a caught.

        Written **only after a reconciliation fully succeeded**, so a partial failure is
        retried at the next request rather than remembered as done. `synced_at` is the
        token's `iat` and may be None for a provider that omits it — which means *no
        ordering information*, not *the beginning of time*.

        **A compare-and-set on `expect`**, which is the digest the caller read before it
        began: the write lands only if nothing has changed the marker since. An admin
        linking a group *while* a reconciliation is in flight clears the markers, and
        without this check the in-flight request would put one straight back — computed
        against the group set as it stood before the link, and never revisited, because
        the digest covers the claim and the claim may never change again. Losing this
        race costs one repeated reconciliation; winning it wrongly costs a person their
        access indefinitely.
        """

    def directory_groups(self, tenant_id: str, user_id: str) -> list[dict]:
        """This tenant's directory-backed groups, and whether this person is in each.

        `[{"group_id", "external_id", "member"}]`, ordered by `group_id`, covering
        exactly the groups whose `external_id` is not NULL — a group an admin made by
        hand is not the directory's to change and never appears here.

        **One statement**, because this runs inside authentication. The membership half
        is a LEFT JOIN rather than a second query, for the reason `agent_grant_role`
        inlines `_VIA_GROUP`: the round trip is the thing being conserved. It asks only
        about `principal_kind = 'user'` — reconciliation writes nobody else's rows, which
        is what keeps a directory-backed group's `system` and `machine` members the
        admin's business and the two sources unable to fight.
        """

    # --- api tokens -------------------------------------------------------------
    #
    # Migration 031. A machine caller's credential: a row whose id becomes
    # `Principal.id` for a `machine` principal, and whose `secret_hash` is what a
    # presented token is compared against.
    #
    # **This store never sees a token's plaintext and never produces one.** Minting
    # happens in `access/tokens.py`, which generates the secret, hashes it, and passes
    # the hash here — the same division `core/crypto.py` has with `connections`, for the
    # same reason: a layer that cannot see a secret cannot log one.

    def create_api_token(self, tenant_id: str, token: dict, *, actor: str) -> dict:
        """Mint. `token` carries `id`, `name`, `owner_id`, `secret_hash`, `expires_at`.

        Refuses a duplicate name in the tenant with `ValueRefused`, because that is a
        caller error rather than a broken store: `--list-tokens` is read by somebody
        deciding what to revoke, and two rows called `ci` make that a coin toss.

        Writes a `token.mint` record in the same transaction, on migration 022's rule.
        The record names the token, its owner and its expiry — never the secret, which
        this method is not given in the first place.
        """

    def find_api_token(self, token_id: str) -> dict | None:
        """The row a presented token is about, or None. **No tenant argument.**

        The third lookup that *produces* a tenant rather than taking one, joining
        `find_user` and `claim_run` — a caller holding only a token string has no tenant
        to pass, because the tenant is what is being discovered. The returned row carries
        `tenant_id`.

        **The only method that returns `secret_hash`**, on `find_connection`'s
        discipline: everything else projects it away through `API_TOKEN_PUBLIC_FIELDS`
        rather than each caller remembering not to look.

        Returns revoked and expired rows. Deciding what to do about them is
        `access/tokens.py`'s, which has to tell them apart to refuse them — and a store
        that hid them would make `--list-tokens` unable to show what it must.
        """

    def list_api_tokens(self, tenant_id: str, *, owner_id: str = "") -> list[dict]:
        """This tenant's tokens, ordered by name, revoked ones included.

        Projected through `API_TOKEN_PUBLIC_FIELDS`, so no caller of this can leak a
        hash. Revoked rows are listed because the question this answers is "what exists
        and what happened to it" — a revoked row that vanished would look like a token
        somebody deleted, and this schema has no delete.

        `owner_id` narrows to one person's tokens; empty means everyone's, on
        `list_schedules(agent_name=…)`'s precedent. 022b's `GET /me/tokens` is the
        caller — a person picking among the tokens they may schedule — and the filter
        is here rather than in the route because a route that fetched every token and
        discarded most of them would be one refactor away from forgetting to discard.
        """

    def revoke_api_token(
        self, tenant_id: str, token_id: str, *, actor: str
    ) -> dict | None:
        """Stamp `revoked_at`/`revoked_by`. Returns the row, or None if there was none.

        **Never a DELETE.** The row is the only place a `machine:m_...` string in an
        audit record years old resolves to a name and an owner, which is the opposite of
        `platform_roles`' argument for its own table: a role is proved by the log that
        recorded granting it, and a token id is a *subject* in records that outlive it.

        Idempotent: re-revoking returns the row and writes no second record, matching
        `revoke_platform_role`'s treatment of a row that was not there.
        """

    def touch_api_token(self, token_id: str) -> None:
        """Stamp `last_used_at`. Best-effort, on every resolution.

        The same per-request write `record_user_login` has always paid for people, and
        it answers the one question an offboarding review asks that nothing else can:
        is this credential still in use?
        """

    # --- scim tokens -------------------------------------------------------------
    #
    # Migration 052, step 071. The credential a customer's directory presents when it
    # pushes a person in or out. `api_tokens`' shape, for `api_tokens`' reasons: the
    # store never sees the plaintext, `secret_hash` leaves through exactly one door, and
    # revocation is a stamp rather than a delete because `system:scim:<id>` in a record
    # years old has to resolve to a name and a minter.
    #
    # What is different is the binding. A SCIM token is bound to a tenant **and an
    # issuer**, because a provisioned row needs an issuer for adoption to have a key and
    # a tenant may register more than one. Minting refuses an issuer the tenant has not
    # registered; resolving, in `access/scim/tokens.py`, refuses a token whose issuer row
    # has since gone. Same sentence at both ends.

    def mint_scim_token(self, tenant_id: str, row: dict, *, actor: str) -> dict:
        """Mint. `row` carries `id`, `issuer`, `name`, `secret_hash`, `created_by`.

        Refuses a duplicate id with `StorageError` — the id is minted rather than
        chosen, so a collision is the generator's fault and nothing a caller can act on.
        Refuses an issuer this tenant has not registered with `ValueRefused`, because
        that one *is* the caller's: `--mint-scim-token --idp` named a provider that is
        not theirs, and a token bound to it could provision rows nobody could ever
        adopt.

        Writes `scim.token.mint` in the same transaction, targeting the token. The
        record names the issuer and the name — never the secret, which this method is
        not given.
        """

    def find_scim_token(self, token_id: str) -> dict | None:
        """The row a presented credential is about, or None. **No tenant argument.**

        The fourth lookup that produces a tenant rather than taking one, after
        `find_user`, `claim_run` and `find_api_token`, for the same reason: a caller
        holding a credential string has no tenant to pass, because the tenant is what
        is being discovered.

        **The only method that returns `secret_hash`**, on `find_api_token`'s
        discipline. Returns revoked rows; deciding what to do about one is the
        resolver's, which needs to tell *revoked* from *unknown* to say so.
        """

    def list_scim_tokens(self, tenant_id: str) -> list[dict]:
        """This tenant's SCIM tokens, revoked ones included, oldest first then by id.

        Projected through `SCIM_TOKEN_PUBLIC_FIELDS`, so nothing that renders this
        list can carry a hash past a caller who was not thinking about it. Ordered by
        creation rather than name because the question is *what has been minted and
        what happened to it*, and a token minted to replace another reads better below
        the one it replaced.
        """

    def revoke_scim_token(
        self, tenant_id: str, token_id: str, *, actor: str
    ) -> dict | None:
        """Stamp `revoked_at`/`revoked_by`. The row, or None if there was none.

        Never a DELETE, and idempotent: a second revoke returns the row and writes no
        second record. `revoke_api_token`'s contract, held to the letter, because the
        same seam in `cli.py` will be reading both.
        """

    def touch_scim_token(self, token_id: str) -> None:
        """Stamp `last_used_at`. Best-effort, on every resolution, no record."""

    def tenant_has_live_scim_token(self, tenant_id: str, issuer: str) -> bool:
        """Whether a directory currently owns this issuer's membership.

        `directory.reconcile` asks this after its digest short-circuit and does nothing
        for an issuer that answers True — the push is the fresher authority, and two
        writers with one seam and different opinions oscillate (071, decision 5). One
        indexed read per *changed* claim set, and revoking the token turns the pull back
        on at the next sign-in.
        """

    # --- the MCP door's per-token budget ------------------------------------------
    #
    # Migration 040. What a machine token has spent through `/mcp` in one window.
    #
    # **The only budget in this system that is a row rather than a counter on an
    # object**, and the reason is decision 9 of plan 033: a tool-mode door call is not a
    # run, so nothing in the process outlives a request to hold its count — and the door
    # exists to sit in front of somebody's production agents, which means the API has to
    # be able to run replicated. N processes each holding an in-memory copy of one
    # ceiling is N times that ceiling wearing the wrong label.
    #
    # This layer stores a counter keyed by a window and has no opinion about how long a
    # window is. "The window is the UTC day" is policy and lives in `carnet/door.py`,
    # which is also what computes the date — so the two stores cannot disagree by
    # reading two clocks.

    def spend_mcp_call(
        self, tenant_id: str, subject: str, window_start, *, ceiling: int
    ) -> int | None:
        """Consume one door call against this subject's window. **Atomic.**

        Returns the new count when the call is admitted, and **None when the ceiling is
        already met** — no row is written in that case, so a refusal costs nothing and
        cannot push a caller further past the line.

        **`subject` is whose allowance this is, and the door decides it** (step 108,
        migration 054). For a service token it is the token's id, as it was from 040: a
        CI bot with three tokens for three pipelines was given three allowances on
        purpose. For a *personal* token it is the **owner's user id**, so an engineer's
        laptop and desktop draw on one allowance and *a daily ceiling per engineer* means
        what it says. `door.budget_subject` is the one place that rule is spelled; this
        layer stores whatever string it is handed and joins it to nothing — migration 054
        dropped the foreign key to `api_tokens` for exactly that reason.

        One statement, never read-then-write: two replicas racing at `ceiling - 1` must
        produce one admission and one refusal, and a check followed by an increment
        produces two admissions on any interleaving. This is the same property
        `start_run` has for the queue, at a different address.

        `ceiling` must be positive. There is deliberately **no** "unlimited" value here:
        a deployment that has turned the dial off should not be writing rows nobody will
        read, so `door.py` skips this call entirely rather than passing a sentinel — and
        a sentinel this method had to interpret would be a branch that only the caller's
        absence of care could reach.

        `window_start` is a `date`. Rows for past windows are left alone: they are a few
        dozen bytes each and they are the only record of what a credential has been
        doing, which is what an offboarding review would want.
        """

    def mcp_calls_spent(self, tenant_id: str, subject: str, window_start) -> int:
        """What this subject has already spent in this window. 0 when there is no row.

        **Never on the call path** — `spend_mcp_call` returns the new count, so the door
        needs no second query to know how much is left. What reads this today is the
        suite, and the property it exists to make assertable is the one a returned count
        cannot show: that a *refused* call wrote nothing, and that a denial upstream of
        the budget never reached it. A ceiling you can only observe by spending against
        it is a ceiling whose off-by-one nobody can test.

        Written down as part of the interface rather than reached around in tests,
        because a test that inspected a store's internals would pass against the fake
        and have nothing to say about Postgres — which is the whole reason this file
        exists.

        **Still the suite's, as of 035e** — the product's reader is the range method
        below, which answers the current window and its history in one read. Said here
        so *this* sentence is not read as a claim about the family.
        """

    def mcp_call_windows(
        self,
        tenant_id: str,
        subject: str,
        *,
        since: date,
        until: date,
    ) -> list[dict]:
        """This subject's windows between two dates, **inclusive**, oldest first.

        `subject` is `spend_mcp_call`'s: a token id, or an owner's user id for a personal
        token — and a page about a personal token that asked for the token's id would
        read an empty week, because nothing has been written under that key since 054.

        Step 035e, and the first read of this table with a caller outside the suite:
        `GET /me/tokens/{id}/budget` renders *why did this token stop working* on the
        token's own page. Until it, the ceiling's refusal sentence was seen only by the
        caller holding the credential — which is never the person who comes to a browser
        asking why the nightly job stopped at three.

        `[{"window_start": "2026-08-26", "calls": 41}, ...]`, and `window_start` is an
        **ISO date string** in both stores rather than a `date`: the coercion every log
        reader here applies, for its reason — the fake and Postgres must return the same
        thing or the contract suite is asserting against two shapes.

        **Sparse. Only windows that have a row.** A window a token spent nothing in has
        no row, and this reports the table rather than improving on it. Zero-filling
        belongs above storage and is done there (`routes_admin.my_token_budget`), on the
        rule `mcp_calls_spent` already states one method up — *0 when there is no row* —
        so the fill applies an existing documented semantic rather than inventing a fact.
        A store that filled gaps here would be a fake that is kinder than Postgres, which
        is the exact drift the contract suite exists to catch.

        **A separate method rather than an `until=` on `mcp_calls_spent`**, because the
        return type would otherwise change shape with the argument — `int` for one window
        and a list for several — and every reader would have to branch on it.

        **No index, and it was measured rather than assumed.** Migration 040 says the
        primary key `(tenant_id, subject, window_start)` *"is the whole access pattern"*,
        and a range on the third column under equalities on the first two is a prefix
        scan it already serves: at 2,000,000 rows all four predicates land in the
        `Index Cond` and a seven-day read touches five buffers in 0.023 ms. What would
        need a new index is the *cross-token* question — "who spent what today", keyed
        `(tenant_id, window_start)` — which migration 040 explicitly declined and which
        is a different question. See `DEFERRED.md`.

        **Ordered oldest-first**, which is `audit_records`', `denial_records`' and
        `door_call_records`' rule copied rather than rhymed with: two readers of two logs
        that disagreed about ordering would be two things to remember.

        Revoked tokens keep their windows, and this does not check. Revocation closes a
        door and deletes no evidence (migration 031's rule, which this table inherits by
        doing nothing) — and *what was that credential spending before I killed it* is
        exactly the question asked after a revocation rather than before one.
        """

    # --- schedules ----------------------------------------------------------------
    #
    # Migration 033. A machine caller with a clock: a row naming an agent, a task, an
    # `api_tokens` row to fire as, and the next instant it is due.
    #
    # **This layer owns no policy about firing.** It stores rows, answers "what is due",
    # and performs one compare-and-set. Whether a fire is permitted — the token live, the
    # owner live, the grant held, the previous run finished — is `schedules.py`'s, above
    # this, for the reason `load_agents` has no opinion about a valid grant.

    def create_schedule(self, tenant_id: str, schedule: dict, *, actor: str) -> dict:
        """Create one. `schedule` carries `SCHEDULE_FIELDS` minus the stamped ones.

        Refuses an unknown agent or an unknown token with `ValueRefused` — both are
        foreign keys in Postgres, and both are caller errors rather than broken stores.
        The token key is composite (`tenant_id, token_id`), so a schedule can never fire
        another customer's machine; see migration 033.

        Writes a `schedule.create` record in the same transaction, on migration 022's
        rule — **naming the cadence and never the task**, which is `AGENT_DETAIL_REDACTED`'s
        rule reaching a second column.
        """

    def update_schedule(
        self,
        tenant_id: str,
        schedule_id: str,
        changes: dict,
        *,
        actor: str,
        if_unchanged_since,
    ) -> dict | None:
        """Change part of a schedule, if nobody else has written it. Row, or None.

        `changes` carries any of `task`, `cadence`, `timezone`, `token_id` and
        `next_fire_at`, and nothing else. The caller has already decided which of them
        moved and has already recomputed the clock — see `schedules.update`, and
        `set_schedule_enabled`'s reason for the same split: the cadence vocabulary is
        `schedules.py`'s and this layer stays free of it.

        **`if_unchanged_since` is the compare-and-set and it is the whole method**, on
        `update_agent`'s reasoning at a second table: a read in the route followed by a
        write here has a window in which the other editor commits, which is precisely the
        lost update the timestamp exists to catch, arriving through the code meant to
        prevent it. There is no window inside a single UPDATE.

        None means the row is gone **or** somebody else got there first, exactly as
        `update_agent` does — the two are told apart by a second read above this layer,
        where it is a report rather than a window because the write did not happen either
        way.

        Writes `schedule.update` naming the **keys that moved and never their values**,
        `schedule.create`'s redaction rule at the same table.

        Refuses an unknown token with `ValueRefused` — the composite foreign key is still
        the second layer, and a caller error must never be a 503.
        """

    def runs_of_schedule(
        self,
        tenant_id: str,
        schedule_id: str,
        *,
        limit: int = 50,
    ) -> list[dict]:
        """The runs one schedule produced, **newest first**. `list_runs`' rows.

        **Derived rather than stored, and this is the method that makes the derivation
        answerable over HTTP.** Every fire's idempotency key is
        `sched:<schedule_id>:<due instant>`, so the linkage is a prefix match on a column
        that already exists and is already unique per tenant. 035k took that decision
        explicitly against a fire log: a fourth append-only table would be a second source
        of truth for a fact the first one already holds, and the day the two disagree —
        a log row with no run after a crash between two writes — the question has two
        answers and no tiebreak. `door_call_records` made the same call about the `door-`
        prefix, and 021 made it about `runs.agent_version`.

        **The filter is in the query, which is what this method is for.** Its predecessor
        (`schedules.runs_of`) fetched `limit * 10` rows and filtered in Python, so it
        answered *what did this schedule do lately* and could silently return fewer than
        `limit` rows that existed — a truncation that reads as *that is everything*.
        Here `limit` means `limit`.

        **What the derivation cannot see, and the reason its register row narrows rather
        than closes**: a refused or skipped fire submits no run, so it appears in no
        prefix match. `last_outcome` is still the whole surface for those, and it is one
        sentence deep.

        Still an unindexed scan, and priced rather than hidden: the fix when it bites is a
        partial index, which is where `door_call_records` left its own.
        """

    def get_schedule(self, tenant_id: str, schedule_id: str) -> dict | None:
        """One schedule, or None. `SCHEDULE_FIELDS`."""

    def list_schedules(
        self, tenant_id: str, *, agent_name: str = ""
    ) -> list[dict]:
        """This tenant's schedules, ordered by agent then id. `SCHEDULE_FIELDS`.

        `agent_name` narrows it to one agent, which is what a per-agent screen asks and
        what the CLI's listing uses when given one. Disabled schedules are included, on
        `list_api_tokens`' reasoning: the question is "what exists and what happened to
        it", and a row that vanished when somebody turned it off looks like a deletion.
        """

    def due_schedules(self, *, now=None, limit: int = 100, limit_to_tenant=None):
        """Every enabled schedule due at `now`, oldest due first. **No tenant argument.**

        Tenantless like `claim_run`, and for the same reason: a worker serves every
        tenant, and a method that takes one would need a caller that already knows which.
        `limit_to_tenant` is the same test-only escape hatch `claim_run` carries.

        **This claims nothing**, and that is a decision rather than an omission. Two
        workers reading this get the same rows and both fire; the fire is idempotent by
        `schedule_fire_key`, so one run exists, and `advance_schedule`'s compare-and-set
        means one of them advances the clock. The cost is duplicated work proportional to
        worker count, which is the honest trade for never *losing* a fire — a claim would
        mean a worker that dies between claiming and submitting has silently eaten one.
        """

    def advance_schedule(
        self,
        tenant_id: str,
        schedule_id: str,
        *,
        if_next_fire_at,
        next_fire_at,
        last_run_id: str = "",
        last_outcome: str = "",
        fired: bool = True,
    ) -> dict | None:
        """Move the clock on. Returns the row, or **None if somebody else moved it first**.

        `if_next_fire_at` is the compare-and-set, and it is 10d's `updated_at` device at
        a different address: the value must still be the one the caller read, or nothing
        moves. That is what makes a due schedule advance exactly once however many
        workers noticed it — and there is no window inside a single UPDATE.

        `fired` is false for a fire that submitted nothing (skipped, or refused). It
        decides whether `last_fired_at` is stamped, so "when did this last actually run"
        stays answerable next to "what happened last time", which is `last_outcome`.
        """

    def set_schedule_enabled(
        self, tenant_id: str, schedule_id: str, enabled: bool, *, next_fire_at, actor: str
    ) -> dict | None:
        """Turn one on or off. Returns the row, or None if there is none.

        `next_fire_at` is recomputed by the caller and passed in, because **re-enabling
        does not backfill**: a schedule switched off for a month and back on fires next
        at its next cadence instant, not once for every instant it missed. Passing it in
        rather than computing it here keeps this layer free of the cadence vocabulary,
        which is `schedules.py`'s.

        Writes `schedule.enable` / `schedule.disable`. Idempotent: setting the state it
        already holds returns the row and writes no record, on `revoke_api_token`'s rule
        that the log holds changes rather than attempts.
        """

    def delete_schedule(self, tenant_id: str, schedule_id: str, *, actor: str) -> bool:
        """Remove one. True if a row went. Writes `schedule.delete` only when one did.

        A real delete, unlike a token's revocation, because a schedule is standing
        configuration rather than a subject in old records: nothing in `runs` names a
        schedule, so no record is orphaned by this going. The runs it produced survive
        untouched, as every run does.
        """

    # --- event triggers ---------------------------------------------------------
    #
    # Migration 034. A schedule with the clock replaced by a door: a row naming an
    # agent, a task, an `api_tokens` row to fire as, and a sealed HMAC secret a
    # delivery must prove it holds.
    #
    # **This layer owns no policy about delivering.** It stores rows and stamps
    # outcomes; signature verification, the token's liveness, the grant and the rate
    # ceiling are `triggers.py`'s and `runs.submit`'s, above this, on the schedules
    # section's exact division.

    def create_trigger(self, tenant_id: str, trigger: dict, *, actor: str) -> dict:
        """Create one. `trigger` carries `TRIGGER_FIELDS` minus the stamped ones.

        The secret arrives **sealed** — `normalize_trigger` refuses anything else, and
        storage never sees a plaintext. Refuses an unknown agent or an unknown token
        with `ValueRefused`; the token key is composite, so a trigger can never fire
        another customer's machine (migration 034, inheriting 033's index).

        Writes a `trigger.create` record naming the agent, the trigger's name and the
        machine — **never the task and never any form of the secret**.
        """

    def get_trigger(self, tenant_id: str, trigger_id: str) -> dict | None:
        """One trigger, or None. `TRIGGER_FIELDS`."""

    def find_trigger(self, trigger_id: str) -> dict | None:
        """One trigger by id, **tenantless**. `find_api_token`'s shape, same reason:
        the door has no tenant until this row supplies one — a delivery arrives with a
        URL and a signature, and everything else is learned from what they prove."""

    def list_triggers(self, tenant_id: str, *, agent_name: str = "") -> list[dict]:
        """This tenant's triggers, ordered by agent then id. `TRIGGER_FIELDS`.

        Disabled triggers included, on `list_schedules`' reasoning: a row that vanished
        when somebody turned it off looks like a deletion, and there is no delete that
        leaves the URL answering.
        """

    def record_trigger_delivery(
        self, tenant_id: str, trigger_id: str, *, last_run_id: str, last_outcome: str
    ) -> None:
        """Stamp what a **verified** delivery did — fired or refused. Fire-and-forget.

        Last-writer-wins with no compare-and-set, unlike `advance_schedule`, because
        there is no clock to advance and nothing races toward a wrong state: every
        stamp is one delivery's true outcome and the newest is the one `--list-triggers`
        wants. Writes no administrative record — a delivery is not an administrative
        act (`ADMIN_ACTIONS`' schedules argument, verbatim). Callers only reach this
        after signature verification, so an unauthenticated flood writes nothing.
        """

    def rotate_trigger_secret(
        self,
        tenant_id: str,
        trigger_id: str,
        *,
        secret_sealed,
        secret_key_id: str,
        actor: str,
    ) -> dict | None:
        """Reseal one trigger under a new secret. Returns the row, or None if there is none.

        **The URL does not move**, which is the entire point of the verb: the address
        lives in somebody else's webhook configuration screen, so delete-and-recreate
        spends a retype in a system we do not own. That cost is what the register row
        priced and what this closes.

        Takes the sealed blob and its key id **already sealed**, on `create_trigger`'s
        rule and `core/crypto.py`'s division: a layer that cannot see a secret cannot log
        one, and storage receives ciphertext or nothing. The same `check_trigger` guard
        that refuses a `str` here still applies — a plaintext secret must never reach
        storage in any column.

        Writes `trigger.rotate`, which names the agent and the trigger and **carries
        nothing about either secret**, old or new.
        """

    def set_trigger_enabled(
        self, tenant_id: str, trigger_id: str, enabled: bool, *, actor: str
    ) -> dict | None:
        """Turn one on or off. Returns the row, or None if there is none.

        No `next_fire_at` to recompute — the sender owns the clock — so unlike
        `set_schedule_enabled` this takes nothing but the state. Idempotent the same
        way: setting the state it already holds returns the row and writes no record.
        """

    def delete_trigger(self, tenant_id: str, trigger_id: str, *, actor: str) -> bool:
        """Remove one. True if a row went. Writes `trigger.delete` only when one did.

        A real delete, on `delete_schedule`'s argument — with the one consequence that
        differs said out loud: the URL an outside system still holds starts answering
        the same 404 an unknown id gets, which is the door working, not broken.
        """

    # --- agent grants -----------------------------------------------------------
    #
    # "May this PERSON use this agent", which is a different question from "may this
    # AGENT do this thing" and is deliberately not asked in `core/permissions.py`.
    # Absence is denial; there is no wildcard and no public flag.
    #
    # ## Two flavours, and the parameter names are how you tell them apart
    #
    # Step 9a split these methods in a way that is invisible if they all keep saying
    # `principal_kind`:
    #
    #     grantee_kind / grantee_id       LITERAL. One row. Never resolves anything.
    #     principal_kind / principal_id   RESOLVING. Answers through the person's groups.
    #
    # Getting them backwards is silent in both directions — a resolving revoke that
    # reports success and removes nothing, or a literal check that misses somebody's
    # group access — so the distinction is in the signature rather than in a comment
    # somebody has to have read.

    def grant_agent(
        self,
        tenant_id: str,
        agent_name: str,
        grantee_kind: str,
        grantee_id: str,
        role: str = "user",
        granted_by: str = "",
        *,
        actor: str,
    ) -> None:
        """Idempotent. Re-granting updates the role, who granted it, and when.

        **`actor` and `granted_by` are not the same thing, and step 011 is where that
        stopped being a distinction without a difference.** `granted_by` is a *column*:
        free text, last-writer-wins, and migration 011 fills it with `'migration:011'`
        for every agent it adopted — a value that is not a principal and never can be.
        `actor` is who performed *this operation*, it goes into `admin_audit.actor_kind`,
        and that column carries a CHECK against `PRINCIPAL_KINDS`.
        The plan for this step had them as one parameter. They cannot be: the choice was
        between widening the actor CHECK until a group could appear in it, and narrowing
        `granted_by` until the rows migration 011 already wrote became illegal to write.
        Every caller passes the same string to both today, and nothing says they must.

        Granting `owner` where an agent already has one **raises**, rather than quietly
        moving ownership: an agent has exactly one owner, and a caller who meant to move
        it should say so. See `transfer_agent_ownership`.

        A `group` grantee must name a group that exists. There is no foreign key for it —
        `grantee_id` means a different table depending on the column beside it, and a
        foreign key cannot be conditional — so both stores check it and raise the same
        sentence. A grant naming a group nobody created is a row that grants nothing and
        looks exactly like access.
        """

    def revoke_agent(
        self,
        tenant_id: str,
        agent_name: str,
        grantee_kind: str,
        grantee_id: str,
        *,
        actor: str,
    ) -> None:
        """Idempotent: revoking a grant that does not exist is not an error.

        **`actor` is the parameter step 011 exists for.** `grant_agent` has carried
        `granted_by` since 009 and this had nothing, because an actor column lives on a
        row and a row being deleted has nowhere to put one. The record it writes —
        `grant.revoke`, carrying the role that was removed — is the only thing that will
        ever say who took Sam's access away.

        **Literal.** Removes one row and never resolves a group — taking somebody's
        inherited access away means removing them from the group or revoking the group's
        grant, and `access/grants.py` refuses rather than pretending otherwise.

        Revoking an owner is permitted and leaves the agent orphaned. Refusing here
        would make deleting a departed employee's access impossible without first
        inventing somewhere to put the agent, and an orphan is visible in
        `list_agent_grants` where a refusal would only be visible to whoever hit it.
        """

    def transfer_agent_ownership(
        self,
        tenant_id: str,
        agent_name: str,
        principal_kind: str,
        principal_id: str,
        granted_by: str = "",
        *,
        actor: str,
    ) -> None:
        """Move ownership, demoting the previous owner to `editor`.

        **The recipient is a principal, not a grantee**, and the parameter names say so.
        A group cannot be handed an agent — see `GROUP_ROLES` — so this is the one
        write to `agent_grants` that still validates against `PRINCIPAL_KINDS`.

        Atomic, because the two halves cannot both be true at once: the unique index
        permits one owner, so the old one must step down before the new one steps up,
        and a failure between those is an agent with no owner at all.

        Demotion rather than revocation is the Docs behaviour and the useful one — the
        person handing an agent over almost never means "and lock me out of it".
        """

    def agent_grant_role(
        self, tenant_id: str, agent_name: str, principal_kind: str, principal_id: str
    ) -> str | None:
        """This principal's **effective** role on this agent, or None if they have none.

        **Resolving, and one statement.** The highest of what they hold directly and what
        they hold through any group they are in. This runs before every run and behind
        every list view, so it is a single round trip by requirement rather than by
        preference — a membership list fetched into Python and intersected here would be
        two queries on the hot path, and a per-group loop would be N.

        Highest-wins rather than direct-overrides-inherited. The alternative reads as
        more precise and produces a trap: somebody already granted `user` individually
        silently does not gain what the rest of their team has, and the two people differ
        for a reason invisible in the grant list and in any UI built on it.

        Returns the role rather than answering "may they?" — what a level permits is
        policy, and policy lives in `access/grants.py`. This layer knows the set is
        closed and ordered and nothing else about what the words mean.
        """

    def direct_agent_grant_role(
        self, tenant_id: str, agent_name: str, grantee_kind: str, grantee_id: str
    ) -> str | None:
        """The role on **one grant row**, ignoring groups entirely.

        Exists so `unshare` can tell "this person has a grant of their own" from "this
        person's access comes from a group". Without the distinction, revoking somebody
        whose access is inherited deletes nothing and reports success, and the person
        who ran it stops looking — the same failure as reporting a cancel on a finished
        run, and prevented the same way.
        """

    def granted_agent_names(
        self, tenant_id: str, principal_kind: str, principal_id: str
    ) -> list[str]:
        """Which agents this principal may run, ordered by name. "What can I run?"

        **Resolving, and one statement**, for the reason `agent_grant_role` is: this is
        the list view's hot path, and a person in a group holding grants on fifty agents
        must not make it fifty queries.
        """

    def groups_granting_agent(
        self, tenant_id: str, agent_name: str, principal_kind: str, principal_id: str
    ) -> list[str]:
        """The groups through which this principal reaches this agent, ordered by id.

        Only for explaining a refusal and for `who_has_access`. Never on the run path —
        `agent_grant_role` already answers the question a run asks, and asking this as
        well would be a second round trip to produce a string nobody reads.
        """

    def list_agent_grants(self, tenant_id: str, agent_name: str) -> list[dict]:
        """The grant **rows** on this agent, ordered by grantee. Groups appear as rows.

        Deliberately not expanded. Membership expansion is `access/grants.py`'s job
        because "what is Sam's effective role" is a ladder comparison, and the ladder is
        policy. This returns what was written down.
        """

    # --- groups -------------------------------------------------------------------
    #
    # A group is a name and a set of principals. It is a thing you GRANT TO and never a
    # thing that acts — see `GRANTEE_KINDS`, and migration 017 for what that buys.
    #
    # Membership is rows here rather than claims in a token, and that is what keeps
    # "who has access to this agent?" a finite, complete answer. It is the test that
    # separates a group from the wildcards step 006 refused: a wildcard cannot be
    # enumerated after an incident and a group can. Step 9b resolves membership from a
    # customer's directory instead, and inherits the obligation to say plainly that its
    # answer has become a partial one.

    def create_group(
        self,
        tenant_id: str,
        group_id: str,
        name: str,
        description: str = "",
        external_id: str | None = None,
        created_by: str = "",
        *,
        actor: str,
    ) -> dict:
        """Create a group. Raises if the name is taken in this tenant.

        The name is unique per tenant because it is how a person names a group on the
        CLI, and two groups called "support" is a command whose meaning depends on
        insertion order. The **id** is what grants record, so a rename costs nothing.
        """

    def set_group_external_id(
        self, tenant_id: str, group_id: str, external_id: str | None, *, actor: str
    ) -> dict:
        """Link a group to a directory group, or unlink it. Returns the row.

        Step 033e, and the one write this table was missing. `external_id` has been
        settable since migration 017 and only at creation, which made *point the `eng`
        you already have at your directory* mean delete it and make a new one — and
        `delete_group` takes its grants with it. That is not a migration path.

        Writes `group.link` rather than a `group.update` that happens to differ in one
        field, on `connector.asserted_identity`'s argument: this is a security control
        changing state — who may now change who is in this group — and *who turned that
        on, and when* should be a row a reader finds without diffing anything. Unlinking
        writes the same action with a null id, because giving the group back to the admin
        is the same decision in the other direction.

        `None` unlinks, and unlinking removes **nobody**: the membership the group has
        stays, and the admin owns it again. Refuses a value another group in this tenant
        already holds — `UNIQUE (tenant_id, external_id)` — with a sentence about the
        *directory* id rather than about the name, which is the one thing this method's
        Postgres sibling used to get wrong (every unique violation was reported as a name
        collision, because until this method existed a second `external_id` was
        unreachable).
        """

    def rename_group(
        self, tenant_id: str, group_id: str, name: str, *, actor: str
    ) -> dict | None:
        """Change what a group is called. The row after, or None if there was none.

        Step 071. A directory renames a group with a PUT or PATCH on `displayName`,
        and until this there was no seam for it — `name` was settable at creation and
        nowhere after, so a rename meant delete and recreate, which takes the grants.
        The id is what every grant and membership row names, so nothing else moves.

        Refuses a blank name and a name another group in this tenant already holds —
        `UNIQUE (tenant_id, name)` — with a sentence naming the *other* group's id,
        because the reader is a push that must say which row collided. Writes
        `group.rename` with `from` and `to`, on `agent.rename`'s argument: the log
        holds the name as it stood at the time, and this row is the only place the two
        halves of a group's history meet. **Only when the name actually changed**; a
        push restating the current name leaves no record.
        """

    def get_group(self, tenant_id: str, group_id: str) -> dict | None:
        """One group by id, or None."""

    def find_group_by_name(self, tenant_id: str, name: str) -> dict | None:
        """One group by its name, or None. For the CLI, never for authorization."""

    def list_groups(self, tenant_id: str) -> list[dict]:
        """Every group in this tenant, ordered by name."""

    def delete_group(self, tenant_id: str, group_id: str, *, actor: str) -> bool:
        """Delete a group. Returns whether there was one. Idempotent.

        **Its grants and its membership go with it, in the database rather than here.**
        Membership cascades by foreign key; the grants go by the trigger migration 017
        installs, because a conditional foreign key does not exist. Cleanup code in
        Python would be a rule that holds only while every caller remembers it, and the
        caller that forgets leaves a row granting nothing and looking like access.
        """

    def add_group_member(
        self,
        tenant_id: str,
        group_id: str,
        principal_kind: str,
        principal_id: str,
        added_by: str = "",
        *,
        actor: str,
    ) -> None:
        """Put a principal in a group. Idempotent.

        **A group may not be a member of a group.** Refused by `check_principal_kind`,
        which already permits exactly `user` and `system` — so nesting is refused by a
        rule that predates this step, rather than by a new one plus cycle detection on
        a check that runs before every run.
        """

    def remove_group_member(
        self,
        tenant_id: str,
        group_id: str,
        principal_kind: str,
        principal_id: str,
        *,
        actor: str,
    ) -> bool:
        """Take a principal out of a group. Returns whether they were in it.

        Writes `group.member.remove` only when somebody was actually removed. This is
        the one removal in this file that takes access away on *every* agent at once,
        so a record naming who did it is worth more here than anywhere else.
        """

    def list_group_members(self, tenant_id: str, group_id: str) -> list[dict]:
        """Who is in this group, ordered by principal."""

    def groups_for_principal(
        self, tenant_id: str, principal_kind: str, principal_id: str
    ) -> list[str]:
        """The group ids this principal belongs to, ordered.

        Never called on the permission path. `agent_grant_role` resolves membership
        inside its own statement; fetching this first and passing it down would be the
        two round trips decision 7 exists to avoid.
        """

    # --- platform roles -----------------------------------------------------------
    #
    # Migration 026. Who may administer this **tenant** — as opposed to `agent_grants`,
    # which answers who may use one agent.
    #
    # **The two never meet, and that is the invariant this section exists to state.**
    # Nothing here is consulted by `agent_grant_role`, and `has_platform_role` consults
    # no grant. An admin with no grant on an agent gets the same 404 as a stranger. The
    # reason is 7b's: an `admin` that implied agent access would rebuild the operator who
    # holds everybody's credentials, which is the failure delegated credentials exist to
    # prevent.
    #
    # `system` principals hold no rows here and are administrators anyway — that rule
    # lives in `access/roles.require_admin`, one layer up, because it is a policy about
    # who the CLI is rather than a fact about the table. Storage answers only what is
    # written down.

    def grant_platform_role(
        self,
        tenant_id: str,
        principal_kind: str,
        principal_id: str,
        role: str,
        granted_by: str = "",
        *,
        actor: str,
    ) -> dict:
        """Give somebody a platform role. Returns the row. **Upsert.**

        Re-granting a role somebody already holds refreshes `granted_by` / `granted_at`
        **and records again** — `allow_host`'s argument verbatim: a second approval is a
        second decision, and the most recent yes is who an incident wants to talk to.

        No compare-and-set. One-bit state has no merge problem, so there is no lost
        narrowing to protect the way `update_agent`'s ETag protects a scope — last write
        wins, said out loud so nobody adds a precondition reflexively.

        A group is refused by `check_platform_role` and by the CHECK in migration 026.
        """

    def revoke_platform_role(
        self,
        tenant_id: str,
        principal_kind: str,
        principal_id: str,
        role: str,
        *,
        actor: str,
    ) -> bool:
        """Take a platform role away. Returns whether they had it. Idempotent.

        Writes `role.revoke` **only when a row was there to remove**, which is
        `delete_pending_grant`'s rule and `revoke_host`'s: the log records changes, not
        attempts.

        Revoking the **last** administrator is allowed, and deliberately has no guard.
        Lockout is impossible — the CLI is always an administrator — so a
        "cannot remove the last admin" rule would defend a failure that cannot occur, and
        would become wrong on the day role administration moves to HTTP, where it must be
        *re-decided* rather than inherited.
        """

    def list_platform_roles(self, tenant_id: str) -> list[dict]:
        """Every platform role row in this tenant, ordered by principal then role.

        **This does not list the administrators**, and the difference matters: `system`
        principals are administrators and hold no row. `--list-roles` says so in its own
        output rather than this method inventing rows that are not there.
        """

    def has_platform_role(
        self, tenant_id: str, principal_kind: str, principal_id: str, role: str
    ) -> bool:
        """Does this principal hold this role in this tenant?

        The one method on the request path, and it is a primary-key lookup. Filters on
        tenant like everything else here — an admin of tenant A holds nothing in tenant B,
        and the tenant comes off the principal rather than off a URL.
        """

    # --- pending grants ---------------------------------------------------------
    #
    # A grant addressed to an email nobody has logged in with yet. See migration 012 —
    # including why resolving an address here does not contradict `users`' rule that an
    # email is never used to look anybody up.

    def find_user_by_email(self, tenant_id: str, email: str) -> dict | None:
        """A user in this tenant with this address, or None.

        For **sharing**, never for authentication. Nobody is identified by this — the
        person still arrives with a token and is resolved by `(issuer, subject)`. This
        answers "is there already a principal to grant to?" and nothing else.

        Matched case-insensitively, because a person typing a colleague's address into a
        share box will not match its stored casing and being right about RFC 5321 would
        only make the feature not work.
        """

    def add_pending_grant(
        self,
        tenant_id: str,
        agent_name: str,
        email: str,
        role: str = "user",
        granted_by: str = "",
        *,
        actor: str,
    ) -> None:
        """Idempotent, keyed on the address. Re-sharing changes the level."""

    def claim_pending_grants(
        self, tenant_id: str, email: str, principal_kind: str, principal_id: str
    ) -> list[str]:
        """Turn every pending grant for this address into a real one. Returns the agent
        names claimed.

        Atomic per row and safe to lose: two of a person's very first requests arriving
        at once both try to claim, and the second must find nothing rather than fail.
        That is the same race `users.resolve` already survives, arriving one layer down.

        **Only a `user` may claim.** A pending grant is addressed to a person's email;
        a system principal has none and never arrives through a login, so claiming one
        as `system` is meaningless. The only caller passes `user` already — this refuses
        it here so a second caller cannot quietly make it mean something else. System
        principals are granted by id, which is what `grant_agent` is for.
        """

    def list_pending_grants(self, tenant_id: str, agent_name: str) -> list[dict]:
        """Addresses waiting on a first login, ordered by email."""

    def delete_pending_grant(
        self, tenant_id: str, agent_name: str, email: str, *, actor: str
    ) -> None:
        """Idempotent. Un-sharing before somebody has ever arrived.

        Writes `grant.pending.delete` only when a row was there to remove — otherwise
        `unshare_email`, which calls this on both branches, would record a cancellation
        every time somebody revoked an ordinary grant.
        """

    # --- connections ------------------------------------------------------------
    #
    # Delegated credentials: the caller's own account, encrypted, so two people running
    # one agent reach two different sets of data. This layer stores opaque bytes and
    # **never decrypts anything** — `core/crypto.py` is the only module that holds a
    # key, and keeping storage ignorant of it is what makes "where could a credential
    # leak from" a one-module answer rather than a search.
    #
    # Keyed by (tenant, principal, connector), which is also what the ciphertext is
    # bound to. A row copied between any of those three fails to decrypt rather than
    # working — the primary key stops two rows colliding and has no opinion about a
    # value moved between them.

    def save_connection(
        self,
        tenant_id: str,
        principal_kind: str,
        principal_id: str,
        connector_id: str,
        *,
        ciphertext: bytes,
        key_id: str,
        expires_at=None,
        account_label: str = "",
        credential_kind: str = STATIC_CREDENTIAL,
        refresh_expires_at=None,
        actor: str,
    ) -> None:
        """Insert or replace one person's credential for one connector.

        Replace rather than raise, because reconnecting an account is the normal way a
        rotated or expired token is fixed and refusing it would mean disconnecting
        first — a window in which the person has no credential at all.

        `expires_at` is nullable and the nullability is the point: never connected and
        connected-but-expired send a person to different places, and a single "no
        credential" answer would send them to the wrong one.

        **Clears `reconsent_reason` unconditionally.** Reconnecting is the fix for a
        connection whose upstream grant was revoked, so a replacement that left the old
        refusal standing would be a person doing exactly the right thing and being told
        it did not work.

        `actor` arrives in step 7b, on migration 011's precedent and for the reason
        `DEFERRED.md` named this method: *"a record that somebody connected an account is
        wanted and the ciphertext must never be near it"*. It is required and keyword-only
        like every other actor here — and this is the first one where the actor and the
        subject are routinely **the same person**, which is correct rather than redundant.
        A consent flow is something somebody does to themselves; `--connect-account` is
        something an operator does on their behalf, and the record is what tells the two
        apart afterwards.
        """

    def find_connection(
        self, tenant_id: str, principal_kind: str, principal_id: str, connector_id: str
    ) -> dict | None:
        """This principal's credential row for this connector, or None.

        The **only** method that returns `ciphertext`. Everything else in this section
        is metadata, so a caller that wants to list connections cannot accidentally
        acquire the sealed bytes on the way past.
        """

    def has_connection(
        self, tenant_id: str, principal_kind: str, principal_id: str, connector_id: str
    ) -> bool:
        """Whether a delegated credential exists, without returning it.

        Not merely a convenience over `find_connection`. The caller is
        `tools/mcp`, which needs to know that a per-user credential exists in order to
        refuse a connector that cannot carry one — and which has no business holding
        ciphertext to answer a yes/no question.
        """

    def list_connections(
        self,
        tenant_id: str,
        *,
        principal_kind: str | None = None,
        principal_id: str | None = None,
    ) -> list[dict]:
        """Connection metadata for this tenant, ordered by (principal, connector).

        **Without `ciphertext`.** This is the administrator's view — "who is connected,
        and as whom" — and the people who ask it are exactly the people who should not
        be handed sealed credentials in the reply. `key_id` is included, because "which
        rows still need re-encrypting after a rotation" is asked of this same view.
        """

    def delete_connection(
        self,
        tenant_id: str,
        principal_kind: str,
        principal_id: str,
        connector_id: str,
        *,
        actor: str,
        detail: dict | None = None,
    ) -> bool:
        """Idempotent: disconnecting an account that was never connected is not an error.

        Deletion rather than a status flag. A revoked row still holding live ciphertext
        is a worse artifact than no row — see migration 013.

        Returns whether a row went, and writes `connection.delete` **only when one did** —
        the rule `delete_pending_grant` and `delete_connector` already follow, because
        otherwise every idempotent retry records a disconnection that did not happen.

        `detail` is the caller's, and carries `revoked_upstream` for an OAuth connection:
        whether the provider was successfully told. That answer is only available one
        layer up, where the revocation endpoint is POSTed, and it is the half of decision
        12 that makes *"is that token still live at Atlassian"* answerable at all.
        """

    # --- OAuth: the credential a person gives themselves --------------------------
    #
    # Step 7b. Three tables' worth of methods, and they divide by lifetime rather than by
    # subject, which is the fastest way to keep them straight:
    #
    #   connector_oauth           configuration. Written once by an admin, read on every
    #                             consent and every refresh. Holds a client secret.
    #   pending_authorizations    one flow. Written at /connect, consumed at the callback,
    #                             gone. Holds a PKCE verifier.
    #   connections               the credential itself, and already existed — 7b only
    #                             adds a second way for a row to arrive and a conditional
    #                             update for keeping it fresh.
    #
    # **Nothing here decrypts anything**, the same containment the rest of this layer
    # keeps: `core/crypto.py` holds the only key, and storage moves opaque bytes.

    def set_connector_oauth(
        self,
        tenant_id: str,
        connector_id: str,
        *,
        authorize_endpoint: str,
        token_endpoint: str,
        revoke_endpoint: str = "",
        client_id: str,
        client_secret: bytes,
        key_id: str,
        scopes=(),
        authorize_params=None,
        scope_notes=None,
        actor: str,
    ) -> None:
        """Configure the OAuth application for a connector. Upsert, and safe to re-run.

        An upsert rather than a `create_connector`-style refusal, and the asymmetry is
        worth stating because 012 argued the other way. `create_connector` refuses a
        second registration because `save_connector` replaces a *vetted allowlist* —
        losing nine approved tools to a mistyped command. There is no allowlist here: the
        row is five fields an admin typed, re-running the command is how a rotated client
        secret is installed, and refusing would make secret rotation a delete-then-create
        with a window in which nobody can connect.

        Raises `NoSuchConnectorError` if the connector is not registered. Configuring a
        consent flow for a connector that does not exist configures nothing, and this is
        the same refusal `vet_tool` makes for the same reason.

        Writes `connector.oauth.configure`. The record carries the `client_id` (public by
        construction), the scopes and the token endpoint — **never the client secret**.

        `scope_notes` is migration 051: per-scope prose for the consent screen, checked
        against `scopes` by `normalize_scope_notes`. It is replaced wholesale on every
        call rather than merged, like `scopes` and `authorize_params` beside it — this row
        is what an admin last configured, not an accumulation of what they have ever
        configured, and a note surviving the scope it described is the misalignment the
        key-by-scope shape exists to make unrepresentable.
        """

    def get_connector_oauth(self, tenant_id: str, connector_id: str) -> dict | None:
        """The full OAuth application row **including the sealed client secret**, or None.

        The `find_connection` of this table: the only method that returns the ciphertext,
        so a caller that merely wants to describe the configuration cannot acquire the
        secret by asking the wrong question. Its callers are the two that genuinely need
        to authenticate to a token endpoint — the code exchange and the refresh.
        """

    def list_connector_oauth(self, tenant_id: str) -> list[dict]:
        """Every connector in this tenant that has a consent flow, **without the secret**.

        `OAUTH_APP_PUBLIC_FIELDS`, ordered by connector id. This is what the Connections
        page is built from: the third state on that screen — *"no consent flow yet, ask an
        administrator"* — is exactly a connector absent from this list.
        """

    def delete_connector_oauth(
        self, tenant_id: str, connector_id: str, *, actor: str
    ) -> bool:
        """Remove a connector's OAuth application. Returns whether one went.

        Does **not** touch `connections`. A credential somebody consented to give keeps
        working until its access token expires, and the honest consequence is that it can
        then no longer be refreshed — which surfaces as needing re-consent, and there is
        nothing left to consent with until an admin configures one again. Deleting the
        credentials instead would be migration 021's mistake: destroying evidence as a
        side effect of an administrative action about configuration.

        Writes `connector.oauth.remove`, only when a row was actually removed.
        """

    def update_connection_credential(
        self,
        tenant_id: str,
        principal_kind: str,
        principal_id: str,
        connector_id: str,
        *,
        ciphertext: bytes,
        key_id: str,
        expires_at,
        refresh_expires_at,
        account_label: str | None = None,
        if_updated_at,
    ) -> dict | None:
        """Replace a connection's sealed credential, **conditional on its version**.

        Returns the new metadata row, or **None when `if_updated_at` did not match** —
        the shape `update_agent`, `start_run` and `finish_run` all use, because a lost
        race is the ordinary form of concurrency here rather than an exception.

        This is decision 11's compare-and-set and it exists for a failure that is
        invisible in a single-threaded test and permanent in production. Most providers
        rotate refresh tokens: every refresh issues a new one and kills the old. Two runs
        for one person overlapping — the ordinary case, because `POST /runs` is a queue
        with a worker — both read the same refresh token, and a plain last-write-wins
        update stores whichever landed second. If that is the *older* exchange's result,
        the row now holds a refresh token the provider has already invalidated and the
        connection is broken forever with nothing anywhere saying why.

        A caller whose write does not land must **re-read the row and use the token that
        is now there**, never retry the exchange: the refresh token it holds is spent, and
        Atlassian treats reuse of a spent refresh token as a breach signal and revokes the
        whole grant. `access/oauth.py` is where that rule is written down.

        `account_label` is optional here and required-shaped in `save_connection`, which is
        the difference between connecting and refreshing: a refresh response usually
        carries no identity claim at all, and overwriting a verified label with `''`
        because the provider did not repeat it would lose the one thing on this row a
        person recognises. None means leave it alone.

        Clears `reconsent_reason`, for `save_connection`'s reason: a refresh that worked
        is the proof the grant is back.

        Writes **no** administrative record. A refresh is not an administrative act — it
        is the same credential, still the same consent, kept alive — and recording every
        one of them would put a row per run per connector into a table kept forever, in
        which the connections a person actually made would stop being findable.
        """

    def mark_connection_reconsent(
        self,
        tenant_id: str,
        principal_kind: str,
        principal_id: str,
        connector_id: str,
        *,
        reason: str,
    ) -> bool:
        """Record that this connection cannot be used until the person reconnects.

        Returns whether a row was there to mark. Unconditional — no version check —
        because a terminal `invalid_grant` is true whoever else is writing: the grant is
        gone at the provider, and a refresh racing this cannot have succeeded.

        The row is **kept, not deleted**, which is the decision. Deleting it would send
        `for_connector` down its "no row" branch and straight into the shared environment
        variable, so a person whose consent was revoked at Atlassian would silently start
        acting as the operator — the exact untruth 7a's three-outcome rule exists to
        prevent. A row with a reason on it fails loudly and says what to do.
        """

    def create_pending_authorization(
        self,
        state: str,
        tenant_id: str,
        *,
        principal_kind: str,
        principal_id: str,
        connector_id: str,
        code_verifier: bytes,
        key_id: str,
        redirect_uri: str,
        return_to: str = "",
    ) -> None:
        """Mint the row a `state` parameter is a handle on. See migration 024.

        Raises on a duplicate `state` rather than replacing. A collision on a 256-bit
        random value is not a thing that happens, so a duplicate means something is
        generating them badly — and quietly overwriting the row would hand one person's
        flow to another's callback, which is the single worst outcome this table has.
        """

    def consume_pending_authorization(self, state: str) -> dict | None:
        """Take the row for this `state` **and delete it, atomically**. None if there is none.

        One `DELETE ... RETURNING`, and the atomicity is the single-use guarantee rather
        than a detail of the implementation: a read-then-delete has a window in which two
        callbacks carrying the same `state` both find it, and both then exchange the same
        authorization code. A replayed `state` must find nothing.

        **Not scoped to a tenant, and it cannot be.** The callback is a top-level
        navigation with no bearer token, so there is no principal and therefore no tenant
        to scope by — the row is what supplies both. That is why `state` is the primary
        key of its own table and why it must be unguessable: it is a bearer token for one
        flow, and the only reason this is safe is that nothing but the row's own contents
        decides what the callback then does.
        """

    def sweep_pending_authorizations(self, *, older_than_seconds: int) -> int:
        """Delete abandoned consent flows. Returns how many went.

        Rows go on use, so this only ever collects the ones nobody came back from — a
        person who clicked Connect and closed the tab. It is the first thing in this
        system that wants a scheduler, which does not exist, so it rides on an existing
        entry point and is deliberately cheap enough to.
        """

    # --- the door as an OAuth resource server -------------------------------------
    #
    # Step 083, migration 053. Two tables that exist only *before* a token does: a
    # client that registered itself, and the code a person's consent produced. Rows in,
    # rows out — what PKCE is, what a redirect URI may look like and what a replayed
    # code means are `access/oauth_server.py`'s, and nothing here knows any of it.

    def create_oauth_client(self, client: dict) -> dict:
        """Register a client. `client` carries `id`, `client_name`, `redirect_uris`,
        `metadata`. **No tenant** — see migration 053. Raises `StorageError` on a
        duplicate id, which is a minting collision rather than anything a caller did."""

    def find_oauth_client(self, client_id: str) -> dict | None:
        """The row, or None. Tenantless, like `find_api_token`, and for the same reason:
        the caller holds an id and no tenant, because there is none on the row."""

    def touch_oauth_client(self, client_id: str) -> None:
        """Stamp `last_consented_at`. Called once per approval; it is what keeps the
        client out of `sweep_oauth_clients`' population."""

    def sweep_oauth_clients(self, *, unused_for_seconds: int) -> int:
        """Delete clients nobody has ever consented to, registered longer ago than the
        window. Returns how many went. A client with any approval ever is kept: its
        tokens name it and the person may re-consent."""

    def create_oauth_code(self, tenant_id: str, code: dict) -> None:
        """Write the row a consent produced. `code` carries `code_hash`, `client_id`,
        `owner_id`, `redirect_uri`, `code_challenge`, `resource`, `token_name`,
        `expires_at`. Raises on a duplicate hash rather than replacing — a collision on
        256 random bits means the generator is broken, and replacing would hand one
        person's consent to another's client."""

    def find_oauth_code(self, code_hash: str) -> dict | None:
        """The row, used or not, expired or not, or None. Tenantless: the token request
        carries no bearer, so the row is what supplies the tenant. Deciding what a used
        or expired row *means* is the access layer's — it needs a used one to find the
        token a replay revokes."""

    def consume_oauth_code(self, code_hash: str) -> bool:
        """Stamp `used_at` **if and only if it is NULL**, in one statement. True if this
        call was the one that did it. The compare-and-set is the single-use guarantee:
        two exchanges racing on one code cannot both mint."""

    def record_oauth_code_token(self, code_hash: str, token_id: str) -> None:
        """Remember which token the exchange minted, so a replayed code can revoke it."""

    def sweep_oauth_codes(self, *, older_than_seconds: int) -> int:
        """Delete codes whose expiry is further in the past than the window, used or
        not. Returns how many went. The window is what keeps a used row around long
        enough for a replay to be recognised as one."""

    # --- key rotation -------------------------------------------------------------
    #
    # Step 026. Four sealed columns exist — `connections.ciphertext`,
    # `connector_oauth.client_secret`, `triggers.secret_sealed`,
    # `pending_authorizations.code_verifier` — and each blob is AAD-bound to its own
    # row's identity, so a rotation is four table-specific sweeps rather than one loop
    # over a `key_id` column. Two shapes per table:
    #
    #   *_not_sealed_under(key_id)   the population: every row NOT sealed under the
    #                                given key, **tenantless** and blob included
    #   reseal_*(..., if_<blob>)     one row's blob replaced, compare-and-set on the
    #                                blob bytes themselves
    #
    # The fetches are tenantless on `find_trigger` and `claim_run`'s argument: a
    # rotation serves every customer or it is not a rotation. They are also the only
    # methods besides `find_*`/`get_connector_oauth` that return sealed bytes, and for
    # the same reason those do — the caller must read what it re-seals. Nothing here
    # decrypts anything; `core/crypto.py` still holds the only key, and `rotation.py`
    # is the one caller.
    #
    # **The compare-and-set token is the blob itself.** A fresh GCM nonce per seal means
    # any concurrent rewrite — a token refresh, a re-connect, another sweep — produces
    # different bytes, so `if_<blob>` is a version check every one of the four tables
    # already carries, including the two with no `updated_at`. Zero rows matched means
    # the row changed or vanished underneath the sweep, and both mean "leave it alone":
    # a concurrent writer sealed under the current key, so the row left the population
    # by the other door.
    #
    # No reseal writes an administrative record, on `update_connection_credential`'s
    # argument: a re-seal is the same plaintext under the same binding with a newer
    # key — no fact any reader reads has changed. The rotation's record is the CLI
    # printout in the operator's hands.

    def sealed_key_id_census(self) -> dict:
        """Which key every sealed row in the deployment names, counted. No blobs.

        `{table: {key_id: rows}}`, all four tables present, every tenant. **This is the
        done-when question in one query** — *no row names a retired key* — and it is a
        separate method from the fetches above precisely so that answering it does not
        drag every credential in the deployment through process memory a second time.
        Counting key ids needs `GROUP BY`, not ciphertext.
        """

    def connections_not_sealed_under(self, key_id: str) -> list[dict]:
        """Every connection not sealed under this key, across all tenants.

        Identity columns, `ciphertext` and `key_id`, ordered by identity. The blob is
        returned because the sweep must open it; the metadata view for humans stays
        `list_connections`, which withholds it.
        """

    def connector_oauth_not_sealed_under(self, key_id: str) -> list[dict]:
        """Every OAuth application not sealed under this key, across all tenants.

        `tenant_id`, `connector_id`, `client_secret`, `key_id`, ordered by identity.
        """

    def triggers_not_sealed_under(self, key_id: str) -> list[dict]:
        """Every trigger whose secret is not sealed under this key, across all tenants.

        `tenant_id`, `id`, `secret_sealed`, `secret_key_id`, ordered by identity.
        """

    def pending_authorizations_not_sealed_under(self, key_id: str) -> list[dict]:
        """Every pending consent flow not sealed under this key, across all tenants.

        `state`, `tenant_id`, `code_verifier`, `key_id`, `created_at`, ordered by
        identity. `created_at` rides along so the sweep can say how stale a flow is.
        """

    def reseal_connection(
        self,
        tenant_id: str,
        principal_kind: str,
        principal_id: str,
        connector_id: str,
        *,
        ciphertext: bytes,
        key_id: str,
        if_ciphertext: bytes,
    ) -> bool:
        """Replace one connection's sealed blob, conditional on the bytes read.

        Returns whether the write landed; False means the row changed or vanished, and
        the caller moves on. **Deliberately not `update_connection_credential`**: that
        method clears `reconsent_reason` (a false "the grant is back" signal) and bumps
        `updated_at` (the refresh machinery's compare-and-set token). A reseal touches
        the blob and the key id and nothing else, so rotation is invisible to every
        other reader and writer of this row.
        """

    def reseal_connector_oauth(
        self,
        tenant_id: str,
        connector_id: str,
        *,
        client_secret: bytes,
        key_id: str,
        if_client_secret: bytes,
    ) -> bool:
        """Replace one OAuth application's sealed client secret, conditional. See above."""

    def reseal_trigger_secret(
        self,
        tenant_id: str,
        trigger_id: str,
        *,
        secret_sealed: bytes,
        secret_key_id: str,
        if_secret_sealed: bytes,
    ) -> bool:
        """Replace one trigger's sealed secret, conditional. `updated_at` untouched.

        **Not `rotate_trigger_secret`, and the two must not be confused.** That one
        (035k) gives the trigger a *different secret* — the sender must be told, and the
        old one stops working. This one re-seals *the same secret* under a newer platform
        key: nothing the outside system holds changes, and nobody is told because nothing
        happened to them.

        **`updated_at` untouched, and that is load-bearing rather than incidental.** Since
        035k `TriggerDetail.updated_at` is what a reader uses to tell a rotated trigger
        from an untouched one — so a key sweep that moved it would report a secret change
        to every trigger in the deployment, on a night when nobody's secret changed.
        """

    def reseal_pending_authorization(
        self,
        state: str,
        *,
        code_verifier: bytes,
        key_id: str,
        if_code_verifier: bytes,
    ) -> bool:
        """Replace one pending flow's sealed verifier, conditional. Tenantless by state,
        `consume_pending_authorization`'s shape: the state is the row's whole address.
        A callback consuming the row mid-sweep deletes it, the condition matches
        nothing, and False is the honest answer."""

    def refresh_lock(
        self, tenant_id: str, principal_kind: str, principal_id: str, connector_id: str
    ):
        """A context manager holding an exclusive lock on one connection's refresh.

        Decision 11's second mechanism, and it answers a different half from the
        compare-and-set. The conditional update makes a lost update *impossible*; this
        makes the common case cost **one** token-endpoint call instead of N. Without it,
        eight concurrent runs make eight exchanges of which seven come back
        `invalid_grant` — correct under the compare-and-set, and eight times the load on a
        customer's identity provider for one useful result, with seven of them looking
        like a credential-stuffing attempt in the provider's own logs.

        A lock and not a lease: it is held for the length of one token-endpoint round trip
        inside one process, and a process that dies releases it because the transaction
        that held it is gone. In Postgres that is `pg_advisory_xact_lock`, which is exactly
        this shape and needs no table.

        Waiters do **not** then refresh. The contract is *acquire, re-read, and refresh
        only if the row is still stale* — the winner has already written a good token, and
        a waiter that refreshed anyway would spend the refresh token the winner just
        obtained and put the connection back into the state the lock was taken to avoid.
        """

    # --- runs -------------------------------------------------------------------
    #
    # A run as a row rather than as a grouping of audit records. See migration 015 for
    # why, including why this table is also the queue.
    #
    # The division of labour is the point: **this row is authoritative for the run, and
    # audit records stay authoritative for the calls it made.** Two sources answering
    # one question is the disagreement this codebase keeps refusing to build, so
    # `audit_query` keeps its per-call reporting and has no opinion about status.

    def enqueue_run(self, tenant_id: str, run: dict) -> tuple[dict, bool]:
        """Record a run before anything executes. Returns `(row, created)`.

        `run` carries `run_id`, `agent`, `principal_kind`, `principal_id`, `task`, and
        optionally `idempotency_key`, `status` and `parent_run_id`.

        **A run with a parent is a follow-up turn** (migration 027). The store derives
        `root_run_id` from the parent row itself — the parent's root, never the parent
        — because a caller-supplied root would be a second opinion about a fact the
        parent already holds. A parent absent from this tenant is refused with
        `ValueRefused`: the row it would reference either does not exist or belongs to
        another customer, and those two must stay indistinguishable. A parent whose
        one continuation slot is occupied (a live or `complete` child — see
        `LIVE_CHILD_STATUSES`) is refused with `FollowUpConflict`, decided by the
        `runs_one_live_child` index in Postgres and by the same predicate under the
        lock in memory, so two simultaneous follow-ups have no read-then-write window
        in either store.

        A run without a parent is its own root: `root_run_id = run_id`.

        **`created` is false when an idempotency key matched an existing run**, and the
        row returned is that existing run — not the one asked for. A caller has to know
        which happened, because the difference is whether it should now go and execute
        something. Returning it here rather than making the caller compare is what keeps
        the check and the insert atomic: this is one `ON CONFLICT DO NOTHING`, where a
        find-then-insert would let two concurrent retries both find nothing.

        An empty `idempotency_key` never matches anything, including another empty one.

        **`file_id` (step 028)** names a file already uploaded, or is ''. Stored as a
        plain column with no foreign key — `agent`'s rule, for `agent`'s reason: a run is
        history and must survive the deletion of what it referred to. Whether the caller
        may use that file is decided above storage by `runs.usable_file`, because the
        answer needs a principal and this tier has none.
        """

    def create_file(self, tenant_id: str, row: dict) -> dict:
        """Store one uploaded file. Returns its metadata — **never its content**.

        Step 028. `row` carries `id`, `owner_kind`, `owner_id`, `filename`,
        `media_type`, `content`, `sha256` and `byte_size`. The id is minted by the
        caller (`runs.new_file_id`) rather than here, matching `enqueue_run`.

        A duplicate id is a `StorageError` rather than a silent overwrite: at 128 bits a
        collision is not a thing that happens, so one means a caller reused an id, and
        overwriting would hand the second uploader's bytes to a run the first one
        started.
        """

    def get_file(self, tenant_id: str, file_id: str) -> dict | None:
        """One file's metadata — including its owner — or None. **Never the bytes.**

        Step 028. This is what the ownership check reads, what an API response carries,
        and what a run detail page shows. `byte_size` is stored rather than derived from
        the content precisely so this never touches the content column.

        Tenant-scoped like `get_run` and for the same reason: an id from another customer
        must be indistinguishable from one that does not exist. **Ownership within the
        tenant is not decided here** — that is `runs.usable_file`, above storage, beside
        the caller that has to phrase the refusal.
        """

    def file_content(self, tenant_id: str, file_id: str) -> bytes | None:
        """A file's bytes, or None. Step 028.

        **The only method in this protocol that reads file content, and it is separate
        from `get_file` for that reason alone.** A run list showing fifty filenames must
        not fetch fifty files; a worker about to hand a document to a model must fetch
        exactly one. Splitting them makes the expensive call something a caller asks for
        by name rather than something it receives by accident.

        Called once per run, by the worker, at execute time.
        """

    def get_run(self, tenant_id: str, run_id: str) -> dict | None:
        """One run by its exact id. Tenant-scoped, so an id from another customer is
        indistinguishable from one that does not exist."""

    def find_run(self, tenant_id: str, prefix: str) -> dict | None:
        """One run by id or **unique prefix**, or None when absent or ambiguous.

        Separate from `get_run` rather than folded into it. A full id is its own prefix,
        so one method would do — but the exact lookup is what every internal caller
        wants and it should not silently become a range scan. The prefix form exists
        because twelve hex characters is a lot for a person to type.
        """

    def list_runs(
        self,
        tenant_id: str,
        *,
        limit: int | None = None,
        status: str | None = None,
        root: str | None = None,
        roots_only: bool = False,
        principal_kind: str | None = None,
        principal_id: str | None = None,
        finished_since=None,
    ) -> list[dict]:
        """This tenant's runs, **newest first**.

        The opposite order from `audit_records`, and deliberately: that is a sequence
        and this is a list. A log is read forwards; "what has run lately" is read from
        the top, and `limit` there means "the last N of the sequence" while here it
        means "the N most recent".

        Three filters arrive with migration 027, all conjunctive:

            root           every run in one thread — `root_run_id = root`. The thread
                           view's whole query, against the `runs_thread` index.
            roots_only     only thread starters — `parent_run_id IS NULL`. The
                           Conversations list.
            principal_*    only runs this principal submitted. Passed together or not
                           at all; this is the "mine" filter, and it is a clause here
                           rather than a Python `if` above because a missing scope
                           clause against real Postgres is the failure that matters.

        `finished_since` arrives with step 013 and is the usage report's whole window:
        runs whose `finished_at` is at or after that instant, over migration 045's
        `runs_finished` index.

        **`finished_at` rather than `created_at`, and the name says so.** It is the
        column 013's own query names, and it is the one that matches what the counters
        mean: a run's tokens are written when the row is finished, so a run that starts
        at 23:59 and ends at 00:04 is accounted on the day it was accounted. It also
        excludes `queued` and `running` rows for free, which is right — a run still in
        flight has spent nothing that has been recorded.

        Composes with `limit`, and the composition is the honest order: the window
        first, the newest N of what is left second. A report that took the newest N runs
        and *then* dropped the ones outside its window would print a number smaller than
        the truth and say nothing about it.
        """

    def spend_since(
        self,
        tenant_id: str,
        since,
        *,
        principal_kind: str | None = None,
        principal_id: str | None = None,
    ) -> list[dict]:
        """Tokens accounted since `since`, **grouped by model**. Step 013c.

        `[{model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens}]`,
        one row per model, richest first. Scoped to one principal when both `principal_*`
        are given — passed together or not at all, `list_runs`' rule and its reason: a
        missing scope clause against the real store is the failure that matters, so it is
        a clause here rather than a filter above.

        **Grouped by model rather than summed flat, and that is what makes money
        possible without putting money in the schema.** A cost is tokens x the rate for
        the model that produced them, so a single `SUM` could only ever be priced at a
        blended rate — the arithmetic `cost_of` refuses one layer up. Grouping here and
        pricing in Python keeps the rate table out of SQL and out of every stored row,
        which is 013's decision 4 (*"a stored cost is a frozen guess that reads like an
        invoice"*) held rather than worked around. The result is a handful of rows.

        Over `runs_principal_finished` (migration 046) when scoped and `runs_finished`
        (045) when not — both partial on `finished_at IS NOT NULL`, both carrying the
        counters as payload so the read is index-only.

        Only **finished** runs, matching `tokens_spent_since` and `finished_since`
        everywhere else: a run in flight has spent nothing that has been accounted. Rows
        written before 045 carry zeros and a `''` model, and group under that.
        """

    def door_spend_since(
        self,
        tenant_id: str,
        since,
        *,
        principal_kind: str,
        principal_id: str,
    ) -> list[dict]:
        """What this principal's **door calls** spent since `since`, grouped by model.

        Step 045b. `spend_since`'s sibling on the other side of the door, returning the
        identical shape — `[{model, input_tokens, output_tokens, cache_read_tokens,
        cache_write_tokens}]`, richest first — so `core.usage.price_buckets` prices door
        rows and run rows with one function and there is no second vocabulary for money.

        **A separate method rather than a flag on `spend_since`, because the two read
        different tables** and always will: a run's tokens live on `runs` (migration 045)
        and a door call's live on `audit` (048), because a door call writes no `runs` row.
        That is the premise's own rule, and a single method with a `door=True` parameter
        would be one function pretending two tables are one — the exact confusion
        `CLAUDE.md` says has already been got wrong once.

        Only rows whose `run_id` begins `DOOR_CALL_ID_PREFIX`, and only rows with usage
        recorded (`input_tokens IS NOT NULL`). The second predicate is not an optimisation
        dressed as a filter: a NULL counter means *this call touched no model*, which is
        every ordinary tool call, and a store that read them as zeros would return one
        enormous `''` bucket contributing nothing but an unpriced-model warning.

        `principal_kind` and `principal_id` are **required here** where `spend_since`
        makes them optional, and the asymmetry is deliberate. `spend_since` has a
        tenant-wide reader (the usage report); this has exactly one reader, the per-
        principal ceiling, and an optional scope is how a half-applied filter counts one
        person's spend against another's allowance. A tenant-wide door total is a
        different question with a different index, and `overview` asks it separately.

        Over `audit_principal_usage` (migration 048), partial on `input_tokens IS NOT
        NULL` and carrying the counters as payload, so the read is index-only and empty
        on every deployment whose tools report no usage at all.
        """

    def owner_door_spend_since(self, tenant_id: str, since, *, owner_id: str) -> list[dict]:
        """What this person's **personal tokens** spent through the door, together.

        Step 108, decision 7. `door_spend_since` for a personal token answers for the one
        token presented, and a person with two machines holds two — so the money and
        token ceilings were per device, and *a daily ceiling per engineer* was not what
        the dial did. This is the read that makes it so: every `audit` row whose
        `principal_id` is a token owned by `owner_id` **with `acts_as_owner`**, summed
        into `door_spend_since`'s exact shape, so `price_buckets` and the ceiling's
        arithmetic do not know which read fed them.

        **Only tokens that act as their owner.** A service token this person happens to
        own is its own subject with its own allowance (a CI bot's three tokens are three
        allowances on purpose), and pooling it here would charge a person's day for a
        pipeline's. The bit is `api_tokens.acts_as_owner`, read at query time — the
        same one `credentials.personal_owner` decides by, so the door and this read
        cannot disagree about which tokens are somebody's.

        **Revoked tokens count.** A token revoked at noon spent what it spent this
        morning, and a rule that forgot it would let anyone reset their day by revoking
        and re-minting — which the silent first-run exchange does for them. Expired
        tokens count for the same reason.

        A subquery over `api_tokens` rather than a list of ids passed in: the set is
        small (one row per machine the person has), but resolving it here means one
        statement under one snapshot, and no window in which a token minted between two
        queries is charged to nobody.

        Same index as `door_spend_since`; the subquery's ids become an `= ANY` over the
        index's third column under the same two leading equalities.
        """

    def tokens_spent_since(self, tenant_id: str, since) -> int:
        """Every model token this tenant's finished runs accounted for since `since`.

        The token ceiling's whole read (step 013b), asked by `runs.submit` immediately
        before the insert — `count_recent_runs`' shape and `count_recent_runs`' reason:
        one aggregate returning exactly what the refusal needs, over migration 045's
        partial `runs_finished` index.

        **One SUM rather than `list_runs` and a loop.** The alternative puts the whole
        day's rows through Python on the submit path, so a busy tenant pays for its own
        history on every submission and the cost grows through the day. This is the query
        plan 013's decision 5 named — *"a tenant total is a query, not a table"* — asked
        of one day instead of a report's window.

        **All four counters summed, not weighted.** Cache reads cost an order of
        magnitude less than input and this deliberately does not care: the ceiling is
        denominated in tokens rather than money, because a money ceiling would inherit
        `estimate_cost`'s hole — a model with no rate contributes nothing, so an unpriced
        model would be free of the ceiling entirely and it would never fire.

        Only **finished** runs count. A run in flight has spent nothing that has been
        accounted, which matches `finished_since` everywhere else and is the same reason
        the counters are written by `finish_run`. Rows written before migration 045 carry
        zeros and contribute nothing, which is honest: nobody counted them.

        Returns `0` for a tenant with no finished runs in the window — never None, so a
        caller never has to spell "no runs" and "no tokens" differently.
        """

    def count_recent_runs(
        self, tenant_id: str, principal_kind: str, principal_id: str, *, since
    ) -> tuple[int, datetime | None]:
        """How many runs this principal created after `since`, and the oldest's instant.

        The rate limit's whole read (step 023): `runs.submit` asks it immediately before
        the insert, over the `runs_by_principal` index. Two values in one query because
        the refusal needs both — the count decides, and the oldest counted `created_at`
        is what `Retry-After` is computed from, so a 429 names when to come back rather
        than guessing.

        Counts **rows**, which is the honest unit: an idempotent resubmission that
        matched an existing run created nothing and costs nothing, so it is not here.
        The second element is None when the count is zero.
        """

    def start_run(self, tenant_id: str, run_id: str, *, claimed_by: str = "") -> dict | None:
        """`queued` -> `running`, stamping `started_at`. Returns the row, or None.

        **Refuses a run that is not queued**, by returning None rather than raising: two
        things trying to start one run is the ordinary shape of a queue race, not an
        error, and the loser needs to carry on rather than to handle an exception. That
        is the same property `claim_run` will need, arriving one chunk early on the one
        transition that exists today.
        """

    def finish_run(
        self,
        tenant_id: str,
        run_id: str,
        status: str,
        *,
        answer: str | None = None,
        error: str = "",
        usage: dict | None = None,
    ) -> dict | None:
        """Move a run to a terminal status, stamping `finished_at`. Returns the row.

        `status` must be terminal — see `TERMINAL_RUN_STATUSES`. Finishing a run that is
        already finished returns None and changes nothing, so a retry after a partial
        failure cannot overwrite the outcome that was recorded first.

        `usage` is what the run spent at the model (step 013, migration 045) — the dict
        `core/usage.Meter.snapshot()` produces, keyed exactly as the columns are named,
        or None for a caller with nothing to record. **Written here rather than through a
        method of its own**, which is 013's decision 2 and is the reason a ten-turn run
        makes one usage write instead of ten: the statement was happening anyway.

        The stated cost of that: **a run whose process dies mid-loop records nothing**,
        because nothing reaches this call. That is wrong in exactly the case where
        somebody most wants to know what was spent, and it is accepted rather than
        hidden — the alternative puts a database round trip inside the model loop for
        every agent in the product. `recover_expired_runs` can carry counters later, when
        there is evidence anybody needs them.

        **The token columns accumulate; they are not assigned — and today that makes no
        observable difference, which is stated rather than glossed.** Plan 013's finding 6
        justified `+=` with *"a run reclaimed after a lease expiry re-executes from the
        beginning and spends tokens again"*, and this platform does not do that:
        `recover_expired_runs` moves an expired run to `interrupted` and never back to
        `queued` — *"a run that may have half-happened must not happen twice"* — while
        `start_run` and `claim_run` both require `queued` and this method's own guard
        keeps the first outcome. So exactly one write lands per row, and `+=` is currently
        indistinguishable from `=`.

        It is still `+=`, and the reason is what happens if that ever changes: a retry
        built on top of `=` loses the first attempt's spend silently, in the column an
        invoice is reconciled against. The cheap shape that stays correct is the one to
        write down. `test_a_second_finish_writes_nothing_at_all` pins the invariant that
        makes them equivalent today, so a change to it is a change somebody has to make
        deliberately.

        The other two columns are not quantities and each takes the rule that fits it:
        `peak_context_tokens` keeps the **larger** value, since the row describes
        everything this run did and the high-water mark of that is a maximum; `model` is
        **replaced only when there is one to replace it with**, so a caller recording no
        model call cannot blank what an earlier one wrote. See migration 045.
        """

    def set_thread_shared(
        self, tenant_id: str, run_id: str, shared: bool
    ) -> dict | None:
        """Open a thread to collaborators, or close it again. Returns the row, or None.

        Migration 027. `thread_shared` is meaningful on root runs only, and the WHERE
        clause enforces it — a follow-up turn's id returns None rather than flagging a
        row nothing reads the flag from. None also covers absent and another tenant's,
        which the caller tells apart by having read the row first, exactly as
        `request_cancel`'s callers do.

        Deliberately no guard on the agent's `private_runs` flag: that is read-time
        policy, evaluated where grants are, and a stored refusal here would be a
        snapshot of a config that can change. The route refuses it; see decision 8.
        """

    def request_cancel(
        self, tenant_id: str, run_id: str, *, cancelled_by: str = ""
    ) -> dict | None:
        """Ask a run to stop. Returns the row, or None if there was nothing to ask.

        **Two outcomes, one statement**, and which one applied is what the row reports:

            queued    -> `cancelled` outright, with `finished_at` stamped. Nothing has
                         run and nothing is going to, so there is nothing to wait for.
            running   -> `cancel_requested_at` set and **the status left alone**. The
                         run is still executing and the row must not claim otherwise.

        None means the run is absent, another customer's, or **finished as something
        other than cancelled** — and the caller has to tell those apart, which is why
        every caller reads the row first. A route answers 404 for the first two and 409
        for the third.

        **Asking twice is not an error**, and that includes asking twice about a queued
        run, which is already `cancelled` by the time the retry arrives. The second
        request returns the row unchanged, preserving the first `cancel_requested_at` and
        the first `cancelled_by`: a repeat of the same intent is a retry, and the
        interesting fact is who asked *first*. See `CANCELLABLE_RUN_STATUSES`, which is
        deliberately not the complement of `TERMINAL_RUN_STATUSES`.

        One statement rather than the two the plan sketched (a guarded `queued` update,
        then a flag update if it matched nothing). The guard is the same — the CASE reads
        the pre-update status — and one atomic statement has no window between them for a
        claim to land in.
        """

    def note_activity(self, tenant_id: str, run_id: str, activity: dict) -> None:
        """Record what a running run is doing right now. Step 032.

        `activity` is the marker `normalize_activity` shapes — turn, doing, since.
        Guarded on `status = 'running'` in the statement itself, so a write that loses a
        race with cancellation or completion changes nothing rather than resurrecting a
        terminal row's marker. A run that is absent, another tenant's, or not running is
        the same silent no-op, because every caller is the runtime making a best-effort
        progress note — there is no remedy a raise would name.

        **Never read back by the writer.** The readers are the run detail and the wait
        probe; the runtime writes and moves on, and a failed write costs a stale
        sentence on a screen rather than anything true.
        """

    def run_fingerprint(self, tenant_id: str, run_id: str) -> str | None:
        """Everything the run detail renders live, folded into one comparable string.

        Step 032's probe: `GET /runs/{id}?wait=…` holds until this differs from the
        cursor the client presented, so it must move exactly when the page would render
        differently — status, cancellation, activity, or a new audit record — and hold
        still otherwise. Composed by `compose_run_fingerprint` in both stores, so the
        two cannot drift; None for a run that is absent or another customer's, which
        the route has already turned into a 404 before it ever waits.

        One statement in Postgres — the row by primary key plus an index-only count of
        the run's audit rows — because it runs a few times a second per watched run and
        is the whole recurring cost of a held wait. **This is the seam LISTEN/NOTIFY
        would replace if it ever earns its reason** (see `WORKER_POLL_INTERVAL`'s note
        in config.py): the probe is a function returning "has anything changed", and a
        notification is a cheaper way to answer it, not a different question.
        """

    # --- the queue --------------------------------------------------------------
    #
    # The three methods a worker needs. `runs` is the queue as well as the record, which
    # is the deciding argument for Postgres over a broker and is not the obvious one:
    # not durability and not volume, but that the queue entry and the run record must
    # never disagree. Here they are one row.

    def claim_run(
        self, worker: str, *, lease_seconds: int, limit_to_tenant: str | None = None
    ) -> dict | None:
        """Take the oldest queued run, or None. `FOR UPDATE SKIP LOCKED`.

        **The only method in this interface that does not take a tenant**, and the
        exception is the point rather than an oversight: a worker serves every customer,
        and a tenant filter here would mean a worker per tenant. What must stay
        tenant-scoped is everything the run then *does* — and it does, because the
        principal on the row carries the tenant and every layer below takes it from
        there.

        `limit_to_tenant` exists for tests, which need two workers racing inside one
        shared database without seeing each other's fixtures. Production passes None.
        It is a keyword and it is last, so nothing can supply it by position while
        meaning something else.

        Concurrency-safe by construction: `SKIP LOCKED` steps over rows another
        transaction has locked, so two workers asking at the same moment get two
        different runs and never the same one. That is the assertion the contract suite
        makes with real threads against real Postgres, because the in-memory store is
        too fast to expose it.
        """

    def heartbeat_runs(
        self, worker: str, run_ids: list, *, lease_seconds: int
    ) -> dict:
        """Extend the lease on the runs this worker still holds.

        Returns `{run_id: cancel_requested}` for the ones it kept. An id that comes back
        **missing** is one this worker no longer owns — it finished, or its lease expired
        and something declared it `interrupted` while this worker was still working on
        it. The caller needs to know, because a worker that keeps heartbeating a run it
        has lost is a worker arguing with the recovery it exists to enable.

        A dict rather than a list because this round trip is also how a worker **learns
        that one of its runs has been cancelled**. The alternative was a query per tool
        call in the broker: a run makes many of them — thirty was the default while this
        tree ran them — so that is
        thirty extra queries to answer "no" thirty times. This beat already happens every
        `RUN_HEARTBEAT` seconds and already returns exactly the right set of rows, so
        carrying one more column on it costs nothing at all.

        The price is latency, and it is stated rather than hidden: a cancelled run takes
        up to one heartbeat interval to notice, plus however long the call it is inside
        takes to return.

        Scoped to `claimed_by = worker`, so one worker cannot renew another's claim.
        """

    def recover_expired_runs(self, *, deadline_seconds: int) -> list:
        """Move abandoned runs to `interrupted`. Returns the rows moved.

        Two conditions, one status:

            the lease expired      the worker is gone
            the deadline passed    the worker is fine and the run is not

        The same status deliberately. Both mean *this started, we do not know how far it
        got, and a person should look* — and splitting them would invent a distinction
        nobody can act on differently. Which one fired is written to `error`, because
        that is a sentence a person reads rather than a branch anybody takes.

        **Never re-queued.** A run that may have half-happened is not re-run: it calls
        tools that write to a customer's systems, and one comment becomes two. See
        decision 5 of step 008.

        No tenant argument, for the same reason as `claim_run`.
        """

    # --- lifecycle ---------------------------------------------------------------

    def close(self) -> None:
        """Release whatever the store is holding. Idempotent, and safe on any store.

        On the protocol because a caller that opens a store should be able to close one
        without asking which kind it got — `localidp/frontdoor.py` was already calling it
        and only ever ran against Postgres, so the drift was invisible until 027's type
        check named it. The in-memory store's implementation is a documented no-op
        rather than an omission: there is nothing to release, and that is an answer.
        """

    def verify_tenant_isolation(self) -> None:
        """Refuse, with a remedy, when tenant scoping cannot work on this store.

        Called by the API server's lifespan beside `configure_crypto`, on the same
        argument — *at startup, not at first use*. A deployment whose login role cannot
        take the tenant role, or does not own the tables (row-level security then
        default-denies it everything the moment migration 037 lands), should refuse to
        boot with a sentence naming the fix, not answer its first scoped request with a
        503 and its first unscoped one with an empty list.

        Raises `StorageError`. The in-memory store's implementation is a documented
        no-op: it has no roles and no policies, and the scope invariant it *can* check
        is enforced on every call instead — see `memory.py`'s scope-mismatch guard.
        """


# Keys a connector manifest may carry. `read_only` is deliberately absent; see
# save_connector.
CONNECTOR_FIELDS = frozenset({"id", "description", "launch", "vetted"})

DERIVED_CONNECTOR_FIELDS = frozenset({"read_only"})

# What one entry of `manifest["vetted"]` holds, and what each field defaults to when a
# manifest omits it. Shared by both implementations so a vetted row round-trips
# identically through either — the same device as `IDP_DEFAULTS`, and here for the same
# reason `RUN_FIELDS` exists: `audit.credential` shipped written by Postgres and
# silently dropped by the fake, with the suite green, because nothing named the columns
# in one place.
#
# `vetted_by` and `vetted_at` are deliberately absent. They are the review record, not
# the allowlist — see `load_vetting_record`.
VETTED_TOOL_DEFAULTS = {
    "effect": "read",
    # Whose account the tool acts as — step 033a, beside `effect` because it is the
    # same kind of fact: a judgment made at approval time. The default is the stated
    # break in docs/UPGRADING.md: a row written before the field reads as the shared
    # credential, which is what every headless caller always got.
    "identity": "service",
    "resources": [],
    "local_name": None,
    "max_response_bytes": None,
    # Added by migration 018. Stored rather than fetched, so a catalogue answers with
    # the connector's server stopped.
    "description": "",
    "note": "",
    # The request binding of a `rest` connector's tool — migration 047, step 045a.
    # NULL on every MCP row ("not applicable", the `response_bytes` precedent). The
    # field and the connector's launch kind imply each other, refused both ways by
    # `check_binding_kind` at every write that knows the launch.
    "binding": None,
    # Which of this tool's arguments the audit log hashes rather than stores —
    # migration 049, step 045c. `[]` rather than None, and the difference from
    # `binding` above is that there is no "not applicable" state: every tool has an
    # answer to *what of this call is not written down*, and for most of them it is
    # *none*. A row written before the column meant exactly that.
    "redact_args": [],
}

VETTED_TOOL_FIELDS = frozenset({"remote_name", *VETTED_TOOL_DEFAULTS})

# The launch kind whose vetted rows carry a binding. A string rather than an import,
# because `tools/` imports storage and not the other way around — pinned against
# `tools.mcp.RestLaunch.KIND` by the contract suite, the `_OAUTH_ACCESS` boundary
# cost paid again.
REST_LAUNCH_KIND = "rest"

# What a binding may say, shape-wise. `tools/rest.check_binding` owns the
# cross-checks (every schema property mapped, path placeholders in the schema);
# this layer enforces only the rules that are facts about the row alone — the same
# split `check_vetted_tool`'s docstring states for every other field.
BINDING_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
BINDING_KEYS = frozenset(
    {"method", "path", "query", "body", "input_schema", "usage_map", "pricing"}
)

BINDING_WITHOUT_REST = (
    "'{tool}' carries a request binding, but connector '{connector}' does not speak "
    "'rest'. A binding describes a plain REST request; an MCP server describes its "
    "own tools, and a stored binding it would never use reads as honoured. The field "
    "and the 'rest' kind imply each other."
)

REST_WITHOUT_BINDING = (
    "'{tool}' is vetted on '{connector}', a REST connector, with no request binding. "
    "A REST API does not describe itself, so the method, path, argument mapping and "
    "input schema must be authored at vetting time."
)


def check_binding_kind(launch: dict, row: dict, connector_id: str) -> None:
    """The kind/binding implication, refused at the storage boundary both ways.

    Takes the stored launch dict rather than a Connector, because this layer is rows
    in, rows out and must not learn what a launch means — only which kind the row
    says it is. Runs where the launch is in hand: `vet_tool` and `save_connector`,
    in both stores.
    """
    is_rest = (launch or {}).get("kind") == REST_LAUNCH_KIND
    if is_rest and row.get("binding") is None:
        raise StorageError(
            REST_WITHOUT_BINDING.format(
                tool=row.get("remote_name", ""), connector=connector_id
            )
        )
    if not is_rest and row.get("binding") is not None:
        raise StorageError(
            BINDING_WITHOUT_REST.format(
                tool=row.get("remote_name", ""), connector=connector_id
            )
        )


UNSCOPEABLE_WRITE = (
    "'{tool}' is vetted as a write and declares no resources. A write to something "
    "policy cannot name is unscopeable — give it a resource, or mark it read if it "
    "genuinely changes nothing."
)


def check_vetted_tool(row: dict) -> None:
    """The one descriptor rule that is enforced **at the storage boundary**.

    `tools/validation.py` already refuses an unscopeable write, and has since step 003.
    That check runs when a manifest becomes a `Connector` — at load, and at every write
    that goes through `tools.save_connector`. It is the right place and it is not the
    only place that needed one.

    The reason this exists is step 012's second verification, stated as a property rather
    than as a test: *a vetted write with no resource is impossible* — not "the CLI asks
    for one". Registration adds a second write path into `vetted_tools` (`vet_tool`,
    one row at a time), and any interface that forgets is an interface that creates a
    tool the broker will happily call against a resource nobody can constrain. Putting
    the rule where every write funnels means no interface *can* forget it.

    Deliberately the only rules duplicated here — two since 033a — and worth saying why
    the others are not: every remaining check in `validation.py` compares the descriptor
    against the tool's **input schema**, and storage does not have one. `resources` is a
    JSONB column and the schema lives on the server. So this layer enforces the rules
    that are facts about the row alone, and the schema-relative rules stay one layer up
    where the schema is. The identity check qualifies by the same test as the write
    rule: a row carrying an identity nobody defined would otherwise be stored fine and
    refuse at the next load, when whoever wrote it is long gone from the terminal.
    """
    if row.get("effect") == "write" and not row.get("resources"):
        raise StorageError(UNSCOPEABLE_WRITE.format(tool=row.get("remote_name", "")))

    if row.get("identity") not in ("service", "user"):
        raise StorageError(
            f"'{row.get('remote_name', '')}' declares identity "
            f"'{row.get('identity')}'; expected 'service' or 'user'. Whose account a "
            "tool acts as is not something to guess."
        )

    # Step 045c. The shape only — a list of non-empty strings — on this function's own
    # test: a row whose redaction policy is a string or a list of nulls would be stored
    # fine and fail at the next bind, when whoever wrote it is long gone. Whether each
    # name is *in the tool's schema* is a schema-relative rule and stays one layer up in
    # `tools/validation.py`, where the schema is, exactly as `resources` does.
    redact_args = row.get("redact_args")
    if redact_args is not None:
        if not isinstance(redact_args, (list, tuple)) or not all(
            isinstance(name, str) and name for name in redact_args
        ):
            raise StorageError(
                f"'{row.get('remote_name', '')}' declares redact_args "
                f"{redact_args!r}; expected a list of argument names. What a tool "
                "keeps out of the audit log is a policy, and a malformed one is a "
                "policy nothing applies."
            )

    # Step 086. The shape only, on `redact_args`' test directly above: a family list
    # that is a string, or holds a blank, would be stored fine and fail at the next
    # bind. The two rules that are *about what a family means* — no separator in it, and
    # none on a composed resource — are schema-relative in the same sense and stay in
    # `tools/validation.py`, where the descriptor is whole.
    #
    # A blank family is refused here rather than only there because of what it would do
    # if it ever reached a matcher: `family_of` finds an empty token run inside every
    # identifier, so one scope line naming it would admit every model on the connector.
    # `config.model_rates` refuses an empty rate key on exactly this argument.
    for ref in row.get("resources") or ():
        families = (ref or {}).get("families")
        if families is None:
            continue
        # A NUL or a lone surrogate in a family, refused with the sentence and the
        # **400** family rather than Postgres' *"unsupported Unicode escape sequence"* —
        # which is the 503 that means *the database is broken*, about a value somebody
        # typed. Both stores now answer the same thing: driven in step 086's edge pass,
        # the in-memory store took all three and Postgres took none, which is this
        # register's oldest recorded split. `check_config_is_storable` is the rule
        # already written down one function away; this is that rule reaching the two
        # caller-supplied string positions step 086 added inside a jsonb column.
        check_config_is_storable(
            {"families": families}, what=f"'{row.get('remote_name', '')}' resource families"
        )
        if not isinstance(families, (list, tuple)) or not all(
            isinstance(name, str) and name.strip() for name in families
        ):
            raise StorageError(
                f"'{row.get('remote_name', '')}' declares families {families!r} on "
                f"resource '{(ref or {}).get('type', '')}'; expected a list of "
                "non-empty names. A family is what a scope line may say instead of a "
                "dated id, and a blank one is a name every identifier answers to."
            )

    if row.get("binding") is not None:
        _check_binding_shape(row["remote_name"], row["binding"])


def check_rate_table(table, where: str) -> None:
    """Refuse a malformed rate table. Raises `ValueError` naming `where`.

    **A rate table has two homes and this is under both of them.** One is the operator's
    `CARNET_MODEL_RATES` file; the other is `vetted_tools.binding.pricing`, written by
    whoever registered the vendor's key (step 086). `config.check_rate_table` is the name
    the rest of the tree calls this by and delegates here.

    **Down here rather than beside the file that reads it, and step 086's edge pass is
    why.** The rules were one layer up, so the *vet* path ran them and the wholesale
    write path — `save_connector`, which is `--seed` and any manifest writer — did not.
    Driven against real Postgres, four malformed tables stored fine and three of them
    broke money:

      - `{"gpt-5": {}}` reached `estimate_cost` and raised **`KeyError: 'input'`**, and
        `door_spend_today` is on every metered door call, so one seeded typo is a 500 on
        every brokered call in that tenant until somebody edits the database.
      - `{"input": "abc"}` raised **`TypeError`** at the same address.
      - a **negative** rate priced spend at `-0.00499` — the quiet one this function has
        always refused in a file, arriving on a row instead.
      - a **bool**, priced at 1, which is the failure four other places in this codebase
        refuse a bool to prevent.

    Which puts it exactly where `check_vetted_tool`'s own rule says: *"this layer enforces
    the rules that are facts about the row alone"*. A rate needs no schema, no connector
    and no clock — it is arithmetic, checked against itself.

    **Non-finite is refused, and that rule is new.** `json.load` accepts bare `NaN` and
    `Infinity`, so both could reach a figure: `Infinity` refuses every call forever, and
    `NaN` is worse because it is silent — `nan > ceiling` is **False**, so a dollar
    ceiling over NaN spend never fires, and the API answers `{"usd": NaN}`, which no
    parser outside Python accepts. Postgres refused both at the JSON parser with a
    syntax error while the in-memory store took them, so this also closes a two-store
    split: both refuse now, with the same sentence.
    """
    if not isinstance(table, dict):
        raise ValueError(
            f"{where}: a rate table is an object mapping a model-id "
            f"fragment to its four rates, not a {type(table).__name__}. Example: "
            '{"gpt-5": {"input": 1.25, "output": 10.0, "cache_read": 0.125, '
            '"cache_write": 0.0}}'
        )

    needed = ("input", "output", "cache_read", "cache_write")
    for family, rate in table.items():
        if not isinstance(family, str) or not family.strip():
            raise ValueError(
                f"{where}: {family!r} is not usable as a key. A key is the "
                "piece of a model id that identifies it — 'gpt-5', 'claude-opus-5' — "
                "and an empty one is a substring of every id, which would price every "
                "model in the deployment at this one rate."
            )
        if not isinstance(rate, dict):
            raise ValueError(
                f"{where}: the rates for '{family}' are a "
                f"{type(rate).__name__}, not an object. Each key maps to "
                '{"input": .., "output": .., "cache_read": .., "cache_write": ..}, '
                "in USD per million tokens."
            )

        missing = [
            k
            for k in needed
            # `bool` first: `isinstance(True, int)` is true, so a JSON `true` would
            # otherwise pass as the number 1 and price a million tokens at a dollar.
            if isinstance(rate.get(k), bool) or not isinstance(rate.get(k), (int, float))
        ]
        if missing:
            raise ValueError(
                f"{where}: rates for '{family}' are missing {missing}. "
                "Each family needs all four — a table with three of them prices the "
                "fourth kind of token at nothing and reports a total that looks whole."
            )

        # Before the sign test, because `nan < 0` is False and would sail past it.
        unreal = sorted(k for k in needed if not math.isfinite(rate[k]))
        if unreal:
            raise ValueError(
                f"{where}: rates for '{family}' are not finite numbers at {unreal}. "
                "`json` accepts a bare NaN and Infinity and neither is a price: an "
                "infinite rate refuses every call forever, and a NaN is the silent one "
                "— every comparison against a ceiling is False, so the ceiling never "
                "fires, and the figure serializes to something no JSON parser outside "
                "Python will read."
            )

        negative = sorted(k for k in needed if rate[k] < 0)
        if negative:
            raise ValueError(
                f"{where}: rates for '{family}' are negative at {negative}. "
                "A negative rate makes spend fall as tokens are used, so a dollar "
                "ceiling is never reached and a deployment that believes it has one "
                "does not — the one wrong number here that nothing anywhere would "
                "report."
            )


def _check_binding_shape(tool: str, binding) -> None:
    """The binding's *shape*, at the storage boundary — step 045a.

    Qualifies by `check_vetted_tool`'s own test: a row whose binding names a method
    nobody defined, or carries a key nothing reads, would otherwise be stored fine
    and refuse at the next load, when whoever wrote it is long gone from the
    terminal. The cross-checks — every schema property mapped, path placeholders in
    the schema — stay one layer up in `tools/rest.check_binding`, where every
    interface that writes a binding funnels through them at vet and at bind.
    """
    if not isinstance(binding, dict):
        raise StorageError(
            f"'{tool}': a request binding must be a mapping, not "
            f"{type(binding).__name__}"
        )

    unknown = set(binding) - BINDING_KEYS
    if unknown:
        raise StorageError(
            f"'{tool}': binding carries unknown keys {sorted(unknown)}; expected "
            f"only {sorted(BINDING_KEYS)}. Refused rather than dropped — a stored "
            "key nothing reads would read as honoured."
        )

    if binding.get("method") not in BINDING_METHODS:
        raise StorageError(
            f"'{tool}': binding method {binding.get('method')!r} is not one of "
            f"{', '.join(BINDING_METHODS)}"
        )

    path = binding.get("path")
    if not isinstance(path, str) or not path.startswith("/"):
        raise StorageError(
            f"'{tool}': binding path must be a string starting with '/', got "
            f"{path!r}"
        )

    for where in ("query", "body"):
        names = binding.get(where) or []
        if not isinstance(names, list) or not all(
            isinstance(entry, str) and entry for entry in names
        ):
            raise StorageError(
                f"'{tool}': binding '{where}' must be a list of argument names, "
                f"got {names!r}"
            )

    if not isinstance(binding.get("input_schema"), dict):
        raise StorageError(
            f"'{tool}': binding must carry 'input_schema' as a mapping — the "
            "authored schema is what the model sees and what resources validate "
            "against, and a binding without one is a tool nobody can describe."
        )

    usage_map = binding.get("usage_map")
    if usage_map is not None and (
        not isinstance(usage_map, dict)
        or not all(
            isinstance(k, str) and k and isinstance(v, str) and v
            for k, v in usage_map.items()
        )
    ):
        raise StorageError(
            f"'{tool}': binding usage_map must map counter names to response "
            f"paths, both non-empty strings, got {usage_map!r}"
        )

    # Step 086, and **the whole table rather than its outline** — the edge pass found
    # the difference the hard way. This started as a shape check (keys are strings,
    # values are objects) on the reasoning that the *rules* about a rate belong one layer
    # up with `usage_map`'s. That reasoning is right for a `usage_map`, whose worst
    # malformation is a counter that never arrives, and wrong for a price, which is
    # arithmetic: `{"gpt-5": {}}` passed the outline, stored, and made every metered door
    # call in that tenant raise `KeyError: 'input'`. See `check_rate_table`.
    #
    # Re-raised as `StorageError` because that is the family every refusal on this path
    # answers with, and a bare `ValueError` through a route is a 500.
    pricing = binding.get("pricing")
    if pricing is not None:
        try:
            check_rate_table(pricing, f"'{tool}': binding pricing")
        except ValueError as exc:
            raise StorageError(str(exc)) from exc
        # And the keys, which are caller-supplied strings inside a jsonb column — the
        # `families` rule above, at the other new position step 086 opened.
        check_config_is_storable(pricing, what=f"'{tool}' binding pricing")


def normalize_vetted_tool(row: dict) -> dict:
    """One `manifest["vetted"]` entry with every key present, defaults filled.

    Both stores call this so neither can be the one that keeps a field. Unknown keys
    are dropped rather than refused: `read_only` is the field that must never be
    stored and it lives on the connector, not here, so there is nothing on this row
    worth failing a write over.

    It **does** refuse an unscopeable write — see `check_vetted_tool`. The asymmetry with
    the sentence above is intentional: a dropped unknown key changes nothing about what
    the platform will do, and an unscopeable write changes what a broker will let an
    agent reach.
    """
    # Refused rather than indexed. `row["remote_name"]` raised a bare `KeyError` here,
    # which is the one failure on this path that was not a `StorageError` — so a manifest
    # whose vetted entry omitted the name came back as an unhandled crash rather than the
    # refusal every other malformed field gets. Found by 027 narrowing a test that had
    # asserted `pytest.raises(Exception)` and so could not tell the two apart.
    if not row.get("remote_name"):
        raise StorageError("each vetted tool must have a non-empty 'remote_name'")

    normalized = {"remote_name": row["remote_name"]}
    for key, default in VETTED_TOOL_DEFAULTS.items():
        value = row.get(key, default)
        # A null where the column is NOT NULL means the same thing as an omission.
        # `local_name` and `max_response_bytes` default to None and keep it.
        if value is None and default is not None:
            value = default
        # **A tuple normalizes to a list, and that is a fix rather than tidiness.**
        # This used to be `isinstance(value, list)` alone, so a caller handing a tuple
        # got a tuple back out of the memory store and a **list** out of Postgres, which
        # round-trips through `json.dumps`. Two stores answering different types for one
        # write is the exact failure this function's docstring says it exists to prevent,
        # and it was latent on `resources` for as long as this function has existed.
        #
        # 045c made it reachable: `Vetted.redact_args` *is* a tuple, so the obvious thing
        # for a caller to write — handing the field straight to `vet_tool` — produced the
        # divergence. Verified against real Postgres before this line was changed.
        normalized[key] = (
            list(value) if isinstance(value, (list, tuple)) else value
        )

    # **A resource's `families` normalizes to a list, one level down.** Step 086, and
    # it is the divergence the comment directly above records as latent on `resources`
    # since this function has existed: a tuple survives the memory store and becomes a
    # list through Postgres' `json.dumps`, so two stores answer different types for one
    # write. `vetted_to_dict` already writes a list, so this catches the wholesale
    # writer (`--seed`, a recipe applied in one call) rather than the vetting path —
    # and a new field is the wrong place to add a second instance of a known split.
    if isinstance(normalized.get("resources"), list):
        normalized["resources"] = [
            {
                **ref,
                "families": list(ref["families"]),
            }
            if isinstance(ref, dict) and isinstance(ref.get("families"), (list, tuple))
            else ref
            for ref in normalized["resources"]
        ]

    # A binding round-trips with every key present, defaults filled — the same
    # device as the row itself, one level down, so a binding written by `--vet` and
    # one written wholesale compare equal after either store's round trip.
    if isinstance(normalized.get("binding"), dict):
        binding = dict(normalized["binding"])
        binding.setdefault("query", [])
        binding.setdefault("body", [])
        binding.setdefault("usage_map", None)
        # Step 086, on the same device: every binding key present, so a row written by
        # `--vet` and one written wholesale compare equal after either store's round
        # trip.
        binding.setdefault("pricing", None)
        if binding.get("query") is None:
            binding["query"] = []
        if binding.get("body") is None:
            binding["body"] = []
        normalized["binding"] = binding

    check_vetted_tool(normalized)
    return normalized

# What a `tenant_idps` row holds, and what each field defaults to when absent.
# Shared by both implementations so a row round-trips identically through either.
IDP_DEFAULTS = {
    "discriminator_claim": None,
    "discriminator_value": None,
    # Which claim carries the stable identity, and which carries the email. Both are
    # per provider because providers disagree, and both defaults are what a conformant
    # token uses. See migration 010 for the real Okta token that made `subject_claim`
    # necessary — its access tokens put the login in `sub` and the stable id in `uid`.
    "subject_claim": "sub",
    "email_claim": "email",
    # Which claim carries the groups this person is in — migration 043, step 033e. The
    # third claim mapping, and the only one whose default is **None** rather than what a
    # conformant token uses: every token has a subject and an address, and a provider
    # that says nothing about groups is ordinary rather than misconfigured. NULL means
    # the directory decides nothing here, which is how every row behaved before 043.
    "groups_claim": None,
    "allowed_domains": (),
    "enabled": True,
}

IDP_REQUIRED = ("issuer", "jwks_uri", "audience")

# The only issuer whose `allowed_domains` may be `"*"`. See `check_allowed_domains` for
# why one issuer is exempt and every other one is not.
#
# Defined here rather than in `localidp/` and imported *by* that package, so the rule and
# the value have one home. The dependency points the safe way: storage owns the constraint
# and the provider conforms to it, which is also what keeps `api/` and `access/` free of
# any knowledge that a local provider exists — the property
# `test_the_server_never_imports_the_local_idp` asserts.
LOCAL_ISSUER_WILDCARD_OK = "carnet-local"

USER_STATUSES = frozenset({"active", "disabled"})

# What a `connector_oauth` row holds when read back, in the order both stores return it.
# The `RUN_FIELDS` / `AGENT_FIELDS` device again, and here it carries a rule as well as an
# order: **`client_secret` and `key_id` are the last two, and `OAUTH_APP_PUBLIC_FIELDS` is
# everything before them.** A reader that wants to describe a connector's OAuth
# configuration — the Connections page, `--list-connectors` — asks for the public list and
# is structurally unable to acquire the sealed secret on the way past, which is the same
# containment `list_connections` has against `ciphertext`.
OAUTH_APP_PUBLIC_FIELDS = (
    "connector_id",
    "authorize_endpoint",
    "token_endpoint",
    "revoke_endpoint",
    "client_id",
    "scopes",
    "authorize_params",
    # Migration 051. Public in the strongest sense on this list: the whole reason it
    # exists is to be rendered to a non-administrator at a consent screen, which is a
    # weaker audience than any other field here has.
    "scope_notes",
    "configured_by",
    "configured_at",
)
OAUTH_APP_FIELDS = (*OAUTH_APP_PUBLIC_FIELDS, "client_secret", "key_id")

# What an `api_tokens` row holds, migration 031, and it carries the same rule in the same
# shape: **`secret_hash` is last, and `API_TOKEN_PUBLIC_FIELDS` is everything before it.**
# `--list-tokens`, the offboarding review and anything that ever renders this list ask for
# the public tuple and are structurally unable to pick up the hash on the way past.
#
# `find_api_token` is the single exception and the only method that returns the full
# tuple, because comparing against the hash is the one thing that needs it — exactly the
# containment `find_connection` has against `ciphertext`.
API_TOKEN_PUBLIC_FIELDS = (
    "id",
    "tenant_id",
    "name",
    "owner_id",
    "acts_as_owner",
    "created_by",
    "created_at",
    "expires_at",
    "revoked_at",
    "revoked_by",
    "last_used_at",
)
API_TOKEN_FIELDS = (*API_TOKEN_PUBLIC_FIELDS, "secret_hash")

# The prefix on a presented credential, and the reason `api/deps.py` can dispatch on the
# token string without parsing it: a JWT is base64 of `{"alg"...` and begins `eyJ`, so the
# two shapes cannot collide. One door per shape, and no fallback chain — a malformed
# machine token is refused as one rather than retried as a JWT, because a resolver that
# tries both produces two reasons for one failure and logs the wrong one.
API_TOKEN_PREFIX = "art_"

# What separates the id from the secret in a presented credential. Here rather than in
# `access/tokens.py` because **both the parser and the id guard need it**, and a rule
# enforced with two copies of a character is a rule with two opinions the day one of them
# is edited. `normalize_api_token` refuses an id containing it.
API_TOKEN_SEPARATOR = "."

# What a `scim_tokens` row holds, migration 052, in `API_TOKEN_PUBLIC_FIELDS`' shape and
# under its rule: **`secret_hash` is last, and the public tuple is everything before
# it.** `--list-scim-tokens` reads the public tuple; `find_scim_token` is the one method
# that returns the whole thing, because comparing against the hash is the one thing that
# needs it.
SCIM_TOKEN_PUBLIC_FIELDS = (
    "id",
    "tenant_id",
    "issuer",
    "name",
    "created_by",
    "created_at",
    "revoked_at",
    "revoked_by",
    "last_used_at",
)
SCIM_TOKEN_FIELDS = (*SCIM_TOKEN_PUBLIC_FIELDS, "secret_hash")

# What one `pending_authorizations` row holds. `code_verifier` is in it, unlike the
# connection case — this row has exactly one reader, the callback, and the verifier is the
# only reason the row exists. There is no metadata view of it to protect.
PENDING_AUTHORIZATION_FIELDS = (
    "state",
    "tenant_id",
    "principal_kind",
    "principal_id",
    "connector_id",
    "code_verifier",
    "key_id",
    "redirect_uri",
    "return_to",
    "created_at",
)

# What an `oauth_clients` row holds — migration 053. No `tenant_id`, and that is the
# table's defining fact: a client registers before anybody signs in, so the person who
# consents decides the tenant, on the code row.
OAUTH_CLIENT_FIELDS = (
    "id",
    "client_name",
    "redirect_uris",
    "metadata",
    "created_at",
    "last_consented_at",
)

# What an `oauth_codes` row holds — migration 053. `code_hash` is the digest of the
# code the client will present; the code itself is stored nowhere, on `api_tokens.
# secret_hash`'s reasoning. `token_id` is filled at the exchange and is what a replayed
# code revokes.
OAUTH_CODE_FIELDS = (
    "code_hash",
    "tenant_id",
    "client_id",
    "owner_id",
    "redirect_uri",
    "code_challenge",
    "resource",
    "token_name",
    "created_at",
    "expires_at",
    "used_at",
    "token_id",
)

# Bounds on what an unauthenticated registration may write. `access/oauth_server.py`
# refuses above them with RFC 7591's error; the stores refuse again here because a
# bound enforced in one layer is a bound the next caller does not have.
OAUTH_CLIENT_MAX_REDIRECT_URIS = 10
OAUTH_CLIENT_MAX_URI_LENGTH = 2048
OAUTH_CLIENT_MAX_NAME_LENGTH = 200
OAUTH_CLIENT_MAX_METADATA_BYTES = 4096

# Whether a customer may use the platform at all. Migration 020, and the words differ
# from `USER_STATUSES` on purpose: 'disabled' is something done to one account, and
# 'suspended' is something done to a business relationship. Two sets that happened to
# share a vocabulary would be one `check_status` helper away from a caller disabling a
# tenant and suspending a person.
#
# 'read_only' is deliberately absent — see the migration. Nothing honours it, and a
# CHECK value no code path answers is a control that lies.
TENANT_STATUSES = frozenset({"active", "suspended"})

# The setting `delete_tenant` and `prune_log_records` turn on for one transaction, and
# the only thing that lets a DELETE past the append-only triggers. Migration 029.
#
# Named here rather than typed at the two call sites so the guard and the exemption
# cannot drift — the same argument `LOCAL_ISSUER_WILDCARD_OK` settled for the wildcard
# in 016, where a constant with one home is what stops a rule and its exception being
# edited apart.
RETENTION_GUC = "agent_runtime.retention"
RETENTION_GUC_ON = "on"

# The role migration 037's policies apply to, and the setting that names which tenant a
# scoped connection is serving. Step 029. Named here for the same reason `RETENTION_GUC`
# is: `postgres.py` sets them, `tenancy.py` documents them, the contract suite's catalog
# guard asserts them, and three copies of a string is how a rule and its enforcement get
# edited apart. The migration necessarily repeats them as SQL literals — a migration
# cannot import — which is `RETENTION_GUC`'s own arrangement with migration 029.
TENANT_ROLE = "agent_runtime_tenant"
TENANT_GUC = "agent_runtime.tenant_id"

# The tables referencing `tenants(id)` with **no** `ON DELETE CASCADE`, in the order
# `delete_tenant` must empty them.
#
# The order is a foreign-key fact, not a preference: `groups` fires
# `groups_cascade_grants` (migration 017) on its way out, and `runs` references itself
# (migration 027) — a single statement per table satisfies that because Postgres checks
# at statement end rather than per row.
#
# **`runs` and `groups` are the two nobody had counted.** Every previous statement of
# this problem — three migrations, the register, two handoffs — names `audit` as *the*
# blocker. It is one of five, and the other four were found by reading the catalog
# rather than the prose. That is also why this list exists as a constant with a test
# walking `information_schema` against it: the next migration that adds such a table
# fails that test rather than failing a customer's deletion.
TENANT_BLOCKING_TABLES = (
    "runs",
    "groups",
    "access_denials",
    "admin_audit",
    "audit",
)

# The three append-only log tables, which are what retention prunes. A subset of the
# above, and deliberately a separate name: everything here is prunable *by age*, and
# `runs` and `groups` are not — they are product data that goes when the customer does.
RETAINED_LOG_TABLES = ("audit", "admin_audit", "access_denials")

# How far ahead of the current month `ensure_log_partitions` keeps coverage. Migration
# 030, and the number is a bound on how long a deployment can go without running any of
# the three things that call it — the migration, opening a store, or a worker sweep —
# before an append lands in a month that has nowhere to go.
#
# Three months rather than one because the failure is loud and the cost is nothing: an
# empty partition is a catalog row, and a quarter is long enough that the deployments
# which reach the end of it are the ones nobody is operating at all.
PARTITION_HORIZON_MONTHS = 3


def _add_months(when: datetime, months: int) -> datetime:
    """`when` shifted by whole months, keeping the day at 1. Callers pass month starts."""
    index = (when.year * 12 + when.month - 1) + months
    return when.replace(year=index // 12, month=index % 12 + 1, day=1)


def month_start(when: datetime) -> datetime:
    """The first instant of `when`'s month, in UTC. The partition boundary.

    UTC because every `ts` in this schema is written from `datetime.now(timezone.utc)`,
    and a boundary that depended on a server's local zone would put two deployments'
    partitions in different places for the same data. An aware datetime in any other zone
    is converted first, so a timestamp half an hour into September in Tokyo floors to
    August — the month it is in UTC, which is the month its partition is named for.

    **A naive datetime is refused rather than assumed.** `astimezone` on one silently
    reads it as the *server's local* time, which shifts the answer by up to a day and,
    within a day of a month boundary, by a whole month — so a retention sweep on a
    machine east of UTC would drop a month it was never asked to drop. That is a wrong
    answer with no symptom, in the one operation in this product that destroys records
    somebody may later be asked to produce. `check_prune_batch`'s argument, which this
    step deleted for a different reason, applies here exactly: this is reachable from a
    public storage method and the next caller will not know.
    """
    if when.tzinfo is None or when.tzinfo.utcoffset(when) is None:
        raise StorageError(
            f"a retention boundary must be an aware datetime, not {when!r}. A naive one "
            "would be read as this server's local time, which lands in a different month "
            "either side of a boundary — and the answer decides which records are "
            "destroyed. Pass datetime.now(timezone.utc), or attach a tzinfo."
        )
    return when.astimezone(timezone.utc).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )


def log_partition_months(back_to: datetime | None = None, *, now: datetime | None = None):
    """Every month a log partition should exist for, oldest first.

    From `back_to`'s month — or the month before this one, whichever is earlier —
    through this month plus `PARTITION_HORIZON_MONTHS`.

    **The previous month is always included**, which costs one empty partition and closes
    the boundary case a monthly scheme otherwise has: a record stamped at 23:59:59 on the
    last day of a month, inserted a second after midnight, belongs to a month that is no
    longer the current one. `back_to` is for the callers that write a back-dated world on
    purpose — the retention tests and the e2e scripts — because production writers stamp
    `now` and never need it.
    """
    now = now or datetime.now(timezone.utc)
    start = month_start(now)
    first = min(start if back_to is None else month_start(back_to), _add_months(start, -1))
    last = _add_months(start, PARTITION_HORIZON_MONTHS)

    months = []
    while first <= last:
        months.append(first)
        first = _add_months(first, 1)
    return months


def prune_floor(cutoff: datetime) -> datetime:
    """The boundary a retention sweep actually applies: the start of `cutoff`'s month.

    **Both stores call this, and that is the whole point of it existing.** Since
    migration 030 a prune is a partition drop, and a partition is a whole month — so
    Postgres can only remove a month once the cutoff has passed all of it. The in-memory
    store could delete at the exact instant and would then disagree with the real one
    about which records survive a sweep, which is the drift the contract suite exists to
    catch. One function, two callers, one answer.

    **What it costs, stated rather than buried:** a record outlives its window by up to
    a month plus one sweep interval. The window was always a floor rather than a
    ceiling — nothing ever promised deletion *at* the boundary, only after it — and this
    makes the size of that gap explicit. A contract that needs day-grained deletion is
    the register's named-customer trigger, not a change to this function.

    Strictly `<` survives at the coarser scale: a record stamped exactly at the floor
    lives in the month that begins there, which is the month being kept. A boundary has
    to have one answer, and it is still the same answer.
    """
    return month_start(cutoff)


def missing_partition(table: str, detail: str) -> str:
    """The sentence an append gets when its month has no partition. Migration 030.

    The loud failure that backs the decision *not* to create partitions on the write
    path: DDL inside an append would take a lock on the parent for the length of the
    caller's transaction, and `_write_admin` rides the caller's transaction by design —
    so every log write in the product would serialise behind one partition creation.

    Three things keep this from happening (the migration seeds a horizon, opening a store
    repairs it, and the worker's sweep maintains it), and if all three are missed the
    write fails naming the fix rather than guessing at one.
    """
    return (
        f"no partition of '{table}' covers this record's timestamp: {detail}. "
        "Log tables are partitioned by month and coverage is created ahead of time — "
        "call storage.ensure_log_partitions() (a worker sweep and opening a store both "
        "do) and retry. A back-dated write needs ensure_log_partitions(back_to=...)."
    )

# What a `tenant_tombstones` row holds, in the order both stores return it. Migration
# 029, and the `AGENT_FIELDS` / `RUN_FIELDS` device: written once so a column added to
# the table and forgotten in a store is a contract-suite failure rather than a drift.
TOMBSTONE_FIELDS = ("tenant_id", "name", "deleted_at", "actor", "detail")

# `detail`'s version, on `ADMIN_AUDIT_V`'s argument: it is what makes a later reader a
# filter on a field rather than a guess from which keys are present.
TOMBSTONE_V = 1

# Who may ACT. A principal owns a run, appears in an audit record, and — the reason
# this set must stay closed — holds a delegated credential sealed to
# `(tenant, principal, connector)`.
#
# **A group is not in here and adding one is not a widening, it is an inversion.** Step
# 7a's whole point is that a credential belongs to one person; a group credential is an
# operator credential wearing a team's name. Migration 017 puts the same three words into
# CHECK constraints on `connections`, `runs` and `audit`, so this frozenset is no longer
# the only thing standing there — which it was, silently, from 004 until then.
#
# **`machine` arrives with step 020 and is the first kind reachable over HTTP that is not
# a person.** Widening this set is therefore not the whole change and must not be treated
# as one: migration 031 widens six CHECK constraints and deliberately leaves two narrow,
# and the two Python guards below (`check_platform_role`, `split_actor`) are what keep
# the in-memory store refusing what Postgres refuses. Editing this line alone makes the
# fake looser than the real store in exactly those two places.
PRINCIPAL_KINDS = frozenset({"user", "system", "machine"})

# --- the three audit vocabularies, step 066 -----------------------------------------
#
# `decision`, `outcome` and `identity_source` are closed sets with CHECK constraints
# behind them — migrations 004/030 for the first two, 041 for the third — and until now
# they existed **only** in SQL. That was survivable while nothing in Python had to decide
# whether a value was in the set. `GET /admin/door-calls` gaining filters is what ends
# it: the route validates the closed vocabularies by its signature, and the one thing
# that must not happen is a hand-written `Literal` beside a CHECK it can drift from.
#
# That is not hypothetical here. `AgentAccessEntry.kind` was written out by hand against
# `GRANTEE_KINDS`, went stale, and the first share sheet holding a machine grantee
# answered 500 with everything below it correct — which is why `/admin/denials` derives
# its `resource_kind` filter from `DENIAL_RESOURCE_KINDS` rather than typing it again.
# These three sets are that pattern applied before the bug rather than after it: a value
# added to a CHECK and to one of these becomes filterable without anybody remembering to
# go and look, and — the direction that matters more — cannot be forgotten here while
# being accepted there.
#
# They are `frozenset`s, sorted at the point of use, for `PRINCIPAL_KINDS`' reason: the
# set is the fact and the order is the presentation.

# What the broker decided. Two values, and the CHECK has held them since migration 004.
DECISIONS = frozenset({"allow", "deny"})

# What happened to a call the broker admitted. **`''` is a member**, and that is the
# awkward part of this set rather than an oversight: the column is `NOT NULL DEFAULT ''`
# and a refused call has no outcome to report, so the empty string is a real stored value
# and a filter that could not express it could not ask "the ones nothing was recorded
# for". `unknown` is likewise a stored value that no screen has ever drawn.
# `aborted` since migration 055: a streamed call the caller walked away from. Step 108.
OUTCOMES = frozenset({"", "ok", "error", "oversize", "unknown", "aborted"})

# What an acting-for claim was worth. 033c's three, and they are **never collapsed** —
# a filter that offered "named" as one value would merge `verified` and `asserted`, which
# is the upgrade the three-valued column exists to prevent.
IDENTITY_SOURCES = frozenset({"verified", "asserted", "none"})

# Who may perform an ADMINISTRATIVE act — the actor of an `admin_audit` row. A subset,
# and the subset is the point: `machine` is missing, matching `admin_audit.actor_kind`'s
# CHECK, which migration 031 pointedly did not widen.
#
# No code path lets a machine reach a method that writes one of these records, so this
# refuses something nothing currently attempts. That is what a tripwire is: the day some
# route hands a machine principal to a storage method that logs, this is the sentence
# rather than a constraint name from Postgres and a 503 in the fake's absence.
ADMIN_ACTOR_KINDS = frozenset({"user", "system"})

# Who may be GRANTED. A superset, and the distinction is the load-bearing decision of
# step 9a: you grant *to* a group, and nothing ever acts *as* one.
#
# Only `agent_grants` validates against this. Everything else validates against the set
# above, and migration 017's CHECK constraints mean that stays true even if somebody
# edits this file.
#
# `machine` is here because that is the entire design of step 020: a machine caller is
# not an exemption from the grant model, it is a grantee. What it may be granted is
# capped at `user` by `check_grant` and by `agent_grants_no_machine_above_user` — see
# `MACHINE_ROLES`.
GRANTEE_KINDS = frozenset({"user", "system", "group", "machine"})

# What a machine may be granted. `GROUP_ROLES`' argument at a different address: a
# machine runs an agent, and editing or re-sharing one is an act with somebody's judgment
# in it — judgment that should not live in a CI variable. Widening this later is
# additive; narrowing it after a customer has granted `editor` to a pipeline is not.
MACHINE_ROLES = ("user",)

# What a group may be granted. Not `owner`, for the reason `PENDING_ROLES` is not either:
# an agent owned by something that cannot be held accountable is an orphan. Everyone in
# the group could delete it, nobody answers for it, and `transfer` has no meaning when
# the recipient is a set.
GROUP_ROLES = ("user", "editor")

# The sharing ladder, weakest first. **Order is the meaning** — index is the level, so a
# check is one comparison rather than a matrix. See migration 011 for why these are not
# called viewer/editor/owner.
#
# This lives here, at the bottom, because both stores validate against it and the
# contract suite compares their refusals. What each level *permits* is policy and lives
# in `access/grants.py`; storage only knows the set is closed and ordered.
AGENT_ROLES = ("user", "editor", "owner")

OWNER_ROLE = "owner"

# What somebody may hold over the **tenant** rather than over an agent, from migration
# 026. A tuple like `AGENT_ROLES` — ordered-and-closed by convention, with the CHECK in
# the column and the tuple here so both stores refuse alike.
#
# **One value, and the set is closed on purpose.** Every feature waiting on this needs the
# same answer — *may this person administer this tenant* — and no customer has asked to
# split it. A matrix invented now is guessed granularity, and the two directions are not
# symmetric: collapsing a wrongly split role is a breaking change to somebody's
# configuration, where widening one role into a matrix later is additive.
#
# **This ladder does not meet `AGENT_ROLES` anywhere**, and that is the property worth
# stating in the same file as both. Holding `admin` grants access to no agent, no run and
# no connection; `grants.require` never consults this table and `require_admin` never
# consults that one. See migration 026 for why 7b makes that boundary non-negotiable.
PLATFORM_ROLES = ("admin",)

ADMIN_ROLE = "admin"

# `agent_name_is_a_slug`, from migration 019. Here rather than in `agents/` because the
# constraint is on the column and both stores have to refuse the same names as Postgres
# — the meaning of the shape is documented in the migration, which is where somebody
# widening it has to go anyway.
#
# **Since migration 035 this is a rule about a *label*, not about a key.** Everything the
# sentence in `check_agent_name` says is still true — it is the URL and the audit string —
# and one thing it used to say is not: the name is no longer what the row is stored under.
AGENT_NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
AGENT_NAME_MAX = 64

# Migration 035. An agent's identity, which is not its name.
#
# `a_` + 16 hex, which is `access/users.py`'s `u_` and `access/groups.py`'s `g_` to the
# character — including the argument, which 017 put best: *never derived from the name; a
# group that is renamed is the same group, and every grant naming it has to survive the
# rename untouched.* Agents were the last long-lived entity in this schema keyed by their
# display string, and 035 is where that ends.
#
# The regex is `agent_id_is_opaque` from that migration, in Python for `AGENT_NAME_RE`'s
# reason: both stores mint these, and a fake that minted a shape Postgres refuses would be
# permissive in the one direction `memory.py` forbids.
AGENT_ID_PREFIX = "a_"
AGENT_ID_HEX = 16
AGENT_ID_RE = re.compile(rf"^{AGENT_ID_PREFIX}[0-9a-f]{{{AGENT_ID_HEX}}}$")


def new_agent_id() -> str:
    """One agent identity. `uuid4`, exactly as a user id and a group id are minted.

    Not derived from the name, the tenant, the clock or the config — the whole point of
    the column is that nothing about it can change when any of those do.
    """
    return f"{AGENT_ID_PREFIX}{uuid.uuid4().hex[:AGENT_ID_HEX]}"


def check_agent_id(agent_id) -> None:
    """`agent_id_is_opaque`, from migration 035, in Python. Raises `StorageError`.

    Reached by callers that pass an id rather than mint one — the fake's re-key checks and
    anything reconstructing a world in a test. The message is written for a developer
    because there is no path from a person's keyboard to this value: an agent id is minted
    by `new_agent_id` and never typed.
    """
    if not agent_id or not isinstance(agent_id, str):
        raise StorageError(
            "an agent row must have a non-empty string 'agent_id'; it is the key the row "
            "is stored under and the thing five other tables reference"
        )

    if not AGENT_ID_RE.fullmatch(agent_id):
        raise StorageError(
            f"'{agent_id}' is not an agent id. They are minted by `new_agent_id` as "
            f"'{AGENT_ID_PREFIX}' followed by {AGENT_ID_HEX} hex characters and are never "
            "derived from anything a person can change — see migration 035."
        )

# What may be addressed to somebody who has not logged in yet. Not `owner`: ownership is
# transferred rather than granted, and transferring an agent to a row that may never be
# claimed is an orphan created on purpose. See migration 012.
PENDING_ROLES = ("user", "editor")

# What a run can be. The CHECK constraint from migration 015, where each value is
# documented alongside what a person does about it. Nothing writes `cancelled` or
# `interrupted` yet; both are here because the vocabulary is schema.
RUN_STATUSES = frozenset(
    {
        "queued",
        "running",
        "complete",
        "incomplete",
        "failed",
        "cancelled",
        "interrupted",
    }
)

# A run in one of these is over and its row will not change again. `interrupted` counts:
# nothing more will happen to it *automatically*, which is exactly the point — it needs a
# person, and resubmission is a new run with a new id rather than a retry of this one.
TERMINAL_RUN_STATUSES = frozenset(
    {"complete", "incomplete", "failed", "cancelled", "interrupted"}
)

# What `request_cancel` will accept, and it is **not** the complement of the above.
#
# `cancelled` is terminal and still cancellable, which looks like a contradiction and is
# a bug fix. A queued run cancelled outright *is* `cancelled` a microsecond later, so a
# client retrying its own request — the retry every enterprise HTTP stack makes — hit an
# already-terminal row and got a 409 reporting a failure where nothing had failed. Asking
# to cancel something already cancelled is the definition of a repeat of one intent, and
# the idempotency work already settled that a repeat is not an error.
#
# Found by running the command twice, which is the only way this shows up: every test
# that cancelled a queued run cancelled it once.
CANCELLABLE_RUN_STATUSES = frozenset({"queued", "running", "cancelled"})

RUN_REQUIRED = ("run_id", "agent", "principal_kind", "principal_id")

# Every field a `runs` row carries, in the order both stores return it.
#
# Written down here and used by both, for the reason `_AUDIT_COLUMNS` in postgres.py
# exists: the table has fixed columns and the in-memory store keeps whatever dict it is
# handed, so a field added to one and forgotten in the other is written by one
# implementation and **silently dropped** by the other. That is exactly how
# `audit.credential` shipped, with 818 tests green.
#
# The contract suite asserts that a round-tripped row has these keys and no others, in
# both stores — so the next forgotten column fails without anybody remembering to
# extend a list.
RUN_FIELDS = (
    "run_id",
    "tenant_id",
    # The agent's **name as submitted**, and it stays that. Migration 015 argued the
    # missing foreign key — a run is history and must survive its agent — and 035 leaves
    # this column doing what it has always done: recording what a person asked for, in the
    # words they asked for it. For a run whose agent has since been deleted it is the only
    # thing left that says what ran.
    "agent",
    # Migration 035, and **nullable with no foreign key**, for `agent`'s own reason. What
    # it adds is a spine: four comparisons used to be made on the name — the worker's
    # config load, run-list visibility, the follow-up turn's parent check and idempotency
    # conflict detection — and each of them silently changed meaning across a rename, while
    # two of them changed meaning across a delete-and-recreate. NULL is a run whose agent
    # was already gone when 035 ran; nothing new can be said about those and nothing tries.
    "agent_id",
    "principal_kind",
    "principal_id",
    "task",
    "status",
    "answer",
    "error",
    "idempotency_key",
    "claimed_by",
    "claimed_at",
    "lease_expires_at",
    "attempt",
    "created_at",
    "started_at",
    "finished_at",
    # Migration 016. Two fields because they are two facts: when somebody asked, and —
    # in `status` — whether the run has actually stopped yet. See `request_cancel`.
    "cancel_requested_at",
    "cancelled_by",
    # Migration 027: a run that continues a run. `parent_run_id` is NULL for a root;
    # `root_run_id` is the parent's root or the run's own id, written once at insert
    # and never updated. `thread_shared` is meaningful on root runs only and is the
    # one of the three that mutates — see `set_thread_shared`.
    "parent_run_id",
    "root_run_id",
    "thread_shared",
    # Migration 036: the file this run was given, or ''. **No foreign key**, which is
    # `agent`'s rule and for `agent`'s reason — a run is history, and deleting a file
    # must not delete the record of the run that read it.
    "file_id",
    # Migration 038: what a running run is doing right now —
    # `{"v": 1, "turn": N, "doing": "model"|"tools", "since": iso8601}` — or None.
    # Written by the runtime at its turn transitions through `note_activity`, nulled on
    # every path to a terminal status. **Current state, deliberately not a history**;
    # the history of tool calls is the audit trail.
    "activity",
    # Migration 045, step 013: what the run spent at the model. Written once, by
    # `finish_run`, from the meter the runtime accumulated — see `USAGE_FIELDS` below
    # and `core/usage.py` for why there are four token columns rather than 013's three.
    #
    # `model` is what the *reply* said it was served by, which is not always what the
    # config asked for. '' and 0 on every run that predates the migration, and on every
    # run that never reached a model call — honest in both cases, and the reason
    # `core/usage.py`'s report half did, before step 084 deleted it.
    "model",
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "peak_context_tokens",
)


# The six columns `finish_run` writes from a meter, and the only place their names are
# spelled out. `core/usage.Meter.snapshot()` produces exactly this set of keys, both
# stores consume it through `normalize_usage`, and the contract suite asserts the two
# agree — which is `RUN_FIELDS`' own device applied to the half of a row that arrives as
# a dict rather than as parameters.
USAGE_FIELDS = (
    "model",
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "peak_context_tokens",
)

# The five that accumulate across attempts. `model` is not a quantity and
# `peak_context_tokens` is a maximum rather than a sum — see `finish_run`.
USAGE_COUNTERS = (
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
)


# Step 028. What `create_file` is handed — everything the row needs, content included.
FILE_FIELDS = (
    "id",
    "owner_kind",
    "owner_id",
    "filename",
    "media_type",
    "content",
    "sha256",
    "byte_size",
)

# What a read gives back. **`content` is absent by design** — the bytes have exactly one
# reader, `file_content`, called once per run by the worker. Everything that merely
# *describes* a file is here, so no screen, no ownership check and no idempotency
# comparison has a reason to drag 10 MiB off TOAST.
FILE_META_FIELDS = (
    "id",
    "tenant_id",
    "owner_kind",
    "owner_id",
    "filename",
    "media_type",
    "sha256",
    "byte_size",
    "created_at",
)


# --- shared coercion --------------------------------------------------------------
#
# Both implementations call these, so a row means the same thing whichever store it
# lands in. Written here rather than duplicated because the contract suite compares
# round-tripped rows for equality, and two normalizers that drift by a default are
# exactly the kind of difference a fake hides until production.


def check_allowed_domains(issuer: str, allowed_domains) -> None:
    """Refuse `"*"` on any issuer but the local provider's.

    A wildcard means *this provider may vouch for any address on earth*, and step 016
    introduced it provider-agnostically — a row is data, and the CLI warned. Under an
    enterprise premise that warning is a control that lies: `--add-idp` writes the row for
    a customer's Okta just as happily, and the result inverts what 005 built the domain
    list to say. The gate exists so one customer's provider cannot vouch for another
    customer's data; a wildcard on it is that boundary switched off by a flag.

    It stays legitimate for exactly one issuer, and the asymmetry is real rather than a
    carve-out: the local provider **is** the account authority. Its registration form
    decides who may hold an account at all, so a domain check there refuses the first
    teammate on a personal address and protects nothing. Every other issuer belongs to
    somebody whose directory we do not control.

    Keyed on the issuer rather than on a mode, because a mode is a fact about how the
    process started and this has to be a fact about the row — the row outlives the process
    that wrote it, and `--local` against a customer's DSN writes one into their database.
    """
    if LOCAL_ISSUER_WILDCARD_OK in {"*", ""}:  # pragma: no cover - guards a bad edit
        raise StorageError("LOCAL_ISSUER_WILDCARD_OK must name a real issuer")
    if "*" in tuple(allowed_domains or ()) and issuer != LOCAL_ISSUER_WILDCARD_OK:
        raise ValueRefused(
            f"'*' is not an allowed email domain for '{issuer}'. A wildcard lets that "
            "provider create an account for any address it will vouch for, which is the "
            "domain gate switched off rather than widened. Name the domains this "
            "customer owns."
        )


def normalize_idp(idp: dict) -> dict:
    """Validate and fill in a `tenant_idps` row. Raises `StorageError` on nonsense."""
    missing = [field for field in IDP_REQUIRED if not idp.get(field)]
    if missing:
        raise StorageError(
            f"identity provider is missing {missing}. An issuer identifies it, a "
            "jwks_uri is where its keys live, and an audience is what makes a token "
            "ours rather than merely valid."
        )

    row = {**IDP_DEFAULTS, **{k: v for k, v in idp.items() if v is not None}}

    claim = row.get("discriminator_claim")
    value = row.get("discriminator_value")
    if (claim is None) != (value is None):
        # The CHECK constraint, in Python. A claim with no value routes nothing; a
        # value with no claim names no field to read it from.
        raise StorageError(
            "discriminator_claim and discriminator_value must be given together or "
            "not at all. One without the other cannot route anything."
        )

    row["discriminator_claim"] = claim
    row["discriminator_value"] = value
    row["allowed_domains"] = tuple(row.get("allowed_domains") or ())
    row["enabled"] = bool(row.get("enabled", True))
    # Here rather than in the CLI, on the lesson this repo has now recorded three times:
    # a guard in an entry point is a guard the next entry point does not have. Both stores
    # call this function, so the refusal covers `--add-idp`, the local front door, the
    # contract suite and whatever registers a provider next.
    check_allowed_domains(row["issuer"], row["allowed_domains"])
    return {k: row[k] for k in (*IDP_REQUIRED, *IDP_DEFAULTS)}


# How long a directory group id may be. Entra emits a 36-character GUID and Okta a
# group name; 256 leaves room for a distinguished name. **Here rather than in
# `access/directory.py`** so the bound is the same at both ends — the edge-case pass
# found it enforced when *reading* a claim and not when *writing* an id, so a group
# could be linked to a 5000-character value no token could ever carry.
EXTERNAL_ID_MAX = 256


def normalize_external_id(external_id: str | None) -> str | None:
    """A group's directory id, as it will be compared. `None` means *not linked*.

    Both writers call this — `create_group` and `set_group_external_id`, in both stores —
    on the lesson `check_allowed_domains` is placed by: *a guard in an entry point is a
    guard the next entry point does not have*. The edge-case pass found exactly that,
    with `link` stripping and `create` not, so `POST /groups` could store `"dir-eng\\n"`.

    Two rules, and each closes a group that could never work:

    - **Stripped**, because the id is matched byte for byte against a token claim at
      sign-in (migration 007's rule about the issuer, one column over) and a value pasted
      out of an admin console arrives with a newline more often than not. A padded id
      matches nothing, so the directory could never fill the group — and the seam that
      refuses hand-adds to a linked group would then leave it unfillable by anybody.
    - **Blank is refused, and `None` is not blank.** `GROUP_FIELDS` already says NULL and
      `''` are different states; `''` is `IS NOT NULL`, so a group linked to it appears
      to the reconciliation and no claim value can ever match it (`_values` drops empty
      strings), which makes it a group that removes every person at each sign-in. `None`
      is how *not linked* is spelled, and it stays the only spelling.
    """
    if external_id is None:
        return None

    cleaned = external_id.strip()
    if not cleaned:
        raise ValueRefused(
            "a directory group id cannot be blank. To stop following the directory, "
            "unlink the group explicitly — that keeps everybody who is in it now."
        )

    if len(cleaned) > EXTERNAL_ID_MAX:
        raise ValueRefused(
            f"a directory group id may be {EXTERNAL_ID_MAX} characters; this one is "
            f"{len(cleaned)}. A claim carrying a longer value is refused at the other "
            "end too, so a group linked to one could never be filled."
        )

    # A control character in this value would ride into a refusal sentence, the
    # `--groups` table and every log line the reconciliation writes — and a NUL cannot
    # be stored in a Postgres TEXT at all, which arrives as a `StorageError` and is
    # rendered *"storage unavailable: try again later"* about a value that will never be
    # accepted. Refused here, where the sentence can say which character and why.
    bad = next((ch for ch in cleaned if ch < " " or ch == "\x7f"), None)
    if bad is not None:
        raise ValueRefused(
            f"a directory group id may not contain control characters (found "
            f"{bad!r}). Paste the id your directory shows, without the line break."
        )

    return cleaned


def normalize_user_external_id(external_id: str | None) -> str | None:
    """A person's directory id, as it will be compared. `None` means *not linked*.

    `normalize_external_id`'s rules — stripped, blank refused, bounded, no control
    characters — with one difference that is the whole reason for a second function:
    **blank becomes None rather than a refusal.** A group unlinked by `''` was a group
    that removed everybody at each sign-in, so 033e refused it. A person's `externalId`
    is only ever a lookup key, a blank one matches nobody, and a push that sends `""`
    for a field it has no value for is a push saying *none* — which is what None means.
    """
    if external_id is None:
        return None

    cleaned = external_id.strip()
    if not cleaned:
        return None

    if len(cleaned) > EXTERNAL_ID_MAX:
        raise ValueRefused(
            f"a directory user id may be {EXTERNAL_ID_MAX} characters; this one is "
            f"{len(cleaned)}. Nothing a directory sends is that long, so this is a "
            "value that arrived in the wrong field."
        )

    bad = next((ch for ch in cleaned if ch < " " or ch == "\x7f"), None)
    if bad is not None:
        raise ValueRefused(
            f"a directory user id may not contain control characters (found "
            f"{bad!r})."
        )

    return cleaned


def normalize_user(user: dict) -> dict:
    """Validate and fill in a `users` row.

    `subject` is optional since migration 052 — a provisioned row has none yet — and
    when it is given it is stripped and may not be blank, because `find_user` refuses
    to match a blank one and a row stored with one could never be signed into.
    """
    missing = [field for field in ("id", "issuer") if not user.get(field)]
    if missing:
        raise StorageError(
            f"user is missing {missing}. Identity is (issuer, subject); `id` is ours "
            "and opaque, and becomes Principal.id in every audit record."
        )

    subject = user.get("subject")
    if subject is not None:
        if not isinstance(subject, str) or not subject.strip():
            raise StorageError(
                "a user's subject may be absent — a provisioned person has not signed "
                "in yet — but it may not be blank: `find_user` never matches a blank "
                "subject, so a row stored with one could never be signed into."
            )
        subject = subject.strip()

    status = user.get("status") or "active"
    if status not in USER_STATUSES:
        raise StorageError(f"status must be one of {sorted(USER_STATUSES)}")

    return {
        "id": user["id"],
        "issuer": user["issuer"],
        "subject": subject,
        "external_id": normalize_user_external_id(user.get("external_id")),
        "email": user.get("email") or "",
        "display_name": user.get("display_name") or "",
        "status": status,
    }


def normalize_scim_token(row: dict) -> dict:
    """Validate a `scim_tokens` row. Migration 052.

    `normalize_api_token`'s job for the directory's credential, and the same two rules
    for the same reasons: every field is required — there is no such thing as an
    unbound or unnamed token — and the id may not contain the separator, because the
    presented credential is `ars_<id>.<secret>` split on the first one.

    Both stores call it, so a row one implementation accepts is not one the other
    quietly rejects.
    """
    missing = [
        field
        for field in ("id", "issuer", "name", "secret_hash", "created_by")
        if not row.get(field)
    ]
    if missing:
        raise StorageError(
            f"scim token is missing {missing}. `id` is ours and becomes the actor "
            "`system:scim:<id>` in every record the directory writes; `issuer` is "
            "the provider whose pushes it speaks for, and `created_by` is the person "
            "answerable for minting it."
        )

    if API_TOKEN_SEPARATOR in row["id"]:
        raise StorageError(
            f"a scim token id may not contain '{API_TOKEN_SEPARATOR}': it is what "
            "separates the id from the secret in the credential the directory "
            "presents, so an id carrying one could never be parsed back out of it."
        )

    name = row["name"].strip()
    if not name:
        raise ValueRefused("a scim token needs a name: it is what `--list-scim-tokens` shows")

    return {
        "id": row["id"],
        "issuer": row["issuer"],
        "name": name,
        "secret_hash": row["secret_hash"],
        "created_by": row["created_by"],
    }


def check_name_is_text(name, *, what: str) -> None:
    """Refuse a name a TEXT column cannot hold or a page cannot render. Raises `ValueRefused`.

    Step 087. Three things, one rule, because each is a value a caller typed and can
    fix and each answered as something else:

    - a **NUL** — no Postgres text column holds one, so the real store answered *503,
      storage unavailable* while the fake stored it: migration 007's direction of drift.
    - a **lone surrogate** — `json.loads` produces one from the six ASCII bytes `\\ud800`,
      so it arrives from any client that writes the escape, and UTF-8 cannot encode it:
      the driver raised `UnicodeEncodeError` and the route answered **500**. Two register
      rows said this half was unreachable over HTTP; it was reachable from `curl`.
    - any other **control character** — stored fine, then rendered as a line break or a
      bell on the tokens page and in `--list-tokens`. 083's rule for `client_name`, for
      083's reason: the name exists to be read by somebody deciding what to revoke.

    `check_config_is_storable` is the same rule for a jsonb value; this is the scalar
    form for the TEXT columns a person names something through.
    """
    if not isinstance(name, str):
        raise ValueRefused(f"{what} must be a string, not {type(name).__name__}.")
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueRefused(
            f"{what} contains an unpaired surrogate, which no text column can hold "
            "and no UTF-8 encoder can write. It is the `\\ud800` escape a JSON body can "
            "carry; remove it."
        ) from None
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
        raise ValueRefused(
            f"{what} may not contain control characters. It is shown on a page and "
            "printed in a list; a NUL cannot be stored at all and a line break makes "
            "the list unreadable."
        )


def personal_name_taken(name: str) -> str:
    """The refusal for migration 054's per-owner index, in both stores' words.

    One sentence, defined once, because the two stores raise it from different places —
    the fake from a loop, Postgres from a constraint name — and the CLI, the tokens page
    and `e2e_team_journey` all quote it. *This owner*, not *this customer*: the name is
    unique among the owner's live personal tokens and nobody else's, which is the whole
    of what 054 changed.
    """
    return (
        f"this owner already has a live personal token called '{name}'. The name is what "
        "they read on their tokens page when deciding which to revoke, so two live rows "
        "sharing one makes that decision a guess. Revoking the old one frees the name "
        "for its replacement."
    )


def service_name_taken(name: str) -> str:
    """The refusal for the customer-wide index a service token still lives under."""
    return (
        f"this customer already has a live API token called '{name}'. The name is what "
        "somebody reads when deciding which token to revoke, so two live rows sharing "
        "one makes that decision a guess. Revoking the old one frees the name for its "
        "replacement."
    )


def normalize_api_token(token: dict) -> dict:
    """Validate and fill in an `api_tokens` row. Migration 031.

    `expires_at` is the only optional field and `None` is a real value meaning *no
    expiry* — deliberately not defaulted, because an expiry nobody diarised is a cron
    job that stops at 3am, and revocation is the control that actually works. A naive
    datetime is refused on `check_connection`'s precedent: a boundary compared against
    `now(timezone.utc)` must know its own zone.
    """
    missing = [
        field
        for field in ("id", "name", "owner_id", "secret_hash")
        if not token.get(field)
    ]
    if missing:
        raise StorageError(
            f"api token is missing {missing}. `id` is ours and opaque and becomes "
            "Principal.id in every record the machine writes; `owner_id` is the person "
            "answerable for it, and there is no such thing as an unowned token."
        )

    # Step 087: a NUL was a 503 and a lone surrogate a 500, from three writers, and
    # the fake stored both. The rule is the row's, so it is here rather than in each.
    check_name_is_text(token["name"], what="a token's name")

    # **The id may not contain the separator.** A presented credential is
    # `art_<id>.<secret>` split on the FIRST separator, so an id carrying one would make
    # the two halves ambiguous — the id would be truncated and the rest of it read as the
    # start of the secret.
    #
    # Unreachable from `tokens.mint`, which builds `m_` plus hex, and refused here anyway
    # for `check_prune_batch`'s reason: this is a public method on the storage protocol
    # and the next caller will not know that. Found by an edge hunt, not by a caller.
    if API_TOKEN_SEPARATOR in token["id"]:
        raise StorageError(
            f"an api token id may not contain '{API_TOKEN_SEPARATOR}': it is what "
            "separates the id from the secret in the credential a machine presents, so "
            "an id carrying one could never be parsed back out of it."
        )

    expires_at = token.get("expires_at")
    if expires_at is not None:
        if not isinstance(expires_at, datetime):
            raise StorageError("api token 'expires_at' must be a datetime or None")
        if expires_at.tzinfo is None:
            raise StorageError(
                "api token 'expires_at' must be timezone-aware. A naive value is read "
                "as server-local time, which moves the moment a credential stops "
                "working by however far the deployment is from UTC."
            )

    # Step 033d. A real bool, refused rather than coerced: this is the column three
    # readers redirect on (grants, credentials, the door's refresh), and a truthy
    # string arriving here would make "personal" a fact about how a caller spelled it.
    acts_as_owner = token.get("acts_as_owner", False)
    if not isinstance(acts_as_owner, bool):
        raise StorageError(
            "api token 'acts_as_owner' must be a bool. It decides whose grant rows "
            "answer for this token, so it is a decision, never a coercion."
        )

    return {
        "id": token["id"],
        "name": token["name"],
        "owner_id": token["owner_id"],
        # Step 083: how the mint came about, for the record's detail and nothing else.
        # Empty for the CLI and the tokens page; `oauth:<client_id>` for a consent.
        "via": str(token.get("via") or ""),
        "acts_as_owner": acts_as_owner,
        "secret_hash": token["secret_hash"],
        "expires_at": expires_at,
    }


def check_agent_name(name) -> None:
    """`agent_name_is_a_slug`, from migration 019, in Python.

    Called by **both** write paths, not only by `create_agent`. The CHECK constraint is
    on the column, so Postgres refuses a bad name on an upsert too — and a fake that
    accepted one would be more permissive than the real store in the one direction
    `memory.py`'s docstring forbids.

    The sentence is written for whoever typed the name, because in 10c that is a person
    at a form rather than a developer at a config file. It says what the rule *is* rather
    than showing the regex: somebody who does not know what `^[a-z0-9]+(-[a-z0-9]+)*$`
    means is exactly the person this message exists for.
    """
    if not name or not isinstance(name, str):
        raise StorageError(
            "agent config must have a non-empty string 'name'; it is the key the row is "
            "stored under and the identity the broker enforces against"
        )

    if len(name) > AGENT_NAME_MAX:
        raise StorageError(
            f"agent name '{name}' is {len(name)} characters; the limit is "
            f"{AGENT_NAME_MAX}. It goes in a URL and into every audit record this agent "
            "ever produces."
        )

    if not AGENT_NAME_RE.fullmatch(name):
        raise StorageError(
            f"'{name}' is not a usable agent name. Use lowercase letters, digits and "
            "single hyphens between them — 'triage-bot', not 'Triage Bot'. The name is "
            "the URL of this agent and the string in every record of what it did, so "
            "two names that look alike in a list must not be different rows."
        )


def check_principal_kind(kind: str) -> None:
    """Who may ACT. Guards runs, audit, connections and group membership.

    The message names `group` explicitly when that is what arrived, because the two most
    likely ways to get here are a caller who meant `agent_grants` and a caller who is
    about to try nesting groups — and "must be one of ['system', 'user']" answers
    neither.
    """
    if kind not in PRINCIPAL_KINDS:
        extra = (
            ". A group is a grantee, never a principal: it may hold a grant, and it may "
            "not act, own a run, appear in an audit record, or hold a credential."
            if kind == "group"
            else ""
        )
        raise StorageError(
            f"principal_kind must be one of {sorted(PRINCIPAL_KINDS)}, not "
            f"'{kind}'{extra}"
        )


def check_audit_tokens(record: dict) -> None:
    """Migration 048's `audit_tokens_are_not_negative`, in Python. Step 045b.

    Here for `check_principal_kind`'s reason one field over: *a fake that is more
    permissive than the real store is a fake that lies in the direction that matters*. The
    constraint is the thing that actually guarantees it; this is what makes the in-memory
    store refuse the same record, with the sentence rather than a constraint name.

    A negative counter is the one bad value in this column that costs money rather than
    looking obviously broken: it **subtracts** from the sum the door's spend ceiling
    reads, so a connector reporting `-1_000_000` would hand its caller an allowance nobody
    granted. `core.usage.parse_report` refuses it before the broker ever gets here; this
    is the floor under that.

    NULL is legal and is the ordinary case — a call that touched no model. See
    `normalize_audit_record` for why that is not zero.
    """
    for column in ("input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens"):
        value = record.get(column)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, int):
            raise StorageError(
                f"audit '{column}' must be a whole number of tokens or NULL, not "
                f"{value!r}"
            )
        if value < 0:
            raise StorageError(
                f"audit '{column}' must not be negative, and this record carries "
                f"{value}. A negative counter subtracts from the spend the door's "
                "ceiling reads, which is an allowance nobody granted."
            )


def check_grantee_kind(kind: str) -> None:
    """Who may be GRANTED. Guards `agent_grants` and nothing else."""
    if kind not in GRANTEE_KINDS:
        raise StorageError(
            f"grantee_kind must be one of {sorted(GRANTEE_KINDS)}, not '{kind}'"
        )


def check_grant(grantee_kind: str, role: str) -> None:
    """The pair, because one of the rules is about the combination.

    A group at `owner` is refused here and by `agent_grants_no_group_owner` in migration
    017. Both, deliberately: the CHECK is what survives somebody editing `GROUP_ROLES`,
    and this is what produces a sentence rather than a constraint name for the person who
    typed the command.
    """
    check_grantee_kind(grantee_kind)
    check_agent_role(role)

    if grantee_kind == "group" and role not in GROUP_ROLES:
        raise StorageError(
            f"a group may be granted {list(GROUP_ROLES)}, not '{role}'. Ownership is "
            "somebody's name on an agent — a group-owned agent is one everybody may "
            "delete and nobody answers for."
        )

    # Step 020, and the same shape as the rule above it: refused here so the person who
    # typed the command gets a sentence, and by `agent_grants_no_machine_above_user` so
    # the rule survives somebody editing `MACHINE_ROLES`.
    #
    # **`ValueRefused`, not a bare `StorageError`**, and it is the difference between a
    # 400 and a 503. Unlike the group rule above — which `grants.share` refuses earlier
    # with `ShareRefused`, so HTTP never reaches this line — nothing above the storage
    # layer knows about the machine ceiling, so this *is* the refusal a share sheet gets.
    # Found by driving it: the route answered "storage unavailable: try again later"
    # about a grant that will never be accepted, which is exactly the family the table at
    # the top of `api/errors.py` exists to catch and has now caught eight times.
    if grantee_kind == "machine" and role not in MACHINE_ROLES:
        raise ValueRefused(
            f"a machine may be granted {list(MACHINE_ROLES)}, not '{role}'. An API "
            "token runs an agent; editing one and sharing it are decisions with "
            "somebody's judgment in them, and a credential that lives in a CI variable "
            "is the wrong place for that judgment to sit. Grant the token's owner "
            "instead."
        )


def check_agent_role(role: str) -> None:
    """The CHECK constraint, in Python, so both stores refuse identically."""
    if role not in AGENT_ROLES:
        raise StorageError(
            f"role must be one of {list(AGENT_ROLES)}, not '{role}'"
        )


def check_platform_role(principal_kind: str, role: str) -> None:
    """A `platform_roles` row, both columns, because both are refusals worth a sentence.

    The kind first, and its message is the one that matters: **a group may not hold a
    platform role**, because group membership would then be self-service promotion —
    anybody already able to add a member could mint an administrator. Refused here and by
    the CHECK in migration 026, the same two places `check_principal_kind` and migration
    017's constraints already stand together, and for the same reason: the constraint is
    what survives somebody editing a frozenset, and this is what produces a sentence
    rather than a constraint name for the person who typed the command.
    """
    if principal_kind == "group":
        raise StorageError(
            "a group cannot hold a platform role. Membership of a group is not an "
            "administrative decision — anybody who may add a member would be able to "
            "make an administrator — so a role is granted to a person or to a system "
            "principal, by id."
        )

    # Step 020, and this is the **other half of not inheriting the always-admin rule**.
    # Refusing a machine the `system` shortcut is worth nothing if the long way round is
    # open: a machine that could be granted `admin` would be an administrator with a
    # credential in a CI variable and no human session behind it. Refused here and by
    # `platform_roles_principal_kind_check`, which migration 031 pointedly left narrow.
    if principal_kind == "machine":
        raise StorageError(
            "a machine cannot hold a platform role. An API token is an administrator "
            "nowhere — that is the whole reason it is a third principal kind rather "
            "than a `system` one — and an administrative decision needs a person who "
            "can be asked about it afterwards. Grant the role to the token's owner."
        )

    check_principal_kind(principal_kind)

    if role not in PLATFORM_ROLES:
        raise StorageError(
            f"platform role must be one of {list(PLATFORM_ROLES)}, not '{role}'. The "
            "vocabulary is closed and lives in PLATFORM_ROLES and in migration 026's "
            "CHECK — a second role is a deliberate addition to both, not a string a "
            "caller passes."
        )


def check_claimant(principal_kind: str) -> None:
    """Only a person claims a grant addressed to an email. See `claim_pending_grants`."""
    check_principal_kind(principal_kind)
    if principal_kind != "user":
        raise StorageError(
            "a pending grant is addressed to a person's email address, so only a "
            f"'user' may claim one — not '{principal_kind}'. Grant a system principal "
            "by id instead."
        )


def check_pending_role(role: str) -> None:
    if role not in PENDING_ROLES:
        raise StorageError(
            f"a grant to somebody who has not logged in must be one of "
            f"{list(PENDING_ROLES)}, not '{role}'. Ownership is transferred to a real "
            "principal, never left waiting on an address."
        )


def check_credential_kind(kind: str) -> None:
    """The `connections.credential_kind` CHECK, in Python, so both stores refuse alike.

    See migration 024: the discriminator exists so that nothing has to guess a stored
    credential's encoding from its shape — and a guess would have to decrypt the value
    before it could look, which is the wrong order for a decision about how to read it.
    """
    if kind not in CREDENTIAL_KINDS:
        raise StorageError(
            f"'{kind}' is not a credential kind; they are {sorted(CREDENTIAL_KINDS)}. "
            "'static' is a token somebody pasted in and 'oauth' is one a consent flow "
            "returned — they are sealed differently, so this is never inferred."
        )


# The floor on a `state` parameter's length, matching migration 024's CHECK. Not a
# format — `secrets.token_urlsafe(32)` produces 43 characters and a different generator
# would produce something else — but a length below which it is guessable, which is the
# only property that matters and is the one a constraint can express.
STATE_MIN_LENGTH = 32


def normalize_scopes(scopes) -> tuple:
    """OAuth scopes as an ordered tuple of non-empty strings, duplicates removed.

    **Order is preserved rather than sorted**, which is the one thing here that is a
    decision. A scope list is sent verbatim to a provider as a space-delimited string,
    and while no provider is documented as caring about order, the value an admin typed
    is what they will compare against the provider's own consent screen when something
    looks wrong. Sorting it would make the two disagree for no gain.

    Accepts a space-delimited string as well as a sequence, because that is how every
    provider's documentation writes them and therefore what somebody will paste.
    """
    if isinstance(scopes, str):
        scopes = scopes.split()

    seen: dict = {}
    for scope in scopes or ():
        if not isinstance(scope, str):
            raise ValueRefused(
                f"a scope must be a string, not {type(scope).__name__}. Scopes are sent "
                "to a provider verbatim."
            )
        cleaned = scope.strip()
        if not cleaned:
            continue
        if any(character.isspace() for character in cleaned):
            # They are joined with spaces on the wire, so one containing a space is two
            # scopes wearing a disguise — and the consent screen would ask for something
            # nobody typed.
            raise ValueRefused(
                f"scope '{scope}' contains whitespace. Scopes are space-delimited on "
                "the wire, so pass them as separate values rather than as one string "
                "with a space in it."
            )
        seen[cleaned] = None
    return tuple(seen)


# What a scope note may say. `access` is onecli's field, copied deliberately — see
# migration 051 for why it is NOT `vetted_tools.effect` and why conflating them would be a
# mistake rather than a tidy-up.
SCOPE_NOTE_FIELDS = frozenset({"name", "description", "access"})
SCOPE_NOTE_ACCESS = frozenset({"read", "write"})


def normalize_scope_notes(notes, *, scopes=()) -> dict:
    """Per-scope prose for a consent screen, checked against the scopes it describes.

    Migration 051. A mapping of scope string to `{name, description, access}`, where
    `access` is `read` or `write`.

    **Every key must be a scope this configuration actually requests**, and that is the
    check worth having rather than the type checks around it. A note for a scope nobody is
    asking for is unreachable at best; at worst it describes a permission this consent
    flow does not grant, on the screen where somebody decides whether to grant it. Same
    rule as `redact_args` against a tool's input schema (045c, migration 049): a policy
    that reads as applied and is not, caught where it is written rather than never.

    The refusal names the scope and lists what is available, because the overwhelmingly
    likely cause is a typo in a recipe or a vendor spelling a scope differently from their
    own documentation — and both are fixed by seeing the two lists side by side.

    A scope with no note is normal and not an error. `offline_access` is bookkeeping with
    nothing to say to a person, and inventing a sentence for it would be this platform
    describing somebody else's permission from a guess.
    """
    if not notes:
        return {}
    if not isinstance(notes, dict):
        raise ValueRefused(
            f"scope_notes must be a mapping of scope to its description, not "
            f"{type(notes).__name__}"
        )

    # `authorize_params`' rule, and for the identical reason: this is a jsonb column, and
    # a NUL or a lone surrogate reaches Postgres as *"unsupported Unicode escape
    # sequence"* — a `StorageError`, and so a 503 about a request that will never work.
    check_config_is_storable(notes, what="scope_notes")

    known = set(normalize_scopes(scopes))
    cleaned: dict = {}
    for scope, note in notes.items():
        if not isinstance(scope, str) or not scope.strip():
            raise ValueRefused("a scope note needs the scope it describes")
        scope = scope.strip()
        if "\x00" in scope:
            raise ValueRefused(
                "a scope note's key contains a NUL byte. Postgres holds these in a jsonb "
                "column and refuses it outright."
            )
        if scope in cleaned:
            raise ValueRefused(
                f"'{scope}' is described twice. Keys are stripped of surrounding spaces "
                "before they are stored, so two that differ only in spacing are the same "
                "scope — and keeping the last one silently would throw away a sentence "
                "somebody wrote."
            )
        if scope not in known:
            raise ValueRefused(
                f"scope note '{scope}' describes a scope this consent flow does not "
                f"request. Nobody would ever read it, and a note for a permission that "
                f"is not being granted is worse than none on the screen where somebody "
                f"decides whether to grant it.\n"
                f"  requested: {' '.join(sorted(known)) or '<none>'}\n"
                f"  described: {scope}"
            )
        if not isinstance(note, dict):
            raise ValueRefused(
                f"the note for '{scope}' must be an object with a name, a description "
                f"and an access, not {type(note).__name__}"
            )
        unknown = set(note) - SCOPE_NOTE_FIELDS
        if unknown:
            raise ValueRefused(
                f"the note for '{scope}' carries {sorted(unknown)}, which this column "
                f"does not hold. A scope note is three fields — "
                f"{sorted(SCOPE_NOTE_FIELDS)} — and storing more would let a recipe put "
                f"something in front of a person that nothing here has looked at."
            )
        access = note.get("access", "")
        if access not in SCOPE_NOTE_ACCESS:
            raise ValueRefused(
                f"the note for '{scope}' has access {access!r}; it must be one of "
                f"{sorted(SCOPE_NOTE_ACCESS)}. This is the word shown beside the scope "
                f"at a consent screen, and it is a vendor's claim about their own API "
                f"rather than a permission this platform enforces — see migration 051."
            )
        for field in ("name", "description"):
            value = note.get(field, "")
            if not isinstance(value, str):
                raise ValueRefused(
                    f"the note for '{scope}' has a {field} that is not a string"
                )
        cleaned[scope] = {
            "name": (note.get("name") or "").strip(),
            "description": (note.get("description") or "").strip(),
            "access": access,
        }
    return cleaned


# Query parameters `access/oauth.begin` builds itself, and which a stored row may
# therefore never supply. Migration 025 explains why two of these are load-bearing rather
# than merely tidy:
#
#   `state`         is the ONLY thing binding a callback to the person who started it,
#                   because the callback is a top-level navigation carrying no token. A
#                   fixed or guessable one makes every consent flow in the tenant
#                   forgeable.
#   `redirect_uri`  is where somebody's authorization code is delivered. One that a row
#                   could override sends it wherever the row says, and the only thing in
#                   the way is the provider validating it against their own registration —
#                   which is somebody else's control, not ours.
#
# The rest are refused because a row silently overriding them produces a request that does
# not match what this code believes it sent, which is the class of bug that is impossible
# to read off either side.
RESERVED_AUTHORIZE_PARAMS = frozenset(
    {
        "response_type",
        "client_id",
        "redirect_uri",
        "state",
        "code_challenge",
        "code_challenge_method",
        "scope",
    }
)


def normalize_authorize_params(params) -> dict:
    """Provider-specific authorize parameters, checked. See migration 025.

    Refuses anything `begin` builds itself — see `RESERVED_AUTHORIZE_PARAMS`, where two of
    the seven are the security design rather than bookkeeping.
    """
    if not params:
        return {}
    if not isinstance(params, dict):
        raise ValueRefused(
            f"authorize_params must be a mapping of name to value, not "
            f"{type(params).__name__}"
        )

    # **Postgres cannot hold every string Python can**, and this column is `jsonb`. A NUL
    # or a lone surrogate arrived as *"unsupported Unicode escape sequence"* — a
    # `StorageError`, and therefore a **503 about a request that will never work**, which
    # is the exact sentence `check_config_is_storable` was written for on the config
    # columns. Same rule, same helper, at the column that had not been given it. Found by
    # 035g's third pass; before it, one NUL byte in a browser form field was *"try again
    # later"*.
    check_config_is_storable(params, what="authorize_params")

    cleaned = {}
    for name, value in params.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueRefused("an authorize parameter needs a name")
        name = name.strip()
        # The helper above walks a mapping's **values** — it says so, and it is right to,
        # because `json.dumps` coerces keys and refusing that would break callers. A JSONB
        # *key* still cannot hold a NUL, so the name gets the same rule said separately
        # rather than a helper bent to cover it.
        if "\x00" in name:
            raise ValueRefused(
                "an authorize parameter's name contains a NUL byte. Postgres holds these "
                "in a jsonb column and refuses it outright, so accepting it here would "
                "turn a value you can fix into a failure at write time."
            )
        # **Two names that differ only in their surrounding spaces are one name here**, and
        # before this the second silently won — a parameter somebody typed, accepted, and
        # thrown away with nothing said. A form with a row per parameter makes that a
        # reachable typo rather than a curiosity, so it is a refusal that names the
        # parameter rather than a `dict` overwrite.
        if name in cleaned:
            raise ValueRefused(
                f"'{name}' is given twice. Names are stripped of surrounding spaces "
                "before they are stored, so two that differ only in spacing are the same "
                "parameter — and keeping the last one silently would throw away a value "
                "somebody typed."
            )
        if name in RESERVED_AUTHORIZE_PARAMS:
            raise ValueRefused(
                f"'{name}' is built by the consent flow itself and may not be set here. "
                + (
                    "It is the only thing binding a provider's callback to the person "
                    "who started it — the callback carries no token, so a fixed or "
                    "guessable value makes every consent flow in this tenant forgeable."
                    if name == "state"
                    else "It decides where a person's authorization code is delivered, "
                    "and a stored row that could redirect it is a stolen grant waiting "
                    "for a provider that validates loosely."
                    if name == "redirect_uri"
                    else f"Setting it would make the request differ from what this "
                    f"platform believes it sent. Reserved: "
                    f"{sorted(RESERVED_AUTHORIZE_PARAMS)}."
                )
            )
        if not isinstance(value, str):
            raise ValueRefused(
                f"authorize parameter '{name}' must be a string; it goes into a URL"
            )
        cleaned[name] = value
    return cleaned


def check_oauth_app(
    *,
    authorize_endpoint: str,
    token_endpoint: str,
    client_id: str,
    client_secret: bytes,
    key_id: str,
) -> None:
    """Migration 024's CHECKs on `connector_oauth`, in Python, so both stores agree.

    The endpoints are required to be absolute `https` URLs here rather than merely
    non-empty, which is stricter than the column. Both are values a stored row turns into
    an outbound request — the token endpoint into a POST carrying the client secret, the
    authorize endpoint into somebody's browser — and `http://` on either is the client
    secret or the authorization code travelling in clear text. `HttpLaunch.__post_init__`
    makes the same check on a connector's URL for the same reason, and permits `http` for
    a local server; this does not, because there is no equivalent of a development MCP
    server here — an authorization server is somebody else's, always.
    """
    for name, url in (
        ("authorize_endpoint", authorize_endpoint),
        ("token_endpoint", token_endpoint),
    ):
        if not url:
            raise ValueRefused(f"{name} is required to configure a consent flow")
        if not url.startswith("https://"):
            raise ValueRefused(
                f"{name} must be an https URL, not '{url}'. The token endpoint receives "
                "this deployment's client secret and the authorize endpoint receives a "
                "person's authorization code; over http either is readable by anything "
                "on the path."
            )

    # **The second door into `RESERVED_AUTHORIZE_PARAMS`, closed here.** A query string on
    # the authorize endpoint is legitimate and predates the column — `oauth.begin` appends
    # its own parameters after it with an `&`, which is why `?audience=x` on the endpoint
    # still works. What it must not carry is one of the seven the flow builds itself: the
    # URL would then hold that name **twice**, and RFC 6749 does not say which one a
    # provider reads. A provider that reads the first gets a `state` a stored row chose,
    # which is precisely the forgeable consent flow `normalize_authorize_params` refuses
    # two functions up — arriving through a field nothing checked.
    #
    # Found by 035g's third pass driving a real consent start and counting the parameters
    # on the link. Non-reserved names are untouched, because they are the reason a query
    # string on this endpoint is allowed at all.
    for name, _ in parse_qsl(urlsplit(authorize_endpoint).query, keep_blank_values=True):
        if name.strip() in RESERVED_AUTHORIZE_PARAMS:
            raise ValueRefused(
                f"the authorize endpoint's own query string sets '{name.strip()}', which "
                "the consent flow builds itself. The sign-in link would carry that name "
                "twice and no specification says which one a provider reads — so this is "
                "the same refusal an authorize parameter of that name gets, at the other "
                "place the name can arrive. Put the provider-specific parameters in "
                "authorize_params and leave the endpoint's query string to anything else."
            )

    if not client_id:
        raise ValueRefused(
            "client_id is required. It is public — it appears in the authorize URL in "
            "somebody's address bar — but a consent flow without one is not a flow."
        )

    if not isinstance(client_secret, (bytes, bytearray, memoryview)) or not bytes(
        client_secret
    ):
        raise ValueRefused(
            "client_secret must be non-empty sealed bytes. Storage never encrypts or "
            "decrypts anything — the caller seals it with `crypto.oauth_app_aad` and "
            "hands over the ciphertext. A public client (PKCE with no secret) is not "
            "supported: this is a confidential client on a server, which is what keeps "
            "the token out of the browser."
        )

    if not key_id:
        raise ValueRefused(
            "key_id is required. A sealed value that does not say which key it needs is "
            "one nothing can open after a rotation."
        )


def normalize_oauth_client(client: dict) -> dict:
    """Validate and bound an `oauth_clients` row. Migration 053.

    The bounds are the only opinion this has: the registration endpoint carries no
    credential, so every field here was written by somebody nobody has authenticated,
    and a row that could be a megabyte is a table that could be a disk. What a redirect
    URI may *look like* is the access layer's rule; this only asks that it is a short
    string and that there are not many of them.
    """
    client_id = client.get("id") or ""
    name = client.get("client_name") or ""
    uris = client.get("redirect_uris")
    metadata = client.get("metadata") if client.get("metadata") is not None else {}
    if not client_id:
        raise StorageError("an OAuth client needs an id; it is minted, never chosen")
    if not name or len(name) > OAUTH_CLIENT_MAX_NAME_LENGTH:
        raise StorageError(
            f"an OAuth client's name must be 1 to {OAUTH_CLIENT_MAX_NAME_LENGTH} "
            "characters. It is rendered on the consent page and nowhere else."
        )
    # **A NUL is refused by the store, not only by the layer above.** Postgres text
    # columns cannot hold one at all, so the real store raised `StorageError` — a 503,
    # from an unauthenticated route — while the fake stored it happily. That is the
    # fake being *more permissive* than the real store, which is migration 007's
    # direction of drift and the one the contract suite exists to catch: a test suite
    # that is green in memory and 503 in production.
    if "\x00" in name or any("\x00" in uri for uri in uris if isinstance(uri, str)):
        raise StorageError(
            "an OAuth client's name and redirect URIs may not contain NUL bytes; no "
            "text column in this schema can hold one."
        )
    if (
        not isinstance(uris, (list, tuple))
        or not uris
        or len(uris) > OAUTH_CLIENT_MAX_REDIRECT_URIS
        or any(
            not isinstance(uri, str) or not uri or len(uri) > OAUTH_CLIENT_MAX_URI_LENGTH
            for uri in uris
        )
    ):
        raise StorageError(
            f"an OAuth client registers 1 to {OAUTH_CLIENT_MAX_REDIRECT_URIS} redirect "
            f"URIs of at most {OAUTH_CLIENT_MAX_URI_LENGTH} characters each."
        )
    if not isinstance(metadata, dict):
        raise StorageError("an OAuth client's metadata is an object")
    if len(json.dumps(metadata, default=str).encode("utf-8")) > OAUTH_CLIENT_MAX_METADATA_BYTES:
        raise StorageError(
            f"an OAuth client's metadata is bounded at {OAUTH_CLIENT_MAX_METADATA_BYTES} "
            "bytes. It exists to name the client on a page, not to describe it."
        )
    return {
        "id": client_id,
        "client_name": name,
        "redirect_uris": [str(uri) for uri in uris],
        "metadata": dict(metadata),
    }


def normalize_oauth_code(code: dict) -> dict:
    """Validate an `oauth_codes` row before it is written. Migration 053."""
    missing = [
        field
        for field in (
            "code_hash", "client_id", "owner_id", "redirect_uri", "code_challenge",
            "token_name", "expires_at",
        )
        if not code.get(field)
    ]
    if missing:
        raise StorageError(
            f"an OAuth code row is missing {missing}. Every one of them is compared at "
            "the exchange; a row without one is a code nothing could redeem safely."
        )
    expires_at = code["expires_at"]
    if not isinstance(expires_at, datetime) or expires_at.tzinfo is None:
        raise StorageError(
            "an OAuth code's expiry must be a timezone-aware datetime: it is compared "
            "against now(timezone.utc) at the exchange."
        )
    # Step 087. The name the exchange will mint under, typed on the consent page: a
    # NUL here was a 503 from an authenticated route, and the fake stored it.
    check_name_is_text(code["token_name"], what="the token's name")
    return {
        "code_hash": code["code_hash"],
        "client_id": code["client_id"],
        "owner_id": code["owner_id"],
        "redirect_uri": code["redirect_uri"],
        "code_challenge": code["code_challenge"],
        "resource": code.get("resource") or "",
        "token_name": code["token_name"],
        "expires_at": expires_at,
    }


def check_pending_authorization(
    *,
    state: str,
    connector_id: str,
    code_verifier: bytes,
    key_id: str,
    redirect_uri: str,
    return_to: str,
) -> None:
    """Migration 024's CHECKs on `pending_authorizations`, in Python. See that migration.

    `return_to` is the one worth reading twice. It becomes a `Location` header at the end
    of the flow, so a value that could be an absolute URL is an **open redirect**: an
    attacker who can start a consent flow with `return_to=https://evil.example` gets this
    deployment's own domain to bounce somebody there, which is the phishing primitive
    that makes a redirect vulnerability worth having at all.

    So: it must begin with a single `/` and the second character must not be another —
    `//evil.example` is a protocol-relative URL and every browser treats it as absolute,
    which is the form that gets past a check for "starts with a slash". Backslashes are
    refused for the same reason: several browsers normalise `\\` to `/` in a URL, so
    `/\\evil.example` is protocol-relative to them and a safe relative path to a naive
    check.
    """
    if not state or len(state) < STATE_MIN_LENGTH:
        raise StorageError(
            f"a consent flow's state must be at least {STATE_MIN_LENGTH} characters. "
            "It is the only thing binding a callback to the person who started it, and "
            "a guessable one is an attacker completing somebody else's connection."
        )
    if not connector_id:
        raise StorageError("a pending authorization must name the connector it is for")
    if not isinstance(code_verifier, (bytes, bytearray, memoryview)) or not bytes(
        code_verifier
    ):
        raise StorageError(
            "code_verifier must be non-empty sealed bytes; storage never seals anything"
        )
    if not key_id:
        raise StorageError("key_id is required for a sealed code_verifier")
    if not redirect_uri:
        raise StorageError(
            "redirect_uri is required, and is stored rather than recomputed so that the "
            "value sent to the authorize endpoint and the value sent to the token "
            "endpoint are the same string by construction"
        )

    check_return_to(return_to)


def check_return_to(return_to: str) -> None:
    """Refuse a `return_to` that could leave this application. See above.

    Its own function because it has **two callers with different jobs**, which is the
    `normalize_host` shape. This one is the constraint mirror — the last thing before a
    row is written, so no path into storage can skip it. `access/oauth.begin` calls it
    first and turns the refusal into an `OAuthRefused`, so a caller who typed a bad
    `return_to` gets a 400 that names the value rather than a 503 saying *"storage
    unavailable"* about a database that is fine.

    Found by driving the route: the check was in the right place and produced the wrong
    status code, which is the same class of miss as `NoSuchGroupError` arriving as a 503
    in step 011.
    """
    if not return_to:
        return

    if not return_to.startswith("/") or return_to[1:2] in ("/", "\\"):
        raise StorageError(
            f"return_to '{return_to}' is not a path within this application. It "
            "must start with a single '/' — an absolute or protocol-relative URL "
            "here is an open redirect, because this value becomes a Location header "
            "at the end of somebody's consent flow."
        )
    if "\\" in return_to:
        raise StorageError(
            f"return_to '{return_to}' contains a backslash. Several browsers "
            "normalise it to '/', so it is a protocol-relative URL to them and a "
            "safe relative path to a check that only looks at the first character."
        )



def check_reseal(blob: bytes, key_id: str, expected: bytes) -> None:
    """A re-seal's own NOT NULLs, so both stores refuse alike. Step 026.

    `check_connection`'s rules, minus the expiry it has no opinion on, plus the
    expectation the compare-and-set is made of: a reseal whose `if_` argument were a
    `str` would silently match nothing and be reported as "the row changed underneath
    us", which is the one wrong answer this method must never give.
    """
    for label, value in (("the new sealed value", blob), ("the expected value", expected)):
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise StorageError(
                f"{label} must be bytes, not {type(value).__name__}. These columns hold "
                "sealed credentials; storage never encodes or decodes one."
            )
        if not bytes(value):
            raise StorageError(f"{label} is empty — a re-seal writes a sealed blob")
    if not key_id:
        raise StorageError(
            "key_id is required. A row that does not say which key it needs is a row "
            "nothing can open after a rotation."
        )

def check_connection(ciphertext: bytes, key_id: str, expires_at) -> None:
    """The NOT NULLs and the type expectations, in Python, so both stores refuse alike.

    `ciphertext` is checked for being `bytes` rather than `str` specifically: psycopg
    would accept a string into a BYTEA column by encoding it, the in-memory store would
    keep it as text, and the two would then disagree about what came back out — a drift
    the contract suite could only catch if one of them refused.
    """
    if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
        raise StorageError(
            f"ciphertext must be bytes, not {type(ciphertext).__name__}. This column "
            "holds a sealed credential; storage never encodes or decodes one."
        )
    if not bytes(ciphertext):
        raise StorageError("ciphertext is empty — there is nothing sealed to store")
    if not key_id:
        raise StorageError(
            "key_id is required. A row that does not say which key it needs is a row "
            "nothing can open after a rotation."
        )
    if expires_at is not None:
        if not isinstance(expires_at, datetime):
            raise StorageError(
                f"expires_at must be a datetime or None, not "
                f"{type(expires_at).__name__}"
            )
        if expires_at.tzinfo is None:
            # Postgres would attach the server's zone to a naive value, so the same row
            # would mean different instants depending on where it was written.
            raise StorageError(
                "expires_at must be timezone-aware. A naive timestamp is a different "
                "instant in every deployment that reads it."
            )


def normalize_run(run: dict) -> dict:
    """Validate and fill in a `runs` row. Raises `StorageError` on nonsense.

    `task` is permitted to be empty and the required list says so by omission — a task
    is the caller's free text and refusing an empty one is a policy decision that
    belongs above storage, next to the agent that would have to answer it.
    """
    missing = [field for field in RUN_REQUIRED if not run.get(field)]
    if missing:
        raise StorageError(
            f"run is missing {missing}. `run_id` is the correlation id every audit "
            "record from this run already carries, and the principal is who it acts for."
        )

    check_principal_kind(run["principal_kind"])
    check_run_status(run.get("status") or "queued")

    return {
        "run_id": run["run_id"],
        "agent": run["agent"],
        # `None` rather than `''` for absent, matching `parent_run_id` below and unlike
        # `idempotency_key`: an agent id is either one or there is not one, and `''` would
        # be a second spelling of the NULL the column already has. A caller that omits it
        # gets a run that behaves exactly like one written before migration 035.
        "agent_id": run.get("agent_id") or None,
        "principal_kind": run["principal_kind"],
        "principal_id": run["principal_id"],
        "task": run.get("task") or "",
        "status": run.get("status") or "queued",
        "idempotency_key": run.get("idempotency_key") or "",
        # None, not '', for "this is a root": the column carries a foreign key, and ''
        # is not a run. The root is derived from the parent by the store itself — a
        # caller-supplied root would be a second opinion about a fact the parent row
        # already holds.
        "parent_run_id": run.get("parent_run_id") or None,
        # Step 028. '' for "this run had no file", matching `idempotency_key` beside it
        # and unlike `parent_run_id` — the NULL spelling belongs to columns carrying a
        # key, and this one deliberately has none. Whether the id names a file the caller
        # may use is decided above storage, by `runs.usable_file`.
        "file_id": run.get("file_id") or "",
    }


def normalize_usage(usage: dict | None) -> dict | None:
    """Validate what `finish_run` was told a run spent. None passes straight through.

    Step 013, migration 045. The whole of the shared coercion for the usage half of a
    row, so a `runs` row means the same thing whichever store it lands in — the rule
    stated at the top of this section, and the one `audit.credential` was lost to.

    Three refusals, and each of them is a mistake with a plausible-looking result rather
    than an obvious one:

      - **An unknown key** is a column that does not exist, which Postgres would refuse
        with a syntax error and the in-memory store would happily keep forever as a field
        no read method returns. Refused here so both answer the same way.
      - **A negative count** is the `=`-where-`+=`-belongs bug arriving from above, and
        it is the reason migration 045 carries a CHECK. This is that CHECK, for the store
        that has none.
      - **Anything but an integer** where a count belongs. A float total is a token count
        somebody computed rather than read, which is the one thing this whole feature
        exists not to do.

    Missing keys default rather than raise: a caller recording only what it measured is
    the ordinary case for a run that never reached a model call, and `0`/`''` is what
    "nobody recorded this" already looks like in this schema.
    """
    if usage is None:
        return None

    unknown = sorted(set(usage) - set(USAGE_FIELDS))
    if unknown:
        raise StorageError(
            f"usage carries {unknown}, which is not a column on `runs`. The keys are "
            f"{list(USAGE_FIELDS)} — `core/usage.Meter.snapshot()` produces exactly "
            "those, and anything else is a column one store would keep and the other "
            "would refuse."
        )

    normalized: dict = {"model": str(usage.get("model") or "")}
    for field in USAGE_FIELDS:
        if field == "model":
            continue
        value = usage.get(field, 0) or 0
        # `bool` is an `int` in Python and `True` is not a token count. Checked because
        # the alternative is a row saying a run spent one token.
        if isinstance(value, bool) or not isinstance(value, int):
            raise StorageError(
                f"usage['{field}'] is {value!r}, which is not a whole number of tokens. "
                "These counts are read off a model reply, never computed."
            )
        if value < 0:
            raise StorageError(
                f"usage['{field}'] is {value}. Token counters only ever count up — a "
                "negative one is an assignment where an accumulation belongs. See "
                "migration 045's CHECK."
            )
        normalized[field] = value

    return normalized


def normalize_file(row: dict) -> dict:
    """Validate the row `create_file` was handed. Step 028.

    Storage's own check, and **not** a second copy of `runs.validate_upload`. That
    function answers a product question — is this a type we accept, does the content
    match the claim, is it inside the ceiling for its type — and belongs above storage
    beside the caller that has to phrase the refusal. This one answers a structural
    question: are the fields present, are they the right types, and is the digest the
    right shape for the column that will hold it.

    The per-type ceilings are deliberately absent here and live in config, with the
    absolute one in the CHECK constraint. Storage refusing a policy number would put one
    product decision in three places; the database refusing an impossible row puts it
    where nothing can route around it.
    """
    missing = [f for f in FILE_FIELDS if not row.get(f)]
    if missing:
        raise StorageError(
            f"file is missing {missing}. Every one of them is written at upload and "
            "none can be filled in later."
        )

    check_principal_kind(row["owner_kind"])

    content = row["content"]
    if not isinstance(content, (bytes, bytearray)):
        raise StorageError(
            f"file content is {type(content).__name__}, not bytes. The column is BYTEA "
            "and the file is whatever the caller uploaded — decoding it to text here "
            "would corrupt every PDF."
        )

    digest = row["sha256"]
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise StorageError(
            f"file sha256 '{digest}' is not 64 lowercase hex characters."
        )

    if row["byte_size"] != len(content):
        raise StorageError(
            f"file byte_size is {row['byte_size']} and the content is {len(content)} "
            "bytes. The stored size exists so a metadata read never touches the content "
            "column, which only works while the two agree."
        )

    return {
        "id": row["id"],
        "owner_kind": row["owner_kind"],
        "owner_id": row["owner_id"],
        "filename": row["filename"],
        "media_type": row["media_type"],
        "content": bytes(content),
        "sha256": digest,
        "byte_size": row["byte_size"],
    }


def check_run_status(status: str) -> None:
    """The CHECK constraint, in Python, so both stores refuse identically."""
    if status not in RUN_STATUSES:
        raise StorageError(
            f"status must be one of {sorted(RUN_STATUSES)}, not '{status}'"
        )


# What `activity.doing` may say. Two values because the turn loop has two phases; a
# third phase is a change to the loop before it is a change to this tuple.
ACTIVITY_DOING = ("model", "tools")


def normalize_activity(turn: int, doing: str, since) -> dict:
    """The one shape an `activity` marker may have, so both stores write the same dict.

    Versioned like the audit record and for the same reason: the value outlives the
    code that wrote it, and a reader handed `{"v": 1, ...}` knows which vocabulary it
    was written in. `since` arrives as a datetime and is stored as ISO-8601 text — the
    marker is JSON in one store and a dict in the other, and a driver-native datetime
    inside it would make the two disagree about what a marker is.
    """
    if doing not in ACTIVITY_DOING:
        raise StorageError(
            f"activity.doing must be one of {ACTIVITY_DOING}, not '{doing}'"
        )
    if turn < 1:
        raise StorageError(f"activity.turn is 1-based; {turn} is not a turn")
    return {
        "v": 1,
        "turn": turn,
        "doing": doing,
        "since": since.isoformat(timespec="seconds"),
    }


def compose_run_fingerprint(
    status: str, cancel_requested_at, activity: dict | None, record_count: int
) -> str:
    """Fold what the run detail renders live into one comparable string. Step 032.

    Both stores call this, and so does the route composing the cursor it hands back —
    one composition, three call sites, zero drift. Four legs, each one thing the page
    would render differently: the status wording (status + cancellation), the activity
    line, and the trail (its records are append-only, so a count is a cursor).

    Readable rather than hashed, deliberately: the client treats it as opaque, and a
    person debugging a wait that never returns can read the two strings and see which
    leg disagrees.
    """
    cancel = cancel_requested_at.isoformat(timespec="seconds") if cancel_requested_at else ""
    doing = (
        json.dumps(activity, sort_keys=True, separators=(",", ":"))
        if activity
        else ""
    )
    return f"{status}|{cancel}|{doing}|{record_count}"


# What `recover_expired_runs` writes to `error`, so both stores say the same sentence
# and a person reading a row learns which of the two conditions fired.
LEASE_LOST = (
    "the worker holding this run stopped responding. It started, and how far it got is "
    "in the audit trail under this run id — nothing re-ran it, because a run that may "
    "have half-happened must not happen twice."
)

DEADLINE_PASSED = (
    "this run passed its wall-clock deadline while its worker was still alive, which "
    "means it stopped making progress rather than stopped running. What it did before "
    "that is in the audit trail under this run id."
)


def check_terminal_status(status: str) -> None:
    check_run_status(status)
    if status not in TERMINAL_RUN_STATUSES:
        raise StorageError(
            f"'{status}' is not a terminal status. finish_run records how a run ended; "
            f"the ones that end it are {sorted(TERMINAL_RUN_STATUSES)}."
        )


def normalize_email(email: str) -> str:
    """One normalisation, applied on the way in and on the way out.

    Lowercased and stripped. The local part of an address is case-sensitive by RFC and
    case-insensitive at every provider anybody actually uses, so matching exactly would
    be correct by the standard and broken in fact — somebody types `Priya@Acme.com` into
    a share box and the grant never lands.
    """
    return email.strip().lower()


# One message, raised by both implementations, because the contract suite compares them
# and because it is the message a person reads while trying to share something.
OWNER_TAKEN = (
    "agent '{agent}' already has an owner. An agent has exactly one, so this is a "
    "transfer rather than a grant — use transfer_agent_ownership."
)

# Migration 017 cannot express this as a foreign key, so both stores raise it. See
# `grant_agent`: a grant naming a group nobody created grants nothing and looks like
# access, which is the state this whole step is trying not to create.
NO_SUCH_GROUP = "no group '{group}' in tenant '{tenant}'"

# Migration 021's two directions, worded for the person who hit them rather than named
# after the constraint. Postgres raises `connections_connector_fk` for both; the
# in-memory store raises these directly, which is the only way the two agree.
NO_SUCH_CONNECTOR = (
    "no connector '{connector}' in tenant '{tenant}'. A credential can only be stored "
    "against a connector this customer has vetted — sealing one against a name that "
    "does not exist produces a row nothing can ever use and nobody can read."
)

NO_SUCH_CONNECTOR_TO_TRUST = (
    "no connector '{connector}' in tenant '{tenant}'. Asserted identity is trust in a "
    "caller for one server's tools; enabling it for a server nobody has registered "
    "would be a decision with nothing behind it. Register the connector first."
)

CONNECTOR_IN_USE = (
    "connector '{connector}' in tenant '{tenant}' still holds connected accounts, so "
    "it cannot be deleted. Their credentials are sealed and unreadable without it — "
    "disconnect them first, deliberately, rather than leaving rows that a connector "
    "later reusing this id would silently inherit."
)

# Both raised by both stores, so the refusal a person reads does not depend on which
# store they happen to be running against.
CONNECTOR_EXISTS = (
    "tenant '{tenant}' already has a connector called '{connector}'. Registering it "
    "again is refused rather than treated as an update, because the update would "
    "replace its whole allowlist — nine approved tools gone to a command whose visible "
    "effect is 'the row exists'. To change where it points, delete and re-register; to "
    "approve another tool on it, use --vet."
)

# `vet_tool`'s version of the same absence, and it is a **different sentence on purpose**
# — a connector admin who mistyped `--vet jira` is told to register the server, where
# somebody connecting an account is told what a credential can be sealed against.
#
# **This was called `NO_SUCH_CONNECTOR` and silently shadowed the constant above**, which
# is defined thirty lines earlier under a comment explaining that migration 021 has *two*
# directions worded differently. Python kept the second binding, so both directions got
# the vetting wording: every `--connect-account` against an unregistered connector — and
# every `ConnectionRefused` the routes in 7b raise — answered *"Register it first with
# --add-connector: a tool can only be vetted on a server..."*, which is advice for a
# different person about a different command.
#
# Nothing failed, and nothing could have: both stores raise the same name, so the
# contract suite compared one wrong message against an identical wrong message and
# agreed. Found by adding a third caller and reading the sentence it produced.
NO_SUCH_CONNECTOR_TO_VET = (
    "tenant '{tenant}' has no connector '{connector}'. Register it first with "
    "--add-connector: a tool can only be vetted on a server somebody has already "
    "decided to point this customer at."
)

GROUP_NAME_TAKEN = (
    "tenant '{tenant}' already has a group called '{name}'. Names are how a person picks "
    "a group on the command line, so two with one name is a command whose meaning "
    "depends on insertion order."
)

# Step 033e. The *other* uniqueness on `groups`, and it needs its own sentence: until
# there was a way to link an existing group, a second `external_id` was unreachable, so
# the Postgres store translated every unique violation on this table as a name collision
# — a true-sounding sentence about the wrong column, sending an admin to rename a group
# whose name is fine. One string, both stores, so they cannot drift apart again.
GROUP_LINK_TAKEN = (
    "tenant '{tenant}' already has a group linked to directory group '{external_id}'. "
    "One directory group is one group here, or membership would have two homes and the "
    "reconciliation would put somebody in both."
)

# Step 071. `GROUP_NAME_TAKEN` for a rename, and it names the *other* group's id rather
# than only the name: the reader is a SCIM push that has to say which row collided, and
# the name alone is the thing that collided.
GROUP_RENAME_TAKEN = (
    "tenant '{tenant}' already has a group called '{name}' (group '{other}'). Names are "
    "how a person picks a group on the command line, so two with one name is a command "
    "whose meaning depends on insertion order."
)

# Step 071. The one refusal `mint_scim_token` makes that is the caller's to fix, and the
# same sentence `access/scim/tokens.py` uses when the issuer row is found to be gone at
# resolve time — one sentence at both ends, on migration 052's rule.
SCIM_ISSUER_NOT_REGISTERED = (
    "this tenant has no identity provider registered at issuer '{issuer}'. A SCIM "
    "token is bound to the provider whose pushes it speaks for, so the rows it "
    "provisions can be adopted at that provider's first sign-in; register the "
    "provider first, or name one that is registered."
)

# `create_agent` with an owner argument that is present and empty. There is no default
# and there must not be one: an owner that can be omitted is an owner that eventually is,
# and the artifact is an agent nobody — including its author — can run.
NO_OWNER = (
    "create_agent needs an owner. An agent with no owner grant cannot be run by "
    "anybody, including whoever created it, because absence is denial."
)

# What `create_agent` raises on a name that exists. Says nothing about who owns it — see
# `AgentNameTaken`, where the reason that omission is deliberate is written down.
AGENT_NAME_TAKEN = (
    "this organisation already has an agent called '{agent}'. Names are how an agent is "
    "addressed in a URL and in every record of what it did, so there is exactly one of "
    "each. Choose another."
)

# What a rename refuses when the new name is the old one. Step 025 decision 4: a no-op is
# not the answer, because a request that asks for nothing is a mistake somebody made and
# silently succeeding at it writes a version row arguing about whether anything happened.
AGENT_RENAME_TO_SELF = (
    "agent '{agent}' is already called that. A rename that changes nothing would still "
    "advance its version history, so nothing was written."
)

# A version row claiming a provenance neither store knows. Migration 032 leaves this
# vocabulary out of the schema deliberately (see `VERSION_SOURCES`), so this refusal is
# the whole of the constraint and both stores must raise it.
UNKNOWN_VERSION_SOURCE = (
    "'{source}' is not a way a config version can come to exist. A version records which "
    "write produced it, and a source nothing writes is a row nobody can explain."
)

BAD_VERSION_NUMBER = (
    "{what} must be an integer, got {value}. Postgres will cast a string to compare it "
    "against the column and the in-memory store will not, so a caller passing anything "
    "else gets an answer from one and an absence from the other."
)

UNSTORABLE_CONFIG = (
    "this {what} cannot be stored{at}: {why}. Postgres holds a config in a jsonb column "
    "and refuses this outright, so accepting it here would mean a config that works "
    "against the in-memory store and fails in a deployment."
)

BAD_VERSION_LIMIT = (
    "a version limit must be a non-negative integer, got {value}. Postgres refuses a "
    "negative LIMIT outright; a Python slice quietly drops rows off the end, which is a "
    "truncated history reported as a whole one."
)

# What a version write refuses when `restored_from` names a version that was never
# written. Migration 032 says the same thing as a self-referential foreign key; this is
# the fake's half, and the message is the one both stores raise.
# The self-referential key migration 032 creates, named here because Postgres reports a
# violation by constraint name and `_translate` would otherwise call it an unknown
# tenant. Asserted by a test that reads `pg_constraint`, on 020's lesson that a rename
# carries constraint names along and `DROP CONSTRAINT IF EXISTS <the obvious name>` is
# silent.
#
# **Migration 035 renamed it, and gave it a name of its own rather than another
# auto-generated one.** 032 let Postgres derive it from the table and columns, which meant
# this constant spelled out a column list — so re-keying the table silently invalidated it,
# and the only thing that would have noticed is the test that reads the catalogue. That
# test is why the rename was caught; the explicit name is why the next re-key will not need
# it to be.
RESTORED_FROM_FK = "agent_versions_restored_from_fkey"

# `agents_name_unique` from migration 035 — what a taken name violates now that the
# primary key is the id. Named here for `RESTORED_FROM_FK`'s reason: `create_agent` and
# `rename_agent` both catch this by name to answer `AgentNameTaken`, and the other unique
# key on the same table is the one on `agent_id`, where the honest answer is not "that
# name is taken" but "a uuid4 collided". Asserted against `pg_constraint` by a test.
AGENT_NAME_UNIQUE = "agents_name_unique"

RESTORED_FROM_UNKNOWN = (
    "agent '{agent}' has no version {version}, so a restore cannot have come from it. "
    "Nothing was written."
)

# What a version write refuses when the number it was given already holds something else.
# See `_write_version` in either store: the suppression rests on the counter and the row
# agreeing, and this is what happens when they do not.
VERSION_COLLISION = (
    "version {version} of '{agent}' already exists and holds a different configuration. "
    "The version counter on the agent row and its history have disagreed, so nothing was "
    "written — writing would have left the live config unrecorded while the history "
    "claimed to hold it."
)

# --- scheduling, migration 033 -----------------------------------------------------

# What a schedule names when it refuses. Both stores raise these, because migration 033
# deliberately puts no CHECK behind the cadence vocabulary — see the migration, and
# `VERSION_SOURCES` for the same argument one table over.
BAD_CADENCE = (
    "this is not a cadence this system can express: {why}. The vocabulary is "
    "{{'every': 'day', 'at': 'HH:MM'}}, {{'every': 'week', 'on': '<weekday>', 'at': "
    "'HH:MM'}} or {{'every': 'hour', 'at': ':MM'}} — and nothing finer than an hour, "
    "which is deliberate rather than missing: a schedule is the first thing in this "
    "product that submits runs on a timer, and every-N-minutes is the door that turns "
    "an outage into a bill."
)

BAD_TIMEZONE = (
    "'{timezone}' is not a timezone this machine knows. A schedule needs an IANA name — "
    "'Europe/Berlin', 'America/New_York', 'UTC' — because 'every morning at 07:30' is a "
    "claim about a wall clock, and a schedule that cannot name its own clock fires at "
    "the wrong hour every day rather than failing once."
)

MISSING_TIMEZONE = (
    "a schedule must name its timezone, and there is deliberately no default. Defaulting "
    "to UTC would turn somebody's 'every morning at 07:30' into 3am silently, every day, "
    "with nothing anywhere reading as wrong."
)

# The two foreign keys migration 033 creates, named here because Postgres reports a
# violation by constraint name and `_translate` would otherwise call both of them an
# unknown tenant — which is what a reader of the resulting 503 would then go and check.
#
# Postgres auto-names them from the table and the columns. **That name is asserted out of
# `pg_constraint` by the end-to-end check rather than trusted here**, on 020's lesson: a
# constraint's live name and the name its migration appears to give it are different
# facts, and the code that discriminates on one of them fails silently when they diverge.
#
# The agent key is `schedules_agent_fkey` since migration 035, which names it explicitly
# rather than letting Postgres derive it from a column list — see `RESTORED_FROM_FK` for
# what the derived spelling cost when the columns moved. The token key still carries the
# derived name, because 035 does not touch it.
SCHEDULE_AGENT_FK = "schedules_agent_fkey"
SCHEDULE_TOKEN_FK = "schedules_tenant_id_token_id_fkey"

NO_SUCH_AGENT_TO_SCHEDULE = (
    "tenant '{tenant}' has no agent called '{agent}'. A schedule is standing "
    "configuration naming an agent, so it cannot be created for one that is not there — "
    "and if it could, it would spring to life the day somebody reused the name."
)

NO_SUCH_TOKEN_TO_FIRE_AS = (
    "tenant '{tenant}' has no API token with id '{token}'. A schedule fires as a machine "
    "and there is no such thing as one that fires as nobody — mint it with --mint-token, "
    "then grant it the agent. A token belonging to another customer is refused by the "
    "same key, which is the more important half of what it enforces."
)

# The three arms of the cadence union. A frozenset with no CHECK behind it, on migration
# 022's reasoning for `ADMIN_ACTIONS` and 032's for `VERSION_SOURCES`: a vocabulary that
# grows with the code does not want a migration per value.
#
# **The absence of anything below `hour` is a control, not an omission.** See `BAD_CADENCE`
# and migration 033's header — this is where 020's "a machine can submit at loop speed"
# row is answered structurally rather than with a budget nobody has built yet.
SCHEDULE_CADENCES = frozenset({"day", "week", "hour"})

# Monday-first, because `datetime.weekday()` is and a second ordering would be a second
# thing to get wrong. The index into this tuple *is* the value `weekday()` returns.
WEEKDAYS = (
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
)

# Every field a `schedules` row carries, in the order both stores return it.
SCHEDULE_FIELDS = (
    "id",
    "tenant_id",
    # Migration 035. The column; `agent_name` beside it is derived from it on every read,
    # so a rename changes what a listing shows without writing a row here.
    "agent_id",
    "agent_name",
    "token_id",
    "task",
    "cadence",
    "timezone",
    "enabled",
    "next_fire_at",
    "last_fired_at",
    "last_run_id",
    "last_outcome",
    "created_by",
    "created_at",
    "updated_at",
)

# What the idempotency key of a fire is built from. Here rather than in `schedules.py`
# because **two things need it and they are in different layers**: the scheduler writes
# these keys, and anything asking "which runs did this schedule produce" reads them back
# as a prefix. A convention held in one module and re-spelled in another is one that
# drifts the first time somebody changes the separator.
SCHEDULE_KEY_PREFIX = "sched:"


def schedule_fire_key(schedule_id: str, due_at: datetime) -> str:
    """The idempotency key for one schedule's one due instant.

    **This is the exactly-once mechanism**, and it is `runs_idempotency` doing the work
    rather than anything new: two workers that both fire the same due row submit the same
    key, and the partial unique index means one run exists. There is no read-then-write
    window anywhere in that, which is the same property 014 relied on for
    `runs_one_live_child`.

    `due_at` is the instant the row said it was due — never `now()`. A key carrying the
    firing worker's clock would be a different key per worker, which is exactly the
    duplicate this exists to prevent.
    """
    return f"{SCHEDULE_KEY_PREFIX}{schedule_id}:{due_at.astimezone(timezone.utc).isoformat()}"


def schedule_key_prefix(schedule_id: str) -> str:
    """Every key `schedule_fire_key` can mint for one schedule, as a prefix.

    **Named here, beside the minting function, because 035k made the derivation
    load-bearing.** Until it, the prefix was spelled inline in `schedules.runs_of`; now
    two stores match on it to answer a route, and a prefix that disagreed with the keys
    actually written would be a run history that is quietly empty. One home, so the two
    cannot drift — `describe_cadence`'s argument at a smaller expression.
    """
    return f"{SCHEDULE_KEY_PREFIX}{schedule_id}:"


# The two foreign keys migration 034 creates, on `SCHEDULE_AGENT_FK`'s reasoning and
# with its caveat intact: the live names are asserted out of `pg_constraint` by the
# end-to-end check rather than trusted here.
TRIGGER_AGENT_FK = "triggers_agent_fkey"
TRIGGER_TOKEN_FK = "triggers_tenant_id_token_id_fkey"

NO_SUCH_AGENT_TO_TRIGGER = (
    "tenant '{tenant}' has no agent called '{agent}'. A trigger is standing "
    "configuration naming an agent, so it cannot be created for one that is not there — "
    "and if it could, its URL would spring to life the day somebody reused the name."
)

NO_SUCH_TOKEN_TO_TRIGGER = (
    "tenant '{tenant}' has no API token with id '{token}'. A trigger fires as a machine "
    "and there is no such thing as one that fires as nobody — mint it with --mint-token, "
    "then grant it the agent. A token belonging to another customer is refused by the "
    "same key, which is the more important half of what it enforces."
)

# Every field a `triggers` row carries, in the order both stores return it. The sealed
# secret rides along: it is ciphertext bound to this row and useless anywhere else, and
# a listing that silently dropped two of the table's columns would be the `RUN_FIELDS`
# drift waiting to happen. Surfaces that show a trigger to a person omit it themselves.
TRIGGER_FIELDS = (
    "id",
    "tenant_id",
    # Migration 035, `SCHEDULE_FIELDS`' twin.
    "agent_id",
    "agent_name",
    "token_id",
    "name",
    "task",
    "secret_sealed",
    "secret_key_id",
    "enabled",
    "last_delivery_at",
    "last_run_id",
    "last_outcome",
    "created_by",
    "created_at",
    "updated_at",
)

# What the idempotency key of a delivery is built from — here rather than in
# `triggers.py` for `SCHEDULE_KEY_PREFIX`'s exact reason: the door writes these keys and
# anything asking "which runs did this trigger produce" reads them back as a prefix.
TRIGGER_KEY_PREFIX = "trig:"


def trigger_fire_key(trigger_id: str, body: bytes) -> str:
    """The idempotency key for one trigger's one delivery.

    **This is the replay protection**, and it needs no timestamp: `runs_idempotency` is
    a *permanent* unique index, so a byte-identical redelivery — a sender's retry, a
    captured request replayed next month — collapses to the run that already exists and
    executes nothing, at any later time rather than inside a tolerance window. A
    *modified* body would be a fresh key, and a modified body fails the HMAC first.

    The honest cost, stated where the key is minted: a sender whose *distinct* events
    are byte-identical bodies gets one run for all of them. Real senders' payloads carry
    their own ids and timestamps; a custom sender that wants distinct fires includes any
    distinguishing field. The door's contract is that an identical body is the same
    event — which is exactly what makes replaying one harmless.
    """
    return f"{TRIGGER_KEY_PREFIX}{trigger_id}:{hashlib.sha256(body).hexdigest()}"


# The namespaces the platform mints keys in. A caller may not spell one, and the reason
# is `check_idempotency_key`'s.
RESERVED_KEY_PREFIXES = (SCHEDULE_KEY_PREFIX, TRIGGER_KEY_PREFIX)


def check_idempotency_key(key: str) -> str:
    """A key a **caller** supplied, or `ValueRefused`. Returns it unchanged.

    **`runs_idempotency` is `(tenant_id, idempotency_key)` — there is no principal in
    it** — and it is permanent by design, which is what makes a trigger's replay
    protection work at all. Both properties together mean the key namespace is a shared,
    write-once resource inside a tenant, and the platform mints keys in it from values
    that are not secret: `trig:<trigger id>:<sha256 of the body>` and
    `sched:<schedule id>:<due instant>`. A trigger id and a schedule id are both readable
    by anyone with `user` on the agent, and a due instant is in the same listing.

    So without this check, the lowest-privileged member of a tenant could compute the key
    a delivery or a fire *was going to use* and book it first with an ordinary
    `POST /runs`. When the genuine, correctly-signed delivery arrived it would collide:
    **409 forever** if the squatter chose a different agent or task — permanently, because
    the index does not expire — or a silent 202 `created=False` naming the squatter's run
    if they matched, which tells the outside sender it succeeded while nothing of the
    trigger's ran. A door that cannot be opened and reports success is worse than one that
    refuses.

    Found by driving `POST /runs` after 023b made trigger ids readable over HTTP. The plan
    had anticipated the *accident* — "a person types a `trig:`-prefixed key" — and
    answered it with the 409 the typist deserves; it had not considered the same act done
    on purpose against the door, which is the difference between a collision and an
    attack. Reserving the namespace is the whole fix: the platform's keys stay derivable
    (they must be, for two workers to collide on the same fire), and nobody outside the
    platform can spell one.

    Held here, beside the prefixes, rather than at the one route that reads the header —
    021's `role_of` lesson, before the second surface exists rather than after it.
    """
    for prefix in RESERVED_KEY_PREFIXES:
        if key.startswith(prefix):
            raise ValueRefused(
                f"'{prefix}' starts a reserved idempotency key. The platform mints keys "
                f"in that namespace for schedules and triggers, and a caller that could "
                f"spell one could take a fire's key before it fired. Choose any key that "
                f"does not begin with {' or '.join(repr(p) for p in RESERVED_KEY_PREFIXES)}."
            )
    return key


def check_sealed_secret(value) -> None:
    """Refuse a secret that is not sealed. Raises `StorageError`.

    **A function rather than a line inside `normalize_trigger`, as of 035k**, because
    that is the step that gave the column a second writer. `rotate_trigger_secret` does
    not go through the normalizer — it writes two columns of an existing row rather than
    building a new one — so the guard would have been one function away from the write it
    guards, which is the exact shape `check_config_is_storable` was in when 035i found it
    walking a dict's values and never its keys.

    `StorageError` and not `ValueRefused`, deliberately, and this is the one place on
    that boundary where a 503 is the honest answer: no caller can put a value here. The
    plaintext never leaves `triggers.py`, so a `str` arriving in this column is a module
    above sealing nothing — a bug in our code, not a mistake in somebody's request.
    """
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise StorageError(
            f"trigger 'secret_sealed' must be bytes — the sealed blob from crypto.seal — "
            f"got {type(value).__name__}. A plaintext secret must "
            "never reach storage in any column."
        )
    # **Empty too, and this is `check_reseal`'s rule reached rather than re-derived.**
    # That function guards the *third* writer of this same column (026's key sweep) and
    # refuses an empty blob as well as a wrongly-typed one. A guard on one writer of a
    # column that is weaker than the guard on another is the drift this function was
    # extracted to prevent — so it takes the stricter of the two, and `memoryview` comes
    # with it for the same reason.
    if not bytes(value):
        raise StorageError(
            "trigger 'secret_sealed' is empty — a trigger without a sealed secret is a "
            "door with no lock. This is minted by the module above, so it is a bug "
            "rather than an input."
        )


def normalize_trigger(trigger: dict) -> dict:
    """Validate and fill in a `triggers` row. Migration 034.

    `normalize_schedule`'s job at the next table: both stores refuse identically, in the
    same sentences, including what Postgres would catch anyway. The secret arrives
    **already sealed** — `(secret_sealed, secret_key_id)` from `crypto.seal` — because
    storage never sees a plaintext secret; that is `mint`'s division of labour
    (`access/tokens.py`) and `connections`' before it, and a layer that cannot see a
    secret cannot log one.

    **Two refusal families, and the line between them is where the value came from.**
    `name`, `task`, `agent_name` and `token_id` arrive from outside the process — a form,
    a JSON body, a flag — so an empty one is a person's mistake and answers `ValueRefused`
    (400). `id`, `secret_sealed` and `secret_key_id` are minted by this codebase, so an
    empty one means the layer above is broken and `StorageError` is the truth. Split
    after an edge hunt found the whole list answering *"storage unavailable: try again
    later"* to somebody who left a field blank — the sixth instance of a check written
    for a CLI (where every refusal is one `parser.error` and the family costs nothing)
    later being put behind a form. `normalize_schedule` had it too.
    """
    typed = [
        field
        for field in ("agent_name", "token_id", "name", "task")
        if not trigger.get(field)
    ]
    if typed:
        raise ValueRefused(
            f"a trigger needs {', '.join(sorted(typed))}. It is standing configuration "
            "naming an agent and a machine to act as, and its name is how somebody "
            "finds it again in a list beside an outside system's configuration screen."
        )

    minted = [field for field in ("id", "secret_key_id") if not trigger.get(field)]
    if not trigger.get("secret_sealed"):
        minted.append("secret_sealed")
    if minted:
        raise StorageError(
            f"trigger is missing {sorted(minted)}. The sealed secret is what a delivery "
            "must prove it holds — a trigger without one is a door with no lock. These "
            "are minted by the module above, so this is a bug rather than an input."
        )

    check_sealed_secret(trigger["secret_sealed"])

    # 021 defect 8's discipline at the two TEXT columns a person types. The task is the
    # sharper one: it becomes part of a prompt and a run row, and a NUL byte a dict
    # holds happily is refused outright by Postgres.
    check_config_is_storable({"name": trigger["name"]}, what="name")
    check_config_is_storable({"task": trigger["task"]}, what="task")

    return {
        "id": trigger["id"],
        "agent_name": trigger["agent_name"],
        "token_id": trigger["token_id"],
        "name": trigger["name"],
        "task": trigger["task"],
        "secret_sealed": bytes(trigger["secret_sealed"]),
        "secret_key_id": trigger["secret_key_id"],
        "enabled": bool(trigger.get("enabled", True)),
    }


def describe_cadence(cadence: dict) -> str:
    """A cadence as a person would say it: `every day at 07:30`.

    One definition, because **three surfaces render this and two of them are records
    somebody reads years later** — the administrative log, `--list-schedules`, and any
    screen that arrives later. `RUN_FIELDS`' lesson: a shape spelled out at each call
    site is one that drifts, and here the drift would be between what the log says a
    schedule was and what the product shows it is.

    Assumes a cadence `check_cadence` has already accepted, and says so by being unable
    to fail: an unknown `every` renders as itself rather than raising, because a
    formatter that can refuse is one that can take down the log line explaining why
    something was refused.
    """
    every = cadence.get("every")
    at = cadence.get("at", "")
    if every == "day":
        return f"every day at {at}"
    if every == "week":
        return f"every {cadence.get('on', '?')} at {at}"
    if every == "hour":
        return f"every hour at {at}"
    return f"{every} {at}".strip()


def _known_timezones() -> frozenset:
    """The canonical IANA key set, read once.

    `available_timezones()` costs ~10ms and is not cached by `zoneinfo`, so it is cached
    here: this is on every schedule write. A process restart is what picks up a tzdata
    update, which is how tzdata is deployed anyway.
    """
    global _TIMEZONE_KEYS
    if _TIMEZONE_KEYS is None:
        try:
            _TIMEZONE_KEYS = frozenset(available_timezones())
        except Exception:  # noqa: BLE001 - an image with no tzdata at all
            _TIMEZONE_KEYS = frozenset()
    return _TIMEZONE_KEYS


_TIMEZONE_KEYS = None


def check_timezone(name) -> str:
    """An IANA zone both stores accept, or `ValueRefused`. Returns it.

    Validated at **every write and never at fire time**, which is the whole point of
    doing it here: a schedule whose zone cannot be loaded is one that fails inside a
    worker loop at 3am, in a thread whose only reader is a log file, instead of failing
    in front of the person who typed it.

    ## Membership first, and the load second — because a load alone is not portable

    **Found by an edge hunt on macOS.** `ZoneInfo('europe/berlin')` *loads here*, because
    `zoneinfo` resolves a key by opening a file and this filesystem is case-insensitive.
    It is not an IANA key: `'europe/berlin' not in available_timezones()`. So a schedule
    created on a developer's Mac would store a zone name that raises `ZoneInfoNotFoundError`
    the moment the same row is read on a Linux deployment — inside the worker loop, at
    3am, which is exactly the failure this function exists to prevent, arriving by the one
    route it was not checking.

    The load is still attempted after the membership check, because a key can be listed
    and unreadable (a truncated tzdata), and refusing early is the whole point.
    """
    if not isinstance(name, str) or not name:
        raise ValueRefused(MISSING_TIMEZONE)

    known = _known_timezones()
    if known and name not in known:
        raise ValueRefused(BAD_TIMEZONE.format(timezone=name))

    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError) as exc:
        # `ValueError` is a name with a `..` or a leading slash — zoneinfo treats a
        # traversal attempt as a bad key rather than reading the file, and refusing it
        # here means a stored zone is always a name this machine resolved once.
        raise ValueRefused(BAD_TIMEZONE.format(timezone=name)) from exc
    return name


def check_next_fire_at(value, *, what: str = "next_fire_at") -> datetime:
    """An instant a schedule's clock may hold. Returns it; raises `StorageError`.

    **Its own function because three writes set this column and only one of them was
    checking it.** `normalize_schedule` refused a naive instant from the first version;
    `advance_schedule` and `set_schedule_enabled` took whatever they were handed. That is
    021's lesson exactly — a rule stated in one place and enforced at one of the paths
    that needs it — and here it had teeth, which is why this is a function rather than a
    line copied twice.

    **What the hole did, measured rather than imagined.** A `None` or a naive value goes
    into the in-memory store unchallenged (Postgres coerces the naive one and refuses the
    `None`, so the two stores disagree as well). The very next `due_schedules` then raises
    `TypeError: can't compare offset-naive and offset-aware datetimes` — and
    `due_schedules` is **one scan across every tenant**, evaluated before any schedule is
    considered. So one malformed row stops scheduling for the entire deployment, in every
    customer, permanently, and the only symptom is `scheduler tick failed` once per tick
    in a log nobody is reading at 3am.
    """
    if value is None or not isinstance(value, datetime):
        raise StorageError(
            f"schedule '{what}' must be a datetime, got {value!r}. This column is the "
            "scheduler's clock and it is read by one query across every customer — a row "
            "holding anything else stops scheduling for all of them rather than for one."
        )
    if value.tzinfo is None:
        raise StorageError(
            f"schedule '{what}' must be timezone-aware. A naive value is read as "
            "server-local time, which moves every fire by however far the deployment is "
            "from UTC — and in the in-memory store it cannot be compared against an "
            "aware instant at all, which stops every tenant's schedules rather than this "
            "one's."
        )
    return value


def check_outcome(last_run_id: str, last_outcome: str) -> None:
    """What a fire may write back about itself. Raises `StorageError`.

    021 defect 8 at two more TEXT columns. `last_outcome` is built from `str(exc)` of
    whatever refused the fire, so its content is only as constrained as the messages
    upstream of it — and a NUL byte is stored happily by a dict and refused outright by
    Postgres, which is the divergence that makes a suite green about a write that 503s.
    """
    for field, value in (("last_run_id", last_run_id), ("last_outcome", last_outcome)):
        if not isinstance(value, str):
            raise StorageError(f"schedule '{field}' must be a string, got {value!r}")
        check_config_is_storable({field: value}, what=field)


def check_cadence(cadence) -> dict:
    """A cadence both stores read identically, or `ValueRefused`. Returns it.

    **`ValueRefused` rather than a bare `StorageError`, which is a 400 rather than a 503,
    and it was the second family for the first eight months of this function's life.**
    022 wrote these refusals for a CLI, where every `StorageError` becomes the same
    `parser.error` and the distinction cost nothing. 022b put a form in front of them, and
    every cadence a person mistypes would have answered *"storage unavailable: try again
    later"* about a payload that will never work — sending somebody to check a database
    that is fine. Found by driving the route at its edges, which is where this project has
    now found the same family error five times; see `ValueRefused`'s own docstring, which
    describes this exact case in as many words.

    Exact rather than lenient, and every branch below is a sentence somebody reads. The
    reason for the strictness is that this value is *only* ever read by a background
    loop: a cadence that parses loosely produces a schedule that fires at a time nobody
    asked for and that nothing reports, which is worse than a refusal at the keyboard.

    Extra keys are refused rather than ignored, on `normalize_vetted_tool`'s precedent —
    `{"every": "day", "at": "07:30", "on": "monday"}` is somebody expecting a weekly
    schedule, and silently dropping the key they meant is how they find out in a month.
    """
    if not isinstance(cadence, dict):
        raise ValueRefused(BAD_CADENCE.format(why=f"expected an object, got {type(cadence).__name__}"))

    every = cadence.get("every")
    if every not in SCHEDULE_CADENCES:
        raise ValueRefused(
            BAD_CADENCE.format(why=f"'every' must be one of {sorted(SCHEDULE_CADENCES)}, got {every!r}")
        )

    allowed = {"every", "at"} | ({"on"} if every == "week" else set())
    extra = sorted(set(cadence) - allowed)
    if extra:
        raise ValueRefused(
            BAD_CADENCE.format(
                why=f"an '{every}' cadence has no {extra} — it is read by a background "
                f"loop, so a key nobody honours is a schedule that fires at a time "
                f"nobody chose"
            )
        )

    at = cadence.get("at")
    if not isinstance(at, str):
        raise ValueRefused(BAD_CADENCE.format(why=f"'at' must be a string, got {at!r}"))

    if every == "hour":
        # `:MM`, and the leading colon is what makes it read as *past the hour* rather
        # than as an hour somebody mistyped.
        if not at.startswith(":"):
            raise ValueRefused(
                BAD_CADENCE.format(why=f"an hourly cadence is ':MM' — minutes past the hour — not {at!r}")
            )
        _check_two_digits(at[1:], "minute", 59, at)
    else:
        hour, _, minute = at.partition(":")
        if not minute and ":" not in at:
            raise ValueRefused(BAD_CADENCE.format(why=f"'at' must be 'HH:MM', got {at!r}"))
        _check_two_digits(hour, "hour", 23, at)
        _check_two_digits(minute, "minute", 59, at)

    if every == "week":
        on = cadence.get("on")
        if on not in WEEKDAYS:
            raise ValueRefused(
                BAD_CADENCE.format(why=f"'on' must be one of {list(WEEKDAYS)}, got {on!r}")
            )

    return dict(cadence)


def _check_two_digits(value: str, what: str, ceiling: int, at: str) -> int:
    """`07` — exactly two digits, in range. Raises `ValueRefused`.

    Two digits **exactly**, so `7:5` is refused rather than read as 07:05. A format that
    accepts both spellings is one where a config file and a screen disagree about what
    the same schedule says, and `int()` alone would also accept `' 7'`, `'+7'` and
    `'٧'` — Python's int() reads Unicode digits, which is a fine default everywhere
    except a field that is going to be compared as a string.
    """
    if len(value) != 2 or not all(character in "0123456789" for character in value):
        raise ValueRefused(
            BAD_CADENCE.format(
                why=f"the {what} in {at!r} must be exactly two digits — '07', not '7'"
            )
        )
    number = int(value)
    if number > ceiling:
        raise ValueRefused(
            BAD_CADENCE.format(why=f"{at!r} names {what} {number}, and the highest is {ceiling}")
        )
    return number


# The fields a `PATCH` may move, and the list is the decision rather than a convenience.
#
# **`enabled` is deliberately absent.** It has two verbs of its own, with their own
# idempotence (`AND enabled <> %s`) and their own administrative records; a second path to
# the same state would be a second home for that rule. **`agent_name` is absent** because
# it is the URL and the containment check — a body that disagreed with the path is a 400
# whose whole job is to teach that, on `PATCH /agents/{name}`'s precedent for `name`. And
# `next_fire_at`, `last_*`, `id` and the stamps are absent because they are derived or
# historical: a caller setting `next_fire_at` directly is the backfill the no-backfill
# rule exists to refuse, arriving through a different door.
SCHEDULE_PATCH_FIELDS = ("task", "cadence", "timezone", "token_id")


def normalize_schedule_changes(changes: dict) -> dict:
    """Validate a partial `schedules` write. Returns the fields that move. 035k.

    **`normalize_schedule`'s checks, reached by the same names**, which is the whole
    reason this is beside it rather than in `schedules.py`: the *six wrong refusal
    families* row says the shape spreads by copy — a new normalizer written from the last
    one, family and all — and a patch path with its own hand-rolled bounds would be the
    seventh instance waiting to be found. `check_cadence`, `check_timezone` and
    `check_config_is_storable` are called here exactly as create calls them, so the two
    doors into these four columns cannot develop different sentences.

    `next_fire_at` is accepted and checked but is **not** in `SCHEDULE_PATCH_FIELDS`: the
    caller above recomputes it from the new cadence through `first_fire` and passes it
    down, which is `set_schedule_enabled`'s split and keeps this layer free of the cadence
    vocabulary. It is not something a request can carry.

    An empty patch is refused rather than accepted as a no-op. A `PATCH` that moves
    nothing still advances `updated_at` and still writes a record, so accepting one would
    put a row in the log saying a person changed a schedule and nothing about what — and
    the sentence a person needs is that they sent no fields.
    """
    unknown = sorted(set(changes) - set(SCHEDULE_PATCH_FIELDS) - {"next_fire_at"})
    if unknown:
        raise StorageError(
            f"cannot change {unknown} on a schedule. The module above decides which "
            f"fields move ({', '.join(SCHEDULE_PATCH_FIELDS)}), so this is a bug rather "
            "than an input."
        )

    moved: dict = {}

    if "task" in changes:
        if not changes["task"]:
            raise ValueRefused(
                "a schedule needs task. It is what the agent is asked to do at every "
                "fire, and a schedule that asks nothing fires nothing worth having."
            )
        check_config_is_storable({"task": changes["task"]}, what="task")
        moved["task"] = changes["task"]

    if "cadence" in changes:
        cadence = check_cadence(changes["cadence"])
        check_config_is_storable(cadence, what="cadence")
        moved["cadence"] = cadence

    if "timezone" in changes:
        moved["timezone"] = check_timezone(changes["timezone"])

    if "token_id" in changes:
        if not changes["token_id"]:
            raise ValueRefused(
                "a schedule needs token_id. It is the machine it fires as, and there is "
                "no such thing as a schedule that fires as nobody."
            )
        moved["token_id"] = changes["token_id"]

    if not moved:
        raise ValueRefused(
            f"this changes nothing about the schedule. Send at least one of "
            f"{', '.join(SCHEDULE_PATCH_FIELDS)}."
        )

    if "next_fire_at" in changes:
        moved["next_fire_at"] = check_next_fire_at(changes["next_fire_at"])

    return moved


def schedule_update_detail(before: dict, moved: dict) -> dict:
    """What a `schedule.update` record carries. 035k.

    **The keys that moved, and never their values** — `schedule.create`'s redaction rule
    at the same table, and `AGENT_DETAIL_REDACTED`'s one column over. The task is the
    sharp one: it is the same class of content as `default_task`, which migration 022
    keeps out of a record about an agent, and a record is forever.

    The three exceptions are the three `schedule.create` already names out loud, so this
    discloses nothing that log line does not: the cadence as a sentence, the zone, and
    the machine. They are named because *what did this become* is the question somebody
    reading a fire schedule's history is actually asking, and a record saying only
    `["cadence"]` sends them to a `GET` they may not be entitled to make.

    **`changed` is a real diff against the stored row, not the list of fields the request
    wrote**, and the difference is not pedantry. A `PATCH` that sets four fields to the
    values they already hold is legal — it is how a client that re-sends a whole form
    behaves — and the first version of this function recorded it as *"cadence, task,
    timezone and token_id changed"*. In an append-only record read years later that is a
    false hit for the one query this row exists to answer: **who changed the machine this
    fires as**. `ScheduleChanged` already computed a real diff for its 409 body, so the
    log was the only half of this chunk that lied.

    A no-op edit therefore records `changed: []` rather than being refused. That is
    `update_agent`'s precedent, which advances `updated_at` and writes an `agent.update`
    record for a save that changed nothing, while writing no version row: **the log holds
    the act, and the act happened.** What it must not do is misdescribe it.

    `next_fire_at` is not listed. It is a consequence of a cadence change rather than a
    field anybody sent, and listing it would read as a fifth thing the person did.
    """
    # Compared against the stored row, so a field re-sent unchanged does not appear.
    # `cadence` is a dict and `before` holds it as one in both stores, so `!=` is the
    # right comparison and not an identity check.
    changed = sorted(
        key
        for key, value in moved.items()
        if key != "next_fire_at" and before.get(key) != value
    )
    detail: dict = {"agent": before["agent_name"], "changed": changed}
    # Only for what actually moved: naming the new cadence of an edit that did not touch
    # the cadence would put the same claim back one key over.
    if "cadence" in changed:
        detail["cadence"] = describe_cadence(moved["cadence"])
    if "timezone" in changed:
        detail["timezone"] = moved["timezone"]
    if "token_id" in changed:
        detail["fires_as"] = f"machine:{moved['token_id']}"
    return detail


def normalize_schedule(schedule: dict) -> dict:
    """Validate and fill in a `schedules` row. Migration 033.

    Everything a caller may set, checked here so both stores refuse identically — the
    same job `normalize_api_token` does for 031, including the parts Postgres would catch
    anyway. The fake being *stricter than nothing* is not the goal; the fake and Postgres
    producing the same sentence is.

    `check_config_is_storable` runs over the cadence for 021 defect 8's reason: `cadence`
    is a jsonb column, a dict holds a `NaN` or a lone surrogate happily, and Postgres
    refuses it — so without this the suite would go green on schedules that 503 in
    production. The task gets the same treatment because a NUL byte is refused by TEXT
    too, which is the same lesson at a different column type.
    """
    # `created_by` is deliberately absent from this list: it is the `actor` keyword every
    # write on this interface already takes, on `normalize_api_token`'s shape. A field
    # that could arrive either in the dict or beside it is one that arrives in neither.
    # **Two families, split by where the value came from** — `normalize_trigger`'s
    # comment carries the argument, and this address is the older of the two: a `POST
    # /agents/{name}/schedules` with an empty task has answered *"storage unavailable:
    # try again later"* since 022b shipped the route. Found driving the *trigger* routes
    # at their edge and fixed here too, because a fix at one address of a shape that has
    # now appeared six times is how it appears a seventh.
    typed = [
        field for field in ("agent_name", "token_id", "task") if not schedule.get(field)
    ]
    if typed:
        raise ValueRefused(
            f"a schedule needs {', '.join(sorted(typed))}. `token_id` is the machine it "
            "fires as, and there is no such thing as a schedule that fires as nobody."
        )
    if not schedule.get("id"):
        raise StorageError(
            "schedule is missing ['id']. It is minted by the module above, so this is a "
            "bug rather than an input."
        )

    cadence = check_cadence(schedule.get("cadence"))
    check_config_is_storable(cadence, what="cadence")
    check_config_is_storable({"task": schedule["task"]}, what="task")
    timezone_name = check_timezone(schedule.get("timezone"))

    # Shared with `advance_schedule` and `set_schedule_enabled`, which is the whole point
    # of it being a function — see `check_next_fire_at`.
    next_fire_at = check_next_fire_at(schedule.get("next_fire_at"))

    return {
        "id": schedule["id"],
        "agent_name": schedule["agent_name"],
        "token_id": schedule["token_id"],
        "task": schedule["task"],
        "cadence": cadence,
        "timezone": timezone_name,
        "next_fire_at": next_fire_at,
        "enabled": bool(schedule.get("enabled", True)),
    }


# Every field a `groups` row carries, in the order both stores return it. Written down
# for the reason `RUN_FIELDS` is: the table has fixed columns, the in-memory store keeps
# whatever dict it is handed, and a field added to one and forgotten in the other is
# silently dropped by the other. That is how `audit.credential` shipped with 818 tests
# green.
GROUP_FIELDS = (
    "tenant_id",
    "group_id",
    "name",
    "description",
    # Nullable, and NULL is not ''. A group that has been linked to a directory group
    # with an empty id and one that has never been linked are different states, and 9b
    # reads this column to tell them apart.
    "external_id",
    "created_by",
    "created_at",
)

GROUP_MEMBER_FIELDS = (
    "tenant_id",
    "group_id",
    "principal_kind",
    "principal_id",
    "added_by",
    "added_at",
)

# What one `platform_roles` row holds, in the order both stores return it. Migration 026,
# and the `RUN_FIELDS` device for the reason `VETTING_FIELDS` names: the contract suite
# builds its expectation from this tuple rather than typing the keys out, so a column
# added to one implementation and not the other fails without anybody remembering to
# extend a list.
PLATFORM_ROLE_FIELDS = (
    "tenant_id",
    "principal_kind",
    "principal_id",
    "role",
    "granted_by",
    "granted_at",
)

# Every field an `agents` row carries, in the order both stores return it. The
# `RUN_FIELDS` device, and step 10d is where it stopped being optional here.
#
# Until this step both read methods returned `config` alone, so `created_at` and
# `updated_at` were columns nothing above storage could see — and the in-memory store did
# not have them at all: `save_agent` wrote `copy.deepcopy(config)` into a dict, with no
# room for a modified time anywhere. "Use the ETag that already exists" was therefore two
# changes wearing one sentence, and the second half is exactly the drift this device
# catches: a field Postgres keeps and the fake drops, invisible to a suite that runs
# against the fake by default.
#
# `config` is the agent as every layer above this one speaks it. The rest is the row.
AGENT_FIELDS = (
    "tenant_id",
    # Migration 035, and the row's actual key. Everything below it in this tuple is
    # either the agent's configuration or its clock; this is the only field that says
    # *which agent this is*, and it is the only one that never changes.
    "agent_id",
    # Still here, still unique per tenant, and no longer the key. It is the URL, the thing
    # a person types, and the string in every audit record — see `AGENT_NAME_RE`.
    "name",
    "config",
    "created_at",
    # The ETag. Advanced by every write to the row, including `save_agent`'s upsert —
    # which is why re-seeding a tenant invalidates every open edit form in it. Rare, and
    # worth knowing before somebody debugs it.
    "updated_at",
    # Migration 032. The live version number, and it is **not** a second ETag: `If-Match`
    # still takes `updated_at`, because the compare-and-set is identical either way and
    # changing it would re-decide 010d inside a feature step. What this is for is naming
    # a row in `agent_versions` — it always names the newest one, and that one always
    # holds what `config` holds.
    #
    # It differs from `updated_at` in exactly one way, and the difference is the feature:
    # a write that changes nothing advances the timestamp and **not** this. The history
    # is of states; the log is of writes.
    "version",
)

# --- config version history -------------------------------------------------------
#
# Migration 032. `agents.config` is overwritten in place, `admin_audit` is forbidden from
# holding a prompt (022, and `agent_detail` below implements the refusal), so before this
# step no past configuration was reconstructible from anything the system kept.

# Every field an `agent_versions` row carries, in the order both stores return it.
AGENT_VERSION_FIELDS = (
    "tenant_id",
    # Migration 035's re-key, and the reason history survives a rename: the version rows
    # are keyed by the agent's identity, so renaming writes one row here (source `rename`)
    # and moves none.
    "agent_id",
    # **Derived, not stored.** The column is gone; both stores fill this in from the agent
    # it belongs to, so it is always the agent's name *now* rather than whatever it was
    # called when the version was written. The name inside `config` is the historical one —
    # see `agents.restore`, which normalises it on the way back out.
    "agent_name",
    "version",
    "config",
    # The agent's `updated_at` at the moment this version became live — passed in by the
    # write rather than generated here. What it supports is the *interval* reading:
    # version N was live from its `created_at` until N+1's.
    #
    # It does **not** mean an ETag names a version, though an earlier draft of this
    # comment said so. A save that changes nothing moves `agents.updated_at` and writes
    # no version, so a live agent's ETag is routinely newer than anything in its history.
    "created_at",
    "created_by",
    "source",
    "restored_from",
)

# What a *list* of versions carries: everything except the configs. `OAUTH_APP_PUBLIC_FIELDS`
# and `API_TOKEN_PUBLIC_FIELDS`' device, here for size rather than secrecy — a history card
# shows dates and authors, and fifty configs down the wire to render them is fifty prompts
# nobody asked for. The contract suite builds its expectation from this tuple, so adding
# `config` to a list projection fails without anybody remembering to check.
AGENT_VERSION_SUMMARY_FIELDS = tuple(
    field for field in AGENT_VERSION_FIELDS if field != "config"
)

# How a version came to exist. A frozenset with no CHECK behind it, on migration 022's
# reasoning for `ADMIN_ACTIONS`: a vocabulary that grows with the code does not want a
# migration per value, and the constraint that *is* structural — a restore names what it
# restored — is a CHECK in 032.
#
# `migration` is 032's backfill and nothing else writes it. It is a source rather than a
# hidden flag because version 1 of a pre-existing agent is the config as of the migration
# rather than as first written, and a screen that says "created by migration:032" is
# telling the truth about where history starts.
#
# `rename` is step 025's, and it is a source rather than a silent `update` because a
# rename is the one write that changes what the agent is *called* without changing what it
# *does* — a history screen showing "renamed" beside a config whose only difference is the
# `name` field is telling the truth about an edit nobody made to the prompt.
VERSION_SOURCES = frozenset(
    {"create", "save", "update", "restore", "migration", "rename"}
)

# The number every agent's history starts at.
FIRST_VERSION = 1


def check_version_source(source: str) -> None:
    """Refuse a source neither store would accept. Raises `StorageError`.

    Python-only, like `ADMIN_ACTIONS`' check and for the same reason — see
    `VERSION_SOURCES`. Both stores call it, so the fake refuses what Postgres would
    refuse if the CHECK existed, which is the parity the contract suite is for.
    """
    if source not in VERSION_SOURCES:
        raise StorageError(UNKNOWN_VERSION_SOURCE.format(source=source))


def check_version_number(version, *, what: str = "version") -> int:
    """A version number both stores read the same way. Returns it; raises `StorageError`.

    **Found by asking both stores the same odd question.** `get_agent_version(t, n, "1")`
    returned the row from Postgres — which casts a text literal to compare it against an
    `integer` column — and `None` from the fake, whose dict is keyed by an `int`. A
    caller passing the wrong type therefore got an answer from one store and an absence
    from the other, which is drift of the worst kind: the fake looks stricter and is
    merely differently wrong.

    `bool` is refused explicitly because `True == 1` in Python and `isinstance(True, int)`
    is true, so a stray flag would silently become version 1.
    """
    if isinstance(version, bool) or not isinstance(version, int):
        raise StorageError(BAD_VERSION_NUMBER.format(what=what, value=repr(version)))
    return version


# What Postgres will accept in a LIMIT clause. Beyond it psycopg sends a numeric and the
# server refuses, while a Python slice carries on — the same divergence a negative limit
# had, at the other end.
MAX_LIMIT = 2**63 - 1


def check_version_limit(limit: int) -> int:
    """A row cap both stores read the same way. Returns it; raises `StorageError`.

    **Also found by asking both.** A negative limit made Postgres raise *"LIMIT must not
    be negative"* and made the fake return `rows[:limit]` — every version except the last
    few, silently, which is a truncated history reported as a whole one. Zero is legal in
    both and means what it says. `None` is not: a Python slice reads it as *everything*
    and so does `LIMIT NULL`, which agrees by accident and defeats the cap this argument
    exists to hold.
    """
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or limit < 0
        or limit > MAX_LIMIT
    ):
        raise StorageError(BAD_VERSION_LIMIT.format(value=repr(limit)))
    return limit


# Everything a config may be made of, and it is the intersection rather than Python's
# idea of it: `json.dumps` will happily emit `NaN`, which is not JSON and which Postgres
# refuses, and it will not emit a `datetime` at all.
_STORABLE_SCALARS = (str, int, float, bool, type(None))


def check_config_is_storable(config: dict, *, what: str = "config") -> None:
    """Refuse a config Postgres could not hold. Raises `ValueRefused`.

    **The family is `ValueRefused` as of 022b, and this reaches further than the step
    that changed it.** A `NaN`, a lone surrogate or a NUL byte is a value a caller
    supplied and can fix, so it is a 400 — and it answered 503 on all six config write
    paths, `PATCH /agents/{name}` included, for as long as this function has existed.
    Nothing caught it because no test asserted the status and the CLI cannot tell the two
    apart. Changed here rather than wrapped at one call site, because a second family for
    the same fact is how the first five of these happened.


    **The fake catching up to the real store**, which is the direction this project fixes
    parity in. Everything below is stored happily by a dict and refused by a `jsonb`
    column, so before this the in-memory suite was green on configs that fail in
    production — and step 021 doubled the number of jsonb columns a config lands in.

    Three families, each found by asking both stores the same question:

    - **A NUL, or a lone surrogate, in any string.** Postgres: *"unsupported Unicode
      escape sequence"*, arriving as a 503 about a request that will never work.
    - **`NaN` or an infinity.** `json.dumps` emits bare `NaN`, which is not JSON. It also
      breaks the version counter specifically, and silently: `nan != nan`, so the fake
      sees every re-seed of such a config as a change and grows a version per boot —
      exactly what the suppression exists to prevent, invisible to the test that pins it.
    - **Anything not JSON-native** — a `datetime`, a set. `json.dumps` raises `TypeError`,
      which escapes the storage boundary as neither a `StorageError` nor anything a
      caller can catch.

    Tuples and non-string keys are **not** refused: `json.dumps` coerces both, so
    Postgres stores them as a list and a string key. The fake keeps them as written,
    which is a real divergence — recorded rather than refused, because coercion is what
    every other JSON writer does and refusing it would break callers that work today.
    """

    def _at(path):
        return f" at {path}" if path else ""

    def walk(value, path):
        if isinstance(value, bool) or value is None:
            return
        if isinstance(value, float):
            if value != value or value in (float("inf"), float("-inf")):
                raise ValueRefused(UNSTORABLE_CONFIG.format(
                    what=what, at=_at(path), why=f"{value} is not a JSON number"
                ))
            return
        if isinstance(value, str):
            if "\x00" in value:
                raise ValueRefused(UNSTORABLE_CONFIG.format(
                    what=what, at=_at(path), why="it contains a NUL byte"
                ))
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                raise ValueRefused(UNSTORABLE_CONFIG.format(
                    what=what, at=_at(path), why="it contains an unpaired surrogate"
                )) from None
            return
        if isinstance(value, int):
            return
        if isinstance(value, dict):
            for key, item in value.items():
                # **Keys, and not only values.** This function's own sentence above is *a
                # NUL, or a lone surrogate, in any string*, and a dict key is a string —
                # but the walk visited values alone for as long as it has existed, so
                # `{"a\x00b": ...}` passed the check and reached Postgres as a 503 about a
                # request that will never work. The wrong refusal family, at the one place
                # this function exists to prevent it.
                #
                # Found by 035i's edge pass, which is the first thing to put a **person's
                # keystrokes into a config key**: a JSON Schema's `properties` are dict
                # keys, the schema editor is a textarea, and `"\u0000"` is four characters
                # somebody can paste. Before that every key in every config came from the
                # code, which is why the hole survived — the fix is one line and the reason
                # it was reachable is the whole story.
                #
                # `str(key)` because `json.dumps` coerces a non-string key rather than
                # refusing it (see the docstring), so a NUL inside an integer key is not a
                # thing that exists — but a key that is not a string is not this check's
                # business either way.
                if isinstance(key, str):
                    walk(key, f"{path}.<key>" if path else "<key>")
                walk(item, f"{path}.{key}" if path else str(key))
            return
        if isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]")
            return
        raise ValueRefused(UNSTORABLE_CONFIG.format(
            what=what, at=_at(path), why=f"{type(value).__name__} is not a JSON value"
        ))

    walk(config, "")


def configs_differ(before, after) -> bool:
    """Whether two configs differ **the way `jsonb IS DISTINCT FROM jsonb` does.**

    The in-memory store's half of the suppression rule, and it is not `!=`.

    Python and jsonb agree on almost everything — key order is irrelevant to both, and
    both read `1` and `1.0` as the same number. They disagree on exactly one thing:
    `True == 1` in Python, and `'true'::jsonb <> '1'::jsonb` in Postgres, because a
    boolean and a number are different types there. So a config that changed
    `private_runs` from `1` to `true` was a new version in Postgres and no version at all
    in the fake — a divergence in the version *number*, which is the one value this whole
    step hands to a screen.

    Found by an edge hunt asking both stores the same odd question. Everything else about
    `!=` was correct, which is why this is a function rather than a rewrite.
    """
    if isinstance(before, bool) != isinstance(after, bool):
        return True
    if isinstance(before, dict) and isinstance(after, dict):
        if before.keys() != after.keys():
            return True
        return any(configs_differ(before[key], after[key]) for key in before)
    if isinstance(before, (list, tuple)) and isinstance(after, (list, tuple)):
        if len(before) != len(after):
            return True
        return any(configs_differ(a, b) for a, b in zip(before, after))
    return before != after

# `pending_grants` — migration 012's table, 035's key.
#
# **Promoted out of `postgres.py` by step 025**, where it had lived as a private
# `_PENDING_COLUMNS` since 006 while every other table's shape sat here. That is the
# `RUN_FIELDS` device with one table exempted: the fake built these rows by hand and
# returned them with a `deepcopy`, so nothing compared the two shapes and the projection
# that catches drift was the one thing missing. Both stores read this tuple now.
PENDING_GRANT_FIELDS = (
    "tenant_id",
    "agent_id",
    # Derived on read in both stores — see `GRANT_FIELDS`.
    "agent_name",
    "email",
    "role",
    "granted_by",
    "granted_at",
)

# `agent_grants`, after migration 017 renamed two of them and 035 re-keyed it.
GRANT_FIELDS = (
    "tenant_id",
    # Migration 035. What the grant is actually attached to — so a rename cannot detach
    # anybody's access, which is the one property this whole step exists to buy.
    "agent_id",
    # Derived on read, like `SCHEDULE_FIELDS`'.
    "agent_name",
    "grantee_kind",
    "grantee_id",
    "role",
    "granted_by",
    "granted_at",
)



def normalize_audit_record(record: dict) -> dict:
    """One audit record with every optional field filled in, as it will be stored.

    **This exists because the two stores disagreed and nothing compared them.** Postgres
    fills the optional columns at INSERT (`record.get("effect", "")`, and the rest) because
    the table's own defaults demand a value; the in-memory store kept whatever dict it was
    handed. So a record written without `identity_source` read back as `'none'` from one
    store and with the key **absent** from the other — the exact shape of drift
    `test_every_audit_field_survives_a_round_trip` was written for after `credential`
    shipped the same way, one field further on.

    Nothing in production writes a partial record: `core/audit.record` sets every field.
    That is what kept this invisible, and it is not a reason to leave it — `append_audit`
    is a public method on the interface, and the first strict reader over this table
    (`api/schemas.DoorCallRecord`, step 035a) turns a missing key into a 500 on one store
    and a correct answer on the other.

    The eight defaults are the column defaults, and each is the truthful reading of an
    absent value rather than a convenience:

      effect/reason/outcome  ''    — `''` is a value these columns *mean* something by
      args                   {}    — a call with no arguments, not a call we lost
      credential             None  — no secret, or nothing executed; NOT `''`, because
                                     "none needed" and "not recorded" must stay apart
      duration_ms/response_bytes  None — never ran, rather than ran in zero time
      acting_for             None  — nobody was named
      identity_source        'none' — migration 041's own words: existing rows read
                                     `none` "which is precisely true of them: no record
                                     written before this column existed had an
                                     acting-for to lose"
      model                  ''    — nobody recorded one; `runs.model`'s reading
      the four token counters None — **not 0.** The call touched no model, so it spent
                                     nothing *applicable*, which is `response_bytes`'
                                     distinction one column over. The door's spend
                                     ceiling reads `WHERE input_tokens IS NOT NULL`, so
                                     a 0 here would enrol every ordinary tool call in a
                                     money query it has no business being in.

    The eight required keys are deliberately *not* defaulted: a record with no `decision`
    or no `run_id` is a bug in its writer, and both stores raise `KeyError` on it today.
    """
    return {
        **record,
        "effect": record.get("effect", ""),
        "args": record.get("args") or {},
        "reason": record.get("reason", ""),
        "outcome": record.get("outcome", ""),
        "credential": record.get("credential"),
        "duration_ms": record.get("duration_ms"),
        "response_bytes": record.get("response_bytes"),
        "acting_for": record.get("acting_for"),
        # `or` rather than `.get(..., "none")`: the CHECK admits no NULL and no '',
        # so an explicit empty value has to become the default too.
        "identity_source": record.get("identity_source") or "none",
        # Step 045b. `or ""` for the same reason as `identity_source` above — the column
        # is NOT NULL, so an explicit None has to land on the default; `.get(...)` for
        # the counters, because None is a value they *mean* something by and must
        # survive.
        "model": record.get("model") or "",
        "input_tokens": record.get("input_tokens"),
        "output_tokens": record.get("output_tokens"),
        "cache_read_tokens": record.get("cache_read_tokens"),
        "cache_write_tokens": record.get("cache_write_tokens"),
    }


# --- the call audit log -----------------------------------------------------------
#
# `audit` holds every brokered call, whether it came from a run or through the MCP door.
# The two are told apart by the shape of `run_id` and by nothing else: a run's is
# `context.new_run_id`, a door call's is `door.new_call_id`, which prefixes this string.
#
# **The prefix lives here rather than in `door.py` because two layers need it and this is
# the lower one.** `door.py` mints ids with it; `door_call_records` filters on it. Storage
# imports nothing from the app — that is what keeps every import pointing downward — so a
# constant both need has to sit at the bottom, and `door.CALL_ID_PREFIX` is bound to this
# rather than repeating the literal. A second copy would be two values free to disagree,
# and the disagreement would be silent: the door would keep minting ids the reader no
# longer matches, and the log would simply look empty.
DOOR_CALL_ID_PREFIX = "door-"

# Two refusal phrases, here for **exactly the reason the prefix above is here** — step
# 041's `overview` reads them and `core.limits` / `door` write them, so the constant
# belongs to the lower layer and the writers bind to it.
#
# It is worth saying why a *sentence* is a shared constant at all, because it looks like
# one. A budget refusal is not a distinct kind of audit row: every `Spending.reserve`
# returns a `Decision` and the broker writes the ordinary
# `decision='deny'` record. That is deliberate — 033b's *"a budget denial writes the same
# audit record an in-product budget denial writes"* is a property held by having one path
# instead of two, and it is worth more than the convenience of a `kind` column. The bill
# comes due here: with no column, the sentence is the only thing left that distinguishes
# *an agent hit its own ceiling* from *the broker refused this*, and those are different
# facts that a manager acts on differently (plan 041, finding 5).
#
# So they are matched rather than joined, and the coupling is made **one name** so it
# cannot drift across a module boundary in silence. The failure it prevents: a reworded
# refusal quietly re-files itself as a policy denial, and the graph reports the broker
# refusing more than it ever did — a wrong number nobody would think to check, on the one
# screen built to be trusted at a glance.
#
# Matched with a wildcard on both sides, because three of the four sentences a per-run
# budget wrote qualify the noun (*write* budget, *response* budget) and a
# leading-anchor match would silently count only the first.
#
# **Since step 084 this tree has no writer for it**, only the reader. `core.limits.Budget`
# was the writer and it went with the rest of the unread run machinery; `overview`'s
# `run_budget` band stays, because an upgraded deployment's `audit` table holds rows a
# pre-078 tree wrote, and re-filing those as policy denials is precisely the silent
# wrong number the paragraph above exists to prevent.
# How many rows a leaderboard on the overview returns. Step 041.
#
# The two ranked lists — callers and tools — are drawn as a dozen bars, and a tenant can
# have thousands of either. Capping in SQL rather than in the page is the difference
# between a bounded response and one that ships five thousand rows to draw twelve; and
# the cap living here rather than in a route is what lets the memory store apply the
# identical one, which the contract suite then holds them to.
#
# **The count on the tile is a separate query and is never `len(this list)`** — a
# leaderboard is the top of something, and a total derived from its length would report
# the cap as the answer.
LEADERBOARD = 15

BUDGET_REFUSAL_MARKER = "budget exhausted"

# The door's ceiling, and deliberately **not** the same string as the one above. The two
# are separate series on the overview for the reason they are separate constants here:
# one says an agent is looping or is configured too tightly, the other says a credential
# is being used harder than its daily allowance, and a "refusals" line that summed them
# would spike identically for either.
#
# Telling a ceiling refusal from a run-budget refusal needs no text at all — a ceiling
# refusal is only ever written for a `door-` call, and a run budget refusal never is,
# because a door call has no run and no per-run budget. What this string separates is a ceiling
# refusal from an ordinary *policy* denial on the same door call, which share everything
# a query can otherwise see.
CEILING_REFUSAL_MARKER = "calls through the MCP door today"

# The door's *money* ceiling, and the third marker rather than a reuse of the second.
# Step 045b.
#
# `CEILING_REFUSAL_MARKER` above says a credential made too many calls; this one says it
# spent too much. They are different facts with different answers — the first is usually
# a loop or a dial set too tight, the second is a real bill arriving — and a refusals
# chart that summed them would spike identically for either, which is precisely the
# failure that constant's own comment was written about. So: a third string, a fourth
# band in `_q_refusals` and its in-memory twin.
#
# **The two phrases must stay non-overlapping**, because the classification is
# `LIKE '%...%'` against one column and the door writes both. If a spend refusal's
# sentence ever contained the word sequence above, every money refusal would be counted
# as a call-count refusal and the money line would read zero forever — a wrong number
# nobody would think to check. The bands are tested against both sentences for that
# reason and not for coverage's sake.
SPEND_REFUSAL_MARKER = "at the model through the MCP door today"


# --- the administrative audit log -------------------------------------------------
#
# Migration 022. Everything below is shared by both implementations, so a record means
# the same thing whichever store wrote it — the same device as `RUN_FIELDS`, and here
# for a sharper version of the same reason: `audit.credential` shipped written by
# Postgres and silently dropped by the fake, with 818 tests green, because nothing named
# the fields in one place.

# Present from the first record, for the reason `audit.v` is. Bumped when the meaning of
# a field changes, never when one is added — a reader filtering on `v` is asking "can I
# trust what this field meant when it was written".
ADMIN_AUDIT_V = 1

# Every field a record carries, in the order both stores return it.
ADMIN_AUDIT_FIELDS = (
    "tenant_id",
    "v",
    "ts",
    "actor_kind",
    "actor_id",
    "action",
    "target_kind",
    "target_id",
    "detail",
)

# What a record can be about. A grant is recorded against the **agent** rather than
# against its grantee, because "everything that ever happened to triage-bot" is the
# question asked after an incident and "everything that ever happened to Sam" is
# answered by `actor_id` and by the detail.
#
# **`user` and `system` arrive with migration 026, and they are the first targets that
# are principals rather than things.** A role grant has no other noun available: it is not
# about an agent, and recording it against one would be a record no query for "who made
# Sam an administrator" would ever find. The column has no CHECK — migration 022 left it
# `<> ''` deliberately, *"so the set grows every time a method comes into scope"* without
# an ALTER on an append-only table — and this is the first time that decision is spent.
#
# **Both, and the plan said only `user`.** Found by running the thing: a role may be
# granted to a `system` principal, so recording every role grant as `target_kind='user'`
# would have logged `nightly` as a person. Recording the principal's own kind keeps the
# pair meaning what it means everywhere else in this table — the *kind of thing* and its
# *identifier* — so `admin_audit_records(target_kind='user', target_id=priya)` answers
# "everything that ever happened to Priya" with the id every other row spells the same way.
ADMIN_TARGET_KINDS = frozenset(
    # `tenant` arrives with 018, and it is the first target that is the customer itself
    # rather than something inside them. A retention prune is about the tenant's whole
    # log, so there is no narrower noun available — recording it against an agent would
    # be a record no query for "what happened to this customer's history" would find.
    #
    # `machine` arrives with 020, and note which column it joins: a machine is something
    # a record can be **about**, never something that writes one. `ADMIN_ACTOR_KINDS`
    # and `admin_audit.actor_kind`'s CHECK are the other half of that sentence. This
    # column has no CHECK at all — migration 022 left it `<> ''` so *"the set grows every
    # time a method comes into scope"* — so this is a Python-only addition, which is the
    # second time that decision has paid off.
    # `schedule` arrives with 022, and it is a target rather than an actor for the same
    # reason `machine` is: a schedule is something records are about, and the thing that
    # fires one writes a `runs` row rather than an administrative record.
    # `trigger` arrives with 023, on the identical sentence — a delivery writes a
    # `runs` row and stamps its own trigger, never this log.
    # `scim_token` arrives with 071, and it joins this column for `machine`'s reason
    # exactly: a SCIM token is something a record is *about* — minted, revoked — and
    # never an actor. The directory acts as `system:scim:<id>`, which is a `system`
    # principal, and `ADMIN_ACTOR_KINDS` is unchanged.
    {
        "agent",
        "group",
        "connector",
        "host",
        "user",
        "system",
        "tenant",
        "machine",
        "schedule",
        "trigger",
        "scim_token",
    }
)

# Who a retention prune is attributed to. Not `system:cli`, because nobody typed it —
# this is the sweeper inside a worker acting on a configured policy, and a record saying
# `cli` would send an incident straight to a person's terminal history.
RETENTION_ACTOR = "system:retention"

# What a `tenant_egress_hosts` row holds, in the order both stores return it. The
# `RUN_FIELDS` / `AGENT_FIELDS` device — `tenant_id` is not among them because the caller
# already knows which tenant it asked about, matching `VETTING` rather than `AGENT_FIELDS`.
EGRESS_HOST_FIELDS = ("host", "allowed_by", "allowed_at", "note")

# What one `load_vetting_record` row holds. Named for the same reason the others are: two
# columns arrived in step 012 and a reader that hardcoded four keys would have kept
# working while quietly reporting less than the table knows.
VETTING_FIELDS = (
    "connector_id",
    "remote_name",
    "vetted_by",
    "vetted_at",
    "server_name",
    "server_version",
    "vetted_arguments",
)


def normalize_host(host: str) -> str:
    """A bare hostname, lowercased. Raises on anything that is not one.

    Deliberately **not** a URL parser, and this is the decision rather than an
    implementation detail. `urlsplit("mcp.example.com/x").hostname` is `None`, and
    `urlsplit` is happy to accept a great many strings that are not hosts — so a
    normalizer built on it would quietly turn a typo into an allowlist entry that
    matches nothing, which is a control that looks configured and is not.

    So: refuse anything carrying a scheme, a port, a path, a credential, or whitespace,
    and say which. The caller wanting to allow the host *of a URL* extracts it first with
    `egress.host_of` — one direction, one place, and the error message tells them so.

    Trailing dots are stripped: `example.com.` is the same host as `example.com` to every
    resolver, and storing both would let one be allowed while the other is refused.
    """
    if not isinstance(host, str) or not host.strip():
        raise ValueRefused("a host is required; an empty allowlist entry matches nothing")

    cleaned = host.strip().rstrip(".").lower()

    for token, what in (
        ("://", "a scheme"),
        ("/", "a path"),
        (":", "a port"),
        ("@", "a credential"),
        ("?", "a query"),
    ):
        if token in cleaned:
            raise ValueRefused(
                f"'{host}' contains {what}. The allowlist is keyed on the host alone: a "
                "path is not a security boundary, and a port would let the same server "
                "be allowed on one and refused on another for no stated reason. Pass "
                "just the hostname — for a URL, take its host first."
            )

    if any(character.isspace() for character in cleaned):
        raise ValueRefused(f"'{host}' contains whitespace, so it is not a hostname")

    if not cleaned:
        raise ValueRefused(f"'{host}' normalizes to nothing")

    return cleaned

# The vocabulary, `'<noun>.<verb>'`. Ordered as pairs on purpose: **the right-hand column
# is what step 011 exists to add**, and reading them side by side is the fastest way to
# notice a half that has gone missing again.
#
#     agent.create           agent.delete
#     agent.save             —                 an upsert has no removal half
#     agent.update           —                 a compare-and-set replaces, 10d
#     grant.create           grant.revoke
#     grant.transfer         —                 a transfer demotes, it never removes
#     grant.pending.add      grant.pending.delete
#     grant.pending.claim    —                 a claim converts, it never removes access
#     group.create           group.delete
#     group.link             —                 unlinking is the same action, null id
#     group.rename           —                 the id stays; nothing is removed
#     group.member.add       group.member.remove
#     user.create            —                 there is no delete; decision 1 of 071
#     user.update            —                 an edit has no removal half
#     user.adopt             —                 once, and it cannot be undone
#     user.disable           user.enable
#     scim.token.mint        scim.token.revoke
#
# A frozenset here rather than a CHECK on the column, which is the one place this table
# departs from migration 017's precedent — see the migration for why: the set grows every
# time a method comes into scope, and a CHECK makes each of those an ALTER on an
# append-only table.
ADMIN_ACTIONS = frozenset(
    {
        "agent.create",
        "agent.save",
        "agent.update",
        "agent.delete",
        # Step 021. A restore is an ordinary write as far as this log is concerned —
        # `agent_detail` and its redaction are unchanged, so the record still says which
        # fields moved and never what they say. It gets its own action rather than
        # riding `agent.update` because "somebody put an old configuration back" is a
        # different act from "somebody edited", and the log is where that distinction
        # survives after the history itself has been deleted with its agent.
        "agent.restore",
        # Step 025, and this is the record that keeps the audit log readable across a
        # rename. `audit.agent`, `admin_audit.target_id` and every denial record hold the
        # name as it stood at the time, deliberately (migration 035 says why), which means
        # an agent's trail is written under two names with nothing joining them — except
        # this row, whose detail carries `from` and `to`. It is the only place the two
        # halves meet, so it is not optional.
        "agent.rename",
        "grant.create",
        "grant.revoke",
        "grant.transfer",
        "grant.pending.add",
        "grant.pending.claim",
        "grant.pending.delete",
        "group.create",
        "group.delete",
        # Step 033e. Binding a group to a directory group, or letting it go. Its own
        # action rather than an update that happens to differ in one field, because what
        # it changes is *who may change who is in this group* — the same argument
        # `connector.asserted_identity` makes one noun over.
        "group.link",
        # Step 071, on `agent.rename`'s reasoning one noun over: a group's grants and
        # membership are keyed on its id and survive the rename untouched, and this
        # row — carrying `from` and `to` — is what keeps the name in older records
        # readable against the name the group has now.
        "group.rename",
        "group.member.add",
        "group.member.remove",
        # Step 012. `connector.vet` is the one that finally makes `vetted_by` history
        # rather than last-writer-wins: `vetted_tools` holds only the *current* review,
        # so "who approved this, and did anybody approve it before them" is a question
        # that table cannot answer and this log can.
        "connector.create",
        "connector.save",
        "connector.vet",
        "connector.delete",
        # Step 033c. A security control changing state: whether the MCP door believes
        # an *asserted* acting-for for this connector's tools. Its own action rather
        # than a `connector.save` that happens to differ in one field, because "who
        # turned trust in a caller on, and when" is the row the plan's who-approved
        # question is answered from — a reader must not have to diff manifests for it.
        "connector.asserted_identity",
        # Approving a host is the decision that lets a database row cause an outbound
        # connection, which makes it the most consequential administrative act in this
        # list and the one most worth being able to attribute afterwards.
        "egress.allow",
        "egress.revoke",
        # Step 7b, and `DEFERRED.md` named these as the administrative log's remaining
        # scope: *"the connection methods — where a record that somebody connected an
        # account is wanted and the ciphertext must never be near it"*. This is the step
        # that makes connecting something a person does to **themselves** rather than
        # something an operator does for them, which is what makes "who connected an
        # account, and when" a question worth being able to answer afterwards.
        #
        # `connection.create` is the first action in this list whose actor and subject are
        # routinely the same principal. That is not a degenerate case to be tidied away —
        # it is the difference between a consent flow and `--connect-account`, and the
        # record is the only place that difference survives.
        "connector.oauth.configure",
        "connector.oauth.remove",
        "connection.create",
        "connection.delete",
        # Step 12b, and these are the two this log exists for most literally: it is the
        # log of *who changed who may do what*, and a platform role is the widest such
        # change the product has. Recorded against the **person**, which is why `user`
        # joins `ADMIN_TARGET_KINDS` — "everything that ever happened to Sam" has never
        # been a query this table could answer, and for a role grant it is the only
        # sensible one.
        #
        # Note what is deliberately absent: there is no `role.read`. Reading the log
        # changes nothing, and an access log for reads is a different table with a
        # different retention question — see decision 6 of plan 012b, which refuses to
        # smuggle it in here.
        "role.grant",
        "role.revoke",
        # Step 018, and the first action whose subject is the log itself: how many rows
        # aged out of each table, and where the boundary fell.
        #
        # It lands in a table this sweep prunes, which is deliberate rather than ironic.
        # The record says *the log is bounded and here is where the boundary passed*, it
        # names no person, and it ages out like everything else. The permanent trace of
        # an erasure is the tombstone, which nothing can prune — see migration 029.
        "retention.prune",
        # Step 020. Minting a credential that can submit runs unattended is the most
        # consequential act on this list after `egress.allow`, and — unlike a role grant
        # — it produces a bearer secret that outlives the session it was typed in. The
        # record names the token, its owner and its expiry; it cannot name the secret,
        # because the storage layer is never given one.
        #
        # There is deliberately no `token.use`. Every request would write one, the log
        # would become a request log with a retention story it was not designed for, and
        # the question it would answer — is this token in use — is `last_used_at`.
        "token.mint",
        "token.revoke",
        # Step 022. Administering a schedule is a person's act and is recorded like any
        # other; **firing one is not on this list, and its absence is the decision.** A
        # fire is `POST /runs` performed on a timer, so its record is the `runs` row, its
        # refusal is an `access_denials` row, and a fourth entry here would be a request
        # log — the same argument that keeps `token.use` off this list, at the rate of
        # one row per fire per schedule forever.
        #
        # The record names the agent, the cadence, the zone and the machine it fires as.
        # It **never names the task**, which is migration 022's rule reaching a second
        # column: `AGENT_DETAIL_REDACTED` keeps `default_task` out of a record about an
        # agent, and a schedule's task is the same content wearing a different key.
        "schedule.create",
        # 035k. An edit, on the same terms as the four around it: a person's act on
        # standing configuration, so it is recorded, and the detail follows
        # `schedule.create`'s redaction exactly — **the keys that moved, never their
        # values**. The task is the sharp one and it is the same content
        # `AGENT_DETAIL_REDACTED` keeps out of an agent's record; a cadence and a zone
        # are named because create names them, and `fires_as` is named for the same
        # reason create does. So the log answers *what about this schedule changed* and
        # never *what does it now say*, which is `GET` and needs a grant.
        "schedule.update",
        "schedule.enable",
        "schedule.disable",
        "schedule.delete",
        # 023, on 022's terms exactly: administering a trigger is a person's act and a
        # delivery is not — a delivery's record is its `runs` row, its refusal is the
        # trigger row's own stamp (plus a denial row when it is a grant refusal), and an
        # entry per delivery here would be a request log by another name. The record
        # names the agent, the trigger's name and the machine — never the task, and
        # never the secret, which storage only ever holds sealed.
        "trigger.create",
        # 035k. A rotation is an administrative act on a credential and belongs here for
        # the reason `token.revoke` does: the secret changed, somebody did it, and the
        # sender's next delivery will fail until they are told. The record names the
        # agent and the trigger's name and **carries nothing about either secret** —
        # not the plaintext, not the ciphertext, not the key id — because a record is
        # forever and `core/crypto.py`'s division is that a layer which cannot see a
        # secret cannot log one.
        "trigger.rotate",
        "trigger.enable",
        "trigger.disable",
        "trigger.delete",
        # Step 071. The first five things the log ever says about a *person* rather than
        # about what a person did, and the first two are the reason the offboarding
        # half of the enterprise gate was unreachable until now: `set_user_status` had
        # existed since 008 and had no caller, and nothing wrote a row when somebody
        # was cut off. Now the directory's push writes `user.disable` with the SCIM
        # token as the system actor, the CLI's `--disable-user` writes it with a person,
        # and either way "who cut Sam off, and when" is a query.
        #
        # `user.create` is written **only for a provisioned row** — the JIT sign-in path
        # passes no actor and writes nothing, because a first login is not an
        # administrative act and a record per new person would be a request log.
        # `user.adopt` is the one that pairs a pushed row with the sign-in that claimed
        # it, and it is the record that proves the two-accounts outcome did not happen.
        # There is deliberately no `user.delete`: decision 1 of 071, no hard delete.
        "user.create",
        "user.update",
        "user.adopt",
        "user.disable",
        "user.enable",
        # The directory's credential, on `token.mint`/`token.revoke`'s terms: the
        # record names the token, its issuer and its name, and cannot name the secret
        # because storage is never given one. No `scim.token.use`, for `token.use`'s
        # reason — `last_used_at` is the answer to that question.
        "scim.token.mint",
        "scim.token.revoke",
    }
)

# What a connection record may carry, and — the point of the list — what it may not.
#
# **No secret and no ciphertext**: not the client secret, not the access or refresh token,
# not the `code_verifier`. What is recorded is the connector, the principal, how the
# credential arrived, the scopes asked for (public, and the interesting half — *what did
# we ask for*), the verified account label, and whether the provider was told on the way
# out.
#
# Nothing here enforces it and nothing could — `detail` is a dict and a rule about its
# contents is a rule about meaning. What exists instead is the test 011 wrote for the same
# hazard: `test_no_record_carries_an_agents_system_prompt` runs the whole flow with every
# secret set to a marker string and requires none of them to appear anywhere in the log.
CONNECTION_DETAIL_KEYS = frozenset(
    {"principal", "kind", "label", "scopes", "revoked_upstream", "reason"}
)

# What `--seed` and the CLI's unattended paths pass. The same principal migration 011
# uses for a seeded agent's owner grant, and saying it out loud is the honest version of
# a nullable actor: the log does not cover `--seed` beyond recording that a system
# principal wrote something, which is the least useful *true* statement available.
SYSTEM_ACTOR = "system:cli"

NO_ACTOR = (
    "every administrative write needs an actor, in the form 'kind:id'. There is no "
    "default and there must not be one: a record that can say nobody did it is worse "
    "than no record, because it looks like an answer. Unattended work passes "
    f"'{SYSTEM_ACTOR}'."
)


def split_actor(actor: str) -> tuple[str, str]:
    """`'user:u_a4d6'` -> `('user', 'u_a4d6')`. Raises on anything else.

    One string rather than two parameters, because `granted_by`, `created_by` and
    `added_by` have all carried this shape since 009 and every caller already builds it
    as `f"{principal.kind}:{principal.id}"`. Splitting on the **first** colon: a
    principal id is opaque and nothing forbids one containing a colon, while a kind is
    one of two literal words.

    Validated against `ADMIN_ACTOR_KINDS` rather than `GRANTEE_KINDS` **or**
    `PRINCIPAL_KINDS`. A group may be granted access and may not take it away; a machine
    may act and may not administer. `admin_audit.actor_kind` carries exactly this set as
    a CHECK, so this is the sentence and that is the guarantee.

    It read `PRINCIPAL_KINDS` until step 020, when the two sets stopped being the same
    thing. Left as it was, the in-memory store would have accepted a `machine:` actor
    that Postgres refuses — the fake being looser than the real store, which is the
    drift the contract suite exists to catch.
    """
    if not actor or not isinstance(actor, str):
        raise StorageError(NO_ACTOR)

    kind, sep, ident = actor.partition(":")
    if not sep or not ident:
        raise StorageError(
            f"'{actor}' is not an actor. {NO_ACTOR}"
        )

    if kind == "machine":
        raise StorageError(
            "a machine cannot be the actor of an administrative record. An API token "
            "runs agents; it administers nothing, and `admin_audit.actor_kind` carries "
            "the same refusal as a CHECK. If this arrived from a route, the route is "
            "the bug — see migration 031."
        )

    # Together with the line above, this is exactly `ADMIN_ACTOR_KINDS` — and it is
    # written as two refusals rather than one membership test on purpose. A third guard
    # here would be a third Python layer standing in front of `admin_audit.actor_kind`,
    # and `test_the_agent_and_its_owner_grant_are_one_transaction` stands the guards
    # down one at a time precisely to prove the *database* is the last line. A check
    # that cannot be reached from a test is a control nobody can verify.
    #
    # What keeps the two sets honest as `PRINCIPAL_KINDS` grows is
    # `test_every_principal_kind_is_sorted_into_one_of_the_two_actor_sets`, which fails
    # until a new kind is deliberately placed on one side or the other.
    check_principal_kind(kind)
    return kind, ident


def check_admin_action(action: str, target_kind: str) -> None:
    """The vocabulary, in Python, because it is not in the column. See `ADMIN_ACTIONS`.

    Both stores call it, so an action one implementation accepts is not one the other
    quietly rejects — and a typo'd action is a record nobody's query will ever find,
    which is the failure mode a log has instead of a crash.
    """
    if action not in ADMIN_ACTIONS:
        raise StorageError(
            f"'{action}' is not an administrative action. The vocabulary is "
            f"{sorted(ADMIN_ACTIONS)} — add to it deliberately, in ADMIN_ACTIONS, "
            "rather than at a call site."
        )
    if target_kind not in ADMIN_TARGET_KINDS:
        raise StorageError(
            f"'{target_kind}' is not something a record can be about; the kinds are "
            f"{sorted(ADMIN_TARGET_KINDS)}"
        )


def make_admin_record(
    action: str,
    target_kind: str,
    target_id: str,
    actor: str,
    detail: dict | None = None,
) -> dict:
    """One `admin_audit` row, less its tenant. Built here so both stores build it alike.

    **`detail` is what CHANGED, never the contents of every field.** A role, a grantee, a
    list of field names, a scope — not an agent's `system` prompt, not a credential, not
    a token. The first two of those are obvious and the third is the one somebody will
    add, because an agent's system prompt is free text a person typed, which is exactly
    the class `audit`'s redaction exists to keep out of a record kept forever.

    Nothing here enforces that, and nothing could: `detail` is a dict and a rule about
    its contents is a rule about meaning. What exists instead is
    `test_no_record_carries_an_agents_system_prompt`, which builds an agent whose prompt
    is a marker string and requires it to appear nowhere in the log.
    """
    check_admin_action(action, target_kind)
    actor_kind, actor_id = split_actor(actor)

    if not target_id:
        raise StorageError(
            f"a '{action}' record needs a target id — a record that does not say what "
            "it was about is one no query will ever find"
        )

    return {
        "v": ADMIN_AUDIT_V,
        "ts": datetime.now(timezone.utc),
        "actor_kind": actor_kind,
        "actor_id": actor_id,
        "action": action,
        "target_kind": target_kind,
        "target_id": target_id,
        "detail": detail or {},
    }


def make_tombstone(tenant_id: str, name: str, actor: str, counts: dict) -> dict:
    """One `tenant_tombstones` row. Built here so both stores build it alike.

    **What it may hold, and what it must not.** A tenant id, an organisation's name,
    who did it, and how many rows went. That is a contract counterparty and an
    arithmetic result — no principal ids, no addresses, no agent names, nothing about
    any person who worked there. The point of this table is that it can be kept forever
    without reopening the question the deletion was performed to answer, and it can only
    stay true if `detail` stays counts.

    `split_actor` runs before anything is deleted, at the top of `delete_tenant`, so an
    unusable actor refuses the deletion rather than being discovered after five tables
    are already empty.
    """
    actor_kind, actor_id = split_actor(actor)

    if not tenant_id:
        raise StorageError("a tombstone needs the tenant id it is about")

    return {
        "tenant_id": tenant_id,
        "name": name,
        "actor": f"{actor_kind}:{actor_id}",
        "detail": {"v": TOMBSTONE_V, "rows": dict(counts)},
    }


# What `agent.create` and `agent.save` put in `detail`, and the two words that must never
# be in it. `system` is the agent's prompt and `description` is free text somebody typed;
# both are the class of thing this log does not keep. What is recorded is which fields
# the config carried, plus the two that decide what the agent can reach.
AGENT_DETAIL_REDACTED = frozenset({"system", "description", "default_task"})


def agent_detail(config: dict) -> dict:
    """`detail` for an agent write: what it can reach, and which fields were set.

    Not the config. Reconstructing an agent's configuration at a past date needs every
    record replayed and nothing does that — a known limit of this step, stated rather
    than half-fixed by storing a copy of the prompt in a table kept forever.

    **Reads defensively, because this layer validates nothing about a config beyond its
    name.** Whether `permissions` is a dict is `agents/validate`'s question and it is one
    layer up, so a config that never went through it — a fixture, a hand-written row, a
    `--seed` of something broken — still has to produce a record rather than an
    AttributeError. A write refused because its *log entry* could not be built would be
    this step breaking a path it was only supposed to observe.
    """
    permissions = config.get("permissions")
    if not isinstance(permissions, dict):
        permissions = {}
    return {
        # The field *names*, so "somebody changed the model" is answerable and "what did
        # the prompt say" is not.
        "fields": sorted(k for k in config if k not in AGENT_DETAIL_REDACTED),
        "tools": sorted(permissions.get("tools") or ()),
        # The scope is the thing an incident asks about — what could this agent reach —
        # and it is patterns from the catalogue rather than anything a person typed free
        # hand. See `_validate_scope_matches_tools`, which is why the two agree.
        "scope": permissions.get("scope") or {},
    }


# --- the access-denial log ---------------------------------------------------------
#
# Migration 028. Everything below is shared by both implementations, so a record means
# the same thing whichever store wrote it — the `RUN_FIELDS` device, applied at birth
# rather than retrofitted, because the failure it closes has already happened once:
# `audit.credential` shipped written by Postgres and silently dropped by the fake, with
# the whole suite green.

# Present from the first record, for the reason `audit.v` is. Bumped when the meaning
# of a field changes, never when one is added.
DENIAL_V = 1

# Every field a record carries, in the order both stores return it.
DENIAL_FIELDS = (
    "tenant_id",
    "v",
    "ts",
    "principal_kind",
    "principal_id",
    "resource_kind",
    "resource_id",
    "required",
    "held",
)

# What a refusal can be about: an agent by name, the administrative surface, or — since
# 033b — a tool by name. The column carries the same CHECK — migration 017's precedent,
# because a rule that lives only in a Python constant is one the next caller widens, and
# a test written in the same language as the constant does not survive somebody widening
# it.
#
# **`tool` arrives with the MCP door and it is a widening the door forced**, which is
# worth recording because the constraint did its job. Until 033b every refusal was about
# a *grant* — the two seams are `grants.require` and `roles.require_admin` — so an agent
# and the admin surface were genuinely everything a denial could name. The door adds a
# refusal that is about neither: a token asking for a tool name that appears in no agent
# it is granted. That call reaches no broker (there is no agent to attribute an audit
# record to) and so writes nothing in the audit log, and without this kind a token
# probing tool names would leave no trace anywhere at all.
#
# It was found by running the door rather than by reading this line: `denials.record` is
# best-effort by design, so the refusal was served correctly and the evidence was logged
# and dropped — which is the quiet half of a fail-safe doing exactly what it promises,
# and exactly why the promise is not a substitute for the column being right.
DENIAL_RESOURCE_KINDS = frozenset({"agent", "admin", "tool"})


def check_denial_resource_kind(resource_kind: str) -> None:
    """What a refusal may be ABOUT. Guards every write to `access_denials`.

    Extracted from `make_denial_record` by step 035b, and the extraction is the point
    rather than tidiness: the check used to be reachable only through the builder, so
    `record_denial` — a **public** method on the storage interface — accepted in the fake
    what the column's CHECK refuses in Postgres. That is the direction
    `test_storage_contract.py` exists to catch, and `append_audit` two hundred lines up
    already refuses to rely on its callers being well behaved for exactly this reason.

    One copy of the rule, called from both places. The sentence names the kinds because
    the caller who gets here is usually one word away from a legal one.
    """
    if resource_kind not in DENIAL_RESOURCE_KINDS:
        raise StorageError(
            f"'{resource_kind}' is not something a denial can be about; the kinds are "
            f"{sorted(DENIAL_RESOURCE_KINDS)}"
        )


def make_denial_record(
    principal_kind: str,
    principal_id: str,
    resource_kind: str,
    resource_id: str,
    required: str,
    held: str = "",
) -> dict:
    """One `access_denials` row, less its tenant. Built here so both stores build it alike.

    `resource_id` may be empty — `require_admin`'s callers pass a `what` that often is,
    and refusing it would turn the hook into a parameter every caller must remember,
    which is the design decision 2 of plan 015 rejected. `held` is `''` for a principal
    holding nothing, which is the headline case.

    No user free text can arrive here, and **033b is when that stopped being structural
    and became a rule somebody has to keep.** It used to hold by construction: the only
    producers were `grants.require` and `roles.require_admin`, which see constants,
    principal ids and agent names. The MCP door is a third seam, and its `resource_id` is
    a tool name that arrived off the wire from somebody else's agent — so it checks the
    name against the tool registry's own `TOOL_NAME_RE` first and refuses anything else
    without a row.

    That guard is load-bearing rather than tidy, and the reason is this column: it is
    unbounded TEXT in an append-only table, and the door's refusal happens before the
    broker, so no budget bounds it. A fourth producer must do the same — bound what it
    passes, at its own edge, where it knows what a legal value looks like. The redaction
    discipline `audit` needs is still unnecessary, because nothing that reaches here is
    free text; it is not unnecessary *by construction* any more.
    """
    check_principal_kind(principal_kind)
    check_denial_resource_kind(resource_kind)

    return {
        "v": DENIAL_V,
        "ts": datetime.now(timezone.utc),
        "principal_kind": principal_kind,
        "principal_id": principal_id,
        "resource_kind": resource_kind,
        "resource_id": resource_id,
        "required": required,
        "held": held,
    }
