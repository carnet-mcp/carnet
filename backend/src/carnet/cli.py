"""Command-line entry point.

    carnet --list                   # show configured agents and their grants
    carnet --list-tools             # every tool this tenant may grant, with its effect
    carnet --local                  # the whole product on one port, with a local login

Onboarding a customer, which is deliberately not self-serve:

    carnet --add-tenant acme "Acme Corp"
    carnet --add-idp acme --issuer https://acme.okta.com \
        --jwks-uri https://acme.okta.com/oauth2/v1/keys \
        --audience 0oa1client --domain acme.com

    # Google Workspace shares one issuer across every customer on it, so a claim has
    # to say which one this is:
    carnet --add-idp globex --issuer https://accounts.google.com \
        --jwks-uri https://www.googleapis.com/oauth2/v3/certs \
        --audience 123.apps.googleusercontent.com \
        --discriminator hd=globex.com --domain globex.com

Also runnable without installing: python -m carnet.cli
"""

import argparse
import getpass
import json
import logging
import os
import sys
from dataclasses import replace
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import NoReturn

from . import __version__
from . import config as _config
from . import agents, bootstrap, carnetfile, door, storage, tools
from .access import connections, grants, groups, oauth, recipes, roles, tokens, users
from .access.grants import NoAccess, ShareRefused
from .agents import InvalidAgentError
from .config import (
    DATABASE_URL,
    DEFAULT_TENANT_ID,
    PUBLIC_ORIGIN,
)
from .storage import (
    ADMIN_ROLE,
    AgentNameTaken,
    PLATFORM_ROLES,
    IssuerConflictError,
    StorageError,
    UnknownTenantError,
    ValueRefused,
    migrate,
)
from .core import Principal
from .core import credentials, crypto, vault
from .tools import mcp
from .tools.base import Resource

# How many un-re-sealable rows `--finish-rotation` names in full before it summarises.
# Enough that an ordinary broken row is always shown with its remedy, few enough that a
# deployment which stranded everything still prints a transcript somebody can read. The
# count of what was elided is printed, and the totals never are.
STRANDED_ROWS_SHOWN = 20


def _configure_logging(verbose: bool) -> None:
    """Send the runtime's log to this terminal, in the shape the CLI has always printed.

    Configured **by the entry point and nowhere else**. A library that calls
    `basicConfig` steals logging from whatever embeds it, which is why the modules
    below only ever take a logger and write to it. The API entry point configures its
    own, differently, and neither has to know about the other.

    `--quiet` raises the threshold rather than muting a boolean: a denial is a warning
    and still comes through, which is what `--quiet` always did.
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("  %(message)s"))

    logger = logging.getLogger("carnet")
    logger.handlers[:] = [handler]
    logger.setLevel(logging.INFO if verbose else logging.WARNING)
    logger.propagate = False


def _tokens(count: int) -> str:
    """A token count a person can read across a column. 1_240_000 -> `1.24M`.

    Exact under a thousand and rounded above it, which is the right trade for the one
    thing these numbers are used for: comparing rows. Nobody has ever needed the last
    digit of a nine-million-token total, and thirteen characters of it in a column makes
    the two numbers either side of it harder to compare.
    """
    if count < 1_000:
        return str(count)
    if count < 1_000_000:
        return f"{count / 1_000:.1f}k"
    return f"{count / 1_000_000:.2f}M"


def _money(amount) -> str:
    """An estimate, or `—` for a total nothing could be priced from.

    Never `$0.00` for an unpriced model. Zero is a claim — *this cost nothing* — and the
    whole reason `estimate_cost` hands back None is that the honest answer there is *we
    do not know*.
    """
    return "—" if amount is None else f"${amount:,.2f}"


def _admin_log(tenant_id: str, limit: int) -> None:
    """`--admin-log`: who changed who may do what, most recent last.

    **The only way to read migration 022's table without `psql`, and that is the
    decision in plan 011 most worth arguing with.** There is no `GET /admin-audit`,
    because a read route needs a tenant-admin role and this platform has none — the same
    wall 9a hit when it refused to put group administration on HTTP. **12b built the role,
    so `GET /admin-audit` exists now**, behind it. That reasoning is why the route waited
    rather than why it never arrived: writing the log is what is irrecoverable, reading it
    back is not, and a route retrofitted with authorization later is worse than no route —
    so the authorization went in first.

    This stays, and not only for symmetry. It is the reader that works when the API is
    down, when nobody has been granted a role yet, and during the bootstrap where there is
    by definition no administrator to sign in as.

    So this exists instead, and it exists because *a log nobody can read is a log nobody
    notices is broken*. It is deliberately cheap: no filters beyond a count, no
    pagination, and the same `system` principal every other administrative command here
    runs as.

    Oldest last, matching `audit_records` and the opposite of `--runs`. A log is read
    forwards; "what has run lately" is read from the top.
    """
    rows = storage.active().admin_audit_records(tenant_id, limit=limit)
    if not rows:
        print(f"No administrative records for tenant '{tenant_id}'")
        return

    print(f"{'when':22}{'who':32}{'what':22}{'to':28}detail")
    for row in rows:
        actor = f"{row['actor_kind']}:{row['actor_id']}"
        target = f"{row['target_kind']}:{row['target_id']}"
        # `detail` differs per action by design, so it is printed rather than columned.
        # Sorted so two records of one action read as the same shape.
        detail = ", ".join(
            f"{k}={v}" for k, v in sorted(row["detail"].items()) if v not in (None, [], {})
        )
        print(
            f"{row['ts'][:19]:22}{actor[:31]:32}{row['action']:22}"
            f"{target[:27]:28}{detail}"
        )


def _denials(tenant_id: str, limit: int) -> None:
    """`--denials`: who tried, and was refused, most recent last.

    Reads `denial_records` — the same method `GET /admin/denials` reads, so the two
    surfaces cannot disagree. This is also the reader that works when the API is down
    and during the bootstrap where there is no administrator to sign in as, which is
    `--admin-log`'s reason for existing, inherited whole.

    `held` prints as `-` for none: an empty column is invisible in a table, and the
    difference between "held nothing" and "held `user`, wanted `editor`" is the one
    this log is read for.
    """
    rows = storage.active().denial_records(tenant_id, limit=limit)
    if not rows:
        print(f"No access denials recorded for tenant '{tenant_id}'")
        return

    print(f"{'when':22}{'who':32}{'on':10}{'what':28}{'required':10}held")
    for row in rows:
        who = f"{row['principal_kind']}:{row['principal_id']}"
        print(
            f"{row['ts'][:19]:22}{who[:31]:32}{row['resource_kind']:10}"
            f"{row['resource_id'][:27]:28}{row['required']:10}{row['held'] or '-'}"
        )



def _list_agents(tenant_id: str) -> None:
    """Show each agent's capability (tools) and reach (resource scope) separately.

    Unfiltered, and marked rather than filtered. Hiding rows from somebody holding
    `CARNET_DATABASE_URL` is theatre — they can read the table — but listing an
    agent that `--agent` then refuses is a confusing five minutes, so the ones this
    principal cannot run say so and point at the command that explains why.

    Note `patterns` below rather than `grants`: this function used to bind a local of
    that name, which now shadows the access module imported at the top of the file. It
    is harmless today and is exactly the kind of shadow that stops being harmless the
    first time somebody adds one line to this loop.
    """
    principal = _cli_principal(tenant_id)
    runnable = set(grants.runnable_names(principal))

    for config in agents.load(tenant_id):
        name = config["name"]
        permissions = config.get("permissions", {})
        mark = "" if name in runnable else f"   [not shared with {principal}]"
        print(f"{name}{mark}")

        print("    tools: " + (", ".join(permissions.get("tools", [])) or "<none>"))

        scope = permissions.get("scope", {})
        if not scope:
            print("    scope: <none>")
            continue

        print("    scope:")
        for resource_type in sorted(scope):
            for effect in sorted(scope[resource_type]):
                patterns = ", ".join(map(str, scope[resource_type][effect]))
                print(f"        {effect:5}  {resource_type}  ->  {patterns}")


def _list_tools(tenant_id: str) -> None:
    """The catalogue: everything this tenant may grant, and which of it writes.

    Reads `tools.catalogue()` — the same function `GET /tools` answers from, which is
    the reason that function is in `tools/` rather than in the route. Two readers of
    one table is how a CLI and an API stop agreeing about what a customer approved.

    **Contacts no server.** Descriptions are stored at vetting time, so this prints the
    same thing with Docker stopped, which is the point of migration 018 rather than a
    detail of it.
    """
    for group in tools.catalogue(tenant_id):
        where = group["id"] or "built in"
        print(f"\n{where}  —  {group['description'] or '(no description)'}")

        if not group["tools"]:
            print("    (no tools)")
            continue

        for tool in group["tools"]:
            types = ", ".join(ref["type"] for ref in tool["resources"]) or "nothing scoped"
            # The effect first, in a fixed column. It is the one thing on this line a
            # person is scanning for, and `post_message` and `list_issues` are the same
            # word until something says which of them changes anybody's systems. The
            # identity beside it, because "as whom" is the second question — step 033a.
            print(
                f"    {tool['effect']:5}  as-{tool['identity']:8}"
                f"{tool['name']}   ({types})"
            )

            if tool["remote_name"] and tool["remote_name"] != tool["name"]:
                print(f"           upstream: {tool['remote_name']}")
            if tool["description"]:
                print(f"           {tool['description']}")
            if tool["note"]:
                print(f"           note: {tool['note']}")

            # Said out loud rather than left blank, and step 012 is where this line
            # started carrying a person's name: `--vet` writes the acting principal, so
            # a tool approved through it says who. `--seed` still writes `system:cli`,
            # which is true and uninformative, and a blank column would read as "we did
            # not print it" rather than as "nobody's name is on this".
            if tool["vetted_at"]:
                who = tool["vetted_by"] or "nobody recorded"
                print(f"           vetted by {who} at {tool['vetted_at']}")

            # What the server called itself when it was approved — migration 023's whole
            # point, and only printed when there is something to print. Empty on every
            # `--seed` row and on everything vetted before 023, because neither contacted
            # a server; the alternative is a line saying "against nothing", which is
            # noise on the rows where it is true and a lie on none.
            if tool["server_name"] or tool["server_version"]:
                print(
                    "           against "
                    + mcp.discovery.server_label(
                        {
                            "name": tool["server_name"],
                            "version": tool["server_version"],
                        }
                    )
                )
    print()


def _add_tenant(parser, tenant_id: str, name: str) -> None:
    """Create a customer.

    Idempotent, like `create_tenant` itself — running it twice on an existing customer
    is not an error and does not touch their data.

    **Takes `parser` as of 018**, because `create_tenant` acquired a refusal: a deleted
    tenant's id is never reused, and without the catch that arrives as a traceback. That
    is the `api/errors.py` family in its CLI form — a caller error reported as a crash —
    and it was found by typing the command rather than by reading the code.
    """
    try:
        storage.active().create_tenant(tenant_id, name)
    except StorageError as exc:
        parser.error(str(exc))
    print(f"Tenant '{tenant_id}' ({name}) exists.")
    print("Next: register their identity provider with --add-idp.")


def _tenant_status(parser, tenant_id: str, status: str) -> None:
    """Suspend a customer, or bring one back.

    Prints what suspension does, in the two sentences that matter during an incident:
    nobody signs in, and every door call the tenant's tokens make is refused from the
    next call — `door._granted_agents` re-reads on every call, so there is no window.
    """
    store = storage.active()

    if store.get_tenant(tenant_id) is None:
        parser.error(f"no tenant '{tenant_id}'. Create it with --add-tenant.")

    try:
        store.set_tenant_status(tenant_id, status)
    except StorageError as exc:
        parser.error(str(exc))

    if status == "suspended":
        print(f"Tenant '{tenant_id}' is suspended.")
        print("  Nobody in it can sign in, and every door call its tokens make is refused")
        print("  from the next call on. Nothing of theirs is deleted.")
    else:
        print(f"Tenant '{tenant_id}' is active.")


# The one way past the confirmation, and it is deliberately unpleasant to type. Step 072's
# deletion drill found the check underneath the refusal was `stdin is readable`, so
# `echo <id> | carnet --delete-tenant <id>` deleted a customer past a sentence promising
# the command would not run unattended. The check is `sys.stdin.isatty()` now, which makes
# the sentence true and makes the command genuinely unrunnable in CI — so the one script
# that must rehearse it (`scripts/e2e_tenant_deletion.py`) needs a door, and this is it.
#
# **The name is the guard.** No flag, because a flag is discoverable by reading `--help`
# and reachable by a typo next to a tenant id; no short name, because a short name gets
# exported in a CI profile and stays there. Nothing sets this by accident, and anything
# that sets it on purpose has typed a sentence saying what it is.
DELETION_REHEARSAL_ENV = "CARNET_TENANT_DELETION_REHEARSAL_I_AM_NOT_A_PERSON"


def _delete_tenant(parser, tenant_id: str) -> None:
    """Erase a customer, and everything of theirs, permanently.

    **CLI-only, and there is no route.** 12b decision 5 refuses to let an administrator
    mint an administrator over HTTP, on the grounds that it is the one thing a
    compromised admin token cannot do; deleting the customer *and the log of what was
    done to them* is strictly worse than that. Whoever runs this already holds
    `CARNET_DATABASE_URL`, which is the trust boundary the whole CLI sits on.

    **The confirmation is the tenant id itself**, not a fixed word. `--fresh` types
    'fresh', which is right for a local scratch database and wrong here: a fixed word can
    be pasted out of a runbook without reading the line above it, and the thing that must
    be read is *which customer*. Typing the id is the operator saying the name of what
    they are destroying.

    What is printed before the prompt is what will be destroyed, counted from the
    database rather than described in general terms — the same numbers the tombstone will
    carry, so the prompt and the record cannot tell different stories.

    **A terminal, not a readable stdin.** The refusal below has always said this is the
    one command that will not run unattended, and until step 072's drill the check behind
    it was only that `input()` did not raise — so a pipe satisfied it and
    `echo <id> | carnet --delete-tenant <id>` erased a customer with nobody reading
    which. A sentence that claims a stronger guarantee than its check is worse than no
    sentence, because the guarantee is what somebody relies on when deciding whether the
    command is safe to automate. `sys.stdin.isatty()` is the check that makes it true, and
    `DELETION_REHEARSAL_ENV` is the single, named, ugly way past it.
    """
    store = storage.active()

    if store.get_tenant(tenant_id) is None:
        # A tombstone is the one answer more useful than "no such tenant", because
        # "no such tenant" is indistinguishable from a typo.
        gone = store.get_tenant_tombstone(tenant_id)
        if gone is not None:
            print(f"Tenant '{tenant_id}' was already deleted.")
            print(f"  deleted_at: {gone['deleted_at']}")
            print(f"  by:         {gone['actor']}")
            rows = gone["detail"].get("rows", {})
            print(f"  rows removed: {rows}")
            raise SystemExit(0)
        parser.error(f"no tenant '{tenant_id}'.")

    counts = {
        "agents": len(store.load_agents(tenant_id)),
        "connectors": len(store.load_connectors(tenant_id)),
        "runs": len(store.list_runs(tenant_id)),
        "users": len(store.list_users(tenant_id)),
        "audit records": len(store.audit_records(tenant_id)),
        "administrative records": len(store.admin_audit_records(tenant_id)),
        "access denials": len(store.denial_records(tenant_id)),
    }

    print(f"Deleting tenant '{tenant_id}' destroys, permanently:")
    for label, count in counts.items():
        print(f"  {count:>7}  {label}")
    print()
    print("  Their audit log, administrative log and denial log go with them. Those")
    print("  three tables are append-only and this is the only operation that empties")
    print("  them. There is no undo and no export — take a dump first if you want one.")
    print()
    print(f"  A tombstone remains: '{tenant_id}' can never be created again.")
    print()

    rehearsing = bool(os.environ.get(DELETION_REHEARSAL_ENV, "").strip())
    if not sys.stdin.isatty() and not rehearsing:
        # A CI job, a cron entry, a closed pipe — and, the case this check was widened
        # for, an *open* one. Refusing is the only defensible answer, and it is worth
        # saying why rather than just refusing: the confirmation exists so that a person
        # reads which customer is about to be destroyed. A pipe reads nothing, so nothing
        # consented, and a deletion driven by a script is precisely the deletion this
        # prompt is for. There is deliberately no `--yes` flag to add later.
        raise SystemExit(
            "nothing deleted: --delete-tenant needs a terminal to confirm in, and this "
            "is not one — stdin is a pipe, a file, or closed. This is the one command "
            "that will not run unattended.\n"
            f"  The only way past this is {DELETION_REHEARSAL_ENV}=yes, which exists so "
            "that scripts/e2e_tenant_deletion.py can rehearse this command against a "
            "scratch database.\n"
            "  Set it against a deployment holding a real customer and you have deleted "
            "them with nobody reading which. It is named here rather than hidden because "
            "hiding it would only mean finding it in the source."
        )

    try:
        typed = input(f"Type the tenant id '{tenant_id}' to confirm: ").strip()
    except EOFError:
        # Still reachable past the gate above, two ways: Ctrl-D at a real terminal, and a
        # rehearsal whose stdin ran out. **Found by running it with stdin closed**, where
        # it raised an unhandled `EOFError` traceback out of the most destructive command
        # in the product.
        raise SystemExit(
            "nothing deleted: the confirmation was not typed."
        ) from None

    if typed != tenant_id:
        raise SystemExit("nothing deleted.")

    try:
        tombstone = store.delete_tenant(
            tenant_id, actor=str(_cli_principal(tenant_id))
        )
    except StorageError as exc:
        parser.error(str(exc))

    print()
    print(f"Tenant '{tenant_id}' is deleted.")
    for table, count in tombstone["detail"]["rows"].items():
        print(f"  {count:>7}  rows from {table}")
    print(f"  tombstone written at {tombstone['deleted_at']}, actor {tombstone['actor']}")


def _prune_logs(parser) -> None:
    """Run one retention sweep now, and say what went.

    The hand-crank for a policy that otherwise rides the API's maintenance sweep once an hour.
    It exists for two callers who both need *now* rather than *within the hour*: the
    deletion drill the register asks for, and the first enablement on a deployment with
    years of records, where the operator wants to watch the backlog drain rather than
    discover it at 3am.

    Deliberately **not** a way to prune without a policy: it reads the same
    `CARNET_RETENTION_DAYS` the sweep does and refuses without one. A flag that
    could delete records with no configured window would be a second, undocumented
    retention policy living in somebody's shell history.
    """
    from .config import RETENTION_DAYS
    from . import maintenance

    if RETENTION_DAYS is None:
        parser.error(
            "no retention policy is configured, so there is nothing to prune. Set "
            "CARNET_RETENTION_DAYS to the number of days the audit, "
            "administrative and denial logs should keep a record."
        )

    from datetime import datetime, timedelta, timezone

    from .storage.base import prune_floor

    counts = maintenance.sweep_log_tables()
    total = sum(counts.values())

    # **The boundary that was applied, not the one that was asked for.** Since migration
    # 030 a prune drops whole monthly partitions, so the effective boundary is the start
    # of the cutoff's month and a record can outlive its window by up to a month. An
    # operator running this during a deletion drill is exactly the person who must not be
    # told a cleaner number than the one that happened.
    floor = prune_floor(
        datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    )

    if not total:
        print(f"Nothing older than {floor:%Y-%m-%d}. Nothing removed.")
        print(f"  ({RETENTION_DAYS}-day window, applied at the month boundary.)")
        return

    print(f"Removed {total} record(s) stamped before {floor:%Y-%m-%d}:")
    for table, count in counts.items():
        print(f"  {count:>9}  {table}")
    print()
    print(f"  The window is {RETENTION_DAYS} days and the logs are partitioned by month,")
    print("  so a whole month goes only once the window has passed all of it. Records")
    print(f"  after {floor:%Y-%m-%d} are kept even where they are older than the window.")
    print("  Each affected customer has a 'retention.prune' record saying how many of")
    print("  theirs went, and where the boundary fell.")


def _finish_rotation(parser) -> int:
    """Step three of the rotation `crypto.py` has promised since 007: re-encrypt.

    The operator has already done step one at the environment — new key in
    CARNET_SECRET_KEY, old key listed in CARNET_SECRET_KEYS_OLD, every
    process restarted onto them. This sweeps the four sealed columns onto the current
    key and prints the one sentence step four waits for: *no row names a retired key*,
    which is when — and only when — the old list can be emptied.

    Three exit codes, because a runbook is the stated consumer and each means a
    different next step:

        0   nothing named a retired key and nothing was unreadable. Empty the old list.
        1   there is work left or something needs a person — rows still under a retired
            key, or rows under a key nobody holds. Both are listed with their remedies.
        2   this could not run at all: no local keys, or storage was unreachable. The
            rotation is in whatever state it reached, which is always a consistent one.

    Idempotent and safe to interrupt: a re-run finds exactly the rows still owed,
    because a re-sealed row leaves the population by construction — which also makes
    running it with nothing to do the status check, before a rotation as well as after.

    The printout is the record. Rotation writes no administrative rows (`rotation.py`
    says why), and the key-compromise drill's deliverable is a person keeping exactly
    this transcript.
    """
    from . import rotation
    from .access.oauth import PENDING_TTL_SECONDS

    cipher = crypto.active()
    if not isinstance(cipher, crypto.LocalKeyCipher):
        parser.error(
            "the active cipher does not hold local keys, so there is no environment "
            "rotation to finish."
        )

    try:
        report = rotation.sweep(cipher)
    except StorageError as exc:
        # **`parser.error`'s 2, and the distinction is the whole reason this is caught.**
        # An uncaught `StorageError` leaves Python's exit 1 — the same code this command
        # uses for *"rows still need a retired key"* — so a runbook branching on the
        # exit code would read a database outage as an unfinished rotation and keep
        # waiting, or worse, a person would read the traceback as the rotation having
        # done something. Found by pointing the command at an unreachable database in
        # the testing pass. Nothing partial is lost: every re-seal already landed is
        # permanent, and re-running resumes from whatever did.
        parser.error(
            f"the rotation could not be completed: {exc}\n"
            "Nothing was left half-written — each row is re-sealed in one statement — "
            "and re-running picks up exactly where this stopped."
        )

    print(f"current key   {report.current_key_id}")
    if report.retired_key_ids:
        print(f"retired keys  {', '.join(sorted(report.retired_key_ids))}")
    else:
        print(f"retired keys  none listed in {crypto.OLD_KEYS_ENV}")
    print()

    if report.expired_pending_removed:
        print(
            f"Removed {report.expired_pending_removed} abandoned consent flow(s) "
            f"older than {PENDING_TTL_SECONDS // 60} minutes."
        )
    if report.unreadable_pending_removed:
        print(
            f"Removed {report.unreadable_pending_removed} pending consent flow(s) "
            "whose sealed verifier will not authenticate under a key this process "
            "holds. No key recovers those, and each would otherwise have failed at "
            "somebody's callback; the person starts again from the Connections page."
        )

    for result in report.tables:
        line = f"  {result.table:24}{result.resealed:>5} re-sealed"
        if result.changed_underneath:
            # **No claim about what they were changed to.** This used to say "already
            # on the current key", which is the usual case and is not established by
            # anything: a consent callback consuming the row, or a process still on the
            # old key rewriting it, land here identically. The diagnosis for the second
            # is below, where it can be inferred rather than assumed.
            line += (
                f"   ({result.changed_underneath} were written by somebody else "
                "mid-sweep and left alone)"
            )
        if result.failed:
            line += f"   — INCOMPLETE: {result.failed}"
        print(line)
    print()

    # **Capped, and the cap is announced** — this printout is a drill transcript a
    # person reads, and a deployment whose key was dropped early can strand every
    # credential it has. Four lines each would bury the verdict under ten thousand
    # rows. The totals below are never capped, so nothing is hidden by this.
    for row in report.stranded[:STRANDED_ROWS_SHOWN]:
        # A blob that will not authenticate under a key we hold was not merely missed;
        # it was altered or moved, and it should not read like a rotation artifact.
        marker = "SECURITY EVENT   " if row.blocks else "COULD NOT RE-SEAL"
        print(f"  {marker}  {row.table}: {row.address}")
        print(f"      {row.reason}.")
        print(f"      Remedy: {row.remedy}.")
        print()
    if len(report.stranded) > STRANDED_ROWS_SHOWN:
        print(
            f"  … and {len(report.stranded) - STRANDED_ROWS_SHOWN} more row(s) that "
            "could not be re-sealed, counted in the totals below."
        )
        print()

    blockers = {
        table: {k: n for k, n in counts.items() if k in report.retired_key_ids}
        for table, counts in report.remaining.items()
    }
    blocked = sum(n for counts in blockers.values() for n in counts.values())

    if report.finished:
        print("No row names a retired key.")
        if report.retired_key_ids:
            print(f"{crypto.OLD_KEYS_ENV} can be emptied, on every process.")
        if not report.needs_a_person:
            # A consent flow stranded under a key nobody holds is recorded above and
            # not counted here: it expires within the quarter hour on its own, so
            # there is nothing for anyone to do and nothing to fail the command for.
            return 0

        # **Exit 1, even though the old key is droppable, and the two facts are printed
        # apart on purpose.** The verdict above is about the *retired* list and stays
        # true; these rows name keys this process has never held, so keeping the old
        # list does not help them and they must not hold the drop hostage. But a
        # deployment holding rows it cannot decrypt is not a clean one, and a runbook
        # that branches on the exit code has to stop and fetch a person. Found in the
        # testing pass, where the sharpest case is an operator who dropped the old key
        # *before* sweeping: exit 0 would have told them the rotation was complete
        # while every credential written under that key was unreadable.
        print()
        print(
            f"{len(report.needs_a_person)} row(s) above name keys this process has "
            "never held, so this deployment cannot read them. The rotation itself is "
            "finished; these are a separate problem and this command exits 1 until "
            "they are gone."
        )
        print(
            f"If a key was dropped from {crypto.OLD_KEYS_ENV} too early, put it back "
            "and run this again — that is the one remedy that keeps the credentials."
        )
        return 1

    print(f"{blocked} row(s) still name a retired key, so {crypto.OLD_KEYS_ENV}")
    print("cannot be emptied yet:")
    for table, counts in blockers.items():
        for key_id, count in sorted(counts.items()):
            print(f"  {table:24}{count:>5} row(s) under '{key_id}'")
    print()
    stale = report.rows_written_under_a_retired_key
    if stale:
        # **The one failure mode whose remedy is not on any row.** Rows under a retired
        # key that no stranded row explains were written *after* the sweep walked past
        # them, and only a process still holding the retired key as its current one
        # writes those. Left undiagnosed this never converges: the sweep re-seals, that
        # process writes back, and every run reports the same count while the printed
        # remedies (reconnect, reconfigure, recreate) all fail to help.
        print(
            f"{stale} of those row(s) were written under a retired key while this "
            "sweep was running, which nothing but a process still holding that key "
            "can do."
        )
        print(
            "  Restart every server onto the new "
            f"{crypto.KEY_ENV} before running this again — re-sealing rows underneath "
            "a process that is still writing old ones never finishes."
        )
        print()
    print("Resolve the rows listed above and run this again.")
    return 1


def _add_idp(parser, args) -> None:
    """Register an identity provider for a customer.

    The failure this reports carefully is `IssuerConflictError`, because it is the one
    that means *somebody would have been able to read another customer's data*. A
    stack trace would be a poor way to find that out.
    """
    missing = [
        flag
        for flag, value in (
            ("--issuer", args.issuer),
            ("--jwks-uri", args.jwks_uri),
            ("--audience", args.audience),
        )
        if not value
    ]
    if missing:
        parser.error(f"--add-idp needs {', '.join(missing)}")

    claim = value = None
    if args.discriminator:
        if "=" not in args.discriminator:
            parser.error("--discriminator must look like CLAIM=VALUE, e.g. hd=acme.com")
        claim, value = args.discriminator.split("=", 1)

    try:
        storage.active().save_tenant_idp(
            args.add_idp,
            {
                "issuer": args.issuer,
                "jwks_uri": args.jwks_uri,
                "audience": args.audience,
                "discriminator_claim": claim or None,
                "discriminator_value": value or None,
                "subject_claim": args.subject_claim,
                "email_claim": args.email_claim,
                "groups_claim": args.groups_claim or None,
                "allowed_domains": tuple(args.domain or ()),
            },
        )
    except UnknownTenantError:
        parser.error(
            f"tenant '{args.add_idp}' does not exist. Create it first:\n"
            f"  carnet --add-tenant {args.add_idp} \"Their Name\""
        )
    except IssuerConflictError as exc:
        # Not a validation error. This one means the registration would have made a
        # token ambiguous between two customers.
        parser.error(f"refused: {exc}")
    except ValueRefused as exc:
        # `--domain '*'` on anything but the local provider. It used to print a warning
        # here and register the row anyway; the refusal now lives in `normalize_idp`, so
        # this branch reports it rather than deciding it.
        parser.error(f"refused: {exc}")

    where = f" ({claim}={value})" if claim else ""
    print(f"Registered {args.issuer}{where} for tenant '{args.add_idp}'.")
    # The claim mapping this registration actually wrote, printed because this command
    # is an **upsert**: re-running it to change a domain silently resets every claim to
    # its default, and `--groups-claim` is the one where that turns a directory-managed
    # tenant back into a hand-managed one. Step 033e — the line that makes it visible at
    # the moment it happens, rather than the week somebody notices nobody is joining.
    print(
        f"Claims: subject={args.subject_claim}, email={args.email_claim}, "
        f"groups={args.groups_claim or '<none>'}."
    )
    if not args.groups_claim:
        print(
            "No --groups-claim, so group membership stays what --group-add makes it."
        )
    if not args.domain:
        print(
            "Note: no --domain given, so nobody will be created automatically on first "
            "login. Add one to let this provider vouch for its own people."
        )


def _refuse(exc: NoAccess, tenant_id: str, agent_name: str) -> NoReturn:
    """Report a `NoAccess` on the CLI, with the context the API deliberately withholds.

    `grants.require` raises one sentence — "no agent named X" — whether the agent is
    absent, ungranted, or granted too low, and the API sends exactly that. The equality
    is the point: over HTTP, distinguishing them lets somebody sweep plausible names and
    enumerate a company's agents, which is worth more than the access.

    On a terminal that sentence is a lie by omission. Whoever ran this holds
    `CARNET_DATABASE_URL`, can read `agent_grants` directly, and has very likely
    just seen the agent in `--list` — so telling them it does not exist teaches them
    to distrust the tool. The exception's wording is unchanged, because that is the
    tested property; the CLI adds what it already knows on top.

    **A sentence, not the usage block.** `parser.error` printed ~90 lines of argparse
    usage after every one of these, which is step 072's second finding: the operator asked
    a permission question and got the entire flag list, in which the one line that matters
    is invisible. Nothing here is a *usage* error — the arguments parsed fine and the
    answer is "not you" — so this reports the way every other refusal in this file that is
    not about argument shape does, `print(..., file=sys.stderr)` and exit 1.
    """
    known = storage.active().get_agent(tenant_id, agent_name) is not None
    hint = (
        f"\n  It exists. It has not been shared with {_cli_principal(tenant_id)} at the "
        f"level this needs:\n  carnet --agent-access {agent_name}"
        if known
        else ""
    )
    print(f"{exc}{hint}", file=sys.stderr)
    raise SystemExit(1)


def _share_agent(parser, tenant_id: str, agent_name: str, who: str, role: str) -> None:
    """Give somebody access to an agent, or change the level they have.

    The CLI acts as `system:cli`, which migration 011 made the owner of every agent that
    existed before sharing did — so this works out of the box on an existing database and
    does not on an agent somebody has since taken over. That is the model working: the
    operator is not a superuser, they are a principal with grants like anybody else.

    `who` is an **email address** — the thing a person actually knows about a colleague —
    or a principal id (`u_8f2c1a`, `system:nightly`) for the cases an address cannot
    name. An address is resolved to whoever holds it, and held as a pending grant if
    nobody does yet.
    """
    principal = _cli_principal(tenant_id)

    if "@" in who:
        if role == storage.OWNER_ROLE:
            # Ownership is transferred to a real principal, never left waiting on an
            # address. `share_by_email` refuses an unresolvable one itself, so this only
            # translates a resolvable address into the id `transfer` needs.
            existing = storage.active().find_user_by_email(tenant_id, who)
            if existing is None:
                parser.error(
                    f"nobody has logged in as '{who}', so ownership cannot be handed to "
                    "them. An agent owned by an address that is never claimed is an "
                    "orphan. Share it at editor, or wait until they sign in."
                )
            who = existing["id"]
        else:
            try:
                outcome = grants.share_by_email(principal, agent_name, who, role=role)
            except ShareRefused as exc:
                # Reported plainly, with no hint appended. `_refuse` explains a
                # *permission* failure, and this is not one — the caller owns the agent
                # and the address is the problem. Saying otherwise told an operator who
                # owned the agent that it had not been shared with them.
                parser.error(str(exc))
            except NoAccess as exc:
                _refuse(exc, tenant_id, agent_name)

            if outcome == "pending":
                print(
                    f"'{who}' has not logged in yet. Held: they will have {role} access "
                    f"to '{agent_name}' the first time they sign in."
                )
            else:
                print(f"'{who}' now has {role} access to '{agent_name}'.")
            return

    kind, _, ident = who.rpartition(":")
    kind = kind or "user"

    if kind == "group":
        # `group:support` is what a person types; `group:g_8f2c...` is what a grant
        # records. Resolved here rather than in `grants.share`, for the reason an address
        # is resolved here: turning what somebody typed into an id is an entry point's
        # job, and the access layer deals in ids.
        try:
            ident = groups.resolve(principal, ident)["group_id"]
        except groups.GroupRefused as exc:
            parser.error(str(exc))

    try:
        if role == storage.OWNER_ROLE:
            grants.transfer(principal, agent_name, kind, ident)
        else:
            grants.share(principal, agent_name, kind, ident, role=role)
    except ShareRefused as exc:
        # A group at `owner`, or a grant naming a group that does not exist. Not a
        # permission failure, so no hint is appended — see `_refuse`.
        parser.error(str(exc))
    except NoAccess as exc:
        _refuse(exc, tenant_id, agent_name)
    except ValueRefused as exc:
        # A rule the *storage* layer owns, arriving here as a refusal rather than a
        # traceback — step 020's machine-role ceiling is the first one that reaches this
        # path. 018 learned exactly this about `--add-tenant`: a refusal added below the
        # CLI shows up as a stack trace in the terminal until somebody types the command.
        # `ValueRefused` and not `StorageError`, because a genuinely broken store must
        # still fail loudly rather than being reported as if the operator mistyped.
        parser.error(str(exc))

    print(f"'{kind}:{ident}' now has {role} access to '{agent_name}'.")

    if kind == "group" and not groups.members(principal, ident):
        print(
            "\nWARNING: that group has no members, so this shares the agent with "
            "nobody.\nIt will still appear in --agent-access as though somebody has "
            "access.",
            file=sys.stderr,
        )


def _unshare_agent(parser, tenant_id: str, agent_name: str, who: str) -> None:
    principal = _cli_principal(tenant_id)

    if "@" in who:
        try:
            outcome = grants.unshare_email(principal, agent_name, who)
        except ShareRefused as exc:
            # Reachable by address too: an address resolves to a person whose access is
            # inherited. Same refusal, same reason.
            parser.error(str(exc))
        except NoAccess as exc:
            _refuse(exc, tenant_id, agent_name)

        if outcome == "cancelled":
            print(f"Cancelled the invitation for '{who}' to '{agent_name}'.")
        else:
            print(f"'{who}' no longer has access to '{agent_name}'.")
        return

    kind, _, ident = who.rpartition(":")
    kind = kind or "user"

    if kind == "group":
        try:
            ident = groups.resolve(principal, ident)["group_id"]
        except groups.GroupRefused as exc:
            parser.error(str(exc))

    try:
        grants.unshare(principal, agent_name, kind, ident)
    except ShareRefused as exc:
        # Decision 6: their access is real and this command would not have touched it.
        # Refused rather than obeyed, because "revoked" followed by them still running it
        # is how somebody stops trusting the tool.
        parser.error(str(exc))
    except NoAccess as exc:
        _refuse(exc, tenant_id, agent_name)

    print(f"'{kind}:{ident}' no longer has access to '{agent_name}'.")


def _rename_agent(parser, tenant_id: str, agent_name: str, new_name: str) -> None:
    """Change what an agent is called. Step 025.

    **`owner`, checked through `grants.require` like the HTTP route** — parity is the rule
    (022's split, restated at every step since), and the level is the route's argument
    verbatim: an editor changes what an agent does, this changes the URL somebody
    bookmarked.

    Everything survives: grants, pending grants, schedules, triggers, the version history,
    the threads and the run history. Before migration 035 none of that was true, because
    the only way to change a name was to create a second agent and delete the first.
    """
    principal = _cli_principal(tenant_id)

    try:
        grants.require(principal, agent_name, "owner")
    except NoAccess as exc:
        _refuse(exc, tenant_id, agent_name)

    try:
        row = agents.rename(tenant_id, agent_name, new_name, actor=str(principal))
    except (InvalidAgentError, AgentNameTaken, ValueRefused) as exc:
        # Three refusals, one sentence each, and all three are the caller's to fix: a name
        # the rules reject, a name already taken, and the name it already has. `--seed`'s
        # convention — the validator's words, not a paraphrase — and exit 2, which is what
        # `parser.error` gives every other bad-input path here.
        parser.error(str(exc))

    if row is None:
        parser.error(
            f"no agent named '{agent_name}' in tenant '{tenant_id}'. Nothing was renamed."
        )

    print(f"Renamed '{agent_name}' to '{new_name}'.")
    # Said out loud because it is the one consequence a person will not think of, and the
    # moment to think of it is now rather than when a webhook starts 404ing.
    print(
        f"  Its grants and history came with it. Anything holding the old URL — a "
        f"bookmark, a runbook, another system's config — now points at nothing:\n"
        f"    /agents/{agent_name}  ->  /agents/{new_name}"
    )


def _agent_access(tenant_id: str, agent_name: str) -> None:
    """Who may use this agent, and at what level.

    The command somebody actually needs first on an existing database: it is how you
    discover that `system:cli` owns everything after migration 011, and who to hand each
    agent to.

    **Read as an administrator, not as a grantee — step 072's second finding.** This used
    to go through `grants.who_has_access`, which checks the *agent* ladder; `system:cli`
    holds no grant on an agent somebody has taken over, so the operator who owns the
    database was told the agent did not exist. That refusal protected nothing: 026's own
    argument for keeping role granting on the CLI is that whoever runs it holds
    `CARNET_DATABASE_URL` and can `SELECT * FROM agent_grants` in the next shell.

    **Fixed here rather than in `grants.require`**, and the choice matters. Widening
    `require` would let any administrator read any agent's sheet over HTTP — and
    `access/roles.py` states as a load-bearing rule that the two ladders never touch:
    *"this module never consults `agent_grants` and `access/grants.py` never consults
    `platform_roles`"*. Making an admin role imply agent access is exactly the operator
    holding everybody's data that 7b exists to prevent. So the *platform* check happens
    here, in the entry point that is allowed to compose layers, and `grants` keeps its
    ladder: `who_has_access_unchecked` takes a tenant and an agent and asks nobody's
    permission, because the caller has already established the right to read.

    An administrator reading a sheet is still not a grant: nothing here can run the agent.

    One record stops being written and it is worth naming: `require` logged a denial on
    every refusal, so `access_denials` used to collect a row each time the operator ran
    this. Those rows recorded the defect, not an attempt — nobody was kept out of
    anything — and the read that replaces them is not a denial to record.
    """
    store = storage.active()
    principal = _cli_principal(tenant_id)

    if store.get_agent(tenant_id, agent_name) is None:
        # The one answer the ladder used to give here that must not be lost. Without the
        # grant check, a typo'd name would read "Nobody has access to 'triaeg'", which is
        # true of every name nobody has ever used and is not what was asked. The sentence
        # is the ladder's own, so a person who ran this before sees no new wording.
        _refuse(NoAccess(f"no agent named '{agent_name}'"), tenant_id, agent_name)

    try:
        roles.require_admin(principal, f"reading who can reach '{agent_name}'")
    except roles.RoleRequired as exc:
        # Unreachable while `_cli_principal` is a `system` principal, which `is_admin`
        # admits before any storage read. Caught anyway on 018's lesson: a rule added
        # below the CLI arrives as a stack trace in somebody's terminal until somebody
        # types the command.
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from None

    rows = grants.who_has_access_unchecked(tenant_id, agent_name)
    # `who_is_waiting`'s body without its ladder check, for the reason above.
    waiting = store.list_pending_grants(tenant_id, agent_name)

    if not rows and not waiting:
        # Reachable: revoking an owner is permitted and leaves an agent orphaned.
        print(f"Nobody has access to '{agent_name}'. No token can call through it.")
        return

    if waiting:
        # Listed apart from the grants, because they are a different fact: nobody has
        # this access, somebody *will* if a person ever arrives at that address. Also
        # the only way to spot a share that will never land, since nothing expires them.
        print(f"{'waiting on a first login':40}{'role':10}invited by")
        for row in waiting:
            print(f"{row['email']:40}{row['role']:10}{row['granted_by'] or '<unrecorded>'}")
        if rows:
            print()

    if not rows:
        return

    # The third column is the whole point since groups exist — see `who_has_access`.
    # Without it an owner sees Sam, removes Sam, and Sam still has access.
    print(f"{'principal':40}{'role':10}{'how':28}granted by")
    for row in rows:
        who = f"{row['kind']}:{row['id']}"
        print(
            f"{who:40}{row['role']:10}{_how(row):28}"
            f"{row['granted_by'] or '<unrecorded>'}"
        )

    if any(row["direct"] is None for row in rows):
        print(
            "\nSomebody above has access only through a group. Unsharing them is "
            "refused,\nbecause it would remove nothing — take them out of the group, or "
            "unshare the group.",
            file=sys.stderr,
        )

    # Step 033e, and the obligation 9b inherited: with membership coming from a claim
    # this list is everybody who has **signed in** since being placed in the group, not
    # everybody who is in it. Said plainly rather than by quietly returning a shorter
    # list — which is exactly how `who_is_waiting` is kept apart from real grants.
    #
    # **The pronoun is pluralised too, and 035h's pass two is what noticed.** The verb has
    # agreed since 033e and `them` was hardcoded, so one group read *"g_… follows your
    # directory. People placed in them there…"* — and the share sheet's own comment cites
    # this sentence as the thing it agrees with, which made a broken singular a claim about
    # agreement that was false in the commonest case there is.
    followed = [row["id"] for row in rows if row["kind"] == "group" and row["directory"]]
    if followed:
        one = len(followed) == 1
        print(
            f"\n{', '.join(followed)} follow{'s' if one else ''} your "
            f"directory. People placed in\n{'it' if one else 'them'} there who have not "
            "signed in since are not listed above — they will appear\nwhen they next "
            "sign in.",
            file=sys.stderr,
        )


def _how(row: dict) -> str:
    """Where this row's access comes from, in the words the refusal will use."""
    via = ", ".join(f"group:{g}" for g in row["via"])
    if row["direct"] is not None and via:
        return f"direct + {via}"
    return via or "direct"


# --- groups ---------------------------------------------------------------------------


def _add_group(parser, tenant_id: str, name: str, *rest: str) -> None:
    principal = _cli_principal(tenant_id)
    description = " ".join(rest)

    try:
        row = groups.create(principal, name, description=description)
    except groups.GroupRefused as exc:
        parser.error(str(exc))

    print(f"Created group '{row['name']}' ({row['group_id']}).")
    print(
        f"It grants nobody anything yet. Put people in it with --group-add, and share "
        f"an agent with it:\n  carnet --share-agent AGENT group:{row['group_id']} "
        "--role user"
    )


def _delete_group(parser, tenant_id: str, who: str) -> None:
    """Delete a group by name or id.

    **Naming a group that is not there is an error, and that is deliberate** even though
    `groups.delete` is idempotent and `--unshare-agent` on somebody with no grant is
    not an error.

    The difference is what a wrong answer costs. 8c's lesson — anything a client retries
    must tolerate a second call — is about machines retrying automatically, and nothing
    retries this. What does happen is somebody typing `--delete-group finanace`, and
    answering "nothing to do" there reports success for an action that did nothing, which
    is the failure decision 6 exists to refuse. Same principle, applied to the same step.
    """
    principal = _cli_principal(tenant_id)

    try:
        group = groups.resolve(principal, who)
        member_count = len(groups.members(principal, group["group_id"]))
        groups.delete(principal, group["group_id"])
    except groups.GroupRefused as exc:
        parser.error(str(exc))

    print(f"Deleted group '{group['name']}' ({group['group_id']}).")
    if member_count:
        print(
            f"{member_count} member(s) lost whatever access they had through it, on "
            "every agent it was shared with.",
            file=sys.stderr,
        )


def _group_member(parser, tenant_id: str, who_group: str, who: str, add: bool) -> None:
    principal = _cli_principal(tenant_id)

    try:
        group = groups.resolve(principal, who_group)
    except groups.GroupRefused as exc:
        parser.error(str(exc))

    # **A group cannot hold a pending member**, and this is where somebody meets that.
    # `pending_grants` lets a share wait for a first login; there is no equivalent for
    # membership, so "add the new hire to the support team" does not work until they
    # have signed in once — which is the exact workflow groups exist for. Building the
    # equivalent is a table and a claim step, and 9b may make it moot by resolving
    # membership from the directory instead. Either way it should not be discovered as
    # a message about credentials.
    member = _principal_for(
        parser,
        tenant_id,
        who,
        unresolved=(
            "A group holds principals, and a principal does not exist until its owner "
            "signs in once — there is no pending membership the way there is a pending "
            "share. Ask them to sign in, then add them. To give them access to one "
            "agent in the meantime, share it with the address directly:\n"
            f"  carnet --share-agent AGENT {who}"
        ),
    )

    try:
        if add:
            groups.add_member(principal, group["group_id"], member.kind, member.id)
        else:
            removed = groups.remove_member(
                principal, group["group_id"], member.kind, member.id
            )
    except groups.GroupRefused as exc:
        parser.error(str(exc))

    if add:
        print(f"{member} is in group '{group['name']}'.")
        return

    if not removed:
        print(f"{member} was not in group '{group['name']}'. Nothing to do.")
        return

    print(f"{member} is no longer in group '{group['name']}'.")
    print(
        "Every access they had through this group is gone, on every agent, and they "
        "have not been told.",
        file=sys.stderr,
    )


def _group_link(parser, tenant_id: str, who_group: str, external_id: str | None) -> None:
    """Point a group at the customer's directory, or hand it back. Step 033e.

    **The print is the control.** Linking is a takeover: from here on the group's
    membership is whatever the claim says, so everybody in it the directory does not name
    is removed as they sign in, one at a time. The count of who that currently is stops
    being knowable the moment it starts happening, so it is printed before — the same
    reason `delete_group` counts what it is about to destroy rather than reporting
    afterwards that something went.
    """
    principal = _cli_principal(tenant_id)

    try:
        group = groups.resolve(principal, who_group)
        at_risk = groups.unmanaged_members(principal, group["group_id"]) if external_id else []
        row = groups.link(principal, group["group_id"], external_id)
    except groups.GroupRefused as exc:
        parser.error(str(exc))

    if not external_id:
        print(
            f"Group '{row['name']}' ({row['group_id']}) no longer follows your "
            "directory. Nobody was removed;\nits membership is yours to edit again."
        )
        return

    print(
        f"Group '{row['name']}' ({row['group_id']}) follows directory group "
        f"'{row['external_id']}'.",
        flush=True,
    )
    print(
        "Membership is now set from the groups claim at each person's next sign-in. "
        "Nothing\nchanges for anybody until they next sign in.",
        file=sys.stderr,
    )
    if at_risk:
        print(
            f"{len(at_risk)} person(s) are in it now. Any the directory does not name "
            "will be removed\nat their next sign-in, losing whatever access this group "
            "carries.",
            file=sys.stderr,
        )


def _groups(parser, tenant_id: str, who: str | None) -> None:
    """Every group, or one group's members."""
    principal = _cli_principal(tenant_id)

    if who is None:
        rows = groups.list_groups(principal)
        if not rows:
            print(
                f"No groups in tenant '{tenant_id}'. Create one with --add-group, then "
                "share an agent with it."
            )
            return

        print(f"{'group':26}{'name':24}{'members':9}{'directory':38}description")
        for row in rows:
            count = len(groups.members(principal, row["group_id"]))
            # Step 033e. The column an admin reads to know whether the membership
            # beside it is theirs to edit — and where they check the value they pasted.
            linked = row["external_id"] or "—"
            print(
                f"{row['group_id']:26}{row['name']:24}{count:<9}{linked:38}"
                f"{row['description'] or ''}"
            )
        return

    try:
        group = groups.resolve(principal, who)
        rows = groups.members(principal, group["group_id"])
    except groups.GroupRefused as exc:
        parser.error(str(exc))

    if not rows:
        # Worth saying plainly: a grant to an empty group is a row in --agent-access
        # that gives nobody anything, and it looks exactly like access.
        print(
            f"Group '{group['name']}' ({group['group_id']}) has no members. Anything "
            "shared with it is shared with nobody."
        )
        return

    print(f"Group '{group['name']}' ({group['group_id']})")
    if group["external_id"]:
        print(
            f"Membership follows your directory (as '{group['external_id']}'): it is "
            "set at each\nperson's next sign-in, and people placed in it there who have "
            "not signed in\nsince are not listed."
        )
    print(f"{'member':40}added by")
    for row in rows:
        member = f"{row['principal_kind']}:{row['principal_id']}"
        print(f"{member:40}{row['added_by'] or '<unrecorded>'}")


def _cli_principal(tenant_id: str) -> Principal:
    """The CLI is a headless caller: nobody opened this, so there is no user whose
    authority it acts under. `CARNET_TENANT` picks which customer it acts for.

    **This principal is always an administrator**, and that is where the whole platform
    role model bottoms out — see `access/roles.py`. Whoever can run this already holds
    `CARNET_DATABASE_URL` and can write any row by hand, so a role check that
    refused them would be a control with nothing behind it. It is also what makes lockout
    impossible: revoking the last `admin` leaves this door open.
    """
    return Principal.system("cli", tenant_id)


# --- platform roles ------------------------------------------------------------------
#
# **Granting stays here and does not become a route**, and that is a decision rather than
# an ordering. A role model whose first version lets administrators mint administrators
# over HTTP hands a compromised admin token the one thing it lacks, quietly, in the step
# whose whole purpose is containment. The administrative log would record the escalation,
# and recording one is not preventing one.


def _grant_role(parser, tenant_id: str, role: str, who: str) -> None:
    """`--grant-role admin <who>`: make somebody an administrator of this tenant.

    `<who>` is an email address or a principal id, resolved exactly as
    `--connect-account` resolves it — **including the refusal for an address nobody has
    logged in with**, and for a sharper version of that reason. A share may wait for
    somebody (`pending_grants`, claimed at first sign-in); a *role* must not, because a
    pending admin grant is a landmine that promotes whoever eventually claims an address —
    a mistyped one, a recycled one — silently, at login, with the granting recorded weeks
    earlier.
    """
    subject = _principal_for(
        parser,
        tenant_id,
        who,
        unresolved="A role is not an invitation — it cannot wait for somebody the way a "
        "share can, because whoever eventually claimed that address would become an "
        "administrator at their first sign-in. Ask them to sign in once, then grant it.",
    )

    if subject.kind == "group":
        parser.error(
            "a group cannot hold a platform role. Membership of a group is not an "
            "administrative decision, so anybody who may add a member would be able to "
            "make an administrator."
        )

    try:
        roles.grant(_cli_principal(tenant_id), subject, role)
    except StorageError as exc:
        parser.error(str(exc))

    print(f"'{subject.kind}:{subject.id}' is now an administrator of '{tenant_id}'.")
    print(
        "  This grants access to no agent, no run and no connection — it is tenant "
        "configuration,\n  not tenant data. They still need a grant like anybody else "
        "to run anything."
    )


def _revoke_role(parser, tenant_id: str, role: str, who: str) -> None:
    """`--revoke-role admin <who>`: take it away. Idempotent, and it warns when it empties.

    **Revoking the last administrator is allowed**, deliberately and without a guard.
    Lockout is impossible — this command runs as `system:cli`, which is always an
    administrator — so a "cannot remove the last admin" rule would defend a failure that
    cannot happen here, and would become wrong the day role administration moves to HTTP
    where it has to be re-decided rather than inherited. What it gets instead is a loud
    sentence, because the *product* becomes unadministerable by anybody without a shell.
    """
    subject = _principal_for(
        parser,
        tenant_id,
        who,
        unresolved="There is nobody by that address to take a role from.",
    )

    principal = _cli_principal(tenant_id)
    removed = roles.revoke(principal, subject, role)

    if not removed:
        print(
            f"'{subject.kind}:{subject.id}' did not hold '{role}' in '{tenant_id}'. "
            "Nothing to do."
        )
        return

    print(f"'{subject.kind}:{subject.id}' is no longer an administrator of '{tenant_id}'.")

    remaining = [row for row in roles.list_roles(principal) if row["role"] == ADMIN_ROLE]
    if not remaining:
        # **Flushed before the warning, or the two arrive out of order.** stdout is
        # block-buffered when it is a pipe and stderr never is, so `... 2>&1 | tee log`
        # puts the warning *above* the line it is a warning about. On a terminal the
        # ordering is right by luck, which is the worst way for it to be right.
        sys.stdout.flush()
        print(
            f"\nWARNING: tenant '{tenant_id}' now has no administrators. Nothing in the "
            "application\ncan administer it — no group management, no vetting screen, "
            "and no administrative log.\nThis command still works, because it runs as a "
            "system principal, and that is the only\nway back: "
            f"carnet --grant-role {ADMIN_ROLE} <who>",
            file=sys.stderr,
        )


def _list_roles(tenant_id: str) -> None:
    """`--list-roles`: who may administer this tenant.

    **The note under the table is not decoration.** `system` principals administer and
    hold no row, so a listing that printed only the table would answer "who can administer
    this" incompletely — which is the one question it exists for. `list_platform_roles`
    deliberately returns what the table holds and nothing else; the rule about `system`
    is policy, and it is stated here where somebody is reading the answer.
    """
    rows = roles.list_roles(_cli_principal(tenant_id))

    if not rows:
        print(f"No platform roles granted in tenant '{tenant_id}'.")
    else:
        print(f"{'who':40}{'role':10}{'granted by':32}granted at")
        for row in rows:
            who = f"{row['principal_kind']}:{row['principal_id']}"
            granted_at = row["granted_at"]
            when = (
                granted_at.isoformat(timespec="seconds")
                if hasattr(granted_at, "isoformat")
                else str(granted_at)
            )
            print(f"{who[:39]:40}{row['role']:10}{row['granted_by'][:31]:32}{when}")

    print(
        "\nEvery `system` principal is an administrator and holds no row here — "
        "including this\ncommand, which runs as system:cli. That is the bootstrap and "
        "the way back from an\nempty table."
    )


# --- api tokens ----------------------------------------------------------------------
#
# **Minting stays here and does not become a route**, on the same argument as the roles
# above and a sharper version of it. What a compromised bearer token lacks is
# *persistence*: it expires, and the person holding it is eventually offboarded. A mint
# route hands it a durable successor that survives both, under a name nobody reads.
#
# The terminal is also the only place a secret can be shown once and not end up in a
# response body that some client library logs by default.
#
# Granting an agent to a machine is deliberately **not** here-only: that is an ordinary
# share, it goes through the existing routes and `--share-agent`, and the two-sidedness
# is the point. Minting the credential is the sensitive act; deciding what it may run is
# the same decision anybody makes about a colleague.


def _mint_token(
    parser,
    tenant_id: str,
    name: str,
    who: str,
    expires_days,
    *,
    acts_as_owner: bool = False,
) -> None:
    """`--mint-token NAME WHO`: create an API token owned by a person, print it once.

    `WHO` is resolved exactly as `--grant-role` resolves it, **including the refusal for
    an address nobody has logged in with**, and for the same reason one step further on:
    a token whose owner has never existed is a credential answerable to nobody, and the
    live owner check on every request would refuse it at its first call anyway. Failing
    at mint is the same refusal, six weeks earlier and with somebody watching.

    `--as-owner` mints a personal token (step 033d), and the print differs in the one
    place it must: the closing hint. The service-token hint names the exact command
    (`--share-agent ... machine:<id>`) that `grants.share` now *refuses* for a
    personal token, so printing it here would be a suggested command that fails — the
    defect this function's own history note below records being found by typing one.
    """
    owner = _principal_for(
        parser,
        tenant_id,
        who,
        unresolved="A token is not an invitation — every request it makes re-reads its "
        "owner and refuses when they are missing or disabled, so a token owned by "
        "nobody could never make one. Ask them to sign in once, then mint it.",
    )

    if owner.kind != "user":
        parser.error(
            f"a token's owner must be a person, not '{owner.kind}'. The owner is who is "
            "answerable for what the token does and who it dies with — a machine owning "
            "a machine is a chain with nobody at the end of it."
        )

    expires_at = None
    if expires_days is not None:
        if expires_days < 1:
            parser.error(
                "--expires-days must be at least 1. There is no spelling of 'expires "
                "immediately': to end a token now, mint nothing and use --revoke-token."
            )
        try:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)
        except OverflowError:
            # The ceiling is what a date can represent rather than a number somebody
            # chose, so there is nothing here to re-derive later. Refused rather than
            # clamped: silently turning "a hundred million days" into year 9999 answers a
            # question the operator did not ask.
            parser.error(
                f"--expires-days {expires_days} is further ahead than a date can be "
                "written. If the intent is a token that does not expire, leave the flag "
                "off — that is what 'no expiry' is spelled as."
            )

    try:
        row, presented = tokens.mint(
            tenant_id,
            name,
            owner.id,
            actor=str(_cli_principal(tenant_id)),
            expires_at=expires_at,
            acts_as_owner=acts_as_owner,
        )
    except StorageError as exc:
        parser.error(str(exc))

    print(f"Minted '{row['name']}' for tenant '{tenant_id}'.")
    print(f"  id     {row['id']}")
    print(f"  owner  user:{owner.id}")
    if acts_as_owner:
        print(
            "  kind   personal — resolves its owner's access (grants and groups), "
            "capped at user"
        )
    print(
        "  expires"
        + (
            f"  {expires_at.isoformat(timespec='seconds')}"
            if expires_at
            else "  never — revoke it to end it"
        )
    )
    print()
    print("  " + presented)
    print()
    # Said plainly because it is true and because the alternative — somebody assuming it
    # can be looked up later — ends with a support request nothing can answer.
    print(
        "This is the only time that string exists. It is stored as a hash, so nothing\n"
        "here or in the database can show it again — if it is lost, revoke this token\n"
        "and mint another."
    )
    if acts_as_owner:
        # No grant hint: the command the service hint suggests is one `grants.share`
        # refuses for this token, and a suggested command that fails is this
        # function's own recorded defect. What is true instead is said instead.
        print(
            f"\nIt can call whatever user:{owner.id} can call, from this moment and as "
            "their access changes.\nGrant nothing to the token itself — share agents "
            "with the owner, and every personal\ntoken they hold follows. When they "
            "are disabled, it stops."
        )
        return

    # **`--role user`, not a bare `user`.** As first written this line printed a command
    # that argparse refuses with *"unrecognized arguments: user"* — `--share-agent` takes
    # exactly two positionals and the level is a flag. Shipped in 020 and found in 022 by
    # copying the hint out of this function into another one and then typing it, which no
    # test would ever have done: a suggested command nothing executes is a string, and a
    # string cannot fail.
    print(
        f"\nIt can call nothing yet. Grant it an agent like anybody else:\n"
        f"  --share-agent <agent> machine:{row['id']} --role user"
    )


def _revoke_token(parser, tenant_id: str, token_id: str) -> None:
    """`--revoke-token ID`: close the door. Idempotent, and it says what it does not do.

    **The row is stamped, never deleted**, because it is the only place a
    `machine:m_...` string in an old audit record resolves to a name and an owner.

    The sentence about what it does not do is section H's standing constraint, printed
    rather than assumed: revocation closes a door and stops nothing already through it.
    That is the same sentence `--tenant-status` prints for a suspension, and it is here
    for the same reason — the person typing this is usually typing it because something
    is wrong, which is exactly when "it stopped everything" is the wrong thing to believe.
    """
    store = storage.active()

    try:
        row = store.revoke_api_token(
            tenant_id, token_id, actor=str(_cli_principal(tenant_id))
        )
    except StorageError as exc:
        parser.error(str(exc))

    if row is None:
        parser.error(
            f"tenant '{tenant_id}' has no API token with id '{token_id}'. "
            "`--list-tokens` shows the ids."
        )

    print(f"Token '{row['name']}' ({row['id']}) is revoked.")
    print("  Its next request is refused. The row stays, so old records still name it.")

    print(
        "  A call already admitted is not reached: revocation closes a door, it does not "
        "reach through one."
    )


def _token_principal(parser, tenant_id: str, token_id: str):
    """The principal a door call by this token is made under, or exit(2). Step 069.

    **Constructed, not resolved, and constructed as the *machine*** — which is the trap
    both readers below would otherwise fall into. `grants.runnable_names` redirects a
    personal token through its owner, so simulating "as the owner" looks right; it is
    not. `permissions._resolve` substitutes `${principal.id}` from the principal it is
    handed, and the broker is handed the machine principal on a real door call. The two
    readers here have to be wrong in the same way the door is, or they are not answering
    the door's question.

    Nothing is presented and nothing is stamped: `last_used_at` answers *was this
    credential used*, and a review conducted by reading would corrupt the one column that
    question has.
    """
    row = storage.active().find_api_token(token_id)
    if row is None or row["tenant_id"] != tenant_id:
        parser.exit(
            2,
            f"there is no API token '{token_id}' in tenant '{tenant_id}'. "
            "`--list-tokens` shows the ids.\n",
        )
    return Principal.machine(token_id, tenant_id)


def _reach(parser, tenant_id: str, token_id: str) -> None:
    """`--reach`: what a token may call, tool by tool.

    The transpose, because the per-agent view is the one the browser already had and the
    one that cannot be read tool-first. Under 033b's union rule a token holds the union
    of its granted agents' tools with **each tool keeping its own agent's scope**, so the
    agent-by-agent listing hands a cross-reference exercise to whoever is trying to work
    out whether a credential is over-broad.

    `door.reach` computes it — the door's own functions, not a second reading of the
    grants — and this prints what that returns. No socket is opened, no credential is
    read and nothing is stamped.
    """
    principal = _token_principal(parser, tenant_id, token_id)
    answer = door.reach(principal)

    # Whose day the ceilings count — step 108, decision 7. Said on both branches, because
    # this is the command an administrator reads before asking why a token was refused,
    # and for a personal token the answer is often another machine's morning.
    pooled = door.budget_owner(principal)
    ceilings = (
        f"Daily ceilings: shared with every personal token {pooled} holds — one "
        "allowance per person, not per machine."
        if pooled is not None
        else "Daily ceilings: this token's own. A service token's day is its own, "
        "whoever else the owner's tokens are."
    )

    if not answer["tools"]:
        print(f"API token '{token_id}' is granted nothing. It can authenticate and "
              "call no tool at all.")
        if answer["invalid_agents"]:
            print(f"\n  {len(answer['invalid_agents'])} granted agent(s) have an invalid "
                  f"config and were skipped: {', '.join(answer['invalid_agents'])}")
        print(f"\n{ceilings}")
        return

    print(f"API token '{token_id}' reaches {len(answer['tools'])} tool(s) "
          f"through {len(answer['agents'])} agent(s).\n")

    for entry in answer["by_tool"]:
        effect = entry["effect"] or "?"
        print(f"  {entry['tool']}  ({effect})")
        for grant in entry["granted_by"]:
            if not grant["applies"]:
                # No resource type, or none this agent grants — a tool that touches
                # nothing policy has a name for, or a descriptor we no longer have.
                print(f"      via {grant['agent']}: no resource bound")
                continue
            for type_, allowed in sorted(grant["applies"].items()):
                shown = ", ".join(allowed) if allowed else "<nothing>"
                print(f"      via {grant['agent']}: {type_} {shown}")
        print()

    if len(answer["agents"]) > 1:
        print("Where two agents carry one tool, the call is attributed to the first of "
              "them whose\nscope admits the arguments — the order above. "
              "`--simulate` answers it for a given call.")

    if answer["invalid_agents"]:
        print(f"\n{len(answer['invalid_agents'])} granted agent(s) were skipped as "
              f"invalid: {', '.join(answer['invalid_agents'])}")

    print(f"\n{ceilings}")

    print("\nThis is the grant. Whether the token still works — revoked, expired, owner "
          "disabled\n— is `--list-tokens`.")


# The widest label `_simulate` prints, plus its colon — so the values line up.
_WIDTH = len("attributed to:")


def _simulate(parser, tenant_id: str, token_id: str, tool: str, raw_args) -> None:
    """`--simulate TOKEN --call NAME [--arg k=v ...]`: the verdict, without the call.

    The door's own `_granted_agents`, `_candidates` and `_adjudicate`, invoked without
    executing anything. It opens no session, resolves no credential, charges no budget
    and writes no row — see `door.simulate`, which carries the argument for the last of
    those.

    Values are strings, always. `permissions._identify` stringifies whatever it is given
    (`str(tool_input[arg])`) before the matcher sees it, so parsing `--arg limit=10` into
    an integer here would be this reader inventing a type the check does not have.
    """
    if not tool:
        parser.exit(2, "--simulate needs --call TOOL: the call to ask about.\n")

    arguments = {}
    for pair in raw_args or ():
        name, sep, value = pair.partition("=")
        if not sep or not name:
            parser.exit(2, f"--arg takes NAME=VALUE; got '{pair}'.\n")
        arguments[name] = value

    principal = _token_principal(parser, tenant_id, token_id)
    answer = door.simulate(principal, tool, arguments)

    verdict = "ALLOWED" if answer["verdict"] == "allowed" else "REFUSED"
    print(f"{verdict}  {tool}  for API token '{token_id}'")
    if arguments:
        print("  arguments: " + ", ".join(f"{k}={v}" for k, v in sorted(arguments.items())))
    print()

    # Padded to one width rather than each label to its own, so the values line up in a
    # column somebody can read down. `_WIDTH` is the longest label plus its colon.
    def line(label, value):
        print(f"  {label + ':':<{_WIDTH}} {value}")

    if answer["attributed_to"]:
        # Different words on a refusal, because "attributed to" beside a REFUSED reads as
        # *this is the one that let it through*. It is the agent the denial would be
        # **recorded** under, which is a different and less reassuring fact.
        line(
            "attributed to" if answer["verdict"] == "allowed" else "recorded under",
            answer["attributed_to"],
        )
    if answer["rule"]:
        line("rule", answer["rule"])
    if answer["reason"]:
        line("reason", answer["reason"])

    if answer["considered"]:
        print("\n  Every granted agent that carries this tool:")
        for candidate in answer["considered"]:
            mark = "allows" if candidate["allowed"] else "refuses"
            print(f"    {candidate['agent']} — {mark}")
            if candidate["reason"]:
                print(f"        {candidate['reason']}")

    print("\n  Not checked: " + ", ".join(answer["not_checked"]) + ".")
    print("  This is a permission answer. Nothing was called, nothing was dialled and "
          "no record\n  was written.")


def _list_tokens(tenant_id: str) -> None:
    """`--list-tokens`: what exists, and what happened to it.

    Revoked tokens are listed rather than filtered out. A revoked row that vanished
    would look like a token somebody deleted, and there is no delete — what the operator
    needs to see is that it existed, who owned it, and that it is closed.
    """
    rows = storage.active().list_api_tokens(tenant_id)

    if not rows:
        print(f"No API tokens in tenant '{tenant_id}'.")
        print("  Mint one with --mint-token NAME WHO.")
        return

    def when(value, absent):
        if value is None:
            return absent
        return (
            value.isoformat(timespec="seconds")
            if hasattr(value, "isoformat")
            else str(value)
        )

    print(f"{'id':22}{'name':20}{'owner':16}{'kind':10}{'state':28}last used")
    for row in rows:
        if row["revoked_at"]:
            state = f"revoked {when(row['revoked_at'], '')}"
        elif row["expires_at"]:
            state = f"expires {when(row['expires_at'], '')}"
        else:
            state = "live"
        # This column is also where an operator holding a `machine:m_...` string from
        # an old audit record reads the "via" half — the owner is derived from this
        # row at read time, never stored per record (step 033d's decided question).
        kind = "personal" if row["acts_as_owner"] else "service"
        print(
            f"{row['id'][:21]:22}{row['name'][:19]:20}{row['owner_id'][:15]:16}"
            f"{kind:10}{state[:27]:28}{when(row['last_used_at'], 'never')}"
        )

    print(
        "\nA service token's access is its grants; a personal token's is its owner's "
        "(capped at\nuser), live as the owner's changes. Either way a token whose "
        "owner is disabled is\nrefused, and every record it wrote names machine:<id> — "
        "this table is what resolves\nthat id to a name and an owner."
    )


# --- delegated credentials ---------------------------------------------------------


# --- people (071) ------------------------------------------------------------------


def _when(value, absent: str = "never") -> str:
    if value is None:
        return absent
    return value.isoformat(timespec="seconds") if hasattr(value, "isoformat") else str(value)


def _list_users(tenant_id: str) -> None:
    """`--list-users`: who is here, and whether they can get in.

    The row a provisioned person has before their first sign-in is the one worth
    showing: `signed in: never` with a subject of `-` is somebody the directory pushed
    who has not yet arrived, and the adoption that binds them (plan 071, decision 2)
    happens at that first arrival. A disabled row says `disabled`, which after this step
    is a state the CLI can put somebody into and out of.
    """
    rows = storage.active().list_users(tenant_id)
    if not rows:
        print(f"No users in tenant '{tenant_id}'. People are created at first sign-in.")
        return

    print(f"{'id':20}{'email':34}{'status':10}{'directory id':26}{'signed in':22}issuer")
    for row in rows:
        print(
            f"{row['id'][:19]:20}{(row.get('email') or '')[:33]:34}"
            f"{row['status']:10}{(row.get('external_id') or '-')[:25]:26}"
            f"{_when(row.get('last_seen_at'))[:21]:22}{row['issuer']}"
        )
    print(
        "\nA disabled person cannot sign in, and every token they own is refused at its "
        "next\ncall. --disable-user and --enable-user change it."
    )


def _set_user_active(parser, tenant_id: str, who: str, active: bool) -> None:
    """`--disable-user WHO` / `--enable-user WHO`, through the one offboarding seam.

    Idempotent, and it says what it did: disabling somebody already disabled writes no
    record and prints so.
    """
    target = _principal_for(
        parser,
        tenant_id,
        who,
        unresolved="Only somebody who exists can be disabled; --list-users shows who does.",
    )
    if target.kind != "user":
        parser.error(f"'{who}' is a {target.kind}, and only a person has a status to change.")

    before = storage.active().get_user(tenant_id, target.id)
    if before is None:
        parser.error(f"there is no user '{target.id}' in tenant '{tenant_id}'.")
    wanted = "active" if active else "disabled"
    if before["status"] == wanted:
        print(f"{target.id} ({before.get('email') or 'no address'}) is already {wanted}.")
        return

    try:
        users.set_active(_cli_principal(tenant_id), target.id, active, cause="--disable-user" if not active else "--enable-user")
    except users.UserRefused as exc:
        parser.error(str(exc))

    print(f"{target.id} ({before.get('email') or 'no address'}) is now {wanted}.")
    if not active:
        print(
            "  Their sign-in is refused from now, every API token they own is refused at "
            "its next call."
        )
        print(
            "  Their agents, grants, group memberships and connections are untouched — "
            "nothing they made is deleted."
        )


def _principal_for(parser, tenant_id: str, who: str, unresolved: str = "") -> Principal:
    """Turn what somebody typed into a principal.

    An **email address** — the thing a person knows about a colleague — or a principal
    id (`u_8f2c1a`, `system:nightly`) for what an address cannot name.

    Unlike sharing, an unresolvable address is refused rather than held, and the two
    callers refuse it for **different reasons** — so `unresolved` is a parameter rather
    than one sentence serving both. It was one sentence, about credentials, and
    `--group-add` inherited it: somebody adding a new hire to the support team was told
    there was "no principal to hold a credential for", which is a message that
    actively misinforms about what they were doing. Same class of bug as collapsing
    `NoAccess` and `ShareRefused`, found the same way — by running the command.
    """
    if "@" in who:
        found = storage.active().find_user_by_email(tenant_id, who)
        if found is None:
            parser.error(
                f"nobody in tenant '{tenant_id}' has logged in as '{who}'. "
                + (
                    unresolved
                    or "There is no principal to hold a credential for. A connection is "
                    "not an invitation — it cannot wait for somebody the way a share "
                    "can. Ask them to sign in once, then connect the account."
                )
            )
        return Principal.user(found["id"], tenant_id)

    kind, _, ident = who.rpartition(":")
    return Principal(kind=kind or "user", id=ident, tenant_id=tenant_id)


def _read_credential(parser: argparse.ArgumentParser, connector_id: str) -> str:
    """Take the credential from a hidden prompt, or from a pipe when there is no tty.

    **Never from argv.** A token on the command line lands in shell history, and is
    visible in the process table to anything on the box for as long as the command
    runs. This is the one command whose entire subject is a secret, so it is the one
    place that would matter most.

    Piped input is read as-is so the command scripts, which is the same reason it does
    not simply refuse when there is no terminal:

        echo "$TOKEN" | carnet --connect-account github-mcp priya@acme.com
    """
    if not sys.stdin.isatty():
        return sys.stdin.readline()

    try:
        return getpass.getpass(f"Paste the credential for '{connector_id}' (hidden): ")
    except (EOFError, KeyboardInterrupt):
        parser.error("no credential supplied; nothing was stored")


def _connect_account(parser, tenant_id: str, connector_id: str, who: str, label: str) -> None:
    """Store somebody's own credential for a connector.

    The connector is checked for existence here rather than in `access/connections.py`,
    which deals in opaque connector ids for the same reason `core/credentials.py` deals
    in opaque variable names. An entry point is the thing allowed to compose layers.
    """
    connector = mcp.get_connector(tenant_id, connector_id)
    if connector is None:
        known = ", ".join(c.id for c in mcp.connectors_for(tenant_id)) or "none vetted"
        parser.error(
            f"tenant '{tenant_id}' has no connector '{connector_id}'. Vetted: {known}."
        )

    principal = _principal_for(parser, tenant_id, who)
    credential = _read_credential(parser, connector_id)

    try:
        row = connections.connect_account(
            principal,
            connector_id,
            credential,
            account_label=label or "",
            # **The operator, not the person the credential is for**, and that asymmetry
            # is the whole reason 7b exists. `--connect-account` means somebody at a
            # shell obtained and saw this person's third-party token; a consent flow
            # means the person gave it to themselves and nobody else ever held it. The
            # administrative record is the only place that difference survives, so the
            # actor here is whoever ran the command.
            actor=str(_cli_principal(tenant_id)),
        )
    except connections.ConnectionRefused as exc:
        parser.error(str(exc))

    where = f" as {row['account_label']}" if row["account_label"] else ""
    print(f"Connected '{connector_id}' for {principal}{where}. Key {row['key_id']}.")

    # Named at the point somebody is doing the thing 7b replaces, because this command
    # is where an operator learns there is a better way. Only when there *is* one — a
    # connector with no consent flow configured has nothing to suggest.
    if storage.active().get_connector_oauth(tenant_id, connector_id) is not None:
        print(
            f"\nNote: '{connector_id}' has a consent flow configured, so this person "
            "could connect it themselves from the Connections page — without you "
            "holding their token. This pasted credential is stored as 'static' and "
            "keeps working; it is simply not the one they would have given themselves.",
            file=sys.stderr,
        )

    # A warning rather than a refusal, and the distinction is deliberate: the row is
    # legitimate and the *connector* is the problem, so refusing the write would leave
    # somebody unable to prepare for a transport change an administrator is making.
    # The run is where this is actually enforced — see mcp.check_delegation_supported.
    try:
        mcp.check_delegation_supported(connector)
    except mcp.DelegationUnsupported as exc:
        print(f"\nWARNING: this credential cannot be used yet.\n{exc}", file=sys.stderr)


# --- registering a connector ---------------------------------------------------------
#
# The four commands that make the product's premise true. Until this step a connector was
# a Python module and adding Jira to a customer's deployment was a change to our source
# and a release of our product; after it, it is a command their own engineer runs against
# their own deployment. That distance is covered without a single HTTP route.
#
# **CLI-only, and that is a chunk boundary rather than a limitation.** A vetting screen
# needs a tenant-admin role, which had blocked three things when this was written — group
# administration (9a), a read route for the administrative log (11), and this. Building
# the role here would have been 010's mistake in a new place: a platform-role model has
# its own questions (per tenant or per connector? who grants the first one? what does it
# mean in a deployment with one customer?) and answering them inside a vetting step gets
# both wrong.
#
# **12b answered them on purpose, so the wall is gone and the first two are through it.**
# The vetting screen is 12c's, which now has its prerequisite; these commands stay as
# they are until it arrives, because a screen is what was missing rather than a route.


def _recipe_or_exit(parser: argparse.ArgumentParser, recipe_id: str) -> dict:
    """One recipe by id, or a refusal that lists what this build ships. Step 068."""
    try:
        found = recipes.load(recipe_id)
    except recipes.RecipeRefused as exc:
        # A malformed file is this build's defect, not the operator's, and the sentence
        # names which file. Refusing here rather than half-applying it is the same
        # fail-closed choice `from_manifest` makes at load.
        parser.error(str(exc))
    if found is None:
        available = ", ".join(item["id"] for item in recipes.catalogue()) or "<none>"
        parser.error(
            f"no recipe '{recipe_id}' in this build. Available: {available}\n"
            "  Recipes are checked into the repository and reviewed like code — there "
            "is no registry to fetch one from, on purpose."
        )
    return found


def _staleness_warning(recipe: dict) -> str:
    """The sentence a recipe's `verified_on` earns, or `''`. Step 068, rule 4.

    We are not in the call path of a consent flow once the URL is handed over, so a
    vendor moving an endpoint is something we learn from a customer. There is no
    freshness to check — only a claim to stop making, which is what this says.
    """
    state = recipes.staleness(recipe)
    if state == "verified":
        return ""
    when = (
        f"last checked {recipe['verified_on']}"
        if state == "stale"
        else "never checked against the vendor"
    )
    return (
        f"WARNING: this recipe was {when}. Vendors move OAuth endpoints and rename "
        "scopes without telling anybody, so confirm these values against their "
        "documentation before you rely on them. Every one of them is yours to override."
    )


def _list_recipes() -> None:
    """The presets this build ships, and when each was last looked at."""
    found = recipes.catalogue()
    if not found:
        print("This build ships no connector recipes.")
        return

    print("Connector recipes in this build. A recipe fills a form and decides nothing:")
    print("it vets no tool, approves no host, and carries no client id or secret.\n")
    for recipe in found:
        state = recipes.staleness(recipe)
        stamp = {
            "verified": f"checked {recipe.get('verified_on')}",
            "stale": f"checked {recipe.get('verified_on')} — old",
            "unverified": "NOT CHECKED",
        }[state]
        print(f"  {recipe['id']:<22} {recipe['name']}")
        print(f"  {'':<22} {recipe['description']}")
        print(
            f"  {'':<22} {recipe['connector']['kind']}, "
            f"{'consent flow' if recipe.get('oauth') else 'shared credential'}, "
            f"{len(recipe.get('tools') or [])} proposed tool(s) — {stamp}"
        )
        print(f"  {'':<22} needs: {' '.join(h['host'] for h in recipe['hosts'])}")
        print()

    print("Use one:")
    print("  carnet --allow-host <each host above>       a separate act, deliberately")
    print("  carnet --add-connector <id> --from-recipe <recipe>")
    print("  carnet --set-oauth <id> --from-recipe <recipe> --client-id <yours>")
    print("  carnet --vet <id> --tool <name> ...         one tool at a time, as ever")


def _apply_connector_recipe(parser, args) -> dict:
    """A recipe's connector half as defaults under whatever flags were given.

    **The flag always wins**, and that is rule 1 in one line: a recipe is a default, not
    a dependency, so there is no value it supplies that an operator cannot override
    without editing this build. Returns the merged values rather than mutating `args`,
    so what came from where stays readable at the call site.
    """
    recipe = _recipe_or_exit(parser, args.from_recipe)
    preset = dict(recipe["connector"])
    preset.pop("connector_id", None)

    # `None` is *not supplied* for these three and a **real value** for the two
    # credential fields — an `x-api-key` vendor wants `--credential-prefix ''`, and 045c
    # established that `or None` anywhere on this path silently restores `Bearer `. So
    # the test is `is None` on the argument, never truthiness.
    merged = {
        "url": args.url or preset.get("url") or "",
        "kind": args.kind or preset.get("kind") or "http",
        "credential_env": args.credential_env or preset.get("credential_env") or "",
        # Deliberately NOT offered by a recipe (`recipes.CONNECTOR_FIELDS` has no such
        # key), for 068's own reason applied one field over: a checked-in file can carry
        # a vendor's endpoints and scopes, and it cannot know where in *your* vault your
        # token is. Typed by the administrator, at the moment `--credential-env` would
        # have been.
        "credential_ref": args.credential_ref or "",
        "credential_header": (
            args.credential_header
            if args.credential_header is not None
            else preset.get("credential_header")
        ),
        "credential_prefix": (
            args.credential_prefix
            if args.credential_prefix is not None
            else preset.get("credential_prefix")
        ),
        "description": args.description or preset.get("description") or "",
    }
    headers = dict(preset.get("headers") or {})
    headers.update(dict(_parse_header(parser, raw) for raw in args.header or ()))
    merged["headers"] = headers
    merged["_recipe"] = recipe
    return merged


def _tool_proposal(parser: argparse.ArgumentParser, args) -> dict:
    """One recipe's proposal for `--tool`, or a refusal listing what it does propose.

    Returns a plain dict, and every field of it is a **default under a flag** — the same
    rule the connector half follows. A recipe that proposes `effect: "read"` loses to
    `--effect write` without argument, because the effect is the vetter's judgment and a
    file in this repository is not the vetter.
    """
    recipe = _recipe_or_exit(parser, args.from_recipe)
    for tool in recipe.get("tools") or ():
        if tool["remote_name"] == args.tool:
            warning = _staleness_warning(recipe)
            if warning:
                print(warning + "\n", file=sys.stderr)
            return tool

    offered = ", ".join(t["remote_name"] for t in recipe.get("tools") or ())
    parser.error(
        f"recipe '{recipe['id']}' proposes nothing called '{args.tool}'.\n"
        + (
            f"  It proposes: {offered}"
            if offered
            else "  It proposes no tools at all — its connector's tools are discovered "
            "from the server, so there is nothing for it to pre-fill here."
        )
    )


def _add_connector(parser, tenant_id: str, connector_id: str, args) -> None:
    """Register a connector. Vets nothing, and says so.

    Ordering, because it is the whole reason this is one of four commands rather than a
    flag on another: migration 021's foreign key means a credential cannot be sealed
    against a connector that does not exist, and discovery needs a credential because no
    server lists its tools to an unauthenticated caller. So *connect, look, then decide
    whether to register* is not expressible, and the row has to come first.

    **A recipe changes what the flags default to and nothing else** (step 068). The call
    below is the same call with the same arguments; `--from-recipe` only decides what
    they hold when the operator did not say. Nothing about the row that lands, the actor
    on it, or the egress check in front of it is different, which is the property that
    makes a recipe-registered connector indistinguishable from a hand-registered one.
    """
    recipe = None
    if args.from_recipe:
        merged = _apply_connector_recipe(parser, args)
        recipe = merged.pop("_recipe")
    else:
        merged = {
            "url": args.url or "",
            "kind": args.kind or "http",
            "credential_env": args.credential_env or "",
            "credential_ref": args.credential_ref or "",
            "credential_header": args.credential_header,
            "credential_prefix": args.credential_prefix,
            "description": args.description or "",
            "headers": dict(_parse_header(parser, raw) for raw in args.header or ()),
        }

    if not merged["url"]:
        parser.error(f"--add-connector needs --url.\n{tools.STDIO_REFUSED}")

    if merged["credential_ref"]:
        # **Parsed here rather than in `register_connector`, and the reason is the
        # layering.** `core/vault` owns what an `op://` reference means and `tools/` may
        # not import `core/`, so the friendly refusal for a typo lives at the entry
        # points — this one and the admin route — while the load-bearing one lives at
        # the credential read. Same two-place shape as `config.is_platform_env`.
        try:
            vault.parse(merged["credential_ref"])
        except vault.VaultError as exc:
            parser.error(str(exc))

        # A warning and not a refusal, on `egress.approval_warning`'s reasoning: the row
        # is legitimate — somebody said where their credential lives — and the
        # deployment's vault is configured by a different person at a different time.
        # What must not happen is silence, which is how an operator concludes the
        # reference is live when the first call will refuse.
        if not vault.configured():
            print(
                "Note: this reference is recorded, but this deployment has no vault "
                "configured (CARNET_VAULT_URL, CARNET_VAULT_TOKEN in backend/.env), "
                "so every call to this connector will refuse until it has one.",
                file=sys.stderr,
            )

    if recipe is not None:
        warning = _staleness_warning(recipe)
        if warning:
            print(warning + "\n", file=sys.stderr)

    try:
        tools.register_connector(
            tenant_id,
            connector_id,
            url=merged["url"],
            kind=merged["kind"],
            credential_env=merged["credential_env"],
            credential_ref=merged["credential_ref"],
            # Passed through as given, `None` meaning *the launch's own default*. An
            # empty `--credential-prefix ''` is a real value and must survive: it is
            # what an `x-api-key` vendor wants, and `or None` here would silently
            # restore `Bearer `. Step 045c.
            credential_header=merged["credential_header"],
            credential_prefix=merged["credential_prefix"],
            headers=merged["headers"] or None,
            description=merged["description"],
            # Deliberately not settable from a recipe. Believing an asserted acting-for
            # is a posture a tenant adopts on purpose with the actor recorded, not a
            # default a vendor preset arrives holding — `recipes.CONNECTOR_FIELDS`.
            allow_asserted_identity=bool(args.allow_asserted_identity),
            from_recipe=recipe["id"] if recipe else "",
            actor=str(_cli_principal(tenant_id)),
        )
    except (
        tools.RegistrationRefused,
        mcp.EgressRefused,
        storage.ConnectorExistsError,
        storage.StorageError,
        RuntimeError,
    ) as exc:
        parser.error(str(exc))

    print(f"Registered '{connector_id}' at {merged['url']}. Nothing is vetted yet.")
    print("\nNext, in order:")
    if merged["credential_ref"]:
        # First, and before anything that would use it. A reference has more ways to be
        # wrong than a variable name has in total, and every one of them shows up as a
        # tool going unavailable in somebody else's assistant unless it is checked here.
        print(f"  carnet --check-credential {connector_id}")
        print(
            "      does the vault reference resolve? Never prints the value — and this "
            "is the"
        )
        print(
            "      one place the item's field labels are listed, because you can "
            "already read them."
        )
    if merged["kind"] == "rest":
        # No --discover step: a REST API does not describe itself, so vetting is
        # authoring — the schema, the mapping and the description are yours.
        print(
            f"  carnet --vet {connector_id} --tool <name> --effect read|write "
            "--method GET --path /... --schema '<json>' ..."
        )
        print(
            "      one tool at a time, with its authored schema and binding. A REST "
            "API does not"
        )
        print(
            "      describe itself, so there is no --discover; nothing it offers is "
            "reachable until vetted."
        )
    else:
        if merged["credential_env"]:
            print(f"  carnet --connect-account {connector_id} <who>")
            print("      a credential, because a server will not list its tools without one")
        print(f"  carnet --discover {connector_id}")
        print("      what it offers, and the argument names --resource needs")
        print(f"  carnet --vet {connector_id} --tool <name> --effect read|write ...")
        print("      one tool at a time. Nothing this connector offers is reachable until then.")

    _print_recipe_leftovers(recipe, connector_id)


def _print_recipe_leftovers(recipe, connector_id: str) -> None:
    """What a recipe proposed and did **not** do. Step 068.

    Printed because the two things a recipe deliberately refuses to do are exactly the
    two somebody will assume it did. Silence here is how an operator concludes a recipe
    with four proposed tools has approved four tools.
    """
    if recipe is None:
        return
    if recipe.get("oauth"):
        print(
            f"\n  carnet --set-oauth {connector_id} --from-recipe {recipe['id']} "
            "--client-id <yours>"
        )
        print(
            "      the consent flow. The client id and secret are YOURS — created in "
            "the vendor's own"
        )
        print(
            "      console — and are the two fields no recipe carries or ever will."
        )
    proposed = recipe.get("tools") or []
    if proposed:
        names = ", ".join(tool["remote_name"] for tool in proposed)
        print(
            f"\nThis recipe proposes {len(proposed)} tool(s) and has approved none of "
            f"them: {names}."
        )
        print(
            "Each still needs --vet, one at a time. A vendor proposing its own effect "
            "is the thing"
        )
        print("the review record exists to refuse.")


def _parse_header(parser, raw: str) -> tuple:
    """`NAME=VALUE`, for `--header`. Step 045c.

    Split on the **first** `=` only, because a header value may contain one and the
    name may not. Refused with an example rather than guessed at: a header that
    silently did not arrive is a vendor rejecting every call for a reason nothing in
    this deployment names.

    Non-secret by construction — this is `HttpLaunch.headers`, whose whole reason for
    being separate from the credential is that which of the two is the secret should be
    obvious at a glance. Nothing stops somebody typing a key here; what stops it being
    invisible is that this value is stored in the manifest in the clear and shown by
    `--list-connectors`, where a credential never is.
    """
    name, sep, value = raw.partition("=")
    if not sep or not name.strip():
        parser.error(
            f"--header '{raw}' is not NAME=VALUE. Example:\n"
            "  --header anthropic-version=2023-06-01"
        )
    return name.strip(), value


def _set_asserted_identity(parser, tenant_id: str, values: list) -> None:
    """Turn asserted acting-for on or off for one connector. Step 033c.

    `on|off` rather than a flag pair, so the command reads as the state it produces
    and the administrative record (`connector.asserted_identity`) can be written from
    exactly what was typed. What it gates: whether the MCP door believes an email a
    calling service *asserts* as who it acts for, for this server's tools. A verified
    acting-for — the person's own forwarded IdP token — needs no switch anywhere.
    """
    connector_id, state = values
    if state.lower() not in ("on", "off"):
        parser.error(
            f"--set-asserted-identity takes 'on' or 'off', not '{state}'. Asserted "
            "identity is trust in a calling application, and a state this "
            "consequential is spelled out rather than implied."
        )
    allowed = state.lower() == "on"

    try:
        tools.set_asserted_identity(
            tenant_id, connector_id, allowed, actor=str(_cli_principal(tenant_id))
        )
    except storage.StorageError as exc:
        parser.error(str(exc))

    if allowed:
        print(
            f"'{connector_id}' now believes asserted acting-for through the MCP door."
        )
        print(
            "  An asserted identity is exactly as honest as the calling application; "
            "the audit log keeps it apart from verified. Turn it back off:"
        )
        print(f"    carnet --set-asserted-identity {connector_id} off")
    else:
        print(
            f"'{connector_id}' no longer believes asserted acting-for; verified "
            "(a forwarded IdP token) still works."
        )


def _allow_host(parser, tenant_id: str, host: str, note: str) -> None:
    """Approve a host for this tenant. The decision that lets a row cause a connection.

    Warns — loudly, on stderr — when the host approved is one that will never be dialled
    whatever the allowlist says. Found by running the command: `--allow-host localhost`
    answered *"Tenant 'default' will now dial 'localhost'"*, which is false, and being
    told yes about a control that is not in force is the precise failure this whole
    module is written against.

    A **warning and not a refusal**, deliberately. The row is legitimate — it records
    that somebody approved a host — and the refusal belongs at dial time where it is
    load-bearing. It is also what lets `test_some_hosts_may_never_be_dialled_even_if_approved`
    approve each address before asserting that approving it changes nothing, which is the
    only way to assert *that* rather than merely that a name is refused.

    **The sentence itself is `egress.approval_warning`'s as of 12c**, because
    `POST /admin/hosts` has to say the same thing in a response body where there is no
    stderr to print to. This still decides *where* it goes, which is the half that is
    genuinely a fact about a terminal.
    """
    try:
        storage.active().allow_host(
            tenant_id, host, actor=str(_cli_principal(tenant_id)), note=note or ""
        )
    except storage.StorageError as exc:
        parser.error(str(exc))

    normalized = storage.normalize_host(host)
    warning = mcp.egress.approval_warning(normalized)
    if warning:
        print(warning, file=sys.stderr)
        return

    print(f"Tenant '{tenant_id}' will now dial '{normalized}'.")


def _revoke_host(parser, tenant_id: str, host: str) -> None:
    """Withdraw a host. Connectors registered against it stay, and stop connecting.

    Says so out loud, because the alternative reading — that revoking a host removed the
    connectors using it — is the one somebody will assume, and assuming it means
    believing a customer's Jira integration is gone when the row is still there waiting
    for the host to come back.
    """
    if not storage.active().revoke_host(
        tenant_id, host, actor=str(_cli_principal(tenant_id))
    ):
        print(f"Tenant '{tenant_id}' had not approved '{host}'. Nothing to do.")
        return

    print(f"Tenant '{tenant_id}' will no longer dial '{storage.normalize_host(host)}'.")

    # Any launch with a URL — HTTP MCP and REST alike (045a), the same predicate the
    # route uses, so the CLI and the API answer "what did this strand" identically.
    stranded = [
        connector.id
        for connector in mcp.connectors_for(tenant_id)
        if getattr(connector.launch, "url", "")
        and mcp.egress.host_of(connector.launch.url) == storage.normalize_host(host)
    ]
    if stranded:
        print(
            f"\n{len(stranded)} connector(s) point at it and were NOT removed: "
            f"{', '.join(stranded)}.",
            file=sys.stderr,
        )
        print(
            "They stay registered, keep their vetting, and will refuse to connect until "
            "the host is approved again. Deleting them here would destroy the record of "
            "which tools somebody approved, which is the one thing this schema goes out "
            "of its way to keep.",
            file=sys.stderr,
        )


def _list_hosts(tenant_id: str) -> None:
    rows = storage.active().allowed_hosts(tenant_id)
    if not rows:
        print(f"Tenant '{tenant_id}' has approved no hosts, so it can dial none.")
        print("An empty allowlist denies rather than permits — see --allow-host.")
        return

    print(f"\nTenant '{tenant_id}' will dial:\n")
    for row in rows:
        print(f"  {row['host']}")
        print(f"      approved by {row['allowed_by']} at {row['allowed_at']}")
        if row["note"]:
            print(f"      {row['note']}")
    print()


def _discover(parser, tenant_id: str, connector_id: str, who: str) -> None:
    """Connect, list, and print each tool **with its input schema**.

    The schema is the point. `mcp.connect()` has listed tools since step 003, so
    discovery adds almost no capability — what it adds is the only place a person can
    read the argument names that `--vet --resource TYPE=ARG` needs. Without it the flag
    is a guess that `validation.py` rejects at the first bind, and a command that printed
    names and descriptions would look complete while leaving the actual difficulty
    exactly where it was.

    Reads nothing from the manifest and writes nothing — except that it does compare, at
    the end, because an operator running `--discover` on a connector that has drifted
    needs to be told before they vet a tenth tool on top of nine that no longer bind.
    """
    connector = mcp.get_connector(tenant_id, connector_id)
    if connector is None:
        known = ", ".join(c.id for c in mcp.connectors_for(tenant_id)) or "none"
        parser.error(f"tenant '{tenant_id}' has no connector '{connector_id}'. Have: {known}.")

    # The remedy, not an empty success — STDIO_REFUSED's precedent (045a).
    if connector.transport_kind == mcp.RestLaunch.KIND:
        parser.error(
            f"'{connector_id}' is a REST API and does not describe itself; there is "
            "nothing to discover. Vet each tool with its authored schema and "
            "binding instead:\n"
            f"  carnet --vet {connector_id} --tool <name> --effect read|write "
            "--method GET --path /... --schema '<json>'"
        )

    credential = _discovery_credential(parser, tenant_id, connector, who)

    try:
        seen = mcp.discovery.discover(tenant_id, connector, credential)
    except (mcp.EgressRefused, mcp.TransportError) as exc:
        parser.error(str(exc))

    advertised = seen["tools"]
    vetted = {v.remote_name for v in connector.vetted}

    print(f"\n{mcp.discovery.server_label(seen['server'])}")
    print(f"{len(advertised)} tool(s) advertised, {len(vetted)} vetted\n")

    for tool in sorted(advertised, key=lambda t: t.get("name") or ""):
        name = tool.get("name") or "(unnamed)"
        mark = "vetted" if name in vetted else "      "
        print(f"  {mark}  {name}")

        description = (tool.get("description") or tool.get("title") or "").strip()
        if description:
            # One line. A server's description can run to paragraphs and this is a list
            # somebody is scanning; the full text is what `--vet` copies into the
            # catalogue, where there is room for it.
            first = description.splitlines()[0]
            print(f"          {first[:100]}{'…' if len(first) > 100 else ''}")

        for line in _schema_lines(tool.get("inputSchema") or {}):
            print(f"          {line}")
        print()

    findings = mcp.discovery.review(
        connector, advertised, _vetting_record(tenant_id)
    )
    if findings:
        print("Since this connector was vetted:\n")
        for finding in findings:
            print(f"  [{finding['severity']}] {finding['message']}\n")

    # Step 095: the block to paste under this connector in a carnet.yaml. Printed for
    # every store, not only a fileborne one — the block is a true description of what
    # the server advertises either way, and a person on the platform artefact may be
    # writing a file for the other one.
    print(f"To declare these in a carnet.yaml, under connectors.{connector_id}:\n")
    print(carnetfile.tools_block(advertised))
    print()


def _schema_lines(schema: dict) -> list[str]:
    """A tool's arguments, one line each. **The reason `--discover` exists.**

    Types and requiredness, because `--resource jira.project=projectKey` needs the exact
    argument name and a person deciding whether a tool is scopeable needs to know which
    arguments are optional — an optional argument that widens reach when absent is the
    case `connectors/github.py` documents at length for `list_issue_fields`, and it is
    invisible without this line.
    """
    properties = schema.get("properties") or {}
    if not properties:
        return ["(takes no arguments)"]

    required = set(schema.get("required") or ())
    lines = []
    for name in sorted(properties):
        spec = properties[name] if isinstance(properties[name], dict) else {}
        kind = spec.get("type") or "any"
        if isinstance(kind, list):
            kind = "|".join(str(k) for k in kind)
        flag = "required" if name in required else "optional"
        lines.append(f"{name} ({kind}, {flag})")
    return lines


def _vetting_record(tenant_id: str) -> dict:
    return {
        (row["connector_id"], row["remote_name"]): row
        for row in storage.active().load_vetting_record(tenant_id)
    }


def _discovery_credential(parser, tenant_id: str, connector, who: str) -> str | None:
    """The credential to discover with, or None.

    Taken from a **stored connection** rather than prompted for, which is decision 4's
    ordering paying off: `--add-connector` created the row, `--connect-account` sealed a
    credential against it, and this reads that back. Prompting again would mean a second
    copy of a secret on a second command line for no gain.

    None is legal and not an error: an unauthenticated MCP server is a real thing, and
    the shipped GitHub read path ran against one for a while. If the server wants auth it
    will say so, and its refusal is a better message than any guess this function could
    make about whether one was needed.
    """
    principal = (
        _principal_for(parser, tenant_id, who) if who else _cli_principal(tenant_id)
    )

    # `env_var` off the manifest, exactly as `runtimes/__init__.py` passes it. This is
    # `for_discovery`, not `for_connector`: discovery happens before vetting, so there
    # is no identity to consult, and the caller's own sealed credential — the one
    # `--connect-account` wrote for exactly this — is the right one to look with.
    env_var = getattr(connector.launch, "credential_env", None)
    ref = getattr(connector.launch, "credential_ref", None)

    try:
        credential = credentials.for_discovery(connector.id, principal, env_var, ref)
    except credentials.CredentialError as exc:
        # Raised for a row that exists and will not decrypt, or one that has expired.
        # Not swallowed: a credential that is *broken* is a different situation from one
        # that is *absent*, and discovering anonymously because somebody's token expired
        # would produce a tool list that does not match what their runs can see.
        parser.error(str(exc))

    return credential.value if credential is not None else None


def _check_credential(parser, tenant_id: str, connector_id: str) -> None:
    """Does this connector's credential resolve? **Never prints the value.** Step 070.

    An administrator who writes an `op://` reference should be able to find out that it
    works before an agent finds out for them, and the agent's version of that answer is a
    tool going unavailable in somebody else's assistant.

    **The length is printed and the value is not**, which is a decision rather than a
    compromise. The question this command is actually asked is *did I point at the right
    field*, and a 93-character answer where a token is 40 says *you got the note* without
    saying anything anybody could use. A command that printed only `yes` could not answer
    it, and one that printed the secret would put it in a shell history and a scrollback
    for the sake of a question a number answers.

    It also lists the item's **field labels** when the field is missing — which
    `core/vault`'s refusals deliberately do not, because those reach the model through
    the door. Here the audience is somebody at a shell who can already open the vault, so
    the structure of it is not a secret being disclosed; it is the answer.
    """
    connector = mcp.get_connector(tenant_id, connector_id)
    if connector is None:
        parser.error(
            f"there is no connector '{connector_id}' in this customer. "
            "`carnet --list-connectors` says which there are."
        )

    env_var = getattr(connector.launch, "credential_env", None)
    ref = getattr(connector.launch, "credential_ref", None)

    if not ref:
        # Answered rather than refused: "this connector's credential is not a reference"
        # is a real answer to the question, and the shape of the other two is worth
        # printing so nobody wonders whether the command looked.
        print(f"{connector_id}  credential: " + ("environment variable" if env_var else "none"))
        if env_var:
            print(f"  variable  {env_var}")
            print(
                "  set       "
                + ("yes" if os.environ.get(env_var) else "no — not in this process")
            )
        else:
            print("  This connector presents no credential. A server that wants one "
                  "will answer 401.")
        print(
            "\n  Nothing to resolve: --check-credential dials a vault, and this "
            "credential is not held in one."
        )
        return

    print(f"{connector_id}  credential: reference")
    print(f"  reference {ref}")
    print(f"  vault     {_config.VAULT_URL or '(CARNET_VAULT_URL is not set)'}")

    try:
        pointer = vault.parse(ref)
        secret = vault.resolve(pointer)
    except vault.VaultError as exc:
        print(f"  resolved  no — {exc.reason}\n")
        print(str(exc))
        if exc.reason in (vault.NO_FIELD, vault.AMBIGUOUS):
            # The half `resolve`'s refusal deliberately withholds, printed here because
            # the audience changed.
            try:
                labels = vault.describe_fields(vault.parse(ref))
            except vault.VaultError:
                labels = []
            if labels:
                # `section/label` where a field is in one, which is exactly the shape a
                # four-segment reference is written in — so the answer to *which do I
                # name?* is the string printed here.
                print(
                    "\n  The item does carry: " + ", ".join(sorted(labels))
                    + "\n  (labels only — no value is printed, and none was read. A "
                    "field shown as 'Section/name' is\n   named in a reference as "
                    "op://<vault>/<item>/Section/name.)"
                )
        raise SystemExit(1) from exc

    print(f"  resolved  yes — {len(secret)} characters (the value is not printed)")


def _parse_resource(parser, raw: str):
    """`--resource TYPE=ARG`, or `--resource TYPE={a}/{b}:a,b` for the composed case.

    Ugly, and the composed case is rare enough that ugly-and-explicit beats clever. The
    single-argument form is what almost every tool needs and reads fine; the second form
    exists because GitHub's API splits a repo across `owner` and `repo`, so a descriptor
    that could only name one argument could not scope the one connector this repo ships.

    Parsed here rather than in `tools/` because it is a *command-line* spelling of a
    `Resource`, and `Resource` itself must not learn one — the moment it does, an HTTP
    route ends up accepting the same string.
    """
    resource_type, sep, rest = raw.partition("=")
    if not sep or not resource_type or not rest:
        parser.error(
            f"--resource '{raw}' is not TYPE=ARG. Examples:\n"
            "  --resource jira.project=projectKey\n"
            "  --resource github.repo={owner}/{repo}:owner,repo"
        )

    template, marker, args = rest.rpartition(":")
    if not marker:
        # The single-argument form. The argument's value IS the identifier, which is
        # what `template=None` means to `Resource.compose`.
        return Resource(resource_type, rest)

    names = tuple(name.strip() for name in args.split(",") if name.strip())
    if not names:
        parser.error(f"--resource '{raw}' names no arguments after the ':'")
    return Resource(resource_type, names, template=template)


def _with_families(parser, resources: tuple, raw_families) -> tuple:
    """Apply `--resource-family TYPE=a,b,c` to resources already parsed. Step 086.

    A separate flag rather than a third colon-delimited field on `--resource`, whose own
    docstring already calls its spelling ugly-and-explicit: a fourth field would make it
    ugly-and-ambiguous, and the composed form already ends in `:a,b`.

    Keyed by resource **type** rather than by position, because that is what the vetter
    is thinking about — `--resource-family anthropic.model=opus,sonnet,haiku` reads as
    the sentence it is — and because a tool declaring two resources of the same type
    (`copy_issue(from_repo, to_repo)`) wants both to answer to the same vocabulary.

    A family named for a type no `--resource` declared is a **refusal, not a shrug**: it
    is a vocabulary that would be silently dropped, and the scope line written against
    it would then refuse every call with no way to see why.
    """
    if not raw_families:
        return resources

    wanted: dict = {}
    for raw in raw_families:
        resource_type, sep, names = raw.partition("=")
        if not sep or not resource_type or not names.strip():
            parser.error(
                f"--resource-family '{raw}' is not TYPE=A,B,C. Example:\n"
                "  --resource-family anthropic.model=opus,sonnet,haiku"
            )
        named = [name.strip() for name in names.split(",") if name.strip()]
        if not named:
            # `--resource-family openai.model=,,,` parses, stores nothing, and reads as
            # applied — the failure this codebase refuses everywhere, and the vetter
            # would only find out when a family scope they then wrote refused every
            # call. `names.strip()` above catches the empty right-hand side and cannot
            # catch this one. Found by driving the flag in step 086's edge pass.
            parser.error(
                f"--resource-family '{raw}' names no families. A family is the piece of "
                "a model id a scope line may say instead of a dated one — "
                "'opus', 'gpt-5' — and an empty list is a flag that reads as applied "
                "and is not."
            )
        wanted.setdefault(resource_type, [])
        wanted[resource_type].extend(named)

    declared = {ref.type for ref in resources}
    for resource_type in wanted:
        if resource_type not in declared:
            listed = ", ".join(sorted(declared)) or "<none>"
            parser.error(
                f"--resource-family names '{resource_type}', which no --resource "
                f"declares. Declared: {listed}. A family on a type this tool does not "
                "touch is a vocabulary nothing would ever derive, and a scope line "
                "using it would refuse every call."
            )

    return tuple(
        replace(ref, families=tuple(wanted[ref.type])) if ref.type in wanted else ref
        for ref in resources
    )


def _vet(parser, tenant_id: str, args) -> None:
    """Approve one tool, appended.

    **One at a time, and appended**, which is decision 4's other half. `save_connector`
    replaces the allowlist wholesale — correct for `--seed`, and data loss here: an admin
    who has approved nine tools and is looking at the tenth must not lose nine by getting
    the command wrong. `storage.vet_tool` moves exactly one row.
    """
    if not args.tool:
        parser.error("--vet needs --tool, the name the server advertises")

    # Step 068. A recipe may *propose* a tool: its effect, its resources, its redactions
    # and — the part that saves real typing — a REST binding, which is otherwise seven
    # flags including a JSON schema. **This is still one command per tool run by a
    # person, and `--effect` is still the person's**: there is no `--vet-all` and adding
    # one would undo 012's judgment. What a proposal removes is retyping, not deciding.
    proposal = _tool_proposal(parser, args) if args.from_recipe else {}
    # A flag, then a recipe's proposal, then the default this flag always had. The
    # ordering is the whole rule: a file in this repository is not the vetter, but it is
    # a better answer than a default nobody chose.
    effect = args.effect or proposal.get("effect") or "read"
    if effect not in tools.VALID_EFFECTS:
        parser.error(f"--effect must be one of {sorted(tools.VALID_EFFECTS)}")

    resources = tuple(_parse_resource(parser, raw) for raw in args.resource or ())
    if not resources and proposal.get("resources"):
        resources = tuple(
            Resource(
                type=ref["type"],
                args=tuple(ref["args"]),
                template=ref.get("template"),
                families=tuple(ref.get("families") or ()),
            )
            for ref in proposal["resources"]
        )
    resources = _with_families(parser, resources, args.resource_family or ())

    connector = mcp.get_connector(tenant_id, args.vet)
    if connector is None:
        parser.error(
            storage.NO_SUCH_CONNECTOR_TO_VET.format(connector=args.vet, tenant=tenant_id)
        )

    # Step 045a: on a REST connector the vetting is authoring — the binding comes
    # from the flags and no server is consulted, so no credential is read either
    # (a person whose stored connection expired must still be able to vet). On an
    # MCP connector the REST flags are refused with the reason, not dropped.
    is_rest = connector.transport_kind == mcp.RestLaunch.KIND
    rest_flags = [
        flag
        for flag, value in (
            ("--method", args.method),
            ("--path", args.path),
            ("--schema", args.schema),
            ("--query", args.query),
            ("--body", args.body),
            ("--usage-map", args.usage_map),
            ("--pricing", args.pricing),
            ("--tool-description", args.tool_description),
        )
        if value
    ]
    if proposal.get("binding") and not is_rest:
        parser.error(
            f"recipe '{args.from_recipe}' proposes a REST binding for '{args.tool}', and "
            f"'{args.vet}' is an MCP server. A binding is what discovery would have "
            f"supplied; an MCP server supplies it itself."
        )
    if not is_rest and rest_flags:
        parser.error(
            f"{', '.join(rest_flags)} describe a REST request, and '{args.vet}' is "
            "an MCP server: its schemas are discovered and its descriptions are "
            "copied from the advertisement, so an authored binding has no meaning "
            "there. Those flags belong to connectors registered with --kind rest."
        )
    if is_rest and proposal.get("binding") and not args.method:
        # The whole proposal, or none of it. A binding half from a recipe and half from
        # flags is a request shape nobody wrote down, and `check_binding`'s refusals
        # would then be about a combination that exists in neither place.
        binding = dict(proposal["binding"])
    else:
        binding = _rest_binding_from_args(parser, args) if is_rest else None

    try:
        recorded = tools.vet_tool(
            tenant_id,
            args.vet,
            args.tool,
            effect=effect,
            identity=args.identity or proposal.get("identity") or "service",
            resources=resources,
            note=args.note or proposal.get("note") or "",
            local_name=args.local_name,
            # The recipe's cap under the flag, like every other proposal field. Step 108
            # found this one falling through: the Azure recipe proposes 4 MiB for a chat
            # completion and the default 64 KiB cut every long answer off.
            max_response_bytes=(
                args.max_response_bytes
                if args.max_response_bytes is not None
                else proposal.get("max_response_bytes")
            ),
            actor=str(_cli_principal(tenant_id)),
            credential=None
            if is_rest
            else _discovery_credential(parser, tenant_id, connector, args.who or ""),
            binding=binding,
            description=args.tool_description or proposal.get("description") or "",
            # Not a REST-only flag: an MCP tool whose argument is somebody's free text
            # has exactly the same problem, and `validate` checks the names against
            # whichever schema this connector kind has. Step 045c.
            redact_args=tuple(args.redact_arg or proposal.get("redact_args") or ()),
        )
    except (
        tools.RegistrationRefused,
        mcp.EgressRefused,
        mcp.TransportError,
        storage.StorageError,
        RuntimeError,
    ) as exc:
        parser.error(str(exc))

    scoped = ", ".join(recorded["resources"]) or "nothing scoped"
    print(
        f"\nvetted {recorded['local_name']}  {recorded['effect']}  "
        f"as-{recorded['identity']}  {scoped}  (upstream: {recorded['remote_name']})"
    )
    if recorded["server"]:
        print(f"against {recorded['server']}, by {recorded['actor']}")
    else:
        # A REST vetting consulted nothing — the schema and binding are the
        # vetter's words, and the record says so rather than inventing a server.
        print(f"authored, no server consulted, by {recorded['actor']}")
    print("\nIt is in the catalogue now: carnet --list-tools")


def _rest_binding_from_args(parser, args) -> dict:
    """The request binding, from the vetting flags. The CLI's spelling of what
    `RestBindingSpec` is over HTTP — `_parse_resource`'s rule, applied again: the
    command-line shape stays here, and `tools/rest` never learns one."""
    missing = [
        flag
        for flag, value in (
            ("--method", args.method),
            ("--path", args.path),
            ("--schema", args.schema),
        )
        if not value
    ]
    if missing:
        parser.error(
            f"--vet on a REST connector needs {', '.join(missing)}. A REST API "
            "does not describe itself, so the method, the path template and the "
            "input schema are authored here — they are what discovery would have "
            "supplied."
        )

    return {
        "method": args.method,
        "path": args.path,
        "query": list(args.query or ()),
        "body": list(args.body or ()),
        "input_schema": _json_flag(parser, "--schema", args.schema),
        "usage_map": _json_flag(parser, "--usage-map", args.usage_map)
        if args.usage_map
        else None,
        # Step 086, spelled exactly like `usage_map` above: `None` when it was not
        # given rather than absent, because `normalize_vetted_tool` fills every binding
        # key so a binding written by `--vet` and one written wholesale compare equal
        # after either store's round trip. A second absent-spelling would break that.
        "pricing": _json_flag(parser, "--pricing", args.pricing)
        if args.pricing
        else None,
    }


def _json_flag(parser, flag: str, value: str):
    """Inline JSON, or a path to a JSON file — `--schema`'s two spellings.

    Inline when it reads as JSON (starts with `{`), a file otherwise, because a
    schema of any size belongs in a file and a small one belongs on the line.
    """
    text = value.strip()
    if not text.startswith("{"):
        try:
            text = Path(value).read_text()
        except OSError as exc:
            parser.error(
                f"{flag} '{value}' is neither inline JSON (it does not start with "
                f"'{{') nor a readable file: {exc}"
            )
    try:
        return json.loads(text)
    except ValueError as exc:
        parser.error(f"{flag} is not valid JSON: {exc}")


def _disconnect_account(parser, tenant_id: str, connector_id: str, who: str) -> None:
    principal = _principal_for(parser, tenant_id, who)

    # Through `oauth.disconnect` rather than `connections.disconnect_account`, so the CLI
    # and the route do the same thing: revoke upstream where there is somewhere to revoke
    # to, then delete either way. A CLI that only deleted would leave a live token at the
    # provider for exactly the connections an operator is most likely to be tidying up.
    outcome = oauth.disconnect(
        principal, connector_id, actor=str(_cli_principal(tenant_id))
    )

    if not outcome["disconnected"]:
        print(f"{principal} had no connection to '{connector_id}'. Nothing to do.")
        return

    print(f"Disconnected '{connector_id}' for {principal}.")

    revoked = outcome["revoked_upstream"]
    if revoked is True:
        print("The token was revoked at the provider.", file=sys.stderr)
    elif revoked is False:
        # Reported rather than swallowed — decision 12. The delete happened regardless,
        # which is the half that matters to the person; this is the half that matters to
        # whoever asks later whether that token is still live.
        print(
            "WARNING: the provider could not be told to revoke this token, so it may "
            "still be live upstream. The local credential is gone either way, and the "
            "administrative log records that revocation failed.",
            file=sys.stderr,
        )

    print(
        "A run already holding the credential is unaffected — the fetch happened "
        "at the tool call.",
        file=sys.stderr,
    )


def _set_oauth(parser, tenant_id: str, connector_id: str, args) -> None:
    """Configure a connector's consent flow. The one administrative half of 7b.

    **Refused on a stdio connector, at the moment of configuring rather than at the first
    run.** `check_delegation_supported` already refuses a delegated credential on a
    transport that cannot hold one; an OAuth flow whose entire output *is* a per-user
    credential is the same refusal one step earlier. Leaving it to the run would let an
    administrator finish setting this up, and a person complete a consent screen at a
    third party, for a credential that could never be used — and the person would find
    out after granting access.

    Post-012 a customer-registered connector is HTTP-only anyway, so this only bites on
    the ones this repository ships. Which is exactly where a confusing half-configured
    state would otherwise live.

    **That refusal, and the connector-exists refusal beside it, are no longer written
    here.** 12c gave `oauth.configure` a second caller and both checks moved down into it
    — see `oauth.STDIO_CONSENT_REFUSED`. What this command lost is one thing worth naming:
    the check used to run *before* `_read_secret`, so a stdio connector was refused
    without anybody being prompted, and now the prompt comes first and the refusal after.
    That is a worse ten seconds and a better rule. The secret went into a hidden prompt,
    was never stored, never logged and never in argv, so the cost is annoyance rather than
    exposure — and the alternative is two copies of one rule, which is the failure the
    move exists to prevent.
    """
    recipe = _recipe_or_exit(parser, args.from_recipe) if args.from_recipe else None
    preset = dict((recipe or {}).get("oauth") or {})
    if recipe is not None and not preset:
        parser.error(
            f"recipe '{recipe['id']}' has no consent flow — it is registered with a "
            f"shared credential (--credential-env). There is nothing for --set-oauth to "
            f"take from it."
        )

    authorize, token = _endpoints(parser, args, preset)

    if not args.client_id:
        parser.error(
            "--set-oauth needs --client-id, the OAuth application's public id"
            + (
                "\n  A recipe carries the endpoints and the scopes and never this: the "
                "OAuth application is yours, created in the vendor's own console, and a "
                "client id in this repository would be one deployment's identity shared "
                "by every other."
                if recipe is not None
                else ""
            )
        )

    if recipe is not None:
        warning = _staleness_warning(recipe)
        if warning:
            print(warning + "\n", file=sys.stderr)

    extra = dict(preset.get("authorize_params") or {})
    for raw in args.authorize_param or ():
        name, sep, value = raw.partition("=")
        if not sep or not name.strip():
            parser.error(
                f"--authorize-param '{raw}' is not NAME=VALUE. Example:\n"
                "  --authorize-param audience=api.atlassian.com"
            )
        extra[name.strip()] = value

    secret = _read_secret(parser, connector_id)

    try:
        row = oauth.configure(
            tenant_id,
            connector_id,
            authorize_endpoint=authorize,
            token_endpoint=token,
            revoke_endpoint=args.revoke_endpoint or preset.get("revoke_endpoint") or "",
            client_id=args.client_id,
            client_secret=secret,
            scopes=tuple(args.scope or preset.get("scopes") or ()),
            authorize_params=extra,
            # **A recipe's notes narrow with the scopes; a typed mismatch is an error.**
            #
            # `normalize_scope_notes` refuses a note for a scope this flow does not
            # request, which is right: it would describe a permission nobody is granting,
            # on the screen where somebody decides whether to grant it. But applying that
            # to a *preset* made `--scope read:jira-work` against a two-scope recipe fail
            # with a refusal about a file the operator did not write — and narrowing the
            # scopes is exactly what somebody wanting read-only access would do.
            #
            # Filtering is not inventing. It drops descriptions of permissions no longer
            # being asked for, which is what the rule wants rather than something it
            # forbids. An explicit `--scope-notes` is passed through unfiltered, because
            # there the operator typed both halves and a mismatch is their typo to see.
            scope_notes=(
                _json_flag(parser, "--scope-notes", args.scope_notes)
                if args.scope_notes
                else {
                    scope: note
                    for scope, note in (preset.get("scope_notes") or {}).items()
                    if scope in set(args.scope or preset.get("scopes") or ())
                }
            ),
            actor=str(_cli_principal(tenant_id)),
        )
    except (oauth.OAuthRefused, mcp.EgressRefused, storage.StorageError) as exc:
        parser.error(str(exc))

    print(f"Consent flow configured for '{connector_id}'.")
    print(f"  authorize  {row['authorize_endpoint']}")
    print(f"  token      {row['token_endpoint']}")
    print(f"  scopes     {' '.join(row['scopes']) or '<none requested>'}")
    # Migration 051. Printed per scope rather than as a count, because the whole point of
    # the column is that a scope string is not a sentence — and an operator who cannot see
    # what will be shown at the consent screen cannot tell whether it is right.
    for scope in row["scopes"]:
        note = (row.get("scope_notes") or {}).get(scope)
        if note:
            print(f"    {scope}  {note['name']} ({note['access']})")
        else:
            print(f"    {scope}  <no description — the consent screen shows the scope>")
    if row["authorize_params"]:
        shown = " ".join(f"{k}={v}" for k, v in row["authorize_params"].items())
        print(f"  also sends {shown}")
    if not row["revoke_endpoint"]:
        print(
            "  revoke     <none> — disconnecting will delete locally and leave the "
            "token live at the provider"
        )

    # The one real onboarding ask in this step, and it is stated where somebody is
    # standing when they have to do it. Same value for every connector on a deployment,
    # so it is registered once per provider rather than once per connector.
    print(
        f"\nRegister this redirect URI at the provider, exactly:\n  {_redirect_uri()}"
    )
    if not any("offline" in scope for scope in row["scopes"]):
        # A warning rather than a refusal, on `--allow-host localhost`'s precedent: the
        # configuration is legitimate, every provider spells this differently, and
        # refusing on a guess about a vendor's vocabulary would block a correct setup.
        print(
            "\nWARNING: no scope here looks like offline access, so this provider may "
            "issue no refresh token. The connection would then work until the access "
            "token expires — about an hour — and ask the person to connect again.",
            file=sys.stderr,
        )

    print("\nPeople can now connect this themselves from the Connections page.")


def _endpoints(parser, args, preset=None) -> tuple[str, str]:
    """The authorize and token endpoints, from `--auth-server`, a recipe, or stated.

    `--auth-server` guesses `/authorize` and `/token`, which is what Atlassian, Okta,
    GitHub and Google all happen to use — and the explicit flags exist because "happens
    to" is not a standard. RFC 8414 metadata discovery would answer this properly and is
    deferred with DCR; until then, a guess that is usually right plus an override that is
    always right beats a required pair of URLs somebody has to go and find.

    **A recipe states both endpoints and never leans on that guess** (step 068). The
    guess is right for somebody at a shell with the vendor's documentation open, who will
    notice a 404 at the token exchange and fix it in the next command. It is wrong to
    freeze into a checked-in preset, which is read by somebody who has *not* opened the
    documentation — and a guessed token endpoint that quietly 404s is precisely what a
    recipe's human verification exists to catch before a customer does.

    Precedence is flags, then the recipe, then `--auth-server`'s guess: the guess is last
    because it is the only one of the three that nobody wrote down on purpose.
    """
    preset = preset or {}
    authorize = args.authorize_endpoint or preset.get("authorize_endpoint") or ""
    token = args.token_endpoint or preset.get("token_endpoint") or ""

    if args.auth_server:
        base = args.auth_server.rstrip("/")
        authorize = authorize or f"{base}/authorize"
        token = token or f"{base}/token"

    if not authorize or not token:
        parser.error(
            "--set-oauth needs --auth-server, or both --authorize-endpoint and "
            "--token-endpoint"
        )
    return authorize, token


def _read_secret(parser: argparse.ArgumentParser, connector_id: str) -> str:
    """The client secret, from a hidden prompt or a pipe. **Never from argv.**

    `_read_credential`'s twin and the same argument, one blast radius wider: a per-user
    token in shell history compromises one person, and a client secret in shell history
    compromises the consent flow for everybody in the tenant.
    """
    if not sys.stdin.isatty():
        return sys.stdin.readline()
    try:
        return getpass.getpass(
            f"Paste the OAuth client secret for '{connector_id}' (hidden): "
        )
    except (EOFError, KeyboardInterrupt):
        parser.error("no client secret supplied; nothing was stored")


def _redirect_uri() -> str:
    from .api.routes_connections import CALLBACK_PATH

    return f"{PUBLIC_ORIGIN.rstrip('/')}{CALLBACK_PATH}"


def _clear_oauth(tenant_id: str, connector_id: str) -> None:
    if oauth.unconfigure(tenant_id, connector_id, actor=str(_cli_principal(tenant_id))):
        print(f"Removed the consent flow for '{connector_id}'.")
        # Said out loud because the alternative — cascading to the credentials — is what
        # somebody will assume happened, and migration 021's argument is why it does not:
        # destroying evidence that people consented, as a side effect of an
        # administrative action about configuration.
        print(
            "Credentials people already connected are untouched and keep working. What "
            "they cannot do is renew, so each will ask to be reconnected when its access "
            "token expires — and there will be nothing to reconnect with until a consent "
            "flow is configured again.",
            file=sys.stderr,
        )
    else:
        print(f"'{connector_id}' had no consent flow. Nothing to do.")


def _list_connections(tenant_id: str) -> None:
    """Who is connected, and as whom. Metadata only; storage cannot return the secret."""
    rows = connections.list_accounts(tenant_id)
    if not rows:
        print(
            f"No connected accounts in tenant '{tenant_id}'. Every call goes out under a "
            "connector's shared credential, where it has one."
        )
        return

    # **`changed`, not `connected` — 035f.** The column prints `updated_at`, which a
    # refresh bumps, so it has not meant "connected" since the first renewal; migration
    # 013 added it for exactly the other question (*"when did this last change"*) and kept
    # `created_at` distinct on purpose. The value was always right and the label was a
    # live mislabel, found when the Connections page needed a word for the same field —
    # and the browser and the shell must not develop two opinions about what a stamp says.
    print(f"{'principal':34}{'connector':18}{'account':24}{'how':8}{'key':10}changed")
    for row in rows:
        who = f"{row['principal_kind']}:{row['principal_id']}"
        label = row["account_label"] or "<unlabelled>"
        expiry = "" if row["expires_at"] is None else f"  expires {row['expires_at']:%Y-%m-%d}"
        print(
            f"{who:34}{row['connector_id']:18}{label:24}"
            # `how` is 7b's column, and it is the one an operator most wants: a `static`
            # row is a token somebody pasted in — which means an operator saw it — and an
            # `oauth` row is one nobody but the person and the provider has ever held.
            # That distinction is the whole step, and a listing that could not show it
            # would make the improvement invisible in the one place people look.
            f"{row['credential_kind']:8}{row['key_id']:10}"
            f"{row['updated_at']:%Y-%m-%d}{expiry}"
        )

    # After the table rather than beside each row, because it is a call to action and a
    # per-row marker would be noise on a healthy deployment.
    stale = [row for row in rows if row["reconsent_reason"]]
    for row in stale:
        print(
            f"\n{row['principal_kind']}:{row['principal_id']} → {row['connector_id']} "
            f"needs reconnecting: {row['reconsent_reason']}",
            file=sys.stderr,
        )


def _list_idps(tenant_id: str | None) -> None:
    """Every registered provider, or one customer's."""
    store = storage.active()
    tenants = [tenant_id] if tenant_id else [t["id"] for t in store.list_tenants()]

    rows = [(t, idp) for t in tenants for idp in store.list_tenant_idps(t)]
    if not rows:
        print("No identity providers registered.")
        return

    print(f"{'tenant':20}{'issuer':50}{'routes on':20}{'groups claim':16}domains")
    for tenant, idp in rows:
        routes = (
            f"{idp['discriminator_claim']}={idp['discriminator_value']}"
            if idp["discriminator_claim"]
            else "(whole issuer)"
        )
        domains = ", ".join(idp["allowed_domains"]) or "<none>"
        # Step 033e, and the column that answers *is this customer's membership coming
        # from their directory or from --group-add*. Beside the routing rather than
        # under it, because both are questions about one row's claims.
        claim = idp["groups_claim"] or "<none>"
        print(f"{tenant:20}{idp['issuer']:50}{routes:20}{claim:16}{domains}")


def main() -> None:
    # Model output is arbitrary text and routinely contains emoji; a Windows console
    # defaults to cp1252 and raises on the first one. Crashing after a run has already
    # made its tool calls loses the answer to a display problem.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(prog="carnet", description=__doc__)
    # First, because "what am I running" is the question somebody asks before any
    # other one — and because until 027 the version sat in a manifest nothing read.
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="print the version and exit",
    )
    parser.add_argument("--list", action="store_true", help="list agents and exit")
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="list every tool this tenant may grant, with its effect, and exit",
    )
    parser.add_argument("--quiet", action="store_true", help="log warnings only")
    parser.add_argument(
        "--admin-log",
        nargs="?",
        const=20,
        type=int,
        metavar="N",
        help="the last N administrative changes — who granted, revoked or deleted what",
    )
    parser.add_argument(
        "--denials",
        nargs="?",
        const=20,
        type=int,
        metavar="N",
        help="the last N refused access attempts — who tried, and was refused",
    )
    parser.add_argument(
        "--migrate",
        action="store_true",
        help="apply pending schema migrations to CARNET_DATABASE_URL and exit",
    )
    parser.add_argument(
        "--seed",
        action="store_true",
        help="write the shipped example agent and connector into this tenant, then exit",
    )
    parser.add_argument(
        "--generate-key",
        action="store_true",
        help=(
            "print a fresh encryption key for delegated credentials, then exit. "
            "Never generated automatically — a key that regenerates makes every "
            "stored credential silently unreadable"
        ),
    )
    # --- the fileborne door (step 095) -------------------------------------------
    #
    # Two commands that need no store. `--new-token` is `--mint-token` with the row
    # taken out: the row is written at boot from the file that names the variable
    # holding this. `--check-file` is the file's `--validate`.
    parser.add_argument(
        "--new-token",
        action="store_true",
        help=(
            "print a fresh machine token for a carnet.yaml, then exit. Put it in an "
            "environment variable and name that variable under tokens: — the file "
            "holds the pointer, never the secret"
        ),
    )
    parser.add_argument(
        "--check-file",
        metavar="PATH",
        help=(
            "read a carnet.yaml, resolve every ${VARIABLE}, apply it to a throwaway "
            "store and report what it declares — or the first refusal, naming the key"
        ),
    )
    parser.add_argument(
        "--finish-rotation",
        action="store_true",
        help=(
            "re-encrypt every stored secret under the current CARNET_SECRET_KEY "
            "and report whether CARNET_SECRET_KEYS_OLD can be emptied, then "
            "exit. Safe to interrupt and re-run. Exits 0 when the old key can be "
            "dropped, 1 while any row still needs a retired key or cannot be read at "
            "all, 2 if it could not run"
        ),
    )

    # --- sharing ------------------------------------------------------------------
    #
    # On the CLI for the same reason onboarding is: it is the only interface that
    # exists, and whoever can run it already holds the database. It also grants nothing
    # new — the CLI acts as `system:cli`, a principal with grants like any other, which
    # is why `--share-agent` on an agent somebody has taken over is refused rather than
    # obeyed.
    #
    # WHO is a principal id (`u_8f2c1a`), optionally prefixed with a kind
    # (`system:scheduler`). Sharing by email address is the next chunk, and until it
    # lands this is the awkward half of the interface people were promised.
    sharing = parser.add_argument_group("sharing an agent")
    sharing.add_argument(
        "--share-agent",
        nargs=2,
        metavar=("AGENT", "WHO"),
        help="give somebody access to an agent (see --role), then exit",
    )
    sharing.add_argument(
        "--role",
        default="user",
        choices=list(storage.AGENT_ROLES),
        help="the level to share at: user calls through it, editor also shares it on, "
        "owner also deletes and transfers (default: user)",
    )
    sharing.add_argument(
        "--unshare-agent",
        nargs=2,
        metavar=("AGENT", "WHO"),
        help="take somebody's access away, then exit",
    )
    sharing.add_argument(
        "--agent-access",
        metavar="AGENT",
        help="who may use this agent and at what level, then exit",
    )
    # In the sharing group rather than a group of its own, because who may do it is the
    # question it shares with the two above: renaming is `owner`, like deleting and
    # transferring. Step 025.
    sharing.add_argument(
        "--rename-agent",
        nargs=2,
        metavar=("OLD", "NEW"),
        help="change an agent's name, keeping its grants and history, then exit",
    )

    # --- groups -------------------------------------------------------------------
    #
    # On the CLI for the reason sharing was in 006, and the awkwardness is the same and
    # is on purpose: the durable decision is what a grant MEANS, not how somebody edits
    # one. A UI is the next step and it is why this one came first.
    #
    # **There are HTTP routes for this as of 12b** — see `api/routes_groups.py`, behind
    # the `admin` platform role. Until that role existed there could not be any, because
    # anybody who could add themselves to a group holding an editor grant would have been
    # promoting themselves. These commands stay: they are the bootstrap, and they work
    # before anybody has been granted anything.
    #
    # WHO is the same spelling `--share-agent` takes: an email address, or a principal id
    # optionally prefixed with a kind (`system:nightly`). A GROUP is its name or its id.
    groups_args = parser.add_argument_group("groups")
    groups_args.add_argument(
        "--add-group",
        nargs="+",
        metavar=("NAME", "DESCRIPTION"),
        help="create a group in this tenant, then exit",
    )
    groups_args.add_argument(
        "--delete-group",
        metavar="GROUP",
        help="delete a group, its membership and its grants, then exit",
    )
    groups_args.add_argument(
        "--group-add",
        nargs=2,
        metavar=("GROUP", "WHO"),
        help="put somebody in a group, then exit",
    )
    groups_args.add_argument(
        "--group-remove",
        nargs=2,
        metavar=("GROUP", "WHO"),
        help="take somebody out of a group, then exit",
    )
    groups_args.add_argument(
        "--group-link",
        nargs=2,
        metavar=("GROUP", "DIRECTORY_ID"),
        help="hand a group's membership to the customer's directory: its members become "
        "whoever the groups claim names, at each person's next sign-in. Needs "
        "--groups-claim on the identity provider",
    )
    groups_args.add_argument(
        "--group-unlink",
        metavar="GROUP",
        help="stop following the directory for a group. Removes nobody — its membership "
        "becomes yours to edit again",
    )
    groups_args.add_argument(
        "--groups",
        nargs="?",
        const="",
        metavar="GROUP",
        help="list this tenant's groups, or one group's members, then exit",
    )

    # --- platform roles -------------------------------------------------------------
    #
    # **Granting is here and there is no HTTP route for it**, unlike the four surfaces the
    # role unblocks. See `access/roles.py`: admins minting admins over HTTP is
    # self-service amplification, and it is the one thing a compromised admin token
    # cannot currently do.
    #
    # WHO is the same spelling every other command takes — an email address, or a
    # principal id optionally prefixed with a kind (`system:nightly`) — with one
    # difference that matters: an address nobody has logged in with is **refused** rather
    # than held. A role is not an invitation.
    role_args = parser.add_argument_group("platform roles")
    role_args.add_argument(
        "--grant-role",
        nargs=2,
        metavar=("ROLE", "WHO"),
        help=f"make somebody an administrator of this tenant ({', '.join(PLATFORM_ROLES)}), then exit",
    )
    role_args.add_argument(
        "--revoke-role",
        nargs=2,
        metavar=("ROLE", "WHO"),
        help="take a platform role away, then exit",
    )
    role_args.add_argument(
        "--list-roles",
        action="store_true",
        help="who may administer this tenant, then exit",
    )

    # --- api tokens ------------------------------------------------------------------
    #
    # **Minting is here and there is no HTTP route for it**, on the roles argument above
    # made sharper: what a stolen bearer token lacks is persistence, and a mint route
    # would hand it a durable successor that outlives both its own expiry and its
    # holder's employment.
    #
    # WHO is spelled as everywhere else — an address, or a principal id — and must be a
    # person. A token is owned by somebody answerable for it, and it dies with them.
    token_args = parser.add_argument_group("api tokens (machine callers)")
    token_args.add_argument(
        "--mint-token",
        nargs=2,
        metavar=("NAME", "WHO"),
        help="create an API token owned by a person and print it once, then exit",
    )
    token_args.add_argument(
        "--expires-days",
        type=int,
        metavar="N",
        help="with --mint-token: expire after N days (default: never; revoke to end it)",
    )
    # Step 033d. Chosen at mint and immutable — there is no token-update path, so the
    # flag is a kind, not a setting. The default (off) is 020's service token exactly.
    token_args.add_argument(
        "--as-owner",
        action="store_true",
        help="with --mint-token: a personal token — it resolves its owner's access "
        "(grants and groups, capped at user) and may hold no grant of its own",
    )
    token_args.add_argument(
        "--revoke-token",
        metavar="TOKEN_ID",
        help="close an API token; the row stays so old records still name it, then exit",
    )
    token_args.add_argument(
        "--list-tokens",
        action="store_true",
        help="this tenant's API tokens and what happened to them, then exit",
    )
    token_args.add_argument(
        "--reach",
        metavar="TOKEN_ID",
        help="what this token may call, tool by tool, with the agents that grant each "
        "and the patterns that decide — without presenting it, then exit",
    )
    token_args.add_argument(
        "--simulate",
        metavar="TOKEN_ID",
        help="with --call: would this call be admitted, and which rule decided. "
        "Executes nothing, dials nothing and records nothing, then exit",
    )
    token_args.add_argument(
        # **`--call`, not `--tool`**, and not only because `--vet --tool` already holds
        # that string. The two would name different things: `--vet --tool` takes the
        # **remote** name a server advertises, and this takes the **local** name a grant
        # and an audit record use (`example_list_issues`, not `list_issues`). One flag
        # meaning two namespaces is a footgun that reads as a convenience.
        "--call",
        metavar="TOOL",
        help="with --simulate: the tool to ask about, by the name a grant uses",
    )
    token_args.add_argument(
        "--arg",
        action="append",
        metavar="NAME=VALUE",
        help="with --simulate: one argument of the hypothetical call. Repeatable. Only "
        "the arguments the tool declares as resources decide anything",
    )

    # --- people (071) --------------------------------------------------------------
    people_args = parser.add_argument_group("people")
    people_args.add_argument(
        "--list-users",
        action="store_true",
        help="who is in this tenant, their status, and whether they have signed in, then exit",
    )
    people_args.add_argument(
        "--disable-user",
        metavar="WHO",
        help="cut somebody off now: sign-in refused, every token they own refused at its "
        "next call. Nothing they made is deleted, then exit",
    )
    people_args.add_argument(
        "--enable-user",
        metavar="WHO",
        help="let a disabled person back in, then exit",
    )


    # --- registering a connector --------------------------------------------------
    #
    # The four commands that make the product's premise true, in the order they must be
    # run. The ordering is forced by migration 021 rather than chosen: a credential
    # cannot be sealed against a connector that does not exist, and no server lists its
    # tools to an unauthenticated caller, so "connect, look, then register" is not
    # expressible and the row has to come first.
    #
    #     --allow-host mcp.acme.com          the host, or nothing will be dialled
    #     --add-connector jira --url ...     the row. Vets nothing.
    #     --connect-account jira <who>       7a, unchanged
    #     --discover jira                    what it offers, and the argument names
    #     --vet jira --tool ... --effect ... one tool at a time, appended
    #
    # **HTTP only.** See `tools.STDIO_REFUSED` for the argument, which is not the one
    # the plan gives: on a single-tenant deployment the shared-infrastructure reason
    # does not hold, and the decision survives on per-user credentials and on the egress
    # question being one question.
    registration = parser.add_argument_group("registering a connector")
    registration.add_argument(
        "--add-connector",
        metavar="ID",
        help="register an MCP server or a REST API for this tenant (vets nothing), "
        "then exit",
    )
    registration.add_argument(
        "--url",
        help="the connector's endpoint: a Streamable HTTP MCP server, or with "
        "--kind rest a REST API's base URL. Required by --add-connector",
    )
    registration.add_argument(
        "--kind",
        choices=("http", "rest"),
        # `None` rather than `"http"` so *not supplied* is representable — step 068
        # needs to tell an unstated kind from an explicit `--kind http`, or a recipe
        # could never be overridden back to the default. Resolved to `http` at use.
        default=None,
        help="what the URL is: 'http' is a Streamable HTTP MCP server (the "
        "default), 'rest' is a plain REST API whose tools are vetted with authored "
        "bindings instead of discovered",
    )
    registration.add_argument(
        "--credential-env",
        metavar="NAME",
        help="environment variable holding the shared credential. A NAME, never a value",
    )
    registration.add_argument(
        "--check-credential",
        metavar="CONNECTOR",
        help="resolve this connector's shared credential now and say whether it "
        "worked. Never prints the value — for an op:// reference it names the vault, "
        "the item and the field, and on a missing field lists the labels the item does "
        "carry",
    )
    registration.add_argument(
        "--credential-ref",
        metavar="op://VAULT/ITEM/FIELD",
        help="with --add-connector: hold the shared credential in your own 1Password "
        "vault instead, read at call time and never stored here. Mutually exclusive "
        "with --credential-env. A LOCATION, never a value — use item ids rather than "
        "names on a hot path: an id costs one request per call and a name costs three",
    )
    # --- where the credential goes — step 045c -------------------------------------
    #
    # `Authorization: Bearer <token>` is what most servers and most APIs want, and it
    # stays the default. These exist because a model vendor is the first customer that
    # does not: Anthropic reads `x-api-key` with no prefix at all. Both fields have been
    # on the launch since the HTTP transport shipped and neither had a writer outside
    # `--seed`, which is the register's own row (045b live e2e).
    registration.add_argument(
        "--credential-header",
        metavar="NAME",
        help="with --add-connector: the header the credential is presented in. "
        "Default 'Authorization'; a model vendor wanting 'x-api-key' says so here",
    )
    registration.add_argument(
        "--credential-prefix",
        metavar="TEXT",
        help="with --add-connector: what precedes the credential in that header. "
        "Default 'Bearer '; pass '' for an API that wants the bare token",
    )
    registration.add_argument(
        "--header",
        action="append",
        metavar="NAME=VALUE",
        help="with --add-connector: a non-secret header sent on every request. "
        "Repeatable — e.g. --header anthropic-version=2023-06-01. Never the credential",
    )
    registration.add_argument(
        "--description",
        help="what this connector is, for whoever reads the catalogue",
    )
    # --- recipes — step 068 ---------------------------------------------------------
    #
    # A checked-in preset that pre-fills the flags above. It fills and never decides:
    # every value it supplies is one an explicit flag overrides, it vets nothing, and it
    # approves no host. See `access/recipes.py`.
    registration.add_argument(
        "--list-recipes",
        action="store_true",
        help="the connector presets this build ships, and when each was last checked "
        "against its vendor",
    )
    registration.add_argument(
        "--from-recipe",
        metavar="ID",
        help="with --add-connector or --set-oauth: take this recipe's values as "
        "defaults. Any flag you also give wins. Vets nothing and approves no host",
    )
    registration.add_argument(
        "--allow-asserted-identity",
        action="store_true",
        help="with --add-connector: believe an asserted acting-for through the MCP "
        "door for this server's tools. Off by default — verified or nothing",
    )
    registration.add_argument(
        "--set-asserted-identity",
        nargs=2,
        metavar=("ID", "ON|OFF"),
        help="turn asserted acting-for on or off for a registered connector, then exit",
    )
    registration.add_argument(
        "--allow-host",
        nargs="+",
        metavar=("HOST", "NOTE"),
        help="let this tenant dial a host, then exit. Nothing is dialled without one",
    )
    registration.add_argument(
        "--revoke-host",
        metavar="HOST",
        help="withdraw a host. Connectors using it stay and stop connecting",
    )
    registration.add_argument(
        "--list-hosts",
        action="store_true",
        help="which hosts this tenant will dial, and who approved each",
    )
    registration.add_argument(
        "--discover",
        metavar="ID",
        help="connect and print what the server advertises, with input schemas",
    )
    registration.add_argument(
        "--vet",
        metavar="ID",
        help="approve one of a connector's tools, then exit. Needs --tool and --effect",
    )
    registration.add_argument("--tool", help="the tool name the server advertises")
    registration.add_argument(
        "--effect",
        # `None` rather than `"read"` so *not supplied* is representable — step 068 needs
        # to tell an unstated effect from an explicit `--effect read`, or a recipe's
        # proposal could never be taken. Resolved to `read` at use, so a command that
        # omits it means exactly what it always meant.
        default=None,
        choices=sorted(tools.VALID_EFFECTS),
        help="does this tool observe, or change something? The annotation MCP cannot make",
    )
    registration.add_argument(
        "--identity",
        # `None` for `--effect`'s reason. Resolved to `service` at use.
        default=None,
        choices=sorted(tools.VALID_IDENTITIES),
        help=(
            "whose account it acts as: 'service' is the connector's shared credential "
            "(the caller's connections never consulted), 'user' is the caller's own "
            "connected account (refused when they have none, never the shared fallback)"
        ),
    )
    registration.add_argument(
        "--resource",
        action="append",
        metavar="TYPE=ARG",
        help=(
            "what this tool touches, and which argument names it. Repeatable. "
            "TYPE=ARG for one argument; TYPE={a}/{b}:a,b when the identifier is "
            "composed from several. A write with no --resource is refused"
        ),
    )
    registration.add_argument(
        "--note",
        help="what somebody here should know before granting it. Ours, not the vendor's",
    )
    registration.add_argument(
        "--local-name",
        help="override the generated name, when prefix + remote name runs past 64 chars",
    )
    registration.add_argument(
        "--max-response-bytes",
        type=int,
        help="per-tool response cap, for a tool whose output is genuinely large",
    )

    registration.add_argument(
        "--redact-arg",
        action="append",
        metavar="ARG",
        help="with --vet: an argument this tool's audit rows hash rather than store. "
        "Repeatable. For a model tool this is where 'messages' goes — a prompt is the "
        "caller's content, and the audit table is append-only",
    )

    # --- vetting a REST tool — step 045a ------------------------------------------
    #
    # A REST API does not describe itself, so these flags author what discovery
    # would have supplied. Refused with a sentence on an MCP connector, where the
    # schema is discovered and the description is the vendor's.
    registration.add_argument(
        "--method",
        choices=("GET", "POST", "PUT", "PATCH", "DELETE"),
        help="with --vet on a REST connector: the HTTP method of this tool's request",
    )
    registration.add_argument(
        "--path",
        help="with --vet on a REST connector: the path template joined to the "
        "connector's base URL. {argument} segments name arguments from --schema, "
        "e.g. /repos/{owner}/{repo}/issues",
    )
    registration.add_argument(
        "--schema",
        help="with --vet on a REST connector: the tool's input schema — inline "
        "JSON, or a path to a JSON file. Authored by you: this is what the model "
        "sees and what --resource validates against",
    )
    registration.add_argument(
        "--query",
        action="append",
        metavar="ARG",
        help="with --vet on a REST connector: a schema argument that travels as a "
        "query parameter. Repeatable. Every schema argument must be mapped into "
        "the path, --query or --body",
    )
    registration.add_argument(
        "--body",
        action="append",
        metavar="ARG",
        help="with --vet on a REST connector: a schema argument that travels in "
        "the JSON request body. Repeatable",
    )
    registration.add_argument(
        "--resource-family",
        action="append",
        metavar="TYPE=A,B,C",
        help="with --vet: the families this resource type's ids divide into, so a "
        "scope line can say 'haiku' instead of a dated model id. Repeatable. Only "
        "meaningful where a vendor's identifiers have families — a model id, not a "
        "repository",
    )
    registration.add_argument(
        "--usage-map",
        help="with --vet on a REST connector, optional: inline JSON mapping "
        "counter names to response paths, where token usage lives in this API's "
        "answers (consumed by the spend metering)",
    )
    registration.add_argument(
        "--pricing",
        help="with --vet on a REST connector, optional: inline JSON of what this "
        "vendor's models cost, in USD per million tokens, keyed as "
        "CARNET_MODEL_RATES is keyed. Written by whoever registered the key, "
        "rather than in a file on the server",
    )
    registration.add_argument(
        "--tool-description",
        help="with --vet on a REST connector: what this tool does, in your words — "
        "there is no vendor advertisement to copy from. Shown to the model and in "
        "the catalogue",
    )
    registration.add_argument(
        "--who",
        help="whose credential to discover or vet with. Defaults to this CLI's own",
    )

    # --- onboarding -------------------------------------------------------------
    #
    # Creating a customer is a business event, so it is deliberately not self-serve
    # and there is no admin API for it — platform roles (who may vet a connector, who
    # may onboard a customer) are a model of their own and out of scope.
    #
    # The CLI is where it goes because whoever can run it already has the database.
    # A command grants nothing somebody could not do with psql, and it turns onboarding
    # into something with a recorded shape rather than a person editing rows by hand.
    # --- delegated credentials -----------------------------------------------------
    #
    # The credential itself is never an argument. It arrives on a hidden prompt, or
    # piped, and the reason is that a token in argv is a token in shell history and in
    # the process table — on the one command whose entire subject is a secret.
    accounts = parser.add_argument_group("connecting an account")
    accounts.add_argument(
        "--connect-account",
        nargs=2,
        metavar=("CONNECTOR", "WHO"),
        help=(
            "store somebody's own credential for a connector, so their calls act as "
            "them. Prompts for the credential; also reads it piped. WHO is an email "
            "address or a principal id"
        ),
    )
    accounts.add_argument(
        "--disconnect-account",
        nargs=2,
        metavar=("CONNECTOR", "WHO"),
        help="remove that credential. Their calls fall back to the shared one",
    )
    accounts.add_argument(
        "--list-connections",
        action="store_true",
        help="who has connected an account, and as whom. Never shows a credential",
    )
    accounts.add_argument(
        "--label",
        default="",
        metavar="ACCOUNT",
        help=(
            "which vendor account this credential is, for --connect-account "
            "(e.g. '@priya-acme'). Not verified — the platform ships no integrations "
            "and cannot ask an arbitrary server whose token this is. An OAuth "
            "connection gets this from the provider and does not need it"
        ),
    )

    # --- the consent flow -----------------------------------------------------------
    #
    # **CLI-only, and that was the same chunk boundary 011 and 012 hit rather than a
    # limitation of 7b.** Configuring a connector needs a tenant-admin role;
    # *connecting your own account* does not, and that is what the two HTTP routes in
    # `api/routes_connections.py` are. The distinction 012 drew holds either way.
    #
    # **12b built the role, so this is unblocked and is deliberately still here.** Moving
    # it to a route ships with 12c, whose administration surface is where its consumer is
    # already standing — a flag moved to an endpoint nobody can reach from a screen would
    # be 7b's routes-without-a-screen finding, repeated knowingly.
    #
    # The client secret is never an argument, for `--connect-account`'s reason and with
    # a wider blast radius: a per-user token in shell history compromises one person,
    # and a client secret in shell history compromises the consent flow for everybody in
    # the tenant.
    consent = parser.add_argument_group("configuring a consent flow (7b)")
    consent.add_argument(
        "--set-oauth",
        metavar="CONNECTOR",
        help=(
            "record the OAuth application a connector's consent flow uses, so people "
            "can connect their own accounts from a browser instead of an operator "
            "pasting their tokens. Needs --client-id and either --auth-server or both "
            "--authorize-endpoint and --token-endpoint. Reads the client secret from a "
            "hidden prompt, or piped"
        ),
    )
    consent.add_argument(
        "--clear-oauth",
        metavar="CONNECTOR",
        help=(
            "remove that configuration. Credentials people already connected are left "
            "alone and keep working until they expire"
        ),
    )
    consent.add_argument(
        "--auth-server",
        metavar="URL",
        help=(
            "the authorization server's base URL. Its /authorize and /token are assumed "
            "unless --authorize-endpoint and --token-endpoint say otherwise"
        ),
    )
    consent.add_argument("--authorize-endpoint", help="where the browser is sent")
    consent.add_argument("--token-endpoint", help="where we POST, with the client secret")
    consent.add_argument(
        "--revoke-endpoint",
        help="RFC 7009. Without it, disconnecting deletes locally and leaves the token "
        "live at the provider",
    )
    consent.add_argument("--client-id", help="the OAuth application's public id")
    consent.add_argument(
        "--authorize-param",
        action="append",
        metavar="NAME=VALUE",
        help=(
            "repeatable. A provider-specific parameter on the sign-in link, for the "
            "providers that mandate one — Atlassian needs "
            "'audience=api.atlassian.com' and 'prompt=consent'. The parameters the "
            "consent flow builds itself are refused, because two of them are what stop "
            "somebody else completing your connection"
        ),
    )
    consent.add_argument(
        "--scope",
        action="append",
        metavar="SCOPE",
        help="repeatable. Include the provider's spelling of offline_access, or the "
        "connection dies in an hour with no way to renew it",
    )
    consent.add_argument(
        "--scope-notes",
        metavar="JSON|FILE",
        help=(
            "with --set-oauth: what each scope permits, in words the person granting it "
            "can read — {\"write:jira-work\": {\"name\": …, \"description\": …, "
            "\"access\": \"read|write\"}}. Shown on the Connections page at the moment "
            "somebody consents, where today they are asked to grant a scope string. "
            "Every key must be a scope you are requesting"
        ),
    )

    onboarding = parser.add_argument_group("onboarding a customer")
    onboarding.add_argument(
        "--add-tenant",
        nargs=2,
        metavar=("TENANT_ID", "NAME"),
        help="create a customer, then exit",
    )
    onboarding.add_argument(
        "--tenant-status",
        nargs=2,
        metavar=("TENANT_ID", "STATUS"),
        help="'active' or 'suspended'. Suspending stops sign-ins and refuses every door "
        "call from the tenant's tokens; nothing is deleted",
    )
    onboarding.add_argument(
        "--prune-logs",
        action="store_true",
        help="run one retention sweep now and report what went, then exit. Needs "
        "CARNET_RETENTION_DAYS",
    )
    onboarding.add_argument(
        "--delete-tenant",
        metavar="TENANT_ID",
        help="erase a customer and everything of theirs, permanently. The tenant must "
        "be suspended first. Prompts for the tenant id as confirmation, then exits",
    )
    onboarding.add_argument(
        "--add-idp",
        metavar="TENANT_ID",
        help="register an identity provider for a customer (needs --issuer, --jwks-uri, --audience)",
    )
    onboarding.add_argument("--issuer", help="the provider's `iss` claim, exactly as it emits it")
    onboarding.add_argument("--jwks-uri", help="where the provider publishes its signing keys")
    onboarding.add_argument("--audience", help="our client id; what a token's `aud` must be")
    onboarding.add_argument(
        "--discriminator",
        metavar="CLAIM=VALUE",
        help="for a shared issuer (Google Workspace): the claim and value identifying "
        "this customer, e.g. hd=acme.com",
    )
    onboarding.add_argument(
        "--domain",
        action="append",
        metavar="DOMAIN",
        help="an email domain this provider may vouch for; repeatable",
    )
    onboarding.add_argument(
        "--email-claim",
        default="email",
        help="which claim carries the email (Entra often uses preferred_username)",
    )
    onboarding.add_argument(
        "--subject-claim",
        default="sub",
        help="which claim carries the STABLE identity. 'sub' per the spec, but Okta's "
        "access tokens put the login there and the stable id in 'uid'",
    )
    onboarding.add_argument(
        "--groups-claim",
        help="which claim carries the groups this person is in (Entra emits object ids "
        "in 'groups'; Okta emits names). Unset means the directory decides nothing: "
        "membership stays what --group-add makes it",
    )
    onboarding.add_argument(
        "--list-idps",
        nargs="?",
        const="",
        metavar="TENANT_ID",
        help="show registered identity providers, then exit",
    )

    local = parser.add_argument_group("running the whole product locally")
    local.add_argument(
        "--local",
        action="store_true",
        help="start everything — database, API, frontend and a local "
        "email+password identity provider — and print a URL. State persists in "
        "var/local/",
    )
    local.add_argument(
        "--admin",
        dest="local_admin",
        metavar="EMAIL",
        help="with --local: who becomes the first administrator (asked on the "
        "terminal otherwise, and remembered)",
    )
    local.add_argument(
        "--port",
        dest="local_port",
        type=int,
        metavar="PORT",
        help="with --local: the one port everything is served on (default 8080)",
    )
    local.add_argument(
        "--host",
        dest="local_host",
        metavar="HOST",
        help="with --local: the bind address. Default 127.0.0.1; anything else is "
        "plain HTTP on a network and the banner will say so",
    )
    # Step 043. An origin, not a URL: the name a browser somewhere else reaches this
    # deployment at, whether that is a Tailscale Funnel name, a Cloudflare tunnel or an
    # ingress somebody runs. `--local` is *told* it; it never goes looking, which is what
    # keeps this module ignorant of three products it has no reason to know about.
    local.add_argument(
        "--public-url",
        dest="local_public_url",
        metavar="URL",
        help="with --local: the public address this deployment is reached at, e.g. "
        "https://box.tailnet.ts.net — added to the sign-in redirects beside localhost "
        "(remembered)",
    )
    local.add_argument(
        "--registration",
        dest="local_registration",
        choices=("open", "closed"),
        help="with --local: whether the sign-in screen offers 'Create account' "
        "(default open; remembered)",
    )
    local.add_argument(
        "--fresh",
        dest="local_fresh",
        action="store_true",
        help="with --local: drop the local database and accounts after a typed "
        "confirmation, then start over",
    )

    args = parser.parse_args()
    _configure_logging(verbose=not args.quiet)

    # Before everything, because its whole purpose is to be runnable by somebody who
    # cannot start the process yet. Printed rather than stored, and printed *once*:
    # whoever runs this has to put it somewhere, and a key the platform also kept a
    # copy of would be a key nobody had to take responsibility for.
    if args.generate_key:
        print(crypto.generate_key())
        print(
            f"\nStore this somewhere you can restore it from, then set {crypto.KEY_ENV}.",
            file=sys.stderr,
        )
        print(
            "Every delegated credential is encrypted with it and unreadable without "
            "it.",
            file=sys.stderr,
        )
        return

    if args.new_token:
        # No store, no owner, no row — the row is written at boot by the file that
        # names the variable this lands in. Said plainly, as `--mint-token` says it:
        # this line is the only copy.
        print(tokens.new_presented())
        print(
            "\nPut it in an environment variable and name that variable in your "
            "carnet.yaml:\n"
            "    tokens:\n"
            "      my-laptop:\n"
            "        secret: ${CARNET_TOKEN_MY_LAPTOP}\n"
            "        agents: [triage]\n"
            "This is the only time that string exists; the door stores a hash of it.",
            file=sys.stderr,
        )
        return

    if args.check_file:
        try:
            summary = carnetfile.check(args.check_file)
        except carnetfile.CarnetFileError as exc:
            parser.error(str(exc))
        print(f"{args.check_file}: {summary}")
        return

    # Beside `--generate-key` and for its reason: the catalogue is files in this build,
    # so this answers with no database, no tenant and no key. Somebody deciding whether
    # this product can reach their Jira should not have to stand a deployment up first.
    if args.list_recipes:
        try:
            _list_recipes()
        except recipes.RecipeRefused as exc:
            parser.error(str(exc))
        return

    # Migration runs before the store is configured: there may not be a schema yet
    # for anything to load from.
    if args.migrate:
        if not DATABASE_URL:
            parser.error(
                "--migrate needs CARNET_DATABASE_URL. Without it the runtime "
                "uses an in-memory store, which has no schema to migrate."
            )
        applied = migrate.apply(DATABASE_URL, verbose=True)
        print(f"{len(applied)} migration(s) applied." if applied else "Already up to date.")
        return

    # Before the store is configured, because it configures its own: `--local` builds
    # a world (database, key, provider row) and then runs it. The import is lazy and
    # stays that way — the server never imports `localidp`, and a test holds the CLI
    # to being the only door in.
    if args.local:
        from .localidp import frontdoor

        frontdoor.run(parser, args)
        return

    # Agents and connectors are rows now, so a store has to exist before anything can
    # be looked up. Without CARNET_DATABASE_URL this is an in-memory store
    # seeded from the shipped modules, so a fresh clone still runs.
    #
    # An in-memory store is seeded on the way up, because otherwise a fresh clone has
    # no agents. A real database is not: its contents are the customer's, and
    # overwriting them on every start would be astonishing. `--seed` is how the
    # shipped examples get in there, deliberately and once.
    tenant_id = DEFAULT_TENANT_ID
    try:
        bootstrap.configure(tenant_id, seed=not DATABASE_URL)
    except StorageError as exc:
        # Step 029: `configure` verifies that tenant scoping can work against this
        # database and refuses when it cannot. One sentence with the remedy in it,
        # the same treatment `configure_crypto` gets immediately below — a startup
        # refusal an operator can act on, rather than a traceback out of a helper
        # four frames down. `--migrate` never reaches here: it runs before the store
        # is configured, which is what lets a pre-037 database be brought up to date.
        parser.error(str(exc))

    # Every command below borrows the store's pool and, until step 099's acceptance
    # pass, nothing gave it back: the CLI returned from wherever it finished and left
    # the pool to the interpreter's finalizer, which on Python 3.14 prints a
    # `PythonFinalizationError: cannot join thread at interpreter shutdown` traceback
    # under the output of **every** command run against Postgres — `--grant-role`,
    # `--allow-host`, `--mint-token`, all of them. Harmless, and exactly the kind of
    # noise that makes an operator distrust a tool. `bootstrap.configure` already
    # closes on its own refusal path for the same reason; this is the success path
    # and every `parser.error` on the way, in one place.
    try:
        _with_store(parser, args, tenant_id)
    finally:
        storage.active().close()


def _with_store(parser: argparse.ArgumentParser, args: argparse.Namespace, tenant_id: str) -> None:
    """Every command that needs the configured store, in the order `main` always ran them.

    Split out of `main` for one reason: a `try`/`finally` around three hundred lines with
    forty `return`s in them is a re-indent nobody can review, and a function boundary is
    the same guarantee with a diff that is only the seam.
    """
    # The encryption key, before anything can reach a stored credential. Required
    # whenever there is a durable store — see bootstrap.configure_crypto for why that
    # is the line, and why an in-memory run does not need one.
    try:
        bootstrap.configure_crypto()
    except crypto.CryptoError as exc:
        parser.error(str(exc))

    if args.seed:
        skipped = bootstrap.seed_tenant(tenant_id)
        print(f"Seeded tenant '{tenant_id}' with the shipped example agent and connector.")
        # Printed rather than silent, and printed even though nothing went wrong: the
        # operator asked for the shipped agent and did not entirely get it, and the
        # reason is a decision somebody else made. Saying nothing here is how the old
        # behaviour was invisible in the other direction.
        for name, author in skipped:
            print(
                f"  left '{name}' alone: its configuration was last written by "
                f"{author}, and --seed never overwrites a config a human wrote."
            )
        return

    if (
        args.add_tenant
        or args.tenant_status
        or args.delete_tenant
        or args.prune_logs
        # 026. Not the sharpest write on the list but the most absurd without a
        # database: it would re-encrypt an in-memory dict and print a verdict about
        # dropping a key, and the operator who believed it would drop a key their
        # real rows still need.
        or args.finish_rotation
        or args.add_idp
        or args.share_agent
        or args.unshare_agent
        or args.connect_account
        or args.disconnect_account
        or args.add_group
        or args.delete_group
        or args.group_add
        or args.group_remove
        # 070. Not because it writes — it writes nothing — but because it reads a
        # connector row, and against a store that dies with the process there is no
        # connector to check. It would print "there is no connector 'x'" about one the
        # operator can see in their own database.
        or args.check_credential
        or args.group_link
        or args.group_unlink is not None
        # A role granted into a dict that dies with this process is the worst member of
        # this list: it prints that somebody is an administrator and leaves nothing
        # behind, and the person who believes it will not find out until they are refused
        # by a screen.
        or args.grant_role
        or args.revoke_role
        # 020, and this one is the sharpest on the list: `--mint-token` PRINTS A SECRET.
        # Without a database the row dies with the process, so the operator is left
        # holding a credential that authenticates against nothing — and the only copy of
        # it has already been shown, so "run it again" is not a recovery, it is a second
        # dead secret in their scrollback.
        or args.mint_token
        or args.revoke_token
        # 071. A disable against a store that dies with the process prints that
        # somebody is cut off, and they are not.
        or args.disable_user
        or args.enable_user
        # Registration is on this list for the same reason sharing is, and one worse:
        # `--add-connector` then `--vet` are two processes, so without a database the
        # second would be told the connector does not exist — after the first printed
        # that it had been registered. Two successes and nothing behind either.
        or args.add_connector
        # Trust in a caller that vanished when the command exited would be an
        # administrator who enabled it and watched the door keep refusing.
        or args.set_asserted_identity
        or args.allow_host
        or args.revoke_host
        or args.vet
        # 7b. A consent flow that vanished when the command exited would be an
        # administrator who configured it, told somebody to go and connect, and watched
        # them get "no consent flow configured" — for the same reason as every row above.
        or args.set_oauth
        or args.clear_oauth
    ):
        # These writes have to be durable, and without a database this process is an
        # in-memory store that dies with it. Running `--add-tenant` then `--add-idp`
        # would print two successes and leave nothing behind, because the second
        # command is a different process with a different empty dict — a failure that
        # looks exactly like success. Same guard `--migrate` has, for the same reason.
        #
        # Sharing is on this list for exactly the same reason and one worse: "I shared
        # that agent with her last week" is a thing somebody will believe, and an
        # in-memory grant is a belief with nothing behind it.
        if not DATABASE_URL:
            parser.error(
                "this command writes, and needs CARNET_DATABASE_URL. Without it "
                "the runtime uses an in-memory store, so anything created here "
                "vanishes when this command exits."
            )

    if args.add_tenant:
        _add_tenant(parser, *args.add_tenant)
        return

    if args.tenant_status:
        _tenant_status(parser, *args.tenant_status)
        return

    if args.delete_tenant:
        _delete_tenant(parser, args.delete_tenant)
        return

    if args.prune_logs:
        _prune_logs(parser)
        return

    if args.finish_rotation:
        sys.exit(_finish_rotation(parser))

    if args.add_idp:
        _add_idp(parser, args)
        return

    if args.list_idps is not None:
        _list_idps(args.list_idps or None)
        return

    if args.share_agent:
        _share_agent(
            parser, tenant_id, args.share_agent[0], args.share_agent[1], role=args.role
        )
        return

    if args.unshare_agent:
        _unshare_agent(parser, tenant_id, *args.unshare_agent)
        return

    if args.agent_access:
        _agent_access(tenant_id, args.agent_access)
        return

    if args.rename_agent:
        _rename_agent(parser, tenant_id, *args.rename_agent)
        return

    if args.add_group:
        _add_group(parser, tenant_id, *args.add_group)
        return

    if args.delete_group:
        _delete_group(parser, tenant_id, args.delete_group)
        return

    if args.group_add:
        _group_member(
            parser, tenant_id, args.group_add[0], args.group_add[1], add=True
        )
        return

    if args.group_remove:
        _group_member(
            parser, tenant_id, args.group_remove[0], args.group_remove[1], add=False
        )
        return

    if args.group_link:
        _group_link(parser, tenant_id, args.group_link[0], args.group_link[1])
        return

    if args.group_unlink is not None:
        # `is not None`, so `--group-unlink ""` reaches the handler and is refused by
        # name resolution rather than falling through every branch and exiting having
        # silently done nothing.
        _group_link(parser, tenant_id, args.group_unlink, None)
        return

    if args.groups is not None:
        _groups(parser, tenant_id, args.groups or None)
        return

    if args.grant_role:
        _grant_role(parser, tenant_id, *args.grant_role)
        return

    if args.revoke_role:
        _revoke_role(parser, tenant_id, *args.revoke_role)
        return

    if args.list_roles:
        _list_roles(tenant_id)
        return

    if args.mint_token:
        _mint_token(
            parser,
            tenant_id,
            args.mint_token[0],
            args.mint_token[1],
            args.expires_days,
            acts_as_owner=args.as_owner,
        )
        return

    if args.revoke_token:
        _revoke_token(parser, tenant_id, args.revoke_token)
        return

    if args.list_tokens:
        _list_tokens(tenant_id)
        return

    if args.list_users:
        _list_users(tenant_id)
        return

    if args.disable_user is not None:
        _set_user_active(parser, tenant_id, args.disable_user, False)
        return

    if args.enable_user is not None:
        _set_user_active(parser, tenant_id, args.enable_user, True)
        return

    # `is not None` on both, on `--group-unlink`'s recorded reason: with a truthiness
    # test, `--reach ""` falls through every remaining branch and exits having printed
    # the whole usage block, which is the *silently did nothing* failure that comment
    # exists to prevent. Empty reaches the handler and is refused by name, like any
    # other id this tenant does not have.
    if args.reach is not None:
        _reach(parser, tenant_id, args.reach)
        return

    if args.simulate is not None:
        _simulate(parser, tenant_id, args.simulate, args.call, args.arg)
        return


    # Registration, in the order the commands are meant to be run. `--allow-host` is
    # first because nothing else works without it, which is the point of an allowlist
    # that denies when empty.
    if args.allow_host:
        _allow_host(parser, tenant_id, args.allow_host[0], " ".join(args.allow_host[1:]))
        return

    if args.revoke_host:
        _revoke_host(parser, tenant_id, args.revoke_host)
        return

    if args.list_hosts:
        _list_hosts(tenant_id)
        return

    if args.add_connector:
        _add_connector(parser, tenant_id, args.add_connector, args)
        return

    if args.set_asserted_identity:
        _set_asserted_identity(parser, tenant_id, args.set_asserted_identity)
        return

    if args.discover:
        _discover(parser, tenant_id, args.discover, args.who or "")
        return

    if args.check_credential:
        _check_credential(parser, tenant_id, args.check_credential)
        return

    if args.vet:
        _vet(parser, tenant_id, args)
        return

    if args.set_oauth:
        _set_oauth(parser, tenant_id, args.set_oauth, args)
        return

    if args.clear_oauth:
        _clear_oauth(tenant_id, args.clear_oauth)
        return

    if args.connect_account:
        _connect_account(
            parser, tenant_id, args.connect_account[0], args.connect_account[1],
            label=args.label,
        )
        return

    if args.disconnect_account:
        _disconnect_account(parser, tenant_id, *args.disconnect_account)
        return

    if args.list_connections:
        _list_connections(tenant_id)
        return

    if args.list:
        _list_agents(tenant_id)
        return

    if args.list_tools:
        _list_tools(tenant_id)
        return

    if args.admin_log is not None:
        _admin_log(tenant_id, args.admin_log)
        return

    if args.denials is not None:
        _denials(tenant_id, args.denials)
        return

    # Nothing was asked for. Every command above returned; there is no default action —
    # this deployment brokers calls for an assistant that connects to /mcp, and running
    # an agent here is not a thing it does.
    parser.print_help(sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    # `main()` rather than `sys.exit(main())`: it returns None on every path, so the
    # wrapper only ever passed None to `sys.exit`. Exit codes come from `parser.error`
    # (2) and the explicit `SystemExit`s the commands raise — see `--finish-rotation`,
    # where the difference between 0 and 1 is the whole verdict.
    main()
