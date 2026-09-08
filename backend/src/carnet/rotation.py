"""Finishing a key rotation: the sweep that lets the old key actually be dropped. 026.

`LocalKeyCipher`'s docstring has stated the whole plan since 007 — *"set the new key,
keep the old one listed, re-encrypt rows in the background, then drop it"* — and until
this module, nothing re-encrypted. The consequence was not an inconvenience but an
impossibility: `CARNET_SECRET_KEYS_OLD` could never be emptied, so a compromised
key stayed a live decryption key for every credential written before the rotation,
forever. This is the third step of the three, and the register's key-compromise drill is
a person running it.

Four sealed columns exist, and each blob is AAD-bound to its own row's identity —
`connection_aad`, `oauth_app_aad`, `trigger_secret_aad`, `pending_authorization_aad` —
so this is four table-specific sweeps rather than one loop over a `key_id` column: the
sweep must rebuild each row's exact binding to open it, and again to re-seal it.

## The shape: fetch once, one pass, no cursor

Resume is the predicate. A re-sealed row's `key_id` becomes the current id, so it leaves
"not sealed under the current key" the moment the write lands — an interrupted sweep is
resumed by running it again, and the query finds exactly the rows still owed. There is
nothing to checkpoint because the data is the checkpoint. The populations are small by
construction (one row per person-per-connector, one per consent-configured connector, a
handful of triggers per agent, fifteen minutes of consent flows), so each table is
fetched once and walked once.

Every write is a compare-and-set on the blob bytes themselves (`base.py`'s rotation
section says why that token is sufficient), so the sweep runs against a live server: a
row a refresh or a consent callback touches mid-sweep fails the condition and is left
alone, correctly — whoever touched it sealed under the current key.

## The three kinds of row it cannot fix, and what it does instead

- **A key in neither list** (`MissingKeyError` territory): reported with its address and
  a remedy, skipped, and deliberately **not** a blocker — the done-when is *no row names
  a retired key*, and a row whose key is in neither list is not helped by keeping the
  old list. It was unreadable before the sweep and is exactly as unreadable after.
- **A retired-key blob that fails authentication** (`UndecryptableError`: altered, or
  copied from another row): reported, skipped, and it **does** block the verdict — it
  still names the retired key, the query stays honest with no "except for" footnote,
  and a blob that will not authenticate is a security event that should be impossible
  to scroll past during the one procedure an operator watches end to end.
- **A pending consent flow whose key is held and still will not authenticate**: deleted,
  not reported — the one destructive branch here, and the arguments invert for it. This
  is the only table whose rows the system already deletes on its own authority (on use,
  on expiry), the plaintext is a PKCE verifier worth nothing once its flow dies, and no
  key can recover the row, so its only possible future is a 503 in the face of whoever's
  callback lands on it. Deleting turns that into "start again from the Connections
  page". A pending row whose key is merely *unknown* is **not** deleted — a restored key
  would open it — and is reported like any other row; see `_sweep_pending`.

**The rule underneath all three: the sweep never destroys anything that putting a key
back would recover.** The single delete above is the case where nothing would.

Expired pending flows are deleted before any of that, via
`sweep_pending_authorizations` — its first production caller — at the same TTL the
callback enforces, so abandoned flows stop being permanent asterisks on the verdict.

Nothing here writes an administrative record; the rotation's record is the CLI printout
in the operator's hands, which is the transcript the gate clause asks for. And nothing
here holds a key: `core/crypto.py` still does, and this module hands blobs to it.
"""

from dataclasses import dataclass, field

from . import storage
from .access.oauth import PENDING_TTL_SECONDS
from .core import crypto


@dataclass(frozen=True)
class Stranded:
    """One row the sweep could not re-seal, addressed for a person, never a secret."""

    table: str
    address: str
    key_id: str
    reason: str
    remedy: str
    # Still names a retired key, so it holds up the drop — and, on the three durable
    # tables, a blob that failed to authenticate under a key we hold, which is a
    # security event rather than a rotation artifact. The printout says so.
    blocks: bool
    # Whether a person has to do something. False for a consent flow, whose remedy is
    # "nothing" because it expires within the quarter hour on its own — so it is
    # recorded in the transcript and does not fail the command.
    needs_a_person: bool = True


@dataclass
class TableSweep:
    """What one table's pass did."""

    table: str
    resealed: int = 0
    # Rows whose compare-and-set matched nothing: somebody else wrote the row, or it
    # was consumed or deleted, between the fetch and the write. **Not evidence that
    # they are now on the current key** — see `RotationReport.rows_written_under_a
    # _retired_key`, which is what actually catches a process still holding the old
    # key as its current one.
    changed_underneath: int = 0
    # Set when this table could not be walked to the end — a storage failure partway.
    # The other tables still run, and the report still prints, because the record of
    # what *did* land is the thing an operator is left holding.
    failed: str = ""


@dataclass
class RotationReport:
    """Everything `--finish-rotation` prints, as data.

    `remaining` is the done-when query, re-run after the sweep: per table, every key id
    still named by some row (the current key's rows are not in it) and how many rows
    name it. `finished` is that query against the retired list and nothing else — a row
    naming a key in *neither* list does not hold the old list hostage (see the module
    docstring), which is why the property checks membership rather than emptiness.
    """

    current_key_id: str
    retired_key_ids: frozenset
    expired_pending_removed: int = 0
    unreadable_pending_removed: int = 0
    tables: list = field(default_factory=list)
    stranded: list = field(default_factory=list)
    remaining: dict = field(default_factory=dict)

    @property
    def finished(self) -> bool:
        return not any(
            key_id in self.retired_key_ids
            for counts in self.remaining.values()
            for key_id in counts
        )

    @property
    def needs_a_person(self) -> list:
        """Stranded rows somebody has to act on. See `Stranded.needs_a_person`."""
        return [row for row in self.stranded if row.needs_a_person]

    @property
    def rows_written_under_a_retired_key(self) -> int:
        """Rows that named a retired key *after* the sweep had already walked past them.

        **The one rotation failure the row counts cannot otherwise explain, and the one
        with a completely different remedy.** Every row still under a retired key is
        either one the sweep could not open — each of which is a blocking `Stranded` —
        or one that was written under that key while the sweep was running. The second
        can only be a process that was never restarted onto the new key: it seals with
        *its* current key, which is the retired one, so the sweep re-seals and it writes
        back, forever. Reconnecting the account will not fix it and neither will running
        this again; restarting that process will.

        Subtraction rather than a flag, because it is a fact about the two numbers
        rather than something a writer could be asked to report.
        """
        unexplained = 0
        for table, counts in self.remaining.items():
            still_retired = sum(
                rows for key_id, rows in counts.items() if key_id in self.retired_key_ids
            )
            accounted = sum(
                1 for row in self.stranded if row.table == table and row.blocks
            )
            unexplained += max(0, still_retired - accounted)
        return unexplained


# The remedy each table's owner surface already offers. Each one deletes or replaces
# the row, which is why "resolve it there" is also how a blocking row stops blocking.
_REMEDIES = {
    "connections": "the person connects the account again (--connect-account, or the "
    "consent flow); reconnecting replaces the row",
    "connector_oauth": "reconfigure the consent flow: --set-oauth writes a fresh "
    "sealed client secret",
    # 035k replaced this remedy, and the old one is worth remembering because it was
    # the expensive one: *"delete and recreate the trigger — the URL changes, so the
    # outside system's webhook config changes with it."* That sentence was true until a
    # rotate verb existed, and it sent an operator resolving a key-rotation blocker into
    # somebody else's configuration screen.
    "triggers": "rotate the trigger's secret (--rotate-trigger-secret) — it reseals "
    "under the current key and keeps the URL, so the outside system changes one field",
}


def sweep(cipher: crypto.LocalKeyCipher | None = None) -> RotationReport:
    """Re-seal everything the current key did not seal. Returns the full report.

    Requires a `LocalKeyCipher` rather than any `Cipher`, and by name: the sweep must
    classify a row's key id as current, retired or unknown, which only a holder of a
    key *list* can answer. A KMS cipher's rotation is a re-wrap inside the KMS — a
    different feature, owned by the BYOK register row.
    """
    if cipher is None:
        cipher = crypto.active()
    if not isinstance(cipher, crypto.LocalKeyCipher):
        raise crypto.CryptoError(
            "finishing a rotation needs locally held keys, and the active cipher is "
            f"a {type(cipher).__name__}. A KMS rotates by re-wrapping inside the KMS; "
            "this sweep is for deployments whose keys live in the environment."
        )

    store = storage.active()
    report = RotationReport(
        current_key_id=cipher.key_id,
        retired_key_ids=cipher.key_ids - {cipher.key_id},
    )

    # Abandoned consent flows first, at the TTL the callback already enforces: rows
    # the callback would refuse anyway must not survive to be counted, re-sealed, or
    # reported as stranded.
    report.expired_pending_removed = store.sweep_pending_authorizations(
        older_than_seconds=PENDING_TTL_SECONDS
    )

    # **One table's storage failure must not discard the other three, nor the record
    # of what already landed.** Every re-seal that lands is permanent, so a sweep that
    # died on table two after re-sealing four hundred rows on table one has done real,
    # durable work — and the first version of this let the exception carry the whole
    # report away with it, leaving the operator a traceback and no idea what had
    # happened. The census below is deliberately *not* contained: without it there is
    # no verdict, and a report with no verdict is not one worth printing.
    passes = (
        (_sweep_connections, "connections"),
        (_sweep_oauth_apps, "connector_oauth"),
        (_sweep_triggers, "triggers"),
        (_sweep_pending, "pending_authorizations"),
    )
    for pass_over, table in passes:
        try:
            pass_over(store, cipher, report)
        except storage.StorageError as exc:
            for result in report.tables:
                if result.table == table:
                    result.failed = str(exc)

    report.remaining = _census(store, cipher.key_id)
    return report


def _contained(report: RotationReport, table: str):
    """This table's result, attached to the report *before* the table is walked.

    Attached up front rather than on the way out, so a pass that raises partway still
    leaves the count of what it managed — and something for `sweep` to mark failed.
    """
    result = TableSweep(table)
    report.tables.append(result)
    return result


def _sweep_connections(store, cipher, report: RotationReport) -> None:
    result = _contained(report, "connections")
    for row in store.connections_not_sealed_under(cipher.key_id):
        address = (
            f"{row['principal_kind']}:{row['principal_id']} @ "
            f"{row['connector_id']}, tenant {row['tenant_id']}"
        )
        aad = crypto.connection_aad(
            row["tenant_id"],
            row["principal_kind"],
            row["principal_id"],
            row["connector_id"],
        )
        plaintext = _opened(cipher, report, "connections", address, row["key_id"],
                            row["ciphertext"], row["tenant_id"], aad)
        if plaintext is None:
            continue
        sealed, key_id = cipher.seal(plaintext, tenant_id=row["tenant_id"], aad=aad)
        landed = store.reseal_connection(
            row["tenant_id"],
            row["principal_kind"],
            row["principal_id"],
            row["connector_id"],
            ciphertext=sealed,
            key_id=key_id,
            if_ciphertext=row["ciphertext"],
        )
        _count(result, landed)


def _sweep_oauth_apps(store, cipher, report: RotationReport) -> None:
    result = _contained(report, "connector_oauth")
    for row in store.connector_oauth_not_sealed_under(cipher.key_id):
        address = f"connector '{row['connector_id']}', tenant {row['tenant_id']}"
        aad = crypto.oauth_app_aad(row["tenant_id"], row["connector_id"])
        plaintext = _opened(cipher, report, "connector_oauth", address, row["key_id"],
                            row["client_secret"], row["tenant_id"], aad)
        if plaintext is None:
            continue
        sealed, key_id = cipher.seal(plaintext, tenant_id=row["tenant_id"], aad=aad)
        landed = store.reseal_connector_oauth(
            row["tenant_id"],
            row["connector_id"],
            client_secret=sealed,
            key_id=key_id,
            if_client_secret=row["client_secret"],
        )
        _count(result, landed)


def _sweep_triggers(store, cipher, report: RotationReport) -> None:
    result = _contained(report, "triggers")
    for row in store.triggers_not_sealed_under(cipher.key_id):
        address = f"trigger {row['id']}, tenant {row['tenant_id']}"
        aad = crypto.trigger_secret_aad(row["tenant_id"], row["id"])
        plaintext = _opened(cipher, report, "triggers", address, row["secret_key_id"],
                            row["secret_sealed"], row["tenant_id"], aad)
        if plaintext is None:
            continue
        sealed, key_id = cipher.seal(plaintext, tenant_id=row["tenant_id"], aad=aad)
        landed = store.reseal_trigger_secret(
            row["tenant_id"],
            row["id"],
            secret_sealed=sealed,
            secret_key_id=key_id,
            if_secret_sealed=row["secret_sealed"],
        )
        _count(result, landed)


def _sweep_pending(store, cipher, report: RotationReport) -> None:
    """Pending flows: live ones re-sealed, unrecoverable ones deleted, the rest left.

    Re-sealing rather than skipping is what lets a person mid-consent-screen survive a
    rotation — the callback opens by the stored key id, which this keeps current.

    **The two failures are told apart, which the first version of this did not do.** A
    row naming a key this process does not hold is one a restored key would open, so it
    is reported and left exactly like the other three tables — the sweep never destroys
    what putting a key back would recover, and this table is no exception to that rule.
    A row whose key *is* held and still will not authenticate is unrecoverable by any
    key, and its only possible future is a 503 in the face of whoever's callback lands
    on it; deleting turns that into "start again from the Connections page", which is
    strictly better and is the one destructive branch in this module.

    Either way the row dies at its own TTL within the quarter hour, which is what keeps
    both answers cheap. The `state` never lands in the report: it is a bearer handle
    for one flow, and a report is printed.
    """
    result = _contained(report, "pending_authorizations")
    for row in store.pending_authorizations_not_sealed_under(cipher.key_id):
        aad = crypto.pending_authorization_aad(row["tenant_id"], row["state"])
        key_id = row["key_id"]

        if key_id not in cipher.key_ids:
            report.stranded.append(
                Stranded(
                    table="pending_authorizations",
                    address=_when(row["created_at"], row["tenant_id"]),
                    key_id=key_id,
                    reason=f"names key '{key_id}', which this process does not hold",
                    remedy=(
                        "nothing, unless the key comes back within the quarter hour: "
                        "the flow expires on its own and the person starts again from "
                        "the Connections page"
                    ),
                    blocks=False,
                    needs_a_person=False,
                )
            )
            continue

        try:
            plaintext = cipher.open_(
                row["code_verifier"],
                tenant_id=row["tenant_id"],
                aad=aad,
                key_id=key_id,
            )
        except crypto.CryptoError:
            # **Recorded before it is destroyed.** On the three durable tables this
            # exact condition — a blob that will not authenticate under a key we hold —
            # is called a security event and blocks the verdict, and the first version
            # of this folded it into a bare count here, losing both the address and the
            # evidence. The row still goes (no key recovers it, and its only future is
            # a 503 at somebody's callback), but the fact that a verifier was altered
            # or copied out of another flow now reaches the transcript.
            report.stranded.append(
                Stranded(
                    table="pending_authorizations",
                    address=_when(row["created_at"], row["tenant_id"]),
                    key_id=key_id,
                    reason=(
                        f"failed authentication under key '{key_id}', which this "
                        "process holds — the sealed verifier was altered, or copied "
                        "out of another flow. Deleted, because no key recovers it"
                    ),
                    remedy=(
                        "none for the row itself; if this was not a corrupted restore, "
                        "somebody has write access to this table"
                    ),
                    blocks=False,
                    needs_a_person=False,
                )
            )
            if store.consume_pending_authorization(row["state"]) is not None:
                report.unreadable_pending_removed += 1
            continue

        sealed, new_key_id = cipher.seal(
            plaintext, tenant_id=row["tenant_id"], aad=aad
        )
        landed = store.reseal_pending_authorization(
            row["state"],
            code_verifier=sealed,
            key_id=new_key_id,
            if_code_verifier=row["code_verifier"],
        )
        _count(result, landed)


def _opened(cipher, report, table, address, key_id, blob, tenant_id, aad):
    """The plaintext, or None with the row recorded as stranded.

    The two None cases are the module docstring's first two kinds: a key this process
    does not hold (skipped, non-blocking), and a blob that will not authenticate under
    a key it does (skipped, blocking iff the key is retired — which it is whenever this
    branch is reached, since the row is in the not-current population and its key is
    held).
    """
    remedy = _REMEDIES[table]
    if key_id not in cipher.key_ids:
        report.stranded.append(
            Stranded(
                table=table,
                address=address,
                key_id=key_id,
                reason=f"names key '{key_id}', which this process does not hold",
                remedy=(
                    "if that key was dropped from the list too early, put it back in "
                    f"{crypto.OLD_KEYS_ENV} and run this again; otherwise " + remedy
                ),
                blocks=False,
            )
        )
        return None
    try:
        return cipher.open_(blob, tenant_id=tenant_id, aad=aad, key_id=key_id)
    except crypto.CryptoError:
        report.stranded.append(
            Stranded(
                table=table,
                address=address,
                key_id=key_id,
                reason=(
                    f"failed authentication under key '{key_id}' — the blob was "
                    "altered, or copied from another row. A security event, not a "
                    "rotation artifact"
                ),
                remedy=remedy,
                blocks=key_id in report.retired_key_ids,
            )
        )
        return None


def _when(created_at, tenant_id: str) -> str:
    """A consent flow's address: when it began and whose it is — never its `state`.

    Rendered in UTC explicitly. `pending_authorizations.created_at` is `TIMESTAMPTZ`
    and psycopg hands it back in the connection's session timezone, so a literal `Z`
    on an unconverted value is a transcript that misstates the time by an offset
    nobody can see. Every other UTC rendering in this codebase converts first.
    """
    from datetime import timezone

    stamp = created_at.astimezone(timezone.utc) if created_at is not None else None
    when = f"{stamp:%Y-%m-%d %H:%M}Z" if stamp else "at an unrecorded time"
    return f"a consent flow begun {when}, tenant {tenant_id}"


def _count(result: TableSweep, landed: bool) -> None:
    if landed:
        result.resealed += 1
    else:
        result.changed_underneath += 1


def _census(store, current_key_id: str) -> dict:
    """The done-when query: per table, every key id still named, with row counts.

    `sealed_key_id_census` rather than a second pass over the four fetches, which is
    what this was and which pulled every credential in the deployment into memory
    twice per run — the second time only to count the strings beside them. Counting
    key ids is a `GROUP BY`, and this module's whole thesis is that a blob is handled
    as little as possible.
    """
    return {
        table: {
            key_id: rows for key_id, rows in counts.items() if key_id != current_key_id
        }
        for table, counts in store.sealed_key_id_census().items()
    }


__all__ = [
    "RotationReport",
    "Stranded",
    "TableSweep",
    "sweep",
]
