"""Email + password accounts, in the provider's own SQLite file.

Deliberately not the product's Postgres: the provider authenticating against state the
product cannot reach is what makes "a provider you run" literally true, and the
product's migration series stays free of schema that exists only for one provider.
The file lives beside the signing key in the front door's state directory, so "back up
the local deployment" is "copy one directory" either way.

Passwords are scrypt (stdlib, OpenSSL-backed): n=2^15, r=8, p=1, a 16-byte salt, and a
self-describing record — ``scrypt$32768$8$1$<salt_b64>$<hash_b64>`` — so a future move
to argon2id is a rehash on next login, not a schema change. Comparison is
`hmac.compare_digest`; lookups are case-insensitive on the address because two accounts
apart by case are one person locked out of both.
"""

import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

# Not RFC 5322 — a floor. One @, no whitespace or angle brackets, a dot somewhere in
# the domain. This address becomes the product's `users.email`, the thing shares are
# matched against and screens display; an address that could never receive mail or
# match a share is refused here, at the door, with a sentence.
_EMAIL = re.compile(r"^[^@\s<>\"',;]+@[^@\s<>\"',;]+\.[^@\s<>\"',;]+$")

# 128 * r * n bytes is exactly 32MiB at these parameters; OpenSSL's default ceiling is
# the same number, and "exactly at the limit" is the wrong side of a >= somewhere.
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_MAXMEM = 64 * 1024 * 1024

# How many scrypt computations may run at once — step 051, blocker B2 of plan 049. Each
# scrypt above is 32 MiB of working memory, and the login path runs on a
# `ThreadingHTTPServer` whose thread pool is unbounded, so without this a few hundred
# concurrent `POST /idp/login` requests each start a 32 MiB hash at once and exhaust the
# host. The guard makes peak scrypt memory `permits * 32 MiB` — a number an operator can
# reason about — by making the excess requests block on the semaphore rather than each
# allocate. Every hashing path (`hash_password`, `check_password`) holds it, so the login,
# register and password-set paths are all covered with nothing to remember at the callers.
# Default 4 (128 MiB in flight): more than any real single-node login rate, far short of a
# problem. A `BoundedSemaphore` so a release without a matching acquire is a loud bug.
_SCRYPT_MAX_CONCURRENCY = max(
    1, int(os.environ.get("CARNET_LOCAL_SCRYPT_CONCURRENCY") or 4)
)
_SCRYPT_GUARD = threading.BoundedSemaphore(_SCRYPT_MAX_CONCURRENCY)


def _scrypt(password: bytes, **kwargs) -> bytes:
    """`hashlib.scrypt`, but never more than `_SCRYPT_MAX_CONCURRENCY` at once."""
    with _SCRYPT_GUARD:
        return hashlib.scrypt(password, **kwargs)


# One writer at a time through this module. Step 064, and it is about the *connection*
# rather than the database.
#
# `open_db` hands one `sqlite3.Connection` to every thread of a `ThreadingHTTPServer`
# (`check_same_thread=False`). SQLite is built serialized here, so no two calls corrupt
# each other — but a connection has ONE implicit transaction, and it is shared. Thread A
# executing while thread B commits means B commits A's half-written statement and A's
# cursor is reset underneath it, which surfaces as `sqlite3.InterfaceError: bad
# parameter or other API misuse` or as a read-back that inexplicably finds nothing.
# Driven with twelve concurrent registrations, that appears in roughly a third of runs.
#
# So every write sequence — statement, commit, and the read-back that must see it —
# happens under this lock, and what a caller gets when it loses a race is the refusal
# the code wrote rather than a 500 about API misuse.
#
# **This is not what makes `only_if_first` atomic.** That is the INSERT's own `WHERE`,
# which is one statement and would hold against a second process this lock cannot see.
# The lock is for the shared connection; the `WHERE` is for the invariant.
_WRITE_LOCK = threading.Lock()


MIN_PASSWORD_LENGTH = 8

_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
  id           TEXT PRIMARY KEY,
  email        TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password     TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  disabled     INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT NOT NULL
);
"""


class AccountError(RuntimeError):
    """A caller mistake with a sentence a form can show."""


class DuplicateEmail(AccountError):
    pass


class WeakPassword(AccountError):
    pass


class RegistrationClosed(AccountError):
    """Somebody else took the one account a closed deployment admits. Step 064.

    Raised by `create_account(only_if_first=True)` when the store was not empty by the
    time the INSERT ran. Its own class because the handler renders it as the
    registration-closed page rather than as a form error beside a field: nothing the
    person typed was wrong.
    """


def open_db(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute(_SCHEMA)
    db.commit()
    # Owner-only, matching what `frontdoor` already does for `secret.key` and what
    # `provider` does for the signing PEM and the cookie key. This file was the one
    # secret left at the process umask, which on a shared host means the scrypt records
    # are world-readable — strong enough to survive that and not supposed to be tested.
    #
    # After the schema write, not before: WAL mode creates `-wal` and `-shm` beside the
    # database on first use, and chmod'ing a file that does not exist yet is a no-op that
    # looks like a control. Best-effort because a filesystem without POSIX modes is a
    # worse place to raise than to continue.
    for suffix in ("", "-wal", "-shm"):
        try:
            os.chmod(f"{path}{suffix}", 0o600)
        except OSError:
            pass
    return db


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = _scrypt(
        password.encode(),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        maxmem=_SCRYPT_MAXMEM,
    )
    return "$".join(
        (
            "scrypt",
            str(_SCRYPT_N),
            str(_SCRYPT_R),
            str(_SCRYPT_P),
            base64.b64encode(salt).decode(),
            base64.b64encode(digest).decode(),
        )
    )


def check_password(password: str, record: str) -> bool:
    """True when `password` produced `record`.

    Reads the parameters out of the record rather than out of the constants, so a
    record written under yesterday's parameters — or a scheme this module has since
    moved past — still verifies for as long as its scheme is one we can compute.
    """
    try:
        scheme, n, r, p, salt_b64, digest_b64 = record.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        digest = _scrypt(
            password.encode(),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
            maxmem=_SCRYPT_MAXMEM,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, expected)


def create_account(
    db: sqlite3.Connection,
    email: str,
    password: str,
    display_name: str = "",
    *,
    only_if_first: bool = False,
) -> dict:
    """Create an account. `only_if_first` admits it **only into an empty store**.

    ## Why the condition is in the statement — step 064

    The edge used to ask `count(db) > 0` and then call this, which is two statements
    with a thread switch between them and, worse, a deliberately slow scrypt: the
    window between the check and the insert is hundreds of milliseconds wide, not a few
    instructions. Two concurrent registrations against an empty store both read zero and
    both inserted — on the deployment shape where registration defaults to *closed*
    precisely because it is exposed. The comment claimed the window was "one account
    wide at both"; under concurrency it was as wide as the traffic.

    A lock in the handler would have fixed the observed race and left the rule in the
    handler, where the third path to account creation would miss it. So the invariant
    is the INSERT's own `WHERE`: one statement, atomic against every other writer on
    this connection, and the database is what says "exactly one" rather than a comment.

    Zero rows inserted is `RegistrationClosed` — somebody else was first.
    """
    email = email.strip()
    if not _EMAIL.match(email):
        raise AccountError("that does not look like an email address.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPassword(
            f"passwords are at least {MIN_PASSWORD_LENGTH} characters here."
        )

    row = {
        "id": f"lu_{uuid.uuid4().hex[:16]}",
        "email": email,
        "password": hash_password(password),
        "display_name": display_name.strip(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    # `INSERT ... SELECT ... WHERE` rather than `VALUES`, so the emptiness test is
    # evaluated inside the same statement that writes — which is the whole point.
    statement = (
        "INSERT INTO accounts (id, email, password, display_name, created_at)"
        " VALUES (:id, :email, :password, :display_name, :created_at)"
        if not only_if_first
        else "INSERT INTO accounts (id, email, password, display_name, created_at)"
        " SELECT :id, :email, :password, :display_name, :created_at"
        " WHERE (SELECT count(*) FROM accounts) = 0"
    )
    # The hash is computed OUTSIDE the lock, deliberately: scrypt is the slow part and
    # it needs no connection, so holding a write lock across it would serialize every
    # registration behind somebody else's key derivation for no gain.
    with _WRITE_LOCK:
        try:
            cursor = db.execute(statement, row)
            db.commit()
        except sqlite3.IntegrityError:
            raise DuplicateEmail(
                "an account with that address already exists. Sign in instead."
            ) from None
        if only_if_first and cursor.rowcount == 0:
            raise RegistrationClosed(
                "registration is closed on this deployment, and the first account has "
                "already been created. An administrator can invite you."
            )
        created = get_account(db, email)
    if created is None:
        # The INSERT committed one statement ago, so this is unreachable short of the
        # database going away underneath us. It is a raise rather than an assert
        # because the signature promises a dict and `-O` strips asserts.
        raise AccountError("the account was written and could not be read back.")
    return created


def get_account(db: sqlite3.Connection, email: str) -> dict | None:
    row = db.execute(
        "SELECT * FROM accounts WHERE email = ? COLLATE NOCASE", (email.strip(),)
    ).fetchone()
    return dict(row) if row else None


def get_account_by_id(db: sqlite3.Connection, account_id: str) -> dict | None:
    row = db.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
    return dict(row) if row else None


def verify_login(db: sqlite3.Connection, email: str, password: str) -> dict | None:
    """The account, when the password is right and the account is live; else None.

    One answer for "no such account", "wrong password" and "disabled" — the login form
    should not be an oracle for which addresses have accounts.
    """
    account = get_account(db, email)
    if account is None:
        # Burn the same work as a real check so timing does not answer the question
        # the return value refuses to.
        check_password(password, hash_password("timing-equalizer"))
        return None
    if not check_password(password, account["password"]) or account["disabled"]:
        return None
    return account


def set_password(db: sqlite3.Connection, email: str, password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPassword(
            f"passwords are at least {MIN_PASSWORD_LENGTH} characters here."
        )
    # Hashed before the lock, for `create_account`'s reason; written under it, for the
    # shared-connection reason beside `_WRITE_LOCK`.
    digest = hash_password(password)
    with _WRITE_LOCK:
        updated = db.execute(
            "UPDATE accounts SET password = ? WHERE email = ? COLLATE NOCASE",
            (digest, email.strip()),
        )
        db.commit()
        if updated.rowcount == 0:
            raise AccountError(f"no account for {email.strip()!r}.")


def count(db: sqlite3.Connection) -> int:
    return db.execute("SELECT count(*) FROM accounts").fetchone()[0]
