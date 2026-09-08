"""Connecting somebody's own account to a connector.

The write half of delegated credentials. `core/credentials.py` reads them; this is
where one arrives, gets sealed, and becomes a row.

**It lives here rather than in `cli.py` on purpose.** A credential arrives three ways
before this is finished — pasted into a command today, returned by an OAuth consent
flow in 7b, and posted to an HTTP route once there is a UI — and each of those is a
different way of *obtaining* the same secret, not a different thing to do with it. Put
the sealing in the CLI and the OAuth callback reimplements it, which means two places
that can disagree about what a credential is bound to. There is only one such place.

**Step 7b is the second of those three, and it changed nothing about that sentence.**
`access/oauth.py` performs the whole consent dance and then calls `connect_account`,
exactly as `--connect-account` does. What it hands over is a different *shape* of
credential — an access token, a refresh token and an expiry rather than a bare string —
and that is the only concession this module makes to it.

**Connector ids are opaque strings here.** This module never asks whether a connector
exists, what transport it speaks, or what tools it has — the same containment
`core/credentials.py` keeps, for the same reason: `access/` sits above `core/` and
beside `agents/`, and it may not know what an MCP server is. The check that a connector
can actually *carry* a per-user credential belongs where the transport is known, and it
is enforced at the point that matters — when a run tries to use one. See
`tools/mcp.check_delegation_supported`.

**Migration 021 makes the database ask the existence question, and that paragraph still
stands.** `connections_connector_fk` refuses a credential naming a connector this tenant
has not vetted. Nothing above changes: this module still asks nothing and still imports
nothing about MCP — Postgres asks, which is the one participant already entitled to know
that `connections.connector_id` points at `connectors`. What changed is *when* a person
finds out. A credential sealed against a connector that does not exist is unusable, and
until 021 it was stored happily and failed at the first run that needed it, long after
whoever pasted it had moved on. It is now a `ConnectionRefused` at the moment of
connecting.

The distinction worth keeping: **existence** is the database's question, answered here;
**capability** is still `tools/mcp.check_delegation_supported`'s, and still deferred to a
run. A stdio connector exists and cannot carry a delegated credential — the shipped
GitHub one is exactly that — so passing the first check says nothing about the second.

## The two shapes a credential comes in, and why the kind is derived rather than passed

A pasted token is a string. An OAuth connection is an access token, a refresh token and
two expiries, and it has to be all of them or it is a connection that dies in an hour
with no way back. So `connect_account` accepts either a `str` or an `OAuthTokens`, and
**derives** `credential_kind` from which it got.

Derived rather than supplied, on `Connector.read_only`'s precedent: a caller that passes
both a bare string and `kind="oauth"` has written a row that describes itself wrongly,
and nothing downstream can tell — the reader would decode a JSON object out of a value
that is not one and raise somewhere unrelated. There is no combination of arguments here
that produces a mislabelled row, which is a stronger guarantee than a validated one.

The *column* stays explicit for the reason migration 024 gives: the reader must not have
to decrypt a value in order to work out how to read it.
"""

import json
from dataclasses import dataclass
from datetime import datetime

from .. import storage
from ..core import crypto
from ..storage import OAUTH_CREDENTIAL, STATIC_CREDENTIAL, UnknownConnectorError


class ConnectionRefused(RuntimeError):
    """This account cannot be connected, and the reason is safe to explain.

    Deliberately not `NoAccess`. That exception means "this may not exist and you may
    not have it", and answers 404 without elaborating. This one means the caller is
    entitled to do what they asked and *this particular* request is wrong — which is
    exactly the distinction between `NoAccess` and `ShareRefused` in `grants.py`, and it
    was worth a real bug there to learn.
    """


@dataclass(frozen=True)
class OAuthTokens:
    """What a token endpoint gave back, less everything we do not keep.

    Deliberately **not** the token response. A provider's JSON carries a token type, a
    scope echo, sometimes an `id_token`, and any number of vendor extensions — and a
    dataclass that mirrored it would be a promise to store a third party's schema in our
    database and keep up with it. What is kept is what is *used*: the token calls are
    made with, the token that renews it, and when each dies.

    `refresh_token` is allowed to be empty and that is a real configuration, not a
    degenerate one: a provider asked for no `offline_access` scope issues none, and the
    connection then works until the access token expires and asks for re-consent. It is
    surfaced honestly rather than refused, because refusing would mean guessing at every
    vendor's spelling of the scope that produces one.
    """

    access_token: str
    refresh_token: str = ""
    expires_at: datetime | None = None
    refresh_expires_at: datetime | None = None

    # `{access, refresh}`, and the key names are short because this is sealed and stored
    # per person per connector — but they are *names*, not positions, so a later field
    # can be added without every existing row becoming unreadable. A tuple or a
    # delimiter-joined string would have made that a migration over ciphertext nobody can
    # decrypt in bulk.
    ACCESS = "access"
    REFRESH = "refresh"

    def sealed_form(self) -> str:
        """The plaintext that goes into the ciphertext. See migration 024."""
        return json.dumps(
            {self.ACCESS: self.access_token, self.REFRESH: self.refresh_token},
            separators=(",", ":"),
        )


def connect_account(
    principal,
    connector_id: str,
    credential,
    *,
    account_label: str = "",
    expires_at=None,
    actor: str,
) -> dict:
    """Seal a credential and store it as this principal's own for this connector.

    `credential` is a bare token (`--connect-account`) or an `OAuthTokens` (7b's consent
    flow). See the module docstring for why the stored `credential_kind` is derived from
    which rather than passed alongside.

    Replaces an existing connection rather than refusing: reconnecting is how a rotated
    or expired token gets fixed, and making somebody disconnect first would leave a
    window in which they have no credential at all.

    `actor` is who performed the connection, and it is required — `storage.NO_ACTOR`'s
    rule, and this is the method `DEFERRED.md` named as the administrative log's
    remaining scope. For a consent flow it is the person themselves; for
    `--connect-account` it is the operator at the shell. **Those are different facts and
    the whole reason the parameter is not defaulted to the principal**: an operator
    holding somebody's token is precisely the situation this step exists to end, and a
    log that could not distinguish it from self-service could not show that it had.

    Returns the metadata row, so a caller can report what it did without holding the
    secret it just wrote. Nothing here returns a credential, ever.
    """
    if isinstance(credential, OAuthTokens):
        plaintext = credential.access_token.strip()
        kind = OAUTH_CREDENTIAL
        refresh_expires_at = credential.refresh_expires_at
        expires_at = credential.expires_at if expires_at is None else expires_at
        sealed_plaintext = credential.sealed_form()
    else:
        plaintext = (credential or "").strip()
        kind = STATIC_CREDENTIAL
        refresh_expires_at = None
        sealed_plaintext = plaintext

    if not plaintext:
        raise ConnectionRefused(
            "no credential was supplied. Nothing was stored — an empty credential "
            "would be a connection that exists and cannot authenticate, which is worse "
            "than no connection at all."
        )

    if not connector_id:
        raise ConnectionRefused("a connection must name the connector it is for")

    # Bound to exactly this row's identity, so the stored value fails to decrypt if it
    # is ever moved to another principal, another tenant, or another connector.
    aad = crypto.connection_aad(
        principal.tenant_id, principal.kind, principal.id, connector_id
    )
    ciphertext, key_id = crypto.seal(
        sealed_plaintext, tenant_id=principal.tenant_id, aad=aad
    )

    store = storage.active()
    try:
        store.save_connection(
            principal.tenant_id,
            principal.kind,
            principal.id,
            connector_id,
            ciphertext=ciphertext,
            key_id=key_id,
            expires_at=expires_at,
            account_label=account_label,
            credential_kind=kind,
            refresh_expires_at=refresh_expires_at,
            actor=actor,
        )
    except UnknownConnectorError as exc:
        # Migration 021. `ConnectionRefused` rather than letting this out, for the
        # reason that class exists: the caller is entitled to connect and *this request*
        # is wrong, which is a sentence a person can act on. Every other StorageError
        # reaching the CLI or a route is a 503, and "the database is unavailable" is the
        # wrong thing to tell somebody who mistyped a connector name.
        raise ConnectionRefused(str(exc)) from exc

    rows = store.list_connections(
        principal.tenant_id,
        principal_kind=principal.kind,
        principal_id=principal.id,
    )
    return next(row for row in rows if row["connector_id"] == connector_id)


def disconnect_account(
    principal, connector_id: str, *, actor: str, detail: dict | None = None
) -> bool:
    """Remove this principal's credential for this connector. Returns whether one went.

    A delete rather than a flag, so the ciphertext is genuinely gone. Idempotent, and
    the boolean is only so a caller can say "there was nothing to disconnect" instead of
    claiming to have done something.

    **This does not revoke anything upstream, and it deliberately does not try.** For an
    OAuth connection the revocation is a network call to a third party, which is
    `access/oauth.disconnect`'s job — see decision 12 for the ordering, which is
    revoke-then-delete and matters. This function is the local half both paths end at,
    and `detail` is how the caller reports what happened upstream: `revoked_upstream`
    lands in the administrative record, so *"is that token still live at Atlassian"* is
    answerable afterwards rather than being a shrug.

    **This does not stop a run already holding the credential.** The fetch happened at
    the tool call and Python cannot interrupt a thread — the same constraint the request
    timeout and the grant check both have.
    """
    return storage.active().delete_connection(
        principal.tenant_id,
        principal.kind,
        principal.id,
        connector_id,
        actor=actor,
        detail=detail,
    )


def list_accounts(tenant_id: str, principal=None) -> list[dict]:
    """Connection metadata for a tenant, or for one principal within it.

    Metadata only — `list_connections` cannot return ciphertext, which is enforced by
    the storage method rather than by remembering here. The people who ask "who is
    connected, and as whom" are exactly the people who should not be handed sealed
    credentials in the reply.
    """
    if principal is None:
        return storage.active().list_connections(tenant_id)

    return storage.active().list_connections(
        tenant_id, principal_kind=principal.kind, principal_id=principal.id
    )


__all__ = [
    "ConnectionRefused",
    "OAuthTokens",
    "connect_account",
    "disconnect_account",
    "list_accounts",
]
