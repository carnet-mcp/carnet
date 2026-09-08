-- Per-user OAuth: the credential a person gives themselves.
--
-- Step 7a built delegated credentials and there has only ever been one way to fill the
-- row — `--connect-account`, on the deployment host, with the token pasted in. So the
-- operator obtains and sees each person's third-party token, which is precisely the
-- thing delegated credentials exist to avoid. This migration is the storage half of
-- closing that: a person clicks Connect, the provider redirects, and the token goes
-- from the provider's token endpoint straight into `connections` without touching the
-- browser or the operator.
--
-- Three separate things live here and they are easy to conflate, so they are described
-- separately below: what a *connection* now records, what an *OAuth application* is,
-- and where a consent flow keeps its secret while it is in flight.
--
-- ## What plan 007b's decision 9 got wrong, recorded because the next reader will
-- ## otherwise re-derive it
--
-- The plan lists `connections.updated_at` as one of this migration's columns, on the
-- grounds that *"`connections` has a four-column primary key, `created_at`, and
-- `account_label` from 013 — and no version of any kind"*. It has one. **Migration 013
-- added `updated_at` in the same ALTER as `account_label`**, for the reason decision 11
-- now needs it: *"reconnecting replaces a credential in place, and 'when did this last
-- change' is the first question asked when somebody's agent starts failing"*. Both
-- stores already return it — it is in `_CONNECTION_META_COLUMNS` and in the in-memory
-- row — so the compare-and-set has had something to compare against for eleven steps
-- and this migration adds no column for it.
--
-- The plan's *reasoning* survives intact and is why this is worth writing down rather
-- than quietly not doing: a refresh needs a version in the WHERE clause, `agents.
-- updated_at` is the precedent, and the device is the same. Only the column was already
-- there.

ALTER TABLE connections
    -- **The discriminator, never sniffed from the ciphertext's shape.** A static
    -- connection seals a bare token; an OAuth one seals a small JSON object carrying an
    -- access token and a refresh token. Two encodings in one column with the reader
    -- guessing which it has is the implicit sniffing this codebase refuses elsewhere —
    -- `_launch_from_dict` carries an explicit `kind` for the same reason, and a manifest
    -- is not even a secret.
    --
    -- The failure a guess would produce is the bad kind: `json.loads` on a bare token
    -- raises, `json.loads` on a token that happens to be a JSON number does not, and
    -- either way the code that decides has to have already decrypted the value in order
    -- to look at it. A column decides before anything is unsealed.
    --
    -- DEFAULT 'static' with a CHECK, so every row written before this migration is
    -- correctly described by it and no back-fill is needed: they were all pasted in.
    ADD COLUMN credential_kind TEXT NOT NULL DEFAULT 'static'
        CHECK (credential_kind IN ('static', 'oauth')),

    -- The **refresh** token's own expiry, which is a different fact from `expires_at`
    -- (the access token's, and the one `for_connector` already refuses on).
    --
    -- Nullable, and the nullability carries meaning exactly as `expires_at`'s does:
    -- NULL means the provider did not say. Most do not — Atlassian's refresh tokens
    -- last 90 days and are not described in the token response, Google's do not expire
    -- for an active app — so this is populated only when a provider volunteers it.
    -- Without the column, "this connection will need re-consenting" cannot be predicted
    -- at all, only discovered by a run failing.
    ADD COLUMN refresh_expires_at TIMESTAMPTZ,

    -- Why this connection cannot currently be used, in the provider's own terms, or ''
    -- when it is fine.
    --
    -- **A sentence rather than a boolean**, on `AgentDetail.your_role`'s precedent: a
    -- flag plus a message is two fields that can disagree, and what a person needs on
    -- the Connections page is the reason. Empty is the only "it is fine" value, so a
    -- reader branches on truthiness and renders the string.
    --
    -- Set when a refresh comes back `invalid_grant` — consent revoked at the provider,
    -- the refresh token expired, or it was already spent. That is terminal and never
    -- retried: retrying an `invalid_grant` is how one dead connection becomes a
    -- rate-limit incident at somebody's identity provider, and Atlassian additionally
    -- treats reuse of a spent refresh token as a breach signal and kills the grant.
    --
    -- Deliberately NOT a status column with 'active' / 'revoked'. Migration 013 refused
    -- one and the argument holds: a revoked row that still holds live ciphertext is a
    -- worse artifact than no row. This does not describe a revoked credential — it
    -- describes a live row whose *upstream grant* is gone, which is a thing the person
    -- fixes by reconnecting and which must not be silently replaced by the shared
    -- environment variable in the meantime.
    ADD COLUMN reconsent_reason TEXT NOT NULL DEFAULT '';


-- ## The OAuth application, which is configuration and holds a secret
--
-- What an OAuth flow needs that a connector row has nowhere to put: an authorization
-- server's two endpoints, a client id, a client secret, and the scopes to ask for.
-- These are facts about *this server* in the same way its URL is, so they belong beside
-- the connector — and in a table of their own rather than as more JSONB in
-- `connectors.launch`, because one of them is a **secret**.
--
-- `connectors.launch` is the column an operator reads to answer "where does this thing
-- point", and it is printed by `--list-tools` and returned inside a manifest. A sealed
-- value living in a column people read for an unrelated reason is how a client secret
-- ends up in a `psql` transcript, a screenshot, or a support ticket. A separate table is
-- one `SELECT` an operator does not run by accident.
CREATE TABLE connector_oauth (
    tenant_id           TEXT        NOT NULL,
    connector_id        TEXT        NOT NULL,

    -- Where the browser is sent, and where we POST. Stored rather than discovered,
    -- which is decision 3: RFC 8414 metadata discovery and RFC 9728's
    -- protected-resource-metadata are both worth having and neither is load-bearing
    -- once the endpoints are written down. They land with Dynamic Client Registration,
    -- which needs the same plumbing.
    --
    -- **Only the token endpoint's host goes through the egress allowlist**, and the
    -- asymmetry is deliberate: the authorize endpoint is a redirect the *browser*
    -- follows, so nothing of ours dials it and an allowlist entry would be describing a
    -- connection we never make. The token endpoint is a server-side POST carrying the
    -- client secret — the same risk class as dialling the MCP server, checked the same
    -- way, in the same place.
    authorize_endpoint  TEXT        NOT NULL CHECK (authorize_endpoint <> ''),
    token_endpoint      TEXT        NOT NULL CHECK (token_endpoint <> ''),

    -- RFC 7009. Empty when the provider publishes none, which is common and not an
    -- error — see decision 12: disconnecting deletes locally regardless, and a provider
    -- with no revocation endpoint must not leave somebody trapped in a connection they
    -- have asked to end.
    revoke_endpoint     TEXT        NOT NULL DEFAULT '',

    -- Public by construction. It appears in the authorize URL, which is a browser
    -- address bar.
    client_id           TEXT        NOT NULL CHECK (client_id <> ''),

    -- Sealed with the same AES-256-GCM as a credential, because it is one. Bound to
    -- `(tenant, connector)` via `crypto.oauth_app_aad`, so a row lifted into another
    -- tenant's table fails to decrypt rather than working — the same cross-tenant
    -- defence `connections` has had since 006, and the reason the AAD is not merely
    -- decorative here: this table's primary key would happily accept a copied row.
    --
    -- A public client — one with no secret, PKCE only — is legal at many providers and
    -- is NOT supported here, deliberately. This is a confidential client on a server,
    -- which is the whole of decision 1: the browser never holds anything. Allowing an
    -- empty secret would make the difference between the two configurations invisible
    -- in the row, and the security properties are not the same.
    client_secret       BYTEA       NOT NULL,
    key_id              TEXT        NOT NULL,

    -- What we ask the person to consent to, as a JSON array of strings. The
    -- *interesting* half of the record from a review point of view — "what did we ask
    -- for" is the question after an incident, and it is the half that is not a secret.
    --
    -- `offline_access` (or a provider's spelling of it) is what makes the provider
    -- issue a refresh token at all. Not enforced: a connector legitimately configured
    -- without one works until its access token expires and then asks for re-consent,
    -- which is a real if unhappy configuration and is surfaced honestly rather than
    -- refused on a guess about a vendor's vocabulary.
    scopes              JSONB       NOT NULL DEFAULT '[]',

    configured_by       TEXT        NOT NULL CHECK (configured_by <> ''),
    configured_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, connector_id),

    -- **CASCADE, and note the asymmetry with `connections`, which migration 021
    -- deliberately made RESTRICT.** A credential somebody consented to give is
    -- evidence, and destroying it as a side effect of an unrelated administrative
    -- action is what 021 refuses. A client application we registered is configuration:
    -- an OAuth app configured for a connector that no longer exists configures nothing,
    -- and keeping the row would only mean a sealed client secret with no way left to
    -- attribute it.
    FOREIGN KEY (tenant_id, connector_id)
        REFERENCES connectors (tenant_id, id) ON DELETE CASCADE
);


-- ## Where a consent flow keeps its secret while it is in flight
--
-- The security crux of this step, and the reason this is a table rather than a cookie.
--
-- When the provider redirects the browser back to `/connect/callback`, that request is a
-- **plain top-level navigation**. The SPA's bearer token lives in memory and is not on
-- it, so the callback cannot ask `principal_from_request` whose connection this is. The
-- binding has to have been made at `/connect`, where we *did* have an authenticated
-- principal, and carried through a third party's website in the one field OAuth gives us
-- for the purpose: `state`.
--
-- So `state` is an opaque, unguessable, single-use, short-lived handle on a row that
-- says who this flow is for. The callback looks it up and **the row tells it the
-- principal**. That is also the CSRF defence the callback needs: an attacker cannot
-- forge a `state` we never minted, and a replayed one finds nothing because the row is
-- consumed atomically on use.
--
-- A signed value — a JWT we issue, checked on the way back — was considered and refused.
-- The PKCE `code_verifier` is a secret for the life of the flow and has to survive the
-- round trip through the provider's website, so the choice is between a row that is
-- deleted on use and a signed blob carrying a secret we then have to expire anyway. A
-- table that is written, read once and deleted looks like state that ought to be a
-- cookie right up until you notice what it is carrying.
CREATE TABLE pending_authorizations (
    -- The `state` parameter itself, and therefore the primary key. Generated with
    -- `secrets.token_urlsafe`; the CHECK is a floor on length rather than a format,
    -- because the only property that matters is that it cannot be guessed and a
    -- constant in Python is not where that should be enforced alone.
    state           TEXT        PRIMARY KEY CHECK (length(state) >= 32),

    tenant_id       TEXT        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Who this flow is for. The whole reason the row exists — see above.
    principal_kind  TEXT        NOT NULL,
    principal_id    TEXT        NOT NULL,
    connector_id    TEXT        NOT NULL,

    -- PKCE (RFC 7636). Sealed, bound to `(tenant, state)`, because a `code_verifier`
    -- read out of the database is a code interception attack completed for free.
    --
    -- PKCE on a confidential server-side client is belt and braces and is here anyway:
    -- it costs one hash, several providers now require it, and the failure it prevents —
    -- an authorization code intercepted in a redirect chain being exchanged by somebody
    -- else — is one whose other defence is a client secret we would rather not be the
    -- only thing standing in the way.
    code_verifier   BYTEA       NOT NULL,
    key_id          TEXT        NOT NULL,

    -- Sent to the authorize endpoint and sent AGAIN, byte-identical, to the token
    -- endpoint, which is what the spec requires and what providers check. Stored rather
    -- than recomputed so the two are the same string by construction: recomputing it at
    -- the callback from a request header is how a deployment behind a proxy gets an
    -- `invalid_grant` that reads like a code bug.
    redirect_uri    TEXT        NOT NULL CHECK (redirect_uri <> ''),

    -- Where to send the browser when this is over. A path within this app, never a URL:
    -- a stored value that becomes a `Location` header is an open redirect, and the
    -- refusal lives in `access/oauth.py` where the value is minted rather than here,
    -- because "is this a safe place to send somebody" is not a question SQL can ask.
    -- The CHECK is the half that can be: no scheme, no protocol-relative form.
    return_to       TEXT        NOT NULL DEFAULT ''
                        CHECK (return_to = '' OR return_to ~ '^/[^/]'),

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()

    -- **No foreign key on `connector_id`**, unlike `connections`. A pending row is not a
    -- credential and holds nothing of the person's; it is a five-minute handle that is
    -- deleted on use. Making it a dependant of `connectors` would mean a connector
    -- deleted mid-consent produces a RESTRICT failure on an administrative action, to
    -- protect a row that expires by itself. The callback re-reads the connector anyway
    -- and refuses if it has gone, which is the check that matters and the one that
    -- happens at the moment it is true.
);

-- Sweeping. Rows are deleted on use and expire in minutes, but an abandoned consent
-- flow — somebody who clicks Connect and closes the tab — leaves one behind. This is the
-- first thing in the system that wants a scheduler, which does not exist, so the sweep
-- rides on an existing entry point and this index is what makes it a range delete rather
-- than a scan.
CREATE INDEX pending_authorizations_created_at ON pending_authorizations (created_at);
