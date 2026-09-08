-- People, as this platform knows them.
--
-- A row here is not an account in the usual sense: nobody sets a password and nobody
-- signs up. It is a local record of somebody the customer's identity provider already
-- vouched for, created the first time they log in.
--
-- ## Identity is (issuer, subject), never email
--
-- Every OIDC provider issues a `sub` that is stable for the life of the account.
-- Emails are not stable: people marry, companies migrate domains, priya@acme.com
-- becomes priya@acmegroup.com over a weekend.
--
-- Keying on email means that weekend detaches somebody from their entire audit
-- history — the record still exists, and it now belongs to nobody. Keying on the
-- subject means the email is just an attribute that changed.
--
-- The cost is that `principal_id` is opaque. A log line reading `user:8f2c1a` is less
-- pleasant than `user:priya@acme.com`, and it is the one that stays true — and the one
-- that can be honoured when somebody asks to be forgotten, because the append-only
-- audit table cannot be edited to remove an address.
--
-- ## The subject is scoped to its issuer
--
-- Two providers can and do issue the same `sub` string. It is unique within an issuer
-- and means nothing across them, so the key is the pair.

CREATE TABLE users (
    -- Our own opaque identifier. This is what becomes `Principal.id` and what lands in
    -- every audit record, so it must never be recycled and never be derived from
    -- anything that can change.
    id            TEXT        PRIMARY KEY,

    tenant_id     TEXT        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Who vouched for them, and their permanent identifier there.
    issuer        TEXT        NOT NULL,
    subject       TEXT        NOT NULL,

    -- Display only. Refreshed on every login, because it is the provider's to change
    -- and ours to reflect. Never used to look anybody up.
    email         TEXT        NOT NULL DEFAULT '',
    display_name  TEXT        NOT NULL DEFAULT '',

    -- 'active' | 'disabled'. Exists because revocation is otherwise only as fast as
    -- token expiry: there is no directory sync and no token introspection, so when
    -- somebody has to be cut off *now*, this is the only thing that does it.
    status        TEXT        NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'disabled')),

    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ,

    -- The real identity. One person per (provider, subject), globally — a subject
    -- cannot belong to two customers, because the issuer already decided which
    -- customer it speaks for.
    UNIQUE (issuer, subject)
);

CREATE INDEX users_by_tenant ON users (tenant_id);
