-- A push on absence: a person the directory told us about before they ever signed in,
-- and the credential the directory presents when it tells us.
--
-- Step 071. Claims are a pull on presence — `access/directory.py` runs on every sign-in
-- and can only ever run for somebody who is *here*. Offboarding is a push on absence: a
-- person deleted in the IdP never signs in again, so nothing reconciles, so nothing
-- revokes. SCIM is the directory calling us, and this migration is what it needs to
-- have somewhere to land. Three changes, each a decision the plan records in full.
--
-- ## `users.subject` loses NOT NULL
--
-- Identity has been `(issuer, subject)` since migration 008 and it still is. What
-- changes is that a row may now exist *before* its subject is known: a SCIM
-- `POST /Users` describes a person who has not signed in yet, and the subject is
-- whatever `subject_claim` names in a token that person has not been issued. The
-- first sign-in adopts the row — a compare-and-set on `subject IS NULL`, once, recorded
-- as `user.adopt`. `UNIQUE (issuer, subject)` is untouched: NULLs are distinct to a
-- unique constraint, so two provisioned rows coexist, and the moment either gains a
-- subject the constraint means exactly what it meant before.
--
-- The rule that goes with it lives in both stores rather than here, because no CHECK can
-- express it: **`find_user` never matches a null subject.** A provisioned row has no
-- subject and must never be found by an empty one — `find_user(issuer, "")` is a token
-- with a blank claim, and the answer to that is *nobody*, not *the first person the
-- directory mentioned*.
--
-- ## `users.external_id` is a column
--
-- Entra's `sub` is pairwise — a different opaque value per application, never the
-- directory object id — while the `externalId` a SCIM push carries *is* the object id.
-- So the push's identifier cannot be the subject without asking every Entra customer to
-- reconfigure `subject_claim` to `oid`, and a row keyed on the wrong one produces two
-- accounts for one person: one SCIM made, one the first sign-in made, with the
-- deprovision disabling the row nobody uses. A column of its own is the answer.
-- `UNIQUE (tenant_id, issuer, external_id) WHERE external_id IS NOT NULL` is the shape
-- `groups.external_id` has carried since migration 017, one column wider because the
-- id is the *directory's* and a tenant may register more than one directory.
--
-- No default and no backfill: NULL is precisely true of every existing row, because no
-- directory has pushed anybody yet. One ADD COLUMN with no default is metadata-only, so
-- `users` is not rewritten however large it is.
--
-- ## `scim_tokens` is hashed, not sealed
--
-- Migration 031's argument, verbatim: a presented secret needs a digest rather than a
-- ciphertext, a digest keeps the row out of the key-rotation population, and a dump of
-- this table does not impersonate the directory. Same shape as `api_tokens` — a row
-- whose id is the lookup key and whose `secret_hash` is what a presented credential is
-- compared against — and the same discipline: the store never sees the plaintext, and
-- `find_scim_token` is the one method that returns the hash.
--
-- **Bound to an issuer, not only a tenant.** A provisioned row needs an issuer for
-- adoption to have a key, and `tenant_idps` may hold more than one per customer. No
-- foreign key, because that table has no single-column key to reference; minting
-- refuses an issuer the tenant has not registered, and resolving refuses a token whose
-- issuer row has since gone, with the same sentence at both ends.
--
-- `revoked_at`/`revoked_by` rather than a DELETE, on 031's rule: every record the
-- directory writes names `system:scim:<id>` as its actor, and this row is the only
-- place that string resolves to a name and a minter after the token is gone.
--
-- The tenant policy line is here rather than in 037's walk because 037 ran before this
-- table existed; the contract suite's catalog guard fails by name when it is forgotten.

ALTER TABLE users
    ALTER COLUMN subject DROP NOT NULL;

ALTER TABLE users
    ADD COLUMN external_id TEXT;

CREATE UNIQUE INDEX users_by_external_id
    ON users (tenant_id, issuer, external_id)
    WHERE external_id IS NOT NULL;

CREATE TABLE scim_tokens (
    id            TEXT        PRIMARY KEY,
    tenant_id     TEXT        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Which of this tenant's providers the pushes speak for. Checked at mint and at
    -- resolve, against `tenant_idps`; not a foreign key, because that table's key is
    -- `(issuer, discriminator_claim, discriminator_value)` and a token binds to the
    -- issuer alone.
    issuer        TEXT        NOT NULL,

    -- What `--list-scim-tokens` shows. The one field a person chose.
    name          TEXT        NOT NULL CHECK (name <> ''),

    -- The digest of the secret, never the secret. See migration 031.
    secret_hash   TEXT        NOT NULL,

    created_by    TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    revoked_at    TIMESTAMPTZ,
    revoked_by    TEXT,

    -- Stamped on every resolution. The question an offboarding review asks that
    -- nothing else answers: is the directory still talking to us?
    last_used_at  TIMESTAMPTZ
);

CREATE INDEX scim_tokens_by_tenant ON scim_tokens (tenant_id);

ALTER TABLE scim_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scim_tokens TO agent_runtime_tenant
    USING (tenant_id = agent_runtime_tenant_id());
