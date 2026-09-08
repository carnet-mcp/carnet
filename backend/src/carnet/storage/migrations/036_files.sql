-- An uploaded file, and the run that points at one. Step 028.
--
-- A task has been text and only text since 015. There was no upload route, no attachment
-- concept and no blob storage anywhere in the codebase, so "summarize this document" —
-- most people's first ask of an agent platform — had no answer.
--
-- ## The shape, and the one it replaced
--
-- Two requests: `POST /files` returns an id, `POST /runs` names it. The rejected
-- alternative was one request with the file glued to the run — no id, no `files` table,
-- and reuse across runs made *unrepresentable* rather than merely refused.
--
-- That version was built first and then deliberately replaced, so the trade is worth
-- writing down rather than rediscovering. **An id is a thing that can be pointed at
-- twice.** With it, "one file, one run" stops being a property of the schema and becomes
-- a rule somebody enforces — here, the ownership check below plus `runs.file_id` holding
-- exactly one value. What the id buys is the reason the register chose it: a large file
-- is uploaded once rather than on every retry, and a slow upload can fail without taking
-- the run with it. The register's row cites Dify, where this contract is load-bearing at
-- a scale this project does not have yet.
--
-- The cost is stated so nobody has to find it: **an orphan is now possible.** A file
-- uploaded and never named by a run is a row nothing collects, and Dify's own documented
-- gap is exactly this. 018's deletion machinery covers the customer-scale answer — the
-- cascade below — and the per-file answer is a register row rather than a promise here.
--
-- ## Why the bytes are not sealed
--
-- Every other BYTEA in this schema is sealed under `core/crypto.py` —
-- `connections.ciphertext` (006), `connector_oauth.client_secret` and
-- `pending_authorizations.code_verifier` (024), `triggers.secret_sealed` (034). Each is a
-- **credential the system holds on somebody's behalf**, and none is content the customer
-- ever needs back in the clear.
--
-- This is not that. An uploaded file is user content, and 015 already decided how user
-- content is held: `task` and `answer` are stored in the clear, with the reasoning
-- written down — encrypting them is a key-scope and retention decision, and folding it
-- into a migration would settle it by accident. A file arrives to be described by a task
-- that sits in plaintext beside it. Sealing one and not the other is a lock on one drawer
-- of an open cabinet: it buys the appearance of protection and none of the substance, and
-- it enrols 10 MiB blobs in the key rotation 026 just made finishable.
--
-- User content is sealed as ONE decision — `task`, `answer` and `content` together — or
-- not at all. Recorded in the register.

CREATE TABLE files (
    -- The id the whole design turns on. Random and opaque, like `run_id`, and **globally
    -- unique rather than per tenant** for `run_id`'s reason inverted: a caller quotes
    -- this back on a later request, so the lookup that resolves it must name one row in
    -- the table. The tenant is then a *filter* on that row, never part of the key — the
    -- same shape `get_run` uses, and what makes another customer's id indistinguishable
    -- from one that does not exist.
    id           TEXT        PRIMARY KEY,

    tenant_id    TEXT        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- **Who uploaded it, and therefore who may use it.** The register's contract in two
    -- columns: only a request carrying this principal may name this file on a run.
    --
    -- The pair rather than a `users` foreign key, matching `runs` and `audit` — a
    -- principal may be `machine:m_nightly` or `system:cli`, neither of which is a row in
    -- `users`. It is also what makes the rule survive offboarding without a second
    -- mechanism: the person's grants go, and a file they uploaded is addressable by
    -- nobody.
    --
    -- Note what this is NOT: a grant. There is no sharing verb for a file and no role
    -- ladder over one. 006 built sharing for agents because an agent is a thing
    -- colleagues collaborate on; a file handed to one run is not, and giving it a grant
    -- table would be the first half of the library this step declines to build.
    owner_kind   TEXT        NOT NULL,
    owner_id     TEXT        NOT NULL,

    -- What the person called it. Stored to be shown back and never trusted: it is not a
    -- path, nothing opens it, and the media type below is decided by reading the bytes
    -- rather than by believing this string or its extension.
    filename     TEXT        NOT NULL CHECK (filename <> ''),

    -- Verified against the content before the row exists — `%PDF-` for a PDF, a
    -- successful UTF-8 decode for the text types. A caller may declare anything; what
    -- lands here is what the bytes actually are.
    --
    -- The allowlist, the per-type ceilings and the deployment blacklist all live in
    -- `config.py` rather than in a CHECK. They are product and deployment decisions that
    -- move — a blacklist is meant to be set per install — and under 027's promise a CHECK
    -- moves only by a new migration, which is the wrong amount of friction for a knob an
    -- operator is expected to turn.
    media_type   TEXT        NOT NULL CHECK (media_type <> ''),

    -- Plain bytes. See the header for why this is not sealed.
    --
    -- The CHECK is the **absolute** ceiling, not the per-type one. Per-type caps are
    -- policy and live in config; this is the number past which a row is not a document
    -- anybody meant to send, and it exists to refuse a path that never passed the door —
    -- a direct INSERT, a future caller, a bug that skipped validation. That is the
    -- difference between a limit and a promise, and it is why this one number is worth
    -- stating twice.
    content      BYTEA       NOT NULL CHECK (octet_length(content) <= 10485760),

    -- Content-addressed identity, and it does real work rather than being a checksum for
    -- its own sake. It is what an API response and an audit line carry, so a reader can
    -- confirm a run used the document they think it did — two files called `report.pdf`
    -- is the ordinary case, not the edge one.
    --
    -- There is deliberately **no download route**. The platform is not the custodian of a
    -- copy somebody else needs back; the uploader has the file, and a route that serves
    -- it back is the next brick of the library.
    sha256       TEXT        NOT NULL CHECK (char_length(sha256) = 64),

    -- Redundant with `octet_length(content)` and stored anyway, so a metadata read is a
    -- metadata read. Describing a file must not drag it off TOAST to report a number the
    -- writer already knew.
    byte_size    INTEGER     NOT NULL CHECK (byte_size > 0),

    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The deletion sweep, and the read that enforces ownership. `delete_tenant` empties
-- TENANT_BLOCKING_TABLES explicitly and lets the rest cascade; without this index that
-- cascade degrades into a sequential scan of the largest table in the schema. Postgres
-- does not index a foreign key's referencing side on its own.
CREATE INDEX files_tenant ON files (tenant_id);

-- "What have I uploaded?" — and, more to the point, the shape the ownership check reads.
CREATE INDEX files_owner ON files (tenant_id, owner_kind, owner_id);


-- The run's side of it: which file this run was given.
--
-- **No foreign key, deliberately, and it is 015's argument unchanged.** That migration
-- gave `runs.agent` no key to `agents` because *a run is history*: deleting an agent must
-- not delete the record of what it did, and an owner who could erase their agent's trail
-- by deleting it has an audit log that answers to the person it is auditing. A file is
-- the same kind of fact. A run that summarized a document must keep saying so after the
-- document is gone, and `ON DELETE SET NULL` would quietly rewrite history instead.
--
-- '' rather than NULL for "this run had no file", matching `idempotency_key` beside it
-- and unlike `parent_run_id`: the NULL spelling belongs to columns that carry a key, and
-- two representations of absent is a thing every reader then has to handle.
--
-- One column rather than a join table, because one run still takes at most one file. The
-- id makes a file reusable *across* runs, which is what it was chosen for; it does not
-- make a run take several, which nothing has asked for.
ALTER TABLE runs ADD COLUMN file_id TEXT NOT NULL DEFAULT '';
