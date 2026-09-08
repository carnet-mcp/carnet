-- Which claim carries the groups, and what we have already made of it.
--
-- Step 033e, decision 6 of plan 033. A group is only a bulk-sharing story if `eng` is
-- not a list somebody maintains by hand beside Entra, and until this migration it was
-- one: `--group-add` was the only way in, so every joiner needed a second manual step
-- that went stale silently.
--
-- ## `tenant_idps.groups_claim`
--
-- The third claim mapping on this table, and it is per provider for exactly the reason
-- the other two are (migration 010, written because of a real Okta token rather than a
-- spec): whether the claim carries group *names* or group *ids* is a question with a
-- provider behind it. Entra emits object ids in `groups`; Okta emits names, in whatever
-- the authorization server was told to call the claim.
--
-- **Nullable with no default, and that is the whole compatibility story.** `subject_claim`
-- and `email_claim` default to what a conformant token uses, because every token has a
-- subject and an address. A groups claim is not like that: a provider that emits none is
-- ordinary, and a default would make this column a promise the token cannot keep. NULL
-- means *this provider says nothing about groups*, and a tenant whose row is NULL
-- behaves exactly as it did before this migration — no query, no write, no log line.
--
-- ## `users.directory_digest` and `users.directory_synced_at`
--
-- What the reconciliation has already done, so it does not do it again.
--
-- `users.resolve` runs on **every authenticated request** rather than once per session
-- (`api/deps.py`), while the claim set it would read is constant for the life of a
-- token. Recomputing per request would repeat identical work for an hour and make the
-- unmatched-value log line — the only surfacing this step ships — fire on every request
-- forever. So `directory_digest` holds a hash of the claim's name and its sorted values,
-- and the work runs when that changes.
--
-- **This is not a cache of an access answer.** No permission is ever read from these
-- columns: `agent_grant_role` and `granted_agent_names` still read live membership rows
-- in one statement, as they have since 9a. What is remembered here is *work already done
-- for this exact input* — and the input's other half (which groups carry which
-- `external_id`, and which claim the provider is read for) is invalidated at its own
-- write, so the marker is exact rather than a guess with a staleness window.
--
-- `directory_synced_at` holds the **token's `iat`**, not our clock. A person can hold two
-- live tokens; without an ordering rule the older one reconciles backwards and membership
-- oscillates for as long as it lives. `iat` is not in `oidc.REQUIRED_CLAIMS` — a token
-- without one is still genuine — so its absence means *no ordering information* and the
-- reconciliation proceeds, which is no worse than not having the column.
--
-- Both nullable, no default and no backfill: NULL is precisely true of every existing
-- row, because no provider has a claim configured and nobody has been reconciled. Three
-- ADD COLUMNs with no default are metadata-only, so `users` is not rewritten however
-- large it is.
--
-- No new table, deliberately, so migration 037's catalog guard gains no obligation here;
-- and no new constraint, because `groups.external_id`'s `UNIQUE (tenant_id, external_id)`
-- from migration 017 is the only one this feature needs and has been there since.

ALTER TABLE tenant_idps
    ADD COLUMN groups_claim TEXT;

ALTER TABLE users
    ADD COLUMN directory_digest TEXT;

ALTER TABLE users
    ADD COLUMN directory_synced_at TIMESTAMPTZ;
