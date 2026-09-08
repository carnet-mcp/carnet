-- `connections` stops being shape-only, and gains the two things an operator has to be
-- able to ask about a credential they cannot read.
--
-- Migration 006 created this table with ciphertext, a key id and an expiry, which is
-- everything the *read path* needs and nothing an administrator needs. The read path is
-- now being built, so this is the moment those are worth having.
--
-- Both columns are added now rather than when somebody asks, and the test is not "is it
-- needed today" but "could the value be recovered later". `updated_at` cannot: once a
-- row exists, when it last changed is gone. `account_label` cannot either, and worse —
-- learning which vendor account a stored token belongs to means asking every user to
-- reconnect, because the platform cannot read its own ciphertext to go and look.
--
-- Two columns deliberately NOT added, because they fail the same test in the other
-- direction:
--
--   status ('active' / 'revoked') — revoking a credential should DELETE the row. A
--   revoked row that still holds live ciphertext is a worse artifact than no row, and
--   an offboarded employee is already cut off by users.status long before this matters.
--   OAuth in 7b will want a 'pending' state while consent is in flight; that is 7b's
--   column to add, at the point it means something.
--
--   connected_by — who performed the connection. It is the connecting user in every
--   case that exists today, so the column would hold one value and imply a distinction
--   the product does not yet have.

ALTER TABLE connections
    -- Which vendor account this credential belongs to, as a human-readable label:
    -- "@priya-acme", "priya@acme.com", "Build Server". Supplied at connect time and
    -- never parsed — the platform ships no integrations and so cannot know how to ask
    -- an arbitrary MCP server whose account a token is. 7b's OAuth flow gets it from
    -- the token response for free.
    --
    -- It is what makes "who is connected, and as whom" answerable without decrypting
    -- anything, which matters because the answer is wanted by people who should not be
    -- able to decrypt anything.
    ADD COLUMN account_label TEXT NOT NULL DEFAULT '',

    -- Reconnecting replaces a credential in place, and "when did this last change"
    -- is the first question asked when somebody's agent starts failing. created_at
    -- cannot answer it.
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
