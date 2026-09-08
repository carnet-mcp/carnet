-- A grant addressed to somebody who has not logged in yet.
--
-- Sharing is meant to work the way a Google Doc does: type an address, that person has
-- access. `agent_grants` cannot express that. It names a `principal_id`, and a principal
-- does not exist until its owner logs in — the `users` row is keyed `(issuer, subject)`
-- and a subject only ever arrives inside a token. **There is no way to make a user row
-- from an email address.**
--
-- So a share resolves one of two ways, and which one is invisible to the person sharing:
--
--     a user in this tenant already has that email  ->  agent_grants, immediately
--     nobody by that email has ever logged in       ->  here, claimed at first login
--
-- The alternative — refusing to share with anyone who has not logged in — is the
-- ticket-filing friction SSO exists to remove, one layer up. The other alternative,
-- inventing a `users` row with a placeholder subject, puts a row in the identity table
-- that no token can ever match and that `find_user` would have to learn to ignore.
--
-- ## "Never used to look anybody up" still holds
--
-- Migration 008 says the email is display-only and is never used to look somebody up,
-- and this does not contradict it. That rule is about **authentication**: identity is
-- `(issuer, subject)` and nothing else, so somebody changing their address keeps their
-- history and cannot become a different person.
--
-- Resolving an email here establishes nothing about who anybody is. The person still
-- has to arrive with a signed token and be identified by their subject exactly as
-- before; this only decides which pending rows are waiting for them once they have.
-- An email is the handle a human types. It is not a credential and it is not an
-- identity, and the two uses must not be confused because only one of them is safe.
--
-- ## No pending owners
--
-- `role` is `user` or `editor` and deliberately not `owner`. Ownership is transferred,
-- not granted, and transferring an agent to somebody who has never logged in leaves it
-- owned by a row that may never be claimed — an orphan created on purpose. An owner
-- hands an agent to a real principal, or not at all.

CREATE TABLE pending_grants (
    tenant_id   TEXT        NOT NULL,
    agent_name  TEXT        NOT NULL,

    -- Stored lowercased by the writer; the claim compares exactly. Case-insensitive
    -- matching is a per-provider question we have no answer for — the local part of an
    -- address is case-sensitive by RFC and case-insensitive at every provider anybody
    -- actually uses — so this normalises once, on the way in, rather than guessing on
    -- the way out.
    email       TEXT        NOT NULL,

    role        TEXT        NOT NULL CHECK (role IN ('user', 'editor')),

    granted_by  TEXT        NOT NULL DEFAULT '',
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, agent_name, email),

    -- Same cascade, same reason as agent_grants: a pending grant on a deleted agent is
    -- a row that reactivates if the name is ever reused, and it would do so silently
    -- and much later, at somebody's first login.
    FOREIGN KEY (tenant_id, agent_name)
        REFERENCES agents(tenant_id, name) ON DELETE CASCADE
);

-- The claim query, run once per person per login-with-a-new-address.
CREATE INDEX pending_grants_by_email ON pending_grants (tenant_id, email);
