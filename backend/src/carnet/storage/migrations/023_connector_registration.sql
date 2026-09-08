-- Registration: which hosts a customer will let us dial, and what a tool was vetted
-- against.
--
-- Two changes, and they are the two halves of letting somebody outside this repository
-- add a connector. Until now a connector was a Python module written into a tenant by
-- `--seed`, so neither question had anywhere to be asked: we chose every host, and every
-- `vetted_by` was the person who wrote the vetting code.
--
-- ## 1. `tenant_egress_hosts` — the first time a row causes an outbound connection
--
-- Step 003 flagged this and `DEFERRED.md` has carried it since: a registration command
-- that takes a URL and dials it is a server-side request forgery primitive with a
-- friendly form in front of it. The control is a per-tenant allowlist, keyed on host.
--
-- **Per tenant**, because which hosts are acceptable is a customer's answer and not
-- ours. **On the host**, not the URL, because a path is not a security boundary — a
-- server that will serve `/mcp` will serve `/../admin` if it is that kind of server, and
-- an allowlist that pretends otherwise is a control that reads as enforced and isn't.
--
-- **An empty allowlist denies.** This matches `_check_domain`'s reading of an empty
-- `allowed_domains` — *no identity provider for this customer may vouch for anybody* —
-- and it is the correct starting state: a tenant that has approved no hosts can register
-- no connectors. It is also the property that makes this table a control rather than a
-- record, and it is the one somebody will be tempted to invert the first time a fresh
-- tenant cannot dial anything. The temptation is the feature.
--
-- Note the consequence for rows that already exist: any HTTP connector in a database
-- predating this migration stops connecting until its host is allowed. That is a real
-- migration cost, deliberately not papered over by back-filling the hosts of existing
-- connectors — a back-fill would be this migration inventing consent that nobody gave,
-- and it would do it silently at exactly the moment the control was introduced.
--
-- ## 2. `vetted_tools.server_name` / `server_version` — the review record grows
--
-- `connectors/github.py` says *"Vetted against github-mcp-server v1.8.0"* in its
-- docstring, and records that `get_issue` was renamed to `issue_read` between versions
-- and that binding refused to start until the file was updated. That is exactly right
-- and **it is a comment**. Nothing in the schema could hold it.
--
-- The consequence was never a silent hole — `bind()` raises when a vetted tool has
-- vanished and `validate()` raises when an argument moved underneath a `Resource`, and
-- both fail closed. What was missing is the *reason*: an operator saw
--
--     connector 'jira' vets 'create_issue', which this server does not advertise
--
-- with nothing anywhere saying what it had been vetted against, so "did the server
-- change, or did somebody edit the manifest" was a question the data could not answer.
--
-- **These are NOT enforced at bind, and that is deliberate.** A version check that
-- refused to start on a patch release is a control nobody can live with and everybody
-- eventually disables, and `bind()` already fails closed on the thing that actually
-- matters. This is so the failure is explicable, not so it is preventable.
--
-- ## Why they go here and not in the manifest
--
-- Step 010b settled this for `vetted_by` and the argument transfers verbatim: a
-- `vetted_by` arriving inside a manifest is a claim that Alice approved this, made by
-- code that is not Alice. A `server_version` arriving inside a manifest is a claim about
-- what a server said at a moment, made by code that never spoke to it.
--
-- So all four are columns the database owns, written by `vet_tool` — which is the method
-- that holds the session that ran `initialize` — and read back by `load_vetting_record`.
-- `save_connector` cannot write them by being handed a dict, because there is no key it
-- would read them from. Plan 012's decision 5 says "the manifest records what it was
-- vetted against"; this is the one place this step departs from it, for the reason above.

CREATE TABLE tenant_egress_hosts (
    tenant_id  TEXT        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Lowercased, no port, no scheme, no path. Normalization happens in Python — see
    -- `storage.normalize_host` — because "what is the host of this URL" is a parsing
    -- question with an answer already written down in the standard library, and a
    -- CHECK here could only re-state a weaker version of it.
    --
    -- The CHECK that IS here is the one a constant cannot be trusted with, on migration
    -- 017's and 019's precedent: no empty string, no scheme, no path, no whitespace, no
    -- uppercase. A rule that lives only in a Python constant is one the next caller
    -- widens, and a test written in the same language as the constant does not survive
    -- somebody widening it.
    host       TEXT        NOT NULL CHECK (
                   host <> ''
                   AND host = lower(host)
                   AND host !~ '[[:space:]/:]'
               ),

    -- Who approved this host, and when. Same shape and same reason as
    -- `vetted_tools.vetted_by`: approving a host is a review decision, so it carries the
    -- name of whoever made it. Unlike `vetted_by` this one has a writer from the day it
    -- ships — `allow_host` requires an actor — so there is no `''` default to explain.
    allowed_by TEXT        NOT NULL CHECK (allowed_by <> ''),
    allowed_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- A note for the next person: "Acme's internal Jira, approved by security 2026-08".
    note       TEXT        NOT NULL DEFAULT '',

    PRIMARY KEY (tenant_id, host)
);

-- Every connect asks "may this tenant dial this host", so the primary key is the index
-- that matters and there is deliberately no second one. Listing a tenant's hosts is a
-- prefix scan of the same key.

ALTER TABLE vetted_tools
    -- What the server called itself, and what version it said it was, at the moment this
    -- tool was vetted — `initialize`'s `serverInfo`, verbatim.
    --
    -- Empty rather than NULL, matching `vetted_by`'s `''` default and for the same
    -- reason: every row that predates this migration was vetted against a server nobody
    -- recorded, and `''` says that in the same vocabulary the rest of the review record
    -- already uses. A NULL here would make every reader write a second branch to say the
    -- same thing.
    --
    -- Not trusted, and worth saying out loud: `serverInfo` is self-declared by the
    -- component being constrained, exactly like `readOnlyHint`. It is recorded because
    -- it explains a later failure, never consulted to decide whether a call is allowed.
    ADD COLUMN server_name    TEXT NOT NULL DEFAULT '',
    ADD COLUMN server_version TEXT NOT NULL DEFAULT '',

    -- Every argument name the tool's schema carried at the moment it was vetted.
    --
    -- **This column exists because the first real discovery run was noise.** Decision 6
    -- says a changed schema should be *reported* when it does not touch an argument a
    -- `Resource` names — and without a baseline there is nothing to diff against, so the
    -- only available approximation was "arguments the scoping does not mention", which
    -- reported nine perfectly ordinary data arguments on `list_issues` as new. Pointed at
    -- the real github-mcp-server, every seeded tool produced a paragraph of that, every
    -- time. A report that is mostly noise is a report people learn to skip, which costs
    -- more than not having one.
    --
    -- So: the names only, never the types or the required list. The names are what
    -- `Resource` binds to and therefore what a diff has to be about; storing the whole
    -- schema would put a copy of a vendor's contract in our database, free to drift from
    -- the vendor's, to answer a question nobody asked.
    --
    -- Empty on every row that predates this migration and on everything `--seed` writes,
    -- for the same reason `server_name` is: neither contacted a server. `review()` treats
    -- an empty baseline as *no baseline* and reports nothing rather than guessing, which
    -- is what makes the first discovery after an upgrade quiet instead of alarming.
    ADD COLUMN vetted_arguments JSONB NOT NULL DEFAULT '[]';
