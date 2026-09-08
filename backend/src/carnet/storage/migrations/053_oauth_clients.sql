-- The door as an OAuth resource server: the client that registers itself, and the
-- code a person's consent turns into a token.
--
-- Step 083. Every MCP client that does OAuth discovery — Claude Desktop, Claude.ai,
-- Cursor — arrives holding nothing but the door's URL. It reads two well-known
-- documents, registers itself (RFC 7591), sends the person to sign in, and exchanges an
-- authorization code with a PKCE verifier for an access token. **The access token is an
-- `api_tokens` row** — a personal `art_` token minted by `access/tokens.py` exactly as
-- the CLI and `POST /me/tokens` mint one — so nothing here is a credential. These two
-- tables are the flow's bookkeeping *before* the token exists, and nothing reads them
-- once it does.
--
-- The first core migration after 082's series split, and the file `migrate.py`'s own
-- docstring named as its example. It adds two tables and touches nothing that exists:
-- `api_tokens` is untouched, deliberately — the client a token was minted for is in the
-- token's name and in the `token.mint` record's detail, and a column for it waits on a
-- reason (`DEFERRED.md`).
--
-- ## `oauth_clients` has no tenant, and that is the whole point of the table
--
-- A client registers *before* anybody signs in — RFC 7591's registration endpoint
-- carries no credential, because the client has none yet. So there is no tenant to key
-- the row on: the person who consents decides the tenant, at consent, and it lands on
-- the code row below. This is the first table in the schema keyed on nothing tenant-
-- shaped, and its policy is decided at the bottom of this file: visible whole to every
-- scoped session, because it belongs to no tenant. The routes that register and
-- exchange carry no principal and run unscoped, the way `find_api_token` does — they
-- are the queries that produce the tenant.
--
-- What an unauthenticated write costs is bounded in `access/oauth_server.py` — ten
-- redirect URIs, a short name, a small metadata object — and a client nobody ever
-- consented to is swept after a month; `last_consented_at` is the sweep's key and is
-- NULL until the first approval.
--
-- ## `oauth_codes` is hashed, not stored
--
-- Migration 031's argument for `api_tokens.secret_hash`, applied to a five-minute
-- credential: a presented code is compared, never read back, so the row holds a digest
-- and a dump of this table redeems nothing. Single-use is a compare-and-set on
-- `used_at IS NULL` in one statement (`consume_oauth_code`), and the row *survives* its
-- use until swept: a code presented twice is RFC 6749 §4.1.2's signal that it was
-- intercepted, and the second presentation revokes the token the first one minted —
-- which needs `token_id` to still be here.
--
-- `code_challenge` is stored as the client sent it (S256, base64url of a SHA-256, no
-- padding); the verifier is never seen by this side until the exchange, which is what
-- PKCE is. `redirect_uri` and `resource` are stored so the exchange compares against
-- what consent saw rather than what the token request claims.

CREATE TABLE oauth_clients (
    -- Ours and opaque: `oc_` and sixteen hex characters, on `api_tokens.id`'s pattern.
    id                 TEXT        PRIMARY KEY,
    -- What the consent page shows. Rendered as text, never trusted as an identity:
    -- anybody may register a client called anything (see the plan's known limits).
    client_name        TEXT        NOT NULL CHECK (client_name <> ''),
    -- A JSON array of strings. Matched byte-for-byte at authorize and at consent; the
    -- scheme rule (https, loopback http, private-use) is `access/oauth_server.py`'s.
    redirect_uris      JSONB       NOT NULL,
    -- The rest of the registration request, bounded, for the page: `client_uri`,
    -- `software_id`, `software_version`. Nothing here decides anything.
    metadata           JSONB       NOT NULL DEFAULT '{}',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_consented_at  TIMESTAMPTZ
);

CREATE TABLE oauth_codes (
    code_hash       TEXT        PRIMARY KEY,
    tenant_id       TEXT        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       TEXT        NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    -- The person who consented, and therefore the owner of the token the exchange
    -- mints. No foreign key to `users`, matching `api_tokens.owner_id`.
    owner_id        TEXT        NOT NULL CHECK (owner_id <> ''),
    redirect_uri    TEXT        NOT NULL CHECK (redirect_uri <> ''),
    code_challenge  TEXT        NOT NULL CHECK (code_challenge <> ''),
    resource        TEXT        NOT NULL DEFAULT '',
    -- The name the token will carry: the client's, made unique at mint.
    token_name      TEXT        NOT NULL CHECK (token_name <> ''),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    token_id        TEXT
);

CREATE INDEX oauth_codes_by_tenant ON oauth_codes (tenant_id);

-- 037's one line per tenant-keyed table.
ALTER TABLE oauth_codes ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON oauth_codes TO agent_runtime_tenant
    USING (tenant_id = agent_runtime_tenant_id());

-- `oauth_clients` has no tenant, so 037's expression cannot apply — and the catalog walk
-- in the contract suite asks every table without one for a *decided* policy rather than
-- a forgotten one. The decision: **visible to every scoped session, whole**. A row here
-- holds a name and a redirect list the registrant typed and nothing tenant-shaped; the
-- consent route runs scoped to the person's tenant and must read the client and stamp
-- `last_consented_at`, and there is no tenant a client could be hidden from because it
-- belongs to none. Row-level security stays enabled so the table is not the one
-- exception to the rule that every table has it.
ALTER TABLE oauth_clients ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON oauth_clients TO agent_runtime_tenant
    USING (true);
