-- Whose account a vetted tool acts as. Step 033a, decision 8 of plan 033.
--
-- The credential read used to try the caller's delegated connection and fall back to
-- the connector's shared credential, so *which account a call went out as* depended on
-- whether the caller happened to have connected one — an invisible per-principal
-- condition nobody stated at vetting time and nobody could read off the tool. Through
-- the MCP door, where one service token serves fifty people, that fallback is how
-- somebody reads data their own account cannot open, with every check passing.
--
-- So the answer becomes part of the approval, beside `effect` and `resources`, because
-- it is the same kind of fact: a judgment about consequence the server cannot make.
--
--   service   the connector's shared credential, always. A caller's connection is
--             never consulted, so one person connecting an account cannot silently
--             change how a shared tool behaves.
--   user      the caller's own connected account, always. No connection means the
--             call is refused with the connection to make — never the shared
--             fallback.
--
-- The default is the deliberate half of this migration, named in docs/UPGRADING.md
-- rather than chosen quietly: every row written before this column was approved under
-- the fallback behaviour, and `service` gives those rows what every headless caller
-- always got. The one thing the backfill must never mean is the fallback itself.
--
-- TEXT with a CHECK rather than an enum, matching every other closed vocabulary here:
-- widening a CHECK is a migration, widening an enum is a different kind of migration,
-- and only one of them can ever be rolled back inside a transaction.

ALTER TABLE vetted_tools
    ADD COLUMN identity TEXT NOT NULL DEFAULT 'service'
    CONSTRAINT vetted_tools_identity_check CHECK (identity IN ('service', 'user'));

-- No index. The column is read when a connector's manifest is assembled — a per-tenant
-- fetch already keyed by (tenant_id, connector_id) — and nothing searches by identity.
