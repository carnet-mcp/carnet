-- Tenants. Every other table references this one, from the first migration.
--
-- Retrofitting tenancy is the migration nobody survives: it means backfilling a
-- column nobody knows the value of, on tables that are already being read by code
-- that does not filter on it. Cheaper to have it before there is a second customer
-- than to add it after.

CREATE TABLE tenants (
    id          TEXT PRIMARY KEY,
    name        TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
