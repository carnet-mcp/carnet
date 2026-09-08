#!/bin/sh
# Runs once, at the bundled database's first boot (the postgres image executes
# /docker-entrypoint-initdb.d/* only when the data directory is empty).
#
# The role it creates is the whole point of this file being here: carnet_app is
# LOGIN, NOSUPERUSER, CREATEROLE — the shape of an RDS or Cloud SQL master user —
# and every DSN in compose.yaml names it. A superuser bypasses row-level security by
# itself, so a compose file that served as the superuser would hide exactly the class
# of defect 029's testing pass found three of. CREATEROLE is what lets migration 037
# create the tenant role itself; without it the migration refuses and names the
# two-line remedy (docs/UPGRADING.md).
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-SQL
	CREATE ROLE carnet_app LOGIN PASSWORD '${CARNET_DB_PASSWORD}'
	    NOSUPERUSER CREATEROLE;
	CREATE DATABASE carnet OWNER carnet_app;
SQL
