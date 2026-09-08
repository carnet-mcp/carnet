-- Acting-for: whom a door call is made for. Step 033c — decision 8's second half.
--
-- Three columns, two tables, nothing backfilled. A shared service calling through the
-- MCP door can now say who is asking — verified (a forwarded IdP token, checked against
-- the same `tenant_idps` row browser logins are) or asserted (an email believed because
-- the tenant chose to trust that caller) — and both facts land here: the connector's
-- opt-in for the cheaper kind, and what the audit row says about every call.
--
-- ## `connectors.allow_asserted_identity`
--
-- A column rather than a key inside the `launch` manifest, because the question a
-- security review asks — *which of our connectors accept asserted identity, and who
-- turned that on* — must be a WHERE clause, exactly as `vetted_tools_writes` made
-- "show me every vetted write" one. The who-turned-it-on half needs no schema: every
-- write to this table already records an `admin_audit` row naming the actor.
--
-- FALSE by default, and the default is the posture: **verified or nothing**. Asserted
-- identity is only as honest as the calling application, so a tenant that wants it
-- opts in per connector, deliberately, with somebody's name on the change.

ALTER TABLE connectors
    ADD COLUMN allow_asserted_identity BOOLEAN NOT NULL DEFAULT FALSE;

-- ## `audit.acting_for` and `audit.identity_source`
--
-- The two columns that make acting-for governable rather than merely configurable:
-- every brokered record — allow, deny, and error alike — now says who the call was for
-- and how much that claim is worth. The three sources are deliberately never collapsed:
--
--     verified   the caller forwarded the person's own IdP token and it checked out
--     asserted   the caller said a name and this tenant chose to believe it
--     none       no acting-for was presented — every run-path record, and every door
--                call made by a service acting as itself
--
-- Existing rows read `none` through the default, which is precisely true of them: no
-- record written before this column existed had an acting-for to lose. That is the same
-- backfill honesty 039 needed a paragraph for and this column gets for free.
--
-- `acting_for` carries an email (ours from the user row when verified, the caller's
-- bounded text when asserted). The length CHECK is the structural bound behind the
-- door's edge bound: `api/routes_mcp.py` refuses an oversized or shapeless value before
-- anything reads it, and this constraint is what makes that a property of the table
-- rather than a promise kept by one producer — the exact lesson
-- `make_denial_record`'s docstring records from 033b. 320 clears any real address
-- (254 is the wire maximum) without admitting a payload.
--
-- Both ALTERs are on the partitioned parent (migration 030) and propagate to every
-- partition, current and future. The append-only trigger and the RLS policies are
-- untouched by added columns. Constraints are named explicitly — migration 031's
-- lesson: a constraint someone must later find deserves a name its own migration wrote.

ALTER TABLE audit
    ADD COLUMN acting_for TEXT
        CONSTRAINT audit_acting_for_bound
        CHECK (acting_for IS NULL OR char_length(acting_for) <= 320),
    ADD COLUMN identity_source TEXT NOT NULL DEFAULT 'none'
        CONSTRAINT audit_identity_source_check
        CHECK (identity_source IN ('verified', 'asserted', 'none'));

-- No index on either. The security team's question filters a bounded log by
-- `identity_source`, which the retention-swept partitions keep small enough to scan;
-- an index on a three-value column of an append-only table would cost every insert
-- something to speed a query nobody has timed. If it is ever slow, the answer is a
-- partial index (`WHERE identity_source = 'asserted'`) beside `audit_denials`.
