-- Which preset a connector came from, on the row rather than only in the log.
--
-- Plan 107, decision 6, funded by 110 and renumbered from the `054` 107 wrote (108 and
-- 109 took 054 and 055 first). Step 068 recorded `from_recipe` in `admin_audit.detail`
-- and nowhere else — provenance, never a link — and that was right for the question 068
-- asked (*which connectors came from the recipe that just broke*, answered by reading the
-- log). It is wrong for the question a screen asks a week later: the OAuth form on the
-- connector's page seeds from the connector's own consent-flow row when there is one,
-- and from the preset's `oauth` block when there is not — and to find the preset it has
-- to know which one. Passing the id in navigation state loses it on refresh and cannot
-- be recovered on the detail page later; one nullable-by-default column is cheaper than
-- that conversation.
--
-- Still not a link. `''` for every existing row and for every connector registered by
-- hand; nothing indexes or joins it; deleting a recipe file breaks nothing, and a reader
-- of a stale id gets a screen that says the preset is no longer in this build. `NOT NULL
-- DEFAULT ''` on a table with tens of rows: a catalogue update under a brief lock, no
-- rewrite, on Postgres 11 and later.

ALTER TABLE connectors ADD COLUMN from_recipe TEXT NOT NULL DEFAULT '';
