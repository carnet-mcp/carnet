-- Suspending a customer.
--
-- There is no way to stop a tenant today. Not during an incident, not for one that
-- stopped paying, not for the window a migration wants. Every lever that exists is
-- per-person: `users.status` cuts off one account, so cutting off a *customer* means
-- running it once per employee and hoping nobody logs in during the loop.
--
-- The column is added now, against a table holding a handful of rows, because the
-- alternative is an `ALTER` on `tenants` during the incident it exists to answer.
-- Nine tables reference this one; that ALTER takes its locks at precisely the worst
-- moment. This is the same test migration 013 applied to `account_label` — not "is it
-- needed today" but "what does acquiring it later cost".
--
-- ## Two states, and the third is deliberately absent
--
-- 'read_only' is the state somebody will ask for during a migration, and it is not
-- here because nothing implements it. A value in a CHECK constraint is a promise the
-- code keeps: `users.status` has two values and two behaviours, and an operator who
-- sets one gets the thing it names. A third value that every code path treated as
-- 'active' would mean somebody suspending writes, watching writes continue, and
-- concluding the whole column is decorative. It goes in when the mutating routes can
-- honour it, which is a decision about each of them rather than a constraint edit.
--
-- ## What suspension does, and what it does not
--
-- It closes both doors work arrives through:
--
--     authentication   `access/users.py` refuses, so no request becomes a Principal
--     the claim loop   `claim_run` will not pick up a suspended tenant's queued runs
--
-- It does **not** stop a run already executing, and nothing here could. That is the
-- standing constraint the deferred register states: grants are checked at load,
-- credentials at the tool call, and Python cannot interrupt the thread it is on.
-- Cancellation (008c) is the thing that stops work in flight, and suspending a tenant
-- deliberately does not call it — a mass cancel is a different, louder operation than
-- closing the doors, and collapsing the two would make suspension unusable for the
-- read-only-window case it is also for.
--
-- The consequence to know: suspend a tenant with fifty queued runs and those fifty
-- stay queued. They do not run, and they do not fail. Resuming the tenant releases
-- them, which is the behaviour a maintenance window wants and a surprise for anybody
-- who read "suspended" as "cancelled".

ALTER TABLE tenants
    ADD COLUMN status TEXT NOT NULL DEFAULT 'active'
               CHECK (status IN ('active', 'suspended'));

-- No index. `tenants` is read by primary key on the auth path, and the claim loop's
-- filter is a semi-join against a table with one row per customer — an index here
-- would be larger than the thing it indexes.
