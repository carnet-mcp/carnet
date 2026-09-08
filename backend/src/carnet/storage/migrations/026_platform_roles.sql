-- Who may administer this tenant.
--
-- **Four features have been stacked behind this one missing idea**, each deferred with
-- the same sentence rather than answered locally:
--
--     group administration over HTTP     9a    access/groups.py, the docstring
--     reading the admin log in the app   11    cli.py -- "a read route needs a
--                                              tenant-admin role and this platform
--                                              has none"
--     the vetting screen                 12    cli.py -- "has now blocked three things"
--     configuring a consent flow         7b    routes_connections.py -- "--set-oauth
--                                              stays CLI-only, the same wall"
--
-- Answering it once here is why it unblocks all four, instead of four local answers that
-- would have disagreed. What kept it deferrable this long is the deployment model: this
-- ships single-tenant per customer, so "who may administer" has been substantially
-- answered by who has shell access. What changed is volume. Every administrative act is
-- a terminal command, and 7b made the *self-serve* half of the product real enough that
-- the administrative half's absence is the visible gap -- a customer's operations team
-- cannot read the log of a product their staff use all day.
--
-- ## Why a new table, when three existing ones nearly fit
--
-- Each near-miss is wrong for a stated reason rather than merely unchosen.
--
-- `users` has no role column, and adding one is wrong twice over. Rows there are created
-- by the login flow -- `users.resolve` creates on first sight -- so a role column rides
-- along every login write, on the one path where a bug locks people out. And a `system`
-- principal, which must be able to answer "admin", has no `users` row at all.
--
-- `agent_grants` is per-agent. The ladder answers *may this person use THIS AGENT*; a
-- platform role answers a question about the tenant. Widening the ladder would put
-- `admin` beside `owner` and invite exactly the collapse the next section refuses.
--
-- Groups are grantees and cannot act -- migration 017's whole argument. A role is about
-- acting.
--
-- ## AN ADMIN IS NOT A SUPERUSER, and 7b is why that is said here rather than in a route
--
-- **Holding `admin` grants no access to any agent, any run, or any connection.** The
-- ladder still answers who may use an agent; `connections.for_connector` still answers
-- whose credential a run acts with. Nothing about a row in this table changes either.
--
-- The argument is 7b's, one level up. 7b exists because *an operator holding everybody's
-- tokens* is the failure delegated credentials prevent. An `admin` role that implied
-- agent access would rebuild that operator under a different name, one grant away, and
-- it would do it quietly -- the row would look like configuration and behave like a
-- master key. The two systems answer different questions and stay orthogonal: an admin
-- who wants to run an agent gets a grant like anybody else, recorded like anybody's.
--
-- What an admin gets is exactly the four surfaces above. Every one is tenant
-- *configuration*; none is tenant *data*.
--
-- ## One role, and the vocabulary is closed
--
-- The product context names two personas -- connector admin, agent creator -- which
-- tempts `connector-admin`, `group-admin`, `auditor`. Refused. All four blocked features
-- need the same answer, and no customer has asked to split it. A matrix invented now is
-- guessed granularity, and the two directions are not symmetric: collapsing a wrongly
-- split role is a breaking change to a customer's configuration, where widening one role
-- into a matrix later is additive. The second role gets added when somebody asks for it
-- by name.
--
-- `admin` is **tenant-scoped**. An admin of tenant A holds nothing in tenant B, and there
-- is deliberately no platform-wide super-role: cross-tenant administration is the
-- operator's, on the shell, where it already lives.
--
-- ## `system` is always an administrator, and it is not a row here
--
-- `api/deps.py` builds every principal through `users.resolve`, which returns
-- `Principal.user(...)`. **There is no path from an HTTP request to `kind='system'`** --
-- checked rather than remembered, and pinned by a test. Two things follow. Treating
-- `system` as always-admin is safe over HTTP, because no HTTP caller can be one; and
-- lockout is impossible by construction, because the CLI is always an administrator.
-- That is what makes revoking the last admin an allowed operation rather than a rule
-- somebody has to maintain.
--
-- It also answers the bootstrap honestly. *Who grants the first admin?* Whoever has the
-- shell -- which is this deployment's actual root of trust, rather than a self-serve
-- ceremony pretending otherwise.

CREATE TABLE platform_roles (
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- **A group cannot hold a role**, and this CHECK is the reason it cannot become one
    -- by somebody widening a Python frozenset. Otherwise group membership is
    -- self-service promotion: add yourself, or be added by any current member-adder, and
    -- be an administrator. The same argument that keeps groups out of `PRINCIPAL_KINDS`,
    -- enforced in the same two places -- here, and in `check_principal_kind`.
    principal_kind  TEXT NOT NULL CHECK (principal_kind IN ('user', 'system')),

    -- **No foreign key to `users`**, and this is `connections`' shape for `connections`'
    -- reason: a `system` principal's id exists in no table, so an FK is unexpressible
    -- without splitting the row shape by kind. The cost is the same known limit -- a row
    -- can name a principal who never logs in again -- and it is smaller here than there,
    -- because a role row for a vanished user grants access to nobody: they cannot
    -- authenticate, and this table is only ever consulted about somebody who has.
    principal_id    TEXT NOT NULL CHECK (principal_id <> ''),

    -- The closed vocabulary, in the column as well as in `PLATFORM_ROLES`. Both, for
    -- migration 017's reason: the CHECK is what survives somebody editing the tuple.
    role            TEXT NOT NULL CHECK (role IN ('admin')),

    -- Free text like `granted_by` everywhere else in this schema, and `'system:cli'` will
    -- be the common value. The log's completeness for role grants is only as good as
    -- migration 022 made it for everything else -- stated rather than pretended away.
    granted_by      TEXT NOT NULL CHECK (granted_by <> ''),
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- **The role is in the key**, so the day a second one exists, holding two is two rows
    -- rather than a migration. Keying on the principal alone would make `role` a column
    -- somebody has to UPDATE, and an UPDATE is where "granted a second role" and
    -- "replaced the first" become indistinguishable in the log.
    PRIMARY KEY (tenant_id, principal_kind, principal_id, role)
);

-- **No `expires_at` and no `status`.** A role is revoked by deleting the row, exactly as
-- migration 013 argued for connections: a disabled-but-present privilege row is a worse
-- artifact than no row, because every reader has to remember the second column and the
-- one that forgets grants access that was withdrawn. Temporary elevation is a feature
-- nobody has asked for, and it is additive when somebody does.

-- The lookup on the request path is by the full primary key, so the index that already
-- exists is the one used. There is deliberately no second index: `--list-roles` is a
-- sequential scan of a table with single-digit rows, and an index added ahead of a
-- measurement is a decision nobody can undo without wondering what it was for.

-- Nothing is added to `admin_audit`. `role.grant` and `role.revoke` join `ADMIN_ACTIONS`
-- and `user` joins `ADMIN_TARGET_KINDS` -- both frozensets in Python, because migration
-- 022 deliberately left `target_kind` with a CHECK of `<> ''` so that *"the set grows
-- every time a method comes into scope"* without an ALTER on an append-only table. That
-- decision pays off here for the first time.
