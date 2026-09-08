# Changelog

Notable changes per release. The database contract this implies — what an upgrade
preserves, how far back it works from, what a failure leaves behind — is
[docs/UPGRADING.md](docs/UPGRADING.md).

Versions are `MAJOR.MINOR.PATCH` while below 1.0: a minor is a step of work, a patch is
a fix between steps, and neither is allowed to break an upgrade path.

## 0.10.0 — 2026-09-08

**The acceptance pass** (step 099). Not a feature: the first time every end-to-end
harness in this repository ran in one sitting, against real Postgres, real sockets, the
real command line in its own process, real Chromium and the real image — forty harnesses,
2,921 assertions, zero failures. `backend/scripts/acceptance.py` is that pass and it is
one command; it gives each harness its own database, runs them in dependency order,
treats a failing harness as a finding rather than an abort, and refuses to let a silent
skip pass for a green run. Four harnesses are new, for the journeys nothing covered: the
fileborne door as an editing session (the refusals a person actually meets, `--discover`
to a pasted block that runs, two tokens with two scopes, a REST API in the file),
`CARNET_OPEN_ADMIN` from both sides, a four-person team from an empty database to each
person calling through the door under their own credential, and the stdout audit line on
the platform artefact together with offboarding. They cost fourteen seconds between them
and run in CI.

It found one defect worth the whole exercise. Every command run against Postgres on
Python 3.14 printed a `PythonFinalizationError` traceback after its own output: the
command line configured a store, did its work and returned, leaving the connection
pool's threads to an interpreter that will no longer join them. Harmless to data,
invisible on the shipped image's Python, and exactly the kind of noise that makes an
operator distrust a tool. Every command now gives the pool back on both the success and
the refusal path.

`docs/CAPABILITIES.md` is new and ships: every command-line flag, HTTP route,
`carnet.yaml` key, `CARNET_*` setting and screen, with a test that fails if the code
grows one the document does not name — so the catalogue cannot quietly fall behind the
surface it describes.

**The fileborne artefact** (step 098, the last of plan 094's four). No new capability:
the image's command line, `carnet.example.yaml` at the repository root carrying every key
the file accepts and loaded by the suite so it cannot rot, the README's first screen —
a file and `docker run`, then the refused call, then the line on stdout — and
`scripts/e2e_file_door.py`, which builds the real image, runs it from a file with no
database and no key, dials a real HTTP MCP server over a real socket, and asserts the
credential presented, the list, both refusals and the stdout lines; it runs in the
`deploy` CI job beside its siblings. Building it found one thing a stranger would have
met first: a bind mount whose host path does not exist arrives inside the container as
an empty directory, and the loader now says so. The organisation is `carnet-mcp` — the
image is `ghcr.io/carnet-mcp/carnet`, the repository `github.com/carnet-mcp/carnet` —
chosen the same day; DEFERRED carries the signed-image row and the client-walkthrough row.

**`CARNET_OPEN_ADMIN`** (step 097, the third of plan 094's four). One flag at the one
seam: with it `on`, `roles.is_admin` answers yes for every signed-in person — never a
machine token — so every member may allow a host, register a connector, approve a tool,
configure a consent flow and manage groups, and the administration screens appear for
everybody because `/me` already carried the one bit. It writes no row: every act is still
in `admin_audit` with the member as actor, and unsetting the flag puts the gate back in
front of whoever holds a real role. Plan 094 feared the flag could not be turned off
without a CLI because a member could grant themselves admin; there is no route that
grants a role, so it can. An admin is still not a superuser, and neither is everybody:
the flag touches nothing on the agent ladder. Off by default in both artefacts; anything
but `on`/`off` refuses at startup.

**The audit line, on stdout** (step 096, the second of plan 094's four). Every brokered
call and every refusal is now one JSON object on stdout — on the `carnet.audit` logger,
with a bare handler, so the line never passes through the app log's text or JSON wrapper.
Two shapes, one discriminator: `{"type": "audit", …}` carries the `audit` row's fields
spelled exactly as the row spells them, plus `tenant_id`; `{"type": "denial", …}` carries
the `access_denials` row — the refusal of a name in no granted agent, which never was an
`audit` row and which a stream of `audit` rows alone would have been silent about.
Emitted after the table append is attempted, never instead of it. `CARNET_AUDIT_STDOUT`
is `on` in both artefacts and `off` silences it; anything else refuses at startup. On the
fileborne door this is the only copy of the log; on the platform artefact it is the copy
a team's Datadog, Azure Monitor or Loki already ingests. `admin_audit` stays off the line
for a stated reason (it is written inside the transaction it describes) and DEFERRED
carries the trigger.

**`carnet.yaml` — the fileborne door** (step 095, the first of plan 094's four). Set
`CARNET_FILE` and the door runs from one file with no database, no sign-in and no
browser: connectors (`http` MCP servers and `rest` APIs), the tools approved on each with
their effect and resources, agents as tool lists with scopes, and tokens — parsed at
startup into the same rows the browser writes, through the same two functions `--seed`
used, so the broker sees one model. Every secret is a `${VARIABLE}` pointer and a literal
is **refused**, naming the key, so the file is safe to commit by construction; the host of
every URL is allowed from the URL and every other egress rule stands. `carnet --new-token`
mints a token with no store behind it — the row is written at boot from the variable the
file names, and the owner check in `access/tokens.py` runs unchanged against a `users`
row that says exactly what is true. `carnet --check-file` validates and applies to a
throwaway store, printing the summary or the first refusal with its path. `--discover`
now ends with a `tools:` block to paste under the connector, proposing the vendor's
`readOnlyHint` where they gave one and `write` — the cautious default — where they did
not. A file beside a database is refused at startup; stdio and `identity: user` are
refused in the file, each with the sentence that names the remedy. The fileborne door
does not demand `CARNET_SECRET_KEY`: nothing in it can seal a credential. `pyyaml` joins
the base dependencies.

**Connections, as cards** (step 093). The third screen in the sequence 091 started, and
the one that needed the least: every sentence on it was already argued for, and what a
person struggled with was five services rendered as five identical rectangles in four
states. Each is now a card with the vendor's own mark — the same tile the connectors tab
draws for the same connector — under a badge computed from the same switch as the
sentence: *Connected*, *Needs reconnecting*, *Not connected*, *Not available yet*. Three
of the four sentences stopped opening with the words the badge now carries and kept the
half a badge cannot say.

**One sentence was rewritten rather than moved.** The `unavailable` state read *"There is
no way to connect it yourself yet — nobody has set up a sign-in flow for this connector.
Ask whoever administers your workspace"* — a passive negative, explained in the product's
own vocabulary, ending in an instruction the person it addresses cannot act on. It now
names who is blocked, what is missing, what to ask an administrator for, and what happens
until then. `connectable` was rewritten with it and gained what it never said: what
signing in buys you.

Otherwise nothing about the content moved: `unavailable` still renders no button, an OAuth row still
refuses to show an access-token expiry that is meaningless on it, the scope notes under a
row being decided are untouched, and a disconnect that could not be revoked upstream still
says so.

**The Create MCP tab a stranger can read** (step 092). The pass 091 did on the connectors
page, applied to `/agents` beside it. The list was a stack of rows whose subtitle was the
tool names joined by commas — forty characters of `acme_list_issues, acme_create_issue,
post_message` answering no question anybody has. It is now a card each, carrying **the
apps that agent touches**, read off the connector prefix the tool names already have:
*"4 tools, across GitHub and Jira."* with the marks to match. A badge — *Ready*, *No
tools*, *Not valid* — is computed beside the sentence from the same three conditions, on
the connectors page's own argument that two screens answering *is this usable* differently
teaches somebody to distrust both.

**The wizard's step strip gets nouns** — *Name · Tools · Access · Review* — and the cards
keep their questions word for word. A step strip is a map, glanced at; two of the four
titles used to be sentences.

**The tools step gets a count and a filter.** *"3 of 47 chosen"* above the list, and a box
that narrows by name, description or app — the first offered only when there are more than
eight tools, because a search box over nine is a control that costs a glance and saves
nothing. The filter **never hides a ticked tool**: one that can conceal a granted write is
one that will, and the count is only true if everything it counts can still be seen.

**The primary action is now called *New MCP***, and so is the page it opens — the sidebar
has said *Create MCP* while the button under it said *New agent*. The prose still says
*agent*, which is the concept's name in the schema, the CLI and every route; what changed
is a label that disagreed with the tab it sat on.

**Nothing about the permission model moved.** The scope is still computed from the
catalogue and never typed, `**` is still produced by the word *anything* and never named,
and the review step still renders the detail page's own component rather than describing
the draft a second time. `EditAgentPage` renders the same three step components and
inherited every change without one of its own.

**The connectors page a stranger can read** (step 091). The screen a demo opens on was
argued sentence by sentence across a dozen plans and read, end to end, as a wall: a
sixty-word lede, the egress allowlist above the thing somebody came to do, and four
paragraphs of security reasoning between a person and a name in a box. It now opens with
**what is connected** — a card each, with the vendor's mark, a status word (*Ready*,
*Needs setup*, *Paused*) and one action — offers **Add a connector** second, and keeps the
allowlist, renamed *Allowed addresses*, at the bottom. Presets are a grid of logo cards
rather than a stacked radio list, and the addresses one needs can be allowed from the row
that names them instead of from a form in another card.

**No request and no route changed**, including the two-fields-one-choice credential rule
and the distinction between an empty `credential_prefix` and an absent one. The ordering
migration 021 forces is still enforced, still visible, and still explained in the server's
own words. Three sentences that exist because somebody once got the opposite impression
were kept and shortened — adding a connector switches nothing on, revoking an address
strands connectors rather than deleting them, an asserted identity is believed without
verification — and the asserted-identity control deliberately stayed in plain sight while
four API-vendor fields moved behind a disclosure.

**The marks are drawn, not fetched.** A logo pulled from a vendor's CDN would tell an
outside party which vendors a customer has connected, on every render, and would need the
CSP widened to let it. `components/ui/BrandMark.tsx` is a table of paths and colours with
a monogram for anything it does not know — no dependency, no network, and no
approximation of a trademark that could not be drawn faithfully.

**The name is Carnet** (step 090, plan 080's A4). `shipyard` (pip name, CLI command),
`shipyard.*` (every import) and the `SHIPYARD_*` environment prefix are `carnet` /
`CARNET_*`. One release, no dual-prefix transition — nothing is deployed to protect. A
retired `SHIPYARD_*` variable in the environment is **refused at startup** with its
replacement named, alongside the `AGENT_RUNTIME_*` prefix retired at 0.8.0.

**Why, since a rename is pure cost otherwise.** Shipyard is a live developer-tools
company: shipyard.build sells ephemeral environments on every pull request, holds a
registered mark in the class software marks live in, and owns the plain GitHub org and
the domain. Same word, same class, same audience. A permissive licence is no defence
against a trademark claim, and the remedy after publication is renaming a repository
strangers have already cloned. This was the last moment the change was mechanical.

**What Carnet means.** An ATA carnet is the document that lets goods cross a border under
control: scoped to named items, time-limited, stamped at every crossing, revocable. That
is the token this product issues, in a word that existed before the product did.

**The database keeps the oldest name.** Migrations are never edited once released, so the
`agent_runtime_tenant` role and the `agent_runtime.*` session variables stay exactly as
migrations 029 and 037 created them. `shipyard_app` — the deployment's own role, which
lives in `deploy/` and no migration — becomes `carnet_app`. No migration is touched and no
checksum moves.

**No migration.** The rename is a name.

**The corners a stranger reaches** (step 089, the publication pass). Every suite was run
and came back green — 2,944 in memory, 3,855 against Postgres, 757 in the frontend, and
the door, OAuth-door, local and admin browser scripts — and then the tree was read the way
a stranger reads it. What that found was sentences and one dependency, not code:

- A real identity provider's tenant, carried as defaults in `dev_token.py` and the
  frontend README, is gone. The script now requires `DEV_OIDC_ISSUER` and
  `DEV_OIDC_CLIENT_ID` and names them when either is missing.
- `HANDOFF.md`, `docs/index.html`, the three architecture pages, `plans-summary.html` and
  `docs/Suggestions.md` — every one describing workers, schedules, triggers and a model
  loop this tree does not have — are removed from this branch. `check_versions.py`
  checks three sources instead of seven.
- The `anthropic` SDK is no longer a dependency of the door. Nothing under `src/` imports
  it; it is the `harness` extra for the one script that drives a real model, and the
  hashed lockfile lost it and six transitive packages while moving nothing else.
- `SHIPYARD_USER_USD_PER_DAY` and `SHIPYARD_USER_TOKENS_PER_DAY` leave `.env.example`;
  neither had a reader. `--tenant-status` stops reading the `runs` table.
- Thirteen sentences in the CLI and on the screens that said *run* where the door says
  *call* say *call*. The package description and docstring say what `PREMISE.md` says.
- `frontend/README.md` is rewritten for the app that exists.

**A JSON escape reaches the two open OAuth routes, and now meets a refusal rather than
an outage** (step 087, a second testing pass over 083 and 086). Two register rows and
two test comments said a lone surrogate could not be sent over HTTP because a client
cannot encode one. The six ASCII bytes `\ud800` are a legal JSON escape, and
`json.loads` — which `POST /oauth/register` and `POST /oauth/token` call instead of a
Pydantic model so they can answer in the RFCs' shape — turns them into a string UTF-8
cannot write. Driven against Postgres, one in `client_name` was a **500** out of the
driver, one in a `redirect_uri` a **503**, and one in `code` a 500 before the code was
looked up. Both routes are unauthenticated. Each now walks every string in its parsed
body and refuses a NUL or an unpaired surrogate with its own error code, before
anything is read — 083's NUL fix, one character over.

**A token's name is the row's rule, in both stores.** `api_tokens.name` and
`oauth_codes.token_name` are written from `--mint-token`, `POST /me/tokens` and a
consent, and a NUL in any of them was a 503 on Postgres while the in-memory store kept
it. `normalize_api_token` and `normalize_oauth_code` now refuse a NUL, an unpaired
surrogate or any other control character with `ValueRefused`, so every writer answers
400 with the sentence. Consent refuses before a code exists: the exchange's name-suffix
loop retries on `ValueRefused` — that is what a duplicate name raises — and would have
spun a hundred times into *this customer already has 100 live tokens*.

**A 422 about a lone surrogate is a 422.** Pydantic refused the string correctly; the
422 body echoes the offending input and Starlette renders it with `ensure_ascii=False`,
so the caller saw a 500 about a request that was merely wrong. One
`RequestValidationError` handler renders the default's exact status and shape as ASCII.

**No migration.** Everything above is a rule about a value, at a boundary that exists.

**A scope line can name a model family, and a price can live where the key was
registered** (step 086, 080's E8 then E5 — both of which that page's table calls fired
and its order line, wrongly, gates on a non-Anthropic customer). `core/patterns.py`
compares whole segments split on `/` and a model id has no separator, so the only two
expressible policies over a model were **this exact dated id** and **every model on this
vendor**: `claude-haiku-*` is one literal segment and matches nothing, and *the small
model but not the large one* — the sentence plan 045 promised as "an ordinary scope
line" — could not be written at all. The consequence is the trigger, and it needs no
second vendor: **a new dated release of the same family fails closed** in every scope
naming the old one.

**The matcher is unchanged, and that is the design.** A prefix wildcard is the bug
`core/patterns.py` exists to make inexpressible — `org/*` matching `org-evil/repo` — and
adding one for models would add one for repositories in the same function. Instead the
*identifier* gained a second name: a vetter declares what a vendor's families are called
(`--resource-family anthropic.model=opus,sonnet,haiku`), the descriptor derives one from
the id the caller sent, and `permissions.check` admits a scope line that names either.
A family matches as a contiguous run of whole `-`-delimited tokens, so `gpt-5` covers
`gpt-5-mini`, does not cover `gpt-4-5`, and `pt-5` covers nothing — a substring test would
be prefix confusion wearing the normalizer's clothes.

**No stored policy changes what it matches.** `*` still means every model, an exact dated
id still means that id, and the only string that gains a meaning is a family name — which
in a scope today denies everything. The two obvious designs were both compatibility
events and are pinned as tests rather than left as prose: a second resource type
(`anthropic.family`) denies every stored agent at the no-grant-for-this-type branch, and a
two-segment value (`haiku/claude-...`) denies every one-segment pattern **including `*`**,
which is the widest scope failing closed silently on deploy. A tool vetted before this
release declares no families and a family scope against it refuses, deliberately: a
vocabulary defaulted onto a stored row would be an approval nobody gave.

**And a price now rides on the connector's binding**, beside the `usage_map` that says
where the counters are — same vendor, same approval, same person. Until now a price could
only be written into a JSON file on the server, by whoever can reach the filesystem, which
is very often not the person who registered the vendor's key. `config.model_rates`' rules
were lifted into `config.check_rate_table` and **shared rather than copied**, because two
implementations of *what is a legal price* diverge as a number rather than as an error —
one writer accepting the negative rate the other refuses is a deployment that believes it
has a dollar ceiling and has none. Precedence, least authoritative first: the built-in
dated snapshot, the connector's binding, then `SHIPYARD_MODEL_RATES` — which still
*replaces* the built-in rather than layering over it, 013's posture unchanged. With
nothing set anywhere an unpriced model is still named as unpriced rather than counted as
free.

**No migration.** `vetted_tools.binding` has been JSONB since `047_rest_binding` and
`families` rides in the vetted-tool JSON that `resources` already rides in; 053 stays the
last migration. What did have to change is the two key allowlists that guard a binding —
they refuse an unknown key rather than dropping it, which is the reason this is a code
change and not a data change.

**The edge pass then drove the write paths rather than the code, and found four more.**
The rate rules sat one layer above the storage boundary, so the *vet* path ran them and
the **wholesale** path — `save_connector`, which is `--seed` and any manifest writer — did
not. Against real Postgres, `{"gpt-5": {}}` stored fine and made every metered door call
in that tenant raise `KeyError: 'input'` out of `estimate_cost`; a string counter did the
same with a `TypeError`; a negative rate priced spend at `-0.00499`; a bool priced at 1.
The reasoning that produced the gap was right about `usage_map`, whose worst malformation
is a counter that never arrives, and wrong about a price, which is arithmetic and runs.
So `check_rate_table` moved down beside `check_limit` into `storage/base.py`, where
`check_vetted_tool`'s own rule puts it — *"facts about the row alone"* — and
`config.check_rate_table` is now the name the tree calls it by. **A rate must also be
finite now**, which was never checked anywhere: `json.load` takes bare `NaN` and
`Infinity`, an infinite rate refuses every call forever, and a NaN is the silent one —
`nan > ceiling` is `False`, so the ceiling never fires, and the figure serializes to
`{"usd": NaN}`. Postgres refused those two at its JSON parser and the in-memory store
took them, so this closes a two-store split as well.

**Two more at the string positions this step opened inside a jsonb column**, and one type
confusion. A NUL or a lone surrogate in a family name or a price key was stored by the
fake and answered by Postgres with *"unsupported Unicode escape sequence"* — the 503 that
means the database is broken, about a value somebody typed. `check_config_is_storable` is
the rule already written down one function away; both positions run it, both stores answer
`ValueRefused`, and the route answers **400**. And `Resource(families="haiku")` iterated
into five one-letter families; `args` normalizes a bare string because `args="repo"` means
the obvious thing, and a bare `families` means nothing anybody intended, so it raises.

One more, in the terminal: `--resource-family openai.model=,,,` parsed, stored nothing and
exited 0 — a flag that reads as applied and is not, found by driving it rather than
reading it, and refused now with the sentence.

**The proof is the two scripts that spend real money.** `e2e_model_connector.py` is
**74/74 live** — a family scope admitting a call the vendor actually served and billed,
a prefix wildcard refusing beside it, a dated id nobody has seen admitted by simulation,
and a binding price making a figure with no rate file anywhere; `e2e_door_spend.py` is
68/68 live with no regression. The edge pass probed its own gate with thirteen mutations
and **one survived** — the bind fingerprint did not carry `families`, so a re-vet that
widened or narrowed a family would have kept answering the old policy until a restart,
which is 033a's stale `identity` and 070's stale `credential_ref` at a third address.
Fixed, and pinned.

**The RLS proof, rewritten door-shaped** (step 085, 080's C6 — the one item in that
section that was a lost *proof* rather than dead weight). `backend/scripts/e2e_rls.py`
was deleted by 078 and not replaced, so the claim a customer's security questionnaire
asks about — row-level security, with a per-tenant database role — had nothing behind it
but the contract suite, and the register cited a file that was not in the tree, three
times. It is back at the same path, **69 checks**, and it proves the half no test can:
`tests/test_api.py` exercises the request-scoping seam against the **in-memory** store,
which has no policies, and the contract suite exercises the policies with no server, no
middleware and no pool contention — so nothing anywhere put the two together. This does:
a real uvicorn, two tenants' assistants alternating **door calls** over one shared
connection pool, eighty of them concurrent, each seeing exactly its own tools, its own
call ids and its own audit rows.

**Three scenes that drove the worker are re-homed rather than dropped**, because 029's
property was never about the queue. *One unscoped worker drains both tenants' queues*
becomes **the retention sweep in the serving process** — `LogMaintainer`, the one
tenantless loop this tree has, pruning a month of every tenant's log rows while the door
is being called, its exemption coming from ownership rather than from being a superuser.
*A run id from the other tenant is a 404* becomes **a call id from the other tenant**,
which 083 hands every caller in its result's `_meta`, refused at the screen, invisible in
the database with no tenant predicate in the SQL, and refused at the door. And the
concurrency scene keeps its eighty requests with the sweep running underneath. **No
`runs` row is written anywhere in it** — a door call is not a run — and the BYOC and
creator-role scenes are kept whole, because they are still where every one of 029's and
030's defects hid.

**The edge pass added four scenes and corrected one false sentence.** The claim that
twenty alternating rounds *"cycle every pooled connection many times over"* — inherited
from the deleted file — is wrong: a sequential caller gets the **same** connection every
time, so the scene is one backend carrying two tenants in turn, which is the harder case.
That is measured now (`pg_backend_pid()` per borrow) rather than asserted. Three more
followed: naming another tenant's tool writes **one `access_denials` row in the caller's
tenant and none in the other**, which is what *are failed access attempts logged* is
asking; every backend the server holds is **terminated underneath it** mid-traffic, and
what must hold is not that nothing fails but that nothing crosses (three honest 503s,
zero leaks, full recovery); and an executed call whose `audit` insert fails is followed
to where step 060 actually puts it — `var/audit-fallback.jsonl`, **naming its tenant** —
which is the one place a tenant's audit record lives outside the database, and which
until now was proven only with the path monkeypatched and the fake store.

`storage/tenancy.py` described a tree that was deleted three steps ago — the worker and
the scheduler as the loops that never scope, and `triggers.deliver` as one of three
callers of `scope_to` — and is corrected to name what actually runs, including 083's
token exchange, which nothing named. No behaviour changed; the module is prose and
policies.

**The dead-weight step: what nothing reads, and the one vocabulary that stays** (step
084, 080's C1 and C3 plus 081's leftover, as one step rather than four patches).
`GET /admin/overview` ran **nineteen** statements and returned **thirty-one** keys, of
which the route read twenty-five and threw away six — `runs`, `run_latency`,
`schedules`, `run_tools` and its two tail figures — on every page load, three of them
over tables nothing in this tree writes. It now runs **fifteen** and returns
**twenty-five**, all read; `overview_totals` went from six statements to five, losing a
`count(*) FROM runs` the tile row read and dropped. **`core/usage_query.py` is deleted**
— 479 lines of run report whose entire production surface was one import of
`price_buckets`, in two places — and `price_buckets` moves to `core/usage.py` beside the
rate table it reads. `core.usage.context_limit` and the 200k/1M window inference go with
it; their only reader was the report, and they were Claude-shaped in a tree that brokers
whatever a customer registered. **081's leftover machinery goes as one decision**:
`core.limits.Budget`, `RunContext.start`, `config.DEFAULT_RUNTIME` and the four
`*_PER_RUN` defaults — correct code with no caller, which is how `max_writes: 0` came to
refuse nothing. **The OpenAPI document is byte-identical** before and after: nothing on
the wire moved, and the frontend is three corrected comments.

Two things were deliberately kept, and both are the interesting half. **The limit
vocabulary** — what `agents.validate` refuses an unknown limit key against — moved rather
than died: it is `agents.KNOWN_LIMITS` now, a frozenset of the same four names producing
the same refusal sentence word for word, because a stored `limits` block is read back by
a person and by a tree that does have a runtime, and a key nobody can spell is worse than
a dial nobody enforces. It also lands where it belongs: `core/` knows no agent. **The
`run_budget` refusal band** stays with a reader and no writer: it reads `audit`, never
`runs`, and an upgraded deployment's `audit` holds refusals a pre-078 tree wrote —
dropping the band would silently re-file those as policy denials on the one screen built
to be trusted at a glance. `storage.BUDGET_REFUSAL_MARKER` says so at its definition.

Every deleted proof was re-aimed rather than dropped: *a door call is not a run* is
asserted against the run reader, the door predicate against the leaderboard that
survives, 045c's pricing claim against `price_buckets` (the function a customer's dollar
figure is actually computed from), and the broker's budget seat against a recording
`Spending` — which is stricter than what it replaces, because it can see the tool being
passed and the response size being handed back, and `door.TokenBudget` deliberately
ignores both. Verified by six mutations, each undoing a piece of this step on a copy of
the tree, each going red.

**The door as an OAuth resource server, and the call id in the result** (step 083,
080's E1 and E2). A client that speaks OAuth — Claude Desktop, Claude.ai, Cursor —
now connects with the door's URL and nothing else: an unauthenticated `POST /mcp`
answers 401 with `WWW-Authenticate: Bearer resource_metadata="…"`, the door serves
`/.well-known/oauth-protected-resource` (RFC 9728) and
`/.well-known/oauth-authorization-server` (RFC 8414), registers the client at
`POST /oauth/register` (RFC 7591, public clients, no secret), sends the person to the
app's new `/oauth/authorize` page to sign in with the provider they already have and
approve, and exchanges the code at `POST /oauth/token` (authorization code with PKCE
`S256`, the only grant). **The access token is an `art_` token** — a personal one,
minted by the same `tokens.mint` the CLI and the tokens page use, on the person's own
tokens page, revocable there, dead when they are — so nothing downstream of
`Authorization: Bearer art_…` changed. Migration **053** adds `oauth_clients` and
`oauth_codes` (codes stored hashed, single-use by compare-and-set; a replayed code
revokes the token it minted) and touches nothing that exists. **What this re-opens is
020's *no mint over HTTP***, narrowed rather than repealed: the only grant is gated on
a person's interactive sign-in, a machine is refused at consent before its body is
read, `client_credentials` and `refresh_token` are refused at both registration and
exchange, and a tripwire pins it. Every `tools/call` result that wrote an audit row now
carries that row's id in `_meta["com.shipyard/call-id"]` — the `run_id` on
`/admin/door-calls` — so an agent with forty calls and one denial can say which is its.
One new defaulted setting, `SHIPYARD_OAUTH_TOKEN_DAYS` (30). **One ingress rule for a
custom front door**: forward `/.well-known/oauth-*` to the API with the path intact;
the shipped Caddyfile, the dev proxy and `--local` do. Four routes carry no principal
for reasons the plan states, and `deps.OPEN_SURFACE` now lists every open route with a
test in both directions. Verified by the official MCP SDK's own `OAuthClientProvider`
completing the whole flow against a real socket in `scripts/e2e_mcp_door.py`.

**And then driven adversarially, which found eight defects** —
`scripts/e2e_oauth_door.py`, 374 checks against a real database with real concurrency,
two customers, and the server started a second time behind a `--root-path` proxy. What
it fixed, all of it in this release: a **non-ASCII `code_verifier` was a 500** (`S256`
is defined over ASCII octets, so computing the digest raised); a **malformed IPv6
authority was a 500** from an unauthenticated route (`urlsplit` raises on
`http://[::1].evil.example/`); a **NUL in `client_name` was a 503**, because no Postgres
text column can hold one — and the in-memory store accepted it, which is the fake being
more permissive than the real one; the **registration request was unbounded** while only
the row it produced was; **`_looks_like_challenge` accepted non-ASCII**, because
`str.isalnum()` answers True for `é`; a **redirect URI could carry credentials**
(`https://claude.ai@evil.example/cb` is a URI for `evil.example`); **three individually
legal metadata fields were refused** as *too large* by an aggregate bound its own
truncation could exceed; and a **malformed registration answered FastAPI's 422** rather
than RFC 7591's error shape. The consent body is bounded now too. Also proved rather
than assumed: two exchanges racing one code mint exactly one token, two people
connecting one client get distinct names under the real partial unique index, the
row-level policy on both new tables is the one migration 053 decided, and no code or
token secret reaches the server's log.

**Two migration series, one ledger** (step 082). `NNN_name.sql` is now the *core*
series, with exactly one author, and a separately installed distribution may add its own
migrations under its own prefix (`ee_NNN_name.sql`) into the same `schema_migrations`
table. **The rule that changed is what "ahead" means**: the runner used to refuse any
ledger row it did not have a file for, so one database carrying two series made each
build refuse it — before a single byte of SQL differed between the two trees. It now
refuses a version it is behind on *within a series it ships*, and has no opinion about a
series it does not. `999_from_a_newer_build` is still refused; `ee_001_approvals` is not.
**Nothing is backfilled and no migration is added**: the series is read out of the
version key every ledger row already carries, so a row written years before this existed
answers correctly on every deployed database. A second series registers through the
`shipyard.migration_series` entry point group, which this package defines and names no
member of — asserted by a tripwire, on the local identity provider's covenant. `--migrate`
names ledger rows belonging to a series the build does not ship, which is what a lost
enterprise package looks like from the inside. `scripts/e2e_migration_series.py` is the
proof: it builds a second series as a real installed distribution and drives the real CLI
against a real database, and it runs in CI.

**A config is a permission list, and the form authors only that** (step 081). Step 078
removed the machinery behind three controls and left the controls on screen; a fourth was
found while checking them. The wizard's *"Each person's runs are private to them"* hid
nothing, the edit screen's answer-schema editor was checked by nothing, and — the one that
matters most — its *"It may not change anything. Every write is refused before it reaches
a system"* tick box refused nothing: an agent's `limits` block reaches enforcement only
through `Budget.for_agent`, whose one caller went with the model loop. All four controls
are gone, the wizard is four steps, and what actually bounds an agent — the token it is
called with, per UTC day — is named on the review step instead. `system`, `model`,
`max_tokens`, `runtime`, `private_runs`, `limits` and `output` are still **accepted,
validated and stored**, still preserved by every edit, and now shown on the agent's page
under *Stored, and not read here* rather than under headings that read as contracts. The
server also stops **minting** a value nobody sent: `AgentDraft.runtime` no longer defaults
to `"simple"`, so an agent created over HTTP and the shipped example finally agree about
the shape of a config. `agents.check_output` and `OutputInvalid` — completion-time
enforcement for a loop that no longer exists — are deleted; the write-time schema
validator stays.

**The door, without the rest of the tree** (step 078). The runtime — runs, the worker,
schedules, triggers, the model loop, their five routers, their screens, and the
`SHIPYARD_BENCH` switch that gated them — is deleted, not disabled. The platform's
`ANTHROPIC_API_KEY` had one reader, the model loop, and is no longer read. `/me/usage`
and `/admin/usage` are gone with the run meter they read; `/me` no longer reports a
`bench`; the overview loses its run series and schedule health; the agent page loses the
run box, the schedule and trigger cards; the wizard asks for no instructions and no
model, because the door reads neither. SCIM (`/scim/v2` and the three provisioning-token
commands) and the grant review (`GET /agents/{name}/review`,
`GET /me/tokens/{id}/touched`, the review card and the token's touched section) leave
the tree as the two modules held back for a paid tier. **Not one migration is touched**:
the tables those features wrote still exist and nothing reads them. Settings that are no
longer read are listed in `docs/UPGRADING.md`; a value left set is ignored.

## 0.9.0 — 2026-09-04

**A tool's description is checked as the prose it is** (step 077). `tools/list` sends
every tool's description to every assistant that connects, and the validator checked
nothing about it. Three mechanical checks, no model: a description that carries what
looks like a credential (a Shipyard token, a bearer value, an OpenAI-, GitHub-, Slack- or
AWS-shaped key) is refused, because a secret in it is a secret published; a control
character other than tab or newline is refused; and there is a length cap of four
thousand characters, because a listing fetched on every connect is not where a document
goes. Empty stays allowed on purpose — MCP makes the description optional, and refusing
a vendor's undocumented tool would make it vanish from the listing at the next bind.

**The connect snippet speaks eight dialects** (step 075). The card's config was
`mcpServers` JSON and nothing else; it is now a picker — Claude Code, Cursor, VS Code,
Codex CLI, opencode, Gemini CLI, Windsurf, and Claude.ai — over a table of constants,
with nothing installed on anybody's machine, because the door's payload is a URL and a
header and that is the whole product claim. The snippet still says `<your token>`. A
client that cannot reach this door gets the reason instead of a snippet: Claude.ai and
Claude Desktop connect with OAuth, which the door does not offer for clients. And *where
to paste it* is shown only for a dialect tried against the real client — Claude Code,
from this machine — since a wrong path on that card is worse than no card; the other
six say they come from the vendor's documentation and were not tried here.

**The grant, read against its evidence** (step 076). The product has enforced the
permission list since the door opened; nothing told anybody whether the list was wider
than the work. `GET /agents/{name}/review` now answers three questions from rows the
door already writes — which tools were granted and never exercised, which were asked
for and always refused (at the broker for scope, or at the door for want of a grant),
and which were used — one row per tool with a verdict, and a card under the reach on
the agent page renders it. `GET /me/tokens/{id}/touched` answers the other direction:
what a credential actually called, grouped agent then tool so it reads beside `reach`,
with a section on the token page. **A record, not a control** — neither screen carries
a button, and the wording says *consider*. **Absence of evidence is not evidence of
absence**: every *unused* is conditional on the tool having been watchable for the
whole window — the workspace's door record and the tool's own grant (from the version
history) both older than the window — and anything younger is *no record*, a gap the
screens say is a gap. Reads `audit` filtered to the door's prefix and `access_denials`;
never `runs`, and a test asserts a bench run's rows do not count.

**The connect card tells *refused* from *idle*** (step 074). A call the door turns
away at its own threshold — a token granted no agent that provides the tool, or an
acting-for claim that fails — never reaches the audit log, so the one screen a person
watches during a first connection rendered a silent failure and an idle agent with the
same sentence. `GET /agents/{name}/door-activity` now carries `last_refusal` — the
newest denial naming one of the agent's own tools, with its time, tool, token and
reason — and the card renders the door's own sentence for it: in place of *waiting*
at zero calls, and beside *connected* when it is newer than the last admitted call.
The waiting line also says what it cannot see: a token the door does not recognise at
all is refused before any agent is known, and leaves no record here.

**Every place that states the version now states the same one, and CI checks it**
(step 073). `backend/scripts/check_versions.py` reads the package, the newest released
heading here, four places in `docs/index.html` and `frontend/package.json`, and fails
when any disagree; a `versions` job runs it on every push and pull request, and on a
tag push it refuses a tag that disagrees with the package. Before it, the package said
0.8.0 with twenty steps filed under *Unreleased*, the docs page said 0.8.0 in one place
and 0.6.0 in another, and the newest tag was `v0.3.1`. This release is the cut those
twenty steps were waiting on. `frontend/package.json` is enrolled rather than exempted
— it was `0.1.0` and read by nothing, and one number everywhere is a rule nobody has to
remember. `docs/UPGRADING.md`'s settings list names only the releases that changed an
operator's obligations, so it is named as not a source rather than silently skipped.

**Three procedures, run rather than described** (step 072). The enterprise gate has two
halves and the second one — *an employee offboarding, a DPA deletion clause and a
key-compromise drill each have a procedure that has been run at least once* — pointed at
nothing, because every other clause points at code and this one points at somebody having
done a thing. `docs/runbooks/` now holds the three procedures and
`docs/runbooks/transcripts/` the verbatim output of running each against a real deployment
on real PostgreSQL, failures included. The offboarding drill was **unrunnable** rather than
merely unrun: `storage.set_user_status` has existed since migration 008 as *"the only thing
that cuts somebody off immediately"* and had no caller anywhere until step 071, so that
clause could not have been satisfied by anybody before the day before. Four findings, none
of which any suite reported: a door-only deployment cannot show an operator what a
deprovision stopped, `--agent-access` refuses the operator holding the database with ninety
lines of usage, the deletion confirmation promises a terminal and checks only that stdin is
readable, and a CI scene had been passing on leftover cluster state. Each is a row in the
register with the condition that makes it due.

**What the drills found, fixed** (step 072, follow-through). `--delete-tenant` checks
`sys.stdin.isatty()` rather than whether stdin can be read, so its own sentence — *this is
the one command that will not run unattended* — is true; the one way past it is
`SHIPYARD_TENANT_DELETION_REHEARSAL_I_AM_NOT_A_PERSON`, named in full inside the refusal,
because hiding it would only mean finding it in the source. `--disable-user` names every
schedule and trigger it stopped rather than counting them, which is the only evidence
available on a door-only deployment, where the listings that would show it are bench
surface. And `--agent-access` answers the operator holding the database instead of refusing
them with ninety lines of usage: it reads as an administrator, and the four grant commands
that share that refusal print a sentence. The administrator check is composed at the CLI
entry point rather than pushed into the grant ladder, so a platform role still does not
imply agent access for an HTTP caller.

**A customer's directory can say somebody left** (step 071, migration 052). SCIM 2.0 at
`/scim/v2` — Users and Groups, a filter parser, a `PATCH` applier, and the three discovery
documents — behind a bearer token minted at the shell and bound to one customer and one
identity provider. Claims are a pull on presence and offboarding is a push on absence: a
person deleted in the IdP never signs in again, so nothing reconciles and nothing revokes,
which is why no amount of claim reading closes this. The rule for what a deprovision leaves
behind is decided rather than inherited: **everything that acts as the person stops, and
nothing the person made is deleted.** Sign-in, their API tokens and acting-for already
stopped by re-reading the row; schedules and triggers firing as those tokens are disabled
here, with a record naming the cause. Agents, grants, memberships, connections and runs
survive. There is no hard delete, because every audit row names their id, so `DELETE`
disables and a later read answers `active: false`. `users.subject` becomes nullable and
`users.external_id` arrives, because Entra's `sub` is pairwise and the directory's object
id therefore cannot be the identity: a provisioned row is **adopted** at the person's first
sign-in, once, bounded to the same tenant, the same issuer, no subject yet, and an address
that same directory signed. While a live token exists for an issuer, the groups claim on
that issuer's tokens is no longer read, because two writers with one seam and different
opinions oscillate.

**A credential the platform does not hold** (step 070). A connector's shared credential may
be `op://vault/item/field`, resolved through a 1Password Connect service account at call
time and written to no disk and no table. The claim is deliberately not *we don't store
your keys* — we do, by default, and that default is right — but **if you would rather we
didn't, we don't have to.** `source` gains no value: a pointer is an *encoding*, not an
identity, so a vault-resolved call and an environment-variable call write byte-identical
audit rows. No cache, because a cached secret is a held secret and invalidation is what a
vault is for; the cost is one to three round trips per call, measured rather than argued
(9.6ms with a variable, 11.3ms name-addressed, 10.0ms id-addressed). The refusals are the
deliverable: ten sentences, each naming the vault and the item, none carrying the item's
field labels — those go to `--check-credential`, where the audience is a shell rather than
a model. No migration: `connectors.launch` is JSONB.

**The door's own verdict, without the call** (step 069). An administrator, or a token's own
owner, can ask whether a named call on a named resource would be admitted and get back the
verdict the door would give, the rule that produced it, and every granted agent's reason.
The union rule makes this genuinely hard rather than merely absent — a token sees the union
of the tools of the agents it is granted, each keeping its own agent's scope — so a person
holding three grants cannot work out their own reach on paper. One code path, made
structural rather than promised: the union loop is extracted from `call_tool` so the
simulator and the door share an implementation rather than an algorithm written twice.
`tools.describe` returns the descriptor as a row and never a socket, and nothing it returns
is callable. A simulation writes no row in any table, and the argument is that every
principal who may simulate can already compute the answer by hand. The same step collapsed
`require_owner_or_admin`'s 403 into its 400: within a tenant, *not yours* and *not there*
were an existence oracle over token ids, and the 403 named the owner besides. Five surfaces
inherited the fix.

**A preset that fills a form and approves nothing** (step 068, migration 051). Six
connector recipes ship as checked-in JSON — Anthropic, OpenAI, GitHub's hosted MCP, Jira,
Linear, Notion — pre-filling the registration form with the four fields nobody can guess
and leaving blank the two nobody may. A recipe **vets no tool, approves no host, and
carries no client id or secret**; registering from one produces byte-identical rows to
registering by hand, and nothing in the database points back at a recipe, which is what
makes the catalogue shrinkable. The carrying cost is settled before any vendor is named:
a slot is earned by a real account and a completed consent flow, the ceiling is eight and
enforced by a test whose failure message is the argument, and staleness is displayed rather
than prevented. `connector_oauth.scope_notes` arrives because the per-scope prose belongs
at **consent** rather than at vetting — the reader is a non-administrator clicking Connect,
being asked to grant `write:jira-work` with nothing anywhere saying what that permits.

**Five things worth taking from onecli, and the half that must not be** (step 067). An
index plan, landing no code: the whole of a competitor read against this repository, five
items admitted, and the long list of what is refused recorded with the reason each is
`PREMISE.md` saying no in a different accent. They are the harness and we are the door.
Four of the five became steps 068 through 071; the fifth, approvals, is restated at its
trigger rather than funded.

**A number that points at its calls** (step 066, migration 050). Every figure on the
Overview that counts door traffic can now be opened into the calls behind it, and the index
that makes that affordable is the migration. A record, not a control: nothing on an admin
screen changes anything.

**The share sheet learns about tokens** (step 065). Sharing an agent with a machine caller
was expressible at the terminal and invisible in the browser.

**A client's first week, audited and remediated** (steps 048–064). Plan 049 walked this
deployment as a client would and found five blockers and a tier of majors. The blockers
(050–053): a connector may not name the platform's own environment variables, refused at
registration and again at the credential read; the login path cannot exhaust the host, with
scrypt bounded and the edge measuring a body before it buffers; an exposed deployment
defaults to closed registration with a Secure cookie; and a guesser is slowed per account.
The majors (054–063): the deployment artifact and a real browser against it join CI; the
supply chain is audited over the lockfile that actually ships, with SBOMs; a readiness
probe touches the database; `/metrics` exposes the numbers the pool comments always said to
size from; the name is not the address, with dial-time DNS pinning closing rebinding; a call
that ran is a call recorded, with a durable fallback when the append fails; and log
partitions follow the serving process rather than a worker no deployment runs. **064 is the
review's own findings, and the load-bearing one is that 058's rebinding closure had been
hand-assembled at three call sites and forgotten at two** — `oauth._post_form`, carrying the
client secret and the refresh token, and `messaging.post_message` were still dialling
unpinned. `egress.dial` is the one way anything here reaches the network now, with a test
that greps for the next bare `requests.post` somebody adds.

**The REST connector gets a form** (step 047). `POST /admin/connectors` has taken
`kind`, `credential_header`, `credential_prefix` and `headers` since 045a, and
`VetRequest` has carried a full request binding plus `redact_args` since 045c — and the
screen sent none of them. So the product's answer to *add your MCP server* was a page and
its answer to *add your model provider* was a shell, which is the connector kind that
takes an agent's last private credential away. The registration form now asks which the
URL is, in the words that matter (a server that describes itself, whose tools are
**discovered**; an API that describes nothing, whose tools are **authored**), and the
detail page branches: REST gets no Discover button, because there is nothing to ask.

Authoring a tool is one form, and the schema drives it. `check_binding` refuses an
unmapped argument or a path naming one the schema lacks — good sentences that a person
could previously only meet after typing everything — so the pasted schema's properties
become one row each, the resource pickers, and the redaction checkboxes. That last is
what keeps a prompt out of an append-only table, and it had no UI at all.

Found while building it: **a REST connector was told it could never have a consent
flow.** The gate read `transport !== "http"` and so lumped REST in with stdio, while
`oauth.configure` refuses stdio and only stdio and `carries_per_user_credentials` has
been true for REST since 045a — a screen refusing what the server permits, invisible
until a REST connector could be made in a browser at all.

**A refusal that names the token, not the vendor** (step 046). A service token calling
a tool on a connector whose every vetted tool acts as the person calling it used to get
*"could not be reached ... (401)"* — false in every clause, observed in the wild by an
external harness against the hosted GitHub MCP server. The server was fine; the caller
has no person behind it. Now the door translates that 401 into the credential fact it is
(`TransportError` carries the status as a field, so nobody parses prose), the refusal
names all three remedies — a personal token, `--connect-account` for the machine, or
acting-for — and the broker hands the model the same sentence instead of
"unavailable (credential error)", a stub with nothing to act on. The mint form's
"Service" choice now states the consequence at decision time, and `shipyard --local`
warns when `SHIPYARD_SECRET_KEY` in the environment shadows the deployment's own key —
the mismatch that seals credentials the server can never read, whose only symptom was a
connector quietly missing from `tools/list`.

**A model connector, and the provider is yours** (step 045c). An agent wired to this door
used to hold two secrets: its Shipyard token and its own model API key. The second is the
shape this product exists to displace, so a model API is now registered like any other
REST connector — a scoped, revocable, metered, audited tool — and the README carries the
recipe for two providers precisely so neither reads as the supported one.

`SHIPYARD_MODEL_RATES` now replaces the built-in rate table **keys included**. Until this
step a model id was matched against three hardcoded Anthropic family names, so an operator
who wrote correct GPT prices into their own file still saw `$0.00`: no key in it was ever
reached, and a dollar ceiling over that traffic bounded nothing while looking like it did.
Keys are matched longest-first; with no override the behaviour is unchanged.

A model with no matching rate is still never billed at some other model's rate — it is
recorded, priced at nothing, and **named**, now with the remedy beside it on the budget
screen and the Overview. A dollar ceiling is only as complete as the rate table;
`SHIPYARD_MCP_TOKENS_PER_DAY` is the one that bounds an unpriced provider.

**A vetted tool can say what its audit rows must not keep** (migration 049). `--redact-arg`
and the equivalent field on the vetting route mark an argument to be hashed rather than
stored — the recipes mark `messages` — because a brokered model call writes one row per
call to an append-only table and that argument is the whole conversation. A redaction
naming an argument the tool's schema does not carry is refused at vet time: a policy that
never applies reads as approved.

**`SHIPYARD_MODEL_RATES` is now validated as the load-bearing file it became.** Making
its keys the vocabulary means every non-Anthropic deployment reaches its prices through
it, so its failures had to become sentences. Five malformed shapes used to escape as a
bare `AttributeError` — a top-level list or string, and a rate entry that is a list, a
string or null — and two were *accepted*: `"input": true` passed as the number 1 because
`isinstance(True, int)` is true in Python, and a **negative** rate was taken at face
value. That last one is the quiet failure worth naming: spend falls as tokens are used,
so a dollar ceiling can never be reached and a deployment that believes it has one does
not. All seven are refused with a message naming the file; a zero rate and an empty table
stay legal.

A REST tool now **refuses** an argument its authored schema does not carry rather than
dropping it. `stream: true` is in no schema and this door is JSON-only, so a caller
asking for a streamed answer is told the tool does not offer one — the alternative told
them a value applied when the request went out without it.

Fixed, found by driving both stores against real Postgres: a vetted tool written with a
**tuple** for `resources` or `redact_args` came back a tuple from the in-memory store and
a list from Postgres, which round-trips through `json.dumps`. Two stores answering
different types for one write is what `normalize_vetted_tool` exists to prevent; it was
latent on `resources` for as long as that function has existed and became reachable when
`Vetted.redact_args` — itself a tuple — gave callers an obvious way to hit it.

Registering a connector can now name its credential header: `--credential-header`,
`--credential-prefix` (empty is a real value) and repeatable `--header NAME=VALUE`, so a
vendor wanting `x-api-key` and its own version header is four commands rather than a
code change.

**A daily spending limit, and the Overview tab that shows it.** `SHIPYARD_USER_USD_PER_DAY`
bounds what one person may spend at the model in a UTC day; a run submitted past it is
refused with a 429 naming the figure and when the allowance frees. Off by default —
deployments differ by orders of magnitude, and a ceiling chosen before anyone has seen
their own numbers is a ceiling sized from nothing.

`SHIPYARD_USER_TOKENS_PER_DAY` is the net underneath it, and it exists because a dollar
ceiling cannot see a model the price list does not know: an unrecognised model is never
billed at some other model's rate, so its tokens cost $0.00 against the limit however many
of them there are. Whichever ceiling is met first refuses, and the sentence says which.

The **Overview** tab now opens for everybody rather than administrators only. Spend is the
reader's own and needs no role, so a non-administrator gets a real page — today against
their allowance, tokens per day by kind, where the money went by model, which agents spent
it. An administrator gets the same page plus the door's traffic, everyone's spend, who
spent it, and which tools the workspace's own agents called.

Two things the page will not do. **It does not attribute tokens to a tool call**: tokens
are recorded once per run and tool calls one per call, so what a single tool cost is not a
number this system holds, and apportioning a run's tokens across the tools it happened to
use would invent one. And **it draws no gauge when no ceiling is set** — a dial against a
limit nobody is counting is the most confident possible rendering of a number that does not
exist.

Cost appears on a screen for the first time, on the terms plan 013 set for it: the price
list names itself beside the figure and the models it could not value are listed, so a
short number is never a silent one.

**A second connector kind, and the door beyond MCP** (step 045a). A registered base URL plus
per-tool request bindings produce the same vetted `Tool` objects, brokered and audited
identically to an MCP tool. It is what step 045c's model connector is built on.

**Created to connected, without a terminal** (step 044). The last mile of the door is
now in the product: a browser session mints its own API token (`POST /me/tokens`, the
secret shown once) and revokes it (`DELETE /me/tokens/{id}`, idempotent, beside what the
token reaches); a **machine caller is refused at the mint** — no credential that
survives its presenter may create another, which is what the old mint-is-CLI-only rule
always protected. The agent page grew a **connect card**: the door's address (from
`Me.mcp_url`, configuration rather than a guess at the page's own origin), a client
config to paste with the token as a placeholder, and a *waiting for the first call* line
that polls `GET /agents/{name}/door-activity` and flips green when the first call lands
— denials count, because arrival is the question. And the create wizard stopped asking
the bench's questions where there is no bench: with `SHIPYARD_BENCH=off` an agent is a
name, tools and reach — no required briefing for a model that will never receive it, and
the stored config carries no `system` and no `model` nobody chose.

**A name that is not localhost** (step 043). One setting so a `--local` deployment can be
told the name it is reached at, and the redirect allowlist stops being the only thing that
assumes loopback. `--public-url` **adds** to the allowlist rather than replacing it, so the
operator's own browser keeps working while a colleague uses the public name. The JWKS URI
stays on loopback deliberately.

**A deployment is the MCP door unless it says otherwise.** `SHIPYARD_BENCH` (`on` or
`off`, default **off**) decides whether this deployment runs agents itself. Off, the
routes that could create a run are not registered at all — `/runs`, `/files`, schedules,
triggers and the unauthenticated `/hooks` delivery door — no worker is started whatever
`SHIPYARD_WORKERS` says, the CLI refuses those commands naming the two settings that turn
them on, and the application does not offer screens for them. `GET /me` carries `bench`
so the app asks the server rather than guessing at build time.

**The point is that the door needs no model key, and the half-way state was worse than
either shape.** With no key the bench did not fail, it *accepted*: `POST /runs` answered
202 exactly as designed, the row reached `queued`, and the failure arrived later at the
model call with nothing on screen to explain it — or never arrived, because no worker was
running. `ANTHROPIC_API_KEY` is now needed only when the bench is on, and
`deploy/.env.example` ships it commented out beside `SHIPYARD_BENCH=off`; the worker
service moved behind a `bench` compose profile.

Nothing about the door changed: `door.py`, `broker.py`, `permissions.py` and every
migration are untouched, and the door's end-to-end script passes 111/111 with the bench
off and no key. **Agents are untouched too, and deliberately** — an agent is a permission
list, it is how the door decides what a caller may touch, and hiding it would make every
token all-or-nothing. What the switch hides is the ability to *execute* one here.

**A run records what it cost.** `response.usage` comes back on every model reply and was
discarded for thirteen steps, so one deployment held one `ANTHROPIC_API_KEY`, got one
invoice, and nothing in the system could say which customer produced it. Migration 045 puts
six columns on `runs` — `model` plus input, output, cache-read, cache-write and
peak-context tokens — written once by `finish_run` from a meter the runtime accumulates.
Every terminal status is counted, including the expensive one: a run that hit the turn
limit spent everything an ordinary run spends and produced no answer.

`shipyard --usage [DAYS]` is the report — totals, per model, per agent, per principal, per
status, per day, the spread of tokens per run, and how close runs came to their context
window. `GET /runs` and `GET /runs/{id}` grow the same counts as fields; the run page
renders them beside the existing ones. **No cost is stored and none appears on any run
shape**: a price list changes without warning, and a wrong number on a screen labelled
"cost" is worse than no screen. The estimate exists in one place, an operator's terminal,
which names the rate table it used — the built-in dated snapshot, or your own via
`SHIPYARD_MODEL_RATES`. A model with no rate is reported as *unpriced* rather than quietly
billed at another model's rate.

The columns read `0` and `''` on every run written before the migration, and that is
honest: those runs spent tokens nobody counted. A report distinguishes them from runs that
spent nothing, because no model reply is free.


**Shipyard is an MCP server.** `POST /mcp` serves an MCP endpoint over streamable HTTP,
authenticated by a machine token in the `Authorization` header — never in the URL, so
rotation is minting a token and revocation is one row. Point Claude Desktop, Cursor or
your own agent's MCP client at it and the tools it sees are **the grant list**: the union
of the tools of the agents that token is granted, each keeping its own agent's scope.
Every call is one brokered call — same permission check, same budget, same credential
resolution, same audit record — so what the door adds is distribution, not capability.

Three things it deliberately is not. It is not a second enforcement path: `broker.call` is
unmodified, and a denial through the door is the same row in the same table as a denial
in the product's own chat. It does not create runs — a tool-mode call has no prompt, no
config and no version, so it carries a `door-…` correlation id in the audit log and never
appears in the run list. And it fails closed: Shipyard unreachable means an agent loses
its tools, which is what a gate is.

Two new settings, both defaulted. `SHIPYARD_MCP_CALLS_PER_DAY` (default 1000, `0`
disables) bounds what one token may spend through the door in a UTC day — counted in
Postgres (migration 040), not in the process, so it is the same ceiling however many API
replicas run. `SHIPYARD_MCP_MAX_CALL_BYTES` (default 65536) bounds what one call may carry
as arguments: every brokered call records them in the append-only audit log, and a
*denied* call spends no budget while still writing a row, so this rather than the ceiling
is what limits how much an authenticated caller can put in that table. Migration 040 also
widens `access_denials.resource_kind` to admit `tool`, so a refusal at the door can be
recorded at all.

Acting-for landed with it: a shared service can say which person it is acting for, a
claim believed only where the connector opted in. **Agent mode — an agent itself as one
MCP tool — is withdrawn permanently** (`docs/PREMISE.md`); tool mode is the only mode.

**Whose account a vetted tool acts as is part of the vetting now.** Each vetted tool
carries an `identity` — `service` (the connector's shared credential, always) or `user`
(the caller's own connected account, always, refused with the connection to make when
there is none). The old try-the-caller's-connection-then-fall-back order is retired,
because it made *which account a call went out as* depend on whether the caller happened
to have connected one — invisible at approval time and indefensible for a shared service.
A tool vetted before this release reads as `service`; migration 039 adds the column and
`docs/UPGRADING.md` states the break.

**The name is Shipyard.** `agent-runtime` (pip name, CLI command), `agent_runtime`
(every import) and the `AGENT_RUNTIME_*` environment prefix are `shipyard` /
`SHIPYARD_*` now, and the repository moved to `psistla132/shipyard`. A clean break, no
dual-prefix transition — nothing was deployed to protect. A retired `AGENT_RUNTIME_*`
variable is refused at startup with its replacement named, never silently ignored.
The identifiers migrations created inside the database keep the old name because
applied migrations are never edited: the `agent_runtime_tenant` role, and the
`agent_runtime.tenant_id` and `agent_runtime.retention` session variables. Details in
`docs/UPGRADING.md`.

## 0.8.0 — 2026-08-21

**Watching a run no longer means polling it — and the screen no longer freezes while
the model thinks.** Two changes, because the complaint was two defects: nothing was
*written* during a model call (the audit log records brokered tool calls, and a model
call is not one), and nothing was *delivered* faster than the page's 2s timer.

The signal: the runtime now writes an `activity` marker on the runs row at each turn
transition — `{"turn": N, "doing": "model"|"tools", "since": …}` (migration 038) —
nulled on every path to a terminal status, so the run page can say *"Turn 3 — waiting
on the model, 24s"* with the elapsed ticking, instead of looking frozen for the
longest stretch of every run. Current state only, deliberately: not audit rows, not
an event log.

The delivery: `GET /runs/{run_id}` learned `wait` and `cursor`. With them the server
holds the request — up to `AGENT_RUNTIME_RUN_WAIT_MAX`, default 25s — until the run's
state would render differently from the cursor (an opaque fingerprint each `RunDetail`
now carries), then answers with the same full snapshot as ever. **No second
transport**: `wait` absent is exactly the old route, every response is complete so a
reconnect is just presenting no cursor, and every degradation — hidden tab, transport
error, a server out of wait slots (`AGENT_RUNTIME_RUN_WAIT_SLOTS`, default 16, full
means answer-now) — is the pre-0.8 poll by construction. Measured in the new
`e2e_wait.py`: an 8s stalled model call costs 3 held requests where the 2s poll paid
~5; at the 40s call that motivated the step, ~2 where it paid ~20. A change —
including a Stop press — reaches a held request within `AGENT_RUNTIME_RUN_WAIT_TICK`
(default 0.4s), not on the next poll beat.

Operators: three new settings, all defaulted, no action on upgrade; an ingress that
replaces the shipped front door should tolerate a quiet ~25s read on `/api/runs/*` or
the product silently regresses to 2s polling (documented in `deploy/README.md`;
`e2e_browser_deploy.py` observes the shipped Caddy passing a held read unbuffered).

## 0.7.0 — 2026-08-20

**A deployed Shipyard can now be signed into, on any OIDC provider — which was false
for every provider before this release.** Step 030's artifact served the bundle and no
`/config.json` (the SPA fallback answered it with `index.html` and a 200, so the
failure surfaced nowhere), and the bundle's CSP named Okta and nothing else. Both
halves now come from one declaration in `.env` — `SHIPYARD_OIDC_ISSUER` and
`SHIPYARD_OIDC_CLIENT_ID` — which the front image's entrypoint turns into
`/config.json` (a real 404 when unconfigured; never the fallback) and the served
Content-Security-Policy, so the two places that must not disagree cannot.
`frontend/index.html`'s meta tag keeps only the provider-independent directives;
`deploy/README.md`'s hand-edit workaround is deleted and its ingress contract gains a
fourth obligation.

The browser half had a third Okta-ism beneath those two: `auth.ts` built
`${issuer}/v1/authorize` by concatenation, a URL shape no other provider has. The app
resolves its endpoints from the issuer's OIDC discovery document now, so the issuer
in `/config.json` is the same string `--add-idp` registers — and Entra, Google, Ping,
Auth0 and Keycloak are expressible at all. The local mode serves a discovery document
and the same CSP header as the deployed front door.

One near-miss is worth naming: `frame-ancestors` moved from `'none'` (030's
clickjacking header) to `'self'`, because the silent-renewal iframe's last hop is
`/login/callback` framed by the app itself and `'none'` breaks every silent re-entry
— found by a real browser, which is also why the new `e2e_browser_deploy.py` exists:
a real Chromium signs into the deployed compose stack against a deliberately
non-Okta-shaped stub issuer, under the CSP the front door actually serves, and
proves an undeclared origin still violates `connect-src`. `e2e_deploy.py` gains
`the_sign_in_wiring` and `the_provider_declaration` (96 checks, up from 64): config
content-type and values, the CSP naming the issuer's origin, mutations for the 404
and the half-configuration refusal, and the entrypoint driven across its whole input
space.

**Two things in this release exist only because the testing pass ran.** A deployment
whose provider's token endpoint is on a second origin — Google's shape — now works:
`SHIPYARD_OIDC_EXTRA_ORIGINS` was documented from the start and, until it was driven
in a browser, refused every valid value it was given. And a front container that
could not start now says so: an `ENTRYPOINT` without a restated `CMD` exited 0 with
no output on a loop while `docker compose up` reported success, so the deploy e2e
asserts the front container is running and has never crash-looped. The full account
is `docs/plans/DEFERRED.md`, *What step 031's testing pass found* — ten defects, all
of them on paths nothing had ever executed.

Upgrading a compose deployment from 0.6.0 **requires two new `.env` variables** and
without them nobody can sign in; `docs/UPGRADING.md` now names them, which it did
not, and that omission was itself one of the ten.

## 0.6.0 — 2026-08-20

**The deployment is now an artifact instead of a narrative.** `deploy/` holds a
compose file, the image it builds, and the terminating proxy three parts of the
product already assumed but nothing specified — TLS on by default, the unauthenticated
body limit enforced in front of the app (023's boundary, finally concrete), the
`/api/*` rewrite, and the SPA fallback. Writing it forced the deployment's shape to be
stated for the first time: one API that only serves, workers scaled separately, the
secret key generated once and held by the platform team, and `--migrate` run by the
deployment itself before anything serves. The bundled Postgres deliberately wears the
BYOC shape — no DSN carries a superuser — so the class of tenant-isolation defect a
superuser silently bypasses (029's testing pass found three) cannot hide in the
default artifact either. No schema change; the next free migration number is still 038.

### Added

- **`deploy/`** — `compose.yaml` (db behind a `bundled-db` profile, one-shot
  `migrate`, `api`, `worker`, `front`), a three-target `Dockerfile`, the `Caddyfile`,
  an initdb script creating the `NOSUPERUSER CREATEROLE` app role, `.env.example`,
  and a README written for the platform team that deploys it — including the
  three-obligation contract an existing ingress must reproduce if it replaces the
  bundled front door.
- **`scripts/e2e_deploy.py`** — the artifact driven end to end over real sockets, in
  six scenes: the README's day-one commands run verbatim, the front door's whole
  contract (TLS, the per-path body limits, the prefix rewrite, the SPA fallback, the
  response headers), every setting being reachable from `.env`, restart-and-scale,
  two mutation checks, and the managed-database path against a Postgres the stack
  does not own. Skips loudly without Docker.
- **The front door now sets the response headers the bundle cannot set for itself**:
  `frame-ancestors 'none'` (the CSP spec ignores that directive in a `<meta>` tag, so
  the deployed app had no clickjacking protection at all), `nosniff`, and
  `Referrer-Policy: no-referrer`. HSTS is set on a real domain and deliberately
  withheld on a `localhost` trial, where it would pin every other local development
  server to HTTPS.
- **Every application setting is reachable from `.env`.** `environment:` is a closed
  list, so the seventeen variables it did not name were not defaulted but silently
  ignored — including `AGENT_RUNTIME_SECRET_KEYS_OLD`, without which the key rotation
  procedure in `docs/UPGRADING.md` could not be performed on a compose deployment at
  all. The e2e reads the list out of `config.py` and `crypto.py`, so a setting added
  later must be declared.

### Fixed

- **Migration 037 skipped its GRANT for the role that *created* the tenant role — the
  RDS-master shape — and every entry point then refused to boot.** PostgreSQL 16
  gives a role's creator an implicit membership carrying only `ADMIN OPTION`, so
  `pg_has_role(..., 'MEMBER')` answered true while `SET ROLE` was still denied. A
  local superuser can never reproduce it (superusers may `SET ROLE` to anything);
  the compose artifact's bundled database — an ordinary `CREATEROLE` role, by
  design — hit it on its first boot. The membership check now asks `'SET'`, the
  thing scoping actually needs, in the migration, in `verify_tenant_isolation` and
  in the contract test, and the self-grant works because `ADMIN OPTION` is exactly
  the right to grant the role. `e2e_rls.py` gained a creator scene that pins the
  fooling state (`MEMBER` true, `SET` false) and the administrator-free remedy.
  037 is edited rather than succeeded because nothing carrying it is released — the
  newest tag is still v0.3.1; a local fixture database migrated with the earlier
  037 will refuse on checksum and is rebuilt by its own script.
- **The first command in the deployment README could not be run.** `.env.example`
  ships an empty encryption key by necessity, and compose interpolates the whole file
  for every subcommand — so while the key was empty, even `compose build` refused, and
  the refusal's remedy was a compose command. The key is now generated with plain
  `docker build` and `docker run`, which need no interpolation.
- **A missing asset answered `200 OK` with `index.html`.** The SPA fallback covered
  hashed build output too, so a stale or half-copied bundle failed with a MIME-type
  error pointing nowhere near the cause. `/assets/*` is now served before the fallback
  and 404s honestly.
- **`deploy/README.md` did not tell a second deployment in one cluster what to do.**
  Migration 037's role is cluster-global, so the second deployment's role cannot grant
  itself membership and the stack correctly refuses to start — the remedy is one
  `GRANT` an administrator runs, and it is now documented and asserted end to end.
- `create_app`'s OpenAPI metadata reported `0.3.0` since 0.4.0; it now reads
  `__version__`, like `/health` always did.

## 0.5.0 — 2026-08-19

**The database now enforces tenant isolation.** Every query has filtered on `tenant_id`
since migration 001, and nothing below the application checked that any of them did — a
missed `WHERE` was a cross-tenant leak. From this release, row-level security is live on
every table: when a request's principal resolves, its connections wear a restricted
database role with the tenant bound in a session setting, and the database itself
refuses to show anybody else's rows. A missed `WHERE` on a request path is now a
not-found instead of a leak.

### Added

- **Migration 037** — one `NOLOGIN` role (`agent_runtime_tenant`), a `tenant_isolation`
  policy on every table with a `tenant_id` (walked from the catalog, not a hand-kept
  list), and grants that extend automatically to tables future migrations create.
- **Scoping at the one seam connections pass through**: the pool hand-out overwrites the
  tenant at borrow, resets it at return, and discards any connection that cannot prove
  it is unscoped — so a pooled connection can never carry the previous borrower's
  tenant.
- **A startup check** (`verify_tenant_isolation`) at **every** entry point — server, CLI
  and worker: a database where scoping cannot work (not migrated, role missing,
  membership missing, or a serving role that does not own the tables) refuses to start
  with the remedy in the sentence. Without it a worker claims *nothing at all* and looks
  healthy, because a query a policy denies returns zero rows rather than an error.
  `--migrate` is exempt by construction, so an un-migrated database can still be brought
  up to date.
- **A catalog-walking guard in CI**: a future migration that adds a table and forgets
  its policy fails by name. Tenancy now costs a new table exactly one `CREATE POLICY`
  line.
- `scripts/e2e_rls.py` — two tenants over one real server and one shared pool, the
  no-WHERE-clause proof, the loud unbound-tenant sentence, and an unscoped worker
  draining both tenants' queues.

### Decisions worth knowing

- **The worker, the scheduler, key rotation and the CLI are exempt by construction.**
  Their queries are deliberately cross-tenant (`claim_run` takes no tenant, and
  migration 015 says why); the policies apply only to the tenant role, which those
  paths never take. They run as the tables' owner, whom PostgreSQL exempts —
  `FORCE ROW LEVEL SECURITY` is deliberately off, and CI pins that.
- **No `BYPASSRLS` anywhere.** Only a superuser may grant it and managed Postgres gives
  you none; ownership — which the migration runner already required — is the bypass.
- **An unbound tenant raises a sentence, never zero rows.** The policy calls a function
  that refuses when the role is active with no tenant bound, because a query silently
  filtered to nothing is indistinguishable from a query that found nothing — the exact
  failure this release exists to kill.
- Migration 037 is the first to touch anything outside your database: creating the role
  needs `CREATEROLE`, once per cluster, and the refusal names the two-line remedy. A
  *second* deployment in the same cluster needs only membership granted to it — the
  requirement is membership, not the right to grant it. See `docs/UPGRADING.md`.
- **The owner exemption is ownership, not superuser status.** Asserted against a
  non-superuser owner in `scripts/e2e_rls.py`, because every database this project
  develops against is owned by a superuser — which bypasses row-level security by
  itself and would have hidden a broken queue on every customer's database.

### Known limits

- **A bug boundary, not a privilege boundary.** The serving process can `RESET ROLE`,
  because the same process runs the tenantless worker. Isolation from a compromised
  server means separate serving and migrating credentials — a register row, not this
  release.
- The worker's execution phase runs unscoped (it knows its tenant from the claimed row
  and could be bracketed); deliberately deferred until the loud-failure machinery has
  production hours behind it.
- If you migrate as one role and serve as another, 0.5.0 refuses to boot — fail closed,
  with the sentence naming the fix. Serve with the role that migrates.

## 0.4.0 — 2026-08-19

**A run can be handed a file.** A task was text and only text; there was no upload route,
no attachment concept and no blob storage anywhere. *"Summarize this document"* is most
people's first ask of an agent platform and the answer was that they could not.

### Added

- **`POST /files`**, multipart, answering **201** with an id — and `file_id` on
  `POST /runs`. Two requests rather than one, so a large file is uploaded **once**: a
  retry of the run, or a second question about the same document, re-sends nothing.
- **A file belongs to whoever uploaded it.** Handing somebody else's id to a run is a
  **404**, identical to an id that never existed — any difference between "not yours" and
  "not there" would let a caller enumerate what colleagues have uploaded.
- **Per-type ceilings**: PDF 10 MiB, CSV 5 MiB, text/markdown/JSON 2 MiB. A PDF is mostly
  structure and a CSV is mostly tokens, so one number would be too tight for documents or
  too loose for spreadsheets. The allowlist *is* the key set of that mapping, so a type
  can never be accepted with no ceiling.
- **`AGENT_RUNTIME_BLOCKED_FILE_TYPES`** — a deployment-level blacklist that only ever
  subtracts. There is deliberately no env var that adds a type: the content sniffing is
  per-type code, not a table.
- **The CLI takes `--upload PATH`**, through the same validator the route uses, so a file
  the CLI accepts is one the server accepts and the refusals read identically.
- **The UI attaches on pick, not on send.** A refusal should arrive while somebody is
  still looking at the file picker, not after they have written a task and pressed Run.
- Migration **036**: `files`, plus `runs.file_id`.

### Decisions worth knowing

- **The declared type is never believed.** `%PDF-` for a PDF, a UTF-8 decode for the text
  types. A `.png` renamed `.pdf` reaches a model as a document it cannot read, and that
  surfaces as a confidently wrong answer rather than an error.
- **The bytes are not sealed.** Every sealed column in this schema is a *credential*;
  user content is not sealed, and 015 recorded that as deliberate. Sealing a file while
  the task describing it sits in plaintext beside it is a lock on one drawer of an open
  cabinet. User content gets sealed as one decision — `task`, `answer`, `content` — or
  not at all.
- **`runs.file_id` carries no foreign key**, which is 015's rule for `runs.agent`
  unchanged: a run is history, so deleting a file must not erase the record of the run
  that read it.
- **Not RAG, and not a knowledge base.** One file inside a per-type ceiling fits the
  context window by construction; retrieval is also actively wrong for *"summarize this"*,
  which has no query to embed and depends on the whole document.
- **A cache breakpoint on the document is load-bearing, not an optimisation.** The
  runtime resends the whole message list every turn, so without it a large file is billed
  at full input price up to `MAX_TURNS` times.

### Known limits

- **An orphan is possible** — a file uploaded and never named by a run — and nothing
  collects it short of deleting the tenant. That is the price of an id, and it is the
  documented gap in the product this contract was taken from.
- There is no `GET /files/{id}` and no download route, deliberately.

## 0.3.1 — 2026-08-18

What 0.3.0's testing pass found. Both were fixed rather than deferred; `v0.3.0` keeps
its meaning because a released tag is not edited, which is the policy 0.3.0 introduced.

### Fixed

- **Several replicas may now run `--migrate` at once.** They serialise on an advisory
  lock: one migrates, the rest wait and then find nothing to do. The data was never at
  risk — each migration is its own transaction — but the losing processes died with a
  Postgres catalog error (`pg_type_typname_nsp_index`) that says nothing about
  migrations, which is the worst possible thing to hand somebody debugging a failed
  deploy they cannot log into. Waiting is deliberate: the alternative is a replica
  starting against a half-migrated schema.

### Testing

- **The migration checksum is now verified against file contents.** It always was, but
  nothing proved it: every test planted a wrong value in the ledger, which proves the
  comparison runs and not what it compares. A checksum over the filename — or a
  constant — passed all of them while leaving an edited migration undetected. Two tests
  close it, including one that edits a released migration on disk.
- The `--seed` guard, previously exercised only against the in-memory store, is now
  driven against real Postgres; the PostgreSQL 16 floor is verified against a real 15.

## 0.3.0 — 2026-08-18

The release that makes the migrations a contract rather than an internal convenience,
because they are about to be held by somebody else's Postgres.

### The migration promise, enforced by the runner

- **Released migrations are checksummed.** Every applied migration's SHA-256 is recorded
  in the database, re-checked on every run, and a file edited after release stops the
  upgrade and names itself. A missing checksum — every ledger written before this
  release — is recorded on first sight rather than treated as a mismatch.
- **A database migrated by a newer build is refused** instead of silently reported as up
  to date. Forward-only means an older build cannot run against a newer schema, and
  until now that case was invisible.
- **A shared database is refused.** Tables land in `public`, so agent-runtime requires a
  dedicated database. The refusal happens before anything is written, including the
  ledger.
- **PostgreSQL 16 is now the stated minimum**, checked before any migration runs. It is
  the version CI proves; the untested feature floor is 15.
- Migration numbering — contiguous, unique, zero-padded — is asserted in CI.
- `--migrate` prints how long each migration took.

### Release discipline

- **A CI job runs the whole upgrade path on every change**: the oldest supported schema,
  populated in the shapes of its own era, walked to head one migration at a time, then
  the storage contract suite run against the *upgraded* database. Row survival is
  asserted by value, not by count.
- **Migration lock time is measured** rather than assumed, over populated tables, and
  the five slowest are printed. See *Lock time* in the upgrade guide.
- **`ruff` and `mypy` run in CI** over the backend, error classes only.
- `docs/UPGRADING.md` and this changelog exist; `v0.3.0` is the first tagged release.

### Fixed

- **`--seed` no longer overwrites a configuration a human wrote.** An agent you edited,
  or one of your own holding a name we also ship, was silently replaced with ours on
  every boot that ran `--seed`. It is now left alone, and the command says which and why.
- A contract test that had never executed — two tests shared a name, so Python kept only
  the second — leaving the grant-side `grantee_kind` check unverified. It was correct;
  now it is checked.
- The `Storage` protocol had drifted from both implementations in two places
  (`set_connector_oauth`'s `authorize_params`, and `close`, which existed on only one
  store while being called).
- A connector manifest with a nameless `vetted` entry crashed instead of being refused.
- A `StorageError` chained from a non-psycopg cause raised `AttributeError` out of the
  handler that was trying to classify it.

### Added

- `agent-runtime --version`, and a `version` field on `GET /health` — so *what are you
  running* has an answer from a machine you cannot shell into. The version now has one
  source: `pyproject.toml` reads it from the package.

## 0.1.0 / 0.2.0 — pre-discipline history

Twenty-six steps of work with no tags, no changelog and no stated upgrade policy,
recorded here as one entry rather than reconstructed into a false history. What they
built is in `docs/plans/`, one document per step, written before the code and kept
afterwards.

The database contract begins at 0.3.0. Migrations 001–035 are covered by it — the
upgrade path is tested from the oldest of them forward — but no release before 0.3.0
promised anything about them.
