# Limits

What Carnet does not do, does badly, or does in a way worth knowing before you rely on
it. It is written down because a limit you know about is a limit; the same limit
undocumented is a surprise, usually at the worst moment.

Every entry here was checked against the code on 2026-09-08. Thirteen entries were
removed in that pass rather than softened — they described limits that had since been
fixed, or a runtime this tree no longer contains — because a stale limit makes the honest
ones easier to discount.

## Permissions and scope

- **`effect` is per-tool, not per-argument.** A hypothetical `copy_issue(from, to)`
  would check both arguments against `write`. Per-argument effects are a later
  refinement.
- **Grants are allow-only.** No explicit denies, so no precedence rules to reason
  about — adding them later is a design decision of its own.
- Scope patterns are strings. An identifier **composed** from several arguments is
  handled (`Resource(..., template=...)`), but one with genuine internal structure —
  an opaque GUID whose bytes carry meaning, a key that isn't segment-shaped — will
  need a new constraint kind, which `_check_resource` is shaped to accept. A family
  alias is a second *name* for an identifier, not a new constraint kind.
- A composed identifier's components may not contain `/`. A resource whose component
  is legitimately path-shaped needs that new constraint kind rather than a template.
- Tool names can't contain dots (`^[a-zA-Z0-9_-]{1,64}$` per the Messages API), so
  `github.list_issues` isn't expressible — hence `github_mcp_list_issues`.
- **A denied read does not make a permitted write suspect.** Observed, not theorised:
  asked for a repository outside its scope, the broker refused — correctly, and the
  refusal is in the audit log — and the model then **invented** plausible issue titles
  and posted them through its *other* grant. The audit record reads `post_message[ok]`,
  because as a call it was entirely legitimate.

  Nothing was breached; the reach boundary held exactly as designed. But it shows the
  boundary's shape: a denial is returned to the model as information, and the model is
  free to fabricate and then act through a different, permitted tool. Permissions bound
  what a call may *reach* and ceilings bound how much it may *do*; **neither has any
  opinion about whether what it writes is true.** What bounds a door caller is a count
  and a spend per day, neither of which distinguishes a write from a read. The narrower
  answer is per-call checks on what a call carries, which is registered work and not
  built. Connecting *that read was refused* to *this write is now suspect* is a real
  design question and nothing in the system does it.

## Identity and access

- **The identity provider is a hard dependency of every request.** A JWKS fetch failure
  would be an outage, so keys are cached for `JWKS_CACHE_TTL` and a stale set is served
  rather than failing when a refresh dies. That is not failing open — a stale key still
  has to verify the signature.
- **An identity provider's token is only revocable by expiry.** There is no
  introspection and no revocation list, so a token a provider issued works until it
  expires; keep lifetimes short. Carnet's own `art_` tokens are different — revoking one
  is immediate, and `carnet --disable-user` cuts somebody off at their next call
  whichever kind they hold.
- **Key rotation at the provider is tested against a synthetic provider, not a real
  one.** Providers replace their signing keys every few months, and a token then arrives
  signed by a key we have never seen. Handled — an unknown `kid` triggers exactly one
  refetch, and there is a test that publishes a second key and checks a token signed by
  it verifies — but the test provider is one we generate, not Okta.

  Getting this wrong locks out **every user** on the day a customer's provider rotates,
  months after deployment, with no code change to blame. So it is worth saying why it
  was not verified against the real thing: Okta *can* be made to rotate on demand
  through its API, but that needs an admin API token — a long-lived secret, unlike the
  public client id and short-lived access tokens everything else here uses. The
  incremental confidence did not seem worth introducing one. Revisit if a rotation ever
  causes an incident, at which point it will be worth the token.
- **No SCIM and no SAML.** The SCIM tables exist in the schema; the protocol surface is
  not in this tree. Some regulated buyers federate only over SAML, and Okta and Entra can
  bridge it.
- **A pending grant to an address somebody's account never carries waits forever.**
  Share with `priya@example.com` when her directory address is `p.sharma@example.com` and
  the row sits there. `--agent-access` lists what is waiting for exactly this reason, and
  nothing expires them. Nobody is notified either — sharing writes a row, and the person
  finds out by looking.
- **A claim runs at a first login and on an address change, not on every request.** A
  grant created between those two moments applies at the next one. The alternative is an
  indexed query per authenticated request to catch a case that is rare by construction.
- **Two users in one tenant can share an address**, since `users` is unique on
  `(issuer, subject)` and a customer may have two providers. The lookup resolves to the
  lowest id, deterministically, and the other never receives what was shared.
- **A share survives its sharer.** An invitation sent by an editor who has since been
  revoked still lands at the recipient's first login — the same way a grant they made
  directly would still stand. Consistent, and worth knowing before reading an access
  list and wondering who authorised what.
- **`CARNET_TENANT` for the CLI is a typo guard, not a boundary.** Whoever runs the CLI
  holds the database URL and can read any tenant directly, so checking which one they
  name protects nothing from them. It catches a misspelling before it reaches a customer
  who does not exist.

## Credentials and keys

- **The encryption key lives in an environment variable**, readable by anything that can
  read the process environment. Better than plaintext in a database by a wide margin, and
  short of a KMS. `key_id` is what makes moving to KMS-wrapped or per-customer keys a
  change to `crypto.py` rather than to every row.
- **One key serves every tenant.** One compromised key is therefore every customer. Real
  isolation needs somewhere per-tenant to keep a key, which is the KMS question again —
  and the seam is in: `seal`/`open_` already take a `tenant_id` that the local cipher
  ignores.
- **Rotation is operator-triggered.** Set a new key, list the old one in
  `CARNET_SECRET_KEYS_OLD`, run `carnet --finish-rotation` until it exits 0, then drop
  the old one. The sweep re-encrypts every sealed column and is safe to interrupt and
  re-run; what does not exist is anything that starts it for you or tells you it is
  overdue.
- **Revoking a connection does not stop a call already holding the credential.** The
  fetch happened at the tool call, and Python cannot interrupt a thread — the same
  constraint as the request timeout and the grant check.
- **Disabling somebody leaves their connections behind**, encrypted and openable by
  nobody — the same orphan shape as their grants. That is deliberate (disabling is
  reversible and deleting their credentials would not be), but nothing sweeps them
  afterwards either.
- **A connection cannot wait for somebody the way a share can.** `--share-agent` to an
  address nobody holds becomes a pending grant; `--connect-account` refuses. A share is
  an invitation, which is a reasonable thing to leave waiting; a credential would be a
  secret sitting encrypted at rest for an account that may never exist.
- **`account_label` is not verified** for a pasted credential. The platform ships no
  integrations, so it cannot ask an arbitrary MCP server whose token this is. An OAuth
  connection's label comes from the provider's own token response and *is* verified; a
  `static` one is whatever somebody typed, and the two look identical on the page except
  for the `credential_kind` beside them.
- `credentials.for_tool()` is still an `if tool_name == ...` chain for hand-written
  tools. Connector tools no longer go through it, so it stops growing — but it should
  become a per-tool declaration before more hand-written tools arrive.

## Connectors and the protocol

- **Tool descriptions are not pinned.** The allowlist controls *which* tools appear;
  it says nothing about what their descriptions say, and a model reads a description
  as authoritative rather than as content. A compromised or careless server can put
  instructions there. The size cap defends tool *results*; nothing defends this. The fix
  is a lockfile — hash description and schema at vetting time, fail the bind on change —
  which is correct and noisy, since every upstream release then breaks the build on
  purpose. Deferred deliberately.
- **The MCP subset is deliberate**: `initialize`, `notifications/initialized`,
  `tools/list` (paginated), `tools/call`, over either transport. No resources, prompts,
  sampling, roots, completions, server-initiated requests, or cancellation — and on the
  HTTP side, no client→server GET stream, which the spec makes optional for exactly
  that reason. Hand-written rather than taken from the `mcp` SDK, which is async-first
  against a synchronous runtime and brings pydantic/httpx/anyio/starlette for three
  methods. If we need more of the protocol, take the SDK and put an adapter behind the
  same `Session` interface.
- **Stdio holds credentials for a process lifetime**, so a stdio connector cannot carry
  per-user credentials. This is **refused rather than documented**: a connection row on a
  stdio connector fails before anything is launched.
- **No SSE resumability.** We do not send `Last-Event-ID`, so a stream dropped
  mid-`tools/call` is an ambiguous write needing a person rather than something the
  client recovers from. Correct, and more annoying than it sounds the first time a
  proxy times out.
- SSE lines are split with `requests.iter_lines`, which splits on more separators than
  SSE defines. A `data:` payload containing a raw U+2028 could be split wrongly. Remote
  in practice, and the fix is a hand-rolled chunk reader.
- `Tool.max_response_bytes` is per-tool. A whole server being verbose wants a
  connector-level default.
- Connectors are loaded from storage per call, with no cache. A cache would have to be
  tenant-keyed and invalidated on write, and the failure mode of getting that wrong is
  not a stale read but one tenant serving another tenant's allowlist.

## Storage, tenancy and the log

- The in-memory store is a second implementation that can drift. The contract suite is
  the mitigation, and it only runs against Postgres when a DSN is set — so a developer
  who never sets one can write a passing test for behaviour Postgres does not have.
- Migrations are forward-only. No `down`, which is right at this stage and will not
  stay right.
- **The audit log is personal data.** `principal_id` is an opaque id rather than an
  email precisely so that a table which is append-only *by trigger* does not accumulate
  addresses nobody can remove — but the linkage exists in `users`. Retention exists
  (`CARNET_RETENTION_DAYS`, a partition drop rather than a delete); what does not exist
  is any way to remove one person's rows from a table the triggers refuse to delete from.
- **A call's correlation id is 48 bits** (`uuid4().hex[:12]`), which collides at around
  a billion calls, and nothing in `audit` enforces uniqueness on it. Widening it changes
  every id already written down.
- `audit_query` loads records into memory to group them by correlation id. Fine at this
  scale; the aggregation belongs in SQL once there is a fleet to report on.
- An existing `var/audit.jsonl` from before the log moved into a table is **not**
  backfilled. Records carry `v` from the first line so a backfill stays possible; it
  wasn't worth doing.
- `var/` is gitignored and holds the message outbox, an audit fallback file written only
  when the database refuses a record, and `--local`'s own state and key. Override the
  location with `CARNET_VAR_DIR` in a container.

## Running it

- **Session locking serializes tool calls** per (tenant, connector, credential). The
  session TTL and pool cap are still invented numbers, but the cap was **re-derived**
  rather than inherited: the key space is tenants × connectors × *users*, so 32 meant
  roughly thirty-two concurrently active people platform-wide. It is 256, settable with
  `CARNET_MCP_SESSION_POOL_MAX`, and `SessionPool.overflow_evictions` counts what
  it would take to stop guessing — an eviction raises no error, so a pool a tenth the
  size it should be otherwise looks exactly like a slow MCP server.
- **Process-local ceilings multiply with `uvicorn --workers N`.** Four processes means
  four session pools, four bound-tool registries and four connection pools. Nothing
  breaks — the locks are per process and so is the state they guard — but those numbers
  stop meaning what they say. **The door's daily ceilings are the exception**: calls,
  tokens and spend are counted in Postgres and hold across replicas, which is why they
  are the ones worth setting.
- Sessions are process-global. A stale one is retired when `tools/list` reveals it and
  replaced once, and an expired HTTP session re-initializes. Idle eviction and a pool
  cap exist, with invented numbers, because there is still no real traffic to size them
  against.
- The shipped GitHub connector is stdio, because that is what the local Docker image
  speaks. Delegating it per person needs the one-row switch to the hosted endpoint.
- The registry holds a single hand-written tool, `post_message`, which exists because no
  vendor publishes it — picking Slack, Discord or a local file from the URL shape is our
  logic. Everything else a deployment can call comes from a connector somebody vetted.

## Where the rest of the gaps are

This document is what is known to be missing or weak in what ships. What is *planned* is
not published: this repository is the product, not the roadmap. If something here matters
to you, an issue saying so is the most useful thing you can send — a limit somebody is
actually hitting outranks one that is merely true.
