/** The API's shapes, mirrored from `backend/src/carnet/api/schemas.py`.
 *
 * **Written by hand, and that is a known limit rather than an oversight.** Two
 * definitions of one contract can drift and nothing here catches it — the same shape as
 * the `RUN_FIELDS` drift that let `audit.credential` ship with 818 tests green. The fix
 * is generating this from the OpenAPI document the server already publishes, and it is
 * deferred because it is a build step in front of the first line of UI.
 *
 * The mitigation until then is that this file is *only* types. Nothing here has a
 * default, a fallback or a transformation, so a field that goes missing on the server
 * fails as `undefined` where it is read rather than as a plausible zero.
 */

export interface AgentSummary {
  name: string;
  /** Migration 035's `agent_id` — an identity a rename cannot move.
   *
   *  Optional, and nothing in this app reads it yet. Every URL here is built from `name`
   *  and stays that way: step 025 decided the name is the address, and an opaque id in a
   *  route is what names exist to avoid. It is typed so a client that wants to correlate
   *  across a rename has something to hold, and so the field is not a surprise. */
  id?: string;
  /** **`| null` since 081, and always present.** The server stopped defaulting an agent
   *  that names no tier to `"simple"` — that was a value nobody wrote, invented on the
   *  way out — so this is null for every agent created since. It stays non-optional
   *  because the key is always sent: `AgentSummary.runtime` is nullable *and* required in
   *  the OpenAPI document, which is `ConnectionSummary`'s stated convention.
   *
   *  Nothing in this app renders it. It is here because this file mirrors the wire. */
  runtime: string | null;
  tools: string[];
  /** False for an agent whose row exists and whose config no longer validates. It is
   *  still listed — an agent that vanishes from the UI when it breaks is one somebody
   *  re-creates rather than fixes. */
  valid: boolean;
  error: string | null;
}

export interface AgentDetail extends AgentSummary {
  system: string;
  /** `{"github.repo": {"read": ["owner/name"], "write": [...]}}` — the config's own
   *  words. Rendered as a catalogue rather than parsed: 10a shows what is there, and
   *  10c is where a person builds one. */
  scope: Record<string, Record<string, string[]>>;
  limits: Record<string, number>;
  /** **The ETag.** Send it back as `If-Match` on a `PATCH` — see `api.updateAgent`.
   *  Full-precision ISO-8601, and it must be sent back byte for byte: it is compared to
   *  `agents.updated_at` by a SQL predicate, so a value rounded to the second matches no
   *  row that was ever written. Never construct one; only ever echo one. */
  updated_at: string;
  /** **The caller's own effective role** on this agent: `user`, `editor` or `owner`.
   *
   *  Here because a screen without it renders buttons that 404 at the person they were
   *  rendered for — `PATCH` needs `editor` and `DELETE` needs `owner`, and nothing else
   *  in this API tells a client who it is. The ladder's own word rather than a flag per
   *  verb: what a level permits is policy, and three booleans is three things that can
   *  disagree with it. */
  your_role: string;
  /** **The live version number**, and it is not a second ETag. Step 021.
   *
   *  `If-Match` still takes `updated_at`. This is what a person reads as "v7", and it is
   *  what names a row in the history — the one number that tells a save which changed
   *  something from a save which did not, since `updated_at` moves on both. */
  version: number;
  /** The **whole stored config**, and the field an edit screen actually needs.
   *
   *  `system`, `scope` and `limits` above are the same data spelled for a reader, and
   *  they are not all of it: the shipped `issue-reporter` carries `default_task` and
   *  `deny_demo_task`, which nothing in this file mentions. A form built from the
   *  reader's fields alone sends back a config missing both, which is the deletion
   *  `PATCH`'s top-level merge exists to make unreachable — arriving through the
   *  response instead of the request. See `fromConfig` in `draft.ts`. */
  config: Record<string, unknown>;
}

/** One row of an agent's history. Step 021.
 *
 *  **No config**, deliberately: a history card shows dates and authors, and fifty
 *  configs down the wire to render one is fifty system prompts nobody asked for.
 *  `api.getAgentVersion` is how the screen asks for one. */
export interface AgentVersionSummary {
  version: number;
  /** When this configuration became live — the agent's `updated_at` at the time, so
   *  version N was live from here until N+1's. */
  created_at: string;
  /** An actor string, **not a person**: `user:u_...`, `system:cli` for a seeded row,
   *  `migration:032` for the one version that predates this feature. Rendering these as
   *  names would be inventing three people; `describeAuthor` says what each one is. */
  created_by: string;
  /** `create` | `save` | `update` | `restore` | `migration`. A plain string rather than
   *  a union, and that is 020's fourth finding applied on purpose: a hand-typed copy of
   *  a server vocabulary goes stale the moment a sixth value exists, and the screen
   *  branches on two of these. */
  source: string;
  /** The version this one was restored from, or `null` — set exactly when `source` is
   *  `restore`. */
  restored_from: number | null;
  /** **Evaluated when this was read, never when the version was written.** What may be
   *  live moves under stored configs: a tool un-vetted last week makes a version from
   *  last month unrestorable, and nothing rewrote the row. This is why the screen can
   *  say so before somebody clicks rather than after. */
  valid: boolean;
  error: string | null;
}

/** One stored configuration, whole.
 *
 *  `config` is what was written — not merged with anything, not repaired. Sending it
 *  back through `api.updateAgent` does **not** restore it: a merge keeps every key the
 *  old config does not have. `api.restoreAgentVersion` is the operation. */
export interface AgentVersion extends AgentVersionSummary {
  config: Record<string, unknown>;
}

/** One row of the share sheet: who, at what level, and — the decision — **how**.
 *
 *  `via` is why this shape exists. Since groups a person can reach an agent with no
 *  grant of their own, so a sheet that only listed rows would be unactionable in the one
 *  situation it is read in: somebody removes Sam, and Sam still has access. */
export interface AgentAccessEntry {
  /** Widened by step 020. `machine` is an API token — headless, owned by a person,
   *  and an administrator nowhere. This union is hand-written from `schemas.py`, where
   *  the same list is now DERIVED from `GRANTEE_KINDS`; it went stale here the moment a
   *  fourth kind existed, which is the drift plan 010 predicted for this very file. */
  kind: "user" | "system" | "group" | "machine";
  id: string;
  /** The **effective** role: the highest of direct and inherited. */
  role: string;
  /** What they hold in their own right, or `null` for access that is entirely
   *  inherited. Null and `role` are different facts and the screen needs both. */
  direct: string | null;
  /** The groups they reach it through. A group's own row has this empty. */
  via: string[];
  /** `kind:id` of whoever wrote the grant, `""` for inherited access. Free text —
   *  migration 011 filled it with `migration:011` — so it is shown, never parsed. */
  granted_by: string;
  /** On a group's own row: this group's membership comes from the workspace's
   *  directory, so the people listed under it are the ones who have **signed in** since
   *  being placed there rather than everybody who will be. Step 033e — the sheet used to
   *  promise a complete answer, and a directory is what takes that away. */
  directory: boolean;
}

/** An address shared with that has never logged in. A separate list from `access`,
 *  because nobody has this access and somebody *will* if a person ever arrives at that
 *  address — merging them would report access that does not exist. */
export interface PendingGrant {
  email: string;
  role: string;
  granted_by: string;
}

export interface AgentAccess {
  access: AgentAccessEntry[];
  waiting: PendingGrant[];
}

/** What a `PUT` on a grant answers.
 *
 *  `outcome` is the field 006 deliberately hid from the sharer. `granted` and `pending`
 *  look identical on a screen and only one of them means anybody has access. */
export interface GrantOutcome {
  outcome: "granted" | "pending";
  kind: string;
  id: string;
  role: string;
}

/** What `POST /agents` answers.
 *
 *  `owner` is here because it is the half of the request the caller did not send and
 *  cannot see anywhere else — there is no route listing an agent's grants until 10d, and
 *  an agent created without one is the failure four handoffs have warned about. */
export interface AgentCreated {
  name: string;
  /** `kind:id`. */
  owner: string;
}

/** What a tool touches, as a **type** and nothing else.
 *
 *  `github.repo` is composed from one server's `owner` and `repo` arguments and policy
 *  never learns that. A client that was handed the argument names would be invited to
 *  build a scope out of them, which is the coupling the type exists to prevent. */
export interface ResourceType {
  type: string;
}

/** One tool this tenant may grant.
 *
 *  `effect` is why this shape exists. It is the one thing MCP cannot say about itself —
 *  a connector admin sits down and vets a server tool by tool — and until `GET /tools`
 *  it was in the database and on nobody's screen. Without it `post_message` and
 *  `github_mcp_list_issues` are two names in a row, and the difference between them is
 *  the difference between a mistake and an incident. */
export interface ToolSummary {
  /** The **local** name: what a grant says and what the audit log records. */
  name: string;
  /** What the upstream server calls it. `null` for a built-in — only one of the two
   *  halves has an upstream. */
  remote_name: string | null;
  /** The vendor's own words, frozen at vetting time. Empty for a tool vetted before
   *  there was anywhere to put a sentence. */
  description: string;
  /** Ours, and optional: what somebody here should know before granting it. */
  note: string;
  effect: "read" | "write";
  /** Whose account it acts as, decided at vetting time exactly as `effect` is:
   *  `service` is the connector's shared credential (the caller's connections never
   *  consulted), `user` is the caller's own connected account (refused when they have
   *  none — never the shared fallback). Step 033a. */
  identity: "service" | "user";
  resources: ResourceType[];
  max_response_bytes: number | null;
  /** The review record. Empty for a built-in — present rather than omitted, because a
   *  screen saying "vetted by" needs one shape, and empty rather than "platform"
   *  because nobody reviewed it. */
  vetted_by: string;
  vetted_at: string;
}

/** Tools that came from one place. `origin` is a field rather than an omission: a
 *  built-in is code in the platform, a connector tool was approved by somebody in this
 *  organisation — which is the difference that decides who to ask when it is wrong. */
export interface ToolGroup {
  origin: "builtin" | "connector";
  /** The connector id, `""` for the built-in group. */
  id: string;
  description: string;
  tools: ToolSummary[];
}

export type IdentitySource = "verified" | "asserted" | "none";

/** One brokered call that came through the **MCP door** — `GET /admin/door-calls`,
 *  step 035a. Administrators only.
 *
 *  **Not a fourth log.** This is a row of the same `audit` table `RunDetail` reads,
 *  selected by the one thing that separates a door call from a run: a correlation id
 *  shaped `door-<hex>`, which the run route's prefix match can never resolve. Those
 *  rows had been written correctly since 033b and were reachable by nothing, which is
 *  the gap this type closes.
 *
 *  **Two fields the stored record has and this one does not**, and their absence is
 *  deliberate rather than an oversight in the mirror: `args` is caller-supplied free
 *  text in a record kept forever, and `credential` is a lookup key nobody asked to read
 *  in a browser. Both are still in storage for the CLI and an incident query — the
 *  server drops them at `api/schemas.DoorCallRecord`. This file mirrors the wire, and
 *  the wire does not carry them. */
export interface DoorCallRecord {
  v: number;
  ts: string;
  /** The `door-<hex>` correlation id. Carried rather than hidden: it is what ties this
   *  row to the same call in a CLI query, and it is the visible proof that a door call
   *  is not a run. */
  run_id: string;
  principal_kind: string;
  principal_id: string;
  /** Which granted agent's scope carried the call. A door caller sees the union of the
   *  agents it is granted, and this is the one the union rule attributed it to. */
  agent: string;
  tool: string;
  effect: string;
  decision: "allow" | "deny";
  reason: string;
  outcome: string;
  duration_ms: number | null;
  response_bytes: number | null;
  /** Whom the call was made for, or `null` when nobody was named. */
  acting_for: string | null;
  identity_source: IdentitySource;
  /** The person behind a personal token, by email — resolved by the server at read
   *  time from the token's owner, never stored on the row. `""` for a service token, a
   *  person's own session and the system. What the *called by* column shows where
   *  there is one, with the token id beneath it. Step 108. */
  owner: string;
}

/** Which of the three-and-a-half states a connector is in **for the signed-in person**.
 *
 *  The third is the one worth building deliberately: a connector with no consent flow
 *  cannot be self-served, and a Connect button that leads nowhere is the *"a control that
 *  exists and does nothing reads as a bug"* failure 10d's share sheet already learned.
 *  So the row says what to do instead.
 *
 *  `reconnect` is the half. A row exists — so it is not `connectable` — and it cannot be
 *  used, so it is not `connected` either. Collapsing it into either loses the reason,
 *  which is the only part a person can act on. */
export type ConnectionState =
  | "connected"
  | "connectable"
  | "reconnect"
  | "unavailable";

/** One row of the Connections page.
 *
 *  Note what is **not** here: any token, and any principal. The token never reaches a
 *  browser (7b's decision 1) and this shape is only ever returned for the caller — there
 *  is no route that answers about anybody else, and 12b's platform role does not change
 *  that: an admin is not a superuser, so whose account is connected where stays tenant
 *  data rather than tenant configuration. */
export interface ConnectionSummary {
  connector_id: string;
  description: string;
  state: ConnectionState;
  /** Whose account, according to the **provider** for an OAuth connection. Empty for a
   *  pasted credential nobody labelled, which is the honest difference between a
   *  verified answer and somebody's guess. */
  account_label: string;
  /** `static` | `oauth` | `""`. A static credential is one an operator pasted in, which
   *  means an operator saw it — that distinction is the whole of this step. */
  credential_kind: string;
  /** The **access** token's expiry, or null. **Only meaningful beside
   *  `credential_kind`, and rendering it on an OAuth row is a bug.** A connection with a
   *  refresh token is renewed at the *start of a run*, so a healthy OAuth row's
   *  `expires_at` sits in the past for most of the time it exists — a page that showed it
   *  would tell the majority of healthy connections they had expired. It is real on a
   *  `static` row, where nothing renews. */
  expires_at: string | null;
  /** When the **connection** lapses — the refresh token's own expiry, or null. The field
   *  that answers *is there anything behind this*: past it, renewing cannot help and the
   *  person has to consent again.
   *
   *  **Null is not "this will not lapse".** Most providers volunteer no refresh lifetime,
   *  and a connection carrying no refresh token at all also reads null here until the next
   *  refresh turns it into `reconnect` with a reason. Render nothing for null. */
  refresh_expires_at: string | null;
  /** When this connection last changed, or null when there is none. A reconnection, a
   *  refresh and a re-labelling all bump it, which is why the word is *changed* —
   *  *connected* belongs to `created_at` and *refreshed* is wrong on a static row.
   *
   *  Server-side it is the row's compare-and-set token. Read-only here: no route accepts
   *  it back, and echoing it would be handing a lock token to a surface with no lock. */
  updated_at: string | null;
  /** The provider's own sentence, non-empty exactly when `state` is `reconnect`.
   *  Rendered rather than paraphrased: "reconnect" is what to do, and this is what says
   *  whether doing it will help. */
  reconsent_reason: string;
  /** What the consent screen will ask for, shown **before** the button that causes it.
   *
   *  **The connector's configured ask, and NOT a granted scope — the trap is the field's
   *  name.** It comes from the OAuth *application*, so it says what a consent flow would
   *  request right now. What a person actually consented to is stored nowhere: there is no
   *  `granted_scopes` column and the provider's `scope` echo is dropped. So rendering this
   *  beside a connected row answers a different question from the one that row invites,
   *  and the sentence has to say which — otherwise an administrator widening the app's
   *  scopes makes the page claim a live credential carries scopes it never had. */
  scopes: string[];
  /** What those scopes **permit**, in words — migration 051.
   *
   *  `scopes` above is honest and useless to the person it is shown to: somebody who is
   *  not an administrator, clicking Connect, being asked to grant `write:jira-work`. This
   *  is the sentence that answers what that means.
   *
   *  Keyed by scope, and a scope with nothing to say has **no key** rather than an empty
   *  entry — `offline_access` is bookkeeping, and inventing a sentence for it would be
   *  describing somebody else's permission from a guess. Carries the same caveat as
   *  `scopes`: what a consent flow would ask for now, not what anybody granted. */
  scope_notes: Record<string, ScopeNote>;
}

/** `POST /connectors/{id}/connect` — a URL to navigate to, and nothing else.
 *
 *  Never fetched-and-parsed: the browser has to *leave this origin*, so the client
 *  assigns `window.location`. Returning a URL rather than a 302 is deliberate — `fetch`
 *  follows a redirect transparently and would pull the provider's consent HTML into a
 *  promise nobody can render. */
export interface ConsentStart {
  authorize_url: string;
}

/** `DELETE /connectors/{id}/connection`.
 *
 *  `revoked_upstream` is **three-valued** and that is the field this shape exists for:
 *  `true` the provider was told, `false` we tried and could not, `null` there was nobody
 *  to tell. Decision 12 makes the local delete unconditional so a provider outage cannot
 *  trap somebody in a connection they have asked to end; the cost of that is exactly this
 *  ambiguity, and a boolean would resolve it by guessing. */
export interface DisconnectOutcome {
  disconnected: boolean;
  revoked_upstream: boolean | null;
}

/** `GET /me` — who the caller is, here. The first shape in this API about the **caller**.
 *
 *  It exists because this app reads display claims off its own token, and a token knows
 *  nothing about a row in `platform_roles`. Without it the only way to discover you are
 *  not an administrator is to render a nav item and watch the page behind it answer 403 —
 *  which is exactly the bug `AgentDetail.your_role` was added to prevent one level down.
 *
 *  `admin` is a bool rather than a list of roles, matching a vocabulary with one member.
 *  It becomes a list on the day there are two, which is additive to a field nothing here
 *  branches on more finely than this. */
export interface Me {
  /** `user:u_9311cad7b95c4592`. The string that appears in every audit and administrative
   *  record, so somebody comparing a screen to the log has the same text. */
  principal: string;
  kind: string;
  email: string;
  display_name: string;
  admin: boolean;
  /** The MCP door's dialable address — `PUBLIC_ORIGIN + "/mcp"`, configuration the
   *  bundle cannot know (behind a proxy the app's origin and the door's genuinely
   *  differ). Step 044, for the connect card. Optional: an older API sends nothing, and
   *  showing no address beats inventing one. */
  mcp_url?: string;
}

/** One row of `GET /admin-audit` — *who changed who may do what*.
 *
 *  `detail` is an open object and stays one. It differs per action by design — a role, a
 *  grantee, a list of field names — and pinning a shape here would be this file inventing
 *  one the server never agreed to, then failing to render a record the log holds. The
 *  screen prints its keys, exactly as `--admin-log` does. */
export interface AdminRecord {
  v: number;
  ts: string;
  actor_kind: string;
  actor_id: string;
  /** `'<noun>.<verb>'` — `grant.create`, `role.revoke`, `connector.vet`. The vocabulary
   *  is `ADMIN_ACTIONS` and is deliberately not a union type here: a server that adds an
   *  action must not make this screen stop rendering the log. */
  action: string;
  target_kind: string;
  target_id: string;
  detail: Record<string, unknown>;
}

/** One row of `GET /admin/denials` — *who tried, and was refused*. Administrators only.
 *
 *  **Step 035b, and the gap it closes is that there was nothing here at all.** The route
 *  has been live since step 015 with both incident filters and a CLI reader; what it
 *  never had was a browser. The log that answers the question asked after an incident
 *  was reachable from a shell and invisible from the product.
 *
 *  Flat, with no `detail`, and that is the seam's shape showing through: the two
 *  producers of a refusal see a principal, a name and a level — no request body, no free
 *  text — so there is nothing unstructured for a record to carry.
 *
 *  `held` is **not optional here and has no default**, mirroring the server. `""` is a
 *  real value in this column: it means the principal held nothing, which is the headline
 *  case and the whole difference between a stranger probing and a `user` probing for
 *  `editor`. A default would make this type invent *"they held nothing"* about somebody
 *  in an incident record. */
export interface DenialRecord {
  v: number;
  ts: string;
  principal_kind: string;
  principal_id: string;
  /** What the refusal was about: an agent by name, the administrative surface, or —
   *  since migration 040 — a tool the MCP door refused. **Deliberately a plain `string`
   *  and not a union**, for `AdminRecord.action`'s reason: a kind added on the server
   *  must not make this screen stop rendering the log. `DenialsPage` prints it as a
   *  value and never switches on it. */
  resource_kind: string;
  /** The thing named, which **may be empty** — `require_admin`'s callers often pass no
   *  finer name than the surface itself, and refusing that would have turned the hook
   *  into a parameter every caller must remember. */
  resource_id: string;
  /** The level the request needed, and the level actually held. A `user` probing for
   *  `editor` reads differently from a stranger probing at all, and this pair is what
   *  says which. */
  required: string;
  held: string;
}

/** The kinds a denial can be about, as the **denial page's filter options**.
 *
 *  This is a copy of the server's `DENIAL_RESOURCE_KINDS`, and this file generally
 *  refuses copies of a server vocabulary — so the reason it is accepted here is worth
 *  stating, because it turns on what drift costs rather than on whether drift happens.
 *
 *  A kind added on the server and missing from this list is a **missing shortcut**. The
 *  rows still arrive, `DenialRecord.resource_kind` still carries the new word, and the
 *  Resource column still prints it, because the *rendering* path never switches on a
 *  kind. What is missing is one filter chip. That is the trade `AppShell` already takes
 *  when it hides an admin nav item — the courtesy is in the frontend and the authority is
 *  on the server — and it is a different trade from the stale `Literal` in
 *  `AgentAccessEntry.kind`, which turned a correct grant into a 500.
 *
 *  The filter's *validation* is not here: the server's signature refuses a kind it cannot
 *  hold, with a 422 naming the field rather than an empty 200 that reads as "none of
 *  those". */
export const DENIAL_RESOURCE_KINDS = ["agent", "admin", "tool"] as const;

/** One group, as the **menu**: enough to pick one, and no membership.
 *
 *  Membership is administrator-only and is deliberately not in this shape — "who is in
 *  every group" is a directory of the company, where a name only discloses that a team
 *  exists. See `api/routes_groups.py`, where that line is argued. */
export interface GroupSummary {
  group_id: string;
  name: string;
  description: string;
  /** Step 035h. Whether this group's membership comes from the customer's directory —
   *  the boolean, never the `external_id` it is computed from, which stays on the
   *  administrator-only `GroupDetail`.
   *
   *  It is on this shape because the menu is where the choice is made: two groups that
   *  look alike here behave differently once shared, and the sharer is the person who
   *  needs to know which they picked. `AgentAccessEntry.directory` is the same bit one
   *  route over, served at `user` since 033e, which is why this is a legibility fix
   *  rather than a new disclosure. */
  directory: boolean;
}

// --- the administration surface (12c) ---------------------------------------------------

/** One row of the egress allowlist.
 *
 *  `warning` is non-empty exactly when this host will never be dialled whatever the
 *  allowlist says — a loopback name, a private range, the link-local block cloud metadata
 *  services live on. Computed by the server per read rather than stored, because the rule
 *  is code and a stored copy of a rule goes stale.
 *
 *  **An empty list of these means the tenant can dial nothing.** An empty allowlist denies
 *  rather than permits, which is the one place in this product where "no rows" is a policy
 *  rather than an absence. */
export interface HostEntry {
  host: string;
  allowed_by: string;
  allowed_at: string;
  note: string;
  warning: string;
}

/** `POST /admin/hosts`. The host is echoed **normalized** — what actually landed in the
 *  table, which is the string every other route will name. */
export interface HostApproved {
  host: string;
  note: string;
  warning: string;
}

/** `DELETE /admin/hosts/{host}` and `DELETE /admin/connectors/{id}/oauth`.
 *
 *  `stranded` is the connectors now pointing at a host nobody will dial. They keep their
 *  registration and their vetting and stop connecting — which is the opposite of what
 *  somebody assumes happened, so it is a field rather than a silence. Always empty for the
 *  consent-flow delete, which strands nothing. */
export interface Revoked {
  host: string;
  removed: boolean;
  stranded: string[];
}

/** A connector's consent flow, **public fields only**.
 *
 *  There is no `client_secret` here and there is no masked echo of one either. The value is
 *  sealed and nothing in this system can retrieve it for a person, so `••••••` would imply
 *  something untrue — the screen renders the word *stored*. */
/** What one OAuth scope permits, for the person being asked to grant it. Step 068.
 *
 *  `access` is deliberately NOT `VettedTool.effect`. `effect` is per tool, is a judgment a
 *  vetter made, and the broker enforces it on every call. This is per scope, is a sentence
 *  a vendor wrote, and nothing enforces it — it is a label on somebody else's permission.
 *  See migration 051 for why collapsing the two would be a mistake. */
export interface ScopeNote {
  name: string;
  description: string;
  access: "read" | "write";
}

export interface OAuthApp {
  connector_id: string;
  authorize_endpoint: string;
  token_endpoint: string;
  revoke_endpoint: string;
  client_id: string;
  scopes: string[];
  authorize_params: Record<string, string>;
  /** Migration 051. Keyed by scope; a scope with nothing to say has no key, which is a
   *  different fact from an empty description and renders differently. */
  scope_notes: Record<string, ScopeNote>;
  configured_by: string;
  configured_at: string;
}

/** One host a recipe needs allowed, and why. Step 068.
 *
 *  The `why` is not decoration: approving a host widens where this workspace may dial,
 *  and "the recipe said so" is not a reason anybody can weigh. */
export interface RecipeHost {
  host: string;
  why: string;
}

/** A tool a recipe **proposes**. Nothing here has been approved.
 *
 *  Not a `VetRequest` and deliberately not the same type: a `VetRequest` is a decision
 *  somebody made and this is a suggestion nobody has looked at. Each still goes through
 *  the vetting form one at a time. */
export interface RecipeTool {
  remote_name: string;
  effect: "read" | "write";
  identity: "service" | "user";
  resources: Array<Record<string, unknown>>;
  local_name: string | null;
  max_response_bytes: number | null;
  description: string;
  note: string;
  redact_args: string[];
  binding: Record<string, unknown> | null;
}

/** A checked-in preset that pre-fills connector registration. Step 068.
 *
 *  Carries no client id and no client secret — a property of the files rather than of this
 *  projection. `staleness` is computed server-side at read time, never stored, which is
 *  `HostEntry.warning`'s precedent. */
export interface Recipe {
  id: string;
  name: string;
  description: string;
  verified_on: string | null;
  verified_by: string;
  verified_against: string;
  staleness: "verified" | "stale" | "unverified";
  hosts: RecipeHost[];
  connector: {
    connector_id: string;
    url: string;
    kind: "http" | "rest";
    credential_env: string;
    credential_header: string | null;
    credential_prefix: string | null;
    headers: Record<string, string>;
    description: string;
  };
  oauth: {
    authorize_endpoint: string;
    token_endpoint: string;
    revoke_endpoint: string;
    scopes: string[];
    authorize_params: Record<string, string>;
    scope_notes: Record<string, ScopeNote>;
  } | null;
  tools: RecipeTool[];
}

/** What configuring a consent flow answers.
 *
 *  `redirect_uri` is returned rather than documented because the person who has to register
 *  it at the provider is looking at this response. `warnings` is a list because there can be
 *  more than one and because neither is a refusal — see the server's reasoning. */
export interface OAuthConfigured {
  app: OAuthApp;
  redirect_uri: string;
  warnings: string[];
}

/** One approved tool, as an administrator sees it: the catalogue row plus provenance. */
export interface VettedTool {
  name: string;
  remote_name: string;
  description: string;
  note: string;
  effect: "read" | "write";
  /** Whose account it acts as — see `ToolSummary.identity`. */
  identity: "service" | "user";
  resources: ResourceType[];
  max_response_bytes: number | null;
  vetted_by: string;
  vetted_at: string;
  /** What the server called itself when this tool was approved — migration 023. Empty for
   *  anything vetted without contacting a server, and empty is what that says. */
  server_name: string;
  server_version: string;
}

/** One registered connector, as an administration list row.
 *
 *  `host_allowed` is checked against the allowlist **now**, not at registration: a host can
 *  be revoked after a connector was registered against it, and that connector then stops
 *  connecting while looking perfectly healthy. */
export interface ConnectorSummary {
  connector_id: string;
  description: string;
  transport: string;
  url: string;
  credential_env: string;
  /** 070: `op://vault/item/field` when this connector's shared credential is held in the
   *  customer's own vault and read at call time, `""` otherwise. Mutually exclusive with
   *  `credential_env` — the server refuses both. A **location**, never a value. */
  credential_ref: string;
  vetted: number;
  writes: number;
  host: string;
  host_allowed: boolean;
  /** Null when no consent flow is configured, which is a distinct fact from one configured
   *  with no scopes — and is exactly the Connections page's third state. */
  oauth: OAuthApp | null;
  /** 033c: whether an *asserted* acting-for through the MCP door is believed for this
   *  server's tools. False is the posture — verified or nothing — and "which of our
   *  connectors accept asserted identity" is the question a security review asks of
   *  this list. */
  allow_asserted_identity: boolean;
}

export interface ConnectorDetail extends ConnectorSummary {
  tools: VettedTool[];
}

/** One argument of an advertised tool. **The one thing a person cannot guess**, which is
 *  the whole reason discovery exists: `resources` needs the exact name this server uses,
 *  and an optional argument that widens reach when absent is invisible without `required`. */
export interface DiscoveredArgument {
  name: string;
  type: string;
  required: boolean;
}

export interface DiscoveredTool {
  name: string;
  description: string;
  arguments: DiscoveredArgument[];
  vetted: boolean;
  /** What this tool would be called here. Shown before anybody commits to it, rather than
   *  left to be learned from a name-collision refusal. */
  local_name: string;
}

/** One thing that changed since this connector was vetted.
 *
 *  `severity` is `refuse` or `report` and the difference is not cosmetic: a `refuse` finding
 *  blocks every further vetting on this connector until somebody deals with it, and a
 *  `report` is a newly advertised tool nobody has approved. Rendering them the same way
 *  would make the blocking one look optional. */
export interface DiscoveryFinding {
  severity: "refuse" | "report";
  message: string;
}

export interface DiscoveryResult {
  server: string;
  tools: DiscoveredTool[];
  findings: DiscoveryFinding[];
}

/** A resource, as the vetting form sends it — **structured, never the CLI's `TYPE=ARG`.**
 *
 *  `cli._parse_resource` owns that spelling and says why it stays there: it is a
 *  command-line spelling, and the moment the server's `Resource` learns one, a route ends
 *  up accepting the same string. `template` is required when `args` has more than one. */
export interface ResourceSpec {
  type: string;
  args: string[];
  template?: string | null;
}

/** How to make one REST tool's request — step 045a, and what discovery would have
 *  supplied if there were anything to ask.
 *
 *  Every property of `input_schema` must be mapped into the path, `query` or `body`, and
 *  every `{placeholder}` in the path must name one of them. Both are `check_binding`'s
 *  rules and both are refusals; the form pre-empts them because they are only meetable
 *  after typing the whole thing. */
export interface RestBindingSpec {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  query: string[];
  body: string[];
  input_schema: Record<string, unknown>;
  /** Where token usage lives in this API's answers, by dotted path. Optional, and only
   *  a model connector has ever needed it. */
  usage_map?: Record<string, string> | null;
}

export interface VetRequest {
  effect: "read" | "write";
  /** Whose account the tool acts as. Optional — the server defaults to `service`,
   *  which is what a missing key means everywhere else. */
  identity?: "service" | "user";
  resources: ResourceSpec[];
  note?: string;
  local_name?: string | null;
  max_response_bytes?: number | null;
  /** REST only, and required there: a REST API describes nothing, so vetting is
   *  authoring. Refused on an MCP connector, whose schema and description are the
   *  server's own words. */
  binding?: RestBindingSpec | null;
  /** REST only — the vetter's words, because there is no advertisement to copy. */
  description?: string;
  /** Arguments whose audit rows keep a hash rather than the value. For a model tool
   *  this is where `messages` goes: a prompt is the caller's content and `audit` is
   *  append-only. */
  redact_args?: string[];
}

export interface VetOutcome {
  local_name: string;
  remote_name: string;
  effect: string;
  identity: string;
  resources: string[];
  /** What the server called itself at the moment of approval. Recorded rather than
   *  trusted, and returned so the approver can see what they approved against. */
  server: string;
  actor: string;
}

/** A group **with its membership**, which is what makes it administrator-only.
 *
 *  "Who is in every group" is a directory of the company. The one legitimate non-admin need
 *  — *who will this share reach* — is answered per agent by `GET /agents/{name}/access`. */
export interface GroupMemberEntry {
  kind: string;
  id: string;
  added_by: string;
}

export interface GroupDetail extends GroupSummary {
  external_id: string | null;
  created_by: string;
  members: GroupMemberEntry[];
}

export interface MemberOutcome {
  group_id: string;
  kind: string;
  id: string;
  /** Whether anything happened. `PUT` and `DELETE` are both idempotent, and an
   *  administrator who cannot tell a no-op from a change cannot tell a working control from
   *  a broken one. */
  changed: boolean;
}

/** One API token the caller owns. Step 022b, `GET /me/tokens`.
 *
 *  There is no secret here and there never was one to omit: the server's only method
 *  that returns a hash is the one that compares against it, and this route does not call
 *  it. The one time a token's secret exists outside its hash is the moment `--mint-token`
 *  prints it, which is why minting has no route.
 *
 *  Revoked and expired rows arrive with the rest, and the **picker** is what greys them
 *  out. A listing that hid them would answer "you have no tokens" to somebody who has
 *  three dead ones, and hide the reason a schedule stopped firing. */
export interface OwnedToken {
  id: string;
  name: string;
  owner_id: string;
  /** **Personal or service, and it is the property that decides a token's blast
   *  radius.** True means this credential resolves its *owner's* grants and group
   *  memberships — live, as they change, capped at `user` — rather than grants held by
   *  the token itself. Step 033d put it on the row; it did not reach the wire until
   *  035c, because `OwnedToken` on the server had never declared it and a pydantic model
   *  drops what it does not name.
   *
   *  Chosen at mint time and immutable: to change kind you mint the other kind. So this
   *  is a fact to render, never a control — it is set once, on the mint form (step
   *  044) or at the terminal, and never edited. */
  acts_as_owner: boolean;
  created_by: string;
  created_at: string;
  /** Three nulls that mean three different things, and the picker branches on all
   *  three: never expires, never revoked, never used. */
  expires_at: string | null;
  revoked_at: string | null;
  revoked_by: string | null;
  last_used_at: string | null;
}

/** What `POST /me/tokens` answers: the listing row plus **the only copy of the
 *  secret**. Step 044. `token` exists exactly once, in this response — it is stored as
 *  a hash and nothing can show it again, which is what the shown-once panel says. */
export interface MintedToken extends OwnedToken {
  token: string;
}

/** What `DELETE /me/tokens/{id}` answers. `changed` is false when the token was
 *  already dead — the revocation is idempotent, and the two outcomes are different
 *  facts about the world. */
export interface TokenRevoked {
  id: string;
  revoked_at: string | null;
  changed: boolean;
}

/** Whether anyone has knocked on an agent through the MCP door — two scalars for the
 *  connect card's waiting state. Step 044. Denials count (a refused call arrived), and
 *  the count restarts across a rename, because the audit log keeps old names. */
/** The newest call the door itself refused for one of this agent's tools. Step 074.
 *  `reason` is the denial row's `required`: `grant` (no agent the token is granted
 *  provides the tool) or `acting-for` (the claim failed). */
export interface DoorRefusal {
  at: string;
  tool: string;
  token: string;
  reason: string;
}

export interface DoorActivity {
  calls: number;
  last_call_at: string | null;
  /** Absent from an API older than 070. */
  last_refusal?: DoorRefusal | null;
}

/** One agent a token is granted, as `GET /me/tokens/{id}/reach` reports it. Step 035d.
 *
 *  **Structurally a `Reachable`** — `features/agents/Reach.tsx`'s prop type — so the
 *  component the agent detail page and the create wizard both render a permission model
 *  with renders a token's reach unmodified, with `name` going in through its `title`
 *  prop. Deliberately *structural* rather than an `extends`: this file mirrors the wire
 *  and must not import a component, and `Reachable`'s own docstring says satisfaction by
 *  shape is the whole point of it being narrower than `AgentDetail`. */
export interface ReachableAgent {
  name: string;
  tools: string[];
  /** `{"github.repo": {"read": ["owner/name"]}}` */
  scope: Record<string, Record<string, string[]>>;
}

/** What a token is granted, without presenting it. Step 035d.
 *
 *  **A list of reaches rather than one of them, and that is the whole shape of this
 *  response.** In tool mode a token sees the union of the tools of the agents it is
 *  granted, *each tool keeping its own agent's scope* — and the second half is why one
 *  flat `{tools, scope}` cannot be the answer. One tool can be granted by several agents
 *  at different bounds (`triage` reads `acme/*`, `security-triage` reads
 *  `acme/secrets-*`, both granting `search_issues`), and which one applies is decided
 *  per call against the call's own arguments. Unioning the scopes would invent a
 *  permission nobody wrote down; picking one would refuse calls the caller is plainly
 *  granted.
 *
 *  So `tools` is the union of **names**, which is statically true, and `agents` carries
 *  the scopes, one section each.
 *
 *  `tools` is the server's and must stay so. It is what `tools/list` answers, computed by
 *  the same function the door computes it with — a `flatMap` here would be a third
 *  implementation of a rule this product has already been bitten by having two of. */
export interface TokenReach {
  token_id: string;
  /** Repeated from the listing because it is the *reason* `resolved_as` says what it
   *  says, not as a second copy of the row. */
  acts_as_owner: boolean;
  /** `kind:id` — whose grants actually answered. A personal token's are its **owner's**,
   *  live, and *which person* is the sentence an offboarding review came for. */
  resolved_as: string;
  /** The union of names, sorted. What an MCP client's `tools/list` would return —
   *  **a superset of it**, in fact: this reports the grant, while `tools/list` also
   *  drops anything whose connector will not bind right now. */
  tools: string[];
  agents: ReachableAgent[];
  /** The same grants, transposed — one row per tool. Step 069. */
  by_tool: ToolReach[];
  /** Granted, and its stored config no longer validates — so the door skips it and this
   *  page cannot show it. Named rather than dropped: *your token reaches two agents*
   *  about a token granted three is an absence that reads as a fact. */
  invalid_agents: string[];
}

/** One granted tool, with every agent that carries it. Step 069's reflect half.
 *
 *  **`agents` read the other way round.** The per-agent sections above are true and are
 *  not an answer to the question people arrive with, which is about a *tool*: the union
 *  rule keeps each tool at its own agent's scope, so a token holding three grants hands
 *  its reader a cross-reference exercise. This is that exercise, done.
 *
 *  `applies` is not an agent's whole scope map — it is the patterns that *can decide* a
 *  call to this tool, selected by its effect and its declared resource types. Keyed by
 *  resource type; an empty array is an agent that carries the tool and grants nothing at
 *  its effect, which is a refusal waiting to happen and worth seeing as one.
 *
 *  **There is no `attributed_to`, and its absence is a decision.** The union rule is
 *  *first **allow** wins*, so which agent an audit record names depends on the call's
 *  arguments. What is true statically is the *order* of `granted_by`, which is the
 *  door's own; `Simulation` answers the rest for a given call.
 *
 *  Computed by the server even though this client holds every input, for `tools`'
 *  reason one paragraph up: a `flatMap` here would be the union rule implemented again,
 *  in TypeScript, by the surface whose whole job is to explain it. */
export interface ToolReach {
  tool: string;
  /** `null` when nothing describes the tool — a granted name that is not vetted, or not
   *  vetted any more. Rare, and shown rather than dropped. */
  effect: string | null;
  resource_types: string[];
  granted_by: ToolReachGrant[];
}

export interface ToolReachGrant {
  agent: string;
  /** resource type -> the patterns granted at this tool's effect. */
  applies: Record<string, string[]>;
}

/** Whether a call would be admitted, and which rule decided. Step 069.
 *
 *  **`considered` is the answer, not `verdict`.** A boolean is what somebody could have
 *  got by making the call; what they could not get is *all three of my agents said no,
 *  and here is each one's reason*.
 *
 *  `verdict`, `rule` and `reason` belong to `attributed_to` — the first agent that
 *  allows, or the first candidate when none does, which is the agent a real call's audit
 *  record would name either way.
 *
 *  `not_checked` is the honest half and must be rendered rather than dropped: this
 *  answers permission and stops short of authentication, binding, the credential and the
 *  daily budget. A verdict that implies more than it checked is worse than no verdict. */
export interface Simulation {
  tool: string;
  /** `"allowed"` | `"refused"`. A string rather than a boolean because a third outcome
   *  is the kind of thing a later step adds, and widening a boolean is breaking. */
  verdict: string;
  attributed_to: string | null;
  /** One of the server's rule names, or `""` on an allow. Switched on rather than the
   *  sentence, because parsing prose is how a client starts re-deciding permission. */
  rule: "" | Rule | (string & {});
  reason: string;
  considered: ConsideredAgent[];
  not_checked: string[];
}

export interface ConsideredAgent {
  agent: string;
  allowed: boolean;
  rule: "" | Rule | (string & {});
  reason: string;
}

/** The nine names in `core/permissions.RULES`, one per refusal branch of
 *  `permissions.check`. **Copied, not derived** — the server closes the set with an
 *  AST test (`test_every_refusal_names_its_rule`) and the client pins its label map to
 *  this list, so a tenth branch fails a test on each side rather than rendering as an
 *  unexplained name in a browser. The `(string & {})` beside it on the wire types keeps
 *  an unknown name assignable: what the server sends renders, known or not. */
export type Rule =
  | "credential_smuggled"
  | "not_described"
  | "not_granted"
  | "resource_missing"
  | "composed_separator"
  | "no_grant_for_effect"
  | "outside_scope"
  | "unsupported_reference"
  | "headless_principal";

/** One UTC day of a token's door spending. Step 035e.
 *
 *  A window with no row in `mcp_budget` still arrives here with `calls: 0`, filled by the
 *  server. That is not an invented row — *0 when there is no row* is the storage layer's
 *  own documented contract — and it is filled there rather than here on purpose: a
 *  zero-fill in this client would be a second implementation of that rule, and a sparse
 *  list would make this page guess whether a gap is *no calls* or *no answer*. */
export interface SpentWindow {
  /** ISO date, the UTC day. */
  window_start: string;
  calls: number;
}

/** What a token has spent through the MCP door, and against what. Step 035e.
 *
 *  **Named for what it holds rather than for the route it comes from** (`/budget`),
 *  because *budget* means three different things in this system — a per-run counter, the
 *  door's per-token ceiling, and the table underneath it — and only one of them is here.
 *
 *  ## `calls` is **admitted**, not attempted, and the label is the whole point
 *
 *  A call refused by the permission check never reaches the budget, and one refused by
 *  the ceiling itself writes nothing either. So a token being denied five hundred times a
 *  day appears here as whatever it **succeeded** at — the opposite of what somebody
 *  investigating an incident is looking for. Say *admitted* on screen, and say what that
 *  excludes: the rest is on `/admin/door-calls` (every call the broker saw) and
 *  `/admin/denials` (the refusals that reached no broker), both of which need the role.
 *
 *  ## `metered` decides whether the figure means anything at all
 *
 *  A deployment can run unmetered (`CARNET_MCP_CALLS_PER_DAY=0`, or any value that is
 *  not positive), and the door then admits **without writing a row**. On such a
 *  deployment `calls` is 0 for a token that has been hammering the door all day, so a
 *  figure — `0 / 0`, `0 / 1000`, a bar at 0% — would say *this credential has barely been
 *  used* about the opposite. **When this is false, render the sentence and no figure.**
 *
 *  Nothing is deleted when the dial is turned off, so `history` may be genuinely
 *  non-empty while `metered` is false: what is in it was counted while the meter ran. */
export interface TokenSpend {
  token_id: string;
  /** Whose figures these are — every number on this page, calls and money alike.
   *  `owner` for a personal token: the person's, across every personal token they hold,
   *  so a second machine draws on the same day and a refusal on this one may be the
   *  other one's morning. `token` for a service token, whose allowance is its own.
   *  Step 108, decision 7 — the page renders a sentence from it rather than leaving the
   *  reader to assume the count is this credential's alone. */
  keyed_by: "owner" | "token";
  /** The UTC day the deployment answering considers today, ISO. The same definition the
   *  door charges against — deliberately not the browser's own idea of the date, which
   *  is the reader's local day and a different one for most of the world. */
  window: string;
  /** Admitted calls in `window`. Always equal to the last entry of `history`. */
  calls: number;
  /** `CARNET_MCP_CALLS_PER_DAY` on whichever replica answered. **A fact about the
   *  deployment, not about the row** — it is the one field here that is not a stored
   *  column, and it is read per request because an operator turns that dial mid-incident.
   *
   *  A number without its limit is not an answer, which is why it travels. */
  ceiling: number;
  /** Whether the ceiling counts anything. `ceiling > 0` computed by the server, because
   *  the door's own test is `<= 0` and a client writing `=== 0` would be wrong for a
   *  deployment set to a negative value — wrong in the reassuring direction. */
  metered: boolean;
  /** Seven UTC days, oldest first, ending at `window`. Dense — see `SpentWindow`. */
  history: SpentWindow[];

  // --- what it cost, step 045b -----------------------------------------------------
  //
  // **The subject is `keyed_by`'s, the same one `calls` above has.** Until step 108 the
  // two halves of this page had different subjects in their comments and the same one in
  // the code; now both are keyed on the owner for a personal token and on the token for
  // a service one, and there is one sentence on the page saying which.
  //
  // Two flags rather than one, because the two dials are independent: a deployment that
  // bounds tokens without pricing anything — every deployment brokering a provider the
  // built-in rate table has never heard of — has an honest $0 under a live token ceiling,
  // and a single flag would have to lie about one of them. Each obeys `metered`'s rule
  // above: **when it is false, render a sentence and no figure.**

  /** Estimated USD spent at a model through the door today, priced at read time. Short by
   *  whatever `unpriced_models` names — never present it as whole without saying so. */
  usd: number;
  /** `CARNET_MCP_USD_PER_DAY` on whichever replica answered. A fact about the
   *  deployment, read per request, for `ceiling`'s reason. */
  usd_ceiling: number;
  /** Whether the dollar ceiling counts anything. `> 0`, computed by the server, because
   *  the door's own test is `<= 0`. */
  usd_metered: boolean;
  /** Every token counted today, priced or not — the net beneath the dollar figure, and
   *  the number that bounds a model nobody has a price for. */
  tokens: number;
  /** `CARNET_MCP_TOKENS_PER_DAY`. */
  tokens_ceiling: number;
  /** Whether the token ceiling counts anything. */
  tokens_metered: boolean;
  /** Models that contributed tokens and no dollars, because the price list could not
   *  value them. Empty is *nothing was unpriced* — a real answer, not an absence. */
  unpriced_models: string[];
}

/** Which days the figures cover, echoed back rather than assumed.
 *
 *  `clamped` says the server answered a different window than the one asked for. A
 *  caller that requested a year and silently got a quarter would draw a quarter and
 *  label it a year. */
export interface OverviewWindow {
  days: number;
  /** The window's dates, always — never its first and last bucket label. With hour
   *  buckets the labels are `…T00` and `…T23`, and a footnote built from those would say
   *  "2026-08-31T00 to 2026-08-31T23, in UTC days". */
  since: string;
  until: string;
  clamped: boolean;
  /** How every dated series below is grouped. Step 066.
   *
   *  `"hour"` for the 24-hour window and `"day"` for the rest. The series keep the field
   *  name `day` either way and only the label format changes — `YYYY-MM-DD` or
   *  `YYYY-MM-DDTHH` — so this is what an axis formatter reads rather than the field's
   *  name. A client that ignored it would still render; it would just print a long tick. */
  bucket: "day" | "hour";
}

/** One day of door traffic.
 *
 *  **`errored` and `oversize` are bands *within* `allowed`, not siblings of it** — a
 *  call that was permitted and then failed is both. Stacking all four would draw a
 *  column taller than the day's traffic, so the page derives a disjoint set before it
 *  reaches a chart. `denied` is the only one of the four that is disjoint from
 *  `allowed`. */
export interface DoorDay {
  day: string;
  allowed: number;
  denied: number;
  errored: number;
  oversize: number;
  /** The other two outcome bands, step 066a. Bands **within** `allowed` like the two
   *  above, and the four do not sum to it: an admitted call whose outcome is `''` — the
   *  server recorded none — is in none of them, so `ok` is never "allowed minus the
   *  rest". */
  ok: number;
  unknown: number;
}

/** What one day's door calls cost. Step 045b, and the first money on the Overview.
 *
 *  **Beside `DoorDay`'s counts rather than inside them**, because the two are measured
 *  differently and a reader has to be able to see that: `allowed` and `denied` count
 *  every call, while these count only the calls whose tool *reported* what it spent. On a
 *  deployment brokering no model calls this series is flat zero under a busy traffic
 *  chart, and that is the truth rather than a gap.
 *
 *  `usd` is priced at read time from the rate table in force, never stored — an operator
 *  who corrects their prices can reprice this history. It is short by whatever
 *  `unpriced_models` names, so never present it as whole without saying so. */
export interface DoorSpendDay {
  day: string;
  usd: number;
  tokens: number;
  unpriced_models: string[];
}

export interface EffectDay {
  day: string;
  read: number;
  write: number;
}

/** One day's calls by **what the acting-for claim was worth** — the governance series.
 *
 *  Three counts and never a total. `verified` is a person's own IdP token, forwarded and
 *  checked; `asserted` is an application's word, believed only where the connector opted
 *  in; `none` is nobody named. Collapsing two of them would upgrade an asserted name to
 *  a verified one, which is the one thing this record exists to prevent. Refusals are
 *  counted here too — *what did we refuse, and on whose behalf* is the half an incident
 *  asks. */
export interface IdentityDay {
  day: string;
  verified: number;
  asserted: number;
  none: number;
}

/** Percentiles for a day, in whole milliseconds — **null where nothing was timed**.
 *
 *  Not zero. A day of refusals has no duration to report, and a zero would draw a chart
 *  claiming instant calls on a day when nothing ran. `queue_median_ms` is absent on the
 *  door's series: a door call is synchronous and queues for nothing. */
export interface LatencyDay {
  day: string;
  median_ms: number | null;
  p95_ms: number | null;
}

/** One caller's totals across the window — *who is using this*.
 *
 *  **The axis is the principal, not the token**, and that is stated rather than
 *  accidental: `audit` carries no token id, so one person's several personal tokens are
 *  one row here. *Which credential is hot* is a different question with its own screen.
 *
 *  **This list is the busiest N and no more**, capped by the server. `totals.callers` is
 *  every distinct caller and is counted separately — so the tile and this list disagree
 *  on a busy tenant, on purpose, and the page says which is which. */
/** What a capped leaderboard left out. Step 066.
 *
 *  Every ranked list on the Overview is the top fifteen, capped in SQL since 041 for a
 *  good reason. What 066 adds is that the cut is on the wire: a walkthrough found
 *  eighteen tools, a cap of fifteen, and a tool that had just been called appearing
 *  nowhere with nothing on the page admitting it.
 *
 *  `n` is 0 rather than absent when nothing was cut, so rendering "and no more" needs no
 *  test for absence. */
export interface LeaderboardTail {
  n: number;
  calls: number;
  denied: number;
}

/** One **permission list**'s totals. Step 066a.
 *
 *  An agent in Carnet is a named set of tools with a scope — the permission model
 *  itself, read on every door call. Every audit row has carried the name since the table
 *  existed and no figure grouped by it until now.
 *
 *  `tools` is the *exercised* breadth, not the granted breadth: an agent carrying forty
 *  tools and calling two is a scoping observation, and this is the half of it the log
 *  can answer. */
export interface AgentTotals {
  agent: string;
  calls: number;
  denied: number;
  tools: number;
}

/** Whose name a call went out under, and what the claim was worth. Step 066a.
 *
 *  Keyed on the **pair**, never on the name alone: one person reached once on their own
 *  verified token and once on an application's word is two rows here, because collapsing
 *  them would upgrade the second in the one record kept to tell them apart. */
export interface ActingForTotals {
  acting_for: string;
  identity_source: string;
  calls: number;
  denied: number;
}

/** One refusal sentence and how often it was written. Step 066a — the refusal chart says
 *  *which control*, and this says *what it said*. */
export interface RefusalReason {
  reason: string;
  count: number;
}

/** How long one tool took across the window. Step 066a.
 *
 *  Percentiles are `null` where nothing was timed, never 0 — a tool that was only ever
 *  refused has no duration to report. Capped and, alone among the leaderboards, without
 *  a tail: a remainder would have to be a percentile of the tools below the cap, and a
 *  median of medians is not a median. */
export interface ToolLatency {
  tool: string;
  calls: number;
  median_ms: number | null;
  p95_ms: number | null;
}

/** What the door carried back on one day. Step 066a — `oversize` is drawn on this page
 *  and the bytes behind it were aggregated nowhere. A sum of nothing is 0 and a
 *  percentile of nothing is not a number, which is why the two answer an empty day
 *  differently. */
export interface BytesDay {
  day: string;
  bytes: number;
  p95_bytes: number | null;
}

/** One weekday-and-hour's calls, across the whole window. Step 066b.
 *
 *  **`weekday` is 0=Monday.** Sparse: an hour nothing happened in is absent, and the grid
 *  draws it as an empty cell rather than as the bottom of the colour ramp — *nothing
 *  happened* and *the least that happened* are different facts. */
export interface HourCell {
  weekday: number;
  hour: number;
  calls: number;
}

export interface CallerTotals {
  principal_kind: string;
  principal_id: string;
  /** The person's email when this bar is a person's personal tokens pooled together
   *  (`principal_kind` is then `user` and `principal_id` their id); `""` for a service
   *  token, which stays its own bar. Step 108 — the label, and the key the bar's link
   *  to the door log filters by. */
  owner: string;
  calls: number;
  denied: number;
  writes: number;
  /** Distinct tools reached, as a count. The names belong on the token's own reach page. */
  tools: number;
  last_seen: string;
}

export interface ToolTotals {
  tool: string;
  effect: string;
  calls: number;
  denied: number;
}

/** Observed volume against the configured ceiling.
 *
 *  Computed from `audit`, never from the meter: `mcp_budget` is not written at all when
 *  the ceiling is off, so a deployment that measures without enforcing — the ordinary
 *  shape of a rollout — has heavy traffic and an empty table. `metered` is what says
 *  whether `ceiling` means anything; when it is false the page prints the volume and
 *  says so rather than drawing a gauge against a limit nobody is counting. */
export interface Headroom {
  metered: boolean;
  ceiling: number;
  busiest_day_calls: number;
  days_at_ceiling: number;
}

/** One day's refusals, in **five kinds that are never summed**.
 *
 *  A single "denials" line tells a manager nothing they can act on, because a spike
 *  could be any of five unrelated stories and three of them are the system working:
 *  `policy` is the broker refusing a call, `ceiling` is a token past its daily *call*
 *  allowance, `door_spend` is a credential past its daily *money* allowance,
 *  `run_budget` is an agent hitting its own `limits` block, and `access` is
 *  somebody refused a resource before any broker was reached.
 *
 *  `ceiling` and `door_spend` are kept apart for the reason they are separate ceilings:
 *  *too many calls* is usually a loop or a dial set too tight, *too much money* is a real
 *  bill arriving, and one line summing them would spike identically for either. */
export interface RefusalDay {
  day: string;
  policy: number;
  ceiling: number;
  door_spend: number;
  run_budget: number;
  access: number;
}

/** One family of administrative change on one day. The family is the action's prefix
 *  before the first dot, so `grant.create` and `grant.revoke` are both `grant`. */
export interface AdminDay {
  day: string;
  family: string;
  count: number;
}

/** The tile row's sums. No ratios: a percentage shipped beside its own numerator and
 *  denominator is a third number that can drift from the two it came from. */
export interface OverviewTotals {
  door_calls: number;
  door_denied: number;
  door_writes: number;
  door_verified: number;
  callers: number;
  refusals: number;
  admin_changes: number;
  /** What the door cost over the window — the sum of `door_spend`'s days, so the tile and
   *  the chart cannot disagree by a rounding step. Step 045b. */
  door_usd: number;
  door_tokens: number;
  /** Models that contributed tokens and no dollars anywhere in the window. `door_usd` is
   *  short by them; empty means nothing was unpriced. */
  door_unpriced_models: string[];
}

export interface Overview {
  window: OverviewWindow;
  totals: OverviewTotals;
  /** The same-length window immediately before this one, as totals alone. Step 066a.
   *
   *  A denominator, not a second dataset: "4,120 calls" is a number nobody can size, and
   *  "4,120, up 18%" is a fact. `null` where the server had no preceding window to read.
   *
   *  **All-zeros is not the same as null.** A quiet fortnight and a deployment younger
   *  than its own window both come back as zeros, and telling them apart needs the age
   *  of the log, which nothing asks for. */
  previous: OverviewTotals | null;

  door_calls: DoorDay[];
  door_spend: DoorSpendDay[];
  door_effects: EffectDay[];
  identity: IdentityDay[];
  door_latency: LatencyDay[];
  /** 066a. Beside the latency rather than on it: two measures of different scale are two
   *  figures, and no chart here has ever had a second y-axis. */
  door_bytes: BytesDay[];
  callers: CallerTotals[];
  door_tools: ToolTotals[];

  /** 066. Every cap's true size and what it left out. Beside the lists rather than
   *  inside them — a tail is a fact about the query and a row is a fact about a caller,
   *  and a sixteenth synthetic row would put something that is not a caller in a list of
   *  callers. */
  caller_tail: LeaderboardTail;
  tool_count: number;
  tool_tail: LeaderboardTail;

  /** 066a. The three dimensions every audit row carried and no figure grouped by. */
  door_agents: AgentTotals[];
  agent_count: number;
  agent_tail: LeaderboardTail;
  acting_for: ActingForTotals[];
  acting_for_count: number;
  acting_for_tail: LeaderboardTail;
  refusal_reasons: RefusalReason[];
  refusal_reason_count: number;
  refusal_reason_tail: LeaderboardTail;
  tool_latency: ToolLatency[];
  /** 066b. Window-wide, never a series. */
  hourly: HourCell[];
  headroom: Headroom;

  refusals: RefusalDay[];
  admin_actions: AdminDay[];
}

/** The windows `GET /admin/overview` will answer for, and the only ones.
 *
 *  Fixed rather than free, and the copy of the server's own list is bounded on purpose:
 *  a value missing here is a missing button, not a missing answer — the route clamps to
 *  the nearest and says so in `window.clamped`. */
export const OVERVIEW_WINDOWS = [1, 7, 30, 90] as const;

/** A registered OAuth client, as the consent page reads it. Step 083. The redirect list
 *  is returned so the page can refuse a decision on an address the client never
 *  registered — the same comparison the server makes at consent. */
export interface OAuthClient {
  client_id: string;
  client_name: string;
  client_uri: string;
  redirect_uris: string[];
}

/** The authorize request's parameters, carried through the consent page, plus the
 *  person's decision. Nulls are parameters the request did not carry. */
export interface OAuthConsent {
  client_id: string;
  redirect_uri: string;
  approve: boolean;
  state: string | null;
  response_type: string | null;
  code_challenge: string | null;
  code_challenge_method: string | null;
  resource: string | null;
  scope: string | null;
  token_name: string | null;
}
