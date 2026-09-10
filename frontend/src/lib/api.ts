/** The only module in this app that calls the API.
 *
 * One place that knows the URLs, one place that attaches the token, and — the reason
 * this is a rule rather than a habit — **one place that implements the 401 rule.** A
 * second `fetch` somewhere in a component would be a second opinion about what an
 * expired token means, and the two would differ under exactly the conditions nobody
 * tests.
 *
 * (`auth.ts` also calls `fetch`, once, at the identity provider's token endpoint. That
 * is a different server and a different protocol, and folding it in here would make
 * this module depend on the thing that depends on it.)
 *
 * ## The 401 rule, which is this codebase's own distinction finally being used
 *
 * `api/deps.py` goes out of its way to answer `401 {"detail": "token expired"}` for an
 * expired token and a different sentence for every other 401, and says why: *"Told apart
 * from every other 401 because a client can act on it: refresh and retry, rather than
 * prompting somebody who is already signed in."* This is the first client, and it acts
 * on it:
 *
 *   - **401 `token expired`** — renew, retry once. The person notices nothing.
 *   - **any other 401** — the token is forged, from another issuer, or no longer
 *     verifiable. Renewing would loop. Sign out.
 *   - **403** — thrown, never retried, and rendered with the server's own sentence.
 *     `deps.py`: *"the message IS returned here, because it is actionable by a
 *     person"*. A UI that signed out on a 403 would loop on a login that cannot help.
 *
 * ## No cache
 *
 * Fetch on mount, poll where the resource changes underneath. Decision 6: what looks
 * like app state is server state, and a copy of it here is a cache that can be stale.
 */

import { bearer, renew, signOut } from "./auth";
import type {
  AdminRecord,
  AgentAccess,
  AgentCreated,
  AgentDetail,
  AgentSummary,
  AgentVersion,
  AgentVersionSummary,
  ConnectorDetail,
  ConnectorSummary,
  DenialRecord,
  DiscoveryResult,
  DoorActivity,
  DoorCallRecord,
  MintedToken,
  Overview,
  GrantOutcome,
  HostApproved,
  HostEntry,
  MemberOutcome,
  OAuthConfigured,
  Recipe,
  ScopeNote,
  Revoked,
  ConnectionSummary,
  ConsentStart,
  DisconnectOutcome,
  GroupDetail,
  GroupSummary,
  Me,
  ToolGroup,
  VetOutcome,
  VetRequest,
  OwnedToken,
  Simulation,
  TokenReach,
  TokenRevoked,
  TokenSpend,
  OAuthClient,
  OAuthConsent,
} from "./types";

/** Every call goes under here, and the reason is a bug rather than a style.
 *
 *  The API's paths are `/agents` and `/tools`; so are this app's routes. Served from one
 *  origin — which is the whole point of the dev proxy, and how the plan has this
 *  deployed — the server answers first, so a **reload** on `/agents/abc123` returns JSON
 *  instead of the app. Clicking to the same page works, because React Router never asks
 *  the server. See the note in vite.config.ts; found by loading a URL rather than
 *  clicking to it.
 *
 *  The prefix is stripped by whatever forwards the request, so the API's own URLs stay
 *  clean for `curl`, the CLI and any integration. */
const BASE = "/api";

export class ApiError extends Error {
  readonly status: number;
  /** The server's `detail`, which in this API is written to be read by a person. */
  readonly detail: string;
  /** Everything else in the body. `RunNotCancellable` puts `run_id` and `status` here,
   *  because prose is not something a client can branch on. */
  readonly extra: Record<string, unknown>;

  constructor(status: number, detail: string, extra: Record<string, unknown> = {}) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.extra = extra;
  }
}

/** Thrown when there is no token at all. Distinct from a 401: nothing was sent. */
export class NotSignedIn extends Error {}

async function request<T>(
  path: string,
  init: RequestInit = {},
  retry = true,
): Promise<T> {
  const token = await bearer();
  if (!token) throw new NotSignedIn("not signed in");

  const response = await fetch(BASE + path, {
    ...init,
    headers: {
      ...(init.headers ?? {}),
      Authorization: `Bearer ${token}`,
      // JSON unless the body is `FormData`, in which case the browser must set the
      // header itself — a multipart body needs a `boundary=` parameter that only the
      // browser knows, and naming the type here produces a request the server cannot
      // parse. Step 028's upload is the one caller that sends `FormData`.
      ...(init.body && !(init.body instanceof FormData)
        ? { "Content-Type": "application/json" }
        : {}),
    },
  });

  if (response.ok) {
    return response.status === 204 ? (undefined as T) : ((await response.json()) as T);
  }

  const body = await readProblem(response);
  const detail = typeof body.detail === "string" ? body.detail : response.statusText;

  if (response.status === 401) {
    if (detail === "token expired" && retry) {
      // The one recoverable 401. Renew and try again exactly once — a second failure
      // is not a stale token, it is something renewal cannot fix.
      if (await renew()) return request<T>(path, init, false);
      throw new NotSignedIn(detail);
    }
    signOut(detail);
    throw new NotSignedIn(detail);
  }

  const { detail: _drop, ...extra } = body;
  throw new ApiError(response.status, detail, extra);
}

async function readProblem(response: Response): Promise<Record<string, unknown>> {
  try {
    const parsed: unknown = await response.json();
    // FastAPI answers a validation failure with `detail` as a list of objects. Never
    // shown raw — a person reading "loc: body.task" learns nothing.
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const record = parsed as Record<string, unknown>;
      if (Array.isArray(record.detail)) {
        return { ...record, detail: "the request was not in a shape the server accepts" };
      }
      // Step 083. The OAuth routes answer in the RFCs' shape — `error` and
      // `error_description` — because the MCP SDK parses that. Read the description as
      // the sentence, so the consent page shows it rather than the status text.
      if (record.detail === undefined && typeof record.error_description === "string") {
        return { ...record, detail: record.error_description };
      }
      return record;
    }
  } catch {
    /* not JSON: fall through to the status text */
  }
  return {};
}

export const api = {
  listAgents: () => request<AgentSummary[]>("/agents"),

  getAgent: (name: string) =>
    request<AgentDetail>(`/agents/${encodeURIComponent(name)}`),

  /** Everything this tenant may grant, and which of it writes.
   *
   *  The one route in this API that is **not** filtered by grant. It answers "what
   *  could I grant", which is asked before anything exists to be granted — the person
   *  about to create their first agent has no grants at all. It discloses which
   *  connectors this organisation vetted and what they approved: not what any agent may
   *  do, not who has access to anything, and not a single resource identifier.
   *
   *  Fetched once per screen and not polled. A vetting decision changes when a person
   *  runs a CLI command, which is not a rate anything here needs to keep up with. */
  listTools: () => request<ToolGroup[]>("/tools"),

  /** Create an agent. **201**, and the caller becomes its owner in the same transaction.
   *
   *  The body **is** the config — no creation-specific shape, which is decision 1 at the
   *  place it would be most tempting to break. See `AgentDraft` in schemas.py.
   *
   *  Three failures worth branching on, and only one of them is a bug:
   *
   *    409  somebody already has that name. Not a replacement, ever
   *    422  the validator refused it, in a sentence written to be read by a person
   *    401  handled here, like everywhere else
   *
   *  No `Idempotency-Key`, deliberately, and it is worth saying why given `startRun` has
   *  one. A retried create is idempotent *by consequence*: the second attempt hits the
   *  primary key and answers 409, so the worst case is somebody being told the name they
   *  just successfully used is taken. That is a confusing sentence and not a second
   *  agent. A run has no such key and is why that route needed one. */
  createAgent: (config: unknown) =>
    request<AgentCreated>("/agents", { method: "POST", body: JSON.stringify(config) }),

  /** Ask the server whether a draft would be accepted, without writing anything.
   *
   *  Resolves for a valid draft and **throws an `ApiError(422)`** for an invalid one,
   *  carrying the validator's own sentence — the same response `createAgent` gives it.
   *  There is no `{valid: false}` to check, which is what stops this screen developing a
   *  second opinion about what an error looks like.
   *
   *  It cannot tell you whether the name is free. That is a 409 and a race, and only the
   *  create can answer it. */
  validateDraft: (config: unknown) =>
    request<{ valid: true }>("/agents/validate", {
      method: "POST",
      body: JSON.stringify(config),
    }),

  /** Change part of an agent. **A partial config, and conditional on `updated_at`.**
   *
   *  `If-Match` is not optional and the server answers **428** without it. That is the
   *  whole of 10d in one header: a `PATCH` with no precondition is last-write-wins, which
   *  is how one person silently reverts another's scope narrowing — and it fails silently
   *  by construction, so it has to be refused rather than defaulted.
   *
   *  `updatedAt` is echoed from `AgentDetail.updated_at`, unchanged. Never build one.
   *
   *  Failures worth branching on:
   *
   *    409  somebody else saved while this form was open. `extra.changed` names the
   *         top-level keys this save disagrees with the stored version about, and
   *         `extra.updated_at` is the version to reload — an empty `changed` means the
   *         save was a no-op and reloading loses nothing
   *    422  the merged config is one the validator refuses, in its own sentence
   *    400  the body named a different agent — renaming is not this operation
   *    404  no grant at `editor`, or no agent. The same 404, deliberately */
  updateAgent: (name: string, patch: unknown, updatedAt: string) =>
    request<AgentDetail>(`/agents/${encodeURIComponent(name)}`, {
      method: "PATCH",
      headers: { "If-Match": `"${updatedAt}"` },
      body: JSON.stringify(patch),
    }),

  /** Give an agent a different name. **`owner`, and no `If-Match`.**
   *
   *  Answers the whole `AgentDetail` at the new name, with a new ETag. This screen throws
   *  both away and navigates, because every card on the detail page is keyed by the name
   *  in the URL and re-fetches under the new one — but the route returns them and this
   *  mirrors the route.
   *
   *  **`owner`, not `editor`, is the route's one access decision** and it is argued
   *  there: an editor changes what an agent *does*; this changes what it is *called*,
   *  which is the URL somebody bookmarked and the string in an outside system's runbook.
   *  A caller below that level gets **404**, not 403 — `grants.require` says the same
   *  sentence for ungranted, held-too-low and absent — so a Rename button rendered for an
   *  editor answers *"no agent named 'triage'"* about the agent on screen. It is rendered
   *  from `your_role` for exactly that reason.
   *
   *  **No `If-Match`, deliberately, and this is the one write on an agent without one.**
   *  An edit form races another edit form and needs a precondition; a rename is one
   *  deliberate act from an owner, serialized on the row, and the second of two
   *  concurrent renames finds no agent by the old name and gets the 404 that is true.
   *
   *  **The old URL is an ordinary 404 afterwards** — no redirect, no memory of former
   *  names, so that a freed name is genuinely free rather than ghost-routed at whoever
   *  takes it next. That cost is the owner's and `RenameBox` is where they are told.
   *
   *  Failures, all four of which the CLI hands to one sentence:
   *
   *    409  another agent already has that name — and it does not say who owns it,
   *         because that would answer "does `payroll-bot` exist and who runs it"
   *    422  a name the slug rules or the reserved list refuse, or the name it already
   *         has. Three refusals, one status, each a written sentence
   *    404  no grant, or no agent. The same 404 */
  renameAgent: (name: string, newName: string) =>
    request<AgentDetail>(`/agents/${encodeURIComponent(name)}/rename`, {
      method: "POST",
      body: JSON.stringify({ new_name: newName }),
    }),

  /** Delete an agent. **204, `owner` only, and there is no undo.**
   *
   *  The row goes and its grants go with it. `audit` and `admin_audit` keep the history.
   *  What is gone is the
   *  agent, and a second call answers 404 rather than 204, because 404 is also what
   *  somebody with no grant gets and this route cannot say which. */
  deleteAgent: (name: string) =>
    request<void>(`/agents/${encodeURIComponent(name)}`, { method: "DELETE" }),

  /** Whether anyone has knocked on this agent through the MCP door — the connect
   *  card's question, readable at `user` like every other read on the agent. Step 044.
   *  Two scalars, cheap enough to poll while somebody watches for the first call. */
  doorActivity: (name: string) =>
    request<DoorActivity>(`/agents/${encodeURIComponent(name)}/door-activity`),

  /** Every configuration this agent has had, newest first. Readable at `user`.
   *
   *  The same level that reads the agent, because it is the same bytes at a different
   *  age — a runner can already see today's instructions.
   *
   *  **A save that changed nothing is absent from this and present in the admin log.**
   *  The history holds distinct states; the log holds writes. Capped by the server, and
   *  not paginated — every list in this API is the same, and that is one register row
   *  rather than a convention per screen. */
  agentVersions: (name: string) =>
    request<AgentVersionSummary[]>(`/agents/${encodeURIComponent(name)}/versions`),

  /** One stored configuration, whole. `user`, and a 404 for a version never written —
   *  the same 404 as an agent you may not see, deliberately. */
  getAgentVersion: (name: string, version: number) =>
    request<AgentVersion>(
      `/agents/${encodeURIComponent(name)}/versions/${version}`,
    ),

  /** Put an old configuration back. **`editor`, and conditional on `updated_at`.**
   *
   *  A restore writes a **new** version whose content is the old one; the version being
   *  restored stays exactly where it is, so a restore is itself restorable.
   *
   *  **This is not `updateAgent` with an old config**, and the difference is silent:
   *  `PATCH` merges at the top level, so a key the old config does not carry survives
   *  from the live one. Restoring a version written before a field existed through
   *  `PATCH` produces neither version while reporting success. There is no way to
   *  remove a field over HTTP at all — hence a route.
   *
   *  Failures worth branching on:
   *
   *    409  somebody saved while this page was open — same shape as `updateAgent`'s
   *    422  this version would no longer validate; the sentence says why, and the
   *         history already said so beside the row
   *    428  no `If-Match` — the same refusal a `PATCH` makes
   *    404  no grant at `editor`, no agent, or no such version. The same 404 */
  restoreAgentVersion: (name: string, version: number, updatedAt: string) =>
    request<AgentDetail>(
      `/agents/${encodeURIComponent(name)}/versions/${version}/restore`,
      { method: "POST", headers: { "If-Match": `"${updatedAt}"` } },
    ),

  /** Who can reach this agent, and how, plus who is still waiting. Readable at `user`. */
  agentAccess: (name: string) =>
    request<AgentAccess>(`/agents/${encodeURIComponent(name)}/access`),

  /** Share it. `editor`, idempotent, and keyed by grantee — which is why it is a `PUT`
   *  on a URL naming them rather than a `POST /share`.
   *
   *  `kind` is `user`, `group`, or **`email`**, and the third is not a grantee kind: an
   *  address is how a person thinks about sharing, and whether it lands as a grant or as
   *  a pending row is a fact about whether that person has ever logged in. The answer's
   *  `outcome` says which happened — render it, because the two look identical otherwise
   *  and only one of them means anybody has access. */
  shareAgent: (name: string, kind: string, grantee: string, role: string) =>
    request<GrantOutcome>(
      `/agents/${encodeURIComponent(name)}/grants/${kind}/${encodeURIComponent(grantee)}`,
      { method: "PUT", body: JSON.stringify({ role }) },
    ),

  /** Take access away. **204**, and a 400 when the access is inherited — the server
   *  refuses rather than deleting nothing and reporting success, and its sentence names
   *  the group. Render it. */
  unshareAgent: (name: string, kind: string, grantee: string) =>
    request<void>(
      `/agents/${encodeURIComponent(name)}/grants/${kind}/${encodeURIComponent(grantee)}`,
      { method: "DELETE" },
    ),

  /** Every connector this organisation has vetted, and **your own** state for each.
   *
   *  Like `listTools`, this needs no grant: it is the menu of what you could connect,
   *  not anybody's data. Unlike `listTools`, the answer differs per person — it is the
   *  first route in this API that is about the signed-in person rather than about an
   *  agent, which is why Connections is a page rather than a section of one. */
  listConnections: () => request<ConnectionSummary[]>("/connections"),

  /** Begin a consent flow. Returns **where to send the browser**, and never a token.
   *
   *  The caller must then do a top-level navigation — `window.location.assign(url)` — not
   *  a fetch. See `ConsentStart`.
   *
   *  `returnTo` is where the provider's callback lands the browser afterwards, and the
   *  server refuses anything that is not a path within this app: it becomes a `Location`
   *  header, and an absolute URL there is an open redirect on our own domain. */
  startConnect: (connectorId: string, returnTo: string) =>
    request<ConsentStart>(
      `/connectors/${encodeURIComponent(connectorId)}/connect` +
        `?return_to=${encodeURIComponent(returnTo)}`,
      { method: "POST" },
    ),

  /** Disconnect your own account. **200 with a body, not 204** — see `DisconnectOutcome`
   *  for why the answer cannot be empty. */
  disconnect: (connectorId: string) =>
    request<DisconnectOutcome>(
      `/connectors/${encodeURIComponent(connectorId)}/connection`,
      { method: "DELETE" },
    ),

  /** Who the caller is, here — including whether they may administer this workspace.
   *
   *  **Fetched once, at the shell, and not polled.** A role changes when somebody runs a
   *  CLI command, which is not a rate anything here needs to keep up with, and polling it
   *  would put a query on every screen for a bit that almost never moves.
   *
   *  Needs no role, which is the point: a non-administrator calls this precisely in order
   *  to be told they are not one, so this app does not render a door that refuses them.
   *  `AgentDetail.your_role`'s problem, one level up. */
  me: () => request<Me>("/me"),

  /** The administrative log — *who changed who may do what*. **Administrators only.**
   *
   *  A **403** for everybody else, carrying the server's own sentence. Rendered rather
   *  than paraphrased and never retried: `deps.py` writes it to be actionable by a
   *  person, and a UI that signed out on it would loop on a login that cannot help.
   *
   *  Oldest first, most recent `limit` records. No filters and no pagination — those
   *  arrive with evidence about what somebody actually needs, matching `--admin-log`'s
   *  deliberate cheapness. `limit` is capped by the server's signature, so an over-large
   *  value is a 422 naming the field rather than a silent truncation. */
  adminAudit: (limit = 200) => request<AdminRecord[]>(`/admin-audit?limit=${limit}`),

  /** The MCP door's traffic — every tool call a machine token made through `/mcp`.
   *  **Administrators only**, and a 403 for everybody else carrying the server's own
   *  sentence, exactly as `adminAudit` does.
   *
   *  Step 035a, and the reason it is its own route rather than a filter on the run
   *  surface: a door call has no prompt, config or version, so it is not a run, and a
   *  run list containing things that are not runs would be lying about both. The rows
   *  are in the same `audit` table `getRun` reads — what separates them is a
   *  correlation id shaped `door-<hex>`, which the run route can never resolve.
   *
   *  Oldest first, most recent `limit` records, capped by the server's signature — so an
   *  over-large value is a 422 naming the field rather than a silent truncation that
   *  would read as "that is everything".
   *
   *  **Ten filters since 066, and an options object like `adminDenials`'** rather than
   *  the positional `limit` this had: those take one argument because their routes take
   *  one, and a fourth positional `undefined` at a call site is how a filter ends up in
   *  the wrong slot. The route earned them by finally having both halves of the
   *  condition it wrote down — an incident argument (the Overview, whose every figure is
   *  one of these queries and which could not point at a single row behind any of its
   *  numbers) and an index (migration 050).
   *
   *  The closed vocabularies are refused by the server with a 422 naming the field; the
   *  open ids are not validated anywhere and match nothing when they match nothing. That
   *  asymmetry is the route's and this client does not soften it — a value it rejected
   *  locally would be a second, quieter copy of the server's vocabulary. */
  adminDoorCalls: (
    options: {
      limit?: number;
      since?: string;
      until?: string;
      tool?: string;
      agent?: string;
      principalId?: string;
      principalKind?: string;
      actingFor?: string;
      /** The person, by email, across every personal token they hold. Step 108. */
      owner?: string;
      decision?: string;
      outcome?: string;
      effect?: string;
      identitySource?: string;
    } = {},
  ) => {
    const query = new URLSearchParams({ limit: String(options.limit ?? 200) });
    // Set only when asked for, `adminDenials`' rule — an empty string is a value the
    // server would refuse for a closed vocabulary and would match nothing for an id, so
    // "no filter" has to be an absent parameter rather than a blank one.
    //
    // **`outcome` is the exception and is spelled out**, because `""` is a real stored
    // value there: the column is `NOT NULL DEFAULT ''`, so *the calls nothing was
    // recorded for* is a question this filter can put, and a truthiness check would
    // silently turn it into "do not narrow".
    const pairs: [string, string | undefined][] = [
      ["since", options.since],
      ["until", options.until],
      ["tool", options.tool],
      ["agent", options.agent],
      ["principal_id", options.principalId],
      ["principal_kind", options.principalKind],
      ["acting_for", options.actingFor],
      ["owner", options.owner],
      ["decision", options.decision],
      ["effect", options.effect],
      ["identity_source", options.identitySource],
    ];
    for (const [key, value] of pairs) if (value) query.set(key, value);
    if (options.outcome !== undefined) query.set("outcome", options.outcome);

    return request<DoorCallRecord[]>(`/admin/door-calls?${query}`);
  },

  /** The window's activity, refusals and change, in one response — **administrators
   *  only**, and a 403 for everybody else carrying the server's own sentence, exactly as
   *  `adminAudit` does.
   *
   *  Step 041, and the one aggregating read in this API. Every other route here returns
   *  rows and lets the caller count them; this one returns eleven series already
   *  counted, because the alternative is a browser summing a tenant's whole audit log to
   *  draw a bar.
   *
   *  **One method for one page.** Eleven routes would give this screen eleven loading
   *  states and the chance for two of them to straddle a write and disagree about what
   *  happened — a chart of admitted calls and a chart of refusals that do not add up to
   *  the same traffic.
   *
   *  `days` is clamped by the server to the nearest window it offers rather than
   *  refused, and `window.clamped` says whether it moved. A dashboard that will not load
   *  because somebody typed a number into a URL is worse than one that loads the largest
   *  honest answer and says so. */
  overview: (days = 30) => request<Overview>(`/admin/overview?days=${days}`),

  /** The access-denial log — *who tried, and was refused*. **Administrators only**, and
   *  a 403 for everybody else carrying the server's own sentence, exactly as `adminAudit`
   *  does. A non-admin's attempt on this route lands in this very log: it records its own
   *  door.
   *
   *  Step 035b, and the route it calls has been live since 015 — this is the first thing
   *  in a browser ever to call it.
   *
   *  **An options object rather than positionals**, which is a break from `adminAudit`
   *  and `adminDoorCalls` and is the route's shape showing through: those take one
   *  argument because their routes take one, and a fourth positional `undefined` at a
   *  call site is how a filter ends up in the wrong slot.
   *
   *  The three filters are the route's, all optional and all applied by the server. The
   *  two ids are the incident queries migration 028's indexes exist for — *"what else did
   *  this person probe?"* and *"who probed payroll-bot?"*. `resourceKind` is 035b's
   *  addition and answers *"which of these came from the door"* without this client
   *  filtering a page it was already given, which would be a lie about completeness in a
   *  log view. A kind the server cannot hold is a **422**, not an empty list.
   *
   *  Oldest first, most recent `limit` records, capped by the server's signature. */
  adminDenials: (
    options: {
      limit?: number;
      principalId?: string;
      resourceId?: string;
      resourceKind?: string;
    } = {},
  ) => {
    const query = new URLSearchParams({ limit: String(options.limit ?? 200) });
    // Set only when asked for. An empty string is a value the server would refuse for
    // `resource_kind` and would match nothing for the two ids, so "no filter" has to be
    // an absent parameter rather than a blank one.
    if (options.principalId) query.set("principal_id", options.principalId);
    if (options.resourceId) query.set("resource_id", options.resourceId);
    if (options.resourceKind) query.set("resource_kind", options.resourceKind);
    return request<DenialRecord[]>(`/admin/denials?${query}`);
  },

  /** Every group in this workspace: id, name, description. **No role required.**
   *
   *  The menu rather than the directory — membership is administrator-only and is not in
   *  this shape. An `editor` sharing an agent with a group has to pick one, and before
   *  12b the share sheet could only take an id somebody was told out of band. */
  listGroups: () => request<GroupSummary[]>("/groups"),

  // --- administration: groups (12c) ----------------------------------------------------
  //
  // 12b shipped these routes with no screen and argued why that was not 7b's
  // routes-without-a-screen mistake: their consumer *was* the engineer who runs
  // `--add-group`. This is the non-technical consumer arriving.

  /** One group **and who is in it**. Administrators only — membership is the directory. */
  getGroup: (groupId: string) =>
    request<GroupDetail>(`/groups/${encodeURIComponent(groupId)}`),

  createGroup: (name: string, description: string, externalId?: string) =>
    request<GroupDetail>("/groups", {
      method: "POST",
      body: JSON.stringify({
        name,
        description,
        // Omitted rather than sent empty: `null` and `""` are different states in
        // `GROUP_FIELDS`, and only one of them means *this group follows a directory*.
        external_id: externalId?.trim() || null,
      }),
    }),

  /** Hand a group's membership to the workspace's directory, or take it back.
   *
   *  Step 033e. Linking is a takeover: from here on the members are whoever the groups
   *  claim names, applied at each person's next sign-in, so anybody in it the directory
   *  does not name is removed as they arrive. `null` unlinks and removes nobody. */
  linkGroup: (groupId: string, externalId: string | null) =>
    request<GroupDetail>(`/groups/${encodeURIComponent(groupId)}`, {
      method: "PATCH",
      body: JSON.stringify({ external_id: externalId }),
    }),

  /** **204, and every access it carried goes with it** — on every agent, immediately, and
   *  nobody is told. Warn before calling this. */
  deleteGroup: (groupId: string) =>
    request<void>(`/groups/${encodeURIComponent(groupId)}`, { method: "DELETE" }),

  /** Idempotent, and `changed` says whether it did anything. A group may not be a member
   *  of a group — refused by a rule that predates these routes, arriving as a 400. */
  addMember: (groupId: string, kind: string, id: string) =>
    request<MemberOutcome>(
      `/groups/${encodeURIComponent(groupId)}/members/${kind}/${encodeURIComponent(id)}`,
      { method: "PUT" },
    ),

  /** Idempotent, and **200 with a body rather than 204**: removing somebody takes away
   *  every access they had through this group, on every agent, immediately, and nothing
   *  tells them. An administrator pressing that deserves to know whether it happened. */
  removeMember: (groupId: string, kind: string, id: string) =>
    request<MemberOutcome>(
      `/groups/${encodeURIComponent(groupId)}/members/${kind}/${encodeURIComponent(id)}`,
      { method: "DELETE" },
    ),

  // --- administration: connectors (12c) ------------------------------------------------
  //
  // The onboarding ordering migration 021 forces, as five calls: approve a host, register
  // a connector, look at what it offers, approve tools one at a time, and — if people are
  // to connect their own accounts — configure a consent flow. Each stage needs the one
  // before it to exist, which is why the screen is a sequence rather than a form.

  listHosts: () => request<HostEntry[]>("/admin/hosts"),

  /** The connector presets this build ships. Step 068.
   *
   *  Reads files on the server and touches no tenant, so the answer is the same for
   *  everybody — admin-gated because it is a control on the registration screen, not
   *  because it is secret. A recipe fills this form and decides nothing: it vets no tool,
   *  approves no host, and carries no client id or secret. */
  listRecipes: () => request<Recipe[]>("/admin/recipes"),

  /** Approve a host. **The host goes in the body, not the path**, because people paste
   *  URLs when adding one and a `/` in a path segment is a routing 404 even
   *  percent-encoded. In the body the refusal is a 400 that says what to strip.
   *
   *  200 always carries `warning`, non-empty when the host approved is one that will never
   *  be dialled. Render it: the row is real and the control is not in force, and being told
   *  plain *yes* is the failure the whole egress module is written against. */
  approveHost: (host: string, note: string) =>
    request<HostApproved>("/admin/hosts", {
      method: "POST",
      body: JSON.stringify({ host, note }),
    }),

  /** Withdraw a host. **`stranded` names the connectors that now cannot connect** — they
   *  keep their registration and their vetting, which is not what somebody assumes. */
  revokeHost: (host: string) =>
    request<Revoked>(`/admin/hosts/${encodeURIComponent(host)}`, { method: "DELETE" }),

  listConnectors: () => request<ConnectorSummary[]>("/admin/connectors"),

  getConnector: (connectorId: string) =>
    request<ConnectorDetail>(`/admin/connectors/${encodeURIComponent(connectorId)}`),

  /** Register a connector. **201, and it vets nothing** — nothing this server offers is
   *  reachable until somebody approves a tool on it, one at a time.
   *
   *  409 when the id is taken, and it is not a replacement: re-registering would replace a
   *  vetted allowlist wholesale, so nine approved tools must not be lost to a mistyped id. */
  registerConnector: (body: {
    connector_id: string;
    url: string;
    credential_env: string;
    /** 070: hold the shared credential in the customer's own 1Password vault instead —
     *  `op://vault/item/field`, resolved at call time and never stored. Optional because
     *  the wire defaults it to `""`; sending both this and a non-empty `credential_env`
     *  is a 400, because there is no rule for which would win. */
    credential_ref?: string;
    description: string;
    /** What the URL is — step 047, and it decides how tools get onto this connector at
     *  all: `http` is a Streamable HTTP MCP server whose tools are **discovered**,
     *  `rest` is a plain API whose tools are **authored**. Optional because the wire
     *  defaults it to `http`, which is what every caller before 047 meant. There is no
     *  update path by design: the two have different security properties and
     *  `_launch_from_dict` refuses to guess between them. */
    kind?: "http" | "rest";
    /** The header the credential is presented in, and what precedes it. Defaults live
     *  on the launch dataclass (`Authorization` / `Bearer `); `""` is a real prefix and
     *  is not the same as omitting the field — a vendor reading `x-api-key` wants the
     *  bare token. REST only: an MCP server's scheme is protocol convention. */
    credential_header?: string;
    credential_prefix?: string;
    /** Non-secret headers sent on every request — an API version, typically. The
     *  credential is the one named by `credential_env` and never belongs here. */
    headers?: Record<string, string>;
    /** 033c, and optional because the wire's is: `ConnectorRequest` defaults it false, so a
     *  request type that demanded it would claim to be stricter than the model it posts to.
     *  Settable **here** so a connector born trusting a caller says so from its first
     *  administrative record; changed afterwards through `setAssertedIdentity`, which is a
     *  security control's state change getting its own log line. */
    allow_asserted_identity?: boolean;
    /** Step 068. **Provenance, never a link.** The id of the recipe whose values filled
     *  this form, recorded in the administrative log and nowhere else — no column, no
     *  foreign key, so deleting a recipe can never orphan anything. The server checks it
     *  names a recipe this build ships and drops it silently otherwise: the registration
     *  is correct either way, and failing it over a provenance hint would make a log line
     *  load-bearing. */
    from_recipe?: string;
  }) =>
    request<ConnectorSummary>("/admin/connectors", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  /** 033c: turn asserted acting-for on or off for one connector. A security control
   *  being switched — it writes its own administrative record naming who and which
   *  way. What it gates is whether the MCP door *believes* an email a calling service
   *  asserts; a verified acting-for (a forwarded IdP token) needs no switch. */
  setAssertedIdentity: (connectorId: string, allowed: boolean) =>
    request<ConnectorSummary>(
      `/admin/connectors/${encodeURIComponent(connectorId)}/asserted-identity`,
      { method: "PUT", body: JSON.stringify({ allowed }) },
    ),

  /** Ask the server what it offers **right now**. A `POST` although it writes nothing: it
   *  opens a connection to a third party, which is not a safe method's contract.
   *
   *  Discovers with **your own** stored connection for this connector. A **502** means the
   *  customer's own server did not answer — not our outage and not your mistake. */
  discover: (connectorId: string) =>
    request<DiscoveryResult>(
      `/admin/connectors/${encodeURIComponent(connectorId)}/discovery`,
      { method: "POST" },
    ),

  /** Approve one tool. **Append, never replace** — a failed tenth never costs nine, and
   *  re-vetting restamps that row alone.
   *
   *  Every way of getting this wrong is a 400 with a sentence written for the person
   *  filling in the form: a tool the server does not advertise, named beside what it does
   *  offer; a resource pointing at an argument that is not in the schema; a write with
   *  nothing to scope it to; a connector whose existing vetting has drifted. Render them. */
  vetTool: (connectorId: string, remoteName: string, body: VetRequest) =>
    request<VetOutcome>(
      `/admin/connectors/${encodeURIComponent(connectorId)}/tools/` +
        encodeURIComponent(remoteName),
      { method: "PUT", body: JSON.stringify(body) },
    ),

  /** Configure a consent flow. **The secret goes and does not come back.**
   *
   *  Sent once, in the body, over TLS — never a query string, which is server logs and
   *  browser history. Nothing in this API ever returns it, not even masked: a masked echo
   *  implies the value is retrievable and it is not. */
  configureOAuth: (
    connectorId: string,
    body: {
      authorize_endpoint: string;
      token_endpoint: string;
      revoke_endpoint: string;
      client_id: string;
      client_secret: string;
      scopes: string[];
      /** Provider-specific parameters on the sign-in link — Atlassian mandates `audience`
       *  and `prompt`. **The seven the flow builds itself are refused**, with a sentence
       *  per name, and two of those sentences are the security design rather than
       *  bookkeeping. They arrive as a 400 and are rendered verbatim.
       *
       *  A wholesale replace, like every other field here: what this body omits, the stored
       *  row loses. */
      authorize_params: Record<string, string>;
      /** Migration 051: what each scope permits, in words the person granting it can
       *  read. **Every key must be a scope in `scopes`** — a note describing a permission
       *  this flow does not request is a 400 naming both lists, because it would appear
       *  on the screen where somebody decides whether to grant it.
       *
       *  A wholesale replace like the rest of this body. */
      scope_notes?: Record<string, ScopeNote>;
    },
  ) =>
    request<OAuthConfigured>(
      `/admin/connectors/${encodeURIComponent(connectorId)}/oauth`,
      { method: "PUT", body: JSON.stringify(body) },
    ),

  /** Remove a consent flow. **Credentials people already gave are untouched** and keep
   *  working until they expire — what they lose is the ability to renew. */
  removeOAuth: (connectorId: string) =>
    request<Revoked>(`/admin/connectors/${encodeURIComponent(connectorId)}/oauth`, {
      method: "DELETE",
    }),

  /** The API tokens **you** own. Step 022b, and no role is required — the person who
   *  needs it is a non-administrator picking among their own machines, and an
   *  admin-gated listing would be useless to exactly them.
   *
   *  Minting and revoking have no route and are not getting one: what a stolen bearer
   *  token lacks is persistence, and a mint route hands it a durable successor. Listing
   *  grants nothing — every field here is one `--list-tokens` already prints.
   *
   *  Revoked and expired tokens are **included**. Grey them out; do not drop them. */
  myTokens: () => request<OwnedToken[]>("/me/tokens"),

  /** The consent page's read — step 083. Behind the session, because a registration
   *  is not a public directory. A 400 (`invalid_client`) is "no such client". */
  oauthClient: (clientId: string) =>
    request<OAuthClient>(`/oauth/clients/${encodeURIComponent(clientId)}`),

  /** The person's decision on an MCP client's authorize request. Answers with where the
   *  browser goes next — always a redirect URI the client registered — or a 400 that
   *  names why nothing is redirected. The page navigates to whatever it is told and
   *  decides nothing about URLs. */
  oauthConsent: (body: OAuthConsent) =>
    request<{ redirect_to: string }>("/oauth/consent", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  /** Mint an API token **owned by you**, and receive its secret exactly once. Step 044.
   *
   *  The response's `token` field is the only copy that will ever exist — it is stored
   *  as a hash, so the panel that renders it is the last place it can be read. There is
   *  no owner field: the route mints for its caller, always, and a machine caller is
   *  refused (no credential that survives its presenter may create another).
   *
   *  `expires_days` omitted means never — revoke it to end it. */
  mintToken: (body: {
    name: string;
    acts_as_owner?: boolean;
    expires_days?: number;
  }) =>
    request<MintedToken>("/me/tokens", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  /** Revoke a token you own (an administrator may revoke anybody's). Idempotent —
   *  `changed: false` means it was already dead, which is a different fact from
   *  "revoked just now" and rendered as one. */
  revokeToken: (tokenId: string) =>
    request<TokenRevoked>(`/me/tokens/${encodeURIComponent(tokenId)}`, {
      method: "DELETE",
    }),

  /** What one of your tokens is **granted** — the door's own answer, without the door.
   *
   *  A token's reach was computable and readable nowhere: the only way to find it out was
   *  to present the credential to `/mcp` and read `tools/list`, which needs the secret,
   *  at the exact moment somebody suspects the token is over-broad.
   *
   *  Authorized on **who owns the row**, not on a role — `tokens.require_owner_or_admin`,
   *  the same rule that decides who may aim a token at a schedule. So it answers for your
   *  own tokens, and for an administrator reading anybody's.
   *
   *  **Reading is not using**: this does not move `last_used_at`, which is the column an
   *  offboarding review reads and which reviewing must not rewrite.
   *
   *  **A revoked, expired or owner-disabled token still answers.** Reach follows the
   *  *grant*; whether the credential works today is the four stamps on the listing row.
   *  Render both — *this is what it is granted* beside *and it is revoked* — because a
   *  refusal here would read as "it reaches nothing" to the one person asking.
   *
   *  Failures worth branching on:
   *
   *    400  no token of that id you may aim — a typo, another customer's real id, or a
   *         colleague's, all in one sentence. Since 069 those are indistinguishable on
   *         purpose: the 403 that used to separate them also named the owner
   */
  tokenReach: (tokenId: string) =>
    request<TokenReach>(`/me/tokens/${encodeURIComponent(tokenId)}/reach`),

  /** Would this call be admitted, and which rule decided. Step 069.
   *
   *  The door's own `_granted_agents`, `_candidates` and `_adjudicate`, invoked without
   *  executing the tool — one code path, because a simulator with its own copy of the
   *  matcher is a second opinion about permission and the first time they disagree the
   *  simulator is believed.
   *
   *  **`POST` for the body, not for a change.** `arguments` is a dict and a query string
   *  carries one badly; nothing is executed, dialled, charged or recorded — including no
   *  audit row for itself, which plan 069 argues rather than assumes.
   *
   *  Refusals are `tokenReach`'s, from the same function. */
  simulateCall: (tokenId: string, tool: string, args: Record<string, string>) =>
    request<Simulation>(`/me/tokens/${encodeURIComponent(tokenId)}/simulate`, {
      method: "POST",
      body: JSON.stringify({ tool, arguments: args }),
    }),

  /** What one of your tokens has **spent** through the MCP door today, and against what
   *  ceiling. Step 035e — the first reader `mcp_budget` has ever had outside the test
   *  suite, though the door has been writing it since migration 040.
   *
   *  The gap it closes: when a token starts refusing calls, the refusal names the ceiling
   *  and **only the caller holding the credential ever sees it**. The person who comes to
   *  a browser asking why the nightly job stopped at three had the token's id and no
   *  answer anywhere in the product.
   *
   *  Authorized on **who owns the row**, not on a role — `tokens.require_owner_or_admin`,
   *  the same rule as `tokenReach` and the schedule surfaces. Reading it does not move
   *  `last_used_at`, and a revoked or expired token still answers: *what was that
   *  credential spending before I killed it* is asked after a revocation, not before.
   *
   *  **Three things about the answer that decide how it may be rendered:**
   *
   *    - `calls` is **admitted**, not attempted. Refusals cost nothing and are not
   *      counted here — they are on `/admin/door-calls` and `/admin/denials`
   *    - when `metered` is false the door writes **no rows at all**, so `calls: 0` means
   *      *nothing was counted*. Render the sentence, never a figure
   *    - `ceiling` is a property of the deployment that answered, not of the token
   *
   *  Failures worth branching on:
   *
   *    400  no token of that id in this workspace. A typo, never an outage — and the
   *         same sentence for another customer's real id, deliberately
   *    403  it is somebody else's and you are not an administrator; the owner is named
   */
  tokenBudget: (tokenId: string) =>
    request<TokenSpend>(`/me/tokens/${encodeURIComponent(tokenId)}/budget`),
};
