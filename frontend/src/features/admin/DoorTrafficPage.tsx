import { useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";

import Failure from "../../components/Failure";
import { Badge, Button, Card, Empty, PageHead, Spinner, Tag } from "../../components/ui";
import { api, LOG_PAGE } from "../../lib/api";
import { ms, on } from "../../lib/format";
import type { Tone } from "../../components/ui";
import type { DoorCallRecord, IdentitySource } from "../../lib/types";
import { usePagedLog } from "../../lib/usePagedLog";
import { LogId } from "./logIds";

/** The MCP door's traffic, rendered — *what came through the door, for whom, and was it
 * allowed*.
 *
 * **This is 035a's deliverable, and it exists because four chunks of plan 033 deferred
 * it with the same sentence.** Every tool-mode call has written a complete audit record
 * since 033b: the tool, the agent whose grant carried it, the machine token that called,
 * whom it was acting for, how much that claim was worth, the decision, the outcome. And
 * none of it was reachable from a browser. The richest rows in the log were the ones
 * nothing could ask for.
 *
 * ## The three identity sources are never collapsed
 *
 * This is the whole reason 033c stored three values instead of a boolean, and this page
 * is where the decision either survives or quietly dies. `verified` means a forwarded
 * IdP token was checked. `asserted` means the calling application said so and nobody
 * checked — it is worth exactly what that application's honesty is worth, which is why a
 * connector has to opt into accepting one at all. `none` means nobody was named.
 *
 * A page that rendered the first two the same way — or rendered *"acting for tom@…"*
 * without saying which — would not be losing a detail. It would be **upgrading an
 * unverified claim**, in the one record kept to tell them apart. So the three get three
 * different treatments, and `none` is rendered as the sentence it is rather than as
 * blank space, because an absent name is an answer.
 *
 * ## The filters are in the URL, which is new for a log screen here — step 066
 *
 * `DenialsPage` holds its filters in React state, against this codebase's repeated
 * argument that an administrator sends a link to a colleague, and it did so for one
 * concrete reason: `Failure` rendered every 422 as *"This agent's configuration is not
 * valid"*, and a filter in a URL is one keystroke from `?decision=banana` — a screen
 * answering a typo with a confident sentence about a different noun.
 *
 * `DEFERRED.md` recorded that with the fix and the trigger together: the fix is
 * `Failure`'s, *"and it is worth doing before the second log screen wants the same
 * thing."* This is the second log screen. 066 retitled the 422 to say what a 422 means,
 * so the reason to keep filters out of the URL is gone — and the reason to put them in
 * has arrived, because the Overview now links here and a link *is* a URL with filters
 * in it.
 *
 * Read straight from `useSearchParams` with no local mirror. A mirror would be a second
 * source of truth for what the page is showing, and the failure mode is the one this
 * repo has refused everywhere else: two values free to disagree, silently.
 *
 * ## The filter bar, and *Show older* — 110f, plan 107 D10
 *
 * The narrowings above were only ever *arrived at*: the Overview linked here with a
 * filter chosen, and the page could show it and drop it but not set one. An
 * administrator asking *what did this token call yesterday* had to compose the URL by
 * hand. The bar writes the same URL the Overview writes — six fields, submitted, into
 * the query string — so a filter typed here is a link a colleague can open, and the
 * chips beneath still name each one. The eleven-entry table above is untouched: the bar
 * covers the six a person types, and the rest still arrive by link.
 *
 * Newest first, a page at a time, keyed on the oldest id shown — `usePagedLog` argues
 * why an id rather than an offset. The cap and its hint are gone: a filtered page is no
 * longer the recent end of a match nobody could see past.
 *
 * ## What is deliberately not here
 *
 * `args` and `credential` are on the stored record and not on the wire — the server
 * drops them at `api/schemas.DoorCallRecord`. One is caller-supplied free text in a
 * record kept forever; the other is a lookup key nobody asked to read in a browser.
 * Both remain available to the CLI and to an incident query. This page is not the place
 * that decision gets reversed by adding a column.
 *
 * No polling. The log is a record of what happened, not a thing in flight, and a table
 * that refreshed under a reader comparing two rows would be worse than a stale one.
 */
/** The filters this page reads from the URL, and the sentence each one narrows by.
 *
 *  A table rather than eleven pieces of JSX, because every one of them is the same
 *  control — a value from the query string, a sentence naming it, and a way to drop it —
 *  and eleven hand-written copies is where the eighth one clears the wrong parameter.
 *
 *  `label` takes the value because the sentence has to name it: *"Only calls to
 *  create_issue"* is a filter somebody can check against what they expected, and
 *  *"Filtered by tool"* is not. */
const FILTERS: { key: string; label: (value: string) => string }[] = [
  { key: "since", label: (v) => `From ${v}` },
  { key: "until", label: (v) => `To ${v}` },
  { key: "tool", label: (v) => `Only calls to ${v}` },
  { key: "agent", label: (v) => `Only calls through ${v}` },
  { key: "principal_id", label: (v) => `Only calls from ${v}` },
  { key: "principal_kind", label: (v) => `Only ${v} callers` },
  { key: "acting_for", label: (v) => `Only calls on behalf of ${v}` },
  { key: "owner", label: (v) => `Only calls by ${v}, on any of their personal tokens` },
  { key: "decision", label: (v) => (v === "deny" ? "Only denied calls" : "Only allowed calls") },
  { key: "outcome", label: (v) => (v ? `Only calls that ended ${v}` : "Only calls with no recorded outcome") },
  { key: "effect", label: (v) => `Only ${v} calls` },
  { key: "identity_source", label: (v) => `Only calls on a ${v} identity` },
];

export default function DoorTrafficPage() {
  const [params, setParams] = useSearchParams();

  // Read straight from the URL — no local copy. `?? undefined` rather than `|| undefined`
  // for `outcome` alone, because `""` is a real stored value there and asking for *the
  // calls nothing was recorded for* must survive the read.
  const get = (key: string) => params.get(key) ?? undefined;
  const outcome = params.has("outcome") ? (params.get("outcome") ?? "") : undefined;

  const { rows: data, error, loading, more, fetching, older } = usePagedLog(
    (before, limit) =>
      api.adminDoorCalls({
        before,
        limit,
        since: get("since"),
        until: get("until"),
        tool: get("tool"),
        agent: get("agent"),
        principalId: get("principal_id"),
        principalKind: get("principal_kind"),
        actingFor: get("acting_for"),
        owner: get("owner"),
        decision: get("decision"),
        outcome,
        effect: get("effect"),
        identitySource: get("identity_source"),
      }),
    LOG_PAGE,
    // The whole query string, so any filter change refetches and none is forgotten from
    // a hand-maintained list of eleven.
    [params.toString()],
  );

  const active = FILTERS.filter(({ key }) => params.has(key));
  const drop = (key: string) => {
    const next = new URLSearchParams(params);
    next.delete(key);
    setParams(next, { replace: true });
  };
  const clear = () => setParams(new URLSearchParams(), { replace: true });
  // A value from a row, as a narrowing: the tool cell is a filter button because a tool
  // has no page of its own (`logIds`), and *every call to this tool* is the question
  // migration 040's index answers.
  const pick = (key: string) => (value: string) => {
    const next = new URLSearchParams(params);
    next.set(key, value);
    setParams(next, { replace: true });
  };

  return (
    <>
      <PageHead
        title="Request log"
        lede="Tool calls made through the MCP server, newest first."
      />

      <FilterBar params={params} onApply={(next) => setParams(next, { replace: true })} />

      {/* **Narrowings, not a filter builder.** There is no dropdown for `tool` and no
          input for `principal_id`, and that is deliberate: this page is where the
          Overview's figures land, so a filter arrives already chosen and what a reader
          needs here is to *see* what they are looking at and be able to drop it. A form
          for constructing queries by hand is a different screen and nobody has asked for
          one.

          Each narrowing names its value, so a reader can check the link did what they
          expected — the failure a filtered log has that an unfiltered one does not is
          reading as "nothing happened" when it means "nothing matched". */}
      {active.length > 0 && (
        <div className="log-filters">
          <span className="muted">Showing:</span>
          {active.map(({ key, label }) => (
            <Button key={key} kind="quiet" onClick={() => drop(key)}>
              {label(params.get(key) ?? "")} &times;
            </Button>
          ))}
          {active.length > 1 && (
            <Button kind="quiet" onClick={clear}>
              Clear filters
            </Button>
          )}
        </div>
      )}

      {loading && <Spinner label="Loading…" />}
      {error && <Failure error={error} />}

      {data && data.length === 0 && active.length === 0 && (
        <Empty title="No requests yet">
          <p className="sentence">
            Requests appear here when a client calls a tool through the MCP server.
          </p>
        </Empty>
      )}

      {/* **Told apart from the empty log on purpose**, which is `DenialsPage`'s rule and
          matters more here because a reader arrives by following a link from a chart: an
          empty result that reads as "nothing came through the door" would contradict the
          bar they just clicked, and one of the two would be believed. */}
      {data && data.length === 0 && active.length > 0 && (
        <Empty title="No matching requests">
          <p className="sentence">Remove a filter above to widen the search.</p>
        </Empty>
      )}

      {data && data.length > 0 && (
        // The count is what is on screen; *Show older* beneath says whether there is
        // more. "Matching" since 066, because the page filters: a hundred requests under
        // a filter is a hundred of the match, and a title that said "requests" would
        // read as the log.
        <Card
          title={`${data.length} matching ${data.length === 1 ? "request" : "requests"}`}
        >
          {/* Eight columns of mono identifiers and a failure sentence do not fit a
              narrow window, and a table that does not fit has to scroll *inside its
              own card* — the alternative is the page scrolling sideways, which moves
              the navigation off screen to read a log. */}
          <div className="scroll-x">
            <table>
              <thead>
                <tr>
                  <th>When</th>
                  <th>Tool</th>
                  <th>Agent</th>
                  <th>Called by</th>
                  <th>On behalf of</th>
                  <th>Decision</th>
                  <th>Outcome</th>
                  <th>Duration</th>
                </tr>
              </thead>
              <tbody>
                {data.map((record) => (
                  // Keyed by the store's sequence number since 110f. `run_id` looks like
                  // one and is not — a correlation id is a correlation, not a primary
                  // key — and the index was right only while a page was never appended
                  // to.
                  <tr key={record.id}>
                    <td className="mono">{on(record.ts)}</td>
                    <td>
                      {/* `write` marked, because the read/write annotation is what a
                          connector admin sat down and decided, and it is the one property
                          of a tool that says whether a mistake is recoverable. The name
                          is the filter for it: a tool has no page to link to. */}
                      <Tag write={record.effect === "write"}>
                        <LogId
                          kind="tool"
                          id={record.tool}
                          onPick={pick("tool")}
                          title="Show only calls to this tool"
                        />
                      </Tag>
                    </td>
                    <td className="mono">
                      <LogId kind="agent" id={record.agent} />
                    </td>
                    <td>
                      {/* The person where there is one — step 108, and the one
                          question a customer opens this page with — with the token id
                          beneath, because *which machine* is still a real question
                          during an incident. A service token, a session and the system
                          have no person and show the id alone, as before. The token id
                          links to the token's page (110f); a session or the system has
                          none and stays text. */}
                      {record.owner ? (
                        <>
                          <div>{record.owner}</div>
                          <div className="muted mono small">
                            <LogId kind={record.principal_kind} id={record.principal_id} />
                          </div>
                        </>
                      ) : (
                        <LogId kind={record.principal_kind} id={record.principal_id} />
                      )}
                    </td>
                    <td>
                      <ActingFor record={record} />
                    </td>
                    <td>
                      <Badge tone={record.decision === "allow" ? "good" : "bad"}>
                        {record.decision}
                      </Badge>
                    </td>
                    <td>
                      <Outcome record={record} />
                    </td>
                    <td className="mono">
                      {record.duration_ms === null ? "" : ms(record.duration_ms)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {more && (
            <p className="log-more">
              <Button kind="quiet" busy={fetching} onClick={older}>
                Show older
              </Button>
            </p>
          )}
        </Card>
      )}
    </>
  );
}

/** The six filters a person types, as a form that writes the URL. Plan 107 D10.
 *
 *  Local state for the six inputs only until **Apply**: the URL is the page's truth
 *  about what it shows, and a bar that refetched on every keystroke would turn
 *  `?tool=jira_s` into a request for a tool that does not exist, four times, on the way
 *  to the one that does. Submitting replaces those six keys and leaves the other five
 *  (`decision`, `acting_for`, `owner`, `effect`, `identity_source`) as they arrived, so
 *  a link from the Overview narrowed to denials stays narrowed to denials while the
 *  reader adds a tool.
 *
 *  `outcome` is a select because its blank is a value: *not recorded* is
 *  `outcome=`, a stored `''`, and the page's own note above explains why that survives
 *  the client. The select's *any* is the absent key. */
const OUTCOMES: { value: string; label: string }[] = [
  { value: "*", label: "any outcome" },
  { value: "ok", label: "ok" },
  { value: "error", label: "error" },
  { value: "unknown", label: "unknown" },
  { value: "", label: "not recorded" },
];

function FilterBar({
  params,
  onApply,
}: {
  params: URLSearchParams;
  onApply: (next: URLSearchParams) => void;
}) {
  const [tool, setTool] = useState(params.get("tool") ?? "");
  const [agent, setAgent] = useState(params.get("agent") ?? "");
  const [token, setToken] = useState(params.get("principal_id") ?? "");
  const [outcome, setOutcome] = useState(params.has("outcome") ? (params.get("outcome") ?? "") : "*");
  const [since, setSince] = useState(params.get("since") ?? "");
  const [until, setUntil] = useState(params.get("until") ?? "");

  const apply = (event: FormEvent) => {
    event.preventDefault();
    const next = new URLSearchParams(params);
    const typed: [string, string][] = [
      ["tool", tool.trim()],
      ["agent", agent.trim()],
      ["principal_id", token.trim()],
      ["since", since],
      ["until", until],
    ];
    for (const [key, value] of typed) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    if (outcome === "*") next.delete("outcome");
    else next.set("outcome", outcome);
    onApply(next);
  };

  return (
    <form className="log-filter-form" onSubmit={apply} aria-label="Narrow the log">
      <label>
        Tool
        <input value={tool} onChange={(e) => setTool(e.target.value)} placeholder="jira_search_issues" />
      </label>
      <label>
        Agent
        <input value={agent} onChange={(e) => setAgent(e.target.value)} placeholder="triage" />
      </label>
      <label>
        Token
        <input value={token} onChange={(e) => setToken(e.target.value)} placeholder="tok_…" />
      </label>
      <label>
        Outcome
        <select value={outcome} onChange={(e) => setOutcome(e.target.value)}>
          {OUTCOMES.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
      <label>
        From
        <input type="date" value={since} onChange={(e) => setSince(e.target.value)} />
      </label>
      <label>
        To
        <input type="date" value={until} onChange={(e) => setUntil(e.target.value)} />
      </label>
      <Button type="submit">Apply</Button>
    </form>
  );
}

/** Whom the call was made for, and how much that claim is worth — never one without the
 *  other.
 *
 *  Driven by `identity_source` rather than by whether `acting_for` is set, because the
 *  source is the authoritative field: it is written on **every** record, denials
 *  included, and a renderer that inferred it from the presence of a name would have to
 *  guess at exactly the distinction the field exists to remove. */
export function ActingFor({ record }: { record: DoorCallRecord }) {
  if (record.identity_source === "none") {
    // A sentence rather than blank space. The call was made by the token on its own
    // behalf, which is a fact, and an empty cell reads as missing data.
    return <span className="muted">nobody named</span>;
  }

  return (
    <span className="acting-for">
      <span className="mono">{record.acting_for}</span>
      <Badge tone={SOURCE_TONE[record.identity_source]}>{record.identity_source}</Badge>
    </span>
  );
}

/** The three sources, in three colours, and never two of them in one.
 *
 *  `asserted` is `warn` deliberately: it is not an error — the connector opted into
 *  accepting it — and it is not the same as proof. A reader scanning this column for
 *  what to trust should find that difference without reading a word, and then find the
 *  word anyway, because `Badge` never means anything by colour alone. */
const SOURCE_TONE: Record<IdentitySource, Tone> = {
  verified: "good",
  asserted: "warn",
  none: "waiting",
};

/** What happened, and — where the server wrote one — why.
 *
 *  A denial carries an empty `outcome` and a `reason`; since step 041 an errored,
 *  oversize or unknown call carries a reason **too** — the same sentence the caller was
 *  handed, kept, because before that the log could say a call failed and nothing
 *  anywhere could say why. Either way it is printed **verbatim**: it is the sentence
 *  the broker wrote at the moment it happened, and a paraphrase here would be a second
 *  wording free to drift from the one the audit trail supports.
 *
 *  It is also the widest thing in this table — a vendor's timeout names a host, a port
 *  and a pool — so `td .row-sub` bounds it and lets it wrap. Unbounded, one failure
 *  sentence sets the width of the whole column.
 *
 *  `unknown` is the one outcome that needs a person. It means a write reached an
 *  external system and never answered — it may or may not have taken effect, and this
 *  record is the only place that will ever say so. It is marked rather than printed
 *  alongside `ok` as though it were another normal ending. */
export function Outcome({ record }: { record: DoorCallRecord }) {
  return (
    <>
      {record.outcome === "unknown" ? (
        <Badge tone="warn">unknown</Badge>
      ) : (
        <span className="mono">{record.outcome}</span>
      )}
      {record.reason && <div className="row-sub">{record.reason}</div>}
    </>
  );
}
